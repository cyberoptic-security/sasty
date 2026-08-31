"""Pull container images (Docker Hub or any registry) and prepare them for scanning.

Trivy talks to registries directly, so a plain `trivy image <ref>` scan needs no
Docker daemon.

Extracting the image filesystem — so the secret scanners and SAST tools can run
over the image contents — is done with crane, a ~12 MB static registry client
that Sasty downloads like any other tool. crane pulls and flattens the image
straight from the registry, so this needs no Docker daemon either. A local
docker CLI is used as a fallback when crane is not installed.
"""

import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Permissive OCI reference charset. The point is not to fully validate the ref
# (the registry will do that) but to reject anything that could be mistaken for
# a CLI flag or smuggle whitespace/control characters into an argv list.
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,254}$")
_DIGEST_RE = re.compile(r"@sha256:[a-f0-9]{64}$")

# Refuse to fill the disk with a runaway image
MAX_ROOTFS_BYTES = int(os.environ.get("SASTY_MAX_IMAGE_BYTES", 5 * 1024 * 1024 * 1024))


class ImagePullError(RuntimeError):
    pass


def normalize_image_ref(ref: str) -> str:
    """Validate an image reference and default the tag to :latest.

    Raises ValueError if the reference is malformed.
    """
    ref = (ref or "").strip()
    if not ref:
        raise ValueError("Image reference is empty")
    if not _SAFE_REF.match(ref):
        raise ValueError(
            f"Invalid image reference: {ref!r} — expected something like "
            "myorg/myapp:latest or ghcr.io/org/image@sha256:..."
        )
    if _DIGEST_RE.search(ref):
        return ref

    # Split off the registry host (first path segment containing a '.' or ':',
    # or literally 'localhost') so we don't mistake its port for a tag.
    head, _, rest = ref.partition("/")
    has_registry = rest and ("." in head or ":" in head or head == "localhost")
    name_part = rest if has_registry else ref

    if ":" not in name_part:
        ref += ":latest"
    return ref


def docker_available() -> bool:
    """True if a usable docker CLI + daemon is reachable."""
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        res = subprocess.run([docker, "version", "--format", "{{.Server.Version}}"],
                             capture_output=True, text=True, timeout=10)
        return res.returncode == 0 and bool(res.stdout.strip())
    except Exception:
        return False


def _crane_path() -> Optional[str]:
    # Imported lazily: tool_manager probes binaries on import-time paths
    from services import tool_manager
    return tool_manager.get_tool_path("crane")


def extraction_backend() -> Optional[str]:
    """Which backend can unpack an image filesystem: "crane", "docker" or None."""
    if _crane_path():
        return "crane"
    if docker_available():
        return "docker"
    return None


def _stream(cmd: list[str], on_output=None, cancel_check=None, timeout: int = 1800) -> tuple[int, list[str]]:
    """Run a command, forwarding its output line by line to on_output.

    Returns (returncode, output_lines) — the lines matter because registry
    errors ("UNAUTHORIZED", "MANIFEST_UNKNOWN") only ever appear there, and a
    bare exit code tells the user nothing about what went wrong.
    """
    import time as _time

    lines: list[str] = []
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    start = _time.monotonic()
    try:
        for line in proc.stdout:
            line = line.strip()
            if line:
                lines.append(line)
                if on_output:
                    on_output(line)
            if cancel_check and cancel_check():
                proc.kill()
                raise _cancelled()
            if _time.monotonic() - start > timeout:
                proc.kill()
                raise ImagePullError(f"Timed out after {timeout}s: {' '.join(cmd[:2])}")
    finally:
        proc.wait()
    return proc.returncode, lines


def explain_registry_failure(image_ref: str, lines: list[str]) -> str:
    """Turn raw registry output into something a user can act on."""
    blob = " ".join(lines).lower()
    if "unauthorized" in blob or "authentication required" in blob:
        # Docker Hub returns UNAUTHORIZED for private *and* non-existent repos,
        # so a typo'd name lands here far more often than a real auth problem.
        return (
            f"{image_ref} could not be pulled — the registry says it is private or "
            "does not exist. Check the spelling of the repository and tag; if the "
            "image really is private, Sasty has no credentials for it."
        )
    if "manifest_unknown" in blob or "manifest unknown" in blob or "not found" in blob:
        return f"{image_ref} was not found in the registry — check the repository name and tag."
    if "no such host" in blob or "dial tcp" in blob or "timeout" in blob or "connection refused" in blob:
        return f"Could not reach the registry for {image_ref} — check network access and any proxy settings."
    detail = _tail(lines)
    return f"Could not pull {image_ref}:\n{detail}"


def _tail(lines: list[str], n: int = 5) -> str:
    return "\n".join(lines[-n:]) if lines else "(no output)"


def _cancelled():
    # Imported lazily to avoid a circular import with scan_runner
    from services.scan_runner import ScanCancelled
    return ScanCancelled()


def export_rootfs(image_ref: str, dest: Path, on_output=None, cancel_check=None) -> Path:
    """Unpack the image's flattened filesystem into `dest`.

    Prefers crane, which pulls and flattens straight from the registry with no
    Docker daemon involved. Falls back to `docker create` + `docker export`.
    Returns `dest`.
    """
    backend = extraction_backend()
    if backend is None:
        raise ImagePullError(
            "Cannot unpack the image — install crane from the Tools panel, "
            "or make a Docker daemon reachable"
        )

    dest.mkdir(parents=True, exist_ok=True)
    tar_dir = Path(tempfile.mkdtemp(prefix="sasty_img_"))
    tar_path = tar_dir / "rootfs.tar"

    try:
        if backend == "crane":
            _export_with_crane(image_ref, tar_path, on_output, cancel_check)
        else:
            _export_with_docker(image_ref, tar_path, on_output, cancel_check)

        size = tar_path.stat().st_size
        if size > MAX_ROOTFS_BYTES:
            raise ImagePullError(
                f"Image filesystem is {size / 1e9:.1f} GB, over the "
                f"{MAX_ROOTFS_BYTES / 1e9:.1f} GB limit — scan without filesystem extraction"
            )
        if on_output:
            on_output(f"Unpacking {size / 1e6:.0f} MB of image filesystem...")

        _safe_extract(tar_path, dest, cancel_check)
    finally:
        shutil.rmtree(tar_dir, ignore_errors=True)

    return dest


def _export_with_crane(image_ref: str, tar_path: Path, on_output=None, cancel_check=None) -> None:
    crane = _crane_path()
    if not crane:
        raise ImagePullError("crane not found — install it from the Tools panel")
    if on_output:
        on_output(f"Pulling {image_ref} from the registry (crane)...")
    # crane defaults to the linux/amd64 variant of a multi-arch image, which is
    # also what trivy scans — keep the two consistent.
    rc, lines = _stream([crane, "export", "--platform", "linux/amd64", image_ref, str(tar_path)],
                        on_output, cancel_check, timeout=1800)
    if rc != 0 or not tar_path.exists():
        raise ImagePullError(explain_registry_failure(image_ref, lines))


def _export_with_docker(image_ref: str, tar_path: Path, on_output=None, cancel_check=None) -> None:
    docker = shutil.which("docker")
    if not docker:
        raise ImagePullError("docker CLI not found")

    if on_output:
        on_output(f"Pulling {image_ref} (docker)...")
    rc, lines = _stream([docker, "pull", image_ref], on_output, cancel_check, timeout=1800)
    if rc != 0:
        raise ImagePullError(explain_registry_failure(image_ref, lines))

    created = subprocess.run(
        [docker, "create", image_ref], capture_output=True, text=True, timeout=120,
    )
    if created.returncode != 0:
        raise ImagePullError(f"docker create failed: {created.stderr.strip()[:300]}")
    container_id = created.stdout.strip()

    try:
        if on_output:
            on_output("Exporting image filesystem...")
        rc, lines = _stream([docker, "export", "-o", str(tar_path), container_id],
                            on_output, cancel_check, timeout=1800)
        if rc != 0:
            raise ImagePullError(f"docker export failed (exit {rc}):\n{_tail(lines)}")
    finally:
        subprocess.run([docker, "rm", "-f", container_id], capture_output=True, timeout=60)


def _safe_extract(tar_path: Path, dest: Path, cancel_check=None) -> None:
    """Unpack a rootfs tar, refusing members that escape the destination."""
    dest_resolved = dest.resolve()
    extracted = 0
    with tarfile.open(tar_path) as tf:
        for member in tf:
            if cancel_check and cancel_check():
                raise _cancelled()
            # Container rootfs tars carry device nodes, fifos and hard links we
            # neither need nor can safely recreate — only take regular files,
            # directories and symlinks.
            if not (member.isreg() or member.isdir() or member.issym()):
                continue
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest_resolved)):
                logger.warning(f"Skipping unsafe tar member: {member.name}")
                continue
            if member.issym():
                # Symlinks in an image rootfs frequently point outside it
                # (/etc/foo -> ../bar). Nothing reads them during a scan, so
                # skip rather than risk a scanner following one off the tree.
                continue
            try:
                tf.extract(member, dest, set_attrs=False)
            except (OSError, tarfile.TarError) as e:
                logger.debug(f"Could not extract {member.name}: {e}")
                continue
            extracted += 1
    logger.info(f"Extracted {extracted} entries from image filesystem")


def cleanup_rootfs(path: Optional[str]) -> None:
    if path and Path(path).exists():
        shutil.rmtree(path, ignore_errors=True)
