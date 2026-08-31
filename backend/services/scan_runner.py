import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from models import Finding, Scan
from services import image_scanner, tool_manager
from services.parsers import bandit_parser, betterleaks_parser, gitleaks_parser, hadolint_parser, semgrep_parser, trivy_parser, trufflehog_parser

logger = logging.getLogger(__name__)
CONTEXT_LINES = 5

# The secret scanners were capped at 120s (trufflehog at 30s), which is fine for
# a source checkout but far too short for a container image rootfs — a 1.5 GB
# image takes gitleaks over two minutes on its own, and the tool was being
# killed mid-scan with its findings silently dropped.
SECRET_SCAN_TIMEOUT = int(os.environ.get("SASTY_SECRET_SCAN_TIMEOUT", 1800))

_db_path = os.environ.get("SASTY_DB_PATH", "./sasty.db")
RAW_OUTPUT_DIR = Path(os.path.dirname(os.path.abspath(_db_path))) / "raw_output"


def get_raw_output_dir(scan_id: int) -> Path:
    """Get the directory for storing raw tool output for a scan."""
    d = RAW_OUTPUT_DIR / str(scan_id)
    d.mkdir(parents=True, exist_ok=True)
    return d

# Set of scan IDs that have been requested to cancel
_cancel_requested: set[int] = set()


def request_cancel(scan_id: int):
    _cancel_requested.add(scan_id)


def _is_cancelled(scan_id: int) -> bool:
    return scan_id in _cancel_requested


def get_code_context(file_path: str, line_start: int, line_end: int) -> Optional[dict]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start_idx = max(0, line_start - 1 - CONTEXT_LINES)
        end_idx = min(len(lines), line_end + CONTEXT_LINES)
        return {
            "lines": [line.rstrip("\n") for line in lines[start_idx:end_idx]],
            "start_line": start_idx + 1,
            "highlight_start": line_start,
            "highlight_end": line_end,
        }
    except Exception as e:
        logger.debug(f"Could not read context from {file_path}: {e}")
        return None


def _find_semgrep() -> list[str]:
    """Locate semgrep executable, handling broken Windows pip installs."""
    if shutil.which("semgrep"):
        return ["semgrep"]
    # On Windows a broken pip install may leave a bare 'semgrep' script
    # without the normal .exe wrapper — invoke it via python directly
    if sys.platform == "win32":
        scripts_dir = Path(sys.executable).parent
        bare_script = scripts_dir / "semgrep"
        if bare_script.exists():
            return [sys.executable, str(bare_script)]
    raise RuntimeError("semgrep not found — install it with: pip install semgrep")


import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07")


class ScanCancelled(Exception):
    pass


def _read_lines(stream, on_output: callable = None, cancel_check: callable = None) -> list[str]:
    """Read from a stream, splitting on both \\n and \\r (for progress bars).
    Strips ANSI escape codes and calls on_output for each non-empty line."""
    lines: list[str] = []
    buf = []
    while True:
        if cancel_check and cancel_check():
            raise ScanCancelled()
        ch = stream.read(1)
        if not ch:
            break
        if ch in ("\n", "\r"):
            line = _ANSI_RE.sub("", "".join(buf)).strip()
            if line:
                lines.append(line)
                if on_output:
                    on_output(line)
            buf = []
        else:
            buf.append(ch)
    # Flush remaining buffer
    line = _ANSI_RE.sub("", "".join(buf)).strip()
    if line:
        lines.append(line)
        if on_output:
            on_output(line)
    return lines


def _count_source_files(path: str) -> dict[str, int]:
    """Count source files by extension for progress reporting."""
    counts: dict[str, int] = {}
    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in (".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".java", ".rb",
                        ".php", ".c", ".cpp", ".cs", ".rs", ".yaml", ".yml", ".json",
                        ".tf", ".hcl", ".sh", ".bash", ".sql"):
                counts[ext] = counts.get(ext, 0) + 1
    return counts


def _run_with_pty(cmd: list[str], on_output: callable = None, cancel_check: callable = None, timeout: int = 600):
    """Run a command with a pseudo-terminal so it thinks it's interactive.
    Returns (returncode, output_lines). Falls back to polling on Windows."""
    output_lines: list[str] = []

    if sys.platform != "win32":
        import pty
        import select

        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(cmd, stdout=slave_fd, stderr=slave_fd, close_fds=True)
        os.close(slave_fd)

        buf = ""
        elapsed = 0
        try:
            while True:
                if cancel_check and cancel_check():
                    proc.kill()
                    raise ScanCancelled()
                # Check if data available (100ms timeout for responsive cancel)
                ready, _, _ = select.select([master_fd], [], [], 1.0)
                if ready:
                    try:
                        data = os.read(master_fd, 4096).decode("utf-8", errors="replace")
                    except OSError:
                        break
                    if not data:
                        break
                    buf += data
                    # Split on \n and \r
                    while "\n" in buf or "\r" in buf:
                        for sep in ("\r\n", "\n", "\r"):
                            if sep in buf:
                                line, buf = buf.split(sep, 1)
                                line = _ANSI_RE.sub("", line).strip()
                                if line:
                                    output_lines.append(line)
                                    if on_output:
                                        on_output(line)
                                break
                else:
                    elapsed += 1
                    if elapsed > timeout:
                        proc.kill()
                        raise RuntimeError(f"Timed out after {timeout}s")
                if proc.poll() is not None:
                    # Process done — drain remaining output
                    try:
                        while True:
                            ready, _, _ = select.select([master_fd], [], [], 0.1)
                            if not ready:
                                break
                            data = os.read(master_fd, 4096).decode("utf-8", errors="replace")
                            if not data:
                                break
                            for line in re.split(r"[\r\n]+", _ANSI_RE.sub("", data)):
                                line = line.strip()
                                if line:
                                    output_lines.append(line)
                                    if on_output:
                                        on_output(line)
                    except OSError:
                        pass
                    break
        finally:
            os.close(master_fd)
            proc.wait()
        return proc.returncode, output_lines
    else:
        # Windows: no pty support. Capture output on a background thread — a
        # tool that fails explains itself on stderr, and discarding that left
        # errors reading as a bare exit code.
        import threading

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, errors="replace",
        )

        def _drain():
            for line in proc.stdout:
                line = _ANSI_RE.sub("", line).strip()
                if line:
                    output_lines.append(line)
                    if on_output:
                        on_output(line)

        reader = threading.Thread(target=_drain, daemon=True)
        reader.start()

        elapsed = 0
        while proc.poll() is None:
            _time.sleep(1)
            elapsed += 1
            if on_output and elapsed % 5 == 0 and not output_lines:
                on_output(f"Scanning in progress... ({elapsed}s)")
            if cancel_check and cancel_check():
                proc.kill()
                raise ScanCancelled()
            if elapsed > timeout:
                proc.kill()
                raise RuntimeError(f"Timed out after {timeout}s")
        reader.join(timeout=5)
        return proc.returncode, output_lines


def _run_semgrep(path: str, configs: list[str], on_output: callable = None, cancel_check: callable = None, scan_id: int | None = None, extra_args: list[str] | None = None) -> list[dict]:
    if not configs:
        configs = ["auto"]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        output_path = f.name

    try:
        uses_auto = "auto" in configs
        cmd = _find_semgrep() + [
            "scan", "--json",
            f"--metrics={'on' if uses_auto else 'off'}",
            "--no-git-ignore",
            "--output", output_path,
        ]
        for config in configs:
            cmd += ["--config", config]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(path)

        if on_output:
            file_counts = _count_source_files(path)
            total_files = sum(file_counts.values())
            on_output(f"Scanning {total_files} source files")
            if file_counts:
                top_exts = sorted(file_counts.items(), key=lambda x: -x[1])[:6]
                breakdown = ", ".join(f"{count} {ext}" for ext, count in top_exts)
                on_output(f"  {breakdown}")
            on_output(f"Configs: {', '.join(c.replace('p/', '') for c in configs)}")

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        stderr_lines = []
        # Read stderr in a thread so we don't block
        import threading
        def _drain_stderr():
            for line in proc.stderr:
                line = line.strip()
                if line:
                    stderr_lines.append(line)
                    if on_output:
                        on_output(line)
        t = threading.Thread(target=_drain_stderr, daemon=True)
        t.start()
        # Read stdout (semgrep progress output)
        output_lines = _read_lines(proc.stdout, on_output, cancel_check)
        t.join(timeout=5)
        proc.wait()
        returncode = proc.returncode

        # Exit codes: 0=no findings, 1=findings found, 2=partial (some rules failed)
        # Only fail on exit code >= 3 (hard errors)
        if returncode >= 3:
            detail = "\n".join(stderr_lines[-10:]) if stderr_lines else "\n".join(output_lines[-10:]) if output_lines else "(no output)"
            raise RuntimeError(f"semgrep exited with code {returncode}:\n{detail}")

        with open(output_path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            if returncode == 2:
                detail = "\n".join(stderr_lines[-10:]) if stderr_lines else "\n".join(output_lines[-10:]) if output_lines else "(no output)"
                raise RuntimeError(f"semgrep failed (exit code 2) and produced no output:\n{detail}")
            return []
        if returncode == 2 and on_output:
            on_output("Warning: some semgrep rules had errors (partial results)")

        # Save raw output for export
        if scan_id is not None:
            try:
                raw_dir = get_raw_output_dir(scan_id)
                (raw_dir / "semgrep.json").write_text(raw, encoding="utf-8")
            except Exception as e:
                logger.warning(f"Could not save raw semgrep output: {e}")

        data = json.loads(raw)
        return semgrep_parser.parse(data)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse semgrep output: {e}")
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass


def _run_gitleaks(path: str, on_output: callable = None, cancel_check: callable = None, scan_id: int | None = None, extra_args: list[str] | None = None) -> list[dict]:
    gitleaks_path = tool_manager.get_tool_path("gitleaks")
    if not gitleaks_path:
        raise RuntimeError("gitleaks not found — use the Tools panel to download it")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        report_path = f.name

    try:
        is_git = (Path(path) / ".git").is_dir()
        cmd = [
            gitleaks_path,
            "detect",
            "--source", path,
            "--report-format", "json",
            "--report-path", report_path,
            "--exit-code", "0",
        ]
        if not is_git:
            cmd.append("--no-git")
        if extra_args:
            cmd.extend(extra_args)
        if on_output:
            file_counts = _count_source_files(path)
            total_files = sum(file_counts.values())
            on_output(f"Scanning {total_files} files for secrets & credentials...")

        _run_with_pty(cmd, on_output, cancel_check, timeout=SECRET_SCAN_TIMEOUT)

        with open(report_path, "r") as f:
            raw = f.read().strip()
        if not raw:
            return []

        # Save raw output for export
        if scan_id is not None:
            try:
                raw_dir = get_raw_output_dir(scan_id)
                (raw_dir / "gitleaks.json").write_text(raw, encoding="utf-8")
            except Exception as e:
                logger.warning(f"Could not save raw gitleaks output: {e}")

        data = json.loads(raw)
        return gitleaks_parser.parse(data) if isinstance(data, list) else []
    except ScanCancelled:
        raise
    except json.JSONDecodeError:
        return []
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass


def _run_betterleaks(path: str, on_output: callable = None, cancel_check: callable = None, scan_id: int | None = None, extra_args: list[str] | None = None) -> list[dict]:
    betterleaks_path = tool_manager.get_tool_path("betterleaks")
    if not betterleaks_path:
        raise RuntimeError("betterleaks not found — use the Tools panel to download it")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        report_path = f.name

    try:
        is_git = (Path(path) / ".git").is_dir()
        subcmd = "git" if is_git else "dir"
        cmd = [
            betterleaks_path,
            subcmd,
            path,
            "--report-format", "json",
            "--report-path", report_path,
            "--exit-code", "0",
        ]
        if extra_args:
            cmd.extend(extra_args)

        if on_output:
            file_counts = _count_source_files(path)
            total_files = sum(file_counts.values())
            on_output(f"Scanning {total_files} files for secrets & credentials (betterleaks)...")

        _run_with_pty(cmd, on_output, cancel_check, timeout=SECRET_SCAN_TIMEOUT)

        with open(report_path, "r") as f:
            raw = f.read().strip()
        if not raw:
            return []

        if scan_id is not None:
            try:
                raw_dir = get_raw_output_dir(scan_id)
                (raw_dir / "betterleaks.json").write_text(raw, encoding="utf-8")
            except Exception as e:
                logger.warning(f"Could not save raw betterleaks output: {e}")

        data = json.loads(raw)
        return betterleaks_parser.parse(data) if isinstance(data, list) else []
    except ScanCancelled:
        raise
    except json.JSONDecodeError:
        return []
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass


def _run_trufflehog(path: str, on_output: callable = None, cancel_check: callable = None, scan_id: int | None = None, extra_args: list[str] | None = None) -> list[dict]:
    import threading
    trufflehog_path = tool_manager.get_tool_path("trufflehog")
    if not trufflehog_path:
        raise RuntimeError("trufflehog not found — use the Tools panel to download it")

    is_git = (Path(path) / ".git").is_dir()

    # Build base command with global flags first
    cmd = [trufflehog_path]

    # Add extra args that go before the subcommand (like --only-verified)
    global_args = []
    subcommand_args = []
    if extra_args:
        for arg in extra_args:
            if arg.startswith("--only-verified") or arg.startswith("--include-detectors") or arg.startswith("--exclude-detectors"):
                global_args.append(arg)
            else:
                subcommand_args.append(arg)

    cmd.extend(global_args)

    if is_git:
        git_uri = Path(path).as_uri()
        cmd.extend(["git", git_uri])
    else:
        cmd.extend(["filesystem", path])

    cmd.extend(["--json", "--no-update"])
    cmd.extend(subcommand_args)

    if on_output:
        on_output("Scanning for credentials with live verification (trufflehog)...")

    logger.debug(f"Trufflehog command: {' '.join(cmd)}")

    items: list[dict] = []

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    def _drain_stdout():
        for line in proc.stdout:
            if cancel_check and cancel_check():
                proc.kill()
                raise ScanCancelled()
            line = line.strip()
            if line and line.startswith("{"):
                try:
                    item = json.loads(line)
                    items.append(item)
                    # Log to see if verified field is present
                    if "verified" in item or "Verified" in item:
                        logger.debug(f"Found verified field: {item.get('verified') or item.get('Verified')}")
                except json.JSONDecodeError:
                    pass

    def _drain_stderr():
        for line in proc.stderr:
            line = line.strip()
            if line and on_output:
                on_output(line)

    stdout_thread = threading.Thread(target=_drain_stdout, daemon=True)
    stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    # Wait for both threads and process with timeout
    stdout_thread.join(timeout=SECRET_SCAN_TIMEOUT)
    stderr_thread.join(timeout=5)
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        logger.warning(f"Scan {scan_id}: trufflehog process timeout, killed it")
        if on_output:
            on_output(f"trufflehog timed out after {SECRET_SCAN_TIMEOUT}s — results may be incomplete")

    if scan_id is not None:
        try:
            raw_dir = get_raw_output_dir(scan_id)
            (raw_dir / "trufflehog.json").write_text(json.dumps(items, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Could not save raw trufflehog output: {e}")

    return trufflehog_parser.parse(items)


def _run_hadolint(path: str, on_output: callable = None, scan_id: int | None = None, extra_args: list[str] | None = None) -> list[dict]:
    hadolint_path = tool_manager.get_tool_path("hadolint")
    if not hadolint_path:
        raise RuntimeError("hadolint not found — use the Tools panel to download it")

    dockerfiles = []
    for root, _dirs, files in os.walk(path):
        for fname in files:
            if fname == "Dockerfile" or fname.startswith("Dockerfile."):
                dockerfiles.append(os.path.join(root, fname))

    if not dockerfiles:
        if on_output:
            on_output("No Dockerfiles found — skipping")
        return []

    all_findings: list[dict] = []
    all_raw: list[dict] = []
    for dockerfile in dockerfiles:
        if on_output:
            on_output(f"Linting {os.path.relpath(dockerfile, path)}")
        cmd = [hadolint_path, "--format", "json"]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(dockerfile)
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=30,
        )
        try:
            data = json.loads(result.stdout)
            all_raw.extend(data)
            all_findings.extend(hadolint_parser.parse(data))
        except json.JSONDecodeError:
            pass

    # Save raw output for export
    if scan_id is not None and all_raw:
        try:
            raw_dir = get_raw_output_dir(scan_id)
            (raw_dir / "hadolint.json").write_text(json.dumps(all_raw, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Could not save raw hadolint output: {e}")

    return all_findings


def _run_bandit(path: str, on_output: callable = None, cancel_check: callable = None, scan_id: int | None = None, extra_args: list[str] | None = None) -> list[dict]:
    """Run Bandit Python security scanner."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        output_path = f.name

    try:
        cmd = [sys.executable, "-m", "bandit", "-r", path, "-f", "json", "-o", output_path, "-q"]
        if extra_args:
            cmd.extend(extra_args)

        if on_output:
            on_output("Running Bandit Python security analysis...")

        returncode, _ = _run_with_pty(cmd, on_output, cancel_check, timeout=300)

        # Exit code 0 = no issues, 1 = issues found, other = error
        if returncode not in (0, 1):
            # Check if output was still produced (bandit can return non-zero with results)
            if not Path(output_path).exists() or Path(output_path).stat().st_size == 0:
                raise RuntimeError(f"bandit exited with code {returncode}")

        try:
            with open(output_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
        except FileNotFoundError:
            return []

        if not raw:
            return []

        if scan_id is not None:
            try:
                raw_dir = get_raw_output_dir(scan_id)
                (raw_dir / "bandit.json").write_text(raw, encoding="utf-8")
            except Exception as e:
                logger.warning(f"Could not save raw bandit output: {e}")

        data = json.loads(raw)
        return bandit_parser.parse(data)
    except ScanCancelled:
        raise
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse bandit output: {e}")
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass


def _run_trivy(path: str, on_output: callable = None, cancel_check: callable = None, scan_id: int | None = None, extra_args: list[str] | None = None) -> list[dict]:
    """Run Trivy filesystem scanner for vulnerabilities and misconfigurations."""
    trivy_path = tool_manager.get_tool_path("trivy")
    if not trivy_path:
        raise RuntimeError("trivy not found — use the Tools panel to download it")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        output_path = f.name

    try:
        cmd = [
            trivy_path, "fs",
            "--format", "json",
            "--output", output_path,
            "--scanners", "vuln,misconfig",
        ]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(path)

        if on_output:
            on_output("Running Trivy vulnerability & misconfiguration scan...")

        returncode, _ = _run_with_pty(cmd, on_output, cancel_check, timeout=600)

        if returncode != 0:
            if not Path(output_path).exists() or Path(output_path).stat().st_size == 0:
                raise RuntimeError(f"trivy exited with code {returncode}")

        try:
            with open(output_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
        except FileNotFoundError:
            return []

        if not raw:
            return []

        if scan_id is not None:
            try:
                raw_dir = get_raw_output_dir(scan_id)
                (raw_dir / "trivy.json").write_text(raw, encoding="utf-8")
            except Exception as e:
                logger.warning(f"Could not save raw trivy output: {e}")

        data = json.loads(raw)
        return trivy_parser.parse(data)
    except ScanCancelled:
        raise
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse trivy output: {e}")
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass


def _run_trivy_image(image_ref: str, on_output: callable = None, cancel_check: callable = None, scan_id: int | None = None, extra_args: list[str] | None = None) -> list[dict]:
    """Scan a container image reference with Trivy.

    Trivy resolves the reference itself — local daemon first, then the remote
    registry — so this works with or without Docker installed.
    """
    trivy_path = tool_manager.get_tool_path("trivy")
    if not trivy_path:
        raise RuntimeError("trivy not found — use the Tools panel to download it")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        output_path = f.name

    try:
        cmd = [
            trivy_path, "image",
            "--format", "json",
            "--output", output_path,
        ]
        # Images get the secret scanner too — layers routinely carry baked-in
        # credentials that a filesystem scan of the source would never see.
        if not (extra_args and "--scanners" in extra_args):
            cmd += ["--scanners", "vuln,secret,misconfig"]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(image_ref)

        if on_output:
            on_output(f"Pulling and scanning image {image_ref}...")

        returncode, out_lines = _run_with_pty(cmd, on_output, cancel_check, timeout=1800)

        if returncode != 0:
            if not Path(output_path).exists() or Path(output_path).stat().st_size == 0:
                # Registry failures are only explained in trivy's own output —
                # surface that rather than a bare exit code.
                raise RuntimeError(image_scanner.explain_registry_failure(image_ref, out_lines))

        try:
            with open(output_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
        except FileNotFoundError:
            return []

        if not raw:
            return []

        if scan_id is not None:
            try:
                raw_dir = get_raw_output_dir(scan_id)
                (raw_dir / "trivy.json").write_text(raw, encoding="utf-8")
            except Exception as e:
                logger.warning(f"Could not save raw trivy output: {e}")

        data = json.loads(raw)
        if on_output:
            meta = data.get("Metadata") or {}
            os_info = meta.get("OS") or {}
            if os_info:
                on_output(f"Image OS: {os_info.get('Family', '?')} {os_info.get('Name', '')}".strip())
        return trivy_parser.parse(data)
    except ScanCancelled:
        raise
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse trivy output: {e}")
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass


def _enrich_with_context(findings: list[dict], base_path: str):
    if not base_path:
        return
    for finding in findings:
        fp = finding.get("file_path", "")
        if not fp:
            continue
        # Make path absolute if relative
        if not os.path.isabs(fp):
            fp = os.path.join(base_path, fp)
        ls = finding.get("line_start")
        le = finding.get("line_end") or ls
        if ls:
            finding["code_context"] = get_code_context(fp, ls, le)
            finding["file_path"] = fp


def _relativise_to_rootfs(findings: list[dict], rootfs_dir: str):
    """Rewrite host paths inside an exported image rootfs to image paths.

    The rootfs is a temp dir that gets deleted once the scan finishes, so a
    finding in `/tmp/sasty_rootfs_7_x/usr/src/app/index.js` is stored as
    `/usr/src/app/index.js` — where it actually lives in the image.
    """
    root = os.path.abspath(rootfs_dir)
    for finding in findings:
        fp = finding.get("file_path", "")
        if fp and os.path.isabs(fp) and os.path.abspath(fp).startswith(root):
            rel = os.path.relpath(os.path.abspath(fp), root)
            finding["file_path"] = "/" + rel.replace(os.sep, "/")


TOOL_RUNNERS = {
    "semgrep": _run_semgrep,
    "gitleaks": _run_gitleaks,
    "betterleaks": _run_betterleaks,
    "hadolint": _run_hadolint,
    "bandit": _run_bandit,
    "trivy": _run_trivy,
}


import copy
import time as _time

from sqlalchemy.orm.attributes import flag_modified

_LOG_TAIL_MAX = 8  # Keep last N lines of tool output


def _set_progress(scan: Scan, db: Session, steps: list[dict], current: str | None):
    # Deep-copy so SQLAlchemy detects the JSON mutation
    scan.progress = copy.deepcopy({"steps": steps, "current_tool": current})
    flag_modified(scan, "progress")
    # Don't commit here - let the caller decide when to commit
    # This prevents database lock contention from multiple commits


def _build_extra_args(tool_name: str, opts: dict) -> list[str]:
    """Convert tool_options dict into CLI extra args for a scanner."""
    args: list[str] = []
    if not opts:
        return args

    # Common: extra_args is a freetext string of additional CLI flags
    extra = opts.get("extra_args", "").strip()
    if extra:
        import shlex
        args.extend(shlex.split(extra))

    # Tool-specific boolean/value options
    if tool_name == "semgrep":
        if opts.get("exclude"):
            for pattern in opts["exclude"].split(","):
                p = pattern.strip()
                if p:
                    args.extend(["--exclude", p])
        if opts.get("severity"):
            args.extend(["--severity", opts["severity"]])
        if opts.get("verbose"):
            args.append("--verbose")
    elif tool_name in ("gitleaks", "betterleaks"):
        if opts.get("log_level"):
            args.extend(["--log-level", opts["log_level"]])
        if opts.get("config"):
            args.extend(["--config", opts["config"]])
        if tool_name == "betterleaks":
            if opts.get("max_archive_depth"):
                args.extend(["--max-archive-depth", str(opts["max_archive_depth"])])
            if opts.get("max_decode_depth"):
                args.extend(["--max-decode-depth", str(opts["max_decode_depth"])])
    elif tool_name == "trufflehog":
        if opts.get("only_verified"):
            args.append("--only-verified")
        if opts.get("include_detectors"):
            args.extend(["--include-detectors", opts["include_detectors"]])
        if opts.get("exclude_detectors"):
            args.extend(["--exclude-detectors", opts["exclude_detectors"]])
    elif tool_name == "hadolint":
        if opts.get("failure_threshold"):
            args.extend(["--failure-threshold", opts["failure_threshold"]])
        if opts.get("ignore"):
            for rule in opts["ignore"].split(","):
                r = rule.strip()
                if r:
                    args.extend(["--ignore", r])
        if opts.get("trusted_registry"):
            for reg in opts["trusted_registry"].split(","):
                r = reg.strip()
                if r:
                    args.extend(["--trusted-registry", r])
    elif tool_name == "bandit":
        if opts.get("severity"):
            level = opts["severity"].upper()
            if level in ("LOW", "MEDIUM", "HIGH"):
                args.extend(["-" + "l" * (1 + ["LOW", "MEDIUM", "HIGH"].index(level))])
        if opts.get("confidence"):
            level = opts["confidence"].upper()
            if level in ("LOW", "MEDIUM", "HIGH"):
                args.extend(["-" + "i" * (1 + ["LOW", "MEDIUM", "HIGH"].index(level))])
        if opts.get("skip"):
            args.extend(["--skip", opts["skip"]])
        if opts.get("tests"):
            args.extend(["--tests", opts["tests"]])
    elif tool_name == "trivy":
        if opts.get("severity"):
            args.extend(["--severity", opts["severity"]])
        if opts.get("ignore_unfixed"):
            args.append("--ignore-unfixed")
        if opts.get("scanners"):
            args.extend(["--scanners", opts["scanners"]])

    return args


def _run_custom_command(path: str, command: str, tool_label: str, on_output: callable = None, cancel_check: callable = None, scan_id: int | None = None, image_ref: str | None = None) -> list[dict]:
    """Run a user-defined custom command and capture JSON output."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        output_path = f.name

    # Replace placeholders in the command
    cmd_str = command.replace("{path}", path).replace("{output}", output_path)
    cmd_str = cmd_str.replace("{image}", image_ref or "")

    try:
        if on_output:
            on_output(f"Running custom command: {cmd_str}")

        import shlex
        if sys.platform == "win32":
            # On Windows, run through shell
            proc = subprocess.Popen(
                cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        else:
            cmd_parts = shlex.split(cmd_str)
            proc = subprocess.Popen(
                cmd_parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )

        stderr_lines = []
        import threading
        def _drain_stderr():
            for line in proc.stderr:
                line = line.strip()
                if line:
                    stderr_lines.append(line)
                    if on_output:
                        on_output(line)
        t = threading.Thread(target=_drain_stderr, daemon=True)
        t.start()
        output_lines = _read_lines(proc.stdout, on_output, cancel_check)
        t.join(timeout=5)
        proc.wait()

        if on_output:
            on_output(f"Custom command exited with code {proc.returncode}")

        # Try to read JSON output file
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
        except FileNotFoundError:
            raw = ""

        if not raw:
            return []

        if scan_id is not None:
            try:
                raw_dir = get_raw_output_dir(scan_id)
                (raw_dir / f"custom_{tool_label}.json").write_text(raw, encoding="utf-8")
            except Exception as e:
                logger.warning(f"Could not save raw custom command output: {e}")

        # Try to auto-detect and parse the output format
        data = json.loads(raw)
        from services.parsers import semgrep_parser, gitleaks_parser, hadolint_parser, bandit_parser, trivy_parser, betterleaks_parser

        if isinstance(data, dict) and "results" in data:
            results = data["results"]
            if isinstance(results, list) and len(results) > 0 and "test_id" in results[0]:
                return bandit_parser.parse(data)
            return semgrep_parser.parse(data)
        elif isinstance(data, dict) and "Results" in data:
            return trivy_parser.parse(data)
        elif isinstance(data, list) and len(data) > 0:
            first = data[0]
            if "RuleID" in first or "Match" in first or "Secret" in first:
                return gitleaks_parser.parse(data)
            elif "code" in first and "message" in first and "level" in first:
                return hadolint_parser.parse(data)

        # If we can't detect the format, return empty
        if on_output:
            on_output("Warning: could not auto-detect output format from custom command")
        return []
    except ScanCancelled:
        raise
    except json.JSONDecodeError:
        if on_output:
            on_output("Warning: custom command output was not valid JSON")
        return []
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass


def _detect_duplicates(scan_id: int, db: Session):
    """Flag findings from different tools that report the same file + line."""
    from sqlalchemy.orm import attributes
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    location_groups: dict[tuple, list] = {}
    for f in findings:
        if f.file_path and f.line_start is not None:
            key = (f.file_path, f.line_start)
            location_groups.setdefault(key, []).append(f)

    duplicate_count = 0
    for group in location_groups.values():
        tools_in_group = {f.tool for f in group}
        if len(tools_in_group) > 1:
            for finding in group:
                finding.is_duplicate = True
                finding.duplicate_ids = [{"id": o.id, "tool": o.tool} for o in group if o.id != finding.id]
                duplicate_count += 1

    if duplicate_count > 0:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan and scan.summary:
            updated_summary = dict(scan.summary)
            updated_summary["duplicates"] = duplicate_count
            scan.summary = updated_summary
            flag_modified(scan, "summary")
        db.commit()
        logger.info(f"Scan {scan_id}: {duplicate_count} findings flagged as cross-tool duplicates")


# Tools that need a real filesystem to look at. In image mode they only run
# once the image rootfs has been exported.
_FS_ONLY_TOOLS = {"semgrep", "gitleaks", "betterleaks", "trufflehog", "hadolint", "bandit"}

IMAGE_EXPORT_STEP = "image-export"


def run_scan(scan_id: int, path: str, tools: list[str], semgrep_configs: list[str], db: Session, triage_map: dict[str, str] | None = None, tool_options: dict[str, dict] | None = None, custom_commands: list[dict] | None = None, image_ref: str | None = None, extract_filesystem: bool = False):
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = "running"
    except Exception as e:
        logger.error(f"Scan {scan_id}: failed to query/update scan status: {e}")
        raise

    # In image mode `path` is the image reference, not somewhere on disk. The
    # exported rootfs (if any) lands in fs_path and is what the file-based
    # tools actually scan.
    fs_path: str | None = None if image_ref else path
    rootfs_dir: str | None = None

    # Build the full tool list including custom commands
    all_steps = list(tools)
    if image_ref and extract_filesystem:
        all_steps.insert(0, IMAGE_EXPORT_STEP)
    custom_cmd_map: dict[str, dict] = {}
    if custom_commands:
        for idx, cmd_def in enumerate(custom_commands):
            label = cmd_def.get("label", f"custom_{idx}")
            step_key = f"custom:{label}"
            all_steps.append(step_key)
            custom_cmd_map[step_key] = cmd_def

    # Initialise progress — all steps pending
    steps = [{"tool": t, "status": "pending", "findings": None, "error": None, "log_tail": []} for t in all_steps]
    _set_progress(scan, db, steps, all_steps[0] if all_steps else None)
    db.commit()

    tool_options = tool_options or {}
    all_findings: list[dict] = []
    errors: list[str] = []

    try:
        for i, tool_name in enumerate(all_steps):
            # Mark current step as running
            steps[i]["status"] = "running"
            _set_progress(scan, db, steps, tool_name)
            logger.info(f"Scan {scan_id}: running {tool_name}")

            # Live output callback — flushes log tail to DB every 2 seconds
            last_flush = [_time.monotonic()]

            def _on_output(line: str):
                steps[i]["log_tail"] = (steps[i].get("log_tail") or [])[-(_LOG_TAIL_MAX - 1):] + [line]
                now = _time.monotonic()
                if now - last_flush[0] >= 2:
                    last_flush[0] = now
                    _set_progress(scan, db, steps, tool_name)
                    db.commit()

            cancel = lambda: _is_cancelled(scan_id)

            # Get extra args for this tool from tool_options
            opts = tool_options.get(tool_name, {})
            extra_args = _build_extra_args(tool_name, opts)

            try:
                logger.debug(f"Scan {scan_id}: starting tool execution for {tool_name}")
                if cancel():
                    raise ScanCancelled()
                logger.debug(f"Scan {scan_id}: cancel check passed")
                if tool_name == IMAGE_EXPORT_STEP:
                    rootfs_dir = tempfile.mkdtemp(prefix=f"sasty_rootfs_{scan_id}_")
                    image_scanner.export_rootfs(image_ref, Path(rootfs_dir), on_output=_on_output, cancel_check=cancel)
                    fs_path = rootfs_dir
                    steps[i]["status"] = "done"
                    _set_progress(scan, db, steps, all_steps[i + 1] if i + 1 < len(all_steps) else None)
                    db.commit()
                    continue

                if image_ref and tool_name in _FS_ONLY_TOOLS and not fs_path:
                    steps[i]["status"] = "skipped"
                    steps[i]["error"] = "Needs the image filesystem — enable filesystem extraction"
                    _set_progress(scan, db, steps, all_steps[i + 1] if i + 1 < len(all_steps) else None)
                    db.commit()
                    continue

                # File-based tools scan the exported rootfs; trivy scans the
                # image reference itself.
                target = fs_path or path

                if tool_name.startswith("custom:"):
                    cmd_def = custom_cmd_map[tool_name]
                    findings = _run_custom_command(
                        target, cmd_def["command"], cmd_def.get("label", "custom"),
                        on_output=_on_output, cancel_check=cancel, scan_id=scan_id,
                        image_ref=image_ref,
                    )
                elif tool_name == "semgrep":
                    findings = _run_semgrep(target, semgrep_configs, on_output=_on_output, cancel_check=cancel, scan_id=scan_id, extra_args=extra_args)
                elif tool_name == "gitleaks":
                    findings = _run_gitleaks(target, on_output=_on_output, cancel_check=cancel, scan_id=scan_id, extra_args=extra_args)
                elif tool_name == "betterleaks":
                    findings = _run_betterleaks(target, on_output=_on_output, cancel_check=cancel, scan_id=scan_id, extra_args=extra_args)
                elif tool_name == "trufflehog":
                    logger.debug(f"Scan {scan_id}: calling _run_trufflehog")
                    findings = _run_trufflehog(target, on_output=_on_output, cancel_check=cancel, scan_id=scan_id, extra_args=extra_args)
                    logger.debug(f"Scan {scan_id}: _run_trufflehog returned {len(findings)} findings")
                elif tool_name == "hadolint":
                    findings = _run_hadolint(target, on_output=_on_output, scan_id=scan_id, extra_args=extra_args)
                elif tool_name == "bandit":
                    findings = _run_bandit(target, on_output=_on_output, cancel_check=cancel, scan_id=scan_id, extra_args=extra_args)
                elif tool_name == "trivy":
                    if image_ref:
                        findings = _run_trivy_image(image_ref, on_output=_on_output, cancel_check=cancel, scan_id=scan_id, extra_args=extra_args)
                    else:
                        findings = _run_trivy(target, on_output=_on_output, cancel_check=cancel, scan_id=scan_id, extra_args=extra_args)
                else:
                    steps[i]["status"] = "skipped"
                    _set_progress(scan, db, steps, all_steps[i + 1] if i + 1 < len(all_steps) else None)
                    continue

                logger.info(f"Scan {scan_id}: enriching {len(findings)} findings with context")
                # Trivy's image findings reference paths inside the image, not
                # on this host — enriching them against the rootfs would point
                # at a temp dir we are about to delete.
                if not (image_ref and tool_name == "trivy"):
                    _enrich_with_context(findings, fs_path)
                if rootfs_dir:
                    _relativise_to_rootfs(findings, rootfs_dir)
                logger.info(f"Scan {scan_id}: extending all_findings")
                all_findings.extend(findings)
                logger.info(f"Scan {scan_id}: marking step as done")
                steps[i]["status"] = "done"
                steps[i]["findings"] = len(findings)
                logger.info(f"Scan {scan_id}: about to log completion")
                logger.info(f"Scan {scan_id}: {tool_name} found {len(findings)} findings")
                logger.info(f"Scan {scan_id}: logged completion, continuing")
            except ScanCancelled:
                steps[i]["status"] = "error"
                steps[i]["error"] = "Cancelled"
                # Mark remaining steps as skipped
                for j in range(i + 1, len(steps)):
                    steps[j]["status"] = "skipped"
                _cancel_requested.discard(scan_id)
                scan.status = "failed"
                scan.finished_at = datetime.utcnow()
                scan.error_log = "Scan cancelled by user"
                scan.progress = copy.deepcopy({"steps": steps, "current_tool": None})
                flag_modified(scan, "progress")
                db.commit()
                image_scanner.cleanup_rootfs(rootfs_dir)
                logger.info(f"Scan {scan_id} cancelled by user")
                return
            except Exception as e:
                msg = str(e)
                steps[i]["status"] = "error"
                steps[i]["error"] = msg
                errors.append(f"{tool_name}: {msg}")
                logger.error(f"Scan {scan_id} tool error — {tool_name}: {msg}")

            next_tool = all_steps[i + 1] if i + 1 < len(all_steps) else None
            logger.debug(f"Scan {scan_id}: setting progress for next tool")
            _set_progress(scan, db, steps, next_tool)
            db.commit()  # Commit progress update
    except Exception as e:
        logger.error(f"Scan {scan_id}: unexpected error during scan: {e}", exc_info=True)
        scan.status = "failed"
        scan.finished_at = datetime.utcnow()
        scan.error_log = f"Unexpected error: {str(e)}"
        scan.progress = copy.deepcopy({"steps": steps, "current_tool": None})
        flag_modified(scan, "progress")
        db.commit()
        image_scanner.cleanup_rootfs(rootfs_dir)
        return

    image_scanner.cleanup_rootfs(rootfs_dir)
    logger.debug(f"Scan {scan_id}: exited tool loop, beginning completion sequence")
    # Carry forward triage states from previous scan via fingerprint matching
    if triage_map:
        for fd in all_findings:
            fp = fd.get("fingerprint")
            if fp and fp in triage_map:
                fd["triage_state"] = triage_map[fp]

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(all_findings)}
    for fd in all_findings:
        key = fd.get("severity", "INFO").lower()
        if key in summary:
            summary[key] += 1

    # Everything below has to be guarded: an exception here used to escape into
    # the executor's future, where nobody reads it, leaving the scan on
    # "running" for ever with no clue as to why.
    try:
        logger.debug(f"Scan {scan_id}: adding {len(all_findings)} findings to database")
        # bulk_insert_mappings skips per-row ORM object construction, which
        # keeps the write transaction short on scans with thousands of findings.
        db.bulk_insert_mappings(
            Finding, [{"scan_id": scan_id, **fd} for fd in all_findings]
        )

        scan.status = "completed"
        scan.finished_at = datetime.utcnow()
        scan.summary = summary
        scan.progress = {"steps": steps, "current_tool": None}
        if errors:
            scan.error_log = "\n".join(errors)

        logger.debug(f"Scan {scan_id}: committing to database")
        db.commit()
        logger.debug(f"Scan {scan_id}: database commit complete")
    except Exception as e:
        logger.error(f"Scan {scan_id}: failed to save results: {e}", exc_info=True)
        db.rollback()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.finished_at = datetime.utcnow()
                scan.error_log = f"Scan ran but results could not be saved: {e}"
                scan.progress = copy.deepcopy({"steps": steps, "current_tool": None})
                flag_modified(scan, "progress")
                db.commit()
        except Exception as inner:
            logger.error(f"Scan {scan_id}: could not even record the failure: {inner}")
        return

    # Persisted count is checked against what we meant to write — a silent
    # shortfall means something rolled the transaction back underneath us.
    saved = db.query(Finding).filter(Finding.scan_id == scan_id).count()
    if saved != len(all_findings):
        logger.error(
            f"Scan {scan_id}: only {saved} of {len(all_findings)} findings persisted"
        )

    try:
        _detect_duplicates(scan_id, db)
    except Exception as e:
        # Cosmetic step — never let it sink a completed scan
        logger.warning(f"Scan {scan_id}: duplicate detection failed: {e}")
    logger.info(f"Scan {scan_id} complete — {summary['total']} findings")
