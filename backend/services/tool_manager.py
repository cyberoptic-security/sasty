import os
import shutil
import stat
import platform
import subprocess
import sys
import zipfile
import tarfile
import tempfile
import logging
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

TOOLS_DIR = Path(__file__).parent.parent / "tools_bin"
TOOLS_DIR.mkdir(exist_ok=True)


def get_platform() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if ("aarch64" in machine or "arm64" in machine) else "x64"
    return system, arch


def get_tool_path(name: str) -> Optional[str]:
    system, _ = get_platform()
    ext = ".exe" if system == "windows" else ""
    local = TOOLS_DIR / f"{name}{ext}"
    if local.exists():
        return str(local)
    return shutil.which(name)


def _get_version(cmd: list[str]) -> Optional[str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.stdout.strip() or res.stderr.strip()
    except Exception:
        return None


def get_semgrep_version() -> Optional[str]:
    """Read semgrep version from installed package metadata.
    This works regardless of PATH — it reads directly from pip's registry."""
    try:
        from importlib.metadata import version
        return version("semgrep")
    except Exception:
        return None


def get_trufflehog_version() -> Optional[str]:
    path = get_tool_path("trufflehog")
    if not path:
        return None
    return _get_version([path, "--version"])


def get_hadolint_version() -> Optional[str]:
    path = get_tool_path("hadolint")
    if not path:
        return None
    return _get_version([path, "--version"])


async def _get_latest_release(owner: str, repo: str) -> dict:
    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/releases/latest",
            headers={"Accept": "application/vnd.github.v3+json"},
        )
        resp.raise_for_status()
        return resp.json()


async def _download_bytes(url: str) -> bytes:
    async with httpx.AsyncClient(follow_redirects=True, timeout=180) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.content


def _make_executable(path: Path):
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


async def update_trufflehog() -> str:
    """Download latest TruffleHog binary from GitHub releases."""
    system, arch = get_platform()
    release = await _get_latest_release("trufflesecurity", "trufflehog")
    version = release["tag_name"].lstrip("v")

    if system == "windows":
        asset_pattern = f"trufflehog_{version}_windows_amd64.zip"
        binary_name = "trufflehog.exe"
    elif system == "darwin":
        mac_arch = "arm64" if arch == "arm64" else "amd64"
        asset_pattern = f"trufflehog_{version}_darwin_{mac_arch}.tar.gz"
        binary_name = "trufflehog"
    else:
        linux_arch = "arm64" if arch == "arm64" else "amd64"
        asset_pattern = f"trufflehog_{version}_linux_{linux_arch}.tar.gz"
        binary_name = "trufflehog"

    asset = next(
        (a for a in release["assets"] if a["name"] == asset_pattern),
        next((a for a in release["assets"] if system in a["name"].lower() and "amd64" in a["name"]), None),
    )
    if not asset:
        raise RuntimeError(f"No trufflehog asset found for {system}/{arch}")

    # Construct direct download URL to avoid potential redirect issues with browser_download_url
    download_url = f"https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/{asset['name']}"
    data = await _download_bytes(download_url)
    dest = TOOLS_DIR / binary_name

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / asset["name"]
        archive.write_bytes(data)

        if asset["name"].endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                members = [m for m in zf.namelist() if "trufflehog" in m.lower() and not m.endswith("/")]
                if not members:
                    raise RuntimeError("No trufflehog binary found in zip")
                zf.extract(members[0], tmp_path)
                extracted_path = tmp_path / members[0]
                if extracted_path.is_file():
                    shutil.move(str(extracted_path), str(dest))
                else:
                    raise RuntimeError(f"Extracted path is not a file: {extracted_path}")
        else:
            with tarfile.open(archive) as tf:
                tf.extractall(tmp_path)
            # Find the trufflehog binary in extracted files
            found = False
            for root, dirs, files in os.walk(tmp_path):
                for file in files:
                    if file == "trufflehog" or file == "trufflehog.exe":
                        src = Path(root) / file
                        shutil.move(str(src), str(dest))
                        found = True
                        break
                if found:
                    break
            if not found:
                raise RuntimeError("No trufflehog binary found in tar archive")

    if system != "windows":
        _make_executable(dest)

    return version


async def update_hadolint() -> str:
    system, _ = get_platform()
    release = await _get_latest_release("hadolint", "hadolint")
    version = release["tag_name"].lstrip("v")

    asset_map = {
        "windows": ("hadolint-Windows-x86_64.exe", "hadolint.exe"),
        "darwin": ("hadolint-macOS-x86_64", "hadolint"),
        "linux": ("hadolint-Linux-x86_64", "hadolint"),
    }
    asset_name, binary_name = asset_map.get(system, asset_map["linux"])

    asset = next((a for a in release["assets"] if a["name"] == asset_name), None)
    if not asset:
        # Fallback: find any asset matching the OS name
        os_key = {"windows": "windows", "darwin": "macos", "linux": "linux"}[system]
        asset = next(
            (a for a in release["assets"] if os_key in a["name"].lower() and "x86_64" in a["name"].lower()),
            None,
        )
    if not asset:
        names = [a["name"] for a in release["assets"]]
        raise RuntimeError(f"No hadolint asset found for {system}. Available: {names}")

    data = await _download_bytes(asset["browser_download_url"])
    dest = TOOLS_DIR / binary_name
    dest.write_bytes(data)

    if system != "windows":
        _make_executable(dest)

    return version


async def update_semgrep() -> str:
    # Run pip targeting only semgrep, leaving running packages (uvicorn etc.) alone
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", "--upgrade-strategy", "only-if-needed", "semgrep"],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        stderr = result.stderr
        if "WinError 32" in stderr or "being used by another process" in stderr:
            raise RuntimeError(
                "Cannot update semgrep while the server is running on Windows. "
                "Stop the server, run: pip install --upgrade semgrep  then restart."
            )
        raise RuntimeError(stderr[:500])
    ver = get_semgrep_version()
    return ver or "unknown"


def get_bandit_version() -> Optional[str]:
    """Read bandit version from installed package metadata."""
    try:
        from importlib.metadata import version
        return version("bandit")
    except Exception:
        return None


def get_betterleaks_version() -> Optional[str]:
    path = get_tool_path("betterleaks")
    if not path:
        return None
    return _get_version([path, "version"])


def get_trivy_version() -> Optional[str]:
    path = get_tool_path("trivy")
    if not path:
        return None
    return _get_version([path, "version"])


async def update_bandit() -> str:
    """Install/upgrade bandit via pip."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", "--upgrade-strategy", "only-if-needed", "bandit"],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        stderr = result.stderr
        if "WinError 32" in stderr or "being used by another process" in stderr:
            raise RuntimeError(
                "Cannot update bandit while the server is running on Windows. "
                "Stop the server, run: pip install --upgrade bandit  then restart."
            )
        raise RuntimeError(stderr[:500])
    ver = get_bandit_version()
    return ver or "unknown"


async def update_betterleaks() -> str:
    """Download latest betterleaks binary from GitHub releases."""
    system, arch = get_platform()
    release = await _get_latest_release("betterleaks", "betterleaks")
    version = release["tag_name"].lstrip("v")

    if system == "windows":
        asset_pattern = f"betterleaks_{version}_windows_x64.zip"
        binary_name = "betterleaks.exe"
    elif system == "darwin":
        asset_pattern = f"betterleaks_{version}_darwin_{arch}.tar.gz"
        binary_name = "betterleaks"
    else:
        asset_pattern = f"betterleaks_{version}_linux_x64.tar.gz"
        binary_name = "betterleaks"

    asset = next(
        (a for a in release["assets"] if a["name"] == asset_pattern),
        next((a for a in release["assets"] if system in a["name"].lower() and ("x64" in a["name"] or "amd64" in a["name"])), None),
    )
    if not asset:
        raise RuntimeError(f"No betterleaks asset found for {system}/{arch}")

    data = await _download_bytes(asset["browser_download_url"])
    dest = TOOLS_DIR / binary_name

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / asset["name"]
        archive.write_bytes(data)

        if asset["name"].endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                members = [m for m in zf.namelist() if "betterleaks" in m.lower() and not m.endswith("/")]
                zf.extract(members[0], tmp_path)
                shutil.move(str(tmp_path / members[0]), str(dest))
        else:
            with tarfile.open(archive) as tf:
                members = [m for m in tf.getmembers() if "betterleaks" in m.name and m.isfile()]
                tf.extract(members[0], tmp_path)
                shutil.move(str(tmp_path / members[0].name), str(dest))

    if system != "windows":
        _make_executable(dest)

    return version


async def update_trivy() -> str:
    """Download latest Trivy binary from GitHub releases."""
    system, arch = get_platform()
    release = await _get_latest_release("aquasecurity", "trivy")
    version = release["tag_name"].lstrip("v")

    if system == "windows":
        asset_pattern = f"trivy_{version}_Windows-64bit.zip"
        binary_name = "trivy.exe"
    elif system == "darwin":
        mac_arch = "ARM64" if arch == "arm64" else "64bit"
        asset_pattern = f"trivy_{version}_macOS-{mac_arch}.tar.gz"
        binary_name = "trivy"
    else:
        asset_pattern = f"trivy_{version}_Linux-64bit.tar.gz"
        binary_name = "trivy"

    asset = next(
        (a for a in release["assets"] if a["name"] == asset_pattern),
        None,
    )
    if not asset:
        # Fallback: find any matching asset
        os_key = {"windows": "windows", "darwin": "macos", "linux": "linux"}[system]
        asset = next(
            (a for a in release["assets"] if os_key in a["name"].lower() and "64bit" in a["name"].lower()),
            None,
        )
    if not asset:
        names = [a["name"] for a in release["assets"]]
        raise RuntimeError(f"No trivy asset found for {system}/{arch}. Available: {names}")

    data = await _download_bytes(asset["browser_download_url"])
    dest = TOOLS_DIR / binary_name

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / asset["name"]
        archive.write_bytes(data)

        if asset["name"].endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                members = [m for m in zf.namelist() if "trivy" in m.lower() and not m.endswith("/")]
                zf.extract(members[0], tmp_path)
                shutil.move(str(tmp_path / members[0]), str(dest))
        else:
            with tarfile.open(archive) as tf:
                members = [m for m in tf.getmembers() if "trivy" in m.name and m.isfile()]
                tf.extract(members[0], tmp_path)
                shutil.move(str(tmp_path / members[0].name), str(dest))

    if system != "windows":
        _make_executable(dest)

    return version


async def get_all_tool_status() -> list[dict]:
    semgrep_ver = get_semgrep_version()
    betterleaks_ver = get_betterleaks_version()
    trufflehog_ver = get_trufflehog_version()
    hadolint_ver = get_hadolint_version()
    bandit_ver = get_bandit_version()
    trivy_ver = get_trivy_version()

    return [
        {
            "name": "semgrep",
            "description": "Multi-language static analysis (JS, TS, Node, Docker, Secrets)",
            "current_version": semgrep_ver,
            "installed": semgrep_ver is not None,
        },
        {
            "name": "betterleaks",
            "description": "Secret & credential scanner with archive and decode support",
            "current_version": betterleaks_ver,
            "installed": betterleaks_ver is not None,
        },
        {
            "name": "trufflehog",
            "description": "Secret scanner with live credential verification against APIs",
            "current_version": trufflehog_ver,
            "installed": trufflehog_ver is not None,
        },
        {
            "name": "hadolint",
            "description": "Dockerfile linting and best-practice checks",
            "current_version": hadolint_ver,
            "installed": hadolint_ver is not None,
        },
        {
            "name": "bandit",
            "description": "Python-focused security vulnerability scanner",
            "current_version": bandit_ver,
            "installed": bandit_ver is not None,
        },
        {
            "name": "trivy",
            "description": "Dependency vulnerability & IaC misconfiguration scanner",
            "current_version": trivy_ver,
            "installed": trivy_ver is not None,
        },
    ]
