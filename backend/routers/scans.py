import logging
import shutil
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import SessionLocal, get_db
from models import Finding, Scan
from services.scan_runner import get_raw_output_dir, request_cancel, run_scan

import os
_db_path = os.environ.get("SASTY_DB_PATH", "./sasty.db")
UPLOADS_DIR = Path(os.path.dirname(os.path.abspath(_db_path))) / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

router = APIRouter()
logger = logging.getLogger(__name__)
_executor = ThreadPoolExecutor(max_workers=2)


class CustomCommand(BaseModel):
    label: str
    command: str


class ScanCreate(BaseModel):
    path: str
    label: str | None = None
    tools: list[str] = ["semgrep", "betterleaks", "trufflehog", "hadolint", "bandit", "trivy"]
    semgrep_configs: list[str] = ["auto"]
    tool_options: dict[str, dict] | None = None
    custom_commands: list[CustomCommand] | None = None


def _scan_in_thread(scan_id: int, path: str, tools: list[str], semgrep_configs: list[str], tool_options: dict | None = None, custom_commands: list[dict] | None = None):
    db = SessionLocal()
    try:
        run_scan(scan_id, path, tools, semgrep_configs, db, tool_options=tool_options, custom_commands=custom_commands)
    finally:
        db.close()


@router.get("")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.started_at.desc()).all()
    return [_scan_to_dict(s) for s in scans]


@router.post("", status_code=201)
def create_scan(body: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    path = str(Path(body.path).resolve())
    if not Path(path).exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {path}")

    custom_cmds = [c.model_dump() for c in body.custom_commands] if body.custom_commands else None

    scan = Scan(
        path=path,
        label=body.label,
        tools_used=body.tools,
        semgrep_configs=body.semgrep_configs,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        _executor.submit,
        _scan_in_thread,
        scan.id,
        path,
        body.tools,
        body.semgrep_configs,
        body.tool_options,
        custom_cmds,
    )

    return _scan_to_dict(scan)


@router.post("/upload", status_code=201)
async def upload_scan(
    file: UploadFile = File(...),
    label: str = Form(""),
    tools: str = Form("semgrep,betterleaks,trufflehog,hadolint,bandit,trivy"),
    semgrep_configs: str = Form("auto"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")

    contents = await file.read()

    tools_list = [t.strip() for t in tools.split(",") if t.strip()]
    configs_list = [c.strip() for c in semgrep_configs.split(",") if c.strip()]
    scan_label = label.strip() or file.filename.rsplit(".", 1)[0]

    # Create scan first so we can use its ID for the persistent upload dir
    scan = Scan(
        path="(uploading)",
        label=scan_label,
        tools_used=tools_list,
        semgrep_configs=configs_list,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Extract to persistent directory (survives restarts, enables re-scan)
    upload_dir = UPLOADS_DIR / str(scan.id)
    try:
        upload_dir.mkdir(parents=True, exist_ok=True)
        zip_path = upload_dir / "upload.zip"
        zip_path.write_bytes(contents)

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Security: reject paths that escape the extract dir
            for member in zf.namelist():
                resolved = (upload_dir / member).resolve()
                if not str(resolved).startswith(str(upload_dir.resolve())):
                    shutil.rmtree(upload_dir, ignore_errors=True)
                    db.delete(scan)
                    db.commit()
                    raise HTTPException(status_code=400, detail="Zip contains unsafe path traversal")
            zf.extractall(upload_dir)

        zip_path.unlink()

        # If the zip contained a single top-level directory, scan that
        entries = [e for e in upload_dir.iterdir()]
        scan_path = str(entries[0]) if len(entries) == 1 and entries[0].is_dir() else str(upload_dir)
    except zipfile.BadZipFile:
        shutil.rmtree(upload_dir, ignore_errors=True)
        db.delete(scan)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid zip file")
    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(upload_dir, ignore_errors=True)
        db.delete(scan)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Failed to extract zip: {e}")

    scan.path = scan_path
    db.commit()

    background_tasks.add_task(
        _executor.submit,
        _scan_in_thread,
        scan.id,
        scan_path,
        tools_list,
        configs_list,
    )

    return _scan_to_dict(scan)


class RescanRequest(BaseModel):
    finding_ids: list[int] | None = None  # None = full rescan


@router.post("/{scan_id}/rescan", status_code=201)
def rescan(scan_id: int, body: RescanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Re-scan: full codebase or only files with selected findings."""
    original = db.query(Scan).filter(Scan.id == scan_id).first()
    if not original:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not Path(original.path).exists():
        raise HTTPException(status_code=400, detail=f"Path no longer exists: {original.path}")

    tools = list(original.tools_used or [])
    configs = list(original.semgrep_configs or [])

    # Collect triage states from the current scan's findings keyed by fingerprint
    triage_map = {}
    old_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    for f in old_findings:
        if f.fingerprint and f.triage_state:
            triage_map[f.fingerprint] = f.triage_state

    if body.finding_ids:
        # Scope to only the tools that produced the selected findings
        selected = db.query(Finding).filter(Finding.id.in_(body.finding_ids), Finding.scan_id == scan_id).all()
        if not selected:
            raise HTTPException(status_code=400, detail="No matching findings found")
        tools = list({f.tool for f in selected})

    # Resolve root scan for versioning (follow parent chain to root)
    root_id = original.parent_scan_id or original.id
    # Count existing versions to determine next version number
    from sqlalchemy import func
    max_version = db.query(func.max(Scan.version)).filter(
        (Scan.id == root_id) | (Scan.parent_scan_id == root_id)
    ).scalar() or 1
    next_version = max_version + 1

    # Inherit the original label (strip any old "(re-scan)" suffixes)
    base_label = original.label or original.path.split("/")[-1].split("\\")[-1]
    import re as _re
    base_label = _re.sub(r"\s*\(re-scan.*?\)\s*$", "", base_label)

    scan = Scan(
        path=original.path,
        label=base_label,
        tools_used=tools,
        semgrep_configs=configs,
        parent_scan_id=root_id,
        version=next_version,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        _executor.submit,
        _rescan_in_thread,
        scan.id,
        original.path,
        tools,
        configs,
        triage_map,
    )

    return _scan_to_dict(scan)


def _rescan_in_thread(scan_id: int, path: str, tools: list[str], configs: list[str], triage_map: dict[str, str]):
    db = SessionLocal()
    try:
        run_scan(scan_id, path, tools, configs, db, triage_map=triage_map)
    finally:
        db.close()


@router.post("/import", status_code=201)
async def import_scan(
    file: UploadFile = File(...),
    label: str = Form(""),
    db: Session = Depends(get_db),
):
    """Import raw semgrep/gitleaks/hadolint JSON output and create a scan from it."""
    if not file.filename or not file.filename.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="Only .json files are supported")

    contents = await file.read()
    try:
        data = __import__("json").loads(contents)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON file")

    # Detect format and parse
    from services.parsers import semgrep_parser, gitleaks_parser, betterleaks_parser, hadolint_parser, bandit_parser, trivy_parser
    from services.scan_runner import get_raw_output_dir, _enrich_with_context

    findings: list[dict] = []
    tool_name = "unknown"

    if isinstance(data, dict) and "results" in data:
        # Could be semgrep (results is list of findings) or bandit (results is list with test_id)
        results = data["results"]
        if isinstance(results, list) and len(results) > 0 and "test_id" in results[0]:
            tool_name = "bandit"
            findings = bandit_parser.parse(data)
        else:
            tool_name = "semgrep"
            findings = semgrep_parser.parse(data)
    elif isinstance(data, dict) and "Results" in data:
        # Trivy format (capital R)
        tool_name = "trivy"
        findings = trivy_parser.parse(data)
    elif isinstance(data, list) and len(data) > 0:
        first = data[0]
        if "RuleID" in first or "Match" in first or "Secret" in first:
            # Gitleaks / betterleaks format (same structure — default to gitleaks)
            tool_name = "gitleaks"
            findings = gitleaks_parser.parse(data)
        elif "code" in first and "message" in first and "level" in first:
            # Hadolint format
            tool_name = "hadolint"
            findings = hadolint_parser.parse(data)
        else:
            raise HTTPException(status_code=400, detail="Unrecognised JSON format — expected semgrep, gitleaks, betterleaks, hadolint, bandit, or trivy output")
    elif isinstance(data, list) and len(data) == 0:
        tool_name = "semgrep"
    else:
        raise HTTPException(status_code=400, detail="Unrecognised JSON format — expected semgrep, gitleaks, betterleaks, hadolint, bandit, or trivy output")

    scan_label = label.strip() or file.filename.rsplit(".", 1)[0]

    scan = Scan(
        path="(imported)",
        label=scan_label,
        tools_used=[tool_name],
        semgrep_configs=[],
        status="completed",
        finished_at=__import__("datetime").datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Save raw output for re-export
    try:
        raw_dir = get_raw_output_dir(scan.id)
        (raw_dir / f"{tool_name}.json").write_bytes(contents)
    except Exception:
        pass

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(findings)}
    for fd in findings:
        key = fd.get("severity", "INFO").lower()
        if key in summary:
            summary[key] += 1
        db.add(Finding(scan_id=scan.id, **fd))

    scan.summary = summary
    db.commit()

    return _scan_to_dict(scan)


@router.get("/{scan_id}/raw-output")
def get_raw_output(scan_id: int, db: Session = Depends(get_db)):
    """Download raw tool output as a zip of JSON files."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    raw_dir = get_raw_output_dir(scan_id)
    json_files = list(raw_dir.glob("*.json"))
    if not json_files:
        raise HTTPException(status_code=404, detail="No raw output available for this scan")

    # If only one tool, return the JSON directly
    if len(json_files) == 1:
        return FileResponse(
            str(json_files[0]),
            media_type="application/json",
            filename=f"sasty-scan-{scan_id}-{json_files[0].stem}.json",
        )

    # Multiple tools — zip them up
    zip_path = Path(tempfile.mktemp(suffix=".zip", prefix=f"sasty_raw_{scan_id}_"))
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in json_files:
            zf.write(f, f.name)

    return FileResponse(
        str(zip_path),
        media_type="application/zip",
        filename=f"sasty-scan-{scan_id}-raw.zip",
    )


@router.get("/check-git")
def check_git(path: str):
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {path}")
    is_git = (resolved / ".git").is_dir()
    return {"is_git": is_git}


@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_dict(scan)


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("running", "pending"):
        raise HTTPException(status_code=409, detail="Scan is not running")
    request_cancel(scan_id)
    return {"status": "cancelling"}


@router.post("/{scan_id}/reset")
def reset_scan(scan_id: int, db: Session = Depends(get_db)):
    """Force-reset a stuck scan that's hung in 'running' state."""
    from datetime import datetime
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "running":
        raise HTTPException(status_code=409, detail=f"Can only reset running scans (current status: {scan.status})")

    scan.status = "failed"
    scan.error_log = "Scan process hung or crashed — manually reset by user"
    scan.finished_at = datetime.utcnow()
    db.commit()

    logger.info(f"Scan {scan_id} forcefully reset from running to failed")
    return {"status": "reset", "message": "Scan marked as failed and can be deleted or re-run"}


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == "running":
        raise HTTPException(status_code=409, detail="Cannot delete a running scan")
    # Clean up uploaded files and raw output
    upload_path = UPLOADS_DIR / str(scan_id)
    if upload_path.exists():
        shutil.rmtree(upload_path, ignore_errors=True)
    from services.scan_runner import RAW_OUTPUT_DIR
    raw_path = RAW_OUTPUT_DIR / str(scan_id)
    if raw_path.exists():
        shutil.rmtree(raw_path, ignore_errors=True)
    db.delete(scan)
    db.commit()


def _scan_to_dict(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "path": scan.path,
        "label": scan.label,
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "tools_used": scan.tools_used or [],
        "semgrep_configs": scan.semgrep_configs or [],
        "summary": scan.summary,
        "progress": scan.progress,
        "error_log": scan.error_log,
        "parent_scan_id": scan.parent_scan_id,
        "version": scan.version or 1,
    }
