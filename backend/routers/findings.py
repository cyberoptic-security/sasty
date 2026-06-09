from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import Finding

router = APIRouter()


VALID_TRIAGE_STATES = {"false_positive", "test_dev", "reported"}


class FindingUpdate(BaseModel):
    triage_state: str | None = None


class BulkTriageUpdate(BaseModel):
    ids: list[int]
    triage_state: str | None = None


@router.patch("/bulk")
def bulk_update_findings(body: BulkTriageUpdate, db: Session = Depends(get_db)):
    if body.triage_state is not None and body.triage_state not in VALID_TRIAGE_STATES:
        raise HTTPException(status_code=400, detail=f"Invalid triage_state: {body.triage_state}")
    if not body.ids:
        raise HTTPException(status_code=400, detail="No finding IDs provided")
    updated = (
        db.query(Finding)
        .filter(Finding.id.in_(body.ids))
        .update({Finding.triage_state: body.triage_state}, synchronize_session="fetch")
    )
    db.commit()
    return {"updated": updated}


@router.get("/scan/{scan_id}")
def get_findings(scan_id: int, db: Session = Depends(get_db)):
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.severity, Finding.rule_id, Finding.file_path, Finding.line_start)
        .all()
    )
    return [_finding_to_dict(f) for f in findings]


@router.patch("/{finding_id}")
def update_finding(finding_id: int, body: FindingUpdate, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if body.triage_state is not None and body.triage_state not in VALID_TRIAGE_STATES:
        raise HTTPException(status_code=400, detail=f"Invalid triage_state: {body.triage_state}")
    finding.triage_state = body.triage_state
    db.commit()
    db.refresh(finding)
    return _finding_to_dict(finding)


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "scan_id": f.scan_id,
        "tool": f.tool,
        "rule_id": f.rule_id,
        "rule_name": f.rule_name,
        "severity": f.severity,
        "category": f.category,
        "message": f.message,
        "file_path": f.file_path,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "col_start": f.col_start,
        "col_end": f.col_end,
        "matched_code": f.matched_code,
        "code_context": f.code_context,
        "fingerprint": f.fingerprint,
        "commit_hash": f.commit_hash,
        "commit_author": f.commit_author,
        "commit_date": f.commit_date,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "references": f.references,
        "triage_state": f.triage_state,
        "is_duplicate": f.is_duplicate or False,
        "duplicate_ids": f.duplicate_ids,
    }
