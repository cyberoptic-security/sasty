from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    path = Column(String, nullable=False)
    label = Column(String, nullable=True)
    status = Column(String, default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    tools_used = Column(JSON, default=list)
    semgrep_configs = Column(JSON, default=list)
    summary = Column(JSON, nullable=True)
    progress = Column(JSON, nullable=True)
    error_log = Column(Text, nullable=True)
    parent_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    version = Column(Integer, default=1)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan", foreign_keys="[Finding.scan_id]")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    tool = Column(String, nullable=False)
    rule_id = Column(String, nullable=False)
    rule_name = Column(String, nullable=True)
    severity = Column(String, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category = Column(String, nullable=True)
    message = Column(Text, nullable=False)

    file_path = Column(String, nullable=False)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    col_start = Column(Integer, nullable=True)
    col_end = Column(Integer, nullable=True)

    matched_code = Column(Text, nullable=True)
    code_context = Column(JSON, nullable=True)

    fingerprint = Column(String, nullable=True)
    commit_hash = Column(String, nullable=True)
    commit_author = Column(String, nullable=True)
    commit_date = Column(String, nullable=True)
    cwe = Column(JSON, nullable=True)
    owasp = Column(JSON, nullable=True)
    references = Column(JSON, nullable=True)
    tags = Column(JSON, nullable=True)

    is_false_positive = Column(Boolean, default=False)
    fp_note = Column(Text, nullable=True)
    triage_state = Column(String, nullable=True)  # null=open, false_positive, test_dev, reported

    is_duplicate = Column(Boolean, default=False)
    duplicate_ids = Column(JSON, nullable=True)  # list of finding IDs that share the same location

    scan = relationship("Scan", back_populates="findings")
