import enum
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    BigInteger,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Confidence(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"


class AssetType(str, enum.Enum):
    subdomain = "subdomain"
    ip = "ip"
    host = "host"


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    root_domain = Column(String(255), nullable=False, unique=True, index=True)
    ownership_status = Column(String(64), default="unknown")
    created_at = Column(DateTime(timezone=True), default=utcnow)

    scans = relationship("Scan", back_populates="target")
    contexts = relationship("CompanyContext", back_populates="target")
    schedules = relationship("ScheduledScanJob", back_populates="target")
    diffs = relationship("ScanDiff", back_populates="target")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    status = Column(Enum(ScanStatus, native_enum=False), default=ScanStatus.pending, nullable=False)
    scan_config_json = Column(Text, default="{}")
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    posture_score = Column(Float, nullable=True)
    progress = Column(Integer, default=0)
    current_step = Column(String(128), default="queued")

    target = relationship("Target", back_populates="scans")
    assets = relationship("Asset", back_populates="scan")
    endpoints = relationship("Endpoint", back_populates="scan")
    findings = relationship("Finding", back_populates="scan")
    artifacts = relationship("Artifact", back_populates="scan")
    contexts = relationship("CompanyContext", back_populates="scan")
    diffs = relationship("ScanDiff", back_populates="scan", foreign_keys="ScanDiff.scan_id")

    @property
    def scan_config(self) -> dict:
        return json.loads(self.scan_config_json or "{}")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    type = Column(Enum(AssetType, native_enum=False), nullable=False)
    value = Column(String(512), nullable=False)
    metadata_json = Column(Text, default="{}")

    scan = relationship("Scan", back_populates="assets")

    @property
    def props(self) -> dict:
        return json.loads(self.metadata_json or "{}")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    host = Column(String(512), nullable=False)
    url = Column(Text, nullable=False)
    method = Column(String(16), default="GET")
    source = Column(String(64), default="crawl")
    requires_auth = Column(String(16), default="unknown")
    status_code = Column(Integer, nullable=True)
    title = Column(String(512), nullable=True)
    headers_json = Column(Text, default="{}")
    discovered_via = Column(String(16), default="unauth")
    unauth_status_code = Column(Integer, nullable=True)
    auth_status_code = Column(Integer, nullable=True)
    content_similarity = Column(Float, nullable=True)
    auth_only_navigation = Column(Boolean, default=False)

    scan = relationship("Scan", back_populates="endpoints")

    @property
    def headers(self) -> dict:
        return json.loads(self.headers_json or "{}")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    severity = Column(Enum(Severity, native_enum=False), nullable=False)
    confidence = Column(Enum(Confidence, native_enum=False), nullable=False)
    category = Column(String(64), nullable=False)
    affected_url = Column(Text, nullable=True)
    evidence_json = Column(Text, default="{}")
    recommendation = Column(Text, nullable=True)
    fingerprint_hash = Column(String(64), nullable=True, index=True)

    scan = relationship("Scan", back_populates="findings")

    @property
    def evidence(self) -> dict:
        return json.loads(self.evidence_json or "{}")

    @staticmethod
    def make_fingerprint(scan_id: int, title: str, affected_url: str) -> str:
        raw = f"{scan_id}|{title}|{affected_url or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    kind = Column(String(64), nullable=False)
    path_or_url = Column(Text, nullable=True)
    metadata_json = Column(Text, default="{}")

    scan = relationship("Scan", back_populates="artifacts")


class CompanyContext(Base):
    __tablename__ = "company_contexts"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    source_url = Column(Text, nullable=False)
    description_raw = Column(Text, nullable=False)
    industry = Column(String(64), nullable=True)
    business_model = Column(String(64), nullable=True)
    keywords_json = Column(Text, default="[]")
    likely_attack_surface_json = Column(Text, default="[]")
    where_to_look_first = Column(Text, nullable=True)
    summary_hash = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    target = relationship("Target", back_populates="contexts")
    scan = relationship("Scan", back_populates="contexts")

    @property
    def keywords(self) -> list[str]:
        return json.loads(self.keywords_json or "[]")

    @property
    def likely_attack_surface(self) -> list[str]:
        return json.loads(self.likely_attack_surface_json or "[]")


class ScheduledScanJob(Base):
    __tablename__ = "scheduled_scan_jobs"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    scan_config_json = Column(Text, default="{}")
    interval_minutes = Column(Integer, nullable=True)
    cron_expr = Column(String(128), nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    alert_webhook_url = Column(Text, nullable=True)
    diff_threshold_json = Column(Text, default="{}")
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    target = relationship("Target", back_populates="schedules")

    @property
    def scan_config(self) -> dict:
        return json.loads(self.scan_config_json or "{}")

    @property
    def diff_threshold(self) -> dict:
        return json.loads(self.diff_threshold_json or "{}")


class ScanDiff(Base):
    __tablename__ = "scan_diffs"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    previous_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    summary_json = Column(Text, default="{}")
    webhook_sent = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    target = relationship("Target", back_populates="diffs")
    scan = relationship("Scan", back_populates="diffs", foreign_keys=[scan_id])

    @property
    def summary(self) -> dict:
        return json.loads(self.summary_json or "{}")
