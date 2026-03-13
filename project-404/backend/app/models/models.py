import enum
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
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


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.pending, nullable=False)
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

    @property
    def scan_config(self) -> dict:
        return json.loads(self.scan_config_json or "{}")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    type = Column(Enum(AssetType), nullable=False)
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

    scan = relationship("Scan", back_populates="endpoints")

    @property
    def headers(self) -> dict:
        return json.loads(self.headers_json or "{}")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    confidence = Column(Enum(Confidence), nullable=False)
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
