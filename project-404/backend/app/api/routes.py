"""FastAPI route handlers."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Endpoint, Finding, Scan, ScanStatus, Target
from app.utils.crypto import encrypt_secret, redact_secret

router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class AuthConfig(BaseModel):
    cookie_header: Optional[str] = None
    authorization_header: Optional[str] = None


class ScanConfig(BaseModel):
    max_depth: int = Field(default=2, ge=1, le=5)


class CreateScanRequest(BaseModel):
    url: str
    scan_config: Optional[ScanConfig] = None
    auth_config: Optional[AuthConfig] = None


class ScanResponse(BaseModel):
    scan_id: int
    status: str
    progress: int
    current_step: str
    posture_score: Optional[float]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    target: Optional[str]


class AssetResponse(BaseModel):
    id: int
    type: str
    value: str
    metadata: dict


class EndpointResponse(BaseModel):
    id: int
    host: str
    url: str
    method: str
    source: str
    requires_auth: str
    status_code: Optional[int]
    title: Optional[str]


class FindingResponse(BaseModel):
    id: int
    title: str
    severity: str
    confidence: str
    category: str
    affected_url: Optional[str]
    evidence: dict
    recommendation: Optional[str]
    fingerprint_hash: Optional[str]


# ---------------------------------------------------------------------------
# POST /api/scans
# ---------------------------------------------------------------------------

@router.post("/scans", status_code=201)
def create_scan(body: CreateScanRequest, db: Session = Depends(get_db)):
    from app.tasks.scan_pipeline import run_scan
    from app.utils.scope import extract_root_domain, normalize_url

    url = normalize_url(body.url)
    # Get or create target
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or ""
    root_domain = extract_root_domain(host)

    target = db.query(Target).filter(Target.root_domain == root_domain).first()
    if not target:
        target = Target(root_domain=root_domain)
        db.add(target)
        db.flush()

    # Build scan config
    sc = (body.scan_config or ScanConfig()).model_dump()
    sc["url"] = url

    # Encrypt auth config if provided
    if body.auth_config:
        ac = body.auth_config.model_dump(exclude_none=True)
        sc["auth_config"] = encrypt_secret(json.dumps(ac))

    scan = Scan(
        target_id=target.id,
        scan_config_json=json.dumps(sc),
        status=ScanStatus.pending,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Dispatch Celery task
    run_scan.delay(scan.id)

    return {"scan_id": scan.id}


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    return ScanResponse(
        scan_id=scan.id,
        status=scan.status.value,
        progress=scan.progress or 0,
        current_step=scan.current_step or "queued",
        posture_score=scan.posture_score,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        target=target.root_domain if target else None,
    )


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}/assets
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/assets")
def get_assets(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    return [
        AssetResponse(
            id=a.id,
            type=a.type.value,
            value=a.value,
            metadata=a.props,
        )
        for a in assets
    ]


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}/endpoints
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/endpoints")
def get_endpoints(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    eps = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    return [
        EndpointResponse(
            id=ep.id,
            host=ep.host,
            url=ep.url,
            method=ep.method,
            source=ep.source,
            requires_auth=ep.requires_auth,
            status_code=ep.status_code,
            title=ep.title,
        )
        for ep in eps
    ]


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}/findings
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/findings")
def get_findings(scan_id: int, severity: Optional[str] = None,
                  db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    findings = q.all()
    return [
        FindingResponse(
            id=f.id,
            title=f.title,
            severity=f.severity.value,
            confidence=f.confidence.value,
            category=f.category,
            affected_url=f.affected_url,
            evidence=f.evidence,
            recommendation=f.recommendation,
            fingerprint_hash=f.fingerprint_hash,
        )
        for f in findings
    ]


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}/report
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/report")
def get_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    return {
        "scan_id": scan_id,
        "target": target.root_domain if target else None,
        "status": scan.status.value,
        "posture_score": scan.posture_score,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "summary": {
            "assets": len(assets),
            "endpoints": len(endpoints),
            "findings": len(findings),
            "severity_breakdown": severity_counts,
        },
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "category": f.category,
                "affected_url": f.affected_url,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
    }
