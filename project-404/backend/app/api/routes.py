"""FastAPI route handlers."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    Asset,
    CompanyContext,
    Endpoint,
    Finding,
    Scan,
    ScanDiff,
    ScanStatus,
    ScheduledScanJob,
    Target,
)
from app.services.company_context import generate_company_context
from app.utils.crypto import encrypt_secret
from app.utils.scope import extract_root_domain, normalize_url

router = APIRouter()

SCHEDULE_INTERVALS = {
    "daily": 24 * 60,
    "weekly": 7 * 24 * 60,
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _interval_name(minutes: int | None) -> Optional[str]:
    for name, value in SCHEDULE_INTERVALS.items():
        if value == minutes:
            return name
    return None


def _schedule_next_run(interval_minutes: int) -> datetime:
    return utcnow() + timedelta(minutes=interval_minutes)


def _context_to_dict(ctx: CompanyContext | None) -> Optional[dict]:
    if not ctx:
        return None
    return {
        "id": ctx.id,
        "target_id": ctx.target_id,
        "scan_id": ctx.scan_id,
        "source_url": ctx.source_url,
        "description_raw": ctx.description_raw,
        "industry": ctx.industry,
        "business_model": ctx.business_model,
        "keywords": ctx.keywords,
        "likely_attack_surface": ctx.likely_attack_surface,
        "where_to_look_first": ctx.where_to_look_first,
        "summary_hash": ctx.summary_hash,
        "created_at": ctx.created_at,
    }


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
    target_id: int
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
    discovered_via: str
    requires_auth: str
    status_code: Optional[int]
    unauth_status_code: Optional[int]
    auth_status_code: Optional[int]
    content_similarity: Optional[float]
    auth_only_navigation: bool
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


class GenerateContextRequest(BaseModel):
    url: str


class CreateScheduleRequest(BaseModel):
    interval: str = Field(default="daily", pattern="^(daily|weekly)$")
    enabled: bool = True
    alert_webhook_url: Optional[str] = None
    diff_threshold: dict = Field(default_factory=dict)


class UpdateScheduleRequest(BaseModel):
    interval: Optional[str] = Field(default=None, pattern="^(daily|weekly)$")
    enabled: Optional[bool] = None
    alert_webhook_url: Optional[str] = None
    diff_threshold: Optional[dict] = None


class ScheduleResponse(BaseModel):
    id: int
    target_id: int
    interval: Optional[str]
    interval_minutes: Optional[int]
    cron_expr: Optional[str]
    enabled: bool
    last_scan_id: Optional[int]
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    alert_webhook_url: Optional[str]
    diff_threshold: dict
    created_at: Optional[datetime]


def _schedule_to_response(job: ScheduledScanJob) -> ScheduleResponse:
    return ScheduleResponse(
        id=job.id,
        target_id=job.target_id,
        interval=_interval_name(job.interval_minutes),
        interval_minutes=job.interval_minutes,
        cron_expr=job.cron_expr,
        enabled=bool(job.enabled),
        last_scan_id=job.last_scan_id,
        last_run_at=job.last_run_at,
        next_run_at=job.next_run_at,
        alert_webhook_url=job.alert_webhook_url,
        diff_threshold=job.diff_threshold,
        created_at=job.created_at,
    )


@router.post("/company-context/generate")
def generate_context(body: GenerateContextRequest):
    url = normalize_url(body.url)
    res = generate_company_context(url)
    return {
        "source_url": res.source_url,
        "description_raw": res.description_raw,
        "industry": res.industry,
        "business_model": res.business_model,
        "keywords": res.keywords,
        "likely_attack_surface": res.likely_attack_surface,
        "where_to_look_first": res.where_to_look_first,
        "summary_hash": res.summary_hash,
    }


@router.post("/scans", status_code=201)
def create_scan(body: CreateScanRequest, db: Session = Depends(get_db)):
    from app.tasks.scan_pipeline import run_scan

    url = normalize_url(body.url)
    host = urlparse(url).hostname or ""
    root_domain = extract_root_domain(host)

    target = db.query(Target).filter(Target.root_domain == root_domain).first()
    if not target:
        target = Target(root_domain=root_domain)
        db.add(target)
        db.flush()

    sc = (body.scan_config or ScanConfig()).model_dump()
    sc["url"] = url
    if body.auth_config:
        sc["auth_config"] = encrypt_secret(json.dumps(body.auth_config.model_dump(exclude_none=True)))

    # Optional target-level baseline context (scan pipeline also persists scan-specific context).
    has_target_context = db.query(CompanyContext).filter(
        CompanyContext.target_id == target.id,
        CompanyContext.scan_id.is_(None),
    ).first()
    if not has_target_context:
        try:
            ctx = generate_company_context(url)
            db.add(
                CompanyContext(
                    target_id=target.id,
                    scan_id=None,
                    source_url=ctx.source_url,
                    description_raw=ctx.description_raw,
                    industry=ctx.industry,
                    business_model=ctx.business_model,
                    keywords_json=json.dumps(ctx.keywords),
                    likely_attack_surface_json=json.dumps(ctx.likely_attack_surface),
                    where_to_look_first=ctx.where_to_look_first,
                    summary_hash=ctx.summary_hash,
                )
            )
            db.flush()
        except Exception:
            pass

    scan = Scan(target_id=target.id, scan_config_json=json.dumps(sc), status=ScanStatus.pending)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    run_scan.delay(scan.id)
    return {"scan_id": scan.id}


@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    return ScanResponse(
        scan_id=scan.id,
        target_id=scan.target_id,
        status=scan.status.value,
        progress=scan.progress or 0,
        current_step=scan.current_step or "queued",
        posture_score=scan.posture_score,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        target=target.root_domain if target else None,
    )


@router.get("/scans/{scan_id}/assets")
def get_assets(scan_id: int, db: Session = Depends(get_db)):
    if not db.query(Scan).filter(Scan.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    return [AssetResponse(id=a.id, type=a.type.value, value=a.value, metadata=a.props) for a in assets]


@router.get("/scans/{scan_id}/endpoints")
def get_endpoints(scan_id: int, db: Session = Depends(get_db)):
    if not db.query(Scan).filter(Scan.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")
    eps = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    return [
        EndpointResponse(
            id=ep.id,
            host=ep.host,
            url=ep.url,
            method=ep.method,
            source=ep.source,
            discovered_via=ep.discovered_via or "unauth",
            requires_auth=ep.requires_auth,
            status_code=ep.status_code,
            unauth_status_code=ep.unauth_status_code,
            auth_status_code=ep.auth_status_code,
            content_similarity=ep.content_similarity,
            auth_only_navigation=bool(ep.auth_only_navigation),
            title=ep.title,
        )
        for ep in eps
    ]


@router.get("/scans/{scan_id}/findings")
def get_findings(scan_id: int, severity: Optional[str] = None, db: Session = Depends(get_db)):
    if not db.query(Scan).filter(Scan.id == scan_id).first():
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


@router.get("/scans/{scan_id}/context")
def get_scan_context(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    ctx = (
        db.query(CompanyContext)
        .filter(CompanyContext.scan_id == scan_id)
        .order_by(CompanyContext.created_at.desc())
        .first()
    )
    if ctx:
        return _context_to_dict(ctx)

    target_ctx = (
        db.query(CompanyContext)
        .filter(CompanyContext.target_id == scan.target_id)
        .order_by(CompanyContext.created_at.desc())
        .first()
    )
    return _context_to_dict(target_ctx)


@router.get("/targets/{target_id}/context/latest")
def get_target_context(target_id: int, db: Session = Depends(get_db)):
    if not db.query(Target).filter(Target.id == target_id).first():
        raise HTTPException(status_code=404, detail="Target not found")
    ctx = (
        db.query(CompanyContext)
        .filter(CompanyContext.target_id == target_id)
        .order_by(CompanyContext.created_at.desc())
        .first()
    )
    return _context_to_dict(ctx)


@router.post("/scans/{scan_id}/schedules", response_model=ScheduleResponse, status_code=201)
def create_schedule(scan_id: int, body: CreateScheduleRequest, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    minutes = SCHEDULE_INTERVALS[body.interval]
    schedule = ScheduledScanJob(
        target_id=scan.target_id,
        scan_config_json=scan.scan_config_json,
        interval_minutes=minutes,
        cron_expr=None,
        enabled=body.enabled,
        next_run_at=_schedule_next_run(minutes) if body.enabled else None,
        alert_webhook_url=body.alert_webhook_url,
        diff_threshold_json=json.dumps(body.diff_threshold or {}),
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return _schedule_to_response(schedule)


@router.get("/targets/{target_id}/schedules")
def list_schedules(target_id: int, db: Session = Depends(get_db)):
    if not db.query(Target).filter(Target.id == target_id).first():
        raise HTTPException(status_code=404, detail="Target not found")
    rows = db.query(ScheduledScanJob).filter(ScheduledScanJob.target_id == target_id).all()
    return [_schedule_to_response(r) for r in rows]


@router.patch("/schedules/{schedule_id}", response_model=ScheduleResponse)
def update_schedule(schedule_id: int, body: UpdateScheduleRequest, db: Session = Depends(get_db)):
    schedule = db.query(ScheduledScanJob).filter(ScheduledScanJob.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if body.interval:
        schedule.interval_minutes = SCHEDULE_INTERVALS[body.interval]
        if schedule.enabled:
            schedule.next_run_at = _schedule_next_run(schedule.interval_minutes)
    if body.enabled is not None:
        schedule.enabled = body.enabled
        if body.enabled and schedule.interval_minutes:
            schedule.next_run_at = _schedule_next_run(schedule.interval_minutes)
        if not body.enabled:
            schedule.next_run_at = None
    if body.alert_webhook_url is not None:
        schedule.alert_webhook_url = body.alert_webhook_url
    if body.diff_threshold is not None:
        schedule.diff_threshold_json = json.dumps(body.diff_threshold)
    db.commit()
    db.refresh(schedule)
    return _schedule_to_response(schedule)


@router.get("/scans/{scan_id}/diff")
def get_scan_diff(scan_id: int, db: Session = Depends(get_db)):
    if not db.query(Scan).filter(Scan.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")
    diff = db.query(ScanDiff).filter(ScanDiff.scan_id == scan_id).order_by(ScanDiff.created_at.desc()).first()
    if not diff:
        return {"scan_id": scan_id, "diff": None}
    return {
        "scan_id": scan_id,
        "previous_scan_id": diff.previous_scan_id,
        "webhook_sent": bool(diff.webhook_sent),
        "summary": diff.summary,
        "created_at": diff.created_at,
    }


@router.get("/scans/{scan_id}/changes")
def get_scan_changes(scan_id: int, db: Session = Depends(get_db)):
    return get_scan_diff(scan_id, db)


@router.get("/scans/{scan_id}/summary")
def get_scan_summary(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    context = (
        db.query(CompanyContext)
        .filter(CompanyContext.scan_id == scan_id)
        .order_by(CompanyContext.created_at.desc())
        .first()
    )
    diff = db.query(ScanDiff).filter(ScanDiff.scan_id == scan_id).order_by(ScanDiff.created_at.desc()).first()
    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
    top_risks = sorted(findings, key=lambda x: ["info", "low", "medium", "high", "critical"].index(x.severity.value), reverse=True)[:5]
    return {
        "scan_id": scan_id,
        "posture_score": scan.posture_score,
        "counts": {
            "endpoints": len(endpoints),
            "findings": len(findings),
            "severity_breakdown": severity_counts,
        },
        "top_risks": [
            {"title": f.title, "severity": f.severity.value, "url": f.affected_url}
            for f in top_risks
        ],
        "context": _context_to_dict(context),
        "changes_since_last_scan": diff.summary if diff else None,
    }


@router.get("/scans/{scan_id}/report")
def get_report(scan_id: int, db: Session = Depends(get_db)):
    return get_scan_summary(scan_id, db)


def _csv_response(filename: str, rows: list[dict]) -> StreamingResponse:
    buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    data = buf.getvalue()
    return StreamingResponse(
        iter([data]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/export/endpoints.csv")
def export_endpoints_csv(scan_id: int, db: Session = Depends(get_db)):
    if not db.query(Scan).filter(Scan.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")
    eps = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    rows = [
        {
            "id": ep.id,
            "method": ep.method,
            "url": ep.url,
            "source": ep.source,
            "status_code": ep.status_code,
            "requires_auth": ep.requires_auth,
            "discovered_via": ep.discovered_via,
            "unauth_status_code": ep.unauth_status_code,
            "auth_status_code": ep.auth_status_code,
            "content_similarity": ep.content_similarity,
            "auth_only_navigation": bool(ep.auth_only_navigation),
        }
        for ep in eps
    ]
    return _csv_response(f"scan-{scan_id}-endpoints.csv", rows)


@router.get("/scans/{scan_id}/export/findings.csv")
def export_findings_csv(scan_id: int, db: Session = Depends(get_db)):
    if not db.query(Scan).filter(Scan.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    rows = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "category": f.category,
            "affected_url": f.affected_url,
            "recommendation": f.recommendation,
            "fingerprint_hash": f.fingerprint_hash,
        }
        for f in findings
    ]
    return _csv_response(f"scan-{scan_id}-findings.csv", rows)


@router.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    summary = get_scan_summary(scan_id, db)
    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).limit(100).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).limit(100).all()

    context = summary.get("context") or {}
    changes = summary.get("changes_since_last_scan") or {}
    ep_rows = "".join(
        f"<tr><td>{ep.method}</td><td>{ep.url}</td><td>{ep.source}</td><td>{ep.status_code or ''}</td></tr>"
        for ep in endpoints
    )
    finding_rows = "".join(
        f"<tr><td>{f.severity.value}</td><td>{f.title}</td><td>{f.affected_url or ''}</td></tr>"
        for f in findings
    )
    top_risks = "".join(f"<li>{r['severity'].upper()}: {r['title']}</li>" for r in summary["top_risks"])
    attack_surface = "".join(f"<li>{s}</li>" for s in context.get("likely_attack_surface", []))

    html = f"""
    <html>
    <head>
      <title>Scan {scan_id} Report</title>
      <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; color: #111; }}
        h1,h2 {{ margin-bottom: 8px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f5f5f5; }}
        .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
        .card {{ border: 1px solid #ddd; padding: 10px; border-radius: 6px; }}
      </style>
    </head>
    <body>
      <h1>Executive Summary: Scan #{scan_id}</h1>
      <div class="grid">
        <div class="card"><strong>Posture Score</strong><div>{summary['posture_score']}</div></div>
        <div class="card"><strong>Endpoints</strong><div>{summary['counts']['endpoints']}</div></div>
        <div class="card"><strong>Findings</strong><div>{summary['counts']['findings']}</div></div>
      </div>
      <h2>Top Risks</h2>
      <ul>{top_risks}</ul>
      <h2>Company Context</h2>
      <p><strong>Industry:</strong> {context.get('industry', '')}</p>
      <p><strong>Business model:</strong> {context.get('business_model', '')}</p>
      <p>{context.get('description_raw', '')}</p>
      <h3>Where to look first</h3>
      <p>{context.get('where_to_look_first', '')}</p>
      <ul>{attack_surface}</ul>
      <h2>Changes Since Previous Scan</h2>
      <pre>{json.dumps(changes.get('counts', {}), indent=2)}</pre>
      <h2>Findings</h2>
      <table><thead><tr><th>Severity</th><th>Title</th><th>Affected URL</th></tr></thead><tbody>{finding_rows}</tbody></table>
      <h2>Endpoints</h2>
      <table><thead><tr><th>Method</th><th>URL</th><th>Source</th><th>Status</th></tr></thead><tbody>{ep_rows}</tbody></table>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
