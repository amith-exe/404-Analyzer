"""Scan diffing and webhook alerting."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import httpx

from app.services.company_context import context_similarity

KEY_SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "referrer-policy",
    "x-content-type-options",
}


def _normalize_headers(raw: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (raw or {}).items():
        lk = k.lower()
        if lk in KEY_SECURITY_HEADERS:
            out[lk] = str(v)
    return out


def build_scan_diff(previous_scan, current_scan, db) -> dict:
    from app.models import CompanyContext, Endpoint, Finding

    prev_eps = db.query(Endpoint).filter(Endpoint.scan_id == previous_scan.id).all()
    curr_eps = db.query(Endpoint).filter(Endpoint.scan_id == current_scan.id).all()

    prev_map = {(e.method, e.url): e for e in prev_eps}
    curr_map = {(e.method, e.url): e for e in curr_eps}

    prev_keys = set(prev_map.keys())
    curr_keys = set(curr_map.keys())

    new_eps = [{"method": m, "url": u} for (m, u) in sorted(curr_keys - prev_keys)]
    removed_eps = [{"method": m, "url": u} for (m, u) in sorted(prev_keys - curr_keys)]

    status_changes: list[dict] = []
    header_changes: list[dict] = []
    for key in sorted(prev_keys & curr_keys):
        old = prev_map[key]
        new = curr_map[key]
        if old.status_code != new.status_code:
            status_changes.append(
                {
                    "method": key[0],
                    "url": key[1],
                    "from": old.status_code,
                    "to": new.status_code,
                }
            )
        old_h = _normalize_headers(old.headers)
        new_h = _normalize_headers(new.headers)
        added = sorted(k for k in new_h.keys() if k not in old_h)
        removed = sorted(k for k in old_h.keys() if k not in new_h)
        changed = sorted(k for k in old_h.keys() & new_h.keys() if old_h[k] != new_h[k])
        if added or removed or changed:
            header_changes.append(
                {
                    "method": key[0],
                    "url": key[1],
                    "added": added,
                    "removed": removed,
                    "changed": changed,
                }
            )

    prev_findings = db.query(Finding).filter(Finding.scan_id == previous_scan.id).all()
    curr_findings = db.query(Finding).filter(Finding.scan_id == current_scan.id).all()
    prev_fps = {f.fingerprint_hash or f"{f.title}|{f.affected_url or ''}": f for f in prev_findings}
    curr_fps = {f.fingerprint_hash or f"{f.title}|{f.affected_url or ''}": f for f in curr_findings}

    new_findings = [
        {
            "title": curr_fps[k].title,
            "severity": curr_fps[k].severity.value,
            "url": curr_fps[k].affected_url,
        }
        for k in sorted(curr_fps.keys() - prev_fps.keys())
    ]
    removed_findings = [
        {
            "title": prev_fps[k].title,
            "severity": prev_fps[k].severity.value,
            "url": prev_fps[k].affected_url,
        }
        for k in sorted(prev_fps.keys() - curr_fps.keys())
    ]

    prev_ctx = (
        db.query(CompanyContext)
        .filter(CompanyContext.scan_id == previous_scan.id)
        .order_by(CompanyContext.created_at.desc())
        .first()
    )
    curr_ctx = (
        db.query(CompanyContext)
        .filter(CompanyContext.scan_id == current_scan.id)
        .order_by(CompanyContext.created_at.desc())
        .first()
    )
    context_change = {
        "changed": False,
        "previous_industry": prev_ctx.industry if prev_ctx else None,
        "current_industry": curr_ctx.industry if curr_ctx else None,
        "similarity": None,
    }
    if prev_ctx and curr_ctx:
        sim = context_similarity(prev_ctx.description_raw, curr_ctx.description_raw)
        context_change["similarity"] = sim
        context_change["changed"] = bool(
            prev_ctx.summary_hash != curr_ctx.summary_hash
            or prev_ctx.industry != curr_ctx.industry
            or sim < 0.75
        )
    elif curr_ctx and not prev_ctx:
        context_change["changed"] = True

    summary = {
        "new_endpoints": new_eps,
        "removed_endpoints": removed_eps,
        "status_changes": status_changes,
        "header_changes": header_changes,
        "new_findings": new_findings,
        "removed_findings": removed_findings,
        "context_change": context_change,
        "counts": {
            "new_endpoints": len(new_eps),
            "removed_endpoints": len(removed_eps),
            "status_changes": len(status_changes),
            "header_changes": len(header_changes),
            "new_findings": len(new_findings),
            "removed_findings": len(removed_findings),
            "context_changed": 1 if context_change.get("changed") else 0,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return summary


def should_send_webhook(diff_summary: dict, threshold: dict | None) -> bool:
    threshold = threshold or {}
    counts = diff_summary.get("counts", {})
    return any(
        counts.get(k, 0) >= int(v)
        for k, v in {
            "new_endpoints": threshold.get("new_endpoints", 1),
            "status_changes": threshold.get("status_changes", 1),
            "new_findings": threshold.get("new_findings", 1),
            "context_changed": threshold.get("context_changed", 1),
        }.items()
    )


def post_webhook(webhook_url: str, payload: dict) -> bool:
    if not webhook_url:
        return False
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(webhook_url, json=payload)
            return resp.status_code < 400
    except Exception:
        return False
