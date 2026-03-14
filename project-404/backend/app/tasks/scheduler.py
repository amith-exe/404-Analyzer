"""Periodic scheduling task for continuous scans."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def compute_next_run(job, base: datetime) -> datetime:
    if job.interval_minutes:
        return base + timedelta(minutes=int(job.interval_minutes))
    cron = (job.cron_expr or "").strip().lower()
    if cron in {"@weekly", "0 0 * * 0", "0 0 * * 7"}:
        return base + timedelta(days=7)
    return base + timedelta(days=1)


def dispatch_scheduled_scans(db, now: datetime | None = None) -> list[int]:
    from app.models import Scan, ScanStatus, ScheduledScanJob
    from app.tasks.scan_pipeline import run_scan

    ref = now or utcnow()
    jobs = (
        db.query(ScheduledScanJob)
        .filter(
            ScheduledScanJob.enabled.is_(True),
            ScheduledScanJob.next_run_at.isnot(None),
            ScheduledScanJob.next_run_at <= ref,
        )
        .all()
    )

    created: list[int] = []
    for job in jobs:
        cfg = job.scan_config
        cfg["schedule_job_id"] = job.id
        scan = Scan(
            target_id=job.target_id,
            status=ScanStatus.pending,
            scan_config_json=json.dumps(cfg),
        )
        db.add(scan)
        db.flush()

        job.last_scan_id = scan.id
        job.last_run_at = ref
        job.next_run_at = compute_next_run(job, ref)

        created.append(scan.id)
        run_scan.delay(scan.id)
    if jobs:
        db.commit()
    return created


@celery_app.task(name="scanner.schedule_tick")
def schedule_tick():
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        created = dispatch_scheduled_scans(db, now=utcnow())
        if created:
            logger.info("Scheduled scans dispatched: %s", created)
    except Exception as exc:
        logger.exception("schedule_tick failed: %s", exc)
    finally:
        db.close()
