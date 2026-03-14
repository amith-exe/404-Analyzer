# 404-Analyzer: External Exposure Monitoring Platform

`404-Analyzer` is an outside-in security scanner for bug bounty and pentest workflows with:
- Authenticated and unauthenticated crawling deltas
- Company context extraction from website URL
- Continuous scheduled monitoring
- Scan-to-scan diffing with webhook alerts
- API-first discovery (OpenAPI + JavaScript route hints)
- Exportable CSV/HTML reporting with executive summary

## What is implemented

1. Authenticated crawling now enqueues links from both unauthenticated and authenticated HTML.
2. Per-endpoint auth delta metadata is persisted:
   - `discovered_via` (`unauth|auth|both`)
   - `unauth_status_code`, `auth_status_code`
   - `content_similarity`
   - `auth_only_navigation`
3. Company context engine is integrated end-to-end:
   - `POST /api/company-context/generate`
   - Context persisted for target and scan (`company_contexts`)
   - Context-aware attack-surface guidance in UI and HTML report
4. Continuous monitoring:
   - Scheduled scan jobs (`scheduled_scan_jobs`)
   - Celery Beat task dispatches due schedules
5. Diff engine:
   - New/removed endpoints
   - Endpoint status changes
   - Security header changes
   - New/removed findings
   - Context changes between scans
   - Persisted in `scan_diffs`
   - Optional webhook alerts when thresholds are met
6. API-first discovery:
   - OpenAPI/Swagger ingestion (`source=openapi`)
   - JS bundle route extraction (`source=js`)
   - Lightweight non-destructive broken-access-control heuristic finding
7. Exports and reporting:
   - Endpoints CSV: `/api/scans/{id}/export/endpoints.csv`
   - Findings CSV: `/api/scans/{id}/export/findings.csv`
   - HTML report: `/api/scans/{id}/report.html`
8. UI improvements on scan detail:
   - Summary tab with company context + likely attack surface
   - Changes tab (diff summary)
   - Monitoring tab (create/toggle schedules)
   - Export buttons

## Architecture

- Backend: FastAPI + SQLAlchemy + Alembic
- Worker: Celery + Redis
- Scheduler: Celery Beat
- Frontend: Next.js
- Database: PostgreSQL

## Quick start (Docker Compose)

```bash
cd project-404
docker compose up --build
```

Services:
- API: `http://localhost:8001`
- API docs: `http://localhost:8001/docs`
- Frontend: `http://localhost:3001`

Default host ports are intentionally non-conflicting:
- `API_PORT=8001`
- `FRONTEND_PORT=3001`
- `POSTGRES_PORT=5433`
- `REDIS_PORT=6380`

Frontend now proxies `/api/*` to backend internally (`http://api:8000`), so browser/API host mismatch errors are avoided.

You can override them, for example:
```bash
API_PORT=8000 FRONTEND_PORT=3000 docker compose up --build
```
- Worker + Beat + Redis + Postgres

Run migrations:

```bash
docker compose run --rm migrate
```

## Basic workflow

1. Create a scan:

```bash
curl -X POST http://localhost:8001/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "url":"https://example.com",
    "scan_config":{"max_depth":2},
    "auth_config":{"cookie_header":"session=abc"}
  }'
```

2. Track progress:

```bash
curl http://localhost:8001/api/scans/1
```

3. Get context/diff:

```bash
curl http://localhost:8001/api/scans/1/context
curl http://localhost:8001/api/scans/1/changes
```

4. Create schedule from an existing scan:

```bash
curl -X POST http://localhost:8001/api/scans/1/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "interval":"daily",
    "enabled":true,
    "alert_webhook_url":"https://example.com/webhook",
    "diff_threshold":{"new_findings":1,"new_endpoints":5}
  }'
```

5. Export:

```bash
curl -OJ http://localhost:8001/api/scans/1/export/endpoints.csv
curl -OJ http://localhost:8001/api/scans/1/export/findings.csv
open http://localhost:8001/api/scans/1/report.html
```

## Key API endpoints

### Scans
- `POST /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/assets`
- `GET /api/scans/{scan_id}/endpoints`
- `GET /api/scans/{scan_id}/findings`
- `GET /api/scans/{scan_id}/summary`
- `GET /api/scans/{scan_id}/report`

### Context
- `POST /api/company-context/generate`
- `GET /api/scans/{scan_id}/context`
- `GET /api/targets/{target_id}/context/latest`

### Monitoring + diff
- `POST /api/scans/{scan_id}/schedules`
- `GET /api/targets/{target_id}/schedules`
- `PATCH /api/schedules/{schedule_id}`
- `GET /api/scans/{scan_id}/diff`
- `GET /api/scans/{scan_id}/changes`

### Exports
- `GET /api/scans/{scan_id}/export/endpoints.csv`
- `GET /api/scans/{scan_id}/export/findings.csv`
- `GET /api/scans/{scan_id}/report.html`

## Safety controls

- Scope enforcement preserved via `app/utils/scope.py`
- Non-destructive checks only (`GET`/`HEAD`)
- Crawl request budget and endpoint cap:
  - `MAX_REQUESTS_PER_SCAN`
  - `MAX_DISCOVERED_ENDPOINTS`
- Rate limiting via `RATE_LIMIT_DELAY`

## Environment variables

Backend (selected):
- `DATABASE_URL`
- `REDIS_URL`
- `SECRET_KEY`
- `CRAWL_MAX_DEPTH`
- `MAX_REQUESTS_PER_SCAN`
- `MAX_DISCOVERED_ENDPOINTS`
- `RATE_LIMIT_DELAY`
- `USER_AGENT`

Frontend:
- `NEXT_PUBLIC_API_URL`

## Migrations added

- `0002_monitoring_context_and_diff.py`
  - endpoint auth delta columns
  - `company_contexts`
  - `scheduled_scan_jobs`
  - `scan_diffs`

## Tests

Run backend tests:

```bash
docker compose run --rm --no-deps api python -m pytest tests -q
```

New critical tests:
- `tests/test_crawl_auth_discovery.py`
- `tests/test_api_discovery.py`
- `tests/test_company_context.py`
- `tests/test_diff_engine.py`
