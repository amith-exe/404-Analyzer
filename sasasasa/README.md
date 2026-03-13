# Outside-In Cloud Visibility Scanner

A hackathon MVP that takes a root URL and produces:
1. **Subdomain expansion + live host probing** — passive CT logs + active DNS brute force
2. **Authenticated + unauthenticated crawling** — BFS crawler with scope enforcement
3. **Vulnerability/posture findings with evidence** — 12+ checks with structured evidence
4. **Dashboard** — Next.js UI with assets / endpoints / findings tabs

---

## Architecture

```
┌──────────────┐    POST /api/scans    ┌──────────────┐
│   Frontend   │ ──────────────────►  │   FastAPI    │
│  (Next.js)   │ ◄──────────────────  │   (Python)   │
└──────────────┘   JSON responses      └──────┬───────┘
                                              │ enqueue task
                                       ┌──────▼───────┐
                                       │    Celery    │
                                       │    Worker    │
                                       └──────┬───────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
             ┌─────────────┐         ┌──────────────┐         ┌──────────────┐
             │   Redis     │         │  PostgreSQL  │         │  Target web  │
             │  (broker)   │         │    (data)    │         │   servers    │
             └─────────────┘         └──────────────┘         └──────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend API | Python 3.12 + FastAPI |
| Worker | Celery + Redis |
| HTTP client | httpx (sync) |
| DNS | dnspython |
| Database | PostgreSQL + SQLAlchemy 2 + Alembic |
| Frontend | Next.js 15 (TypeScript) + Tailwind CSS |
| Local dev | Docker Compose |

---

## Quick Start

### Prerequisites
- Docker + Docker Compose v2

### 1. Clone & start

```bash
git clone <repo-url>
cd sasasasa
docker compose up --build
```

Services started:
- **API**: http://localhost:8000
- **Frontend**: http://localhost:3000
- **API docs**: http://localhost:8000/docs

### 2. Run migrations (first time)

```bash
docker compose run --rm migrate
# or manually:
cd backend && DATABASE_URL=postgresql://scanner:scanner@localhost:5432/scanner alembic upgrade head
```

### 3. Create a scan

Via the UI at http://localhost:3000, or via API:

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "scan_config": {"max_depth": 2},
    "auth_config": {"cookie_header": "session=abc123"}
  }'
# => {"scan_id": 1}
```

### 4. Check scan status

```bash
curl http://localhost:8000/api/scans/1
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://scanner:scanner@postgres:5432/scanner` | PostgreSQL connection string |
| `REDIS_URL` | `redis://redis:6379/0` | Redis URL for Celery |
| `SECRET_KEY` | `change-me-in-production-32-chars!!` | Fernet encryption key for auth configs |
| `CRAWL_MAX_DEPTH` | `2` | Default crawl depth |
| `CRAWL_CONCURRENCY` | `5` | Crawl concurrency limit |
| `CRAWL_TIMEOUT` | `10.0` | Request timeout in seconds |
| `MAX_RESPONSE_SIZE` | `2097152` | Max response body size (bytes) |
| `RATE_LIMIT_DELAY` | `0.3` | Delay between requests (seconds) |
| `USER_AGENT` | `OutsideInScanner/1.0 (security-research)` | HTTP User-Agent string |

Frontend environment variable:
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend API URL |

---

## API Reference

### POST /api/scans
Create a new scan.

**Request body:**
```json
{
  "url": "https://example.com",
  "scan_config": {
    "max_depth": 2
  },
  "auth_config": {
    "cookie_header": "session=abc123; csrf=xyz",
    "authorization_header": "Bearer eyJhbGc..."
  }
}
```

**Response:** `{"scan_id": 1}`

### GET /api/scans/{scan_id}
Get scan status and posture score.

### GET /api/scans/{scan_id}/assets
List discovered hosts/subdomains.

### GET /api/scans/{scan_id}/endpoints
List crawled endpoints.

### GET /api/scans/{scan_id}/findings
List security findings. Optional `?severity=high` filter.

### GET /api/scans/{scan_id}/report
Summarized JSON report.

---

## Scan Pipeline

The scan runs as a Celery task with these steps:

1. **normalize_target** — follow redirects, extract root domain
2. **enumerate_subdomains** — CT log query (crt.sh) + DNS brute force (~200 words)
3. **probe_hosts** — resolve A/AAAA, detect CDN/provider, try HTTPS/HTTP
4. **crawl** — BFS within scope, unauthenticated + authenticated requests
5. **run_checks** — header checks + exposure checks + CORS + TLS
6. **correlate_findings** — deduplicate observations → findings
7. **score_scan** — compute posture score 0-100

---

## Vulnerability Checks (12+)

| Check | Severity | Method |
|-------|----------|--------|
| Missing/weak HSTS | medium/low | Response header analysis |
| Missing/unsafe CSP | medium | Response header analysis |
| Clickjacking (XFO / frame-ancestors) | medium | Response header analysis |
| Referrer-Policy missing/weak | low | Response header analysis |
| Cookie flags (Secure/HttpOnly/SameSite) | high/medium | Set-Cookie header analysis |
| CORS wildcard + credentials | high | ACAO/ACAC header analysis |
| CORS origin reflection | high/medium | Controlled-Origin request |
| TLS cert expiry + hostname mismatch | critical/medium | SSL socket inspection |
| Exposed /.git/HEAD | critical | HEAD + GET probe |
| Exposed /.env, backup.zip, db.sql | critical/high | HEAD + GET probe |
| server-status / phpinfo exposure | medium | HEAD + GET probe |
| Auth leakage (unauth vs auth diff) | high/medium | Response comparison |
| Subdomain takeover heuristic | high | CNAME + body matching |

---

## Data Model

```sql
targets       (id, root_domain, ownership_status, created_at)
scans         (id, target_id, status, scan_config_json, started_at, finished_at, posture_score, progress, current_step)
assets        (id, scan_id, type, value, metadata_json)
endpoints     (id, scan_id, host, url, method, source, requires_auth, status_code, title, headers_json)
findings      (id, scan_id, title, severity, confidence, category, affected_url, evidence_json, recommendation, fingerprint_hash)
artifacts     (id, scan_id, kind, path_or_url, metadata_json)
```

---

## Running Tests

```bash
cd backend
pip install -r requirements.txt
DATABASE_URL=sqlite:///./test.db python -m pytest tests/ -v
```

Tests cover:
- Scope enforcement rules (`test_scope.py`)
- Header parsing + all 5 header checks (`test_header_checks.py`)
- Cookie flag detection details (`test_cookie_flags.py`)

---

## Sample Scan Config JSON

```json
{
  "url": "http://localhost:3000",
  "scan_config": {
    "max_depth": 2
  },
  "auth_config": {
    "cookie_header": "session=demo-session-cookie-value"
  }
}
```

---

## Security & Guardrails

- **Strict in-scope enforcement**: URLs outside `root_domain` are never crawled
- **Rate limiting**: configurable delay between requests
- **Timeouts**: per-request and per-response-size limits
- **Secret redaction**: auth cookies/headers are never stored in findings or logs (only `name=***` format)
- **Auth config encrypted at rest**: Fernet symmetric encryption with key derived from `SECRET_KEY`
- **No aggressive port scanning**: HTTP/HTTPS only
- **User-Agent**: self-identifying scanner string

---

## Development

### Local backend without Docker

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Start API
DATABASE_URL=postgresql://scanner:scanner@localhost:5432/scanner \
REDIS_URL=redis://localhost:6379/0 \
uvicorn app.main:app --reload

# Start worker (separate terminal)
DATABASE_URL=postgresql://scanner:scanner@localhost:5432/scanner \
REDIS_URL=redis://localhost:6379/0 \
celery -A app.tasks.celery_app.celery_app worker --loglevel=info
```

### Local frontend without Docker

```bash
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
```

---

## Project Structure

```
.
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI app entry point
│   │   ├── config.py         # Settings (pydantic-settings)
│   │   ├── database.py       # SQLAlchemy engine + session
│   │   ├── models/           # SQLAlchemy ORM models
│   │   ├── api/              # FastAPI route handlers
│   │   ├── tasks/            # Celery app + scan pipeline
│   │   ├── checks/           # Vulnerability check modules
│   │   └── utils/            # Scope rules, crypto helpers
│   ├── alembic/              # Database migrations
│   ├── tests/                # Unit tests
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/app/              # Next.js App Router pages
│   │   ├── page.tsx          # New scan form
│   │   └── scans/[id]/       # Scan detail with tabs
│   ├── next.config.ts
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```
