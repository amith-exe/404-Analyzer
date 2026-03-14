"""
Complete scan pipeline as a single Celery task (with sub-steps).

Steps:
  1. normalize_target
  2. enumerate_subdomains
  3. probe_hosts
  4. crawl (unauth + auth)
  5. run_checks
  6. correlate_findings
  7. score_scan
  8. persist results
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import dns.resolver
import dns.exception

from app.config import settings
from app.services.api_discovery import discover_js_endpoints, discover_openapi_endpoints
from app.services.company_context import generate_company_context
from app.services.diff_engine import build_scan_diff, post_webhook, should_send_webhook
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Small brute-force wordlist (top ~200 common subdomains)
# ---------------------------------------------------------------------------
SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1",
    "host", "support", "dev", "web", "bbs", "ww42", "mx", "email", "cloud",
    "1", "mail1", "2", "forum", "owa", "www2", "gw", "admin", "store", "mx1",
    "cdn", "api", "exchange", "app", "gov", "2tty", "vps", "govyty", "holo",
    "news", "survey", "autodiscover", "autoconfig", "static", "img", "images",
    "staging", "beta", "demo", "assets", "media", "help", "docs", "wiki",
    "status", "monitor", "dashboard", "auth", "login", "sso", "account",
    "accounts", "id", "identity", "oauth", "iam", "connect", "gateway",
    "internal", "intranet", "corp", "office", "extranet", "partners",
    "api2", "api-v2", "v2", "v1", "old", "new", "prod", "production",
    "preprod", "uat", "qa", "qa2", "testing", "sandbox", "preview",
    "db", "database", "mysql", "postgres", "mongo", "redis", "cache",
    "backup", "backups", "bak", "archive", "old2", "legacy",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "cd", "deploy",
    "k8s", "kube", "kubernetes", "docker", "registry", "artifactory",
    "jira", "confluence", "slack", "chat", "meet", "video", "stream",
    "upload", "download", "files", "storage", "s3", "cdn2", "edge",
    "www3", "wap", "mobile", "tablet", "ios", "android", "app2",
    "analytics", "track", "tracking", "pixel", "beacon", "metrics",
    "grafana", "kibana", "elastic", "logstash", "splunk", "logs",
    "prometheus", "alertmanager", "nagios", "zabbix", "prtg",
    "crm", "erp", "hr", "billing", "payments", "checkout", "cart",
    "webdisk", "cpanel", "whm", "plesk", "webmin", "phpmyadmin",
    "smtp2", "pop", "imap", "mx2", "mail3", "relay", "outbound",
    "vpn2", "ssl", "secure2", "remote2", "rdp", "citrix",
    "customer", "clients", "partner", "vendor", "supplier",
    "investor", "investors", "press", "media2", "brand", "marketing",
    "dev2", "staging2", "test2", "uat2", "sandbox2",
    "graphql", "rest", "soap", "service", "services", "microservice",
    "search", "elastic2", "solr", "sphinx",
    "live", "www4", "www5", "net", "origin", "direct",
    "admin2", "manage", "management", "panel", "console",
    "health", "ping", "heartbeat", "alive",
    "mail4", "mail5", "smtp3", "mailer", "postfix", "sendmail",
    "ftp2", "sftp", "ftps", "files2",
    "web2", "web3", "web4", "site", "home",
    "corp2", "lan", "wifi", "wireless", "voip", "sip", "phone",
]


HTTP_CLIENT_HEADERS = {
    "User-Agent": settings.user_agent,
}


def _make_sync_client(cookies: dict | None = None, extra_headers: dict | None = None,
                       follow_redirects: bool = True) -> httpx.Client:
    h = dict(HTTP_CLIENT_HEADERS)
    if extra_headers:
        h.update(extra_headers)
    return httpx.Client(
        headers=h,
        timeout=settings.crawl_timeout,
        follow_redirects=follow_redirects,
        max_redirects=5,
        verify=False,  # allow self-signed certs
        cookies=cookies or {},
    )


# ---------------------------------------------------------------------------
# Step 1: normalize target
# ---------------------------------------------------------------------------

def normalize_target(url: str) -> dict:
    """Follow redirects, return canonical host + root_domain."""
    from app.utils.scope import extract_root_domain, normalize_url
    url = normalize_url(url)
    try:
        with _make_sync_client() as client:
            resp = client.get(url)
            final_url = str(resp.url)
    except Exception as e:
        logger.warning("normalize_target failed for %s: %s", url, e)
        final_url = url

    parsed = urlparse(final_url)
    host = parsed.hostname or urlparse(url).hostname or ""
    root_domain = extract_root_domain(host)
    return {
        "original_url": url,
        "final_url": final_url,
        "canonical_host": host,
        "root_domain": root_domain,
        "scheme": parsed.scheme or "https",
    }


# ---------------------------------------------------------------------------
# Step 2: enumerate subdomains
# ---------------------------------------------------------------------------

def _query_ct_logs(root_domain: str) -> list[str]:
    """Query crt.sh for certificate transparency data."""
    valid_host = re.compile(r"^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$")
    try:
        with httpx.Client(timeout=15, headers=HTTP_CLIENT_HEADERS) as client:
            resp = client.get(
                "https://crt.sh/",
                params={"q": f"%.{root_domain}", "output": "json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                names: set[str] = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if "@" in n or " " in n:
                            continue
                        if not valid_host.match(n):
                            continue
                        if n.endswith(root_domain) and n != root_domain:
                            names.add(n.lower())
                return list(names)
    except Exception as e:
        logger.warning("CT log query failed: %s", e)
    return []


def _brute_subdomains(root_domain: str) -> list[str]:
    """Attempt DNS resolution for each word in the wordlist."""
    found = []
    words = SUBDOMAIN_WORDLIST[: max(1, settings.brute_force_wordlist_limit)]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    for word in words:
        fqdn = f"{word}.{root_domain}"
        try:
            resolver.resolve(fqdn, "A")
            found.append(fqdn)
        except Exception:
            try:
                resolver.resolve(fqdn, "AAAA")
                found.append(fqdn)
            except Exception:
                pass
    return found


def enumerate_subdomains(root_domain: str) -> dict:
    ct_subs = _query_ct_logs(root_domain)
    brute_subs = _brute_subdomains(root_domain)
    all_subs = list(set(ct_subs) | set(brute_subs))
    return {
        "ct_subdomains": ct_subs,
        "brute_subdomains": brute_subs,
        "all_subdomains": all_subs,
    }


# ---------------------------------------------------------------------------
# Step 3: probe hosts
# ---------------------------------------------------------------------------

CDN_SIGNALS = {
    "cloudflare": ["cloudflare", "cf-ray"],
    "akamai": ["akamai", "x-check-cacheable"],
    "fastly": ["fastly", "x-fastly"],
    "aws_cloudfront": ["cloudfront", "x-amz-cf-id"],
    "azure_cdn": ["azure", "x-msedge"],
    "google_cloud": ["google", "x-goog"],
}


def _detect_provider(headers: dict) -> str:
    h_str = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    for provider, signals in CDN_SIGNALS.items():
        if any(s in h_str for s in signals):
            return provider
    server = headers.get("server", headers.get("Server", "")).lower()
    if server:
        return server.split("/")[0]
    return "unknown"


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:256]
    return ""


def _resolve_host(hostname: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    result = {"a": [], "aaaa": [], "cname": None}
    try:
        ans = resolver.resolve(hostname, "A")
        result["a"] = [r.address for r in ans]
    except Exception:
        pass
    try:
        ans = resolver.resolve(hostname, "AAAA")
        result["aaaa"] = [r.address for r in ans]
    except Exception:
        pass
    try:
        ans = resolver.resolve(hostname, "CNAME")
        result["cname"] = str(ans[0].target).rstrip(".")
    except Exception:
        pass
    return result


def probe_host(hostname: str) -> dict:
    """Probe a single host: DNS + HTTPS/HTTP."""
    dns_info = _resolve_host(hostname)
    live = False
    status_code = None
    title = None
    server_header = None
    provider = "unknown"
    final_url = None
    scheme = None
    response_headers = {}

    for scheme_try in ("https", "http"):
        url = f"{scheme_try}://{hostname}"
        try:
            with _make_sync_client() as client:
                resp = client.get(url)
                live = True
                status_code = resp.status_code
                response_headers = dict(resp.headers)
                server_header = response_headers.get("server", response_headers.get("Server"))
                provider = _detect_provider(response_headers)
                title = _extract_title(resp.text[:65536])
                final_url = str(resp.url)
                scheme = scheme_try
                break
        except Exception:
            pass

    return {
        "hostname": hostname,
        "live": live,
        "dns": dns_info,
        "status_code": status_code,
        "title": title,
        "server": server_header,
        "provider": provider,
        "final_url": final_url,
        "scheme": scheme,
        "headers": response_headers,
    }


def probe_hosts(hosts: list[str]) -> list[dict]:
    results = []
    for host in hosts:
        results.append(probe_host(host))
        time.sleep(settings.rate_limit_delay)
    return results


# ---------------------------------------------------------------------------
# Step 4: crawl
# ---------------------------------------------------------------------------

def _build_auth_headers(auth_config: dict | None) -> dict:
    """Build HTTP headers from auth config (cookie + optional Authorization)."""
    if not auth_config:
        return {}
    headers = {}
    cookie = auth_config.get("cookie_header", "")
    if cookie:
        headers["Cookie"] = cookie
    authorization = auth_config.get("authorization_header", "")
    if authorization:
        headers["Authorization"] = authorization
    return headers


def _extract_links(base_url: str, html: str, root_domain: str) -> list[str]:
    from app.utils.scope import is_in_scope
    links = []
    for pattern in (r'href=["\']([^"\']+)["\']', r'src=["\']([^"\']+)["\']',
                    r'action=["\']([^"\']+)["\']'):
        for m in re.finditer(pattern, html, re.IGNORECASE):
            href = m.group(1).strip()
            if href.startswith("javascript:") or href.startswith("mailto:") or href == "#":
                continue
            full = urljoin(base_url, href)
            if is_in_scope(full, root_domain):
                links.append(full)
    return links


def _content_similarity(a: str, b: str) -> float | None:
    if not a or not b:
        return None
    a_tokens = set(re.findall(r"[A-Za-z0-9_]{3,}", a.lower()))
    b_tokens = set(re.findall(r"[A-Za-z0-9_]{3,}", b.lower()))
    union = a_tokens | b_tokens
    if not union:
        return None
    return round(len(a_tokens & b_tokens) / len(union), 3)


def _via(sources: set[str]) -> str:
    if "auth" in sources and "unauth" in sources:
        return "both"
    if "auth" in sources:
        return "auth"
    return "unauth"


def crawl(
    start_urls: list[str],
    root_domain: str,
    auth_config: dict | None = None,
    max_depth: int | None = None,
    concurrency: int | None = None,
) -> dict:
    """
    BFS crawl within scope.  Returns collected endpoints with headers.
    Performs both unauthenticated and authenticated requests when auth_config given.
    """
    from app.utils.scope import is_in_scope
    max_depth = max_depth or settings.crawl_max_depth
    concurrency = concurrency or settings.crawl_concurrency
    auth_headers = _build_auth_headers(auth_config)

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(u, 0) for u in start_urls]
    endpoints_by_url: dict[str, dict] = {}
    discovered_sources: dict[str, set[str]] = {u: {"unauth"} for u in start_urls}
    requests_made = 0

    with _make_sync_client() as unauth_client, \
         _make_sync_client(extra_headers=auth_headers) as auth_client:

        while queue:
            if requests_made >= settings.max_requests_per_scan:
                logger.info("crawl request budget exhausted at %s requests", requests_made)
                break
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue
            if not is_in_scope(url, root_domain):
                continue
            visited.add(url)

            # Unauthenticated request
            unauth_status = None
            unauth_body = ""
            unauth_headers = {}
            try:
                r = unauth_client.get(
                    url, headers={"User-Agent": settings.user_agent}
                )
                requests_made += 1
                unauth_status = r.status_code
                unauth_body = r.text[:settings.max_response_size]
                unauth_headers = dict(r.headers)
            except Exception as e:
                logger.debug("crawl unauth GET %s failed: %s", url, e)

            # Authenticated request (only if auth provided)
            auth_status = None
            auth_body = ""
            if auth_headers:
                try:
                    r2 = auth_client.get(url)
                    requests_made += 1
                    auth_status = r2.status_code
                    auth_body = r2.text[:settings.max_response_size]
                except Exception as e:
                    logger.debug("crawl auth GET %s failed: %s", url, e)

            discovered_via = _via(discovered_sources.get(url, {"unauth"}))
            endpoint = {
                "url": url,
                "host": urlparse(url).hostname or "",
                "method": "GET",
                "source": "crawl",
                "status_code": unauth_status if unauth_status is not None else auth_status,
                "title": _extract_title(unauth_body or auth_body),
                "headers": unauth_headers,
                "unauth_status": unauth_status,
                "unauth_body": unauth_body[:4096],
                "auth_status": auth_status,
                "auth_body": auth_body[:4096] if auth_body else "",
                "requires_auth": "unknown",
                "discovered_via": discovered_via,
                "content_similarity": _content_similarity(unauth_body, auth_body),
                "auth_only_navigation": discovered_via == "auth",
            }

            # Determine requires_auth heuristic
            if unauth_status in (401, 403):
                endpoint["requires_auth"] = "yes"
            elif auth_status and unauth_status == 200:
                endpoint["requires_auth"] = "no"

            endpoints_by_url[url] = endpoint

            # Queue child links
            if depth < max_depth:
                for source_name, body in (("unauth", unauth_body), ("auth", auth_body)):
                    if not body:
                        continue
                    for link in _extract_links(url, body, root_domain):
                        sources = discovered_sources.setdefault(link, set())
                        sources.add(source_name)
                        if link in endpoints_by_url:
                            via = _via(sources)
                            endpoints_by_url[link]["discovered_via"] = via
                            endpoints_by_url[link]["auth_only_navigation"] = via == "auth"
                        if link not in visited:
                            queue.append((link, depth + 1))

            if len(endpoints_by_url) >= settings.max_discovered_endpoints:
                logger.info("crawl endpoint cap reached at %s", settings.max_discovered_endpoints)
                break

            time.sleep(settings.rate_limit_delay)

    endpoints = list(endpoints_by_url.values())
    return {"endpoints": endpoints, "visited_count": len(visited), "requests_made": requests_made}


# ---------------------------------------------------------------------------
# Step 5: run checks
# ---------------------------------------------------------------------------

def run_checks(endpoints: list[dict], probe_results: list[dict],
               auth_config: dict | None, root_domain: str) -> list[dict]:
    """Run all passive + light active checks. Returns a list of observations."""
    from app.checks.header_checks import run_header_checks
    from app.checks.cors_checks import check_cors
    from app.checks.tls_checks import check_tls
    from app.checks.exposure_checks import EXPOSURE_PATHS, make_exposure_observation
    from app.checks.auth_checks import check_subdomain_takeover, check_auth_leakage

    observations: list[dict] = []
    seen_hosts: set[str] = set()
    checked_exposure: set[str] = set()

    # Per-endpoint checks
    for ep in endpoints:
        headers = ep.get("headers") or {}
        url = ep.get("url", "")
        host = ep.get("host", "")

        # Header/CORS checks only for endpoints with observed HTTP response headers.
        if headers:
            observations.extend(run_header_checks(headers, url))
            cors_obs = check_cors(headers, url, tested_origin="https://evil.example.com")
            observations.extend(cors_obs)

        # Auth leakage
        if auth_config:
            obs = check_auth_leakage(
                url=url,
                unauth_status=ep.get("unauth_status") or 0,
                auth_status=ep.get("auth_status") or 0,
                unauth_body=ep.get("unauth_body") or "",
                auth_body=ep.get("auth_body") or "",
            )
            observations.extend(obs)

        # Lightweight authz heuristic for sensitive endpoints
        if auth_config and ep.get("requires_auth") == "yes":
            unauth_status = ep.get("unauth_status") or 0
            auth_status = ep.get("auth_status") or 0
            similarity = ep.get("content_similarity")
            if unauth_status == 200 and auth_status == 200 and (similarity is None or similarity > 0.75):
                observations.append(
                    {
                        "check": "possible_broken_access_control",
                        "title": "Possible broken access control on auth-marked endpoint",
                        "severity": "high",
                        "confidence": "low",
                        "category": "authorization",
                        "affected_url": url,
                        "evidence": {
                            "unauth_status": unauth_status,
                            "auth_status": auth_status,
                            "content_similarity": similarity,
                            "requires_auth": ep.get("requires_auth"),
                            "source": ep.get("source"),
                        },
                        "recommendation": (
                            "Verify server-side authorization checks and object-level access controls "
                            "for this endpoint."
                        ),
                    }
                )

        # Exposure checks (once per host)
        if host and host not in checked_exposure:
            checked_exposure.add(host)
            base_url = f"{urlparse(url).scheme}://{host}"
            with _make_sync_client() as client:
                for (path, title, severity, category, rec) in EXPOSURE_PATHS:
                    exp_url = base_url.rstrip("/") + path
                    try:
                        # Use HEAD first, fall back to GET
                        r = client.head(exp_url)
                        sc = r.status_code
                        body = ""
                        if sc == 200:
                            r2 = client.get(exp_url)
                            body = r2.text[:500]
                        if sc == 200:
                            observations.append(
                                make_exposure_observation(
                                    path, title, severity, category, rec,
                                    base_url, sc, body
                                )
                            )
                    except Exception:
                        pass
                    time.sleep(settings.rate_limit_delay)

    # TLS checks (once per host seen in probe results)
    for probe in probe_results:
        host = probe.get("hostname", "")
        if host and host not in seen_hosts and probe.get("live") and probe.get("scheme") == "https":
            seen_hosts.add(host)
            tls_obs = check_tls(host)
            observations.extend(tls_obs)

    # Subdomain takeover checks
    for probe in probe_results:
        host = probe.get("hostname", "")
        cname = (probe.get("dns") or {}).get("cname")
        url = probe.get("final_url", f"https://{host}")
        body = ""
        obs = check_subdomain_takeover(host, cname, body, url)
        observations.extend(obs)

    return observations


# ---------------------------------------------------------------------------
# Step 6: correlate findings
# ---------------------------------------------------------------------------

def correlate_findings(observations: list[dict], scan_id: int) -> list[dict]:
    """Deduplicate observations and convert to Finding records."""
    seen: set[str] = set()
    findings = []
    for obs in observations:
        fp = hashlib.sha256(
            f"{obs.get('check')}|{obs.get('affected_url', '')}".encode()
        ).hexdigest()[:16]
        if fp in seen:
            continue
        seen.add(fp)
        findings.append(
            {
                "title": obs["title"],
                "severity": obs["severity"],
                "confidence": obs["confidence"],
                "category": obs["category"],
                "affected_url": obs.get("affected_url"),
                "evidence": obs.get("evidence", {}),
                "recommendation": obs.get("recommendation"),
                "fingerprint_hash": fp,
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Step 7: score scan
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 7,
    "low": 3,
    "info": 0,
}


def score_scan(findings: list[dict]) -> dict:
    """Compute 0-100 posture score (100 = perfect) and category breakdown."""
    if not findings:
        return {"score": 100.0, "breakdown": {}}

    penalty = 0
    category_counts: dict[str, int] = {}
    for f in findings:
        w = SEVERITY_WEIGHTS.get(f["severity"], 0)
        penalty += w
        cat = f.get("category", "other")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    # Cap penalty at 100
    score = max(0.0, 100.0 - min(penalty, 100))
    return {"score": round(score, 1), "breakdown": category_counts}


# ---------------------------------------------------------------------------
# Main Celery task
# ---------------------------------------------------------------------------

@celery_app.task(bind=True, name="scanner.run_scan")
def run_scan(self, scan_id: int):
    """
    Full scan pipeline.  Reads scan config from DB, executes all steps,
    writes results back to DB.
    """
    from app.database import SessionLocal
    from app.models import (
        Asset, AssetType, Artifact, CompanyContext, Endpoint, Finding, Scan, ScanDiff,
        ScanStatus, ScheduledScanJob
    )
    from app.utils.crypto import decrypt_secret

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return

        scan.status = ScanStatus.running
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        config = scan.scan_config
        original_url = config.get("url", "")
        auth_config_enc = config.get("auth_config")
        auth_config = None
        if auth_config_enc:
            try:
                auth_config = json.loads(decrypt_secret(auth_config_enc))
            except Exception:
                auth_config = None

        max_depth = int(config.get("max_depth", settings.crawl_max_depth))

        def _update(step: str, pct: int):
            scan.current_step = step
            scan.progress = pct
            db.commit()

        # Step 1: normalize
        _update("normalizing", 5)
        target_info = normalize_target(original_url)
        root_domain = target_info["root_domain"]
        canonical_host = target_info["canonical_host"]

        # Company context generation from canonical URL
        _update("company_context", 8)
        context_result = generate_company_context(target_info["final_url"])
        db_context = CompanyContext(
            target_id=scan.target_id,
            scan_id=scan_id,
            source_url=context_result.source_url,
            description_raw=context_result.description_raw,
            industry=context_result.industry,
            business_model=context_result.business_model,
            keywords_json=json.dumps(context_result.keywords),
            likely_attack_surface_json=json.dumps(context_result.likely_attack_surface),
            where_to_look_first=context_result.where_to_look_first,
            summary_hash=context_result.summary_hash,
        )
        db.add(db_context)
        db.commit()

        # Step 2: enumerate subdomains
        _update("enumerating_subdomains", 10)
        sub_result = enumerate_subdomains(root_domain)
        all_hosts = list(set([canonical_host] + sub_result["all_subdomains"]))
        if len(all_hosts) > settings.max_hosts_to_probe:
            # Keep canonical host + deterministic subset to avoid very long probe stalls.
            trimmed = sorted(h for h in all_hosts if h != canonical_host)
            all_hosts = [canonical_host] + trimmed[: settings.max_hosts_to_probe - 1]

        # Persist assets
        for sub in sub_result["all_subdomains"]:
            asset = Asset(
                scan_id=scan_id,
                type=AssetType.subdomain,
                value=sub,
                metadata_json=json.dumps({"source": "enumeration"}),
            )
            db.add(asset)
        db.commit()

        # Step 3: probe hosts
        _update("probing_hosts", 20)
        probe_results = []
        total_hosts = max(1, len(all_hosts))
        for idx, host in enumerate(all_hosts, start=1):
            probe_results.append(probe_host(host))
            pct = 20 + int((idx / total_hosts) * 20)
            _update("probing_hosts", min(39, pct))
            time.sleep(settings.rate_limit_delay)
        live_hosts = [p for p in probe_results if p["live"]]

        for p in probe_results:
            asset = Asset(
                scan_id=scan_id,
                type=AssetType.host,
                value=p["hostname"],
                metadata_json=json.dumps({
                    "live": p["live"],
                    "status_code": p.get("status_code"),
                    "title": p.get("title"),
                    "server": p.get("server"),
                    "provider": p.get("provider"),
                    "dns": p.get("dns"),
                }),
            )
            db.add(asset)
        db.commit()

        # Step 4: crawl
        _update("crawling", 40)
        start_urls = [
            p["final_url"] or f"{p['scheme']}://{p['hostname']}"
            for p in live_hosts if p.get("final_url") or p.get("scheme")
        ]
        if not start_urls:
            start_urls = [target_info["final_url"]]

        crawl_result = crawl(
            start_urls=start_urls,
            root_domain=root_domain,
            auth_config=auth_config,
            max_depth=max_depth,
        )
        crawl_endpoints = crawl_result["endpoints"]

        # API-first discovery (OpenAPI + JS routes)
        _update("api_discovery", 50)
        openapi_endpoints = discover_openapi_endpoints(
            start_urls=start_urls,
            root_domain=root_domain,
            auth_config=auth_config,
        )
        js_endpoints = discover_js_endpoints(crawl_endpoints, root_domain=root_domain)

        merged: dict[tuple[str, str], dict] = {}
        for ep in crawl_endpoints + openapi_endpoints + js_endpoints:
            key = (ep.get("method", "GET"), ep["url"])
            existing = merged.get(key)
            if not existing:
                merged[key] = ep
                continue
            # Prefer endpoints with status/title/headers data
            if existing.get("status_code") is None and ep.get("status_code") is not None:
                merged[key] = ep
            else:
                if existing.get("source") != "crawl" and ep.get("source") == "crawl":
                    merged[key] = ep
        crawl_endpoints = list(merged.values())

        # Persist endpoints
        for ep in crawl_endpoints:
            # Redact auth info from stored headers
            safe_headers = {
                k: v for k, v in (ep.get("headers") or {}).items()
                if k.lower() not in ("cookie", "authorization", "set-cookie")
            }
            db_ep = Endpoint(
                scan_id=scan_id,
                host=ep["host"],
                url=ep["url"],
                method=ep["method"],
                source=ep["source"],
                discovered_via=ep.get("discovered_via", "unauth"),
                requires_auth=ep.get("requires_auth", "unknown"),
                status_code=ep.get("status_code"),
                unauth_status_code=ep.get("unauth_status"),
                auth_status_code=ep.get("auth_status"),
                content_similarity=ep.get("content_similarity"),
                auth_only_navigation=bool(ep.get("auth_only_navigation")),
                title=ep.get("title"),
                headers_json=json.dumps(safe_headers),
            )
            db.add(db_ep)
        db.commit()

        # Step 5: run checks
        _update("running_checks", 60)
        observations = run_checks(
            endpoints=crawl_endpoints,
            probe_results=probe_results,
            auth_config=auth_config,
            root_domain=root_domain,
        )

        # Step 6: correlate
        _update("correlating_findings", 80)
        findings_data = correlate_findings(observations, scan_id)

        # Persist findings
        for fd in findings_data:
            # Scrub cookies/auth from evidence
            evidence = fd.get("evidence") or {}
            evidence.pop("cookie", None)
            evidence.pop("authorization", None)

            db_finding = Finding(
                scan_id=scan_id,
                title=fd["title"],
                severity=fd["severity"],
                confidence=fd["confidence"],
                category=fd["category"],
                affected_url=fd.get("affected_url"),
                evidence_json=json.dumps(evidence),
                recommendation=fd.get("recommendation"),
                fingerprint_hash=fd.get("fingerprint_hash"),
            )
            db.add(db_finding)
        db.commit()

        # Step 7: score
        _update("scoring", 90)
        score_result = score_scan(findings_data)
        scan.posture_score = score_result["score"]

        # Persist artifact (summary)
        artifact = Artifact(
            scan_id=scan_id,
            kind="summary",
            metadata_json=json.dumps({
                "posture_score": score_result["score"],
                "breakdown": score_result["breakdown"],
                "findings_count": len(findings_data),
                "endpoints_count": len(crawl_endpoints),
                "hosts_count": len(all_hosts),
                "live_hosts_count": len(live_hosts),
            }),
        )
        db.add(artifact)

        # Diff latest scan vs previous completed scan for target
        _update("diffing", 95)
        previous_scan = (
            db.query(Scan)
            .filter(
                Scan.target_id == scan.target_id,
                Scan.status == ScanStatus.completed,
                Scan.id != scan_id,
            )
            .order_by(Scan.finished_at.desc())
            .first()
        )
        if previous_scan:
            summary = build_scan_diff(previous_scan=previous_scan, current_scan=scan, db=db)
            diff_row = ScanDiff(
                target_id=scan.target_id,
                scan_id=scan_id,
                previous_scan_id=previous_scan.id,
                summary_json=json.dumps(summary),
                webhook_sent=False,
            )
            db.add(diff_row)
            db.flush()

            schedule_job_id = config.get("schedule_job_id")
            if schedule_job_id:
                job = db.query(ScheduledScanJob).filter(ScheduledScanJob.id == schedule_job_id).first()
                if job and job.alert_webhook_url and should_send_webhook(summary, job.diff_threshold):
                    payload = {
                        "event": "scan_diff_alert",
                        "target_id": scan.target_id,
                        "scan_id": scan_id,
                        "previous_scan_id": previous_scan.id,
                        "counts": summary.get("counts", {}),
                        "summary": summary,
                    }
                    diff_row.webhook_sent = post_webhook(job.alert_webhook_url, payload)

        scan.status = ScanStatus.completed
        scan.finished_at = datetime.now(timezone.utc)
        scan.progress = 100
        scan.current_step = "completed"
        db.commit()

    except Exception as e:
        logger.exception("Scan %s failed: %s", scan_id, e)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.failed
            scan.finished_at = datetime.now(timezone.utc)
            scan.current_step = f"failed: {str(e)[:128]}"
            db.commit()
    finally:
        db.close()

