"""OpenAPI and JavaScript route discovery helpers."""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

import httpx

from app.config import settings
from app.utils.scope import is_in_scope

OPENAPI_HINT_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/swagger",
    "/api/docs",
)


def _normalize_api_path(path: str) -> str:
    if not path.startswith("/"):
        return "/" + path
    return path


def _build_auth_headers(auth_config: dict | None) -> dict:
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


def _make_client(extra_headers: dict | None = None) -> httpx.Client:
    headers = {"User-Agent": settings.user_agent}
    if extra_headers:
        headers.update(extra_headers)
    return httpx.Client(
        headers=headers,
        timeout=settings.crawl_timeout,
        follow_redirects=True,
        verify=False,
    )


def discover_openapi_endpoints(
    start_urls: list[str],
    root_domain: str,
    auth_config: dict | None = None,
) -> list[dict]:
    auth_headers = _build_auth_headers(auth_config)
    discovered: list[dict] = []
    seen: set[str] = set()

    with _make_client(extra_headers=auth_headers) as client:
        hosts = {urlparse(u).netloc for u in start_urls if urlparse(u).netloc}
        for host in hosts:
            for hint in OPENAPI_HINT_PATHS:
                candidate = f"https://{host}{hint}"
                if candidate in seen:
                    continue
                seen.add(candidate)
                try:
                    resp = client.get(candidate)
                except Exception:
                    continue
                if resp.status_code >= 400:
                    continue

                ctype = (resp.headers.get("content-type") or "").lower()
                is_jsonish = "json" in ctype or resp.text.strip().startswith("{")
                if not is_jsonish:
                    continue
                try:
                    data = resp.json()
                except Exception:
                    continue
                paths = data.get("paths")
                if not isinstance(paths, dict):
                    continue

                for raw_path, method_map in paths.items():
                    if not isinstance(method_map, dict):
                        continue
                    for method in method_map.keys():
                        if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                            continue
                        full_url = f"https://{host}{_normalize_api_path(raw_path)}"
                        if not is_in_scope(full_url, root_domain):
                            continue
                        discovered.append(
                            {
                                "url": full_url,
                                "host": urlparse(full_url).hostname or "",
                                "method": method.upper(),
                                "source": "openapi",
                                "status_code": None,
                                "title": "OpenAPI discovered endpoint",
                                "headers": {},
                                "requires_auth": "unknown",
                                "discovered_via": "openapi",
                                "unauth_status": None,
                                "auth_status": None,
                                "content_similarity": None,
                                "auth_only_navigation": False,
                            }
                        )
    return discovered


API_ROUTE_RE = re.compile(
    r"""(?:
        ["'`](/api/[a-zA-Z0-9_\-/{}:]+)["'`]
        |
        ["'`](https?://[^"'`]+/api/[a-zA-Z0-9_\-/{}:]+)["'`]
    )""",
    re.VERBOSE,
)


def discover_js_endpoints(
    crawled_endpoints: list[dict],
    root_domain: str,
) -> list[dict]:
    discovered: list[dict] = []
    seen: set[str] = set()

    for ep in crawled_endpoints:
        body = (ep.get("unauth_body") or "") + "\n" + (ep.get("auth_body") or "")
        if not body:
            continue
        src_url = ep.get("url", "")
        for match in API_ROUTE_RE.finditer(body):
            route = match.group(1) or match.group(2)
            if not route:
                continue
            full = urljoin(src_url, route)
            if full in seen:
                continue
            if not is_in_scope(full, root_domain):
                continue
            seen.add(full)
            discovered.append(
                {
                    "url": full,
                    "host": urlparse(full).hostname or "",
                    "method": "GET",
                    "source": "js",
                    "status_code": None,
                    "title": "JavaScript discovered endpoint",
                    "headers": {},
                    "requires_auth": "unknown",
                    "discovered_via": "js",
                    "unauth_status": None,
                    "auth_status": None,
                    "content_similarity": None,
                    "auth_only_navigation": False,
                }
            )
    return discovered
