"""
Header-based security checks.

Each check receives a dict of response headers (lowercased keys) and the URL
that was probed. Returns a list of Observation dicts:

  {
    "check": str,           # check identifier
    "title": str,
    "severity": str,        # info/low/medium/high/critical
    "confidence": str,      # low/medium/high
    "category": str,
    "affected_url": str,
    "evidence": dict,
    "recommendation": str,
  }
"""
from __future__ import annotations

import re
from typing import Any


def _headers_lower(headers: dict) -> dict:
    return {k.lower(): v for k, v in headers.items()}


# ---------------------------------------------------------------------------
# HSTS
# ---------------------------------------------------------------------------

def check_hsts(headers: dict, url: str) -> list[dict]:
    h = _headers_lower(headers)
    hsts = h.get("strict-transport-security", "")
    if not hsts:
        return [
            {
                "check": "missing_hsts",
                "title": "Missing HTTP Strict Transport Security (HSTS)",
                "severity": "medium",
                "confidence": "high",
                "category": "transport_security",
                "affected_url": url,
                "evidence": {"header_present": False, "value": None},
                "recommendation": (
                    "Add 'Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains' to all HTTPS responses."
                ),
            }
        ]
    # Check for weak max-age (< 1 year = 31536000)
    match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    if match:
        age = int(match.group(1))
        if age < 31536000:
            return [
                {
                    "check": "weak_hsts",
                    "title": "Weak HSTS max-age (< 1 year)",
                    "severity": "low",
                    "confidence": "high",
                    "category": "transport_security",
                    "affected_url": url,
                    "evidence": {"header_present": True, "value": hsts, "max_age": age},
                    "recommendation": (
                        "Set HSTS max-age to at least 31536000 (1 year) and "
                        "include 'includeSubDomains'."
                    ),
                }
            ]
    return []


# ---------------------------------------------------------------------------
# CSP
# ---------------------------------------------------------------------------

def check_csp(headers: dict, url: str) -> list[dict]:
    h = _headers_lower(headers)
    csp = h.get("content-security-policy", "")
    if not csp:
        return [
            {
                "check": "missing_csp",
                "title": "Missing Content-Security-Policy header",
                "severity": "medium",
                "confidence": "high",
                "category": "content_security",
                "affected_url": url,
                "evidence": {"header_present": False, "value": None},
                "recommendation": (
                    "Define a Content-Security-Policy. Avoid 'unsafe-inline', "
                    "'unsafe-eval', and wildcard sources."
                ),
            }
        ]

    issues = []
    if "unsafe-inline" in csp:
        issues.append("unsafe-inline detected")
    if "unsafe-eval" in csp:
        issues.append("unsafe-eval detected")
    if re.search(r"(?:script-src|default-src)[^;]*\*", csp):
        issues.append("wildcard source in script/default-src")

    if issues:
        return [
            {
                "check": "unsafe_csp",
                "title": "Unsafe Content-Security-Policy directives",
                "severity": "medium",
                "confidence": "high",
                "category": "content_security",
                "affected_url": url,
                "evidence": {"value": csp, "issues": issues},
                "recommendation": (
                    "Remove 'unsafe-inline', 'unsafe-eval', and wildcard "
                    "sources from your CSP."
                ),
            }
        ]
    return []


# ---------------------------------------------------------------------------
# Clickjacking (X-Frame-Options / CSP frame-ancestors)
# ---------------------------------------------------------------------------

def check_clickjacking(headers: dict, url: str) -> list[dict]:
    h = _headers_lower(headers)
    xfo = h.get("x-frame-options", "")
    csp = h.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_ancestors:
        return [
            {
                "check": "missing_clickjacking_protection",
                "title": "Clickjacking protection missing",
                "severity": "medium",
                "confidence": "high",
                "category": "clickjacking",
                "affected_url": url,
                "evidence": {
                    "x_frame_options": None,
                    "csp_frame_ancestors": False,
                },
                "recommendation": (
                    "Add 'X-Frame-Options: DENY' or a CSP "
                    "'frame-ancestors' directive."
                ),
            }
        ]
    return []


# ---------------------------------------------------------------------------
# Referrer-Policy
# ---------------------------------------------------------------------------

def check_referrer_policy(headers: dict, url: str) -> list[dict]:
    h = _headers_lower(headers)
    rp = h.get("referrer-policy", "")
    if not rp:
        return [
            {
                "check": "missing_referrer_policy",
                "title": "Missing Referrer-Policy header",
                "severity": "low",
                "confidence": "high",
                "category": "information_disclosure",
                "affected_url": url,
                "evidence": {"header_present": False, "value": None},
                "recommendation": (
                    "Set 'Referrer-Policy: strict-origin-when-cross-origin' "
                    "or stricter."
                ),
            }
        ]
    weak_values = {"unsafe-url", "no-referrer-when-downgrade"}
    if rp.lower() in weak_values:
        return [
            {
                "check": "weak_referrer_policy",
                "title": "Weak Referrer-Policy header",
                "severity": "low",
                "confidence": "high",
                "category": "information_disclosure",
                "affected_url": url,
                "evidence": {"value": rp},
                "recommendation": (
                    "Use 'strict-origin-when-cross-origin' or 'no-referrer'."
                ),
            }
        ]
    return []


# ---------------------------------------------------------------------------
# Cookie flags
# ---------------------------------------------------------------------------

def parse_set_cookie_flags(set_cookie_header: str) -> dict:
    """Parse a single Set-Cookie header value and return flag analysis."""
    parts = [p.strip() for p in set_cookie_header.split(";")]
    name_value = parts[0]
    name = name_value.split("=")[0].strip()
    flags_lower = [p.lower() for p in parts[1:]]

    secure = any(f == "secure" for f in flags_lower)
    httponly = any(f == "httponly" for f in flags_lower)
    samesite = next(
        (f for f in flags_lower if f.startswith("samesite")), None
    )

    return {
        "name": name,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite,
        "raw": set_cookie_header,
    }


_AUTH_COOKIE_PATTERNS = re.compile(
    r"(session|token|auth|jwt|login|access|refresh|sid|ssid|user)",
    re.IGNORECASE,
)


def check_cookie_flags(headers: dict, url: str) -> list[dict]:
    """Check Set-Cookie headers for missing security flags on auth-like cookies."""
    h = _headers_lower(headers)
    set_cookies = []
    # httpx may return multiple values joined or as a list
    raw = headers.get("set-cookie") or h.get("set-cookie") or ""
    if isinstance(raw, list):
        set_cookies = raw
    elif raw:
        # May be a single string; in httpx multiple headers come as separate entries
        set_cookies = [raw]

    findings = []
    for sc in set_cookies:
        info = parse_set_cookie_flags(sc)
        is_auth = bool(_AUTH_COOKIE_PATTERNS.search(info["name"]))
        issues = []
        if not info["secure"]:
            issues.append("missing Secure flag")
        if not info["httponly"]:
            issues.append("missing HttpOnly flag")
        if not info["samesite"]:
            issues.append("missing SameSite attribute")

        if issues:
            severity = "high" if is_auth else "medium"
            findings.append(
                {
                    "check": "insecure_cookie_flags",
                    "title": f"Insecure cookie flags on '{info['name']}'",
                    "severity": severity,
                    "confidence": "high",
                    "category": "cookie_security",
                    "affected_url": url,
                    "evidence": {
                        "cookie_name": info["name"],
                        "issues": issues,
                        "secure": info["secure"],
                        "httponly": info["httponly"],
                        "samesite": info["samesite"],
                        # Never store the full cookie value
                        "raw_redacted": f"{info['name']}=***",
                    },
                    "recommendation": (
                        f"Set Secure, HttpOnly, and SameSite=Strict/Lax on "
                        f"cookie '{info['name']}'."
                    ),
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Run all header checks
# ---------------------------------------------------------------------------

def run_header_checks(headers: dict, url: str) -> list[dict]:
    observations: list[dict] = []
    observations.extend(check_hsts(headers, url))
    observations.extend(check_csp(headers, url))
    observations.extend(check_clickjacking(headers, url))
    observations.extend(check_referrer_policy(headers, url))
    observations.extend(check_cookie_flags(headers, url))
    return observations
