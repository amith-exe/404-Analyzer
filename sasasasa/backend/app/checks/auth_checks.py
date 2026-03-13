"""Auth leakage and subdomain takeover heuristics."""
from __future__ import annotations

import re


# Known SaaS platforms and their "unclaimed" response indicators
TAKEOVER_SIGNATURES = [
    ("github.io", ["There isn't a GitHub Pages site here"]),
    ("herokuapp.com", ["No such app", "herokucdn.com/error-pages/no-such-app"]),
    ("azurewebsites.net", ["Web App - Unavailable", "404 Web Site not found"]),
    ("amazonaws.com", ["NoSuchBucket", "The specified bucket does not exist"]),
    ("fastly.net", ["Fastly error: unknown domain"]),
    ("netlify.com", ["Not Found - Request ID"]),
    ("zendesk.com", ["Help Center Closed"]),
    ("shopify.com", ["Sorry, this shop is currently unavailable"]),
    ("ghost.io", ["The thing you were looking for is no longer here"]),
    ("surge.sh", ["project not found"]),
    ("readme.io", ["Project doesnt exist yet"]),
    ("pantheonsite.io", ["The gods are wise"]),
]


def check_subdomain_takeover(host: str, cname: str | None, response_body: str | None,
                              url: str) -> list[dict]:
    """
    Heuristic check: if a CNAME points to a known SaaS and the response body
    contains an unclaimed indicator, flag as potential subdomain takeover.
    Confidence is medium unless we see a very clear indicator.
    """
    if not cname:
        return []

    cname_lower = cname.lower()
    body_lower = (response_body or "").lower()

    for platform, indicators in TAKEOVER_SIGNATURES:
        if platform in cname_lower:
            for indicator in indicators:
                if indicator.lower() in body_lower:
                    return [
                        {
                            "check": "subdomain_takeover",
                            "title": f"Potential subdomain takeover via {platform}",
                            "severity": "high",
                            "confidence": "medium",
                            "category": "subdomain_takeover",
                            "affected_url": url,
                            "evidence": {
                                "host": host,
                                "cname": cname,
                                "platform": platform,
                                "indicator_found": indicator,
                            },
                            "recommendation": (
                                f"Remove the dangling CNAME record for {host} "
                                f"or claim the resource on {platform}."
                            ),
                        }
                    ]
    return []


_LOGIN_INDICATORS = re.compile(
    r"(login|sign.?in|authenticate|enter.*password|access.*denied|"
    r"unauthorized|please log in)",
    re.IGNORECASE,
)


def check_auth_leakage(url: str, unauth_status: int, auth_status: int,
                        unauth_body: str, auth_body: str) -> list[dict]:
    """
    Compare unauthenticated vs authenticated responses.
    Flag when unauthenticated response does NOT show typical auth-wall indicators
    but authenticated response has meaningful content.
    """
    if unauth_status in (401, 403):
        # Properly protected
        return []

    # Unauthenticated got 200 but authenticated response significantly differs
    if unauth_status == 200 and auth_status == 200:
        # Simple similarity check: if bodies are very similar, no leakage
        if unauth_body and auth_body:
            common = len(set(unauth_body.split()) & set(auth_body.split()))
            total = max(len(set(auth_body.split())), 1)
            similarity = common / total
            # If auth body has notably more unique content (< 60% similar)
            if similarity < 0.6 and len(auth_body) > len(unauth_body) * 1.2:
                return [
                    {
                        "check": "auth_leakage",
                        "title": "Sensitive endpoint accessible without authentication",
                        "severity": "high",
                        "confidence": "medium",
                        "category": "authentication",
                        "affected_url": url,
                        "evidence": {
                            "unauth_status": unauth_status,
                            "auth_status": auth_status,
                            "similarity_ratio": round(similarity, 2),
                            "note": "Unauthenticated response differs significantly from authenticated response",
                        },
                        "recommendation": (
                            "Enforce authentication checks on this endpoint. "
                            "Verify that sensitive data is not exposed to unauthenticated users."
                        ),
                    }
                ]

    # Unauthenticated 200 but no login indicators while auth endpoint exists
    if unauth_status == 200 and not _LOGIN_INDICATORS.search(unauth_body or ""):
        if auth_status == 200 and auth_body and len(auth_body) > 500:
            return [
                {
                    "check": "auth_leakage_possible",
                    "title": "Endpoint may be accessible without authentication",
                    "severity": "medium",
                    "confidence": "low",
                    "category": "authentication",
                    "affected_url": url,
                    "evidence": {
                        "unauth_status": unauth_status,
                        "note": "No authentication redirect or wall detected on unauthenticated request",
                    },
                    "recommendation": (
                        "Verify this endpoint requires authentication where appropriate."
                    ),
                }
            ]
    return []
