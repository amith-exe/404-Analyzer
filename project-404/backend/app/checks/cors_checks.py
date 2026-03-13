"""CORS misconfiguration checks."""
from __future__ import annotations


def check_cors(headers: dict, url: str, tested_origin: str = "https://evil.example.com") -> list[dict]:
    """
    Check for CORS misconfigurations:
    1. ACAO=* with credentials
    2. Origin reflection (ACAO mirrors supplied Origin header)
    """
    h = {k.lower(): v for k, v in headers.items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    findings = []

    # Wildcard + credentials
    if acao == "*" and acac == "true":
        findings.append(
            {
                "check": "cors_wildcard_credentials",
                "title": "CORS: wildcard origin with credentials allowed",
                "severity": "high",
                "confidence": "high",
                "category": "cors",
                "affected_url": url,
                "evidence": {
                    "access_control_allow_origin": acao,
                    "access_control_allow_credentials": acac,
                },
                "recommendation": (
                    "Do not combine 'Access-Control-Allow-Origin: *' with "
                    "'Access-Control-Allow-Credentials: true'. "
                    "Explicitly list trusted origins."
                ),
            }
        )

    # Origin reflection
    if acao == tested_origin:
        findings.append(
            {
                "check": "cors_origin_reflection",
                "title": "CORS: server reflects attacker-controlled Origin",
                "severity": "high" if acac == "true" else "medium",
                "confidence": "high",
                "category": "cors",
                "affected_url": url,
                "evidence": {
                    "tested_origin": tested_origin,
                    "reflected_acao": acao,
                    "credentials_allowed": acac == "true",
                },
                "recommendation": (
                    "Validate the Origin header against a strict allow-list "
                    "instead of reflecting it."
                ),
            }
        )
    return findings
