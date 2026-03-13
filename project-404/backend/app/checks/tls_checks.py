"""TLS / certificate checks."""
from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone


def check_tls(host: str, port: int = 443) -> list[dict]:
    """
    Check TLS certificate:
    - Expiry within 30 days (warning) or already expired (high)
    - Hostname mismatch
    Returns a list of observation dicts.
    """
    url = f"https://{host}:{port}"
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        findings.append(
            {
                "check": "tls_cert_error",
                "title": "TLS certificate validation error",
                "severity": "high",
                "confidence": "high",
                "category": "tls",
                "affected_url": url,
                "evidence": {"error": str(e)},
                "recommendation": "Ensure the certificate is valid and matches the hostname.",
            }
        )
        return findings
    except Exception as e:
        # TLS not available / connection refused — not a finding per se
        return []

    # Check expiry
    not_after_str = cert.get("notAfter", "")
    if not_after_str:
        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days
            if days_left < 0:
                findings.append(
                    {
                        "check": "tls_cert_expired",
                        "title": "TLS certificate has expired",
                        "severity": "critical",
                        "confidence": "high",
                        "category": "tls",
                        "affected_url": url,
                        "evidence": {"not_after": not_after_str, "days_overdue": abs(days_left)},
                        "recommendation": "Renew the TLS certificate immediately.",
                    }
                )
            elif days_left <= 30:
                findings.append(
                    {
                        "check": "tls_cert_expiring_soon",
                        "title": f"TLS certificate expires in {days_left} days",
                        "severity": "medium",
                        "confidence": "high",
                        "category": "tls",
                        "affected_url": url,
                        "evidence": {"not_after": not_after_str, "days_left": days_left},
                        "recommendation": "Renew the TLS certificate before it expires.",
                    }
                )
        except Exception:
            pass

    return findings
