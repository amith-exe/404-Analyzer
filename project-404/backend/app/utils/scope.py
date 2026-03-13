"""Scope enforcement: only allow crawling within the root domain."""
import re
from urllib.parse import urlparse


def extract_root_domain(hostname: str) -> str:
    """Return the eTLD+1-like root domain (last two labels)."""
    parts = hostname.lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname.lower()


def is_in_scope(url: str, root_domain: str) -> bool:
    """Return True if *url* is within *root_domain* or a subdomain of it."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except Exception:
        return False
    host = host.lower()
    root = root_domain.lower()
    return host == root or host.endswith("." + root)


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme; default to https."""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url
