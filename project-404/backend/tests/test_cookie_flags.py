"""Unit tests for cookie flag detection (detailed)."""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.checks.header_checks import parse_set_cookie_flags, check_cookie_flags

URL = "https://example.com/"


def test_parse_httponly_case_insensitive():
    info = parse_set_cookie_flags("token=xyz; httponly; secure")
    assert info["httponly"] is True
    assert info["secure"] is True


def test_parse_samesite_lax():
    info = parse_set_cookie_flags("auth=1; SameSite=Lax")
    assert info["samesite"] == "samesite=lax"


def test_parse_samesite_none():
    info = parse_set_cookie_flags("auth=1; SameSite=None")
    assert info["samesite"] == "samesite=none"


def test_cookie_never_stores_value():
    """Cookie value must never appear in evidence."""
    findings = check_cookie_flags({"set-cookie": "jwt=supersecrettoken123"}, URL)
    evidence_str = str(findings)
    assert "supersecrettoken123" not in evidence_str


def test_cookie_missing_samesite_only():
    info = parse_set_cookie_flags("session=abc; Secure; HttpOnly")
    assert info["samesite"] is None
    assert info["secure"] is True
    assert info["httponly"] is True


def test_multiple_cookies_via_list():
    """Simulate multiple Set-Cookie headers as list (as httpx provides them)."""
    findings = check_cookie_flags(
        {"set-cookie": ["session=abc", "csrf=xyz; Secure; HttpOnly; SameSite=Strict"]},
        URL,
    )
    # session cookie is missing all flags → 1 finding
    # csrf cookie is fully secure → 0 findings
    assert len(findings) == 1
    assert findings[0]["evidence"]["cookie_name"] == "session"
