"""Unit tests for header parsing and vulnerability checks."""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.checks.header_checks import (
    check_hsts,
    check_csp,
    check_clickjacking,
    check_referrer_policy,
    check_cookie_flags,
    parse_set_cookie_flags,
    run_header_checks,
)
from app.checks.cors_checks import check_cors


URL = "https://example.com/"


# ---------------------------------------------------------------------------
# HSTS tests
# ---------------------------------------------------------------------------

def test_hsts_missing():
    findings = check_hsts({}, URL)
    assert len(findings) == 1
    assert findings[0]["check"] == "missing_hsts"
    assert findings[0]["severity"] == "medium"


def test_hsts_present_strong():
    findings = check_hsts(
        {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}, URL
    )
    assert findings == []


def test_hsts_weak_max_age():
    findings = check_hsts({"Strict-Transport-Security": "max-age=3600"}, URL)
    assert len(findings) == 1
    assert findings[0]["check"] == "weak_hsts"


# ---------------------------------------------------------------------------
# CSP tests
# ---------------------------------------------------------------------------

def test_csp_missing():
    findings = check_csp({}, URL)
    assert len(findings) == 1
    assert findings[0]["check"] == "missing_csp"


def test_csp_safe():
    findings = check_csp(
        {"Content-Security-Policy": "default-src 'self'; script-src 'self'"}, URL
    )
    assert findings == []


def test_csp_unsafe_inline():
    findings = check_csp(
        {"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"}, URL
    )
    assert any(f["check"] == "unsafe_csp" for f in findings)


def test_csp_unsafe_eval():
    findings = check_csp(
        {"Content-Security-Policy": "script-src 'unsafe-eval'"}, URL
    )
    assert any(f["check"] == "unsafe_csp" for f in findings)


# ---------------------------------------------------------------------------
# Clickjacking tests
# ---------------------------------------------------------------------------

def test_clickjacking_missing():
    findings = check_clickjacking({}, URL)
    assert len(findings) == 1
    assert findings[0]["check"] == "missing_clickjacking_protection"


def test_clickjacking_xfo_deny():
    findings = check_clickjacking({"X-Frame-Options": "DENY"}, URL)
    assert findings == []


def test_clickjacking_frame_ancestors():
    findings = check_clickjacking(
        {"Content-Security-Policy": "frame-ancestors 'none'"}, URL
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Referrer-Policy tests
# ---------------------------------------------------------------------------

def test_referrer_policy_missing():
    findings = check_referrer_policy({}, URL)
    assert len(findings) == 1
    assert findings[0]["check"] == "missing_referrer_policy"


def test_referrer_policy_strict():
    findings = check_referrer_policy(
        {"Referrer-Policy": "strict-origin-when-cross-origin"}, URL
    )
    assert findings == []


def test_referrer_policy_weak():
    findings = check_referrer_policy({"Referrer-Policy": "unsafe-url"}, URL)
    assert any(f["check"] == "weak_referrer_policy" for f in findings)


# ---------------------------------------------------------------------------
# Cookie flag tests
# ---------------------------------------------------------------------------

def test_parse_cookie_all_flags():
    info = parse_set_cookie_flags("session=abc; Secure; HttpOnly; SameSite=Strict")
    assert info["secure"] is True
    assert info["httponly"] is True
    assert info["samesite"] == "samesite=strict"
    assert info["name"] == "session"


def test_parse_cookie_no_flags():
    info = parse_set_cookie_flags("session=abc")
    assert info["secure"] is False
    assert info["httponly"] is False
    assert info["samesite"] is None


def test_cookie_flags_auth_cookie_missing_flags():
    findings = check_cookie_flags({"set-cookie": "session=abc"}, URL)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "missing Secure flag" in findings[0]["evidence"]["issues"]
    assert "missing HttpOnly flag" in findings[0]["evidence"]["issues"]
    # Never store full cookie value
    assert "abc" not in str(findings[0]["evidence"])


def test_cookie_flags_secure_cookie():
    findings = check_cookie_flags(
        {"set-cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"}, URL
    )
    assert findings == []


def test_cookie_flags_non_auth_cookie():
    findings = check_cookie_flags({"set-cookie": "theme=dark"}, URL)
    # Missing flags on non-auth cookie → medium severity
    if findings:
        assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# CORS tests
# ---------------------------------------------------------------------------

def test_cors_wildcard_no_credentials():
    findings = check_cors(
        {"Access-Control-Allow-Origin": "*"}, URL
    )
    assert findings == []


def test_cors_wildcard_with_credentials():
    findings = check_cors(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        URL,
    )
    assert any(f["check"] == "cors_wildcard_credentials" for f in findings)


def test_cors_origin_reflection():
    findings = check_cors(
        {"Access-Control-Allow-Origin": "https://evil.example.com"},
        URL,
        tested_origin="https://evil.example.com",
    )
    assert any(f["check"] == "cors_origin_reflection" for f in findings)


def test_cors_safe_origin():
    findings = check_cors(
        {"Access-Control-Allow-Origin": "https://trusted.example.com"},
        URL,
        tested_origin="https://evil.example.com",
    )
    assert findings == []


# ---------------------------------------------------------------------------
# run_header_checks integration
# ---------------------------------------------------------------------------

def test_run_header_checks_empty_headers():
    """Empty headers should produce multiple findings."""
    findings = run_header_checks({}, URL)
    check_ids = [f["check"] for f in findings]
    assert "missing_hsts" in check_ids
    assert "missing_csp" in check_ids
    assert "missing_clickjacking_protection" in check_ids
    assert "missing_referrer_policy" in check_ids


def test_run_header_checks_all_good():
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }
    findings = run_header_checks(headers, URL)
    security_issues = [f for f in findings if f["check"] not in ("insecure_cookie_flags",)]
    assert security_issues == []
