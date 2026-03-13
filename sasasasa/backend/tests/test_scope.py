"""Unit tests for scope rules."""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.utils.scope import extract_root_domain, is_in_scope, normalize_url


def test_extract_root_domain_simple():
    assert extract_root_domain("example.com") == "example.com"


def test_extract_root_domain_subdomain():
    assert extract_root_domain("sub.example.com") == "example.com"


def test_extract_root_domain_deep():
    assert extract_root_domain("a.b.c.example.com") == "example.com"


def test_extract_root_domain_single_label():
    assert extract_root_domain("localhost") == "localhost"


def test_is_in_scope_exact():
    assert is_in_scope("https://example.com/path", "example.com") is True


def test_is_in_scope_subdomain():
    assert is_in_scope("https://sub.example.com/path", "example.com") is True


def test_is_in_scope_out_of_scope():
    assert is_in_scope("https://evil.com/path", "example.com") is False


def test_is_in_scope_partial_match():
    # notexample.com should NOT be in scope of example.com
    assert is_in_scope("https://notexample.com/path", "example.com") is False


def test_is_in_scope_nested():
    assert is_in_scope("https://a.b.example.com/", "example.com") is True


def test_is_in_scope_different_tld():
    assert is_in_scope("https://example.org/", "example.com") is False


def test_normalize_url_adds_https():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_http():
    assert normalize_url("http://example.com") == "http://example.com"


def test_normalize_url_keeps_https():
    assert normalize_url("https://example.com/path") == "https://example.com/path"


def test_normalize_url_strips_whitespace():
    assert normalize_url("  https://example.com  ") == "https://example.com"
