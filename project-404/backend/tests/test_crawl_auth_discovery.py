"""Auth crawl discovery tests."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.tasks import scan_pipeline


class FakeResponse:
    def __init__(self, url: str, status_code: int, text: str, headers: dict | None = None):
        self.url = url
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class FakeClient:
    def __init__(self, responses: dict[str, FakeResponse]):
        self.responses = responses

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url: str, headers: dict | None = None):
        if url not in self.responses:
            raise RuntimeError(f"unexpected url: {url}")
        return self.responses[url]


def test_crawl_extracts_auth_only_links(monkeypatch):
    unauth = {
        "https://app.example.com": FakeResponse(
            "https://app.example.com", 200, '<a href="/public">Public</a>', {"content-type": "text/html"}
        ),
        "https://app.example.com/public": FakeResponse(
            "https://app.example.com/public", 200, "<html><title>Public</title></html>", {"content-type": "text/html"}
        ),
        "https://app.example.com/private": FakeResponse(
            "https://app.example.com/private", 403, "denied", {"content-type": "text/html"}
        ),
    }
    auth = {
        "https://app.example.com": FakeResponse(
            "https://app.example.com", 200, '<a href="/public">Public</a><a href="/private">Private</a>', {"content-type": "text/html"}
        ),
        "https://app.example.com/public": FakeResponse(
            "https://app.example.com/public", 200, "<html><title>Public</title></html>", {"content-type": "text/html"}
        ),
        "https://app.example.com/private": FakeResponse(
            "https://app.example.com/private", 200, "<html><title>Private</title></html>", {"content-type": "text/html"}
        ),
    }

    clients = [FakeClient(unauth), FakeClient(auth)]
    monkeypatch.setattr(scan_pipeline, "_make_sync_client", lambda *a, **k: clients.pop(0))
    monkeypatch.setattr(scan_pipeline.settings, "rate_limit_delay", 0.0)
    monkeypatch.setattr(scan_pipeline.settings, "max_requests_per_scan", 50)

    out = scan_pipeline.crawl(
        start_urls=["https://app.example.com"],
        root_domain="example.com",
        auth_config={"cookie_header": "session=x"},
        max_depth=2,
    )
    endpoints = {e["url"]: e for e in out["endpoints"]}
    assert "https://app.example.com/private" in endpoints
    assert endpoints["https://app.example.com/private"]["discovered_via"] == "auth"
    assert endpoints["https://app.example.com/private"]["auth_only_navigation"] is True
    assert endpoints["https://app.example.com/private"]["unauth_status"] == 403
    assert endpoints["https://app.example.com/private"]["auth_status"] == 200
