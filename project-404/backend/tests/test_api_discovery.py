"""API discovery tests."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services import api_discovery


class FakeResponse:
    def __init__(self, status_code: int, headers: dict, payload: dict):
        self.status_code = status_code
        self.headers = headers
        self._payload = payload
        self.text = "{}"

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, mapping):
        self.mapping = mapping

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url):
        if url in self.mapping:
            return self.mapping[url]
        return FakeResponse(404, {"content-type": "application/json"}, {})


def test_discover_openapi_endpoints(monkeypatch):
    openapi_payload = {
        "openapi": "3.0.0",
        "paths": {
            "/api/users": {"get": {}, "post": {}},
            "/api/admin/settings": {"get": {}},
        },
    }
    mapping = {"https://demo.example.com/openapi.json": FakeResponse(200, {"content-type": "application/json"}, openapi_payload)}
    monkeypatch.setattr(api_discovery, "_make_client", lambda *a, **k: FakeClient(mapping))

    endpoints = api_discovery.discover_openapi_endpoints(
        start_urls=["https://demo.example.com"],
        root_domain="example.com",
        auth_config=None,
    )
    urls = {(e["method"], e["url"]) for e in endpoints}
    assert ("GET", "https://demo.example.com/api/users") in urls
    assert ("POST", "https://demo.example.com/api/users") in urls
    assert ("GET", "https://demo.example.com/api/admin/settings") in urls


def test_discover_js_endpoints():
    crawled = [
        {
            "url": "https://demo.example.com/static/app.js",
            "unauth_body": 'fetch("/api/orders"); axios.get("https://demo.example.com/api/profile")',
            "auth_body": "",
        }
    ]
    endpoints = api_discovery.discover_js_endpoints(crawled, root_domain="example.com")
    urls = {e["url"] for e in endpoints}
    assert "https://demo.example.com/api/orders" in urls
    assert "https://demo.example.com/api/profile" in urls
