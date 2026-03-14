"""Company context parsing tests."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services import company_context


class FakeResponse:
    def __init__(self, url: str, text: str):
        self.url = url
        self.text = text


class FakeClient:
    def __init__(self, response: FakeResponse):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url):
        return self.response


def test_generate_company_context(monkeypatch):
    html = """
    <html>
      <head>
        <title>Acme Payments Platform</title>
        <meta name="description" content="Acme provides secure payments, billing, and wallet APIs for SaaS businesses." />
      </head>
      <body>dashboard billing checkout wallet</body>
    </html>
    """
    monkeypatch.setattr(
        company_context.httpx,
        "Client",
        lambda *a, **k: FakeClient(FakeResponse("https://acme.example.com", html)),
    )
    out = company_context.generate_company_context("https://acme.example.com")
    assert out.industry in {"fintech", "saas"}
    assert out.business_model in {"b2b", "subscription", "unknown"}
    assert len(out.keywords) > 0
    assert len(out.likely_attack_surface) > 0
    assert out.summary_hash


def test_context_similarity():
    sim_same = company_context.context_similarity("payments dashboard users", "payments dashboard users")
    sim_diff = company_context.context_similarity("education campus students", "crypto exchange trading wallet")
    assert sim_same == 1.0
    assert sim_diff < 0.5
