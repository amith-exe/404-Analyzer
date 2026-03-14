"""Diff engine tests."""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.diff_engine import build_scan_diff, should_send_webhook


class FakeQuery:
    def __init__(self, data):
        self.data = data
        self.filters = []

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def all(self):
        return self.data

    def first(self):
        return self.data[0] if self.data else None


class FakeDB:
    def __init__(self, endpoints_prev, endpoints_curr, findings_prev, findings_curr, contexts_prev, contexts_curr):
        self.endpoints_prev = endpoints_prev
        self.endpoints_curr = endpoints_curr
        self.findings_prev = findings_prev
        self.findings_curr = findings_curr
        self.contexts_prev = contexts_prev
        self.contexts_curr = contexts_curr
        self.call = 0

    def query(self, _model):
        self.call += 1
        mapping = {
            1: self.endpoints_prev,
            2: self.endpoints_curr,
            3: self.findings_prev,
            4: self.findings_curr,
            5: self.contexts_prev,
            6: self.contexts_curr,
        }
        return FakeQuery(mapping.get(self.call, []))


def test_build_scan_diff_and_threshold():
    prev_scan = SimpleNamespace(id=1)
    curr_scan = SimpleNamespace(id=2)
    ep_prev = [
        SimpleNamespace(method="GET", url="https://a.example.com/api/me", status_code=403, headers={"X-Frame-Options": "DENY"}),
    ]
    ep_curr = [
        SimpleNamespace(method="GET", url="https://a.example.com/api/me", status_code=200, headers={"X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'"}),
        SimpleNamespace(method="GET", url="https://a.example.com/api/new", status_code=200, headers={}),
    ]
    f_prev = [SimpleNamespace(title="Old finding", severity=SimpleNamespace(value="medium"), affected_url="/x", fingerprint_hash="a1")]
    f_curr = [SimpleNamespace(title="New finding", severity=SimpleNamespace(value="high"), affected_url="/y", fingerprint_hash="b2")]
    c_prev = [SimpleNamespace(description_raw="old healthcare portal", industry="healthcare", summary_hash="x1")]
    c_curr = [SimpleNamespace(description_raw="new fintech billing portal", industry="fintech", summary_hash="x2")]

    db = FakeDB(ep_prev, ep_curr, f_prev, f_curr, c_prev, c_curr)
    diff = build_scan_diff(prev_scan, curr_scan, db)
    assert diff["counts"]["new_endpoints"] == 1
    assert diff["counts"]["status_changes"] == 1
    assert diff["counts"]["new_findings"] == 1
    assert diff["counts"]["removed_findings"] == 1
    assert diff["context_change"]["changed"] is True
    assert should_send_webhook(diff, {"new_findings": 1}) is True
