"""
Integration test for the Knowledge Digest chain — runs all six nodes in order against one shared
in-memory store, verifying the data contracts connect end to end (digest_resolved_groups → activity →
analyses → per-group reports → email) and that the security_findings ledger flows into the delivered
email's roll-up. Exercises the quiet-week path (no commits): no LLM is called, yet a digest still ships
with the security reassurance, and the lock is released.
"""
import sys
import os
import time
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

NODES = ["digest_check_and_init", "fetch_activity", "analyze_activity",
         "generate_business_report", "generate_technical_report", "send_digest"]


class Store:
    """Dict-backed waveassist data store with a separate run-based namespace."""
    def __init__(self):
        self.g, self.r = {}, {}

    def fetch(self, key=None, default=None, run_based=False, **k):
        return (self.r if run_based else self.g).get(key, default)

    def store(self, key, value, run_based=False, data_type=None, **k):
        (self.r if run_based else self.g)[key] = value


class FakeResp:
    def __init__(self, payload, status=200):
        self._p, self.status_code, self.links = payload, status, {}

    def json(self):
        return self._p


def test_full_digest_chain_quiet_week_ships_security_rollup(monkeypatch):
    import runpy, waveassist, requests

    store = Store()
    # seed: digest on, one repo, and a live security finding for it (new this week)
    store.g["enable_digest"] = "true"
    store.g["github_selected_resources"] = [{"id": "o/a"}]
    store.g["github_access_token"] = "tok"
    store.g["model_name"] = "anthropic/claude-sonnet-4.6"
    store.g["security_findings"] = {
        "sig1": {"repo": "o/a", "status": "open", "severity": "critical", "title": "Auth bypass",
                 "actively_exploited": True,
                 "first_seen": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()},
    }

    emails = []
    monkeypatch.setattr(waveassist, "init", lambda *a, **k: None)
    monkeypatch.setattr(waveassist, "fetch_data", store.fetch)
    monkeypatch.setattr(waveassist, "store_data", store.store)
    monkeypatch.setattr(waveassist, "check_credits_and_notify", lambda *a, **k: True)
    monkeypatch.setattr(waveassist, "send_email", lambda **k: (emails.append(k) or True))
    # no LLM should be needed on a quiet (no-commit) week
    monkeypatch.setattr(waveassist, "call_llm",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM on a quiet week")))
    # GitHub returns no branches / no commits / no PRs
    monkeypatch.setattr(requests, "post",
                        lambda *a, **k: FakeResp({"data": {"repository": {"refs": {"nodes": [],
                                                  "pageInfo": {"hasNextPage": False}}}}}))
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp([]))
    monkeypatch.setattr(time, "sleep", lambda *a, **k: None)

    for node in NODES:
        runpy.run_path(f"{node}.py", run_name="__main__")

    # contracts connected: gate resolved one implicit group...
    groups = store.r["digest_resolved_groups"]
    assert len(groups) == 1 and groups[0]["repos"] == ["o/a"]
    # ...activity + analyses produced for the repo...
    assert "o/a" in store.g["github_activity_data"]
    assert store.g["repository_analyses"][0]["repository"] == "o/a"
    # ...per-group reports keyed by slug...
    slug = groups[0]["slug"]
    assert slug in store.r["digest_business_reports"]
    assert slug in store.r["digest_technical_reports"]
    # ...and exactly one digest email shipped, carrying the security roll-up from the ledger.
    assert len(emails) == 1
    assert "Auth bypass" in emails[0]["html_content"]
    assert "actively exploited" in emails[0]["html_content"]
    # the timer was set, and the lock was acquired then released by send_digest
    assert store.r["tentative_time_to_process"] is not None
    assert store.g["digest_run_lock"] == {}
    assert slug in store.g["digest_state"]
