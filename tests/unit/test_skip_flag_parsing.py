"""
Regression tests for the run-based flag bug (skip_run / security_skip_run).

Two compounding defects, both fixed here:
  Bug 1: flags are written run_based=True but were read globally → reader always got the default.
  Bug 2: the SDK stores a JSON scalar as {"value": "True"/"False"} and returns that DICT, so a bare
         bool(...) of it is ALWAYS truthy → a naive "just add run_based=True" fix would skip every run.

The fix: read run_based=True AND parse via _flag_is_set (unwraps the dict). The same run_based read
also applies to the run-based `security_candidates` handoff and the `security_run_lock_token`.
"""
import sys
import os
import runpy

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from study_repos import _flag_is_set as sr_flag
from fetch_pull_requests import _flag_is_set as fpr_flag
from scan_dependencies import _flag_is_set as sd_flag
from deep_security_audit import _flag_is_set as dsa_flag
from triage_and_alert import _flag_is_set as ta_flag

ALL_HELPERS = [sr_flag, fpr_flag, sd_flag, dsa_flag, ta_flag]


class TestFlagParsing:
    """Every node's copy of _flag_is_set must unwrap the SDK dict and parse correctly."""

    def test_sdk_wrapped_false_is_false(self):
        for f in ALL_HELPERS:
            assert f({"value": "False"}) is False     # the bug: bool({"value":"False"}) was True

    def test_sdk_wrapped_true_is_true(self):
        for f in ALL_HELPERS:
            assert f({"value": "True"}) is True

    def test_raw_bools(self):
        for f in ALL_HELPERS:
            assert f(True) is True
            assert f(False) is False

    def test_missing_or_none_is_false(self):
        for f in ALL_HELPERS:
            assert f(None) is False
            assert f("") is False


class _FakeStore:
    """Faithful mini-mock of the WaveAssist SDK store: wraps JSON scalars as {"value": str(v)} like
    the real backend, and scopes writes/reads by run_based so the run-based handoff is exercised."""
    def __init__(self):
        self.g, self.r = {}, {}

    def store(self, key, value, run_based=False, data_type=None):
        if data_type == "json" and not isinstance(value, (dict, list)):
            value = {"value": str(value)}
        (self.r if run_based else self.g)[key] = value
        return True

    def fetch(self, key=None, run_based=False, default=None):
        return (self.r if run_based else self.g).get(key, default)


_FINDING = {"category": "dependency", "repo": "o/r", "name": "litellm", "version": "1.0",
            "vuln_id": "CVE-1", "severity": "high", "fixed": "1.1", "impact": "leaks keys",
            "actively_exploited": True}


class TestTriageRunBasedHandoff:
    """Drives the real triage_and_alert.py against the faithful fake. The 'not skipped' case is the
    discriminating one: it fails for the current bug (candidates read globally → none found → no
    email) AND for a naive Bug-1-only fix (skip read as bool(dict) → always skip → no email)."""

    def _run(self, monkeypatch, fs):
        import waveassist
        sent = []
        monkeypatch.setattr(waveassist, "fetch_data", fs.fetch)
        monkeypatch.setattr(waveassist, "store_data", fs.store)
        monkeypatch.setattr(waveassist, "send_email", lambda **k: sent.append(k) or True)
        monkeypatch.setattr(waveassist, "is_test_run", lambda: False)
        runpy.run_path("triage_and_alert.py", run_name="__main__")
        return sent, fs

    def test_emails_when_not_skipped_with_run_based_candidates(self, monkeypatch):
        fs = _FakeStore()
        fs.store("security_skip_run", False, run_based=True, data_type="json")   # SDK-wrapped False
        fs.store("security_candidates", [_FINDING], run_based=True, data_type="json")
        fs.store("security_findings", {}, data_type="json")
        fs.store("github_selected_resources", [{"id": "o/r"}], data_type="json")
        sent, fs = self._run(monkeypatch, fs)
        assert len(sent) == 1                          # must find run-based candidates and email
        assert fs.g.get("security_findings")           # ledger (global) written

    def test_silent_when_skipped(self, monkeypatch):
        fs = _FakeStore()
        fs.store("security_skip_run", True, run_based=True, data_type="json")    # SDK-wrapped True
        fs.store("security_candidates", [_FINDING], run_based=True, data_type="json")
        fs.store("security_findings", {}, data_type="json")
        fs.store("github_selected_resources", [{"id": "o/r"}], data_type="json")
        sent, _ = self._run(monkeypatch, fs)
        assert sent == []                              # skip flag honored → no email
