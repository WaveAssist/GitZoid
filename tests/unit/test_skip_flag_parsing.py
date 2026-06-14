"""
Regression tests for the run-based skip flag + handoff keys.

The bug (verified live): flags were written run_based=True but read GLOBALLY (so the read always got
the default), and a JSON-stored bool comes back as a truthy dict {"value": "False"}.

The fix matches what the GitZoid team already did for run_lock_token: the flags are run-based STRINGS
"1"/"0" (strings round-trip cleanly; no dict wrapping), read run-based and compared == "1". The
run-based `security_candidates` handoff (scan→audit→triage) is likewise read run-based.

These tests use a faithful fake of the SDK store (wraps JSON scalars, scopes by run_based) so the
real run-based behaviour is exercised — a global read or a json-bool flag would fail them.
"""
import sys
import os
import runpy

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))


class _FakeStore:
    """Mini-mock of the WaveAssist backend: JSON scalars wrap as {"value": str(v)}; writes/reads are
    scoped by run_based (global dict vs run dict)."""
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
    """Drives the real triage_and_alert.py against the faithful fake. The 'not skipped' case is
    discriminating: it fails for a global candidates read (run-based candidates not found → no email)
    and for a json-bool skip flag (truthy dict → always skip → no email)."""

    def _run(self, monkeypatch, fs):
        import waveassist
        sent = []
        monkeypatch.setattr(waveassist, "fetch_data", fs.fetch)
        monkeypatch.setattr(waveassist, "store_data", fs.store)
        monkeypatch.setattr(waveassist, "send_email", lambda **k: sent.append(k) or True)
        monkeypatch.setattr(waveassist, "is_test_run", lambda: False)
        runpy.run_path("triage_and_alert.py", run_name="__main__")
        return sent, fs

    def _seed(self, fs, skip):
        fs.store("security_skip_run", skip, run_based=True, data_type="string")  # "0"/"1" string
        fs.store("security_candidates", [_FINDING], run_based=True, data_type="json")
        fs.store("security_findings", {}, data_type="json")
        fs.store("github_selected_resources", [{"id": "o/r"}], data_type="json")

    def test_emails_when_not_skipped(self, monkeypatch):
        fs = _FakeStore()
        self._seed(fs, "0")
        sent, fs = self._run(monkeypatch, fs)
        assert len(sent) == 1                          # finds run-based candidates, not skipped → email
        assert fs.g.get("security_findings")           # ledger (global) written

    def test_silent_when_skipped(self, monkeypatch):
        fs = _FakeStore()
        self._seed(fs, "1")
        sent, _ = self._run(monkeypatch, fs)
        assert sent == []                              # "1" → skip honored → no email


class TestWriterStringContract:
    """security_check_and_init must write the flag as a run-based STRING "0"/"1" (not a json bool)."""

    def _run_init(self, monkeypatch, fs):
        import waveassist
        monkeypatch.setattr(waveassist, "fetch_data", fs.fetch)
        monkeypatch.setattr(waveassist, "store_data", fs.store)
        monkeypatch.setattr(waveassist, "check_credits_and_notify", lambda *a, **k: True)
        runpy.run_path("security_check_and_init.py", run_name="__main__")

    def test_acquire_writes_zero_string(self, monkeypatch):
        fs = _FakeStore()
        fs.store("enable_security", "true", data_type="string")
        fs.store("github_selected_resources", [{"id": "o/r"}], data_type="json")
        self._run_init(monkeypatch, fs)
        assert fs.r.get("security_skip_run") == "0"    # acquired this run → "0", run-based, string

    def test_disabled_writes_one_string(self, monkeypatch):
        fs = _FakeStore()
        fs.store("enable_security", "false", data_type="string")
        fs.store("github_selected_resources", [{"id": "o/r"}], data_type="json")
        self._run_init(monkeypatch, fs)
        assert fs.r.get("security_skip_run") == "1"    # disabled → skip → "1"
