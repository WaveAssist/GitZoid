"""
Unit tests for triage_and_alert.py — the single gatekeeper for all security findings.

Covers: position-independent finding identity, the dedupe/escalation ledger (alert once;
re-alert only on escalation or fix-available), resolution detection, ranking, and the
silent-if-empty rule.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from triage_and_alert import (
    finding_sig,
    should_escalate,
    reconcile_ledger,
    rank_findings,
    lock_is_active,
)


def _dep(repo="o/r", name="litellm", title="rce in litellm", severity="high",
         fixed="1.0.1", exploited=False):
    return {"category": "dependency", "repo": repo, "name": name, "title": title,
            "severity": severity, "fixed": fixed, "actively_exploited": exploited,
            "impact": "an attacker can do X"}


class TestFindingSig:
    def test_stable_for_same_logical_finding(self):
        a = _dep(title="RCE in litellm   parser")
        b = _dep(title="rce in litellm parser")          # case + whitespace differences
        assert finding_sig(a) == finding_sig(b)

    def test_differs_by_repo(self):
        assert finding_sig(_dep(repo="o/a")) != finding_sig(_dep(repo="o/b"))

    def test_differs_by_package(self):
        assert finding_sig(_dep(name="a")) != finding_sig(_dep(name="b"))


class TestEscalation:
    def test_severity_increase_escalates(self):
        prior = {"severity": "high", "fixed": None}
        assert should_escalate(prior, _dep(severity="critical", fixed=None)) is True

    def test_fix_now_available_escalates(self):
        prior = {"severity": "high", "fixed": None}
        assert should_escalate(prior, _dep(severity="high", fixed="1.0.1")) is True

    def test_same_state_does_not_escalate(self):
        prior = {"severity": "high", "fixed": "1.0.1"}
        assert should_escalate(prior, _dep(severity="high", fixed="1.0.1")) is False

    def test_severity_decrease_does_not_escalate(self):
        prior = {"severity": "critical", "fixed": "1.0.1"}
        assert should_escalate(prior, _dep(severity="high", fixed="1.0.1")) is False


class TestReconcile:
    def test_new_finding_is_alerted(self):
        ledger, to_alert, resolved = reconcile_ledger({}, [_dep()])
        assert len(to_alert) == 1
        assert len(ledger) == 1
        assert resolved == []
        sig = finding_sig(_dep())
        assert ledger[sig]["status"] == "open"
        assert ledger[sig]["alerted"] is True

    def test_known_finding_not_realerted(self):
        first, _, _ = reconcile_ledger({}, [_dep()])
        ledger, to_alert, resolved = reconcile_ledger(first, [_dep()])
        assert to_alert == []                              # already alerted, unchanged
        assert resolved == []
        assert len(ledger) == 1

    def test_escalation_realerts(self):
        first, _, _ = reconcile_ledger({}, [_dep(severity="high", fixed=None)])
        ledger, to_alert, resolved = reconcile_ledger(first, [_dep(severity="critical", fixed=None)])
        assert len(to_alert) == 1                          # severity rose → re-alert
        assert ledger[finding_sig(_dep())]["severity"] == "critical"

    def test_disappeared_finding_marked_resolved(self):
        first, _, _ = reconcile_ledger({}, [_dep()])
        ledger, to_alert, resolved = reconcile_ledger(first, [])   # gone this run
        assert len(resolved) == 1
        assert to_alert == []                              # resolutions are NOT emailed
        assert ledger[finding_sig(_dep())]["status"] == "resolved"

    def test_resolved_then_reappears_is_open_again(self):
        first, _, _ = reconcile_ledger({}, [_dep()])
        gone, _, _ = reconcile_ledger(first, [])
        back, to_alert, resolved = reconcile_ledger(gone, [_dep()])
        assert back[finding_sig(_dep())]["status"] == "open"
        assert len(to_alert) == 1                          # came back → alert again


class TestRanking:
    def test_kev_first_then_severity(self):
        items = [
            _dep(name="a", severity="high", exploited=False),
            _dep(name="b", severity="low", exploited=True),    # KEV beats severity
            _dep(name="c", severity="critical", exploited=False),
        ]
        ranked = rank_findings(items)
        assert ranked[0]["name"] == "b"                        # actively exploited first
        assert ranked[1]["name"] == "c"                        # then critical
        assert ranked[2]["name"] == "a"

    def test_code_findings_outrank_low_deps(self):
        items = [
            _dep(name="dep", severity="high", exploited=False),
            {"category": "authz", "repo": "o/r", "title": "auth bypass",
             "severity": "high", "named_victim": "any user", "impact": "x"},
        ]
        ranked = rank_findings(items)
        assert ranked[0]["category"] == "authz"                # exploitable code finding leads


class TestLock:
    def test_lock_helpers_present(self):
        assert lock_is_active({}) is False


class TestDriver:
    def _run(self, monkeypatch, fetch_map):
        import runpy, waveassist
        stored, sent = {}, []
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        monkeypatch.setattr(waveassist, "send_email", lambda **k: sent.append(k) or True)
        monkeypatch.setattr(waveassist, "is_test_run", lambda: False)
        runpy.run_path("triage_and_alert.py", run_name="__main__")
        return stored, sent

    def test_skip_run_no_email_no_ledger(self, monkeypatch):
        stored, sent = self._run(monkeypatch, {"security_skip_run": "1"})
        assert sent == []
        assert "security_findings" not in stored

    def test_new_finding_emails_and_stores_ledger(self, monkeypatch):
        cand = [{"category": "dependency", "repo": "o/r", "name": "litellm", "version": "1.0",
                 "vuln_id": "CVE-1", "severity": "high", "fixed": "1.1", "impact": "leaks keys",
                 "actively_exploited": True}]
        stored, sent = self._run(monkeypatch, {
            "security_skip_run": "0", "security_candidates": cand,
            "security_findings": {}, "github_selected_resources": [{"id": "o/r"}]})
        assert len(sent) == 1
        assert "🛡️" in sent[0]["subject"]
        assert "security_findings" in stored
        assert stored["security_findings"][finding_sig(cand[0])]["status"] == "open"

    def test_silent_when_no_candidates(self, monkeypatch):
        stored, sent = self._run(monkeypatch, {
            "security_skip_run": "0", "security_candidates": [],
            "security_findings": {}, "github_selected_resources": [{"id": "o/r"}]})
        assert sent == []                                # silence is the all-clear
        assert "display_output" in stored               # but the run still reports it scanned
