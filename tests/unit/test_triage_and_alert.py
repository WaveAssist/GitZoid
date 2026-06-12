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
    build_alert_email,
    build_subject,
    parse_recipients,
)


class TestRecipients:
    def test_parses_comma_and_space_separated(self):
        assert parse_recipients("a@x.com, b@y.com") == ["a@x.com", "b@y.com"]
        assert parse_recipients("a@x.com b@y.com;c@z.com") == ["a@x.com", "b@y.com", "c@z.com"]

    def test_empty_and_invalid(self):
        assert parse_recipients("") == []
        assert parse_recipients(None) == []
        assert parse_recipients("notanemail, also-bad") == []

EMOJI = "🛡️🔴🟡🔵⚪🚀💡🐛🔒✅⚠️→·—"


class TestCleanOutput:
    """A security email must read clean and serious: no emoji, no em dashes."""

    def _findings(self):
        return [
            {"category": "dependency", "repo": "o/r", "name": "litellm", "version": "1.0",
             "vuln_id": "CVE-1", "severity": "high", "fix": "1.1", "impact": "leaks keys",
             "actively_exploited": True},
            {"category": "authz", "repo": "o/r", "title": "Bypassable check: /acl/list",
             "severity": "high", "named_victim": "any user", "fix": "add authorize_admin",
             "impact": "reads any user's data", "entry_point": "/acl/list"},
        ]

    def test_email_has_no_emoji_or_emdash(self):
        out = build_alert_email(self._findings(), scanned_repos=1)
        for ch in EMOJI:
            assert ch not in out, f"email should not contain {ch!r}"

    def test_subject_has_no_emoji(self):
        subj = build_subject(self._findings())
        for ch in EMOJI:
            assert ch not in subj
        assert "GitZoid Security" in subj

    def test_email_still_shows_fix_and_severity(self):
        out = build_alert_email(self._findings(), scanned_repos=1)
        assert "Fix:" in out
        assert "Severity: High" in out


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

    def test_code_finding_stable_across_reworded_prose(self):
        # Same authz bug (same routes) described differently week to week → SAME identity via dedup_key.
        a = {"category": "authz", "repo": "o/r", "dedup_key": "authz:/acl/list_records",
             "title": "Bypassable check: POST /acl/list_records (and 3 siblings)"}
        b = {"category": "authz", "repo": "o/r", "dedup_key": "authz:/acl/list_records",
             "title": "Missing authorize_admin on /acl/list_records — reads any user's data"}
        assert finding_sig(a) == finding_sig(b)

    def test_code_finding_differs_by_location(self):
        a = {"category": "authz", "repo": "o/r", "dedup_key": "authz:/acl/list_records"}
        b = {"category": "authz", "repo": "o/r", "dedup_key": "authz:/admin/coupons/create"}
        assert finding_sig(a) != finding_sig(b)


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
            "security_findings": {}, "github_selected_resources": [{"id": "o/r"}],
            "security_recipients": "lead@acme.com, sec@acme.com"})
        assert len(sent) == 1
        assert "GitZoid Security" in sent[0]["subject"]
        assert sent[0]["cc"] == ["lead@acme.com", "sec@acme.com"]   # extras CC'd; owner is primary
        assert "security_findings" in stored
        assert stored["security_findings"][finding_sig(cand[0])]["status"] == "open"

    def test_silent_when_no_candidates(self, monkeypatch):
        stored, sent = self._run(monkeypatch, {
            "security_skip_run": "0", "security_candidates": [],
            "security_findings": {}, "github_selected_resources": [{"id": "o/r"}]})
        assert sent == []                                # silence is the all-clear
        assert "display_output" in stored               # but the run still reports it scanned
