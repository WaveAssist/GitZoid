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
    split_findings,
    cap_code_findings,
    lock_is_active,
    build_alert_email,
    build_subject,
    parse_recipients,
    parse_groups,
    slugify,
    resolve_groups,
    clean_email_list,
    group_alerts,
    MAX_CODE_ALERTS,
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
        fs = self._findings()
        code = [f for f in fs if f["category"] in ("authz", "secret", "backdoor")]
        deps = [f for f in fs if f["category"] == "dependency"]
        out = build_alert_email(code, deps, scanned_repos=1)
        for ch in EMOJI:
            assert ch not in out, f"email should not contain {ch!r}"

    def test_subject_has_no_emoji(self):
        subj = build_subject(self._findings())
        for ch in EMOJI:
            assert ch not in subj
        assert "GitZoid Security" in subj

    def test_email_still_shows_fix_and_severity(self):
        fs = self._findings()
        code = [f for f in fs if f["category"] in ("authz", "secret", "backdoor")]
        deps = [f for f in fs if f["category"] == "dependency"]
        out = build_alert_email(code, deps, scanned_repos=1)
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


class TestAuthzDedupAcrossRuns:
    """End-to-end: the SAME authz bug, reworded by the model on a later run, must not re-alert."""

    def test_reworded_authz_not_realerted(self):
        run1 = [{"category": "authz", "repo": "o/r", "dedup_key": "authz:/acl/list_records",
                 "title": "Bypassable check: /acl/list_records in Admin/Controllers/x.py",
                 "severity": "high", "impact": "reads any user data"}]
        ledger, alerted1, _ = reconcile_ledger({}, run1)
        assert len(alerted1) == 1                          # first time → alert

        run2 = [{"category": "authz", "repo": "o/r", "dedup_key": "authz:/acl/list_records",
                 "title": "Missing authorize_admin on /acl/list_records",   # reworded
                 "severity": "high", "impact": "reads any user data"}]
        ledger2, alerted2, resolved = reconcile_ledger(ledger, run2)
        assert alerted2 == []                              # same dedup_key → suppressed
        assert resolved == []                              # still present, not resolved
        assert len(ledger2) == 1                           # no duplicate entry


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
        # Resolution now requires the repo to have been SCANNED OK this run (absence alone is not a fix).
        first, _, _ = reconcile_ledger({}, [_dep()])
        ledger, to_alert, resolved = reconcile_ledger(first, [], scanned_ok_deps={"o/r"})   # gone, repo scanned
        assert len(resolved) == 1
        assert to_alert == []                              # resolutions are NOT emailed
        assert ledger[finding_sig(_dep())]["status"] == "resolved"

    def test_resolved_then_reappears_is_open_again(self):
        first, _, _ = reconcile_ledger({}, [_dep()])
        gone, _, _ = reconcile_ledger(first, [], scanned_ok_deps={"o/r"})
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
        assert stored.get("run_idle") == "1"            # silent scan → marked idle

    def test_alerted_run_not_marked_idle(self, monkeypatch):
        cand = [{"category": "dependency", "repo": "o/r", "name": "x", "version": "1",
                 "vuln_id": "CVE-9", "severity": "high", "fixed": "1.1", "impact": "y",
                 "actively_exploited": True}]
        stored, sent = self._run(monkeypatch, {
            "security_skip_run": "0", "security_candidates": cand,
            "security_findings": {}, "github_selected_resources": [{"id": "o/r"}]})
        assert len(sent) == 1
        assert "run_idle" not in stored                 # an alert went out → acted, not idle

    def test_skip_run_marked_idle(self, monkeypatch):
        stored, sent = self._run(monkeypatch, {"security_skip_run": "1"})
        assert stored.get("run_idle") == "1"            # skipped cycle → idle


class TestReconcileScannedOk:
    """Issue #1 (repeated emails): only RESOLVE a finding when its repo was actually scanned OK this
    run. Absence from a feed/GitHub/LLM hiccup must carry the finding forward, not resolve+re-alert."""

    def test_no_resolve_on_unscanned_repo(self):
        first, _, _ = reconcile_ledger({}, [_dep()])
        ledger, to_alert, resolved = reconcile_ledger(first, [], scanned_ok_deps=set())   # feed hiccup
        assert resolved == []
        assert ledger[finding_sig(_dep())]["status"] == "open"

    def test_resolve_only_when_repo_scanned(self):
        first, _, _ = reconcile_ledger({}, [_dep()])
        ledger, to_alert, resolved = reconcile_ledger(first, [], scanned_ok_deps={"o/r"})
        assert len(resolved) == 1
        assert ledger[finding_sig(_dep())]["status"] == "resolved"

    def test_unscanned_other_repo_does_not_resolve_target(self):
        first, _, _ = reconcile_ledger({}, [_dep(repo="o/a")])
        ledger, to_alert, resolved = reconcile_ledger(first, [], scanned_ok_deps={"o/b"})
        assert resolved == []
        assert ledger[finding_sig(_dep(repo="o/a"))]["status"] == "open"

    def test_no_realert_after_feed_hiccup(self):
        first, _, _ = reconcile_ledger({}, [_dep()])
        # feed failed: finding absent, repo NOT scanned ok -> carried forward, not resolved
        hiccup, to_alert, resolved = reconcile_ledger(first, [], scanned_ok_deps=set())
        assert to_alert == [] and resolved == []
        # next run recovers, same finding present -> it was never resolved, so NO re-alert
        back, to_alert2, _ = reconcile_ledger(hiccup, [_dep()], scanned_ok_deps={"o/r"})
        assert to_alert2 == []


class TestSeverityAndFixFlap:
    """Flapping feed severity / fix-availability must re-alert at most ONCE, not every cycle."""

    def test_no_realert_on_severity_flap(self):
        l1, _, _ = reconcile_ledger({}, [_dep(severity="high", fixed=None)])
        l2, a2, _ = reconcile_ledger(l1, [_dep(severity="critical", fixed=None)], scanned_ok_deps={"o/r"})
        assert len(a2) == 1
        assert l2[finding_sig(_dep())]["max_alerted_severity"] == "critical"
        l3, a3, _ = reconcile_ledger(l2, [_dep(severity="high", fixed=None)], scanned_ok_deps={"o/r"})
        assert a3 == []                                    # high < critical hwm -> no re-alert
        l4, a4, _ = reconcile_ledger(l3, [_dep(severity="critical", fixed=None)], scanned_ok_deps={"o/r"})
        assert a4 == []                                    # back to critical, still at hwm -> no re-alert

    def test_no_realert_on_fix_flap(self):
        l1, _, _ = reconcile_ledger({}, [_dep(fixed=None)])
        l2, a2, _ = reconcile_ledger(l1, [_dep(fixed="1.0.1")], scanned_ok_deps={"o/r"})
        assert len(a2) == 1
        assert l2[finding_sig(_dep())]["fix_alerted"] is True
        l3, a3, _ = reconcile_ledger(l2, [_dep(fixed=None)], scanned_ok_deps={"o/r"})
        assert a3 == []                                    # fix field cleared -> no re-alert
        l4, a4, _ = reconcile_ledger(l3, [_dep(fixed="1.0.1")], scanned_ok_deps={"o/r"})
        assert a4 == []                                    # fix reappears -> already alerted, no re-alert

    def test_max_alerted_severity_and_fix_alerted_seeded(self):
        ledger, _, _ = reconcile_ledger({}, [_dep(severity="high", fixed="1.0.1")])
        e = ledger[finding_sig(_dep())]
        assert e["max_alerted_severity"] == "high"
        assert e["fix_alerted"] is True
        ledger2, _, _ = reconcile_ledger({}, [_dep(fixed=None)])
        assert ledger2[finding_sig(_dep())]["fix_alerted"] is False


class TestSeparation:
    """Issue #4: code/access issues and dependencies render in their own labelled sections, and
    dependencies are NEVER capped (issue #1: report them all at once)."""

    def _code(self):
        return {"category": "authz", "repo": "o/r", "title": "Bypassable check: /acl/list",
                "severity": "high", "named_victim": "any user", "fix": "add authorize_admin",
                "impact": "reads any user's data", "entry_point": "/acl/list"}

    def _dep_f(self, name="litellm"):
        return {"category": "dependency", "repo": "o/r", "name": name, "version": "1.0",
                "vuln_id": "CVE-1", "severity": "high", "fix": "1.1", "impact": "leaks keys"}

    def test_email_has_two_labelled_sections_code_first(self):
        out = build_alert_email([self._code()], [self._dep_f()], scanned_repos=2)
        assert "Code and access issues" in out
        assert "Vulnerable dependencies" in out
        assert out.index("Code and access issues") < out.index("Vulnerable dependencies")
        for ch in EMOJI:
            assert ch not in out

    def test_code_section_omitted_when_empty(self):
        out = build_alert_email([], [self._dep_f()], scanned_repos=1)
        assert "Code and access issues" not in out
        assert "Vulnerable dependencies" in out

    def test_all_dep_findings_sent_not_capped(self):
        deps = [self._dep_f(name=f"pkg{i}") for i in range(20)]
        out = build_alert_email([], deps, scanned_repos=1)
        assert all(f"pkg{i}" in out for i in range(20))     # no dependency cap

    def test_code_cap_applied_but_kev_kept(self):
        code = []
        for i in range(8):
            f = self._code()
            f = {**f, "entry_point": f"/r{i}", "title": f"issue {i}", "severity": "low",
                 "actively_exploited": (i == 7)}      # the LAST one is KEV and lowest priority
            code.append(f)
        kept = cap_code_findings(code)
        assert any(f.get("actively_exploited") for f in kept)   # KEV one survives the cap
        non_kev = [f for f in kept if not f.get("actively_exploited")]
        assert len(non_kev) <= MAX_CODE_ALERTS


class TestScannedOkCategoryScoped:
    """REGRESSION (review P0): a daily dependency-only scan must NOT resolve an un-re-audited CODE
    finding (authz/secret/backdoor). Code findings resolve only against scanned_ok_code (weekly
    audit); dependency findings only against scanned_ok_deps."""

    def _authz(self, repo="o/r"):
        return {"category": "authz", "repo": repo, "dedup_key": "authz:/acl/list",
                "title": "Bypassable check: /acl/list", "severity": "high",
                "impact": "reads any user's data"}

    def test_dep_scan_does_not_resolve_code_finding(self):
        first, _, _ = reconcile_ledger({}, [self._authz()])
        # daily dep scan ran clean for o/r, but the code was NOT audited this run
        ledger, to_alert, resolved = reconcile_ledger(first, [], scanned_ok_deps={"o/r"},
                                                      scanned_ok_code=set())
        assert resolved == []
        assert ledger[finding_sig(self._authz())]["status"] == "open"

    def test_code_scan_resolves_code_finding(self):
        first, _, _ = reconcile_ledger({}, [self._authz()])
        ledger, to_alert, resolved = reconcile_ledger(first, [], scanned_ok_code={"o/r"})
        assert len(resolved) == 1
        assert ledger[finding_sig(self._authz())]["status"] == "resolved"

    def test_code_scan_does_not_resolve_dependency_finding(self):
        first, _, _ = reconcile_ledger({}, [_dep()])
        # weekly audit ran (code), but deps were not scanned this run
        ledger, to_alert, resolved = reconcile_ledger(first, [], scanned_ok_code={"o/r"},
                                                      scanned_ok_deps=set())
        assert resolved == []
        assert ledger[finding_sig(_dep())]["status"] == "open"


class TestDependencyGrouping:
    """Real-world fix: many CVEs for the SAME package must consolidate into ONE block with ONE
    upgrade target, not a dozen near-identical entries with conflicting 'upgrade to X' advice."""

    def _cve(self, vuln_id, severity, fix, impact="some impact"):
        return {"category": "dependency", "repo": "o/r", "name": "Django", "version": "4.2",
                "vuln_id": vuln_id, "severity": severity, "fix": fix, "impact": impact}

    def test_same_package_consolidated_into_one_block(self):
        deps = [
            self._cve("GHSA-1", "critical", "5.2.8", "sql injection"),
            self._cve("GHSA-2", "high", "4.2.24", "denial of service"),
            self._cve("GHSA-3", "high", "6.0.4", "path traversal"),
        ]
        out = build_alert_email([], deps, scanned_repos=1)
        assert out.count("Django 4.2") == 1                      # one block, not three
        assert "3 known vulnerabilities" in out                  # the count
        assert "upgrade Django to 6.0.4 or later" in out         # single target = highest fixed version
        assert "Severity: Critical" in out                       # worst severity surfaced
        for ref in ("GHSA-1", "GHSA-2", "GHSA-3"):
            assert ref in out                                    # every advisory still referenced

    def test_distinct_packages_stay_separate(self):
        deps = [self._cve("GHSA-1", "high", "5.2.8"),
                {"category": "dependency", "repo": "o/r", "name": "authlib", "version": "1.6.4",
                 "vuln_id": "GHSA-9", "severity": "high", "fix": "1.6.5", "impact": "dos"}]
        out = build_alert_email([], deps, scanned_repos=1)
        assert "Django 4.2" in out and "authlib 1.6.4" in out

    def test_no_fixed_version_group(self):
        deps = [self._cve("GHSA-1", "high", None), self._cve("GHSA-2", "high", None)]
        out = build_alert_email([], deps, scanned_repos=1)
        assert "No fixed version" in out


class TestDependencySectionDesign:
    """Dependencies render as their own clearly-marked section at the END of the email, in a calm
    slate accent with a labelled header + one-line explainer, visually distinct from the red
    code/access blocks above."""

    def _code(self):
        return {"category": "authz", "repo": "o/r", "title": "auth bypass", "severity": "high",
                "impact": "reads any user data", "entry_point": "/x"}

    def _dep(self):
        return {"category": "dependency", "repo": "o/r", "name": "django", "version": "1.6",
                "vuln_id": "CVE-1", "severity": "high", "fix": "4.2", "impact": "remote code execution"}

    def test_section_has_label_and_explainer(self):
        out = build_alert_email([], [self._dep()], scanned_repos=1)
        assert "Vulnerable dependencies" in out
        assert "The fix is to upgrade the package." in out

    def test_dep_blocks_slate_code_blocks_red_and_after(self):
        out = build_alert_email([self._code()], [self._dep()], scanned_repos=1)
        assert "border-left:4px solid #475569" in out      # dependency block = slate accent
        assert "border-left:4px solid #b91c1c" in out      # code/access block = red accent
        assert out.index("#b91c1c") < out.index("#475569")  # code section renders before deps

    def test_divider_only_when_both_sections_present(self):
        rule = "height:1px;background:#e5e7eb"
        assert rule in build_alert_email([self._code()], [self._dep()], scanned_repos=1)
        assert rule not in build_alert_email([], [self._dep()], scanned_repos=1)   # deps-only: no stray rule

    def test_design_stays_clean_no_emoji_or_emdash(self):
        out = build_alert_email([self._code()], [self._dep()], scanned_repos=1)
        for ch in EMOJI:
            assert ch not in out


class TestIssueCountGrouped:
    """The header/subject 'N issues' must count GROUPED issues (a package = 1), not raw CVEs —
    so 12 Django advisories shown as one block count as one issue, not twelve."""

    def _cve(self, vid, sev, fix):
        return {"category": "dependency", "repo": "o/r", "name": "Django", "version": "4.2",
                "vuln_id": vid, "severity": sev, "fix": fix, "impact": "x"}

    def test_header_and_subject_count_packages_not_cves(self):
        code = [{"category": "authz", "repo": "o/r", "title": "A", "severity": "high", "impact": "x"},
                {"category": "secret", "repo": "o/r", "title": "B", "severity": "high", "impact": "x"}]
        deps = [self._cve("GHSA-1", "critical", "5.2.8"),
                self._cve("GHSA-2", "high", "4.2.24"),
                self._cve("GHSA-3", "high", "6.0.4")]      # 3 Django CVEs = ONE package
        out = build_alert_email(code, deps, scanned_repos=2)
        assert "3 issues found" in out                     # 2 code + 1 Django package
        assert "5 issues" not in out                       # not the raw 2+3
        subj = build_subject(code + deps)
        assert "3 issues" in subj

    def test_single_issue_singular_wording(self):
        out = build_alert_email([], [self._cve("GHSA-1", "high", "5.0.7")], scanned_repos=1)
        assert "1 issue found" in out and "1 issues" not in out


class TestSubjectMultiRepo:
    """Fix D: when findings span multiple repos the subject must not name just one repo."""

    def _f(self, repo, sev="high", **kw):
        return {"category": "authz", "repo": repo, "title": f"bug in {repo}",
                "severity": sev, "impact": "x", **kw}

    def test_single_repo_names_the_repo(self):
        s = build_subject([self._f("o/r")])
        assert "in o/r" in s

    def test_multi_repo_says_count_of_repos(self):
        s = build_subject([self._f("o/a"), self._f("o/b")])
        assert "2 repositories" in s
        assert "GitZoid Security" in s

    def test_kev_multi_repo_mentions_more(self):
        s = build_subject([self._f("o/a", actively_exploited=True), self._f("o/b")])
        assert "actively exploited" in s and "more" in s


# ---------------------------------------------------------------- group routing (per-group delivery)
# A separate `security_groups` config splits the to-alert set by repo so different repos route to
# different people. resolve_groups/parse_groups/slugify mirror the digest's (duplicated by the same
# no-sibling-imports convention as the lock helpers). group_alerts is the security-specific partition,
# including the owner-only catch-all that guarantees a finding is never silently dropped.

class TestParseGroups:
    def test_list_passthrough(self):
        g = [{"name": "A", "repos": ["o/r"], "recipients": []}]
        assert parse_groups(g) == g

    def test_json_string_parsed(self):
        assert parse_groups('[{"name":"A","repos":["o/r"],"recipients":[]}]') == \
            [{"name": "A", "repos": ["o/r"], "recipients": []}]

    def test_garbage_and_empty_become_empty_list(self):
        assert parse_groups("not json") == []
        assert parse_groups("") == []
        assert parse_groups(None) == []
        assert parse_groups('{"not":"a list"}') == []


class TestSlugify:
    def test_kebab_case(self):
        assert slugify("Acme Platform", 0) == "acme-platform"

    def test_strips_punctuation(self):
        assert slugify("  Mobile / Web!! ", 0) == "mobile-web"

    def test_empty_name_falls_back_to_index(self):
        assert slugify("", 3) == "group-4"
        assert slugify(None, 0) == "group-1"


class TestResolveGroups:
    REPOS = [{"id": "o/a"}, {"id": "o/b"}, {"id": "o/c"}]

    def test_explicit_groups_kept_and_intersected_with_selected(self):
        groups = [{"name": "Front", "repos": ["o/a", "o/x"], "recipients": ["a@x.com"]}]
        out = resolve_groups(groups, self.REPOS)
        assert len(out) == 1
        assert out[0]["repos"] == ["o/a"]            # o/x dropped (not selected)
        assert out[0]["recipients"] == ["a@x.com"]
        assert out[0]["slug"] == "front"
        assert out[0]["implicit"] is False

    def test_group_with_no_selected_repos_is_dropped_then_implicit_fallback(self):
        out = resolve_groups([{"name": "Dead", "repos": ["o/gone"], "recipients": []}], self.REPOS)
        assert len(out) == 1
        assert out[0]["implicit"] is True            # no surviving group -> default-all over selected
        assert sorted(out[0]["repos"]) == ["o/a", "o/b", "o/c"]
        assert out[0]["recipients"] == []            # owner only

    def test_empty_groups_fall_back_to_one_implicit_group_over_all_selected(self):
        out = resolve_groups([], self.REPOS)
        assert len(out) == 1
        assert out[0]["implicit"] is True
        assert out[0]["slug"] == "group-1"
        assert sorted(out[0]["repos"]) == ["o/a", "o/b", "o/c"]

    def test_no_repos_at_all_yields_no_groups(self):
        assert resolve_groups([], []) == []

    def test_duplicate_names_get_unique_slugs(self):
        groups = [{"name": "Team", "repos": ["o/a"], "recipients": []},
                  {"name": "Team", "repos": ["o/b"], "recipients": []}]
        out = resolve_groups(groups, self.REPOS)
        assert [g["slug"] for g in out] == ["team", "team-2"]

    def test_string_repo_list_supported(self):
        out = resolve_groups([], ["o/a", "o/b"])
        assert sorted(out[0]["repos"]) == ["o/a", "o/b"]


class TestCleanEmailList:
    def test_validates_and_dedupes_preserving_order(self):
        assert clean_email_list(["a@x.com", "bad", "a@x.com", "b@y.com"]) == ["a@x.com", "b@y.com"]

    def test_empty_and_none(self):
        assert clean_email_list([]) == []
        assert clean_email_list(None) == []


class TestGroupAlerts:
    """Partition the reconciled to-alert set into per-group send units, by the finding's repo."""

    def _dep(self, repo, name="x"):
        return {"category": "dependency", "repo": repo, "name": name, "version": "1",
                "vuln_id": f"CVE-{name}", "severity": "high", "fixed": "1.1", "impact": "y"}

    def test_single_implicit_group_one_unit_all_findings(self):
        groups = resolve_groups([], [{"id": "o/a"}, {"id": "o/b"}])      # default-all
        units = group_alerts([self._dep("o/a"), self._dep("o/b")], groups)
        assert len(units) == 1
        assert len(units[0]["findings"]) == 2
        assert units[0]["recipients"] == []

    def test_explicit_groups_split_by_repo_with_recipients(self):
        groups = resolve_groups([
            {"name": "Front", "repos": ["o/a"], "recipients": ["a@x.com"]},
            {"name": "Back", "repos": ["o/b"], "recipients": ["b@x.com"]},
        ], [{"id": "o/a"}, {"id": "o/b"}])
        units = group_alerts([self._dep("o/a", "pkgA"), self._dep("o/b", "pkgB")], groups)
        by_slug = {u["slug"]: u for u in units}
        assert by_slug["front"]["recipients"] == ["a@x.com"]
        assert by_slug["front"]["findings"][0]["repo"] == "o/a"
        assert by_slug["back"]["recipients"] == ["b@x.com"]
        assert by_slug["back"]["findings"][0]["repo"] == "o/b"

    def test_group_with_no_findings_produces_no_unit(self):
        groups = resolve_groups([
            {"name": "Front", "repos": ["o/a"], "recipients": ["a@x.com"]},
            {"name": "Back", "repos": ["o/b"], "recipients": ["b@x.com"]},
        ], [{"id": "o/a"}, {"id": "o/b"}])
        units = group_alerts([self._dep("o/a")], groups)               # only o/a has a finding
        assert len(units) == 1
        assert units[0]["slug"] == "front"

    def test_ungrouped_repo_goes_to_owner_only_catch_all_last(self):
        groups = resolve_groups([{"name": "Front", "repos": ["o/a"], "recipients": ["a@x.com"]}],
                                [{"id": "o/a"}, {"id": "o/b"}])         # o/b in no group
        units = group_alerts([self._dep("o/a"), self._dep("o/b", "pkgB")], groups)
        assert units[-1]["slug"] == "ungrouped"                        # catch-all rendered last
        catch = units[-1]
        assert catch["recipients"] == []                               # owner only, no extra CC
        assert catch["findings"][0]["repo"] == "o/b"

    def test_no_findings_no_units(self):
        assert group_alerts([], resolve_groups([], [{"id": "o/a"}])) == []


class TestGroupedDelivery:
    """Driver-level: with a configured security_groups, the to-alert set fans out into one email per
    group (group recipients + global security_recipients CC'd), the code cap is per group, and a repo
    in no group still alerts the owner. With no groups configured, behaviour is the old single email."""

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

    def _dep(self, repo, name):
        return {"category": "dependency", "repo": repo, "name": name, "version": "1",
                "vuln_id": f"CVE-{name}", "severity": "high", "fixed": "1.1", "impact": "y"}

    def _code(self, repo, i):
        return {"category": "authz", "repo": repo, "dedup_key": f"authz:/r{i}",
                "title": f"bug {i}", "severity": "high", "impact": "x", "entry_point": f"/r{i}"}

    def test_explicit_groups_send_separate_emails_to_their_recipients(self, monkeypatch):
        groups = [{"name": "Front", "repos": ["o/a"], "recipients": ["front@acme.com"]},
                  {"name": "Back", "repos": ["o/b"], "recipients": ["back@acme.com"]}]
        cand = [self._dep("o/a", "pkgA"), self._dep("o/b", "pkgB")]
        stored, sent = self._run(monkeypatch, {
            "security_skip_run": "0", "security_candidates": cand, "security_findings": {},
            "github_selected_resources": [{"id": "o/a"}, {"id": "o/b"}],
            "security_groups": groups})
        assert len(sent) == 2
        ccs = {tuple(s["cc"] or ()): s for s in sent}
        assert ("front@acme.com",) in ccs and ("back@acme.com",) in ccs
        assert "pkgA" in ccs[("front@acme.com",)]["html_content"]
        assert "pkgB" not in ccs[("front@acme.com",)]["html_content"]   # each group sees only its repos

    def test_global_recipients_cc_on_every_group(self, monkeypatch):
        groups = [{"name": "Front", "repos": ["o/a"], "recipients": ["front@acme.com"]}]
        cand = [self._dep("o/a", "pkgA")]
        stored, sent = self._run(monkeypatch, {
            "security_skip_run": "0", "security_candidates": cand, "security_findings": {},
            "github_selected_resources": [{"id": "o/a"}],
            "security_groups": groups, "security_recipients": "soc@acme.com"})
        assert len(sent) == 1
        assert sent[0]["cc"] == ["front@acme.com", "soc@acme.com"]      # group + global, de-duped

    def test_ungrouped_repo_alerts_owner_only(self, monkeypatch):
        groups = [{"name": "Front", "repos": ["o/a"], "recipients": ["front@acme.com"]}]
        cand = [self._dep("o/a", "pkgA"), self._dep("o/b", "pkgB")]   # o/b in no group
        stored, sent = self._run(monkeypatch, {
            "security_skip_run": "0", "security_candidates": cand, "security_findings": {},
            "github_selected_resources": [{"id": "o/a"}, {"id": "o/b"}],
            "security_groups": groups})
        assert len(sent) == 2
        owner_only = [s for s in sent if not s["cc"]]
        assert len(owner_only) == 1                                    # catch-all, owner only
        assert "pkgB" in owner_only[0]["html_content"]
        assert "pkgA" not in owner_only[0]["html_content"]

    def test_no_groups_configured_single_email_like_before(self, monkeypatch):
        cand = [self._dep("o/a", "pkgA"), self._dep("o/b", "pkgB")]
        stored, sent = self._run(monkeypatch, {
            "security_skip_run": "0", "security_candidates": cand, "security_findings": {},
            "github_selected_resources": [{"id": "o/a"}, {"id": "o/b"}],
            "security_recipients": "lead@acme.com"})
        assert len(sent) == 1                                          # one consolidated email
        assert sent[0]["cc"] == ["lead@acme.com"]
        body = sent[0]["html_content"]
        assert "pkgA" in body and "pkgB" in body

    def test_code_cap_is_per_group(self, monkeypatch):
        cand = [self._code("o/a", i) for i in range(6)] + [self._code("o/b", i) for i in range(6)]
        groups = [{"name": "A", "repos": ["o/a"], "recipients": ["a@x.com"]},
                  {"name": "B", "repos": ["o/b"], "recipients": ["b@x.com"]}]
        stored, sent = self._run(monkeypatch, {
            "security_skip_run": "0", "security_candidates": cand, "security_findings": {},
            "github_selected_resources": [{"id": "o/a"}, {"id": "o/b"}],
            "security_groups": groups})
        assert len(sent) == 2
        red = "border-left:4px solid #b91c1c"                          # one per rendered code block
        per_email = [s["html_content"].count(red) for s in sent]
        assert all(c <= MAX_CODE_ALERTS for c in per_email)            # cap applies per group
        assert sum(per_email) > MAX_CODE_ALERTS                        # more shown than a single global cap

    def test_display_output_carries_slugs_counts_and_summary_title(self, monkeypatch):
        # The dashboard summary must convey what was sent across groups: slugs + per-group counts +
        # total + a one-line title — not just the last group's HTML.
        groups = [{"name": "Front", "repos": ["o/a"], "recipients": ["front@acme.com"]},
                  {"name": "Back", "repos": ["o/b"], "recipients": ["back@acme.com"]}]
        cand = [self._dep("o/a", "pkgA"), self._dep("o/b", "pkgB")]
        stored, sent = self._run(monkeypatch, {
            "security_skip_run": "0", "security_candidates": cand, "security_findings": {},
            "github_selected_resources": [{"id": "o/a"}, {"id": "o/b"}],
            "security_groups": groups})
        disp = stored["display_output"]
        assert "Security" in disp.get("title", "")
        assert {g["group"] for g in disp["groups"]} == {"front", "back"}
        assert all("issues" in g for g in disp["groups"])
        assert disp["sent"] == 2

    def test_preview_run_prepares_but_does_not_count_as_sent(self, monkeypatch):
        # A preview/test run builds the emails but sends nothing; the stored results must not claim
        # delivery. A `preview` flag (top-level + per group) makes the distinction unambiguous.
        import runpy, waveassist
        stored, sent = {}, []
        fetch_map = {
            "security_skip_run": "0", "security_candidates": [self._dep("o/a", "pkgA")],
            "security_findings": {}, "github_selected_resources": [{"id": "o/a"}]}
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        monkeypatch.setattr(waveassist, "send_email", lambda **k: sent.append(k) or True)
        monkeypatch.setattr(waveassist, "is_test_run", lambda: True)        # preview run
        runpy.run_path("triage_and_alert.py", run_name="__main__")
        assert sent == []                                                  # nothing actually sent
        disp = stored["display_output"]
        assert disp.get("preview") is True
        assert disp.get("sent") == 0                                       # not counted as sent
        assert all(g.get("previewed") is True and g.get("sent") is False for g in disp["groups"])
