"""
Unit tests for send_digest.py — the Digest chain's delivery node (node 6, per group).

Adapted from GitDigest's send_emails: combined HTML email + WeasyPrint PDF, but per group (owner
primary, group recipients CC'd) and with the security roll-up rendered in. It also releases the
digest_run_lock, token-matched, like triage_and_alert. WeasyPrint is imported lazily so the module
loads (and these tests run) without it installed; PDF generation soft-fails to no attachment.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from send_digest import (
    compute_stats,
    clean_recipients,
    render_security_rollup_html,
    build_subject,
    build_email_html,
    group_generation_failed,
)

ROLLUP = {"new": [{"title": "SQLi", "repo": "o/a", "severity": "critical", "actively_exploited": False}],
          "still_open": [], "resolved": [{"title": "patched dep", "repo": "o/a", "severity": "high",
                                          "actively_exploited": False}],
          "counts": {"new": 1, "still_open": 0, "resolved": 1}}


class TestComputeStats:
    ACTIVITY = {
        "o/a": {"commits": [{"author": "alice"}, {"author": "bob"}], "pull_requests": []},
        "o/b": {"commits": [], "pull_requests": []},
        "o/other": {"commits": [{"author": "zed"}], "pull_requests": []},
    }

    def test_scoped_to_group(self):
        s = compute_stats(self.ACTIVITY, ["o/a", "o/b"])
        assert s["commits"] == 2
        assert s["contributors"] == 2          # alice, bob (zed excluded, o/other not in group)
        assert s["total_repos"] == 2
        assert s["active_repos"] == 1          # only o/a had commits


class TestCleanRecipients:
    def test_keeps_valid_emails(self):
        assert clean_recipients(["a@x.com", "bad", "  b@y.io "]) == ["a@x.com", "b@y.io"]

    def test_empty(self):
        assert clean_recipients([]) == []
        assert clean_recipients(None) == []


class TestRenderSecurityRollup:
    def test_lists_new_and_resolved(self):
        h = render_security_rollup_html(ROLLUP)
        assert "SQLi" in h
        assert "patched dep" in h

    def test_clean_week_message_when_scanned(self):
        # scanned + zero findings = a genuine all-clear -> the reassurance line ships.
        h = render_security_rollup_html({"new": [], "still_open": [], "resolved": [], "scanned": True,
                                         "counts": {"new": 0, "still_open": 0, "resolved": 0}})
        assert "no security issues found" in h.lower()   # reassurance, not blank
        assert "<h2>Security</h2>" in h

    def test_hidden_when_not_scanned_yet(self):
        # zero findings but NOT yet scanned (e.g. first run before Security Watch has run) = 'not
        # scanned', not an all-clear -> hide the section rather than post a false 'nothing found'.
        h = render_security_rollup_html({"new": [], "still_open": [], "resolved": [],
                                         "counts": {"new": 0, "still_open": 0, "resolved": 0}})
        assert h == ""

    def test_findings_always_render_regardless_of_scanned_flag(self):
        # A non-empty roll-up was obviously scanned; render it even if the flag is missing.
        assert "SQLi" in render_security_rollup_html(ROLLUP)


class TestGroupGenerationFailed:
    def test_business_failure_detected(self):
        assert group_generation_failed({"generation_failed": True}, {}) is True

    def test_technical_failure_detected(self):
        assert group_generation_failed({}, {"generation_failed": True}) is True

    def test_clean_reports_not_failed(self):
        assert group_generation_failed({"executive_summary": "x"}, {"poem": []}) is False

    def test_quiet_week_empty_but_not_failed(self):
        assert group_generation_failed({"shipped_features": []},
                                       {"repository_deep_dive": [], "poem": ["..."]}) is False


class TestBuildSubject:
    def test_includes_group(self):
        assert "Acme" in build_subject("Acme")

    def test_subject_is_branded(self):
        s = build_subject("Acme", "Jun 15")
        assert s == "GitZoid Acme Digest: Week of Jun 15"   # name inside the brand phrase

    def test_named_group_inside_brand_phrase(self):
        assert build_subject("Sacred Walks", "Jun 15") == "GitZoid Sacred Walks Digest: Week of Jun 15"

    def test_implicit_group_subject_has_no_all_repositories(self):
        s = build_subject("All repositories", "Jun 15", implicit=True)
        assert "All repositories" not in s
        assert s == "GitZoid Digest: Week of Jun 15"

    def test_unnamed_group_is_branded(self):
        s = build_subject("", "Jun 15")
        assert s == "GitZoid Digest: Week of Jun 15"

    def test_all_repositories_suppressed_even_without_flag(self):
        s = build_subject("All repositories", "Jun 15")
        assert "All repositories" not in s


class TestBuildEmailHtml:
    def test_contains_all_sections(self):
        business = {"executive_summary": "Shipped SSO", "shipped_features": ["SSO login"]}
        technical = {"repository_deep_dive": [{"repo_name": "o/a", "status": "Feature Dev",
                                               "technical_changes": ["Added SSO"]}],
                     "poem": ["one", "two", "three", "four"], "security_rollup": ROLLUP}
        stats = {"commits": 5, "contributors": 2, "total_repos": 1, "active_repos": 1}
        html = build_email_html("Acme", business, technical, stats, {})
        assert "Shipped SSO" in html
        assert "SSO login" in html
        assert "o/a" in html
        assert "Added SSO" in html
        assert "SQLi" in html                  # security roll-up rendered
        assert "one" in html                   # poem

    def test_h1_matches_subject_brand_title(self):
        html = build_email_html(
            "Sacred Walks",
            {"executive_summary": "s", "shipped_features": []},
            {"repository_deep_dive": [], "poem": [],
             "security_rollup": {"counts": {"new": 0, "still_open": 0, "resolved": 0}}},
            {"commits": 1, "contributors": 1, "total_repos": 1, "active_repos": 1},
            {})
        assert "<h1>GitZoid Sacred Walks Digest</h1>" in html   # H1 == the subject's brand title
        assert "Knowledge Digest" not in html                    # no second, different title

    def test_implicit_group_h1_is_plain_brand(self):
        html = build_email_html(
            "All repositories",
            {"executive_summary": "s", "shipped_features": []},
            {"repository_deep_dive": [], "poem": [],
             "security_rollup": {"counts": {"new": 0, "still_open": 0, "resolved": 0}}},
            {"commits": 1, "contributors": 1, "total_repos": 1, "active_repos": 1},
            {}, implicit=True)
        assert "<h1>GitZoid Digest</h1>" in html
        assert "All repositories" not in html

    def test_stats_render_as_table_one_row(self):
        """Regression: the 4 stats wrapped (3+1) under WeasyPrint flex; a 4-column table keeps them on
        one row in the PDF and in email clients (both render flexbox unreliably)."""
        stats = {"commits": 46, "contributors": 6, "total_repos": 2, "active_repos": 2}
        html = build_email_html("Acme", {"executive_summary": "s", "shipped_features": []},
                                {"repository_deep_dive": [], "poem": [],
                                 "security_rollup": {"counts": {"new": 0, "still_open": 0, "resolved": 0}}},
                                stats, {})
        style = html.split("</style>")[0]
        assert '<table class="stats-bar"' in html      # a table, not a flex <div>
        assert "display: flex" not in style            # flexbox removed from the stats styling
        for label in ("Commits", "Contributors", "Total Repos", "Active Repos"):
            assert label in html


class TestDriver:
    def _run(self, monkeypatch, fetch_map):
        import runpy, waveassist
        stored, emails = {}, []
        monkeypatch.setattr(waveassist, "init", lambda *a, **k: None)
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        monkeypatch.setattr(waveassist, "send_email",
                            lambda **k: (emails.append(k) or True))
        runpy.run_path("send_digest.py", run_name="__main__")
        return stored, emails

    def test_skip_sends_nothing_but_releases_owned_lock(self, monkeypatch):
        fetch_map = {
            "digest_skip_run": "1",
            "digest_run_lock_token": "TKN",
            "digest_run_lock": {"at": "now", "token": "TKN"},
        }
        stored, emails = self._run(monkeypatch, fetch_map)
        assert emails == []                              # no email on skip
        assert stored.get("digest_run_lock") == {}       # but the owned lock is freed
        assert stored.get("run_idle") == "1"             # skipped cycle → idle

    def test_no_groups_sent_marks_idle(self, monkeypatch):
        # digest enabled this cycle but no groups resolved -> 0 sent -> idle
        stored, emails = self._run(monkeypatch, {
            "digest_skip_run": "0", "digest_run_lock_token": "TKN",
            "digest_run_lock": {"at": "now", "token": "TKN"},
            "digest_resolved_groups": [], "digest_state": {}})
        assert emails == []
        assert stored.get("run_idle") == "1"

    def test_sent_digest_not_marked_idle(self, monkeypatch):
        groups = [{"name": "Front", "repos": ["o/a"], "recipients": [], "slug": "front"}]
        stored, emails = self._run(monkeypatch, {
            "digest_skip_run": "0", "digest_run_lock_token": "TKN",
            "digest_run_lock": {"at": "now", "token": "TKN"},
            "digest_resolved_groups": groups,
            "digest_business_reports": {"front": {"executive_summary": "s", "shipped_features": []}},
            "digest_technical_reports": {"front": {"repository_deep_dive": [], "poem": ["a"], "security_rollup": ROLLUP}},
            "github_activity_data": {"o/a": {"commits": [{"author": "x"}]}},
            "report_date_range": {}, "digest_state": {}})
        assert len(emails) == 1
        assert "run_idle" not in stored                  # a digest went out → acted

    def test_skip_does_not_free_someone_elses_lock(self, monkeypatch):
        fetch_map = {
            "digest_skip_run": "1",
            "digest_run_lock_token": "",                 # this run never took the lock
            "digest_run_lock": {"at": "now", "token": "OTHER"},
        }
        stored, emails = self._run(monkeypatch, fetch_map)
        assert "digest_run_lock" not in stored           # holder's lock untouched

    def test_one_email_per_group_with_cc_and_lock_release(self, monkeypatch):
        groups = [
            {"name": "Front", "repos": ["o/a"], "recipients": ["lead@acme.com"], "slug": "front"},
            {"name": "Mobile", "repos": ["o/b"], "recipients": [], "slug": "mobile"},
        ]
        fetch_map = {
            "digest_skip_run": "0",
            "digest_run_lock_token": "TKN",
            "digest_run_lock": {"at": "now", "token": "TKN"},
            "digest_resolved_groups": groups,
            "digest_business_reports": {"front": {"executive_summary": "s", "shipped_features": []},
                                        "mobile": {"executive_summary": "s2", "shipped_features": []}},
            "digest_technical_reports": {"front": {"repository_deep_dive": [], "poem": ["a"], "security_rollup": ROLLUP},
                                         "mobile": {"repository_deep_dive": [], "poem": ["b"], "security_rollup": ROLLUP}},
            "github_activity_data": {"o/a": {"commits": [{"author": "x"}]}, "o/b": {"commits": []}},
            "report_date_range": {},
            "digest_state": {},
        }
        stored, emails = self._run(monkeypatch, fetch_map)
        assert len(emails) == 2
        front = next(e for e in emails if "Front" in e["subject"])
        assert front["cc"] == ["lead@acme.com"]
        mobile = next(e for e in emails if "Mobile" in e["subject"])
        assert mobile["cc"] is None                      # no recipients → owner-only
        assert stored.get("digest_run_lock") == {}        # lock released
        assert "front" in stored.get("digest_state", {})  # last_sent_at recorded

    def test_display_output_shows_every_group_not_just_last(self, monkeypatch):
        # Regression: the run-output preview must render ALL groups, not only the last one processed.
        groups = [
            {"name": "Front", "repos": ["o/a"], "recipients": ["lead@acme.com"], "slug": "front"},
            {"name": "Mobile", "repos": ["o/b"], "recipients": [], "slug": "mobile"},
        ]
        fetch_map = {
            "digest_skip_run": "0",
            "digest_run_lock_token": "TKN",
            "digest_run_lock": {"at": "now", "token": "TKN"},
            "digest_resolved_groups": groups,
            "digest_business_reports": {"front": {"executive_summary": "ALPHASUMMARY", "shipped_features": []},
                                        "mobile": {"executive_summary": "BETASUMMARY", "shipped_features": []}},
            "digest_technical_reports": {"front": {"repository_deep_dive": [], "poem": ["a"], "security_rollup": ROLLUP},
                                         "mobile": {"repository_deep_dive": [], "poem": ["b"], "security_rollup": ROLLUP}},
            "github_activity_data": {"o/a": {"commits": [{"author": "x"}]}, "o/b": {"commits": []}},
            "report_date_range": {},
            "digest_state": {},
        }
        stored, emails = self._run(monkeypatch, fetch_map)
        out = stored.get("display_output", {})
        body = out.get("html_content", "")
        assert "ALPHASUMMARY" in body and "BETASUMMARY" in body   # BOTH groups' bodies present
        assert "Front" in body and "Mobile" in body               # both labelled
        assert out["title"] == "GitZoid Digest: 2 email(s) sent"

    def test_failed_group_not_sent(self, monkeypatch):
        """A group whose LLM raised (generation_failed) is skipped: no email, state untouched. A clean
        sibling group still sends, and the lock is still released."""
        groups = [
            {"name": "Front", "repos": ["o/a"], "recipients": ["lead@acme.com"], "slug": "front"},
            {"name": "Mobile", "repos": ["o/b"], "recipients": [], "slug": "mobile"},
        ]
        fetch_map = {
            "digest_skip_run": "0",
            "digest_run_lock_token": "TKN",
            "digest_run_lock": {"at": "now", "token": "TKN"},
            "digest_resolved_groups": groups,
            "digest_business_reports": {
                "front": {"executive_summary": "s", "shipped_features": [], "generation_failed": True},
                "mobile": {"executive_summary": "s2", "shipped_features": []}},
            "digest_technical_reports": {
                "front": {"repository_deep_dive": [], "poem": [], "security_rollup": ROLLUP},
                "mobile": {"repository_deep_dive": [], "poem": ["b"], "security_rollup": ROLLUP}},
            "github_activity_data": {"o/a": {"commits": [{"author": "x"}]}, "o/b": {"commits": []}},
            "report_date_range": {},
            "digest_state": {},
        }
        stored, emails = self._run(monkeypatch, fetch_map)
        assert len(emails) == 1
        assert "Mobile" in emails[0]["subject"]
        assert all("Front" not in e["subject"] for e in emails)
        # front's state is never written this run (skipped before digest_state[slug] = state)
        assert "last_sent_at" not in stored.get("digest_state", {}).get("front", {})
        assert stored.get("digest_run_lock") == {}             # lock still released

    def test_quiet_week_still_sent(self, monkeypatch):
        """A genuinely quiet week (empty deterministic reports, NO generation_failed) STILL ships the
        reassurance email with the security roll-up."""
        groups = [{"name": "Solo", "repos": ["o/a"], "recipients": [], "slug": "solo"}]
        fetch_map = {
            "digest_skip_run": "0",
            "digest_run_lock_token": "TKN",
            "digest_run_lock": {"at": "now", "token": "TKN"},
            "digest_resolved_groups": groups,
            "digest_business_reports": {
                "solo": {"executive_summary": "No development activity...", "shipped_features": []}},
            "digest_technical_reports": {
                "solo": {"repository_deep_dive": [], "poem": ["q1", "q2", "q3", "q4"],
                         "security_rollup": ROLLUP}},
            "github_activity_data": {"o/a": {"commits": []}},
            "report_date_range": {},
            "digest_state": {},
        }
        stored, emails = self._run(monkeypatch, fetch_map)
        assert len(emails) == 1
        assert "SQLi" in emails[0]["html_content"]             # security roll-up present

    def test_all_groups_failed_sends_nothing(self, monkeypatch):
        """Every group failed → no email at all, but the lock is still released."""
        groups = [{"name": "Solo", "repos": ["o/a"], "recipients": [], "slug": "solo"}]
        fetch_map = {
            "digest_skip_run": "0",
            "digest_run_lock_token": "TKN",
            "digest_run_lock": {"at": "now", "token": "TKN"},
            "digest_resolved_groups": groups,
            "digest_business_reports": {
                "solo": {"executive_summary": "s", "shipped_features": [], "generation_failed": True}},
            "digest_technical_reports": {
                "solo": {"repository_deep_dive": [], "poem": [], "security_rollup": ROLLUP}},
            "github_activity_data": {"o/a": {"commits": []}},
            "report_date_range": {},
            "digest_state": {},
        }
        stored, emails = self._run(monkeypatch, fetch_map)
        assert emails == []
        assert stored.get("digest_run_lock") == {}


class TestSecurityPoemDivider:
    """User feedback: on a clean week the SECURITY 'nothing found' line and the poem visually merge —
    they need a divider between them."""

    def test_divider_sits_between_security_and_poem(self):
        business = {"executive_summary": "a quiet week", "shipped_features": []}
        technical = {"repository_deep_dive": [], "poem": ["line one", "line two"],
                     "security_rollup": {"scanned": True,
                                         "counts": {"new": 0, "still_open": 0, "resolved": 0}}}
        html = build_email_html("All repositories", business, technical, {"commits": 0}, {})
        assert "<hr" in html
        sec = html.index("<h2>Security</h2>")
        poem = html.index("A small poem")
        hr = html.index("<hr", sec)
        assert sec < hr < poem            # divider between the security section and the poem

    def test_no_dangling_divider_without_poem(self):
        business = {"executive_summary": "s", "shipped_features": []}
        technical = {"repository_deep_dive": [], "poem": [],
                     "security_rollup": {"scanned": True,
                                         "counts": {"new": 0, "still_open": 0, "resolved": 0}}}
        html = build_email_html("All repositories", business, technical, {"commits": 0}, {})
        assert "A small poem" not in html
        assert "<hr" not in html           # no poem -> no divider

    def test_no_divider_when_security_section_hidden(self):
        # Not scanned yet -> security section hidden -> the poem divider must not dangle above the poem.
        business = {"executive_summary": "s", "shipped_features": []}
        technical = {"repository_deep_dive": [], "poem": ["line one", "line two"],
                     "security_rollup": {"counts": {"new": 0, "still_open": 0, "resolved": 0}}}
        html = build_email_html("All repositories", business, technical, {"commits": 0}, {})
        assert "<h2>Security</h2>" not in html   # section hidden
        assert "A small poem" in html            # poem still present
        assert "<hr" not in html                 # no security section -> no divider


class TestDigestStatus:
    """Fix B: an all-skipped run (every group's report generation failed) must NOT report success."""

    def test_all_skipped_is_not_success(self):
        from send_digest import digest_status
        assert digest_status(sent=0, attempted=0) != "success"

    def test_all_delivered_is_success(self):
        from send_digest import digest_status
        assert digest_status(sent=2, attempted=2) == "success"

    def test_partial_delivery_is_email_failed(self):
        from send_digest import digest_status
        assert digest_status(sent=1, attempted=2) == "email_failed"
