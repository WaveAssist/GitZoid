"""
Unit tests for generate_technical_report.py — Digest chain node 5 (per group).

Adapted from GitDigest's technical report (repository_deep_dive + poem), fanned out per group, plus a
NEW deterministic security roll-up computed from the security_findings ledger — the weekly
"we watched, here's the state" reassurance that makes Security Watch's silence trustworthy.
"""
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from generate_technical_report import (
    filter_analyses,
    count_changes,
    build_business_report_context,
    security_rollup,
    QUIET_POEM,
)

NOW = datetime(2024, 1, 15, tzinfo=timezone.utc)

LEDGER = {
    "s1": {"repo": "o/a", "status": "open", "severity": "critical", "title": "SQL injection",
           "actively_exploited": False, "first_seen": "2024-01-14T00:00:00+00:00"},     # new (<7d)
    "s2": {"repo": "o/a", "status": "open", "severity": "medium", "title": "carried over",
           "actively_exploited": False, "first_seen": "2024-01-01T00:00:00+00:00"},     # still open (>7d)
    "s3": {"repo": "o/a", "status": "resolved", "severity": "high", "title": "patched dep",
           "resolved_at": "2024-01-13T00:00:00+00:00"},                                 # resolved (<7d)
    "s4": {"repo": "o/other", "status": "open", "severity": "high", "title": "other group",
           "first_seen": "2024-01-14T00:00:00+00:00"},                                  # not in group
    "s5": {"repo": "o/a", "status": "resolved", "severity": "low", "title": "old resolution",
           "resolved_at": "2023-12-01T00:00:00+00:00"},                                 # resolved long ago
}


def recent_ledger():
    """A ledger keyed to the real 'now' the driver uses (datetime.now), so the 7-day window applies."""
    now = datetime.now(timezone.utc)
    iso = lambda days: (now - timedelta(days=days)).isoformat()
    return {
        "s1": {"repo": "o/a", "status": "open", "severity": "critical", "title": "SQL injection",
               "actively_exploited": False, "first_seen": iso(1)},          # new
        "s2": {"repo": "o/a", "status": "open", "severity": "medium", "title": "carried over",
               "actively_exploited": False, "first_seen": iso(30)},         # still open
        "s3": {"repo": "o/a", "status": "resolved", "severity": "high", "title": "patched dep",
               "resolved_at": iso(2)},                                      # resolved this week
    }


class TestSecurityRollup:
    def test_partitions_new_open_resolved_for_group_only(self):
        out = security_rollup(LEDGER, ["o/a"], NOW)
        assert [i["title"] for i in out["new"]] == ["SQL injection"]
        assert [i["title"] for i in out["still_open"]] == ["carried over"]
        assert [i["title"] for i in out["resolved"]] == ["patched dep"]
        assert out["counts"] == {"new": 1, "still_open": 1, "resolved": 1}

    def test_other_group_repo_excluded(self):
        out = security_rollup(LEDGER, ["o/a"], NOW)
        titles = {i["title"] for part in ("new", "still_open", "resolved") for i in out[part]}
        assert "other group" not in titles

    def test_clean_week_all_zero(self):
        out = security_rollup({}, ["o/a"], NOW)
        assert out["counts"] == {"new": 0, "still_open": 0, "resolved": 0}

    def test_actively_exploited_sorts_first(self):
        ledger = {
            "a": {"repo": "o/a", "status": "open", "severity": "low", "title": "kev low",
                  "actively_exploited": True, "first_seen": "2024-01-14T00:00:00+00:00"},
            "b": {"repo": "o/a", "status": "open", "severity": "critical", "title": "crit",
                  "actively_exploited": False, "first_seen": "2024-01-14T00:00:00+00:00"},
        }
        out = security_rollup(ledger, ["o/a"], NOW)
        assert out["new"][0]["title"] == "kev low"   # KEV outranks even a critical


class TestFilterAndCount:
    ANALYSES = [{"repository": "o/a", "changes": [{"summary": "x", "category": "fix",
                                                   "contributing_commits": []}]},
                {"repository": "o/b", "changes": []}]

    def test_filter(self):
        assert {a["repository"] for a in filter_analyses(self.ANALYSES, ["o/a"])} == {"o/a"}

    def test_count(self):
        assert count_changes(self.ANALYSES) == 1


def test_fallback_poem_constant_removed():
    """The FALLBACK_POEM constant is removed; a generation failure must NOT render a poem at all."""
    import generate_technical_report as m
    assert not hasattr(m, "FALLBACK_POEM")


class TestBuildBusinessReportContext:
    def test_empty(self):
        assert build_business_report_context({}) == ""

    def test_includes_summary_and_features(self):
        ctx = build_business_report_context({"executive_summary": "Shipped auth",
                                             "shipped_features": ["SSO login"]})
        assert "Shipped auth" in ctx and "SSO login" in ctx


class TestDriver:
    def _run(self, monkeypatch, fetch_map, llm=None):
        import runpy, waveassist
        stored = {}
        monkeypatch.setattr(waveassist, "init", lambda *a, **k: None)
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        if llm is not None:
            monkeypatch.setattr(waveassist, "call_llm", llm)
        runpy.run_path("generate_technical_report.py", run_name="__main__")
        return stored

    def test_skip_run_no_work(self, monkeypatch):
        stored = self._run(monkeypatch, {"digest_skip_run": "1"},
                           llm=lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM on skip")))
        assert "digest_technical_reports" not in stored

    def test_quiet_group_still_gets_security_rollup_no_llm(self, monkeypatch):
        groups = [{"name": "Idle", "repos": ["o/a"], "recipients": [], "slug": "idle"}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0",
            "digest_resolved_groups": groups,
            "repository_analyses": [{"repository": "o/a", "changes": []}],
            "digest_business_reports": {},
            "security_findings": recent_ledger(),
        }, llm=lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM for a quiet group")))
        reports = stored.get("digest_technical_reports")
        assert reports["idle"]["repository_deep_dive"] == []
        assert "security_rollup" in reports["idle"]            # reassurance present even when quiet
        assert reports["idle"]["security_rollup"]["counts"]["new"] == 1

    def test_quiet_group_not_flagged_failed(self, monkeypatch):
        """A quiet week keeps the QUIET poem and is NOT flagged as a generation failure."""
        groups = [{"name": "Idle", "repos": ["o/a"], "recipients": [], "slug": "idle"}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0",
            "digest_resolved_groups": groups,
            "repository_analyses": [{"repository": "o/a", "changes": []}],
            "digest_business_reports": {},
            "security_findings": recent_ledger(),
        }, llm=lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM for a quiet group")))
        reports = stored.get("digest_technical_reports")
        assert not reports["idle"].get("generation_failed")
        assert reports["idle"]["poem"] == QUIET_POEM              # genuinely idle (0 commits) keeps the poem

    def test_maintenance_week_drops_quiet_poem(self, monkeypatch):
        """Commits landed but no user-facing changes: the 'quiet repos / untouched branches' poem would
        contradict the commit counter, so it is dropped. Deep dive empty, security roll-up still ships."""
        groups = [{"name": "Maint", "repos": ["o/a"], "recipients": [], "slug": "maint"}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0",
            "digest_resolved_groups": groups,
            "repository_analyses": [{"repository": "o/a", "changes": [], "commit_count": 7}],
            "digest_business_reports": {},
            "security_findings": recent_ledger(),
        }, llm=lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM for a maintenance group")))
        rep = stored["digest_technical_reports"]["maint"]
        assert rep["poem"] == []                                  # poem suppressed when commits exist
        assert rep["repository_deep_dive"] == []
        assert "security_rollup" in rep

    def test_no_fallback_poem_rendered(self, monkeypatch):
        """When call_llm RAISES on an active group, flag generation_failed, render NO poem (no fallback),
        empty deep-dive, but still attach the (correct) security roll-up."""
        groups = [{"name": "Front", "repos": ["o/a"], "recipients": [], "slug": "front"}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0",
            "digest_resolved_groups": groups,
            "repository_analyses": [{"repository": "o/a", "changes": [{"summary": "x", "category": "feature",
                                                                       "contributing_commits": []}]}],
            "digest_business_reports": {"front": {"executive_summary": "s", "shipped_features": []}},
            "security_findings": recent_ledger(),
        }, llm=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        report = stored["digest_technical_reports"]["front"]
        assert report["generation_failed"] is True
        assert report["poem"] == []                            # decisive: NO FALLBACK_POEM
        assert report["repository_deep_dive"] == []
        assert "security_rollup" in report
        assert report["security_rollup"]["counts"]["resolved"] == 1

    def test_active_group_runs_llm_and_attaches_rollup(self, monkeypatch):
        class FakeTech:
            def model_dump(self, by_alias=False):
                return {"repository_deep_dive": [{"repo_name": "o/a", "status": "Feature Dev",
                                                  "technical_changes": ["did x"]}],
                        "poem": ["a", "b", "c", "d"]}
        groups = [{"name": "Front", "repos": ["o/a"], "recipients": [], "slug": "front"}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0",
            "digest_resolved_groups": groups,
            "repository_analyses": [{"repository": "o/a", "changes": [{"summary": "x", "category": "feature",
                                                                       "contributing_commits": []}]}],
            "digest_business_reports": {"front": {"executive_summary": "s", "shipped_features": []}},
            "security_findings": recent_ledger(),
        }, llm=lambda *a, **k: FakeTech())
        report = stored.get("digest_technical_reports")["front"]
        assert report["repository_deep_dive"][0]["repo_name"] == "o/a"
        assert report["security_rollup"]["counts"]["resolved"] == 1


class TestRollupGroupsDependencies:
    """Fix A: the digest security roll-up must group a package's many advisories into ONE issue and
    label it with a version, matching the alert email — not count 13 CVEs as 13 'django' lines."""

    def test_dep_cves_grouped_into_one_issue(self):
        now = datetime.now(timezone.utc)
        iso = now.isoformat()
        ledger = {f"sig{i}": {"category": "dependency", "repo": "o/a", "name": "Django",
                              "version": "4.2", "vuln_id": f"GHSA-{i}",
                              "severity": "critical" if i == 0 else "high",
                              "status": "open", "first_seen": iso} for i in range(13)}
        out = security_rollup(ledger, ["o/a"], now)
        assert out["counts"]["new"] == 1                 # 13 CVEs -> ONE grouped issue
        item = out["new"][0]
        assert item["title"] == "Django 4.2"             # version-bearing title (was bare "django")
        assert item["count"] == 13
        assert item["severity"] == "critical"            # worst severity in the group

    def test_distinct_packages_stay_separate(self):
        now = datetime.now(timezone.utc); iso = now.isoformat()
        ledger = {
            "a": {"category": "dependency", "repo": "o/a", "name": "Django", "version": "4.2",
                  "vuln_id": "G1", "severity": "high", "status": "open", "first_seen": iso},
            "b": {"category": "dependency", "repo": "o/a", "name": "authlib", "version": "1.6",
                  "vuln_id": "G2", "severity": "high", "status": "open", "first_seen": iso},
        }
        out = security_rollup(ledger, ["o/a"], now)
        assert out["counts"]["new"] == 2
