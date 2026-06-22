"""
Unit tests for generate_business_report.py — Digest chain node 4 (per group).

Adapted from GitDigest: same BusinessReport shape and rolling 1-week history, but fanned out per
resolved group (each group is its own "project") and grounded in the brain instead of the dropped
repository_contexts.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from generate_business_report import (
    filter_analyses,
    count_changes,
    build_changes_context,
    build_history_context,
    roll_history,
    brain_block,
)


ANALYSES = [
    {"repository": "o/a", "changes": [{"summary": "Add login", "category": "feature",
                                       "contributing_commits": ["s1"]}]},
    {"repository": "o/b", "changes": []},
    {"repository": "o/c", "changes": [{"summary": "Cache", "category": "improvement",
                                       "contributing_commits": ["s2"]}]},
]


class TestFilterAnalyses:
    def test_keeps_only_group_repos(self):
        out = filter_analyses(ANALYSES, ["o/a", "o/b"])
        assert {a["repository"] for a in out} == {"o/a", "o/b"}

    def test_empty_group(self):
        assert filter_analyses(ANALYSES, []) == []


class TestCountChanges:
    def test_sums_changes(self):
        assert count_changes(ANALYSES) == 2

    def test_zero(self):
        assert count_changes([{"repository": "o/b", "changes": []}]) == 0


class TestBuildChangesContext:
    def test_only_repos_with_changes(self):
        ctx = build_changes_context(ANALYSES)
        assert "o/a" in ctx and "o/c" in ctx
        assert "o/b" not in ctx          # no changes → excluded

    def test_empty_when_no_changes(self):
        assert build_changes_context([{"repository": "o/b", "changes": []}]) == ""


class TestBuildHistoryContext:
    def test_empty(self):
        assert build_history_context([]) == ""

    def test_includes_prior_week(self):
        hist = [{"week": "2024-01-08", "report": {"executive_summary": "Shipped auth"}}]
        ctx = build_history_context(hist)
        assert "2024-01-08" in ctx and "Shipped auth" in ctx


class TestRollHistory:
    def test_keeps_last_one_then_appends(self):
        hist = [{"week": "2024-01-01", "report": {}}, {"week": "2024-01-08", "report": {}}]
        out = roll_history(hist, "2024-01-15", {"executive_summary": "new"})
        assert [h["week"] for h in out] == ["2024-01-08", "2024-01-15"]   # max 2, oldest dropped

    def test_from_empty(self):
        out = roll_history([], "2024-01-15", {"executive_summary": "first"})
        assert len(out) == 1 and out[0]["week"] == "2024-01-15"


class TestBrainBlock:
    def test_empty(self):
        assert brain_block({}) == ""

    def test_includes_arch(self):
        block = brain_block({"o/a": {"architecture_summary": "FastAPI service"}})
        assert "FastAPI service" in block


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
        runpy.run_path("generate_business_report.py", run_name="__main__")
        return stored

    def test_skip_run_no_work(self, monkeypatch):
        import waveassist
        stored = self._run(monkeypatch, {"digest_skip_run": "1"},
                           llm=lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM on skip")))
        assert "digest_business_reports" not in stored

    def test_per_group_report_keyed_by_slug(self, monkeypatch):
        class FakeReport:
            def model_dump(self, by_alias=False):
                return {"executive_summary": "Big week", "shipped_features": ["X"]}
        groups = [{"name": "Front", "repos": ["o/a"], "recipients": [], "slug": "front"}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0",
            "digest_resolved_groups": groups,
            "repository_analyses": ANALYSES,
            "digest_state": {},
        }, llm=lambda *a, **k: FakeReport())
        reports = stored.get("digest_business_reports")
        assert "front" in reports
        assert reports["front"]["executive_summary"] == "Big week"

    def test_group_with_no_activity_gets_fallback_no_llm(self, monkeypatch):
        groups = [{"name": "Idle", "repos": ["o/b"], "recipients": [], "slug": "idle"}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0",
            "digest_resolved_groups": groups,
            "repository_analyses": ANALYSES,
            "digest_state": {},
        }, llm=lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM for an idle group")))
        reports = stored.get("digest_business_reports")
        assert reports["idle"]["shipped_features"] == []

    def test_quiet_week_not_flagged_failed(self, monkeypatch):
        """A deterministic quiet week (no changes, no LLM) is NOT a generation failure — it still ships."""
        groups = [{"name": "Idle", "repos": ["o/b"], "recipients": [], "slug": "idle"}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0",
            "digest_resolved_groups": groups,
            "repository_analyses": ANALYSES,
            "digest_state": {},
        }, llm=lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM for an idle group")))
        reports = stored.get("digest_business_reports")
        assert not reports["idle"].get("generation_failed")

    def test_llm_success_not_flagged(self, monkeypatch):
        """A successful LLM generation is never flagged as failed."""
        class FakeReport:
            def model_dump(self, by_alias=False):
                return {"executive_summary": "Big week", "shipped_features": ["X"]}
        groups = [{"name": "Front", "repos": ["o/a"], "recipients": [], "slug": "front"}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0",
            "digest_resolved_groups": groups,
            "repository_analyses": ANALYSES,
            "digest_state": {},
        }, llm=lambda *a, **k: FakeReport())
        reports = stored.get("digest_business_reports")
        assert not reports["front"].get("generation_failed")

    def test_llm_failure_flags_generation_failed(self, monkeypatch):
        """When call_llm RAISES, the group is flagged generation_failed and history is NOT advanced."""
        groups = [{"name": "Front", "repos": ["o/a"], "recipients": [], "slug": "front"}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0",
            "digest_resolved_groups": groups,
            "repository_analyses": ANALYSES,
            "digest_state": {},
        }, llm=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        reports = stored.get("digest_business_reports")
        assert reports["front"]["generation_failed"] is True
        assert reports["front"]["shipped_features"] == []        # empty_report shape preserved
        # history not advanced on failure
        assert "business_report_history" not in (stored.get("digest_state", {}).get("front", {}) or {})

    def test_upstream_analysis_failure_flags_skip_no_llm(self, monkeypatch):
        """A repo whose analysis FAILED upstream (analysis_failed) with no changes must NOT be rendered
        as a quiet week: flag generation_failed so send_digest skips it. No LLM is called."""
        groups = [{"name": "Front", "repos": ["o/x"], "recipients": [], "slug": "front"}]
        analyses = [{"repository": "o/x", "changes": [], "commit_count": 7, "analysis_failed": True}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0", "digest_resolved_groups": groups,
            "repository_analyses": analyses, "digest_state": {},
        }, llm=lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM on failed analysis")))
        assert stored["digest_business_reports"]["front"]["generation_failed"] is True

    def test_commits_but_no_changes_is_honest_maintenance_not_quiet(self, monkeypatch):
        """Commits landed but nothing user-facing: honest 'maintenance' wording (matches the commit
        counter), NOT 'No development activity', and NOT flagged failed. No LLM."""
        groups = [{"name": "Front", "repos": ["o/x"], "recipients": [], "slug": "front"}]
        analyses = [{"repository": "o/x", "changes": [], "commit_count": 7, "analysis_failed": False}]
        stored = self._run(monkeypatch, {
            "digest_skip_run": "0", "digest_resolved_groups": groups,
            "repository_analyses": analyses, "digest_state": {},
        }, llm=lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM for maintenance week")))
        rep = stored["digest_business_reports"]["front"]
        assert "7 commits" in rep["executive_summary"]
        assert "No development activity" not in rep["executive_summary"]
        assert not rep.get("generation_failed")
        assert rep["shipped_features"] == []


class TestEmptyWeekHelpers:
    def test_maintenance_report_wording_plural_and_singular(self):
        from generate_business_report import maintenance_report
        assert "7 commits" in maintenance_report("Acme", 7)["executive_summary"]
        assert "1 commit " in maintenance_report("Acme", 1)["executive_summary"]
        assert maintenance_report("Acme", 7)["shipped_features"] == []

    def test_group_commit_count_and_failed(self):
        from generate_business_report import group_commit_count, group_analysis_failed
        a = [{"commit_count": 3}, {"commit_count": 4, "analysis_failed": True}]
        assert group_commit_count(a) == 7
        assert group_analysis_failed(a) is True
        assert group_analysis_failed([{"commit_count": 2}]) is False
        assert group_commit_count([]) == 0
