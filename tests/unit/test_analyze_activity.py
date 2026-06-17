"""
Unit tests for analyze_activity.py — the Digest chain's diff analyzer (node 3).

The three-tier token-splitting strategy from GitDigest is preserved verbatim; here it is pinned by
testing batch PLANNING (which commits go in which LLM call, with what budget) separately from LLM
execution, so the hard-won tiering logic is verified without mocking the model.
"""
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from analyze_activity import (
    is_non_code_file,
    estimate_tokens,
    group_commits_by_day,
    choose_tier,
    batch_small_days,
    build_commit_context,
    brain_context_section,
    TIER_1_THRESHOLD,
    TIER_2_THRESHOLD,
    BATCH_THRESHOLD,
)


class TestIsNonCodeFile:
    def test_image(self):
        assert is_non_code_file("logo.png") is True

    def test_lockfile(self):
        assert is_non_code_file("poetry.lock") is True

    def test_code(self):
        assert is_non_code_file("app.py") is False
        assert is_non_code_file("Dockerfile") is False


class TestEstimateTokens:
    def test_three_chars_per_token(self):
        assert estimate_tokens("abcdef") == 2
        assert estimate_tokens("") == 0


class TestChooseTier:
    def test_tier1_below_100k(self):
        assert choose_tier(TIER_1_THRESHOLD - 1) == 1

    def test_tier2_between(self):
        assert choose_tier(TIER_1_THRESHOLD) == 2
        assert choose_tier(TIER_2_THRESHOLD - 1) == 2

    def test_tier3_above_700k(self):
        assert choose_tier(TIER_2_THRESHOLD) == 3


class TestGroupCommitsByDay:
    def test_groups_by_calendar_day(self):
        commits = [
            {"sha": "a", "timestamp": "2024-01-15T10:00:00Z"},
            {"sha": "b", "timestamp": "2024-01-15T22:00:00Z"},
            {"sha": "c", "timestamp": "2024-01-16T01:00:00Z"},
        ]
        by_day = group_commits_by_day(commits)
        assert set(by_day.keys()) == {"2024-01-15", "2024-01-16"}
        assert [c["sha"] for c in by_day["2024-01-15"]] == ["a", "b"]

    def test_missing_timestamp_bucketed_unknown(self):
        by_day = group_commits_by_day([{"sha": "x", "timestamp": ""}])
        assert "unknown" in by_day


class TestBatchSmallDays:
    def test_combines_until_threshold(self):
        # three days, each 40k tokens; threshold 90k → days 1+2 batch, day 3 alone
        day_data = [
            ("2024-01-01", [{"sha": "a"}], 40000),
            ("2024-01-02", [{"sha": "b"}], 40000),
            ("2024-01-03", [{"sha": "c"}], 40000),
        ]
        batches = batch_small_days(day_data, batch_threshold=90000)
        assert len(batches) == 2
        assert [c["sha"] for c in batches[0]["commits"]] == ["a", "b"]
        assert [c["sha"] for c in batches[1]["commits"]] == ["c"]
        assert all(b["token_budget"] is None for b in batches)

    def test_empty(self):
        assert batch_small_days([]) == []


class TestBuildCommitContext:
    def _commit(self, sha="abc1234"):
        return {"sha": sha, "message": "Add caching", "author": "alice",
                "timestamp": "2024-01-15T10:00:00Z"}

    def test_includes_commit_and_diff(self):
        diffs = {"abc1234": [{"filename": "cache.py", "status": "added", "patch": "+ cache code"}]}
        ctx = build_commit_context([self._commit()], diffs)
        assert "abc1234" in ctx
        assert "Add caching" in ctx
        assert "cache.py" in ctx
        assert "+ cache code" in ctx

    def test_token_budget_truncates_large_file(self):
        big_patch = "x" * 60000   # ~20k tokens
        diffs = {"abc1234": [{"filename": "big.py", "status": "modified", "patch": big_patch}]}
        ctx = build_commit_context([self._commit()], diffs, token_budget=100)
        assert "TRUNCATED" in ctx


class TestBrainContextSection:
    def test_empty_profile_no_section(self):
        assert brain_context_section({}) == ""
        assert brain_context_section(None) == ""

    def test_architecture_included(self):
        section = brain_context_section({"architecture_summary": "A FastAPI service"})
        assert "FastAPI service" in section

    def test_conventions_included(self):
        section = brain_context_section({"conventions": ["use type hints", "pytest"]})
        assert "type hints" in section


class TestDriverSkip:
    def test_skip_run_does_no_work(self, monkeypatch):
        import runpy, waveassist
        monkeypatch.setattr(waveassist, "init", lambda *a, **k: None)
        fetch_map = {"digest_skip_run": "1"}
        stored = {}
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        monkeypatch.setattr(waveassist, "call_llm",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM on skip")))
        runpy.run_path("analyze_activity.py", run_name="__main__")
        assert "repository_analyses" not in stored
