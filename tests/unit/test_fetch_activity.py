"""
Unit tests for fetch_activity.py — the Digest chain's GitHub activity collector (node 2).

Adapted from GitDigest's fetch_github_activity: same 7-day window, GraphQL active-branch detection,
bot filter, and SHA dedupe. The pure parsing/filter helpers are pinned here; the HTTP pagination
loops are thin glue over them.
"""
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from fetch_activity import (
    is_bot_user,
    parse_commit,
    pr_in_window,
    parse_pr,
    filter_active_branches,
    build_date_range,
    repos_to_scan,
    dedupe_commits,
    DAYS_TO_FETCH,
)


class TestIsBotUser:
    def test_type_bot(self):
        assert is_bot_user({"type": "Bot"}) is True

    def test_bot_suffix_login(self):
        assert is_bot_user({"login": "some-app[bot]"}) is True

    def test_known_bot(self):
        assert is_bot_user({"login": "dependabot"}) is True
        assert is_bot_user({"login": "renovate"}) is True

    def test_human(self):
        assert is_bot_user({"login": "alice", "type": "User"}) is False

    def test_none(self):
        assert is_bot_user(None) is False
        assert is_bot_user({}) is False


class TestParseCommit:
    def _commit(self, sha="abc", login="alice", bot_type="User"):
        return {
            "sha": sha,
            "html_url": f"https://github.com/o/r/commit/{sha}",
            "author": {"login": login, "type": bot_type},
            "committer": {"login": login, "type": bot_type},
            "commit": {"message": "Fix bug", "author": {"name": login, "date": "2024-01-15T10:30:00Z"}},
        }

    def test_valid_commit(self):
        c = parse_commit(self._commit())
        assert c == {"sha": "abc", "message": "Fix bug", "author": "alice",
                     "timestamp": "2024-01-15T10:30:00Z",
                     "url": "https://github.com/o/r/commit/abc"}

    def test_bot_commit_dropped(self):
        assert parse_commit(self._commit(login="dependabot", bot_type="Bot")) is None

    def test_empty_sha_dropped(self):
        assert parse_commit(self._commit(sha="")) is None


class TestPrInWindow:
    def setup_method(self):
        self.now = datetime(2024, 1, 15, tzinfo=timezone.utc)
        self.since = self.now - timedelta(days=7)

    def _pr(self, created=None, merged=None, updated=None):
        return {"created_at": created or "", "merged_at": merged, "updated_at": updated or ""}

    def test_created_in_window(self):
        assert pr_in_window(self._pr(created="2024-01-14T00:00:00Z"), self.since) is True

    def test_merged_in_window_created_old(self):
        pr = self._pr(created="2023-12-01T00:00:00Z", merged="2024-01-13T00:00:00Z")
        assert pr_in_window(pr, self.since) is True

    def test_updated_in_window_only(self):
        pr = self._pr(created="2023-12-01T00:00:00Z", updated="2024-01-12T00:00:00Z")
        assert pr_in_window(pr, self.since) is True

    def test_all_old(self):
        pr = self._pr(created="2023-11-01T00:00:00Z", merged="2023-11-02T00:00:00Z",
                      updated="2023-11-03T00:00:00Z")
        assert pr_in_window(pr, self.since) is False


class TestParsePr:
    def test_shapes_fields(self):
        pr = {"number": 42, "title": "Add feature", "body": "desc",
              "user": {"login": "alice"}, "created_at": "2024-01-15T11:00:00Z",
              "merged_at": None, "updated_at": "2024-01-15T11:00:00Z",
              "html_url": "https://github.com/o/r/pull/42",
              "head": {"sha": "def"}, "base": {"ref": "main"}}
        out = parse_pr(pr, "open")
        assert out["number"] == 42
        assert out["status"] == "open"
        assert out["author"] == "alice"
        assert out["base_branch"] == "main"
        assert out["head_sha"] == "def"


class TestFilterActiveBranches:
    def setup_method(self):
        self.since = datetime(2024, 1, 8, tzinfo=timezone.utc)

    def test_recent_branch_included(self):
        branches = [{"name": "main", "committedDate": "2024-01-15T10:00:00Z"}]
        assert filter_active_branches(branches, self.since) == ["main"]

    def test_old_branch_excluded(self):
        branches = [{"name": "stale", "committedDate": "2023-12-01T10:00:00Z"}]
        assert filter_active_branches(branches, self.since) == []

    def test_malformed_date_excluded(self):
        branches = [{"name": "weird", "committedDate": "not-a-date"}]
        assert filter_active_branches(branches, self.since) == []


class TestDedupeCommits:
    def test_drops_repeated_shas_keeps_order(self):
        commits = [{"sha": "a"}, {"sha": "b"}, {"sha": "a"}, {"sha": "c"}]
        assert [c["sha"] for c in dedupe_commits(commits)] == ["a", "b", "c"]


class TestBuildDateRange:
    def test_formats(self):
        start = datetime(2024, 1, 8, tzinfo=timezone.utc)
        end = datetime(2024, 1, 15, tzinfo=timezone.utc)
        out = build_date_range(start, end)
        assert out["start_date"] == start.isoformat()
        assert out["end_date"] == end.isoformat()
        assert out["start_date_formatted"] == "January 08, 2024"
        assert out["end_date_formatted"] == "January 15, 2024"


class TestReposToScan:
    def test_union_unique_sorted(self):
        groups = [{"repos": ["o/b", "o/a"]}, {"repos": ["o/a", "o/c"]}]
        assert repos_to_scan(groups) == ["o/a", "o/b", "o/c"]

    def test_empty(self):
        assert repos_to_scan([]) == []


class TestDriverSkip:
    def test_skip_run_does_no_work(self, monkeypatch):
        import runpy, waveassist, requests
        monkeypatch.setattr(waveassist, "init", lambda *a, **k: None)
        fetch_map = {"digest_skip_run": "1"}
        stored = {}
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        # Any HTTP call would be a bug when skipping.
        monkeypatch.setattr(requests, "get",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no HTTP on skip")))
        monkeypatch.setattr(requests, "post",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no HTTP on skip")))
        runpy.run_path("fetch_activity.py", run_name="__main__")
        assert "github_activity_data" not in stored
