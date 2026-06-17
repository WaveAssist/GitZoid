"""
Unit tests for digest_check_and_init.py — the Knowledge Digest chain's weekly starting node.

Mirrors test_security_check_and_init.py. The digest gate differs from security in two ways that
these tests pin down: the toggle defaults OFF when unset (existing users get no surprise weekly
email), and the node resolves the per-group working set (with an implicit single-group fallback)
before any downstream node runs.
"""
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from digest_check_and_init import (
    lock_is_active,
    digest_enabled,
    parse_groups,
    slugify,
    resolve_groups,
    estimate_time_to_process,
    LOCK_TTL_SECONDS,
    DIGEST_SECONDS_PER_REPO,
    DIGEST_BASE_SECONDS,
)


class TestLockActive:
    def test_empty_lock_inactive(self):
        assert lock_is_active({}) is False
        assert lock_is_active(None) is False

    def test_fresh_lock_active(self):
        assert lock_is_active({"at": datetime.now(timezone.utc).isoformat(), "token": "t"}) is True

    def test_stale_lock_inactive(self):
        old = (datetime.now(timezone.utc) - timedelta(seconds=LOCK_TTL_SECONDS + 60)).isoformat()
        assert lock_is_active({"at": old, "token": "t"}) is False


class TestDigestEnabled:
    """OPPOSITE default to security: unset means OFF (existing users), explicit truthy means ON (new)."""

    def test_unset_is_off(self):
        # Existing users never stored this → must be OFF so they get no surprise weekly email.
        assert digest_enabled(None) is False
        assert digest_enabled("") is False

    def test_explicit_true_is_on(self):
        assert digest_enabled("true") is True
        assert digest_enabled(True) is True
        assert digest_enabled("on") is True
        assert digest_enabled("1") is True

    def test_explicit_false_is_off(self):
        assert digest_enabled("false") is False
        assert digest_enabled("off") is False
        assert digest_enabled(False) is False


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
        assert out[0]["repos"] == ["o/a"]          # o/x dropped (not selected)
        assert out[0]["recipients"] == ["a@x.com"]
        assert out[0]["slug"] == "front"

    def test_group_with_no_selected_repos_is_dropped(self):
        groups = [{"name": "Dead", "repos": ["o/gone"], "recipients": []}]
        out = resolve_groups(groups, self.REPOS)
        # no surviving explicit group → implicit fallback over all selected repos
        assert len(out) == 1
        # The bare "All repositories" label is suppressed; the implicit group is unnamed + flagged.
        assert out[0]["name"] == ""
        assert out[0]["implicit"] is True
        assert sorted(out[0]["repos"]) == ["o/a", "o/b", "o/c"]
        assert out[0]["recipients"] == []

    def test_implicit_fallback_marked_and_unnamed(self):
        out = resolve_groups([], self.REPOS)
        assert out[0]["implicit"] is True
        assert out[0]["name"] == ""
        assert out[0]["slug"] == "group-1"
        assert sorted(out[0]["repos"]) == ["o/a", "o/b", "o/c"]

    def test_explicit_group_not_implicit(self):
        out = resolve_groups([{"name": "Front", "repos": ["o/a"], "recipients": []}], self.REPOS)
        assert out[0]["implicit"] is False
        assert out[0]["slug"] == "front"

    def test_empty_groups_fall_back_to_one_implicit_group(self):
        out = resolve_groups([], self.REPOS)
        assert len(out) == 1
        assert sorted(out[0]["repos"]) == ["o/a", "o/b", "o/c"]

    def test_no_repos_at_all_yields_no_groups(self):
        assert resolve_groups([], []) == []

    def test_duplicate_names_get_unique_slugs(self):
        groups = [
            {"name": "Team", "repos": ["o/a"], "recipients": []},
            {"name": "Team", "repos": ["o/b"], "recipients": []},
        ]
        out = resolve_groups(groups, self.REPOS)
        slugs = [g["slug"] for g in out]
        assert slugs == ["team", "team-2"]

    def test_string_repo_list_supported(self):
        out = resolve_groups([], ["o/a", "o/b"])
        assert sorted(out[0]["repos"]) == ["o/a", "o/b"]


class TestEstimateTimeToProcess:
    def test_zero_repos_is_just_base(self):
        assert estimate_time_to_process(0) == DIGEST_BASE_SECONDS

    def test_scales_per_repo(self):
        assert estimate_time_to_process(4) == 4 * DIGEST_SECONDS_PER_REPO + DIGEST_BASE_SECONDS

    def test_bad_input_falls_back_to_base(self):
        assert estimate_time_to_process(-2) == DIGEST_BASE_SECONDS
        assert estimate_time_to_process(None) == DIGEST_BASE_SECONDS


class TestDriver:
    """Driver-level: off/empty cycles are clean no-ops; a proceeding run resolves groups, sets the
    timer, and takes the lock."""

    def _run(self, monkeypatch, fetch_map, credits=True):
        import runpy, waveassist
        stored = {}
        monkeypatch.setattr(waveassist, "init", lambda *a, **k: None)
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        monkeypatch.setattr(waveassist, "check_credits_and_notify", lambda *a, **k: credits)
        runpy.run_path("digest_check_and_init.py", run_name="__main__")
        return stored

    def test_disabled_skips_without_credit_check(self, monkeypatch):
        import waveassist
        monkeypatch.setattr(waveassist, "check_credits_and_notify",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no credit check when off")))
        # enable_digest unset → off
        stored = self._run(monkeypatch, {"github_selected_resources": [{"id": "o/a"}]})
        assert stored.get("digest_skip_run") == "1"
        assert "digest_run_lock" not in stored

    def test_no_repos_skips(self, monkeypatch):
        stored = self._run(monkeypatch, {"enable_digest": "true", "github_selected_resources": []})
        assert stored.get("digest_skip_run") == "1"

    def test_active_lock_skips_cycle(self, monkeypatch):
        fresh = {"at": datetime.now(timezone.utc).isoformat(), "token": "other"}
        stored = self._run(monkeypatch, {"enable_digest": "true",
                                         "github_selected_resources": [{"id": "o/a"}],
                                         "digest_run_lock": fresh})
        assert stored.get("digest_skip_run") == "1"
        assert "digest_run_lock_token" not in stored

    def test_proceeding_run_resolves_groups_sets_timer_and_lock(self, monkeypatch):
        repos = [{"id": "o/a"}, {"id": "o/b"}]
        stored = self._run(monkeypatch, {"enable_digest": "true",
                                         "github_selected_resources": repos})
        assert stored.get("digest_skip_run") == "0"
        groups = stored.get("digest_resolved_groups")
        assert isinstance(groups, list) and len(groups) == 1          # implicit single group
        assert sorted(groups[0]["repos"]) == ["o/a", "o/b"]
        assert stored.get("tentative_time_to_process") == str(estimate_time_to_process(2))
        assert "digest_run_lock_token" in stored

    def test_no_credits_raises(self, monkeypatch):
        import pytest
        with pytest.raises(Exception):
            self._run(monkeypatch, {"enable_digest": "true",
                                    "github_selected_resources": [{"id": "o/a"}]}, credits=False)
