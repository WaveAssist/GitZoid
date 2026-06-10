"""
Unit tests for study_repos.py (the per-repo "brain" builder).
"""
import pytest
import sys
import os
from unittest.mock import Mock, patch
from datetime import datetime, timezone, timedelta

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from study_repos import (
    select_canonical_branch,
    list_branches,
    needs_rebuild,
    pick_key_files,
    _sanitize_profile,
    store_profile,
    get_branch_tree,
    call_llm_with_retry,
    RepoContextProfileV2,
)


def _resp(status=200, json_data=None, links=None):
    r = Mock()
    r.status_code = status
    r.json.return_value = json_data if json_data is not None else {}
    r.links = links or {}
    return r


class TestBranchSelection:
    @patch('study_repos.requests.get')
    def test_override_wins(self, mock_get):
        mock_get.return_value = _resp(200, [
            {"name": "main", "commit": {"sha": "s1"}},
            {"name": "dev", "commit": {"sha": "s2"}},
        ])
        c = select_canonical_branch("o/r", {}, override="dev")
        assert c["branch"] == "dev"
        assert c["source"] == "override"
        assert c["sha"] == "s2"

    @patch('study_repos.requests.get')
    @patch('study_repos.get_default_branch')
    @patch('study_repos.branch_tip_date')
    def test_defaults_to_default(self, mock_tip, mock_default, mock_get):
        mock_get.return_value = _resp(200, [{"name": "main", "commit": {"sha": "s1"}}])
        mock_default.return_value = "main"
        mock_tip.return_value = "2026-06-01T00:00:00Z"
        c = select_canonical_branch("o/r", {})
        assert c["source"] == "default"
        assert c["branch"] == "main"

    @patch('study_repos.requests.get')
    def test_list_branches_paginates(self, mock_get):
        p1 = _resp(200,
                   [{"name": f"b{i}", "commit": {"sha": f"s{i}"}} for i in range(100)],
                   links={"next": {"url": "p2"}})
        p2 = _resp(200, [{"name": "b100", "commit": {"sha": "s100"}}], links={})
        mock_get.side_effect = [p1, p2]
        assert len(list_branches("o/r", {})) == 101


class TestSkipRunNoOp:
    """When skip_run is set (overlapping cycle), the brain builder must not rebuild AND must not
    clobber the stored repo_groups / brain with empty data."""

    def test_skip_run_does_not_store(self, monkeypatch):
        import runpy, waveassist
        fetch_map = {"skip_run": True, "github_selected_resources": [{"id": "owner/repo"}],
                     "github_access_token": "tok"}
        stored = {}
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        import requests
        monkeypatch.setattr(requests, "get",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no GitHub call on skip")))
        runpy.run_path("study_repos.py", run_name="__main__")
        assert "repo_groups" not in stored
        assert "brain" not in stored


class TestStalenessGate:
    def test_missing_rebuilds(self):
        assert needs_rebuild({}) is True

    def test_sha_change_does_not_rebuild(self):
        # Weekly refresh only — a branch SHA change does NOT trigger a rebuild while still fresh.
        existing = {"schema_version": "repo_context_profile_v2",
                    "_fingerprint": {"sha": "x", "built_at": datetime.now(timezone.utc).isoformat()}}
        assert needs_rebuild(existing) is False

    def test_old_schema_rebuilds(self):
        assert needs_rebuild({"summary": "old proto-brain shape"}) is True

    def test_v1_schema_rebuilds(self):
        # a v1 profile must be re-studied into the richer v2 schema (migration, not silent reuse)
        v1 = {"schema_version": "repo_context_profile_v1",
              "_fingerprint": {"sha": "abc", "built_at": datetime.now(timezone.utc).isoformat()}}
        assert needs_rebuild(v1) is True

    def test_recent_profile_skips(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        existing = {"schema_version": "repo_context_profile_v2",
                    "_fingerprint": {"sha": "abc", "built_at": recent}}
        assert needs_rebuild(existing) is False

    def test_ttl_expired_rebuilds(self):
        old = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
        existing = {"schema_version": "repo_context_profile_v2",
                    "_fingerprint": {"sha": "abc", "built_at": old}}
        assert needs_rebuild(existing) is True


class TestKeyFilePicker:
    def test_prefers_auth_skips_vendor_and_tests(self):
        out = pick_key_files([
            "src/auth/login.py",
            "tests/test_auth.py",
            "node_modules/x/route.js",
            "src/router.py",
            "README.md",
        ])
        assert "src/auth/login.py" in out
        assert all("test" not in f and "node_modules" not in f for f in out)


class TestTreeTruncation:
    @patch('study_repos.requests.get')
    def test_truncated_flag_returned(self, mock_get):
        mock_get.return_value = _resp(200, {"tree": [{"type": "blob", "path": "a.py"}], "truncated": True})
        paths, truncated = get_branch_tree("o/r", "main", {})
        assert truncated is True
        assert "a.py" in paths


class TestSanitizer:
    def test_none_lists_coerced(self):
        p = _sanitize_profile({"schema_version": "repo_context_profile_v2",
                               "conventions": None, "security": None,
                               "stack": None, "components": None, "key_files": None})
        assert p["conventions"] == []
        assert p["security"]["routes"] == []
        assert p["security"]["secret_locations"] == []
        assert p["stack"]["languages"] == []
        assert p["stack"]["frameworks"] == []
        assert p["components"] == []
        assert p["key_files"] == []


class TestProfileModel:
    def test_full_payload_validates(self):
        m = RepoContextProfileV2.model_validate({
            "schema_version": "repo_context_profile_v2",
            "architecture_summary": "x",
            "stack": {"languages": ["Python"], "frameworks": ["Django"],
                      "datastores": ["PostgreSQL"], "infrastructure": ["Docker"],
                      "package_managers": ["pip"]},
            "components": [{"name": "api", "responsibility": "REST endpoints"}],
            "key_files": [{"path": "manage.py", "role": "Django entry point"}],
            "conventions": [],
            "dependencies": [],
            "security": {"routes": [], "secret_locations": []},
            "review_focus": [],
        })
        assert m.schema_version == "repo_context_profile_v2"
        assert m.stack.frameworks == ["Django"]
        assert m.key_files[0].path == "manage.py"
        assert m.components[0].name == "api"


class TestAtomicWrite:
    def test_store_profile_per_repo_key(self):
        wa = Mock()
        store_profile(wa, "o/r", {"schema_version": "repo_context_profile_v2"})
        args, kwargs = wa.store_data.call_args
        assert args[0] == "profile:o/r"
        assert kwargs.get("data_type") == "json"


class TestCallLlmRetry:
    def test_succeeds_first_try(self):
        with patch('study_repos.waveassist.call_llm') as m:
            m.return_value = "RESULT"
            out = call_llm_with_retry("model", "prompt", RepoContextProfileV2, attempts=3, sleep_s=0)
            assert out == "RESULT"
            assert m.call_count == 1

    def test_retries_then_succeeds(self):
        with patch('study_repos.waveassist.call_llm') as m:
            m.side_effect = [RuntimeError("transient"), "RESULT"]
            out = call_llm_with_retry("model", "prompt", RepoContextProfileV2, attempts=3, sleep_s=0)
            assert out == "RESULT"
            assert m.call_count == 2

    def test_raises_after_exhausting(self):
        with patch('study_repos.waveassist.call_llm') as m:
            m.side_effect = RuntimeError("down")
            with pytest.raises(RuntimeError):
                call_llm_with_retry("model", "prompt", RepoContextProfileV2, attempts=2, sleep_s=0)
            assert m.call_count == 2
