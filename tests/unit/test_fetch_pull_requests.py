"""
Unit tests for fetch_pull_requests.py
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from fetch_pull_requests import (
    fetch_compare_diff,
    fetch_pr_files,
    is_first_run_for_repo,
    is_bot_pr,
    is_old_pr,
    is_draft_pr,
    build_pr_data,
    fetch_and_process_prs
)


def _paged(status=200, json_data=None, has_next=False):
    r = Mock()
    r.status_code = status
    r.json.return_value = json_data if json_data is not None else {}
    r.links = {"next": {"url": "p2"}} if has_next else {}
    return r


class TestSkipRunNoOp:
    """When check_credits_and_init set skip_run (an overlapping cycle), the driver must be a no-op:
    no GitHub calls, and it must NOT store pull_requests (so downstream nodes no-op too)."""

    def test_skip_run_does_no_work(self, monkeypatch):
        import runpy, waveassist
        fetch_map = {"skip_run": "1", "github_selected_resources": [{"id": "owner/repo"}],
                     "github_access_token": "tok", "reviewed_prs": {}}
        stored = {}
        called = {"get": 0}
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        import requests
        monkeypatch.setattr(requests, "get",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no GitHub call on skip")))
        runpy.run_path("fetch_pull_requests.py", run_name="__main__")
        assert "pull_requests" not in stored   # nothing queued for review
        assert called["get"] == 0


class TestFetchCompareDiff:
    """Tests for fetch_compare_diff function."""
    
    @patch('fetch_pull_requests.requests.get')
    def test_fetch_compare_diff_success(self, mock_get, sample_compare_response):
        """Test successfully fetching compare diff."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_compare_response
        mock_get.return_value = mock_response
        
        headers = {"Authorization": "token fake_token"}
        result = fetch_compare_diff("owner/repo", "base123", "head456", headers)
        
        assert len(result) == 1
        assert result[0]["filename"] == "modified.py"
        assert result[0]["status"] == "modified"
        assert result[0]["additions"] == 1
        assert result[0]["deletions"] == 1
        mock_get.assert_called_once()
    
    @patch('fetch_pull_requests.requests.get')
    def test_fetch_compare_diff_api_error(self, mock_get):
        """Test handling GitHub API errors."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        headers = {"Authorization": "token fake_token"}
        result = fetch_compare_diff("owner/repo", "base123", "head456", headers)
        
        assert result == []
    
    @patch('fetch_pull_requests.requests.get')
    def test_fetch_compare_diff_server_error(self, mock_get):
        """Test handling server errors."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        headers = {"Authorization": "token fake_token"}
        result = fetch_compare_diff("owner/repo", "base123", "head456", headers)
        
        assert result == []
    
    @patch('fetch_pull_requests.requests.get')
    def test_fetch_compare_diff_empty_files(self, mock_get):
        """Test handling empty file list."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"files": []}
        mock_get.return_value = mock_response
        
        headers = {"Authorization": "token fake_token"}
        result = fetch_compare_diff("owner/repo", "base123", "head456", headers)
        
        assert result == []
    
    @patch('fetch_pull_requests.requests.get')
    def test_fetch_compare_diff_missing_patch(self, mock_get):
        """Test handling files without patch data."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "files": [
                {
                    "filename": "binary.bin",
                    "status": "modified",
                    "additions": 0,
                    "deletions": 0
                }
            ]
        }
        mock_get.return_value = mock_response
        
        headers = {"Authorization": "token fake_token"}
        result = fetch_compare_diff("owner/repo", "base123", "head456", headers)
        
        assert len(result) == 1
        assert result[0]["filename"] == "binary.bin"
        assert result[0]["patch"] == ""
    
    @patch('fetch_pull_requests.requests.get')
    def test_fetch_compare_diff_parse_error(self, mock_get):
        """Test handling JSON parse errors."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response
        
        headers = {"Authorization": "token fake_token"}
        result = fetch_compare_diff("owner/repo", "base123", "head456", headers)
        
        assert result == []


class TestFetchPRFiles:
    """Tests for fetch_pr_files function."""
    
    @patch('fetch_pull_requests.requests.get')
    def test_fetch_pr_files_success(self, mock_get, sample_pr_files):
        """Test successfully fetching PR files."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_pr_files
        mock_get.return_value = mock_response
        
        headers = {"Authorization": "token fake_token"}
        result = fetch_pr_files("owner/repo", 123, headers)
        
        assert len(result) == 2
        assert result[0]["filename"] == "test.py"
        assert result[1]["filename"] == "new_file.py"
        mock_get.assert_called_once()
    
    @patch('fetch_pull_requests.requests.get')
    def test_fetch_pr_files_api_error(self, mock_get):
        """Test handling API errors."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        headers = {"Authorization": "token fake_token"}
        result = fetch_pr_files("owner/repo", 123, headers)
        
        assert result == []
    
    @patch('fetch_pull_requests.requests.get')
    def test_fetch_pr_files_invalid_json(self, mock_get):
        """Test handling invalid JSON responses."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response
        
        headers = {"Authorization": "token fake_token"}
        result = fetch_pr_files("owner/repo", 123, headers)
        
        assert result == []


class TestIsFirstRunForRepo:
    """Tests for is_first_run_for_repo function."""
    
    def test_is_first_run_empty_tracker(self):
        """Test first run with empty tracker."""
        reviewed_prs = {}
        result = is_first_run_for_repo("owner/repo", reviewed_prs)
        assert result == True
    
    def test_is_first_run_no_matching_repos(self):
        """Test first run when tracker has other repos."""
        reviewed_prs = {
            "other/repo#123": {"status": "reviewed"}
        }
        result = is_first_run_for_repo("owner/repo", reviewed_prs)
        assert result == True
    
    def test_is_not_first_run(self):
        """Test subsequent run when PRs exist for repo."""
        reviewed_prs = {
            "owner/repo#123": {"status": "reviewed"}
        }
        result = is_first_run_for_repo("owner/repo", reviewed_prs)
        assert result == False


class TestIsBotPR:
    """Tests for is_bot_pr function."""
    
    def test_is_bot_pr_by_type(self, sample_bot_pr_data):
        """Test detecting bot by type field."""
        result = is_bot_pr(sample_bot_pr_data)
        assert result == True
    
    def test_is_bot_pr_by_login(self):
        """Test detecting bot by login ending with [bot]."""
        pr = {
            "user": {
                "type": "User",
                "login": "dependabot[bot]"
            }
        }
        result = is_bot_pr(pr)
        assert result == True
    
    def test_is_not_bot_pr(self, sample_pr_data):
        """Test human user is not detected as bot."""
        result = is_bot_pr(sample_pr_data)
        assert result == False
    
    def test_is_bot_pr_missing_user(self):
        """Test handling missing user data."""
        pr = {}
        result = is_bot_pr(pr)
        assert result == False
    
    def test_is_bot_pr_case_insensitive(self):
        """Test bot detection is case insensitive."""
        pr = {
            "user": {
                "type": "User",
                "login": "DEPENDABOT[BOT]"
            }
        }
        result = is_bot_pr(pr)
        assert result == True


class TestIsOldPR:
    """Tests for is_old_pr function."""
    
    def test_is_old_pr(self, sample_old_pr_data):
        """Test detecting old PR (>60 days)."""
        result = is_old_pr(sample_old_pr_data, days=60)
        assert result == True
    
    def test_is_not_old_pr(self, sample_recent_pr_data):
        """Test recent PR is not detected as old."""
        result = is_old_pr(sample_recent_pr_data, days=60)
        assert result == False
    
    def test_is_old_pr_custom_threshold(self):
        """Test custom day threshold."""
        old_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat().replace("+00:00", "Z")
        pr = {
            "created_at": old_date
        }
        result = is_old_pr(pr, days=5)
        assert result == True
    
    def test_is_old_pr_invalid_date(self):
        """Test handling invalid date format."""
        pr = {
            "created_at": "invalid-date"
        }
        result = is_old_pr(pr, days=60)
        assert result == False
    
    def test_is_old_pr_missing_date(self):
        """Test handling missing created_at."""
        pr = {}
        result = is_old_pr(pr, days=60)
        assert result == False


class TestBuildPRData:
    """Tests for build_pr_data function."""
    
    def test_build_pr_data_full_review(self, sample_pr_data, sample_pr_files):
        """Test building data for full review."""
        result = build_pr_data(
            sample_pr_data,
            sample_pr_files,
            "full",
            "abc123",
            "owner/repo"
        )

        assert result["pr_number"] == 123
        assert result["title"] == "Test Pull Request"
        assert result["review_type"] == "full"
        assert result["current_sha"] == "abc123"
        assert result["id"] == "owner/repo"
        assert result["files"] == sample_pr_files
        assert "previous_sha" not in result
        assert "previous_review_text" not in result
    
    def test_build_pr_data_incremental_review(self, sample_pr_data, sample_pr_files):
        """Test building data for incremental review."""
        result = build_pr_data(
            sample_pr_data,
            sample_pr_files,
            "incremental",
            "new123",
            "owner/repo",
            previous_sha="old123",
            previous_review_text="Previous review"
        )

        assert result["review_type"] == "incremental"
        assert result["previous_sha"] == "old123"
        assert result["previous_review_text"] == "Previous review"
        assert result["current_sha"] == "new123"


class TestFetchAndProcessPRs:
    """Tests for fetch_and_process_prs function."""

    @pytest.fixture(autouse=True)
    def _isolate_review_context(self):
        # These tests predate the per-repo review-context fetch (review.md/CLAUDE.md + PR comments)
        # and mock requests.get for the PR list only. Neutralise the new network calls so they stay
        # hermetic; the review-context behaviour is covered in test_review_context.py.
        empty_cfg = {"instructions": "", "focus": [], "conventions": "", "skip": False,
                     "severity_floor": "", "ignore": [], "source": "", "conventions_source": ""}
        with patch('fetch_pull_requests.fetch_review_config', return_value=empty_cfg), \
             patch('fetch_pull_requests.fetch_pr_comments', return_value=""):
            yield

    @patch('fetch_pull_requests.fetch_pr_files')
    @patch('fetch_pull_requests.requests.get')
    def test_first_run_processes_first_two(self, mock_get, mock_fetch_files, sample_pr_data):
        """Test first run processes first 2 PRs and skips rest."""
        from datetime import datetime, timezone
        # Create fresh PR data with all required fields
        recent_date = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        pr1 = {
            "number": 1,
            "title": "Test PR 1",
            "body": "Description",
            "created_at": recent_date,
            "user": {"type": "User", "login": "testuser"},
            "head": {"sha": "sha1"}
        }
        pr2 = {
            "number": 2,
            "title": "Test PR 2",
            "body": "Description",
            "created_at": recent_date,
            "user": {"type": "User", "login": "testuser"},
            "head": {"sha": "sha2"}
        }
        pr3 = {
            "number": 3,
            "title": "Test PR 3",
            "body": "Description",
            "created_at": recent_date,
            "user": {"type": "User", "login": "testuser"},
            "head": {"sha": "sha3"}
        }
        
        # Mock PR list API
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [pr1, pr2, pr3]
        mock_get.return_value = mock_response
        
        # Mock fetch_pr_files - must return non-empty list
        mock_fetch_files.return_value = [{"filename": "test.py", "patch": "diff", "status": "modified", "additions": 1, "deletions": 0}]
        
        repo_metadata = {"id": "owner/repo"}
        access_token = "fake_token"
        reviewed_prs = {}
        
        prs, changed = fetch_and_process_prs(repo_metadata, access_token, reviewed_prs)
        
        # Should process first 2 PRs
        assert len(prs) == 2
        assert prs[0]["pr_number"] == 1
        assert prs[1]["pr_number"] == 2
        # Should mark PR #3 as skipped
        assert changed == True
        assert "owner/repo#3" in reviewed_prs
        assert reviewed_prs["owner/repo#3"]["status"] == "skipped"
    
    @patch('fetch_pull_requests.fetch_pr_files')
    @patch('fetch_pull_requests.requests.get')
    def test_subsequent_run_new_pr(self, mock_get, mock_fetch_files):
        """Test subsequent run processes new PR."""
        from datetime import datetime, timezone
        recent_date = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        pr4 = {
            "number": 4,
            "title": "Test PR 4",
            "body": "Description",
            "created_at": recent_date,
            "user": {"type": "User", "login": "testuser"},
            "head": {"sha": "sha4"}
        }
        
        # Mock PR list API
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [pr4]
        mock_get.return_value = mock_response
        
        # Mock fetch_pr_files - must return non-empty list
        mock_fetch_files.return_value = [{"filename": "test.py", "patch": "diff", "status": "modified", "additions": 1, "deletions": 0}]
        
        repo_metadata = {"id": "owner/repo"}
        access_token = "fake_token"
        reviewed_prs = {
            "owner/repo#1": {"status": "reviewed", "last_reviewed_sha": "abc123"}
        }
        
        prs, changed = fetch_and_process_prs(repo_metadata, access_token, reviewed_prs)
        
        assert len(prs) == 1
        assert prs[0]["pr_number"] == 4
        # changed will be True because PR #1 is not in open PRs, so it gets cleaned up
        # This is expected behavior - cleanup sets changed = True
        assert changed == True
    
    @patch('fetch_pull_requests.fetch_pr_files')
    @patch('fetch_pull_requests.requests.get')
    def test_detects_new_commits(self, mock_get, mock_fetch_files):
        """Test detecting new commits on reviewed PR (re-review pulls the FULL PR, not the compare diff)."""
        from datetime import datetime, timezone
        recent_date = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        pr123 = {
            "number": 123,
            "title": "Test PR",
            "body": "Description",
            "created_at": recent_date,
            "user": {"type": "User", "login": "testuser"},
            "head": {"sha": "new456"}
        }
        
        # Mock PR list API
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [pr123]
        mock_get.return_value = mock_response
        
        # Mock full PR files - must return non-empty list (re-review reviews the whole PR)
        mock_fetch_files.return_value = [{"filename": "test.py", "patch": "new diff", "status": "modified", "additions": 1, "deletions": 0}]
        
        repo_metadata = {"id": "owner/repo"}
        access_token = "fake_token"
        reviewed_prs = {
            "owner/repo#123": {
                "status": "reviewed",
                "last_reviewed_sha": "old123",
                "last_review_text": "Previous review"
            }
        }
        
        prs, changed = fetch_and_process_prs(repo_metadata, access_token, reviewed_prs)
        
        assert len(prs) == 1
        assert prs[0]["pr_number"] == 123
        assert prs[0]["review_type"] == "incremental"
        assert prs[0]["previous_sha"] == "old123"
        assert prs[0]["current_sha"] == "new456"
        mock_fetch_files.assert_called_once()
    
    @patch('fetch_pull_requests.fetch_pr_files')
    @patch('fetch_pull_requests.requests.get')
    def test_skips_bot_prs(self, mock_get, mock_fetch_files, sample_bot_pr_data):
        """Test skipping bot PRs."""
        from datetime import datetime, timezone
        recent_date = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        human_pr = {
            "number": 123,
            "title": "Human PR",
            "body": "Description",
            "created_at": recent_date,
            "user": {"type": "User", "login": "testuser"},
            "head": {"sha": "sha123"}
        }
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            sample_bot_pr_data,
            human_pr
        ]
        mock_get.return_value = mock_response
        
        # Mock fetch_pr_files - must return non-empty list
        mock_fetch_files.return_value = [{"filename": "test.py", "patch": "diff", "status": "modified", "additions": 1, "deletions": 0}]
        
        repo_metadata = {"id": "owner/repo"}
        access_token = "fake_token"
        reviewed_prs = {}
        
        prs, changed = fetch_and_process_prs(repo_metadata, access_token, reviewed_prs)
        
        # Should only process human PR, skip bot PR
        assert len(prs) == 1
        assert prs[0]["pr_number"] == 123
    
    @patch('fetch_pull_requests.fetch_pr_files')
    @patch('fetch_pull_requests.requests.get')
    def test_skips_old_prs(self, mock_get, mock_fetch_files, sample_old_pr_data, sample_recent_pr_data):
        """Test skipping old PRs."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            sample_old_pr_data,
            {**sample_recent_pr_data, "head": {"sha": "sha126"}}
        ]
        mock_get.return_value = mock_response
        
        # Mock fetch_pr_files - must return non-empty list
        mock_fetch_files.return_value = [{"filename": "test.py", "patch": "diff", "status": "modified", "additions": 1, "deletions": 0}]
        
        repo_metadata = {"id": "owner/repo"}
        access_token = "fake_token"
        reviewed_prs = {}
        
        prs, changed = fetch_and_process_prs(repo_metadata, access_token, reviewed_prs)
        
        # Should only process recent PR
        assert len(prs) == 1
        assert prs[0]["pr_number"] == 126
    
    @patch('fetch_pull_requests.requests.get')
    def test_skips_permanently_skipped_prs(self, mock_get, sample_pr_data):
        """Test skipping permanently skipped PRs."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {**sample_pr_data, "number": 123}
        ]
        mock_get.return_value = mock_response
        
        repo_metadata = {"id": "owner/repo"}
        access_token = "fake_token"
        reviewed_prs = {
            "owner/repo#123": {"status": "skipped"}
        }
        
        prs, changed = fetch_and_process_prs(repo_metadata, access_token, reviewed_prs)
        
        assert len(prs) == 0
    
    @patch('fetch_pull_requests.requests.get')
    def test_cleans_up_closed_prs(self, mock_get, sample_pr_data):
        """Test cleanup of closed PRs from tracker."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []  # No open PRs
        mock_get.return_value = mock_response
        
        repo_metadata = {"id": "owner/repo"}
        access_token = "fake_token"
        reviewed_prs = {
            "owner/repo#123": {"status": "reviewed", "last_reviewed_sha": "abc123"}
        }
        
        prs, changed = fetch_and_process_prs(repo_metadata, access_token, reviewed_prs)
        
        # Closed PR should be removed from tracker
        assert "owner/repo#123" not in reviewed_prs
        assert changed == True
    
    @patch('fetch_pull_requests.requests.get')
    def test_api_failure_handling(self, mock_get):
        """Test handling GitHub API failures."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        repo_metadata = {"id": "owner/repo"}
        access_token = "fake_token"
        reviewed_prs = {}
        
        prs, changed = fetch_and_process_prs(repo_metadata, access_token, reviewed_prs)
        
        assert len(prs) == 0
        assert changed == False
    
    @patch('fetch_pull_requests.requests.get')
    def test_invalid_json_response(self, mock_get):
        """Test handling invalid JSON responses."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response

        repo_metadata = {"id": "owner/repo"}
        access_token = "fake_token"
        reviewed_prs = {}

        prs, changed = fetch_and_process_prs(repo_metadata, access_token, reviewed_prs)

        assert len(prs) == 0
        assert changed == False


class TestIsDraftPR:
    def test_draft_true(self):
        assert is_draft_pr({"draft": True}) is True

    def test_draft_false(self):
        assert is_draft_pr({"draft": False}) is False

    def test_draft_missing(self):
        assert is_draft_pr({}) is False


class TestPagination:
    @patch('fetch_pull_requests.requests.get')
    def test_fetch_pr_files_paginates(self, mock_get):
        page1 = _paged(200, [{"filename": f"f{i}.py", "patch": "p", "additions": 1, "deletions": 0}
                             for i in range(100)], has_next=True)
        page2 = _paged(200, [{"filename": "f100.py", "patch": "p", "additions": 1, "deletions": 0}])
        mock_get.side_effect = [page1, page2]
        result = fetch_pr_files("owner/repo", 1, {})
        assert len(result) == 101
        assert mock_get.call_count == 2

    @patch('fetch_pull_requests.requests.get')
    def test_fetch_compare_diff_paginates(self, mock_get):
        page1 = _paged(200, {"files": [{"filename": f"f{i}.py", "patch": "p"} for i in range(100)]},
                       has_next=True)
        page2 = _paged(200, {"files": [{"filename": "f100.py", "patch": "p"}]})
        mock_get.side_effect = [page1, page2]
        result = fetch_compare_diff("owner/repo", "b", "h", {})
        assert len(result) == 101
        assert mock_get.call_count == 2

    @patch('fetch_pull_requests.requests.get')
    def test_single_page_when_no_next(self, mock_get):
        # a Mock response without a dict .links must NOT loop forever (defensive _has_next_page)
        mock_get.return_value = _paged(200, [{"filename": "a.py", "patch": "p"}])
        result = fetch_pr_files("owner/repo", 1, {})
        assert len(result) == 1
        assert mock_get.call_count == 1


class TestBuildPRDataBrainProfile:
    def test_attaches_brain_profile(self, sample_pr_data, sample_pr_files):
        prof = {"architecture_summary": "x", "conventions": ["c"]}
        r = build_pr_data(sample_pr_data, sample_pr_files, "full", "abc", "owner/repo", brain_profile=prof)
        assert r["brain_profile"] == prof

    def test_no_brain_profile_key_when_absent(self, sample_pr_data, sample_pr_files):
        r = build_pr_data(sample_pr_data, sample_pr_files, "full", "abc", "owner/repo")
        assert "brain_profile" not in r



class TestReviewSkipRepos:
    """`review_skip_repos` turns PR review off for listed repos; security and digest are unaffected."""

    def test_parse_list_json_and_text(self):
        from fetch_pull_requests import parse_repo_list
        assert parse_repo_list(["Org/IPD-API", " ipd-admin "]) == {"org/ipd-api", "ipd-admin"}
        assert parse_repo_list('["org/a", "b"]') == {"org/a", "b"}
        assert parse_repo_list("org/a, b\nc") == {"org/a", "b", "c"}
        assert parse_repo_list("") == set() and parse_repo_list(None) == set()

    def test_matches_full_or_bare_name_only(self):
        from fetch_pull_requests import review_skipped
        skip = {"ipd-api", "org/ipd-user"}
        assert review_skipped({"id": "Org/ipd-api"}, skip)
        assert review_skipped("org/ipd-user", skip)
        assert not review_skipped({"id": "org/ipd-api-v2"}, skip)
        assert not review_skipped({"id": "other/ipd-user"}, skip)

    def test_driver_skips_listed_repos(self, monkeypatch):
        import runpy, waveassist, requests
        seen = []
        fetch_map = {"skip_run": "0", "github_access_token": "t", "reviewed_prs": {},
                     "github_selected_resources": [{"id": "org/ipd-api"}, {"id": "org/ipd-admin"},
                                                   {"id": "org/ipd-user"}, {"id": "org/erp"}],
                     "review_skip_repos": ["ipd-api", "ipd-admin", "ipd-user"]}

        def get(url, *a, **k):
            seen.append(url)
            r = Mock(); r.status_code = 404; r.json.return_value = {}; r.links = {}; r.headers = {}
            return r
        monkeypatch.setattr(waveassist, "fetch_data", lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data", lambda *a, **k: True)
        monkeypatch.setattr(requests, "get", get)
        runpy.run_path("fetch_pull_requests.py", run_name="__main__")
        assert seen and all("/org/erp/" in u for u in seen)


class TestConditionalPrList:
    """Polling ~130 repos every 2 minutes used the whole GitHub hourly limit. The open-PR listing is a
    conditional request: an unchanged repo answers 304, which GitHub does not count."""

    def _resp(self, status, prs=None, etag=None):
        r = Mock()
        r.status_code = status
        r.json.return_value = prs if prs is not None else []
        r.links = {}
        r.headers = {"ETag": etag} if etag else {}
        return r

    def _gh_pr(self, n):
        return {"number": n, "title": f"PR {n}", "body": "b", "draft": False, "labels": [{"name": "x", "id": 1}],
                "created_at": "2026-10-13T00:00:00Z", "updated_at": "2026-10-14T00:00:00Z",
                "user": {"login": "dev", "type": "User", "id": 9}, "head": {"sha": "abc", "repo": {"big": "x" * 500}},
                "base": {"repo": {"big": "x" * 500}}, "_links": {"self": "u"}}

    def test_first_fetch_caches_slim_list_with_etag(self):
        from fetch_pull_requests import list_open_prs
        cache = {}
        with patch("fetch_pull_requests.requests.get", return_value=self._resp(200, [self._gh_pr(1)], 'W/"e1"')) as g:
            prs = list_open_prs("o/r", {"Authorization": "t"}, cache)
        assert "If-None-Match" not in g.call_args.kwargs["headers"]
        assert cache["o/r"]["etag"] == 'W/"e1"' and prs[0]["number"] == 1
        assert "base" not in prs[0] and "repo" not in prs[0]["head"]      # slim: no repo objects

    def test_304_reuses_cache_and_sends_etag(self):
        from fetch_pull_requests import list_open_prs
        cache = {"o/r": {"etag": 'W/"e1"', "prs": [{"number": 7}]}}
        with patch("fetch_pull_requests.requests.get", return_value=self._resp(304)) as g:
            prs = list_open_prs("o/r", {"Authorization": "t"}, cache)
        assert g.call_args.kwargs["headers"]["If-None-Match"] == 'W/"e1"'
        assert prs == [{"number": 7}] and cache["o/r"]["etag"] == 'W/"e1"'

    def test_changed_list_replaces_cache(self):
        from fetch_pull_requests import list_open_prs
        cache = {"o/r": {"etag": 'W/"e1"', "prs": [{"number": 7}]}}
        with patch("fetch_pull_requests.requests.get", return_value=self._resp(200, [self._gh_pr(8)], 'W/"e2"')):
            prs = list_open_prs("o/r", {}, cache)
        assert [p["number"] for p in prs] == [8] and cache["o/r"]["etag"] == 'W/"e2"'

    def test_failure_returns_none_and_keeps_cache(self):
        from fetch_pull_requests import list_open_prs
        cache = {"o/r": {"etag": 'W/"e1"', "prs": [{"number": 7}]}}
        with patch("fetch_pull_requests.requests.get", return_value=self._resp(403)):
            assert list_open_prs("o/r", {}, cache) is None
        assert cache["o/r"]["etag"] == 'W/"e1"'

    def test_cached_and_fresh_lists_review_the_same(self, monkeypatch):
        """A 304 must lead to exactly the same PR handling as a fresh 200 (same queue, same state)."""
        from fetch_pull_requests import fetch_and_process_prs
        import fetch_pull_requests as fp
        monkeypatch.setattr(fp, "fetch_review_config", lambda *a, **k: {})
        monkeypatch.setattr(fp, "_fetch_reviewable_files", lambda *a, **k: ([{"filename": "a.py"}], False))
        monkeypatch.setattr(fp, "fetch_pr_comments", lambda *a, **k: "")
        reviewed = {"o/r#99": {"status": "skipped"}}                    # not a first run
        cache = {}
        with patch("fetch_pull_requests.requests.get", return_value=self._resp(200, [self._gh_pr(1)], 'W/"e1"')):
            fresh, _ = fetch_and_process_prs({"id": "o/r"}, "t", dict(reviewed), list_cache=cache)
        with patch("fetch_pull_requests.requests.get", return_value=self._resp(304)):
            cached, _ = fetch_and_process_prs({"id": "o/r"}, "t", dict(reviewed), list_cache=cache)
        assert [p["pr_number"] for p in fresh] == [p["pr_number"] for p in cached] == [1]
        assert fresh[0]["title"] == cached[0]["title"] and fresh[0]["current_sha"] == cached[0]["current_sha"]

    def test_driver_saves_cache_only_when_a_list_changed(self, monkeypatch):
        import runpy, waveassist, requests
        stored = {}
        fetch_map = {"skip_run": "0", "github_access_token": "t", "reviewed_prs": {},
                     "github_selected_resources": [{"id": "o/a"}],
                     "pr_list_cache": {"o/a": {"etag": 'W/"e1"', "prs": []}, "o/gone": {"etag": "x", "prs": []}}}
        monkeypatch.setattr(waveassist, "fetch_data", lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data", lambda key, value, **k: stored.__setitem__(key, value))
        monkeypatch.setattr(requests, "get", lambda *a, **k: self._resp(304))
        runpy.run_path("fetch_pull_requests.py", run_name="__main__")
        # o/a unchanged (304); o/gone dropped because it is no longer selected -> saved once, pruned
        assert stored.get("pr_list_cache") == {"o/a": {"etag": 'W/"e1"', "prs": []}}


class TestQueueSize:
    """One project's queue grew to 12 MB (a 1,017-file PR), over the API's 2.5 MB request limit; the save
    failed silently and no PR in that project was reviewed for days."""

    def test_cap_keeps_smallest_patches_and_all_filenames(self):
        from fetch_pull_requests import cap_patches
        files = [{"filename": "big.py", "patch": "x" * 100}, {"filename": "a.py", "patch": "y" * 30},
                 {"filename": "b.py", "patch": "z" * 40}]
        out = cap_patches(files, budget=80)
        assert [f["filename"] for f in out] == ["big.py", "a.py", "b.py"]
        assert out[0]["patch"] == "" and out[0]["patch_omitted"] is True
        assert out[1]["patch"] == "y" * 30 and out[2]["patch"] == "z" * 40
        assert files[0]["patch"] == "x" * 100                  # input untouched

    def test_build_pr_data_caps_patches(self):
        from fetch_pull_requests import build_pr_data, PR_PATCH_BUDGET_CHARS
        files = [{"filename": f"f{i}.py", "patch": "p" * 1000} for i in range(1000)]
        data = build_pr_data({"number": 1, "title": "t", "body": "b", "created_at": "x"}, files, "full", "sha", "o/r")
        assert len(data["files"]) == 1000
        assert sum(len(f["patch"]) for f in data["files"]) <= PR_PATCH_BUDGET_CHARS

    def test_fit_queue_defers_largest_and_keeps_order(self):
        from fetch_pull_requests import fit_queue
        prs = [{"n": 1, "d": "a" * 50}, {"n": 2, "d": "b" * 500}, {"n": 3, "d": "c" * 60}]
        kept, deferred = fit_queue(prs, max_bytes=200)
        assert [p["n"] for p in kept] == [1, 3] and deferred == 1
        assert fit_queue(prs, max_bytes=10_000) == (prs, 0)

    def test_failed_save_is_logged(self, monkeypatch, capsys):
        import runpy, waveassist, requests
        fetch_map = {"skip_run": "0", "github_access_token": "t", "reviewed_prs": {},
                     "github_selected_resources": []}
        monkeypatch.setattr(waveassist, "fetch_data", lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data", lambda key, value, **k: False if key == "pull_requests" else True)
        runpy.run_path("fetch_pull_requests.py", run_name="__main__")
        assert "Could not save the review queue" in capsys.readouterr().out
