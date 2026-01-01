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
    build_pr_data,
    fetch_and_process_prs
)


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
            "abc123"
        )
        
        assert result["pr_number"] == 123
        assert result["title"] == "Test Pull Request"
        assert result["review_type"] == "full"
        assert result["current_sha"] == "abc123"
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
            previous_sha="old123",
            previous_review_text="Previous review"
        )
        
        assert result["review_type"] == "incremental"
        assert result["previous_sha"] == "old123"
        assert result["previous_review_text"] == "Previous review"
        assert result["current_sha"] == "new123"


class TestFetchAndProcessPRs:
    """Tests for fetch_and_process_prs function."""
    
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
    
    @patch('fetch_pull_requests.fetch_compare_diff')
    @patch('fetch_pull_requests.requests.get')
    def test_detects_new_commits(self, mock_get, mock_compare_diff):
        """Test detecting new commits on reviewed PR."""
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
        
        # Mock compare diff - must return non-empty list
        mock_compare_diff.return_value = [{"filename": "test.py", "patch": "new diff", "status": "modified", "additions": 1, "deletions": 0}]
        
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
        mock_compare_diff.assert_called_once()
    
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

