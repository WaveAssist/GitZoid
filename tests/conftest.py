"""
Pytest configuration and shared fixtures for GitZoid tests.
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock


@pytest.fixture
def sample_pr_data():
    """Sample PR data for testing."""
    return {
        "number": 123,
        "title": "Test Pull Request",
        "body": "This is a test PR description",
        "created_at": "2024-01-15T10:00:00Z",
        "user": {
            "type": "User",
            "login": "testuser"
        },
        "head": {
            "sha": "abc123def456"
        },
        "base": {
            "sha": "base789"
        }
    }


@pytest.fixture
def sample_bot_pr_data():
    """Sample bot PR data for testing."""
    return {
        "number": 124,
        "title": "Bot PR",
        "body": "Automated PR",
        "created_at": "2024-01-15T10:00:00Z",
        "user": {
            "type": "Bot",
            "login": "dependabot[bot]"
        },
        "head": {
            "sha": "bot123"
        }
    }


@pytest.fixture
def sample_old_pr_data():
    """Sample old PR data (>60 days old)."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=70)).isoformat().replace("+00:00", "Z")
    return {
        "number": 125,
        "title": "Old PR",
        "body": "This PR is old",
        "created_at": old_date,
        "user": {
            "type": "User",
            "login": "testuser"
        },
        "head": {
            "sha": "old123"
        }
    }


@pytest.fixture
def sample_recent_pr_data():
    """Sample recent PR data (<60 days old)."""
    recent_date = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat().replace("+00:00", "Z")
    return {
        "number": 126,
        "title": "Recent PR",
        "body": "This PR is recent",
        "created_at": recent_date,
        "user": {
            "type": "User",
            "login": "testuser"
        },
        "head": {
            "sha": "recent123"
        }
    }


@pytest.fixture
def sample_pr_files():
    """Sample PR files data."""
    return [
        {
            "filename": "test.py",
            "patch": "@@ -1,3 +1,3 @@\n-old line\n+new line\n unchanged",
            "status": "modified",
            "additions": 1,
            "deletions": 1
        },
        {
            "filename": "new_file.py",
            "patch": "@@ -0,0 +1,5 @@\n+def new_function():\n+    return True",
            "status": "added",
            "additions": 5,
            "deletions": 0
        }
    ]


@pytest.fixture
def sample_compare_response():
    """Sample GitHub Compare API response."""
    return {
        "files": [
            {
                "filename": "modified.py",
                "patch": "@@ -1 +1 @@\n-old\n+new",
                "status": "modified",
                "additions": 1,
                "deletions": 1
            }
        ]
    }


@pytest.fixture
def sample_review_dict_full():
    """Sample full review dictionary."""
    return {
        "summary": ["PR adds new authentication feature", "Implements JWT token validation"],
        "potential_issues": ["Missing error handling for invalid tokens", "No rate limiting"],
        "potential_optimizations": ["Cache token validation results"],
        "suggestions": ["Add unit tests", "Consider using environment variables for secrets"]
    }


@pytest.fixture
def sample_review_dict_incremental():
    """Sample incremental review dictionary."""
    return {
        "changes_summary": ["Added error handling for edge cases", "Fixed token validation bug"],
        "addressed_issues": ["Fixed missing error handling", "Added rate limiting"],
        "new_observations": ["Consider adding logging for failed validations"]
    }


@pytest.fixture
def sample_reviewed_prs():
    """Sample reviewed PRs tracker data."""
    return {
        "owner/repo#123": {
            "status": "reviewed",
            "last_reviewed_sha": "abc123def456",
            "reviewed_at": "2024-01-15T10:00:00Z",
            "last_review_text": "Previous review text"
        },
        "owner/repo#124": {
            "status": "skipped",
            "skipped_at": "2024-01-15T10:00:00Z"
        }
    }


@pytest.fixture
def mock_github_headers():
    """Mock GitHub API headers."""
    return {
        "Authorization": "token fake_token",
        "Accept": "application/vnd.github+json"
    }


@pytest.fixture
def mock_waveassist():
    """Mock waveassist module."""
    mock = MagicMock()
    mock.fetch_data.return_value = None
    mock.store_data.return_value = None
    mock.init.return_value = None
    mock.check_credits_and_notify.return_value = True
    mock.call_llm.return_value = None
    return mock

