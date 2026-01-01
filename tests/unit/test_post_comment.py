"""
Unit tests for post_comment.py
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from post_comment import (
    format_array_to_markdown,
    generate_full_comment,
    generate_incremental_comment,
    post_pr_comment,
    update_reviewed_prs
)


class TestFormatArrayToMarkdown:
    """Tests for format_array_to_markdown function."""
    
    def test_format_array_to_markdown_basic(self):
        """Test basic array to markdown conversion."""
        items = ["Item 1", "Item 2", "Item 3"]
        result = format_array_to_markdown(items)
        
        assert "- Item 1" in result
        assert "- Item 2" in result
        assert "- Item 3" in result
        assert result.count("-") == 3
    
    def test_format_array_to_markdown_empty(self):
        """Test handling empty array."""
        result = format_array_to_markdown([])
        assert result == ""
    
    def test_format_array_to_markdown_none(self):
        """Test handling None input."""
        result = format_array_to_markdown(None)
        assert result == ""
    
    def test_format_array_to_markdown_single_item(self):
        """Test single item conversion."""
        result = format_array_to_markdown(["Single item"])
        assert result == "- Single item"
    
    def test_format_array_to_markdown_special_characters(self):
        """Test handling special markdown characters."""
        items = ["Item with *asterisk*", "Item with _underscore_", "Item with `code`"]
        result = format_array_to_markdown(items)
        
        # Should preserve special characters (not escaping, just formatting)
        assert "*asterisk*" in result
        assert "_underscore_" in result
        assert "`code`" in result


class TestGenerateFullComment:
    """Tests for generate_full_comment function."""
    
    def test_generate_full_comment_all_sections(self, sample_review_dict_full):
        """Test generating comment with all sections."""
        comment = generate_full_comment(sample_review_dict_full)
        
        assert "Summary" in comment
        assert "Potential Issues" in comment
        assert "Potential Optimizations" in comment
        assert "Suggestions" in comment
        assert "Gitzoid" in comment  # Footer
        assert "automated AI-generated review" in comment  # Intro
    
    def test_generate_full_comment_missing_sections(self):
        """Test generating comment with missing sections."""
        review_dict = {
            "summary": ["Summary point"],
            "potential_issues": [],
            "potential_optimizations": [],
            "suggestions": []
        }
        comment = generate_full_comment(review_dict)
        
        assert "Summary" in comment
        assert "Potential Issues" not in comment  # Empty section should be omitted
        assert "Potential Optimizations" not in comment
        assert "Suggestions" not in comment
    
    def test_generate_full_comment_only_summary(self):
        """Test comment with only summary section."""
        review_dict = {
            "summary": ["Only summary"],
            "potential_issues": [],
            "potential_optimizations": [],
            "suggestions": []
        }
        comment = generate_full_comment(review_dict)
        
        assert "Summary" in comment
        assert "Only summary" in comment
        assert "Potential Issues" not in comment
    
    def test_generate_full_comment_includes_footer(self, sample_review_dict_full):
        """Test comment includes footer."""
        comment = generate_full_comment(sample_review_dict_full)
        
        assert "Gitzoid" in comment
        assert "waveassist.io" in comment or "gitzoid" in comment.lower()
    
    def test_generate_full_comment_includes_intro(self, sample_review_dict_full):
        """Test comment includes intro."""
        comment = generate_full_comment(sample_review_dict_full)
        
        # Intro has underscores, so check for the core text
        assert "automated" in comment.lower() and "review" in comment.lower()
    
    def test_generate_full_comment_empty_dict(self):
        """Test handling empty review dictionary."""
        comment = generate_full_comment({})
        
        # Should still have intro and footer
        assert "Gitzoid" in comment
        assert "automated" in comment.lower() and "review" in comment.lower()


class TestGenerateIncrementalComment:
    """Tests for generate_incremental_comment function."""
    
    def test_generate_incremental_comment_all_sections(self, sample_review_dict_incremental):
        """Test generating incremental comment with all sections."""
        comment = generate_incremental_comment(
            sample_review_dict_incremental,
            previous_sha="abc123def456",
            current_sha="def456ghi789"
        )
        
        assert "New commits detected" in comment
        assert "Changes Summary" in comment
        assert "Addressed Issues" in comment
        assert "New Observations" in comment
        assert "abc123" in comment  # First 7 chars of previous SHA
        assert "def456" in comment  # First 7 chars of current SHA
    
    def test_generate_incremental_comment_missing_sections(self):
        """Test incremental comment with missing sections."""
        review_dict = {
            "changes_summary": ["Changes"],
            "addressed_issues": [],
            "new_observations": []
        }
        comment = generate_incremental_comment(review_dict)
        
        assert "Changes Summary" in comment
        assert "Addressed Issues" not in comment
        assert "New Observations" not in comment
    
    def test_generate_incremental_comment_no_sha(self, sample_review_dict_incremental):
        """Test incremental comment without SHA info."""
        comment = generate_incremental_comment(sample_review_dict_incremental)
        
        assert "New commits detected" in comment
    
    def test_generate_incremental_comment_sha_formatting(self):
        """Test SHA formatting in incremental comment."""
        review_dict = {
            "changes_summary": ["Changes"]
        }
        comment = generate_incremental_comment(
            review_dict,
            previous_sha="abc123def456",
            current_sha="def456ghi789"
        )
        
        # Should show first 7 characters
        assert "abc123" in comment
        assert "def456" in comment
        assert "→" in comment or "to" in comment.lower()
    
    def test_generate_incremental_comment_includes_footer(self, sample_review_dict_incremental):
        """Test incremental comment includes footer."""
        comment = generate_incremental_comment(sample_review_dict_incremental)
        
        assert "Gitzoid" in comment


class TestPostPRComment:
    """Tests for post_pr_comment function."""
    
    @patch('post_comment.requests.post')
    def test_post_pr_comment_success(self, mock_post):
        """Test successfully posting comment."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": 123, "body": "Test comment"}
        mock_post.return_value = mock_response
        
        result = post_pr_comment("owner/repo", 1, "Test comment", "fake_token")
        
        assert result is not None
        assert result["id"] == 123
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "Bearer fake_token" in call_args[1]["headers"]["Authorization"]
    
    @patch('post_comment.requests.post')
    def test_post_pr_comment_api_error(self, mock_post):
        """Test handling API errors."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"message": "Forbidden"}
        mock_post.return_value = mock_response
        
        result = post_pr_comment("owner/repo", 1, "Test comment", "fake_token")
        
        assert result is None
    
    @patch('post_comment.requests.post')
    def test_post_pr_comment_not_found(self, mock_post):
        """Test handling 404 errors."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"message": "Not Found"}
        mock_post.return_value = mock_response
        
        result = post_pr_comment("owner/repo", 999, "Test comment", "fake_token")
        
        assert result is None
    
    @patch('post_comment.requests.post')
    def test_post_pr_comment_server_error(self, mock_post):
        """Test handling server errors."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {"message": "Internal Server Error"}
        mock_post.return_value = mock_response
        
        result = post_pr_comment("owner/repo", 1, "Test comment", "fake_token")
        
        assert result is None
    
    @patch('post_comment.requests.post')
    def test_post_pr_comment_correct_url(self, mock_post):
        """Test correct API URL is used."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": 123}
        mock_post.return_value = mock_response
        
        post_pr_comment("owner/repo", 42, "Test comment", "fake_token")
        
        call_args = mock_post.call_args
        assert "repos/owner/repo/issues/42/comments" in call_args[0][0]
    
    @patch('post_comment.requests.post')
    def test_post_pr_comment_correct_headers(self, mock_post):
        """Test correct headers are sent."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": 123}
        mock_post.return_value = mock_response
        
        post_pr_comment("owner/repo", 1, "Test comment", "fake_token")
        
        call_args = mock_post.call_args
        headers = call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer fake_token"
        assert headers["Accept"] == "application/vnd.github+json"
    
    @patch('post_comment.requests.post')
    def test_post_pr_comment_correct_body(self, mock_post):
        """Test correct request body is sent."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": 123}
        mock_post.return_value = mock_response
        
        comment_body = "Test comment body"
        post_pr_comment("owner/repo", 1, comment_body, "fake_token")
        
        call_args = mock_post.call_args
        assert call_args[1]["json"]["body"] == comment_body


class TestUpdateReviewedPRs:
    """Tests for update_reviewed_prs function."""
    
    def test_update_reviewed_prs_basic(self):
        """Test basic update of reviewed PRs tracker."""
        reviewed_prs = {}
        update_reviewed_prs(reviewed_prs, "owner/repo", 123, "abc123", "Review text")
        
        key = "owner/repo#123"
        assert key in reviewed_prs
        assert reviewed_prs[key]["status"] == "reviewed"
        assert reviewed_prs[key]["last_reviewed_sha"] == "abc123"
        assert reviewed_prs[key]["last_review_text"] == "Review text"
        assert "reviewed_at" in reviewed_prs[key]
    
    def test_update_reviewed_prs_without_review_text(self):
        """Test update without review text."""
        reviewed_prs = {}
        update_reviewed_prs(reviewed_prs, "owner/repo", 123, "abc123")
        
        key = "owner/repo#123"
        assert key in reviewed_prs
        assert "last_review_text" not in reviewed_prs[key]
    
    def test_update_reviewed_prs_overwrites_existing(self):
        """Test update overwrites existing entry."""
        reviewed_prs = {
            "owner/repo#123": {
                "status": "reviewed",
                "last_reviewed_sha": "old123",
                "reviewed_at": "2024-01-01T00:00:00Z"
            }
        }
        update_reviewed_prs(reviewed_prs, "owner/repo", 123, "new456", "New review")
        
        assert reviewed_prs["owner/repo#123"]["last_reviewed_sha"] == "new456"
        assert reviewed_prs["owner/repo#123"]["last_review_text"] == "New review"
    
    def test_update_reviewed_prs_timestamp_format(self):
        """Test timestamp is in correct format."""
        reviewed_prs = {}
        update_reviewed_prs(reviewed_prs, "owner/repo", 123, "abc123")
        
        timestamp = reviewed_prs["owner/repo#123"]["reviewed_at"]
        # Should be ISO format
        assert "T" in timestamp
        assert "Z" in timestamp or "+" in timestamp

