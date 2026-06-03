"""
Unit tests for generate_review.py
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from generate_review import (
    format_changed_files,
    get_full_review_prompt,
    get_incremental_review_prompt,
    Finding,
    ReviewResult,
    build_diff_lines,
    _sanitize_findings,
    finding_sig,
    apply_gate,
    security_sweep,
    _format_brain_profile,
    brain_auth_files,
    brain_secret_locations,
)


class TestFormatChangedFiles:
    def test_within_limit(self, sample_pr_files):
        result = format_changed_files(sample_pr_files, max_chars=50000)
        assert "test.py" in result
        assert "new_file.py" in result
        assert "[added]" in result
        assert "```" in result

    def test_truncates(self):
        files = [{"filename": "large.py", "patch": "x" * 50000, "status": "modified",
                  "additions": 100, "deletions": 50}]
        result = format_changed_files(files, max_chars=1000)
        assert len(result) <= 1300
        assert "truncated" in result.lower()

    def test_empty_list(self):
        assert format_changed_files([], max_chars=10000) == "No files changed."

    def test_none_input(self):
        assert format_changed_files(None, max_chars=10000) == "No files changed."

    def test_no_patch(self):
        files = [{"filename": "binary.bin", "status": "modified", "additions": 0, "deletions": 0}]
        result = format_changed_files(files, max_chars=10000)
        assert "binary.bin" in result
        assert "No diff available" in result

    def test_status_badges(self):
        files = [
            {"filename": "new.py", "patch": "diff", "status": "added", "additions": 5, "deletions": 0},
            {"filename": "deleted.py", "patch": "diff", "status": "removed", "additions": 0, "deletions": 3},
            {"filename": "modified.py", "patch": "diff", "status": "modified", "additions": 1, "deletions": 1},
        ]
        result = format_changed_files(files, max_chars=10000)
        assert "[added]" in result
        assert "[removed]" in result
        assert "[modified]" not in result

    def test_invalid_max_chars(self):
        files = [{"filename": "test.py", "patch": "diff", "status": "modified", "additions": 0, "deletions": 0}]
        result = format_changed_files(files, max_chars="invalid")
        assert "test.py" in result


class TestFullReviewPrompt:
    def test_includes_metadata_and_files(self, sample_pr_files):
        pr = {"pr_number": 123, "title": "Test PR", "body": "Description", "files": sample_pr_files}
        prompt = get_full_review_prompt(pr)
        assert "123" in prompt
        assert "Test PR" in prompt
        assert "Description" in prompt
        assert "test.py" in prompt
        assert 'pr_review type="full"' in prompt
        assert "senior code reviewer" in prompt

    def test_includes_brain_profile(self):
        pr = {"pr_number": 1, "title": "t", "body": "b", "files": [],
              "brain_profile": {"architecture_summary": "A Flask API.",
                                "conventions": ["use snake_case"],
                                "security": {"routes": [{"route": "POST /login", "unauthenticated": True}],
                                             "secret_locations": [".env"]}}}
        prompt = get_full_review_prompt(pr)
        assert "repo_profile" in prompt
        assert "use snake_case" in prompt
        assert "A Flask API." in prompt

    def test_no_brain_profile_when_absent(self):
        pr = {"pr_number": 1, "title": "t", "body": "b", "files": []}
        prompt = get_full_review_prompt(pr)
        assert "repo_profile" not in prompt

    def test_context_included_and_excluded(self):
        pr = {"pr_number": 1, "title": "t", "body": "b", "files": []}
        assert "Custom guidance" in get_full_review_prompt(pr, additional_context="Custom guidance")
        assert "additional_context" not in get_full_review_prompt(pr, additional_context="")
        assert "additional_context" not in get_full_review_prompt(pr, additional_context=None)


class TestIncrementalReviewPrompt:
    def test_includes_sha_and_previous(self):
        pr = {"pr_number": 1, "title": "t", "body": "b", "files": [],
              "previous_sha": "abc123def", "current_sha": "def456ghi"}
        prompt = get_incremental_review_prompt(pr, previous_review="Prior review text")
        assert "abc123d" in prompt
        assert "def456g" in prompt
        assert "incremental" in prompt
        assert "Prior review text" in prompt
        assert "previous_review" in prompt
        assert "re-raise" in prompt.lower()

    def test_excludes_missing_previous(self):
        pr = {"pr_number": 1, "title": "t", "body": "b", "files": [],
              "previous_sha": "a", "current_sha": "b"}
        prompt = get_incremental_review_prompt(pr, previous_review=None)
        assert "previous_review" not in prompt


class TestFindingModel:
    def test_minimal_defaults(self):
        f = Finding(severity="high", confidence="high", category="bug", body="x")
        assert f.path == ""
        assert f.line is None
        assert f.side == "RIGHT"
        assert f.suggested_replacement is None


class TestBuildDiffLines:
    def test_added_removed_context(self):
        patch = "@@ -1,2 +1,3 @@\n context line\n-removed line\n+added line\n+another added"
        files = [{"filename": "a.py", "patch": patch}]
        dl = build_diff_lines(files)
        assert ("a.py", "RIGHT", 1) in dl   # context
        assert ("a.py", "LEFT", 2) in dl    # removed
        assert ("a.py", "RIGHT", 2) in dl   # first added
        assert ("a.py", "RIGHT", 3) in dl   # second added


class TestSanitizeFindings:
    def test_nullfilled_repaired(self):
        out = _sanitize_findings([{"severity": None, "confidence": None, "category": None,
                                   "side": None, "path": None, "line": "x", "body": None}])
        f = out[0]
        assert f["severity"] == "medium"
        assert f["confidence"] == "low"
        assert f["category"] == "bug"
        assert f["side"] == "RIGHT"
        assert f["path"] == ""
        assert f["line"] is None
        assert f["body"] == ""


def _F(path="a.py", line=1, side="RIGHT", severity="high", confidence="high", category="bug", body="issue"):
    return {"path": path, "line": line, "side": side, "severity": severity,
            "confidence": confidence, "category": category, "body": body}


class TestApplyGate:
    DL = {("a.py", "RIGHT", 1), ("a.py", "RIGHT", 2)}

    def test_keeps_high_bug_anchored_and_blocks(self):
        kept, verdict, _ = apply_gate([_F()], self.DL)
        assert len(kept) == 1
        assert verdict == "needs_changes"

    def test_high_severity_blocks_even_at_medium_confidence(self):
        kept, verdict, _ = apply_gate([_F(severity="high", confidence="medium")], self.DL)
        assert len(kept) == 1
        assert verdict == "needs_changes"

    def test_medium_high_conf_is_minor_not_blocking(self):
        kept, verdict, _ = apply_gate([_F(severity="medium", confidence="high")], self.DL,
                                      severity_threshold="medium")
        assert len(kept) == 1
        assert verdict == "minor_comments"

    def test_drops_low_confidence_medium_bug(self):
        kept, verdict, _ = apply_gate([_F(severity="medium", confidence="low")], self.DL)
        assert kept == []
        assert verdict == "looks_good"

    def test_keeps_medium_high_conf_bug(self):
        kept, _, _ = apply_gate([_F(severity="medium", confidence="high")], self.DL, severity_threshold="medium")
        assert len(kept) == 1

    def test_drops_anchored_line_not_in_diff(self):
        kept, _, _ = apply_gate([_F(line=99)], self.DL)
        assert kept == []

    def test_keeps_unanchored_summary_only(self):
        kept, _, _ = apply_gate([_F(line=None)], self.DL)
        assert len(kept) == 1

    def test_dedup_identical(self):
        kept, _, _ = apply_gate([_F(), _F()], self.DL)
        assert len(kept) == 1

    def test_severity_threshold_drops_medium_when_high(self):
        # medium bug + high conf passes precision, but threshold 'high' drops it (rank 1 > 0)
        kept, _, _ = apply_gate([_F(severity="medium", confidence="high")], self.DL, severity_threshold="high")
        assert kept == []

    def test_optimization_exempt_from_precision_gate(self):
        kept, _, _ = apply_gate([_F(category="optimization", severity="low", confidence="low")], self.DL)
        assert len(kept) == 1

    def test_security_sorted_first(self):
        findings = [_F(category="bug", line=1), _F(category="security", line=2, body="secret")]
        kept, _, _ = apply_gate(findings, self.DL)
        assert kept[0]["category"] == "security"


class TestSecuritySweep:
    def test_detects_live_secret(self):
        files = [{"filename": "app/config.py",
                  "patch": '@@ -0,0 +1,1 @@\n+AWS_KEY = "AKIA1234567890ABCDEF"'}]
        out = security_sweep(files, {})
        assert any(f["category"] == "security" and f["severity"] == "high" for f in out)

    def test_skips_placeholder_secret(self):
        files = [{"filename": "app/config.py",
                  "patch": '@@ -0,0 +1,1 @@\n+API_KEY = "your-api-key-here-xxxx"'}]
        assert security_sweep(files, {}) == []

    def test_skips_known_secret_location(self):
        files = [{"filename": ".env.example",
                  "patch": '@@ -0,0 +1,1 @@\n+AWS_KEY = "AKIA1234567890ABCDEF"'}]
        out = security_sweep(files, {"security": {"secret_locations": [".env.example"]}})
        assert out == []

    def test_detects_sql_injection(self):
        files = [{"filename": "db.py",
                  "patch": '@@ -0,0 +1,1 @@\n+cursor.execute("SELECT * FROM u WHERE id = " + user_id)'}]
        out = security_sweep(files, {})
        assert any("injection" in (f.get("title", "") + f["body"]).lower() or f["category"] == "security"
                   for f in out)

    def test_auth_file_tripwire(self):
        profile = {"key_files": [{"path": "app/auth.py", "role": "JWT signing and verification"}]}
        files = [{"filename": "app/auth.py", "patch": "@@ -1 +1 @@\n+x = 1"}]
        out = security_sweep(files, profile)
        assert any(f["category"] == "security" and "auth" in f["body"].lower() and f["line"] is None
                   for f in out)


class TestBrainAdapters:
    def test_brain_secret_locations(self):
        assert brain_secret_locations({"security": {"secret_locations": [".env"]}}) == [".env"]
        assert brain_secret_locations({}) == []

    def test_brain_auth_files(self):
        prof = {"key_files": [{"path": "app/auth.py", "role": "login"},
                              {"path": "app/utils.py", "role": "helpers"},
                              {"path": "app/models.py", "role": "session storage"}]}
        out = brain_auth_files(prof)
        assert "app/auth.py" in out          # path mentions auth
        assert "app/models.py" in out        # role mentions session
        assert "app/utils.py" not in out

    def test_format_brain_profile_v2_and_empty(self):
        prof = {"architecture_summary": "Django API.", "conventions": ["snake_case"],
                "security": {"routes": [], "secret_locations": []}}
        h = _format_brain_profile(prof)
        assert "Django API." in h
        assert "snake_case" in h
        assert "repo_profile" in h
        assert _format_brain_profile({}) == ""
        assert _format_brain_profile(None) == ""
