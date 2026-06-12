"""
Unit tests for the per-PR security tripwire queue helpers added to generate_review.py.

When a PR touches an auth-flagged file, generate_review enqueues it so the weekly
deep_security_audit picks it up — closing the "queued for the weekly audit" promise the
review comment already makes.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from generate_review import (
    auth_touched_files,
    build_audit_queue_entry,
    merge_audit_queue,
)

BRAIN = {"key_files": [{"path": "src/auth/login.py", "role": "handles login"},
                       {"path": "src/utils.py", "role": "string helpers"}]}


class TestAuthTouchedFiles:
    def test_returns_only_auth_files(self):
        files = [{"filename": "src/auth/login.py"}, {"filename": "src/utils.py"}]
        assert auth_touched_files(files, BRAIN) == ["src/auth/login.py"]

    def test_matches_by_basename(self):
        files = [{"filename": "moved/login.py"}]      # same basename as an auth key file
        assert auth_touched_files(files, BRAIN) == ["moved/login.py"]

    def test_empty_when_no_auth_touch(self):
        assert auth_touched_files([{"filename": "README.md"}], BRAIN) == []

    def test_handles_missing_brain(self):
        assert auth_touched_files([{"filename": "x.py"}], {}) == []


class TestBuildEntry:
    def test_entry_when_auth_touched(self):
        files = [{"filename": "src/auth/login.py"}]
        e = build_audit_queue_entry("o/r", 42, files, "abc123", BRAIN)
        assert e["repo"] == "o/r"
        assert e["pr"] == 42
        assert e["files"] == ["src/auth/login.py"]
        assert e["sha"] == "abc123"

    def test_none_when_no_auth_touched(self):
        assert build_audit_queue_entry("o/r", 42, [{"filename": "README.md"}], "abc", BRAIN) is None


class TestMergeQueue:
    def test_appends_new(self):
        q = merge_audit_queue([], {"repo": "o/r", "pr": 1, "files": ["a.py"], "sha": "s1"})
        assert len(q) == 1

    def test_replaces_same_pr_with_latest(self):
        q = [{"repo": "o/r", "pr": 1, "files": ["a.py"], "sha": "old"}]
        q = merge_audit_queue(q, {"repo": "o/r", "pr": 1, "files": ["a.py", "b.py"], "sha": "new"})
        assert len(q) == 1
        assert q[0]["sha"] == "new"
        assert q[0]["files"] == ["a.py", "b.py"]

    def test_keeps_other_prs(self):
        q = [{"repo": "o/r", "pr": 1, "files": [], "sha": "s1"}]
        q = merge_audit_queue(q, {"repo": "o/r", "pr": 2, "files": ["a.py"], "sha": "s2"})
        assert len(q) == 2

    def test_none_entry_is_noop(self):
        assert merge_audit_queue([{"repo": "o/r", "pr": 1}], None) == [{"repo": "o/r", "pr": 1}]
