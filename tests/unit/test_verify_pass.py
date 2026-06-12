"""
Unit tests for the adversarial verify pass in generate_review.py.

The verify pass re-checks each gate-kept finding against the FULL surrounding code (fetched from
GitHub), drops false positives, corrects inflated severity, and re-gates. It must FAIL OPEN — a
missing token / failed fetch / unavailable LLM keeps the finding (verification only ever removes
what it can actively refute).
"""
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

import generate_review as gr
from generate_review import (
    VerifyVerdict,
    context_window,
    fetch_file_text,
    verify_posted_findings,
)


def _F(path="a.py", line=1, side="RIGHT", severity="high", confidence="high", category="bug", body="issue"):
    return {"path": path, "line": line, "side": side, "severity": severity,
            "confidence": confidence, "category": category, "body": body}


def _verdict(is_real, sev="high", reason="r"):
    return VerifyVerdict(is_real=is_real, true_severity=sev, reason=reason)


DL = {("a.py", "RIGHT", 1), ("a.py", "RIGHT", 2)}
PR = {"id": "owner/repo", "current_sha": "abc123"}


class TestContextWindow:
    def test_whole_file_when_short(self):
        text = "\n".join(f"l{i}" for i in range(10))
        assert context_window(text, 5) == text

    def test_window_when_large(self):
        text = "\n".join(f"l{i}" for i in range(1000))
        out = context_window(text, 500).splitlines()
        assert len(out) <= 2 * gr.VERIFY_WINDOW_RADIUS + 1
        assert "l499" in out          # the finding line region is present
        assert "l0" not in out        # far-away lines are excluded

    def test_large_file_no_line_returns_head(self):
        text = "\n".join(f"l{i}" for i in range(1000))
        out = context_window(text, None).splitlines()
        assert out[0] == "l0"
        assert len(out) == gr.VERIFY_WHOLE_FILE_MAX_LINES


class TestFetchFileText:
    def test_missing_args_returns_empty(self):
        assert fetch_file_text("", "a.py", "sha", "tok") == ""
        assert fetch_file_text("o/r", "a.py", "sha", "") == ""

    def test_200_returns_text(self):
        resp = MagicMock(status_code=200, text="file body")
        with patch.object(gr.requests, "get", return_value=resp):
            assert fetch_file_text("o/r", "a.py", "sha", "tok") == "file body"

    def test_non_200_returns_empty(self):
        resp = MagicMock(status_code=404, text="nope")
        with patch.object(gr.requests, "get", return_value=resp):
            assert fetch_file_text("o/r", "a.py", "sha", "tok") == ""

    def test_exception_returns_empty(self):
        with patch.object(gr.requests, "get", side_effect=Exception("boom")):
            assert fetch_file_text("o/r", "a.py", "sha", "tok") == ""


class TestVerifyPostedFindings:
    def test_empty(self):
        assert verify_posted_findings([], PR, "tok", "m", DL) == ([], "looks_good", [])

    def test_fail_open_when_no_token(self):
        with patch.object(gr.waveassist, "call_llm") as llm:
            kept, _, dropped = verify_posted_findings([_F()], PR, "", "m", DL)
        assert len(kept) == 1 and dropped == []
        llm.assert_not_called()                       # never reaches the LLM without context

    def test_fail_open_on_fetch_failure(self):
        with patch.object(gr, "fetch_file_text", return_value=""), \
             patch.object(gr.waveassist, "call_llm") as llm:
            kept, _, dropped = verify_posted_findings([_F()], PR, "tok", "m", DL)
        assert len(kept) == 1 and dropped == []
        llm.assert_not_called()

    def test_fail_open_on_llm_unavailable(self):
        with patch.object(gr, "fetch_file_text", return_value="code"), \
             patch.object(gr.waveassist, "call_llm", return_value=None):
            kept, _, dropped = verify_posted_findings([_F()], PR, "tok", "m", DL)
        assert len(kept) == 1 and dropped == []

    def test_refuted_high_is_dropped_and_pr_unblocked(self):
        # Headline case: a false-positive high bug is refuted → dropped, PR no longer blocked.
        with patch.object(gr, "fetch_file_text", return_value="code"), \
             patch.object(gr.waveassist, "call_llm", return_value=_verdict(False)):
            kept, verdict, dropped = verify_posted_findings([_F()], PR, "tok", "m", DL)
        assert kept == []
        assert verdict == "looks_good"
        assert len(dropped) == 1

    def test_confirmed_high_kept_and_blocks(self):
        with patch.object(gr, "fetch_file_text", return_value="code"), \
             patch.object(gr.waveassist, "call_llm", return_value=_verdict(True, "high")):
            kept, verdict, dropped = verify_posted_findings([_F()], PR, "tok", "m", DL)
        assert len(kept) == 1
        assert verdict == "needs_changes"
        assert dropped == []

    def test_real_but_inflated_to_low_is_dropped_by_regate(self):
        # Real but over-rated: verify says it's actually low → re-gate drops a low bug.
        with patch.object(gr, "fetch_file_text", return_value="code"), \
             patch.object(gr.waveassist, "call_llm", return_value=_verdict(True, "low")):
            kept, verdict, _ = verify_posted_findings([_F()], PR, "tok", "m", DL)
        assert kept == []
        assert verdict == "looks_good"

    def test_real_downgraded_to_medium_kept_as_minor(self):
        with patch.object(gr, "fetch_file_text", return_value="code"), \
             patch.object(gr.waveassist, "call_llm", return_value=_verdict(True, "medium")):
            kept, verdict, _ = verify_posted_findings([_F()], PR, "tok", "m", DL, severity_threshold="medium")
        assert len(kept) == 1
        assert verdict == "minor_comments"

    def test_diff_fallback_when_full_file_unavailable(self):
        # Fetch fails, but the PR carries the file's patch → verify still runs on the diff (best-effort).
        pr = {"id": "owner/repo", "current_sha": "abc",
              "files": [{"filename": "a.py", "patch": "@@ -1 +1 @@\n+bad line"}]}
        with patch.object(gr, "fetch_file_text", return_value=""), \
             patch.object(gr.waveassist, "call_llm", return_value=_verdict(False)) as llm:
            kept, _, dropped = verify_posted_findings([_F()], pr, "tok", "m", DL)
        llm.assert_called_once()                      # ran via diff fallback, not skipped
        assert kept == [] and len(dropped) == 1

    def test_file_fetched_once_per_path(self):
        # Two findings, same file → one fetch (cache).
        with patch.object(gr, "fetch_file_text", return_value="code") as fx, \
             patch.object(gr.waveassist, "call_llm", return_value=_verdict(True, "high")):
            verify_posted_findings([_F(line=1), _F(line=2)], PR, "tok", "m", DL)
        assert fx.call_count == 1
