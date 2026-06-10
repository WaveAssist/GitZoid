"""
Unit tests for post_comment.py
"""
import pytest
from unittest.mock import Mock, patch
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

import post_comment
from post_comment import (
    finding_sig,
    findings_to_inline_comments,
    build_summary_md,
    rekey_ledger,
    reconcile_ledger,
    update_reviewed_prs,
    create_pr_review,
    create_summary_comment,
    edit_summary_comment,
    find_summary_comment_id,
    release_run_lock,
    SUMMARY_MARKER,
)


def _F(path="a.py", line=5, side="RIGHT", category="bug", severity="high", body="a bug"):
    return {"path": path, "line": line, "side": side, "category": category,
            "severity": severity, "body": body}


class TestFindingSig:
    def test_stable_and_distinct(self):
        assert finding_sig(_F()) == finding_sig(_F())
        assert finding_sig(_F()) != finding_sig(_F(body="different"))

    def test_position_independent(self):
        # Same issue, different line/side → same identity (survives line shifts across commits).
        assert finding_sig(_F(line=5)) == finding_sig(_F(line=99, side="LEFT"))


class TestRekeyLedger:
    def test_rekeys_stale_keys_so_findings_still_match(self):
        f = _F()
        # A ledger persisted under an OLD-format key, with the entry fields preserved.
        old = {"OLD-STALE-KEY": {**f, "status": "open", "first_seen_sha": "s0"}}
        migrated = rekey_ledger(old)
        assert "OLD-STALE-KEY" not in migrated
        assert finding_sig(f) in migrated                      # now keyed by the current sig
        # A re-review that re-finds the same issue carries it (open), not false-fixed + duplicated.
        ledger, inline = reconcile_ledger(migrated, [f], "s1", is_update=True)
        assert list(ledger.values())[0]["status"] == "open"
        assert inline == []                                    # not re-posted as new
        assert ledger[finding_sig(f)]["first_seen_sha"] == "s0"  # history preserved

    def test_empty_and_legacy_safe(self):
        assert rekey_ledger({}) == {}
        assert rekey_ledger(None) == {}


class TestFindingsToInline:
    def test_anchored_finding(self):
        out = findings_to_inline_comments([_F()])
        assert len(out) == 1
        c = out[0]
        assert c["path"] == "a.py" and c["line"] == 5 and c["side"] == "RIGHT"
        assert "🐛 Bug" in c["body"] and "high severity" in c["body"] and "a bug" in c["body"]

    def test_unanchored_skipped(self):
        assert findings_to_inline_comments([_F(line=None)]) == []

    def test_suggestion_block(self):
        f = _F()
        f["suggested_replacement"] = "x = 1"
        out = findings_to_inline_comments([f])
        assert "```suggestion\nx = 1\n```" in out[0]["body"]


class TestBuildSummaryMd:
    def test_renders_all_sections(self):
        review = {"verdict": "needs_changes", "summary": ["does X"],
                  "potential_optimizations": ["batch the calls"], "suggestions": ["rename foo"]}
        ledger = {
            "s1": {"path": "a.py", "line": 5, "body": "real bug", "category": "bug",
                   "severity": "high", "status": "open"},
            "s2": {"path": "b.py", "line": 2, "body": "old issue", "category": "bug", "status": "fixed"},
            "s3": {"path": "c.py", "line": 1, "body": "live secret", "category": "security",
                   "severity": "high", "status": "open"},
        }
        md = build_summary_md(review, ledger, ["a.py", "b.py"], "abc1234")
        assert SUMMARY_MARKER not in md      # marker is added at post time, not by the body builder
        assert "automated AI-generated review" in md            # intro line restored
        assert "Needs changes" not in md and "Minor comments" not in md   # verdict label removed
        assert "## 📝 Summary" in md and "- does X" in md       # summary as bullets
        assert "## ⚠️ Potential Issues (1)" in md               # only OPEN, non-security findings counted
        assert "_high_ `a.py:5` — real bug" in md               # severity text, no per-line emoji
        assert "🐛" not in md                                    # no per-line category emoji
        assert "✅ Resolved (1)" in md                           # fixed findings in their own dropdown (header emoji ok)
        assert "- `b.py:2` — old issue" in md                    # resolved row: clean, no emoji, no severity
        assert "~~" not in md                                    # nothing struck through anymore
        assert "## 🚀 Potential Optimizations (1)" in md
        assert "batch the calls" in md
        assert "## 🔒 Security (1)" in md and "live secret" in md
        assert "💡 Suggestions (1)" in md and "rename foo" in md
        assert "abc1234" in md

    def test_clean_pr_summary(self):
        md = build_summary_md({"verdict": "looks_good", "summary": ["small change"]}, {}, [], "deadbee")
        assert "Looks good" not in md          # no verdict label
        assert "## 📝 Summary" in md and "- small change" in md
        assert "automated AI-generated review" in md

    def test_update_resolved_without_status_line(self):
        # On a re-review the section counts convey the change; there is no separate "since last review" line.
        ledger = {
            "c1": {"path": "a.py", "line": 5, "body": "carried bug", "category": "bug",
                   "severity": "high", "status": "open", "first_seen_sha": "oldsha"},
            "f1": {"path": "b.py", "line": 2, "body": "fixed bug", "category": "bug", "status": "fixed"},
        }
        md = build_summary_md({"verdict": "needs_changes", "summary": ["does X"]}, ledger,
                              ["a.py"], "newsha1", current_sha="newsha", is_update=True)
        assert "Since the last review" not in md          # removed
        assert "## ⚠️ Potential Issues (1)" in md         # carried open issue
        assert "✅ Resolved (1)" in md                     # resolved in its dropdown
        assert "- `b.py:2` — fixed bug" in md             # clean resolved row


class TestReconcileLedger:
    def test_new_bug_open_and_inline(self):
        ledger, inline = reconcile_ledger({}, [_F()], "sha1", is_update=False)
        assert len(ledger) == 1
        assert list(ledger.values())[0]["status"] == "open"
        assert len(inline) == 1

    def test_disappeared_marked_fixed(self):
        f = _F()
        prior = {finding_sig(f): {**f, "status": "open"}}
        ledger, inline = reconcile_ledger(prior, [], "sha2", is_update=True)
        assert list(ledger.values())[0]["status"] == "fixed"
        assert inline == []

    def test_new_nit_suppressed_on_update(self):
        nit = _F(category="optimization", severity="low", body="nit")
        ledger_upd, _ = reconcile_ledger({}, [nit], "sha", is_update=True)
        assert ledger_upd == {}
        ledger_first, _ = reconcile_ledger({}, [nit], "sha", is_update=False)
        assert len(ledger_first) == 1

    def test_survivor_keeps_first_seen(self):
        f = _F()
        sig = finding_sig(f)
        prior = {sig: {**f, "status": "open", "first_seen_sha": "old"}}
        ledger, _ = reconcile_ledger(prior, [f], "newsha", is_update=True)
        assert ledger[sig]["first_seen_sha"] == "old"
        assert ledger[sig]["last_seen_sha"] == "newsha"


class TestUpdateReviewedPrs:
    def test_merges_preserving_existing(self):
        reviewed = {"o/r#1": {"status": "reviewed", "last_reviewed_sha": "old", "keepme": "yes"}}
        update_reviewed_prs(reviewed, "o/r", 1, "new", review_text="t",
                            summary_comment_id=42, findings_ledger={"s": {}})
        e = reviewed["o/r#1"]
        assert e["last_reviewed_sha"] == "new"
        assert e["summary_comment_id"] == 42
        assert e["findings"] == {"s": {}}
        assert e["keepme"] == "yes"       # merge, not replace


def _resp(status, json_data=None):
    r = Mock()
    r.status_code = status
    r.json.return_value = json_data if json_data is not None else {}
    r.text = ""
    return r


class TestRestSequences:
    @patch('post_comment.requests.post')
    def test_create_pr_review_success(self, mock_post):
        mock_post.return_value = _resp(200, {"id": 7})
        out = create_pr_review("o/r", 1, "sha", "", [{"path": "a.py", "line": 5, "body": "x"}], "tok")
        assert out == {"id": 7}
        payload = mock_post.call_args.kwargs["json"]
        assert payload["event"] == "COMMENT" and payload["commit_id"] == "sha"

    @patch('post_comment.requests.post')
    def test_create_pr_review_failure(self, mock_post):
        mock_post.return_value = _resp(422)
        assert create_pr_review("o/r", 1, "sha", "", [], "tok") is None

    @patch('post_comment.requests.post')
    def test_create_summary_has_marker(self, mock_post):
        mock_post.return_value = _resp(201, {"id": 9, "html_url": "u"})
        out = create_summary_comment("o/r", 1, "the summary", "tok")
        assert out["id"] == 9
        assert SUMMARY_MARKER in mock_post.call_args.kwargs["json"]["body"]

    @patch('post_comment.requests.patch')
    def test_edit_summary(self, mock_patch):
        mock_patch.return_value = _resp(200, {"id": 9})
        assert edit_summary_comment("o/r", 9, "updated", "tok") == {"id": 9}

    @patch('post_comment.requests.get')
    def test_find_summary_by_marker(self, mock_get):
        mock_get.return_value = _resp(200, [{"id": 1, "body": "hi"},
                                            {"id": 2, "body": SUMMARY_MARKER + "\nsummary"}])
        assert find_summary_comment_id("o/r", 1, "tok") == 2

    @patch('post_comment.requests.get')
    def test_find_summary_none(self, mock_get):
        mock_get.return_value = _resp(200, [{"id": 1, "body": "no marker"}])
        assert find_summary_comment_id("o/r", 1, "tok") is None


class TestReleaseRunLock:
    """The last node releases the single-run lock only if THIS run owns it (token match)."""

    def _wa(self, fetch_map):
        wa = Mock()
        wa.fetch_data.side_effect = lambda key=None, default=None, **k: fetch_map.get(key, default)
        wa.store_data.return_value = True
        return wa

    def test_releases_when_token_matches(self):
        wa = self._wa({"run_lock_token": "T1", "run_lock": {"at": "now", "token": "T1"}})
        with patch.object(post_comment, "waveassist", wa):
            release_run_lock()
        wa.store_data.assert_called_once_with("run_lock", {}, data_type="json")

    def test_skip_cycle_without_token_does_not_release(self):
        # A lock-skipped cycle has no run_lock_token, so it must never clear the active run's lock.
        wa = self._wa({"run_lock_token": "", "run_lock": {"at": "now", "token": "T1"}})
        with patch.object(post_comment, "waveassist", wa):
            release_run_lock()
        wa.store_data.assert_not_called()

    def test_does_not_release_another_runs_lock(self):
        wa = self._wa({"run_lock_token": "MINE", "run_lock": {"at": "now", "token": "OTHER"}})
        with patch.object(post_comment, "waveassist", wa):
            release_run_lock()
        wa.store_data.assert_not_called()
