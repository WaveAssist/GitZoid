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
    create_single_review_comment,
    create_summary_comment,
    edit_summary_comment,
    find_summary_comment_id,
    process_one_pr,
    run_driver,
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

    def test_token_must_be_read_run_based(self):
        # Regression for the prod bug: the token is WRITTEN run-based by check_credits_and_init,
        # so it must be READ run-based here. Reading it globally returns a non-existent key and
        # the lock is never released (only the TTL frees it). This pins run_based=True.
        wa = self._wa({"run_lock_token": "T1", "run_lock": {"at": "now", "token": "T1"}})
        with patch.object(post_comment, "waveassist", wa):
            release_run_lock()
        token_reads = [c for c in wa.fetch_data.call_args_list
                       if c.args and c.args[0] == "run_lock_token"]
        assert token_reads, "release_run_lock must read run_lock_token"
        assert token_reads[0].kwargs.get("run_based") is True, \
            "run_lock_token must be read run_based=True to match the run-based write"


class TestReleaseRunLockRunBasedScoping:
    """Faithful model of run-based scoping: the real backend suffixes run-based keys by run_id
    (global reads of a run-based key miss). A flat mock hid the original prod bug; this models the
    real isolation and proves the holder releases while a concurrent skipped cycle cannot."""

    def _wa_scoped(self, store, run_id):
        wa = Mock()

        def fetch(key=None, run_based=False, default=None, **k):
            real_key = f"{key}_{run_id}" if run_based else key
            return store.get(real_key, default)

        def put(key=None, data=None, run_based=False, **k):
            real_key = f"{key}_{run_id}" if run_based else key
            store[real_key] = data
            return True

        wa.fetch_data.side_effect = fetch
        wa.store_data.side_effect = put
        return wa

    def test_holder_releases_but_skipper_cannot_free_holders_lock(self):
        # Run A acquired: global lock + run-based token, exactly as check_credits_and_init writes.
        store = {"run_lock": {"at": "now", "token": "TA"}, "run_lock_token_A": "TA"}

        # Run B is a lock-skip — it never wrote run_lock_token_B. Its post_comment must NOT release.
        wa_b = self._wa_scoped(store, "B")
        with patch.object(post_comment, "waveassist", wa_b):
            release_run_lock()
        assert store["run_lock"] == {"at": "now", "token": "TA"}, "skipper freed the holder's lock"

        # Run A (the holder) releases its own lock.
        wa_a = self._wa_scoped(store, "A")
        with patch.object(post_comment, "waveassist", wa_a):
            release_run_lock()
        assert store["run_lock"] == {}, "holder failed to release its own lock"


# ---------------------------------------------------------------- robustness (issue #6)

class TestFindingsToInlineFalsyPath:
    """An inline comment with a falsy path makes GitHub 422 the WHOLE batch — drop it instead."""

    def test_falsy_path_dropped(self):
        assert findings_to_inline_comments([_F(path="")]) == []
        assert findings_to_inline_comments([_F(path=None)]) == []

    def test_normal_finding_still_emitted(self):
        assert len(findings_to_inline_comments([_F()])) == 1   # regression guard


class TestNoneSafeRendering:
    """A None/scalar field from the ledger or a null-filled LLM result must never crash the summary."""

    def test_none_body_and_path_do_not_crash(self):
        ledger = {"s1": {"path": None, "line": None, "body": None, "category": "bug",
                         "severity": "high", "status": "open"}}
        md = build_summary_md({"verdict": "minor_comments", "summary": "a single string summary"},
                              ledger, [], "abc1234")
        assert isinstance(md, str)
        assert "None" not in md                              # no literal "None" leaked
        assert "a single string summary" in md               # string summary -> one bullet, not per-char

    def test_summary_list_with_none_and_scalar(self):
        md = build_summary_md({"summary": ["ok", None, 5]}, {}, [], "abc1234")
        assert "- ok" in md
        assert "- 5" in md                                   # scalar coerced to str
        assert "None" not in md


class TestInline422Fallback:
    """A single bad line-anchor must not lose the whole inline review — fall back per-comment."""

    @patch('post_comment.requests.post')
    def test_falls_back_to_per_comment(self, mock_post):
        def router(url, *a, **k):
            return _resp(422) if url.endswith("/reviews") else _resp(201, {"id": 1})
        mock_post.side_effect = router
        c1 = {"path": "a.py", "line": 5, "side": "RIGHT", "body": "x"}
        c2 = {"path": "b.py", "line": 9, "side": "RIGHT", "body": "y"}
        out = create_pr_review("o/r", 1, "sha", "", [c1, c2], "tok")
        assert out is not None                               # at least one comment posted
        assert mock_post.call_count == 3                     # 1 batch + 2 per-comment

    @patch('post_comment.requests.post')
    def test_skips_only_the_bad_comment(self, mock_post):
        seq = {"n": 0}
        def router(url, *a, **k):
            if url.endswith("/reviews"):
                return _resp(422)
            seq["n"] += 1
            return _resp(201, {"id": 1}) if seq["n"] == 1 else _resp(422)
        mock_post.side_effect = router
        c1 = {"path": "a.py", "line": 5, "side": "RIGHT", "body": "x"}
        c2 = {"path": "b.py", "line": 9, "side": "RIGHT", "body": "y"}
        out = create_pr_review("o/r", 1, "sha", "", [c1, c2], "tok")
        assert out is not None                               # one still posted, the bad one skipped
        assert mock_post.call_count == 3

    @patch('post_comment.requests.post')
    def test_non_422_failure_still_returns_none(self, mock_post):
        mock_post.return_value = _resp(500)
        out = create_pr_review("o/r", 1, "sha", "", [{"path": "a.py", "line": 5, "body": "x"}], "tok")
        assert out is None
        assert mock_post.call_count == 1                     # no per-comment fallback on non-422


class TestDriverRobustness:
    """One bad PR must not sink the rest, and the run-lock must be released even on a crash."""

    def _wa(self, prs, preview=False, raise_on=None):
        store = {}
        data = {"pull_requests": prs, "github_access_token": "tok", "reviewed_prs": {},
                "run_lock_token": "T1", "run_lock": {"token": "T1"}}
        wa = Mock()
        wa.fetch_data.side_effect = lambda key=None, default=None, run_based=False, **k: data.get(key, default)
        wa.is_test_run.return_value = preview

        def store_data(*a, **k):
            key = a[0] if a else k.get("key")
            val = a[1] if len(a) > 1 else k.get("data")
            store[key] = val
            if raise_on and key == raise_on:
                raise RuntimeError(f"store boom on {key}")
            return True
        wa.store_data.side_effect = store_data
        return wa, store

    def test_post_loop_isolates_bad_pr(self):
        prs = [{"id": "o/bad", "pr_number": 1, "comment_generated": True, "review_dict": {"findings": []}},
               {"id": "o/good", "pr_number": 2, "comment_generated": True, "review_dict": {"findings": []}}]
        wa, store = self._wa(prs, preview=False)

        def fake_process(pr, *a, **k):
            if pr["id"] == "o/bad":
                raise RuntimeError("boom in one PR")
            pr["comment_posted"] = True
            return True, "http://good", "<block>"

        with patch.object(post_comment, "waveassist", wa), \
             patch.object(post_comment, "process_one_pr", side_effect=fake_process):
            run_driver()

        assert prs[1].get("comment_posted") is True          # good PR processed despite the bad one
        assert store.get("run_lock") == {}                   # lock released in finally

    def test_lock_released_even_when_cleanup_raises(self):
        prs = [{"id": "o/x", "pr_number": 1, "comment_generated": True, "review_dict": {"findings": []}}]
        wa, store = self._wa(prs, preview=False, raise_on="display_output")

        def fake_process(pr, *a, **k):
            pr["comment_posted"] = True
            return True, "http://x", "<b>"

        with patch.object(post_comment, "waveassist", wa), \
             patch.object(post_comment, "process_one_pr", side_effect=fake_process), \
             pytest.raises(RuntimeError):
            run_driver()                                     # cleanup store raises...

        assert store.get("run_lock") == {}                   # ...but the lock was still released


class TestProcessOnePrPartialPost:
    """Review P2: if inline comments posted but the summary failed, record the ledger anyway so the
    already-posted inline comments are NOT re-posted as 'new' on the next run (no duplicates)."""

    def test_inline_posted_summary_failed_still_records_ledger(self):
        pr = {"id": "o/r", "pr_number": 1, "comment_generated": True, "current_sha": "sha",
              "review_dict": {"verdict": "needs_changes", "findings": [_F()]}}
        reviewed = {}
        with patch.object(post_comment, "find_summary_comment_id", return_value=None), \
             patch.object(post_comment, "create_pr_review", return_value={"id": 99}), \
             patch.object(post_comment, "create_summary_comment", return_value=None):  # summary FAILS
            changed, url, block = process_one_pr(pr, reviewed, "tok", preview=False)
        assert changed is True                          # ledger recorded despite the summary failure
        assert reviewed.get("o/r#1", {}).get("findings")  # findings persisted -> no re-post next run
        assert pr.get("comment_posted") is not True     # not fully done; summary retried next cycle
