"""
Unit tests for the review-context features added to fetch_pull_requests.py + generate_review.py:
  - review.md / CLAUDE.md / AGENTS.md fetch + front-matter control fields (skip, severity_floor,
    ignore globs, focus)
  - PR comment reading (bot-filtered, capped)
  - gitzoid-skip label + ignore-glob filtering
  - the informational prompt blocks in generate_review
"""
import os
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

import fetch_pull_requests as fpr
from fetch_pull_requests import (
    parse_review_md, _cap_text, _matches_glob, apply_ignore_globs,
    pr_has_skip_label, fetch_repo_file, fetch_review_config, fetch_pr_comments,
    build_pr_data,
)
import generate_review as gr


# ---------------------------------------------------------------- _cap_text
class TestCapText:
    def test_under_limit_unchanged(self):
        assert _cap_text("hello", 100, "x") == "hello"

    def test_over_limit_truncates_with_marker(self):
        out = _cap_text("a" * 50, 10, "review.md")
        assert out.startswith("aaaaaaaaaa")
        assert "truncated at 10 chars" in out
        assert len(out) < 50

    def test_none_is_empty(self):
        assert _cap_text(None, 10, "x") == ""


# ---------------------------------------------------------------- parse_review_md
class TestParseReviewMd:
    def test_no_frontmatter_is_all_body(self):
        control, body = parse_review_md("Just prose guidance.\nMore.")
        assert control == {}
        assert body == "Just prose guidance.\nMore."

    def test_empty(self):
        assert parse_review_md("") == ({}, "")

    def test_block_frontmatter(self):
        text = (
            "---\n"
            "skip: false\n"
            "severity_floor: medium\n"
            "ignore:\n"
            "  - docs/**\n"
            "  - '*.md'\n"
            "focus:\n"
            "  - auth changes\n"
            "---\n"
            "Body guidance here."
        )
        control, body = parse_review_md(text)
        assert control["skip"] is False
        assert control["severity_floor"] == "medium"
        assert control["ignore"] == ["docs/**", "*.md"]
        assert control["focus"] == ["auth changes"]
        assert body == "Body guidance here."

    def test_inline_list(self):
        control, body = parse_review_md("---\nignore: [docs/**, dist/**]\n---\nprose")
        assert control["ignore"] == ["docs/**", "dist/**"]
        assert body == "prose"

    def test_skip_true_variants(self):
        assert parse_review_md("---\nskip: true\n---\n")[0]["skip"] is True
        assert parse_review_md("---\nskip: yes\n---\n")[0]["skip"] is True

    def test_bad_severity_ignored(self):
        control, _ = parse_review_md("---\nseverity_floor: bogus\n---\nx")
        assert "severity_floor" not in control

    def test_unclosed_frontmatter_is_body(self):
        control, body = parse_review_md("---\nskip: true\nno closing fence")
        assert control == {}
        assert "no closing fence" in body


# ---------------------------------------------------------------- glob filtering
class TestGlobs:
    def test_matches_basename(self):
        assert _matches_glob("a/b/c.md", "*.md")

    def test_matches_full_path(self):
        assert _matches_glob("docs/readme.md", "docs/*.md")

    def test_matches_dir_prefix(self):
        assert _matches_glob("docs/x/y.txt", "docs/**")
        assert _matches_glob("docs/x/y.txt", "docs/")

    def test_no_match(self):
        assert not _matches_glob("src/app.py", "docs/**")

    def test_apply_ignore_globs_filters(self):
        files = [{"filename": "src/app.py"}, {"filename": "docs/a.md"}, {"filename": "README.md"}]
        out = apply_ignore_globs(files, ["docs/**", "*.md"])
        assert [f["filename"] for f in out] == ["src/app.py"]

    def test_apply_ignore_globs_noop_without_globs(self):
        files = [{"filename": "a.py"}]
        assert apply_ignore_globs(files, []) == files


# ---------------------------------------------------------------- skip label
class TestSkipLabel:
    def test_label_present(self):
        assert pr_has_skip_label({"labels": [{"name": "gitzoid-skip"}]})
        assert pr_has_skip_label({"labels": [{"name": "GitZoid-Skip"}]})

    def test_no_labels(self):
        assert not pr_has_skip_label({})
        assert not pr_has_skip_label({"labels": [{"name": "bug"}]})


# ---------------------------------------------------------------- fetch_repo_file
class TestFetchRepoFile:
    def test_missing_args_empty(self):
        assert fetch_repo_file("", "review.md", "tok") == ""
        assert fetch_repo_file("o/r", "review.md", "") == ""

    @patch("fetch_pull_requests.requests.get")
    def test_200_returns_text(self, mock_get):
        mock_get.return_value = Mock(status_code=200, text="hello")
        assert fetch_repo_file("o/r", "review.md", "tok") == "hello"

    @patch("fetch_pull_requests.requests.get")
    def test_404_returns_empty(self, mock_get):
        mock_get.return_value = Mock(status_code=404, text="not found")
        assert fetch_repo_file("o/r", "review.md", "tok") == ""

    @patch("fetch_pull_requests.requests.get", side_effect=Exception("boom"))
    def test_exception_returns_empty(self, mock_get):
        assert fetch_repo_file("o/r", "review.md", "tok") == ""


# ---------------------------------------------------------------- fetch_review_config
class TestFetchReviewConfig:
    def test_review_md_and_conventions(self):
        def fake(repo, path, tok):
            return {
                ".gitzoid/review.md": "---\nseverity_floor: medium\nignore:\n  - docs/**\n---\nBe strict on auth.",
                "CLAUDE.md": "House rule: prefer small functions.",
            }.get(path, "")
        with patch("fetch_pull_requests.fetch_repo_file", side_effect=fake):
            cfg = fetch_review_config("o/r", "tok")
        assert cfg["source"] == ".gitzoid/review.md"
        assert cfg["severity_floor"] == "medium"
        assert cfg["ignore"] == ["docs/**"]
        assert "Be strict on auth." in cfg["instructions"]
        assert cfg["conventions_source"] == "CLAUDE.md"
        assert "small functions" in cfg["conventions"]

    def test_prefers_gitzoid_dir_then_root(self):
        def fake(repo, path, tok):
            return "root review" if path == "review.md" else ""
        with patch("fetch_pull_requests.fetch_repo_file", side_effect=fake):
            cfg = fetch_review_config("o/r", "tok")
        assert cfg["source"] == "review.md"
        assert cfg["instructions"] == "root review"

    def test_all_absent(self):
        with patch("fetch_pull_requests.fetch_repo_file", return_value=""):
            cfg = fetch_review_config("o/r", "tok")
        assert cfg == {"instructions": "", "focus": [], "conventions": "", "skip": False,
                       "severity_floor": "", "ignore": [], "source": "", "conventions_source": ""}

    def test_skip_flag(self):
        def fake(repo, path, tok):
            return "---\nskip: true\n---\n" if path == ".gitzoid/review.md" else ""
        with patch("fetch_pull_requests.fetch_repo_file", side_effect=fake):
            cfg = fetch_review_config("o/r", "tok")
        assert cfg["skip"] is True


# ---------------------------------------------------------------- fetch_pr_comments
class TestFetchPrComments:
    def _resp(self, data):
        return Mock(status_code=200, json=Mock(return_value=data))

    @patch("fetch_pull_requests.requests.get")
    def test_collects_and_filters_bots(self, mock_get):
        issue = [
            {"user": {"login": "alice"}, "body": "please fix nulls", "created_at": "2024-01-02T00:00:00Z"},
            {"user": {"login": "dependabot[bot]"}, "body": "bump dep", "created_at": "2024-01-03T00:00:00Z"},
        ]
        review = [
            {"user": {"login": "bob"}, "body": "off-by-one here", "path": "a.py", "line": 5,
             "created_at": "2024-01-01T00:00:00Z"},
        ]
        mock_get.side_effect = [self._resp(issue), self._resp(review)]
        out = fetch_pr_comments("o/r", 1, {})
        assert "@alice" in out and "please fix nulls" in out
        assert "@bob" in out and "a.py:5" in out
        assert "dependabot" not in out          # bot filtered
        # newest first
        assert out.index("@alice") < out.index("@bob")

    @patch("fetch_pull_requests.requests.get")
    def test_none_returns_empty(self, mock_get):
        mock_get.side_effect = [self._resp([]), self._resp([])]
        assert fetch_pr_comments("o/r", 1, {}) == ""

    @patch("fetch_pull_requests.requests.get", side_effect=Exception("boom"))
    def test_error_fails_open(self, mock_get):
        assert fetch_pr_comments("o/r", 1, {}) == ""


# ---------------------------------------------------------------- build_pr_data
class TestBuildPrData:
    def test_attaches_review_config_and_comments(self):
        cfg = {"instructions": "be careful", "focus": ["auth"], "conventions": "conv",
               "severity_floor": "medium"}
        data = build_pr_data({"number": 1}, [], "full", "sha", "o/r",
                             review_config=cfg, existing_comments="- @x: hi")
        assert data["review_instructions"] == "be careful"
        assert data["review_focus"] == ["auth"]
        assert data["repo_conventions"] == "conv"
        assert data["review_severity_floor"] == "medium"
        assert data["existing_comments"] == "- @x: hi"

    def test_omits_when_absent(self):
        data = build_pr_data({"number": 1}, [], "full", "sha", "o/r")
        for k in ("review_instructions", "review_focus", "repo_conventions",
                  "review_severity_floor", "existing_comments"):
            assert k not in data


# ---------------------------------------------------------------- generate_review render blocks
class TestRenderBlocks:
    def test_review_instructions_empty(self):
        assert gr._format_review_instructions("", []) == ""

    def test_review_instructions_present(self):
        out = gr._format_review_instructions("focus on nulls", ["auth", "perf"])
        assert "<repo_review_instructions" in out
        assert "focus on nulls" in out
        assert "<item>auth</item>" in out and "<item>perf</item>" in out

    def test_conventions(self):
        assert gr._format_conventions("") == ""
        assert "<repo_conventions" in gr._format_conventions("use tabs")

    def test_existing_discussion(self):
        assert gr._format_existing_discussion("") == ""
        assert "<existing_discussion" in gr._format_existing_discussion("- @x: hi")

    def test_full_prompt_includes_blocks_when_present(self):
        pr = {"pr_number": 1, "title": "t", "body": "b", "files": [],
              "review_instructions": "check auth", "review_focus": ["authz"],
              "repo_conventions": "small fns", "existing_comments": "- @x: seen this"}
        prompt = gr.get_full_review_prompt(pr)
        assert "check auth" in prompt
        assert "small fns" in prompt
        assert "seen this" in prompt
        assert "<repo_review_instructions" in prompt

    def test_full_prompt_omits_blocks_when_absent(self):
        pr = {"pr_number": 1, "title": "t", "body": "b", "files": []}
        prompt = gr.get_full_review_prompt(pr)
        # The rules text names these tags, so assert the actual note-bearing blocks are absent.
        assert "<repo_review_instructions note=" not in prompt
        assert "<repo_conventions note=" not in prompt
        assert "<existing_discussion note=" not in prompt
