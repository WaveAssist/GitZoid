"""
post_comment.py — publish the review as a proper GitHub PR Review + an editable summary.

For each reviewed PR it posts inline, line-anchored comments (with committable suggestions) as one
COMMENT review, plus a single human-readable summary comment that is EDITED IN PLACE on later
pushes (found via a hidden marker). A per-PR findings ledger (in reviewed_prs) dedupes across runs,
marks disappeared findings as fixed, and suppresses new nits on a maturing PR. A test-run shows a
preview and writes nothing. Conventions: flat script, no __main__ guard, no sibling imports
(finding_sig is duplicated from generate_review), fall-through on empty.
"""
import html
import hashlib
import requests
import waveassist
from datetime import datetime, timezone

waveassist.init()   # credits gated once upstream in check_credits_and_init

SUMMARY_MARKER = "<!-- gitzoid:summary -->"
VERDICT_HEAD = {
    "looks_good":     "✅ **Looks good**",
    "minor_comments": "💬 **Minor comments**",
    "needs_changes":  "⚠️ **Needs changes**",
}
_CAT_ICON = {"bug": "🐛", "security": "🔒", "optimization": "🚀", "suggestion": "💡"}
_CAT_NAME = {"bug": "Bug", "security": "Security", "optimization": "Optimization", "suggestion": "Suggestion"}
INTRO = "_Here's an automated AI-generated review to support your development workflow._"
# The summary footer is our highest-volume owned surface (100K+ PR interactions). UTM-tagged so the
# clicks read as a channel in GA4/PostHog instead of arriving as untagged direct traffic. Values are
# fixed and lowercase: analytics treats UTMs as case-sensitive strings, so never vary the casing.
FOOTER_URL = ("https://gitzoid.com/?utm_source=pr-footer&utm_medium=github-comment"
              "&utm_campaign=footer-flip")

OUTPUT_LINK_STYLE = ("color: #1b5e20; font-weight: 600; text-decoration: underline; text-underline-offset: 3px;")
OUTPUT_URL_HINT_STYLE = "display: block; margin-top: 6px; font-size: 11px; color: #5a6c5d;"
OUTPUT_URL_SELECT_STYLE = (
    "display: block; margin-top: 4px; padding: 8px 10px; background: #f3faf4; "
    "border: 1px solid #a3cfbb; border-radius: 6px; font-size: 12px; line-height: 1.4; "
    "font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; "
    "color: #1e293b; user-select: all; cursor: text;")


def _gh_headers(token):
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}


def finding_sig(f):
    """Stable signature of a finding (duplicated from generate_review — nodes never import siblings).
    Position-independent: EXCLUDES line/side so a finding survives line shifts across commits.
    Identity = category + file + the normalized problem text."""
    raw = f"{f.get('category', '')}|{f.get('path', '')}|" \
          f"{' '.join((f.get('body') or '').lower().split())[:160]}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _finding_header(f):
    """A short label so a reader instantly knows what a finding IS."""
    cat = f.get("category")
    label = f"{_CAT_ICON.get(cat, '📌')} {_CAT_NAME.get(cat, 'Note')}"
    sev = f.get("severity")
    return f"**{label}** · {sev} severity" if sev in ("high", "medium", "low") else f"**{label}**"


def _verdict_line(verdict, n_find, n_opt, n_sugg):
    """Informative one-liner with counts, e.g. '⚠️ Needs changes — 1 to fix, 2 optional improvements'."""
    head = VERDICT_HEAD.get(verdict, "💬 **Reviewed**")
    bits = []
    if n_find:
        bits.append(f"{n_find} to fix")
    if n_opt:
        bits.append(f"{n_opt} optional improvement" + ("s" if n_opt != 1 else ""))
    if n_sugg:
        bits.append(f"{n_sugg} suggestion" + ("s" if n_sugg != 1 else ""))
    return head + (" — " + ", ".join(bits) if bits else "")


# ---------------------------------------------------------------- GitHub REST

def create_single_review_comment(repo_path, pr_number, commit_id, comment, token):
    """POST ONE inline review comment. Returns the json on success, None on failure. Used as the
    per-comment fallback when the atomic batch review is rejected for one bad anchor."""
    url = f"https://api.github.com/repos/{repo_path}/pulls/{pr_number}/comments"
    payload = {"commit_id": commit_id, "path": comment.get("path"), "line": comment.get("line"),
               "side": comment.get("side", "RIGHT"), "body": comment.get("body", "")}
    resp = requests.post(url, headers=_gh_headers(token), json=payload, timeout=30)
    if resp.status_code in (200, 201):
        return resp.json()
    print(f"❌ single comment failed HTTP {resp.status_code} "
          f"({comment.get('path')}:{comment.get('line')}): {resp.text[:200]}")
    return None


def create_pr_review(repo_path, pr_number, commit_id, summary_body, inline_comments, token):
    """POST one COMMENT review with inline comments. commit_id anchors the lines. On a 422 (GitHub
    rejects the WHOLE batch when any single line-anchor is stale), fall back to posting each comment
    on its own so one bad anchor only loses itself, not every inline comment."""
    url = f"https://api.github.com/repos/{repo_path}/pulls/{pr_number}/reviews"
    payload = {"commit_id": commit_id, "event": "COMMENT", "body": summary_body or "", "comments": inline_comments}
    resp = requests.post(url, headers=_gh_headers(token), json=payload, timeout=30)
    if resp.status_code in (200, 201):
        return resp.json()
    if resp.status_code == 422 and inline_comments:
        print("⚠️ atomic review rejected HTTP 422; falling back to per-comment posting.")
        posted = sum(1 for c in inline_comments
                     if create_single_review_comment(repo_path, pr_number, commit_id, c, token))
        if posted:
            return {"id": None, "_fallback": True, "_posted": posted}
        return None
    print(f"❌ create review failed HTTP {resp.status_code}: {resp.text[:300]}")
    return None


def create_summary_comment(repo_path, pr_number, summary_md, token):
    body = SUMMARY_MARKER + "\n" + summary_md
    url = f"https://api.github.com/repos/{repo_path}/issues/{pr_number}/comments"
    resp = requests.post(url, headers=_gh_headers(token), json={"body": body}, timeout=30)
    if resp.status_code in (200, 201):
        return resp.json()
    print(f"❌ create summary failed HTTP {resp.status_code}: {resp.text[:300]}")
    return None


def edit_summary_comment(repo_path, comment_id, summary_md, token):
    body = SUMMARY_MARKER + "\n" + summary_md
    url = f"https://api.github.com/repos/{repo_path}/issues/comments/{comment_id}"
    resp = requests.patch(url, headers=_gh_headers(token), json={"body": body}, timeout=30)
    if resp.status_code in (200, 201):
        return resp.json()
    print(f"❌ edit summary failed HTTP {resp.status_code}: {resp.text[:300]}")
    return None


def find_summary_comment_id(repo_path, pr_number, token):
    """Recovery path: locate our summary comment by the hidden marker."""
    resp = requests.get(f"https://api.github.com/repos/{repo_path}/issues/{pr_number}/comments",
                        headers=_gh_headers(token), params={"per_page": 100}, timeout=30)
    if resp.status_code != 200:
        return None
    for c in resp.json():
        if SUMMARY_MARKER in (c.get("body") or ""):
            return c["id"]
    return None


def findings_to_inline_comments(findings):
    out = []
    for f in (findings or []):
        if f.get("line") is None:            # unanchored → summary-only, never an inline comment
            continue
        if not f.get("path"):                # no file → cannot anchor; a falsy path 422s the whole batch
            continue
        body = _finding_header(f) + "\n\n" + (f.get("body") or "")
        if f.get("suggested_replacement"):
            body += f"\n\n```suggestion\n{f['suggested_replacement']}\n```"
        out.append({"path": f.get("path"), "line": f.get("line"), "side": f.get("side", "RIGHT"), "body": body})
    return out


# ---------------------------------------------------------------- summary + ledger

def _finding_row(v, resolved=False):
    """One clean line: no per-line emoji. Section header carries the icon; severity stays as
    text on open issues for quick triage. Resolved rows drop severity entirely."""
    path = v.get("path") or ""
    body = v.get("body") or ""
    loc = f"`{path}:{v.get('line')}`" if v.get("line") is not None else f"`{path}`"
    if resolved:
        return f"- {loc} — {body}"
    sev = v.get("severity")
    sev_md = f"_{sev}_ " if sev in ("high", "medium", "low") else ""
    return f"- {sev_md}{loc} — {body}"


def build_summary_md(review, findings_ledger, changed_files, sha_short, current_sha=None, is_update=False):
    verdict = review.get("verdict", "minor_comments")
    open_all = [v for v in findings_ledger.values() if v.get("status") == "open"]
    fixed_all = [v for v in findings_ledger.values() if v.get("status") == "fixed"]
    # Route findings to their natural section by category (not "everything non-security = issue").
    bugs = [v for v in open_all if v.get("category") == "bug"]
    sec = [v for v in open_all if v.get("category") == "security"]
    opt_f = [v for v in open_all if v.get("category") == "optimization"]
    sug_f = [v for v in open_all if v.get("category") == "suggestion"]
    free_opts = review.get("potential_optimizations") or []
    free_sugg = review.get("suggestions") or []
    summary_pts = review.get("summary") or review.get("changes_summary") or []
    # A null-filled LLM result or a legacy ledger can hand back a string/None/scalar instead of a
    # list of strings; coerce so the render never iterates characters or prints a literal "None".
    if isinstance(summary_pts, str):
        summary_pts = [summary_pts]
    summary_pts = [str(s) for s in summary_pts if s is not None] if isinstance(summary_pts, (list, tuple)) else []
    n_opt = len(opt_f) + len(free_opts)
    n_sug = len(sug_f) + len(free_sugg)

    # SUMMARY_MARKER is added at post time. No verdict label — the plain Summary leads (user feedback).
    # The section counts (Potential Issues (N), Resolved (N)) already convey what changed, so we
    # do not add a separate "since last review" line.
    lines = [INTRO, ""]
    if summary_pts:
        lines.append("## 📝 Summary")
        lines += [f"- {s}" for s in summary_pts]
        lines.append("")
    if bugs:
        lines.append(f"## ⚠️ Potential Issues ({len(bugs)})")
        lines += [_finding_row(v) for v in bugs]
        lines.append("")
    if sec:
        lines.append(f"## 🔒 Security ({len(sec)})")
        lines += [_finding_row(v) for v in sec]
        lines.append("")
    if opt_f or free_opts:
        lines.append(f"## 🚀 Potential Optimizations ({n_opt})")
        lines += [_finding_row(v) for v in opt_f]
        lines += [f"- {o}" for o in free_opts]
        lines.append("")
    if sug_f or free_sugg:
        lines.append(f"<details><summary>💡 Suggestions ({n_sug})</summary>\n")
        lines += [_finding_row(v) for v in sug_f]
        lines += [f"- {s}" for s in free_sugg[:5]]
        lines.append("\n</details>")
        lines.append("")
    # Resolved findings + addressed optimizations/suggestions live in their own collapsed section
    # (clean, not struck through inline). Addressed optimizations are a one-time "you fixed it"
    # acknowledgement reported by the incremental review (they are not ledger-tracked).
    addressed_opts = [str(o) for o in (review.get("addressed_optimizations") or []) if o]
    if fixed_all or addressed_opts:
        n_resolved = len(fixed_all) + len(addressed_opts)
        lines.append(f"<details><summary>✅ Resolved ({n_resolved})</summary>\n")
        lines += [_finding_row(v, resolved=True) for v in fixed_all[:30]]
        lines += [f"- {o}" for o in addressed_opts[:10]]
        lines.append("\n</details>")
        lines.append("")
    # No "Changed files" list: GitHub's own Files-changed tab is authoritative, each finding already
    # cites its file, and the prior list showed only files-with-findings (mislabeled). `changed_files`
    # is kept in the signature for caller compatibility.
    lines.append(f"---\n_Reviewed at `{sha_short}` by [GitZoid]({FOOTER_URL})._")
    return "\n".join(lines)


def rekey_ledger(ledger):
    """Re-key a stored findings ledger by the CURRENT finding_sig (recomputed from each entry's
    category/path/body). Makes a finding_sig format change transparent across an upgrade: entries
    keep matching the new run instead of all looking 'fixed' + re-posting as 'new'. Idempotent
    when keys are already current; a no-op for empty/legacy entries with no findings ledger."""
    out = {}
    for entry in (ledger or {}).values():
        if isinstance(entry, dict) and entry.get("body"):
            out[finding_sig(entry)] = entry
    return out


def reconcile_ledger(prior_ledger, gated_findings, current_sha, is_update):
    """Mark disappeared open findings 'fixed'; carry survivors; tag new; suppress NEW nits on update.
    Returns (new_ledger, inline_comments_for_new_only)."""
    prior = dict(prior_ledger or {})
    current_sigs = {finding_sig(f): f for f in (gated_findings or [])}
    new_ledger, new_inline = {}, []
    for sig, f in current_sigs.items():
        if is_update and sig not in prior and f.get("category") in ("suggestion", "optimization"):
            continue   # suppress brand-new nits on a maturing PR
        entry = dict(prior.get(sig, {}))
        entry.update({"path": f.get("path"), "line": f.get("line"), "side": f.get("side", "RIGHT"),
                      "category": f.get("category"), "severity": f.get("severity"),
                      "body": f.get("body"), "status": "open"})
        entry.setdefault("first_seen_sha", current_sha)
        entry["last_seen_sha"] = current_sha
        new_ledger[sig] = entry
        if sig not in prior and f.get("line") is not None and f.get("category") in ("bug", "security"):
            new_inline += findings_to_inline_comments([f])
    for sig, entry in prior.items():
        if sig not in current_sigs and entry.get("body"):
            entry = dict(entry)
            entry["status"] = "fixed"
            new_ledger[sig] = entry
    fixed = [(s, e) for s, e in new_ledger.items() if e.get("status") == "fixed"]
    if len(fixed) > 30:
        for s, _ in fixed[:-30]:
            new_ledger.pop(s, None)
    return new_ledger, new_inline


def update_reviewed_prs(reviewed_prs, repo_path, pr_number, current_sha, review_text=None,
                        summary_comment_id=None, review_id=None, findings_ledger=None):
    """MERGE into the existing reviewed_prs entry (never blindly replace)."""
    pr_key = f"{repo_path}#{pr_number}"
    entry = reviewed_prs.get(pr_key, {})
    entry["status"] = "reviewed"
    entry["last_reviewed_sha"] = current_sha
    entry["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    if review_text is not None:
        entry["last_review_text"] = review_text
    if summary_comment_id is not None:
        entry["summary_comment_id"] = summary_comment_id
    elif "summary_comment_id" not in entry:
        entry["summary_comment_id"] = None
    if review_id is not None:
        entry["review_id"] = review_id
    if findings_ledger is not None:
        entry["findings"] = findings_ledger
    reviewed_prs[pr_key] = entry


# ---------------------------------------------------------------- per-PR work (isolated)

def process_one_pr(pr, reviewed_prs, access_token, preview):
    """Post the review + summary for ONE pr. Returns (changed, posted_url, html_block). In preview
    mode it posts nothing and returns the preview block. A raise here is caught by run_driver's loop
    so one malformed PR (bad field, network blip) never sinks the rest of the batch."""
    if not pr.get("comment_generated") or pr.get("comment_posted"):
        return False, None, None
    review_dict = pr.get("review_dict") or {}
    if not review_dict:
        return False, None, None
    repo_path = pr.get("id")
    pr_number = pr.get("pr_number")
    current_sha = pr.get("current_sha", "")
    sha_short = current_sha[:7]
    entry = reviewed_prs.get(f"{repo_path}#{pr_number}", {})
    # Re-key by the current finding_sig so a signature-format change across upgrades is transparent.
    prior_ledger = rekey_ledger(entry.get("findings", {}))
    summary_comment_id = entry.get("summary_comment_id")
    if summary_comment_id is None and not preview:   # idempotent: reuse our marked comment, never duplicate
        summary_comment_id = find_summary_comment_id(repo_path, pr_number, access_token)

    gated = review_dict.get("findings", [])
    is_update = bool(summary_comment_id)
    new_ledger, inline_comments = reconcile_ledger(prior_ledger, gated, current_sha, is_update=is_update)
    changed_files = sorted({f.get("path") for f in gated if f.get("path")})
    summary_md = build_summary_md(review_dict, new_ledger, changed_files, sha_short,
                                  current_sha=current_sha, is_update=is_update)

    if preview:
        block = (
            f'<div style="margin-bottom:8px;color:#b26a00;">• <strong>PREVIEW</strong> — would post to '
            f'<strong>{html.escape(str(repo_path))}</strong> PR #{pr_number} ({len(inline_comments)} inline). No write.</div>'
            f'<details><summary>Summary preview</summary><pre style="white-space:pre-wrap;font-size:12px;">'
            f'{html.escape(summary_md)}</pre></details>')
        return False, None, block

    review = None
    if inline_comments:                                   # never POST an empty review
        review = create_pr_review(repo_path, pr_number, current_sha, "", inline_comments, access_token)
    if summary_comment_id:
        result = edit_summary_comment(repo_path, summary_comment_id, summary_md, access_token)
        cid = summary_comment_id
        label = "Updated"
    else:
        summary = create_summary_comment(repo_path, pr_number, summary_md, access_token)
        result = summary
        cid = summary.get("id") if summary else None
        label = "Full"

    if not result and not review:
        return False, None, None        # nothing posted at all → retry the whole PR next cycle (no dup)

    # Record the ledger as soon as ANYTHING posted, so already-posted inline comments are never
    # re-posted as "new" on a later run — even if the summary comment failed this run.
    update_reviewed_prs(reviewed_prs, repo_path, pr_number, current_sha, review_text=summary_md,
                        summary_comment_id=cid, review_id=(review or {}).get("id"),
                        findings_ledger=new_ledger)
    if result:
        pr["comment_posted"] = True                       # fully done only when the summary is up too
        pr["files"] = []                                  # clear patches after the ledger has anchors
    url = (result or {}).get("html_url") or f"https://github.com/{repo_path}/pull/{pr_number}"
    block = (
        f'<div style="margin-bottom: 8px; color: #28a745;">• {label} review posted to '
        f'<strong>{html.escape(str(repo_path))}</strong> PR #{pr_number}. '
        f'<a href="{html.escape(url, quote=True)}" target="_blank" rel="noopener noreferrer" '
        f'style="{OUTPUT_LINK_STYLE}">View on GitHub</a></div>')
    return True, url, block


def release_run_lock():
    """Release the single-run lock acquired by check_credits_and_init — but only if THIS run owns
    it (token match). `run_lock_token` is run-based, so it MUST be read run-based here, matching
    how check_credits_and_init writes it — only the acquiring run reads back its own token; a
    skipped/overlapping cycle never wrote one, so under its own run id it reads "" and bails out,
    and can never free the holder's lock. Called from run_driver's finally so the lock is freed even
    if the run crashes mid-way (instead of waiting out the TTL)."""
    my_token = waveassist.fetch_data("run_lock_token", run_based=True, default="") or ""
    if not my_token:
        return  # this cycle didn't acquire the lock (skip or crash) — nothing to release
    lock = waveassist.fetch_data("run_lock", default={}) or {}
    if isinstance(lock, dict) and lock.get("token") == my_token:
        waveassist.store_data("run_lock", {}, data_type="json")
        print("GitZoid: released run lock.")


# ---------------------------------------------------------------- driver (flat, fall-through)

def run_driver():
    """Post reviews for every generated-but-unposted PR. Each PR is isolated (one bad PR never sinks
    the rest), and the run-lock is released in a finally so a crash anywhere never leaks it."""
    skip_run = waveassist.fetch_data("skip_run", run_based=True, default="0") == "1"
    if skip_run:
        print("GitZoid: skip_run set; post_comment no-op (another run in progress).")
        waveassist.mark_run_idle()
        release_run_lock()   # no-op: skipped runs never write run_lock_token, so token=="" → no release
        return
    prs_to_review = waveassist.fetch_data("pull_requests", default=[]) or []
    should_process = any(pr.get("comment_generated") and not pr.get("comment_posted") for pr in prs_to_review)
    try:
        if should_process:
            access_token = waveassist.fetch_data("github_access_token", default="") or ""
            reviewed_prs = waveassist.fetch_data("reviewed_prs", default={}) or {}
            preview = waveassist.is_test_run()
            display = "<div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 16px; line-height: 1.5;\">"
            posted_links = []
            reviewed_prs_changed = False

            for pr in prs_to_review:
                try:
                    changed, url, block = process_one_pr(pr, reviewed_prs, access_token, preview)
                except Exception as e:
                    print(f"❌ post_comment: PR #{pr.get('pr_number')} ({pr.get('id')}) failed: {e}")
                    continue
                if block:
                    display += block
                if changed:
                    reviewed_prs_changed = True
                if url:
                    posted_links.append(url)

            if posted_links:
                display += (f'<div style="margin-top: 10px;"><span style="{OUTPUT_URL_HINT_STYLE}">'
                            f"If links do not open in this view, copy a URL below.</span></div>")
                for u in posted_links:
                    display += f'<span style="{OUTPUT_URL_SELECT_STYLE}">{html.escape(u)}</span>'
            display += "</div>"

            if not preview:
                if reviewed_prs_changed:
                    waveassist.store_data("reviewed_prs", reviewed_prs, data_type="json")
                waveassist.store_data("pull_requests", [], data_type="json")
            waveassist.store_data("display_output", {"html_content": display}, run_based=True, data_type="json")
            print(f"✅ post_comment done (preview={preview}, posted={len(posted_links)}).")
            if not preview and not posted_links:
                waveassist.mark_run_idle()   # nothing actually posted this cycle → idle
                                             # (preview never posts, so it is NOT idle here)
        else:
            # No generated-but-unposted PRs this cycle (no new PRs, or a skipped cycle) → idle.
            waveassist.mark_run_idle()
    finally:
        release_run_lock()


run_driver()
