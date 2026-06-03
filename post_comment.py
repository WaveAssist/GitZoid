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

waveassist.init(check_credits=True)

SUMMARY_MARKER = "<!-- gitzoid:summary -->"
VERDICT_HEAD = {
    "looks_good":     "✅ **Looks good**",
    "minor_comments": "💬 **Minor comments**",
    "needs_changes":  "⚠️ **Needs changes**",
}
_CAT_ICON = {"bug": "🐛", "security": "🔒", "optimization": "🚀", "suggestion": "💡"}
_CAT_NAME = {"bug": "Bug", "security": "Security", "optimization": "Optimization", "suggestion": "Suggestion"}

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
    """Stable signature of a finding (duplicated from generate_review — nodes never import siblings)."""
    raw = f"{f.get('category', '')}|{f.get('path', '')}|{f.get('line')}|{f.get('side', 'RIGHT')}|" \
          f"{' '.join((f.get('body') or '').lower().split())[:120]}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _finding_header(f):
    """A short label so a reader instantly knows what a finding IS."""
    cat = f.get("category")
    label = f"{_CAT_ICON.get(cat, '📌')} {_CAT_NAME.get(cat, 'Note')}"
    sev = f.get("severity")
    return f"**{label}** · {sev} severity" if sev in ("high", "medium", "low") else f"**{label}**"


def _verdict_line(verdict, n_find, n_opt, n_nit):
    """Informative one-liner with counts, e.g. '⚠️ Needs changes — 1 to fix, 2 optional improvements'."""
    head = VERDICT_HEAD.get(verdict, "💬 **Reviewed**")
    bits = []
    if n_find:
        bits.append(f"{n_find} to fix")
    if n_opt:
        bits.append(f"{n_opt} optional improvement" + ("s" if n_opt != 1 else ""))
    if n_nit:
        bits.append(f"{n_nit} nit" + ("s" if n_nit != 1 else ""))
    return head + (" — " + ", ".join(bits) if bits else "")


# ---------------------------------------------------------------- GitHub REST

def create_pr_review(repo_path, pr_number, commit_id, summary_body, inline_comments, token):
    """POST one COMMENT review with inline comments. commit_id anchors the lines."""
    url = f"https://api.github.com/repos/{repo_path}/pulls/{pr_number}/reviews"
    payload = {"commit_id": commit_id, "event": "COMMENT", "body": summary_body or "", "comments": inline_comments}
    resp = requests.post(url, headers=_gh_headers(token), json=payload, timeout=30)
    if resp.status_code in (200, 201):
        return resp.json()
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
        body = _finding_header(f) + "\n\n" + f.get("body", "")
        if f.get("suggested_replacement"):
            body += f"\n\n```suggestion\n{f['suggested_replacement']}\n```"
        out.append({"path": f.get("path"), "line": f.get("line"), "side": f.get("side", "RIGHT"), "body": body})
    return out


# ---------------------------------------------------------------- summary + ledger

def _finding_row(v, struck=False):
    icon = _CAT_ICON.get(v.get("category"), "•")
    sev = v.get("severity")
    sev_md = f" _{sev}_" if sev in ("high", "medium", "low") else ""
    loc = f"`{v.get('path')}:{v.get('line')}`" if v.get("line") is not None else f"`{v.get('path')}`"
    if struck:
        return f"- {icon} ~~{loc} — {v.get('body')}~~ ✅"
    return f"- {icon}{sev_md} {loc} — {v.get('body')}"


def build_summary_md(review, findings_ledger, changed_files, sha_short):
    verdict = review.get("verdict", "minor_comments")
    open_f = [v for v in findings_ledger.values() if v.get("status") == "open"]
    fixed_f = [v for v in findings_ledger.values() if v.get("status") == "fixed"]
    opts = review.get("potential_optimizations") or []
    nits = review.get("suggestions") or []

    lines = [SUMMARY_MARKER, "", _verdict_line(verdict, len(open_f), len(opts), len(nits)), ""]
    for s in (review.get("summary") or review.get("changes_summary") or [])[:2]:
        lines.append(s)
    lines.append("")
    if open_f or fixed_f:
        lines.append(f"### Findings ({len(open_f)})")
        for v in open_f:
            lines.append(_finding_row(v))
        for v in fixed_f[:20]:
            lines.append(_finding_row(v, struck=True))
        lines.append("")
    if opts:
        lines.append(f"### 🚀 Potential Optimizations ({len(opts)})")
        lines += [f"- {o}" for o in opts]
        lines.append("")
    security = [v for v in findings_ledger.values()
                if v.get("category") == "security" and v.get("status") == "open"]
    if security:
        lines.append(f"### 🔒 Security ({len(security)})")
        lines += [_finding_row(v) for v in security]
        lines.append("")
    if nits:
        lines.append(f"<details><summary>💡 Nits &amp; suggestions ({len(nits)})</summary>\n")
        lines += [f"- {n}" for n in nits[:5]]
        lines.append("\n</details>")
        lines.append("")
    if changed_files:
        lines.append(f"<details><summary>📁 Changed files ({len(changed_files)})</summary>\n")
        lines += [f"- `{p}`" for p in changed_files[:50]]
        lines.append("\n</details>")
        lines.append("")
    lines.append(f"---\n_Reviewed at `{sha_short}` by [GitZoid](https://waveassist.io/assistants/gitzoid)._")
    return "\n".join(lines)


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


# ---------------------------------------------------------------- driver (flat, fall-through)

prs_to_review = waveassist.fetch_data("pull_requests", default=[]) or []
should_process = any(pr.get("comment_generated") and not pr.get("comment_posted") for pr in prs_to_review)

if should_process:
    access_token = waveassist.fetch_data("github_access_token", default="") or ""
    reviewed_prs = waveassist.fetch_data("reviewed_prs", default={}) or {}
    preview = waveassist.is_test_run()
    display = "<div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 16px; line-height: 1.5;\">"
    posted_links = []
    reviewed_prs_changed = False

    for pr in prs_to_review:
        if not pr.get("comment_generated") or pr.get("comment_posted"):
            continue
        review_dict = pr.get("review_dict") or {}
        if not review_dict:
            continue
        repo_path = pr.get("id")
        pr_number = pr.get("pr_number")
        current_sha = pr.get("current_sha", "")
        sha_short = current_sha[:7]
        entry = reviewed_prs.get(f"{repo_path}#{pr_number}", {})
        prior_ledger = entry.get("findings", {})
        summary_comment_id = entry.get("summary_comment_id")
        if summary_comment_id is None and not preview:   # idempotent: reuse our marked comment, never duplicate
            summary_comment_id = find_summary_comment_id(repo_path, pr_number, access_token)

        gated = review_dict.get("findings", [])
        is_update = bool(summary_comment_id)
        new_ledger, inline_comments = reconcile_ledger(prior_ledger, gated, current_sha, is_update=is_update)
        changed_files = sorted({f.get("path") for f in gated if f.get("path")})
        summary_md = build_summary_md(review_dict, new_ledger, changed_files, sha_short)

        if preview:
            display += (
                f'<div style="margin-bottom:8px;color:#b26a00;">• <strong>PREVIEW</strong> — would post to '
                f'<strong>{html.escape(str(repo_path))}</strong> PR #{pr_number} ({len(inline_comments)} inline). No write.</div>'
                f'<details><summary>Summary preview</summary><pre style="white-space:pre-wrap;font-size:12px;">'
                f'{html.escape(summary_md)}</pre></details>')
            continue

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

        if result:
            pr["comment_posted"] = True
            update_reviewed_prs(reviewed_prs, repo_path, pr_number, current_sha, review_text=summary_md,
                                summary_comment_id=cid, review_id=(review or {}).get("id"),
                                findings_ledger=new_ledger)
            reviewed_prs_changed = True
            pr["files"] = []                                  # clear patches after the ledger has anchors
            url = result.get("html_url") or f"https://github.com/{repo_path}/pull/{pr_number}"
            display += (
                f'<div style="margin-bottom: 8px; color: #28a745;">• {label} review posted to '
                f'<strong>{html.escape(str(repo_path))}</strong> PR #{pr_number}. '
                f'<a href="{html.escape(url, quote=True)}" target="_blank" rel="noopener noreferrer" '
                f'style="{OUTPUT_LINK_STYLE}">View on GitHub</a></div>')
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
