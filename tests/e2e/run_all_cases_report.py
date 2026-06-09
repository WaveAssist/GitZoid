"""
Three-cases report: exercises GitZoid's review on a real repo and renders ONE GitHub-styled HTML
showing how each case looks. READ-ONLY (safe for live/prod accounts):
  - in-memory store overlay  -> nothing written to the WaveAssist project,
  - is_test_run forced True   -> post_comment never posts,
  - a HARD guard blocks any GitHub POST/PATCH/PUT/DELETE (only GETs allowed),
  - local Claude only         -> never OpenRouter.

Cases shown:
  1. First-time review   — a brand-new PR: summary comment + inline comments.
  2. Bug review          — the inline bug comment(s) from that review, zoomed in.
  3. Update (new commit) — a PR reviewed before, then a new commit lands: the SAME summary comment
                           edited in place (fixed items struck through) + any new inline.

Usage:
  uid=<UID> project_key=<PROJECT> python3 tests/e2e/run_all_cases_report.py <owner/repo>
"""
import os
import sys
import json
import subprocess

os.environ["LLM_PROVIDER"] = "claude_cli"
os.environ.setdefault("CLAUDE_CLI_MODEL", "claude-sonnet-4-6")
if not os.environ.get("uid") or not os.environ.get("project_key"):
    sys.exit("ERROR: set uid and project_key in the environment.")
_pos = [a for a in sys.argv[1:] if not a.startswith("--")]
TARGET = _pos[0] if _pos else "WaveAssist/GitZoid"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
OUT_HTML = os.environ.get("REPORT_HTML",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../Business/context/GITZOID_THREE_CASES_REPORT.html")))

# --- HARD SAFETY: block every GitHub write verb ---
import requests as _rq  # noqa: E402


def _guard(method):
    orig = getattr(_rq, method)

    def f(url, *a, **k):
        if "api.github.com" in str(url):
            raise RuntimeError(f"SAFETY: blocked GitHub {method.upper()} {url} (read-only run)")
        return orig(url, *a, **k)
    return f


for _m in ("post", "patch", "put", "delete"):
    setattr(_rq, _m, _guard(_m))

import waveassist  # noqa: E402
from waveassist.utils import create_json_prompt as _cjp, parse_json_response as _pjr  # noqa: E402
waveassist.init()


def _local_call_llm(model, prompt, response_model, **k):
    jp = _cjp(prompt, response_model)
    m = os.environ.get("CLAUDE_CLI_MODEL", "claude-sonnet-4-6")
    cmd = ["claude", "-p", jp, "--output-format", "json", "--model", m,
           "--max-turns", "1", "--tools", "", "--strict-mcp-config"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"local claude rc={r.returncode}: {(r.stderr or r.stdout)[:400]}")
    return _pjr(json.loads(r.stdout).get("result", ""), response_model, model)


_store = {}
_real_fetch = waveassist.fetch_data


def _fetch(key=None, default=None, **k):
    return _store[key] if key in _store else _real_fetch(key, default=default, **k)


def _store_data(key, value, **k):
    _store[key] = value
    return True


waveassist.call_llm = _local_call_llm
waveassist.fetch_data = _fetch
waveassist.store_data = _store_data
waveassist.is_test_run = lambda: True

token = _real_fetch("github_access_token", default="") or ""
H = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
print(f"[report] {TARGET}  (READ-ONLY: no posts, no project writes)\n")

# --- 1. Brain ---
_store["github_selected_resources"] = [{"id": TARGET, "properties": {}}]
_store["reviewed_prs"] = {}
import study_repos  # noqa: E402,F401   (driver builds profile:TARGET into the overlay)
profile = _store.get(f"profile:{TARGET}", {})
print(f"[1] brain built — branch {profile.get('_fingerprint', {}).get('branch')}\n")

# --- neutralise node drivers so we can call their helpers directly ---
_store["github_selected_resources"] = []
_store["pull_requests"] = []
import fetch_pull_requests as fpr  # noqa: E402
import generate_review as gr       # noqa: E402
import post_comment as pc          # noqa: E402


def _gate(files, raw_findings):
    diff_lines = gr.build_diff_lines(files)
    raw = (raw_findings or []) + gr.security_sweep(files, profile)
    kept, verdict, _ = gr.apply_gate(raw, diff_lines, seen_sigs=set(), severity_threshold="high")
    return kept, verdict


class SessionLimit(Exception):
    """Raised when local Claude reports a 429/session limit — stop calling, write what we have."""


def _safe_call(prompt, response_model):
    """Call local Claude; return the model or None. Re-raise SessionLimit so the caller can stop early."""
    try:
        return waveassist.call_llm(model=gr.DEFAULT_MODEL, prompt=prompt, response_model=response_model)
    except RuntimeError as e:
        msg = str(e)
        if "429" in msg or "session limit" in msg.lower():
            raise SessionLimit(msg)
        print(f"    ⚠️ review call failed: {msg[:140]}")
        return None


def review_full(pr, files):
    review_pr = {"pr_number": pr["number"], "title": pr.get("title"), "body": pr.get("body"),
                 "files": files, "brain_profile": profile}
    result = _safe_call(gr.get_full_review_prompt(review_pr), gr.ReviewResult)
    if not result:
        return None
    rd = result.model_dump()
    rd["findings"], rd["verdict"] = _gate(files, rd.get("findings"))
    return rd


def review_incremental(pr, new_files, previous_review_text, prev_sha, cur_sha):
    review_pr = {"pr_number": pr["number"], "title": pr.get("title"), "body": pr.get("body"),
                 "files": new_files, "brain_profile": profile,
                 "previous_sha": prev_sha, "current_sha": cur_sha}
    result = _safe_call(gr.get_incremental_review_prompt(review_pr, previous_review=previous_review_text),
                        gr.IncrementalReviewResult)
    if not result:
        return None
    rd = result.model_dump()
    rd["findings"], rd["verdict"] = _gate(new_files, rd.get("findings"))
    return rd


def render_summary_and_inline(rd, files, head_sha, prior_ledger=None, is_update=False):
    gated = rd.get("findings", [])
    ledger, new_inline = pc.reconcile_ledger(prior_ledger or {}, gated, head_sha, is_update=is_update)
    changed = sorted({f.get("path") for f in gated if f.get("path")})
    summary_md = pc.build_summary_md(rd, ledger, changed, head_sha[:7])
    return summary_md, new_inline, ledger


# --- pick PRs (env overrides FIRST_PR / UPDATE_PR target known-good PRs and save LLM calls) ---
resp = _rq.get(f"https://api.github.com/repos/{TARGET}/pulls", headers=H,
               params={"state": "open", "sort": "created", "direction": "desc", "per_page": 50}, timeout=30)
open_prs = [p for p in (resp.json() if resp.status_code == 200 else [])
            if not fpr.is_bot_pr(p) and not fpr.is_draft_pr(p)]
if not open_prs:
    sys.exit("ERROR: no reviewable open PRs on this repo.")
by_num = {p["number"]: p for p in open_prs}
FIRST_PR = os.environ.get("FIRST_PR")
UPDATE_PR = os.environ.get("UPDATE_PR")


def commits_of(n):
    r = _rq.get(f"https://api.github.com/repos/{TARGET}/pulls/{n}/commits", headers=H,
                params={"per_page": 100}, timeout=30)
    return r.json() if r.status_code == 200 else []


# Case 3 (update) PR: explicit UPDATE_PR, else first with >= 2 commits.
update_pr, update_commits = None, None
if UPDATE_PR and int(UPDATE_PR) in by_num:
    cs = commits_of(int(UPDATE_PR))
    if len(cs) >= 2:
        update_pr, update_commits = by_num[int(UPDATE_PR)], cs
if not update_pr:
    for p in open_prs:
        cs = commits_of(p["number"])
        if len(cs) >= 2:
            update_pr, update_commits = p, cs
            break

# Case 1/2 PR: explicit FIRST_PR, else first PR that is NOT the update PR.
if FIRST_PR and int(FIRST_PR) in by_num:
    first_pr = by_num[int(FIRST_PR)]
else:
    first_pr = next((p for p in open_prs if not update_pr or p["number"] != update_pr["number"]), open_prs[0])

records = {"repo": TARGET, "cases": []}
note = None


def write_report():
    DATA = json.dumps(records, default=str)
    with open(OUT_HTML, "w") as fh:
        fh.write(HTML_TEMPLATE.replace("__DATA__", DATA).replace("__NOTE__", note or ""))
    print(f"\n[report] wrote {OUT_HTML} — {len(records['cases'])} case-block(s). READ-ONLY, nothing posted.")


try:
    # ===== Case 1 (first-time) + Case 2 (bug zoom) =====
    print(f"[2] case 1 — first-time review of PR #{first_pr['number']}")
    f_files = fpr.fetch_pr_files(TARGET, first_pr["number"], H)
    f_head = first_pr.get("head", {}).get("sha", "")
    rd1 = review_full(first_pr, f_files)
    if rd1:
        summary1, inline1, _ = render_summary_and_inline(rd1, f_files, f_head)
        records["cases"].append({
            "case": "first_time", "pr": first_pr["number"], "title": first_pr.get("title"),
            "verdict": rd1.get("verdict"), "summary_md": summary1, "inline": inline1, "sha": f_head})
        bug_inline = [c for c in inline1 if "🐛 Bug" in c.get("body", "")]
        records["cases"].append({
            "case": "bug_review", "pr": first_pr["number"], "title": first_pr.get("title"),
            "inline": bug_inline or inline1[:1]})
        print(f"    verdict={rd1.get('verdict')}  inline={len(inline1)}  bug_inline={len(bug_inline)}")

    # ===== Case 3 (update / new commit) =====
    if update_pr:
        print(f"\n[3] case 3 — update review of PR #{update_pr['number']} (>=2 commits)")
        u_head = update_pr.get("head", {}).get("sha", "")
        old_sha = update_commits[-2]["sha"]            # pretend we last reviewed here
        u_files = fpr.fetch_pr_files(TARGET, update_pr["number"], H)
        rd_prior = review_full(update_pr, u_files)
        if rd_prior:
            summary_before, _, prior_ledger = render_summary_and_inline(rd_prior, u_files, old_sha)
            new_files = fpr.fetch_compare_diff(TARGET, old_sha, u_head, H)   # just the newest commit
            rd_incr = review_incremental(update_pr, new_files, summary_before, old_sha, u_head)
            if rd_incr:
                summary_after, new_inline, _ = render_summary_and_inline(
                    rd_incr, new_files, u_head, prior_ledger=prior_ledger, is_update=True)
                records["cases"].append({
                    "case": "update", "pr": update_pr["number"], "title": update_pr.get("title"),
                    "old_sha": old_sha, "new_sha": u_head,
                    "summary_before": summary_before, "summary_after": summary_after,
                    "new_inline": new_inline})
                print(f"    old={old_sha[:7]} new={u_head[:7]}  new_inline={len(new_inline)}")
    else:
        print("\n[3] case 3 — skipped (no open PR with >=2 commits found)")
except SessionLimit as e:
    note = "⚠️ Partial report — local Claude hit its session limit mid-run, so not every case was generated. Re-run after the session resets to fill in the rest."
    print(f"\n⚠️ session limit hit: {str(e)[:120]} — writing partial report with {len(records['cases'])} case(s).")

# --- self-contained HTML template (assigned before write_report() is called below) ---
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>GitZoid — Three Review Cases</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
  :root{--bd:#d0d7de;--bg:#f6f8fa;--mut:#57606a;--blue:#0969da;}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;
       color:#1f2328;max-width:920px;margin:0 auto;padding:28px 20px;background:#fff;}
  h1{font-size:22px} h2.case{font-size:16px;margin:34px 0 6px;padding-top:18px;border-top:2px solid #eaeef2}
  .sub{color:var(--mut);font-size:13px;margin:0 0 14px}
  .pill{display:inline-block;font-size:11px;font-weight:600;border-radius:20px;padding:2px 9px;color:#fff;margin-left:6px}
  .p-bug{background:#cf222e}.p-min{background:#9a6700}.p-ok{background:#1a7f37}
  .thread{border:1px solid var(--bd);border-radius:8px;margin:10px 0;overflow:hidden}
  .thead{background:var(--bg);border-bottom:1px solid var(--bd);padding:8px 14px;font-size:13px;color:var(--mut)}
  .thead b{color:#1f2328}
  .tbody{padding:14px 16px;font-size:14px;line-height:1.55}
  .inline{border:1px solid var(--bd);border-radius:8px;margin:10px 0}
  .ihead{background:#fff;border-bottom:1px solid var(--bd);padding:6px 12px;font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--mut)}
  .ibody{padding:12px 14px;font-size:14px;line-height:1.55}
  .before-after{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .lbl{font-size:12px;font-weight:600;color:var(--mut);margin:8px 0 2px}
  .tbody pre,.ibody pre{background:var(--bg);padding:10px;border-radius:6px;overflow:auto;font-size:12px}
  .tbody code,.ibody code{background:rgba(175,184,193,.2);padding:.15em .35em;border-radius:4px;font-size:85%}
  .tbody pre code,.ibody pre code{background:none;padding:0}
  details{margin:6px 0} summary{cursor:pointer;color:var(--blue)}
  del{color:var(--mut)} hr{border:0;border-top:1px solid #eaeef2;margin:12px 0}
  .empty{color:var(--mut);font-style:italic;font-size:13px}
  #note{background:#fff8e1;border:1px solid #f0d58c;border-radius:8px;padding:10px 14px;margin:10px 0;font-size:13px;color:#7a5d00}
  #note:empty{display:none}
  @media(max-width:680px){.before-after{grid-template-columns:1fr}}
</style></head>
<body>
<h1>GitZoid — how the three cases look</h1>
<div id="note">__NOTE__</div>
<p class="sub" id="repoline"></p>
<div id="root"></div>
<script>
const DATA = __DATA__;
const md = s => marked.parse(s || "", {breaks:true});
const pill = v => v==="needs_changes" ? '<span class="pill p-bug">needs changes</span>'
                : v==="minor_comments" ? '<span class="pill p-min">minor comments</span>'
                : v==="looks_good" ? '<span class="pill p-ok">looks good</span>' : "";
document.getElementById("repoline").textContent = "Repository: " + DATA.repo + "  ·  read-only preview, nothing posted";
const root = document.getElementById("root");
const inlineCard = c => `<div class="inline"><div class="ihead">📄 ${c.path}:${c.line}  (${c.side||'RIGHT'})</div><div class="ibody">${md(c.body)}</div></div>`;

function section(title, sub){const h=document.createElement('h2');h.className='case';h.textContent=title;root.appendChild(h);
  const p=document.createElement('p');p.className='sub';p.innerHTML=sub;root.appendChild(p);}

for(const c of DATA.cases){
  if(c.case==="first_time"){
    section("1 · First-time review", `PR #${c.pr} — <b>${c.title||''}</b> ${pill(c.verdict)}`);
    root.insertAdjacentHTML('beforeend',
      `<div class="thread"><div class="thead">🤖 <b>GitZoid</b> commented — summary comment (posted once, edited later)</div>`+
      `<div class="tbody">${md(c.summary_md)}</div></div>`);
    if((c.inline||[]).length){root.insertAdjacentHTML('beforeend',`<div class="lbl">Inline comments on the diff (${c.inline.length})</div>`);
      c.inline.forEach(ic=>root.insertAdjacentHTML('beforeend',inlineCard(ic)));}
  }
  if(c.case==="bug_review"){
    section("2 · Bug review (zoom)", `The bug finding(s) GitZoid pins to the exact line in PR #${c.pr}`);
    if((c.inline||[]).length) c.inline.forEach(ic=>root.insertAdjacentHTML('beforeend',inlineCard(ic)));
    else root.insertAdjacentHTML('beforeend',`<p class="empty">No bug-category inline findings in this PR.</p>`);
  }
  if(c.case==="update"){
    section("3 · Update — a new commit lands", `PR #${c.pr} — the SAME summary comment is edited in place (<code>${(c.old_sha||'').slice(0,7)}</code> → <code>${(c.new_sha||'').slice(0,7)}</code>)`);
    root.insertAdjacentHTML('beforeend',
      `<div class="before-after">`+
      `<div><div class="lbl">BEFORE (first review)</div><div class="thread"><div class="tbody">${md(c.summary_before)}</div></div></div>`+
      `<div><div class="lbl">AFTER (edited on new commit)</div><div class="thread"><div class="tbody">${md(c.summary_after)}</div></div></div>`+
      `</div>`);
    if((c.new_inline||[]).length){root.insertAdjacentHTML('beforeend',`<div class="lbl">New inline comments from the new commit (${c.new_inline.length})</div>`);
      c.new_inline.forEach(ic=>root.insertAdjacentHTML('beforeend',inlineCard(ic)));}
    else root.insertAdjacentHTML('beforeend',`<p class="empty">No new inline findings from the new commit — only the summary was refreshed.</p>`);
  }
}
</script></body></html>"""

write_report()
