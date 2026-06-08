"""
run_update_sim.py — END-TO-END simulation of GitZoid's review lifecycle on ONE real PR:
  (1) FIRST review at an earlier commit of the PR, then
  (2) a RE-REVIEW at HEAD (full PR, prior review passed in),
showing exactly what the single evolving summary comment looks like before vs after,
including the open/fixed ledger, the "what changed" line, and the ✅ Resolved section.

STRICTLY READ-ONLY (safe for live/prod): in-memory store overlay, is_test_run=True,
a HARD guard blocks every GitHub write verb, local Claude only (never OpenRouter).

Usage:
  uid=.. project_key=.. BRAIN_JSON=/tmp/brain_prsfacade.json \
    python3 tests/e2e/run_update_sim.py <owner/repo> <pr_number>
Writes Business/context/GITZOID_UPDATE_SIM.html and a JSON dump.
"""
import os, sys, json, subprocess
os.environ["LLM_PROVIDER"] = "claude_cli"
os.environ.setdefault("CLAUDE_CLI_MODEL", "claude-sonnet-4-6")
GZ = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, GZ)
TARGET = sys.argv[1] if len(sys.argv) > 1 else "IshaFoundationIT/prs-facade"
PR = int(sys.argv[2]) if len(sys.argv) > 2 else 0
BRAIN_JSON = os.environ.get("BRAIN_JSON", "")

# --- HARD SAFETY: block every GitHub write verb ---
import requests as _rq
def _guard(method):
    orig = getattr(_rq, method)
    def f(url, *a, **k):
        if "api.github.com" in str(url):
            raise RuntimeError(f"SAFETY: blocked GitHub {method.upper()} {url}")
        return orig(url, *a, **k)
    return f
for _m in ("post", "patch", "put", "delete"):
    setattr(_rq, _m, _guard(_m))

import waveassist
from waveassist.utils import create_json_prompt as _cjp, parse_json_response as _pjr
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

_store = {"pull_requests": []}   # empties neutralise the node drivers on import
_real_fetch = waveassist.fetch_data
waveassist.call_llm = _local_call_llm
waveassist.fetch_data = lambda key=None, default=None, **k: _store[key] if key in _store else _real_fetch(key, default=default, **k)
waveassist.store_data = lambda key, value, **k: _store.__setitem__(key, value) or True
waveassist.is_test_run = lambda: True

token = _real_fetch("github_access_token", default="") or ""
H = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}

# brain (cached or build)
if BRAIN_JSON and os.path.exists(BRAIN_JSON):
    profile = json.load(open(BRAIN_JSON))
    print(f"[brain] loaded cache  branch={profile.get('_fingerprint',{}).get('branch')}")
else:
    _store["github_selected_resources"] = [{"id": TARGET, "properties": {}}]
    _store["reviewed_prs"] = {}
    import study_repos  # noqa
    profile = _store.get(f"profile:{TARGET}", {})
    if BRAIN_JSON:
        json.dump(profile, open(BRAIN_JSON, "w"), default=str)
    print("[brain] built")

# import the real nodes (drivers no-op because pull_requests == [])
import fetch_pull_requests as fpr   # noqa
import generate_review as gr        # noqa
import post_comment as pc           # noqa

# --- pick the two commits of the PR: A = second-to-last, B = head ---
p = _rq.get(f"https://api.github.com/repos/{TARGET}/pulls/{PR}", headers=H, timeout=30).json()
base_sha = p["base"]["sha"]
commits = _rq.get(f"https://api.github.com/repos/{TARGET}/pulls/{PR}/commits",
                  headers=H, params={"per_page": 100}, timeout=30).json()
if len(commits) < 2:
    sys.exit(f"PR #{PR} has <2 commits; pick a PR with at least two so there is an 'update' to show.")
sha_A = commits[-2]["sha"]
sha_B = commits[-1]["sha"]
print(f"[pr] #{PR} {p['title']!r}\n     first @ {sha_A[:7]}  →  update @ {sha_B[:7]}  ({len(commits)} commits)")

def files_at(sha):
    return fpr.fetch_compare_diff(TARGET, base_sha, sha, H)

def run_review(files, sha, review_type, prev_review, prev_sha=None):
    pr_data = {"id": TARGET, "pr_number": PR, "title": p.get("title"), "body": p.get("body"),
               "files": files, "current_sha": sha, "previous_sha": prev_sha,
               "previous_review_text": prev_review, "brain_profile": profile}
    if review_type == "full":
        prompt = gr.get_full_review_prompt(pr_data, additional_context="")
        result = _local_call_llm("sim", prompt, gr.ReviewResult)
    else:
        prompt = gr.get_update_review_prompt(pr_data, previous_review=prev_review, additional_context="")
        result = _local_call_llm("sim", prompt, gr.UpdateReviewResult)
    rd = result.model_dump()
    diff_lines = gr.build_diff_lines(files)
    raw = (rd.get("findings") or []) + gr.security_sweep(files, profile)
    kept, verdict, _ = gr.apply_gate(raw, diff_lines, seen_sigs=set(), severity_threshold="high")
    rd["findings"] = kept
    rd["verdict"] = verdict
    return rd

# (1) FIRST review at commit A
print("\n[1] FIRST review (local Claude)...")
files_A = files_at(sha_A)
rd1 = run_review(files_A, sha_A, "full", None)
ledger1, inline1 = pc.reconcile_ledger({}, rd1["findings"], sha_A, is_update=False)
changed1 = sorted({f.get("path") for f in rd1["findings"] if f.get("path")})
comment1 = pc.build_summary_md(rd1, ledger1, changed1, sha_A[:7], current_sha=sha_A, is_update=False)
print(f"    verdict={rd1['verdict']}  findings={len(rd1['findings'])}  inline={len(inline1)}")

# (2) RE-REVIEW at HEAD (full PR), prior review passed in
print("\n[2] RE-REVIEW at HEAD (local Claude)...")
files_B = files_at(sha_B)
rd2 = run_review(files_B, sha_B, "incremental", comment1, prev_sha=sha_A)
ledger2, inline2 = pc.reconcile_ledger(ledger1, rd2["findings"], sha_B, is_update=True)
changed2 = sorted({f.get("path") for f in rd2["findings"] if f.get("path")})
comment2 = pc.build_summary_md(rd2, ledger2, changed2, sha_B[:7], current_sha=sha_B, is_update=True)
n_new = len([v for v in ledger2.values() if v.get("status") == "open" and v.get("first_seen_sha") == sha_B])
n_fixed = len([v for v in ledger2.values() if v.get("status") == "fixed"])
n_open = len([v for v in ledger2.values() if v.get("status") == "open"])
print(f"    verdict={rd2['verdict']}  open={n_open}  new={n_new}  resolved={n_fixed}  new_inline={len(inline2)}")

dump = {"repo": TARGET, "pr": PR, "title": p.get("title"),
        "sha_A": sha_A, "sha_B": sha_B,
        "first": {"verdict": rd1["verdict"], "comment_md": comment1, "n_findings": len(rd1["findings"])},
        "update": {"verdict": rd2["verdict"], "comment_md": comment2,
                   "open": n_open, "new": n_new, "resolved": n_fixed}}
json.dump(dump, open("/tmp/gitzoid_update_sim.json", "w"), indent=2, default=str)

# --- render HTML (first vs updated) ---
import html, markdown
def card(title, sub, md, accent):
    body = markdown.markdown(md, extensions=["fenced_code", "tables"])
    return f'''<div class="card"><div class="ch" style="border-color:{accent}">
      <span class="ct">{html.escape(title)}</span><span class="cs">{html.escape(sub)}</span></div>
      <div class="cb">{body}</div></div>'''

delta = f'🔄 Between the two reviews: <b>{n_new} new</b> · <b>{n_fixed} resolved</b> · {n_open} still open'
doc = f'''<!doctype html><html><head><meta charset="utf-8"><title>GitZoid Update Simulation — PR #{PR}</title>
<style>
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;background:#f6f8fa;color:#1f2328;margin:0;padding:32px}}
 .wrap{{max-width:1500px;margin:0 auto}} h1{{font-size:22px;margin-bottom:2px}}
 .sub{{color:#57606a;font-size:14px;margin-bottom:6px}}
 .delta{{background:#ddf4ff;border:1px solid #54aeff;border-radius:8px;padding:10px 16px;margin:14px 0 22px;font-size:14px}}
 .cols{{display:flex;gap:22px;align-items:flex-start}} .card{{flex:1;background:#fff;border:1px solid #d0d7de;border-radius:10px;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.04)}}
 .ch{{padding:12px 18px;border-bottom:3px solid;background:#fbfdff}} .ct{{font-weight:700;font-size:15px}} .cs{{color:#57606a;font-size:12px;margin-left:8px}}
 .cb{{padding:8px 20px 16px}} .cb h2{{font-size:15px;margin:14px 0 6px}} .cb ul{{padding-left:20px;margin:4px 0 10px}} .cb li{{margin:3px 0;font-size:13.5px}}
 code{{background:#eff1f3;padding:1px 5px;border-radius:5px;font-size:85%}}
 details{{background:#f6f8fa;border:1px solid #eaeef2;border-radius:6px;padding:8px 12px;margin:10px 0}} summary{{cursor:pointer;font-weight:600;font-size:13px}}
 hr{{border:none;border-top:1px solid #eaeef2;margin:10px 0}} .foot{{color:#8b949e;font-size:12px;text-align:center;margin-top:14px}}
</style></head><body><div class="wrap">
<h1>🤖 GitZoid — Review lifecycle on one PR</h1>
<div class="sub">{html.escape(TARGET)} · PR #{PR} · <b>READ-ONLY</b>, nothing posted. In production this is ONE comment, edited in place.</div>
<div class="delta">{delta}</div>
<div class="cols">
 {card("① First review", f"at {sha_A[:7]} · verdict "+rd1['verdict'], comment1, "#8250df")}
 {card("② Updated review (same comment, edited)", f"at {sha_B[:7]} · verdict "+rd2['verdict'], comment2, "#1a7f37")}
</div>
<div class="foot">Simulated locally: first review at an earlier commit, then a full re-review at HEAD with the prior review passed in.</div>
</div></body></html>'''
out = os.path.join(GZ, "..", "..", "Business", "context", "GITZOID_UPDATE_SIM.html")
out = os.path.abspath(out)
open(out, "w").write(doc)
print(f"\n[sim] wrote {out}")
print(f"[sim] wrote /tmp/gitzoid_update_sim.json")
