"""
Full-pipeline PREVIEW runner: study_repos (brain) -> fetch -> generate -> render, for a target repo.

STRICTLY READ-ONLY (safe for live/prod accounts):
  - in-memory store overlay  -> nothing is written to the WaveAssist project,
  - is_test_run forced True   -> post_comment never posts,
  - a HARD guard blocks any GitHub POST/PATCH/PUT/DELETE (only GETs are allowed),
  - local Claude only         -> never OpenRouter.

It seeds the target as the selected resource (useful when the project has none), builds the brain,
and prints the review summary GitZoid WOULD post for the N newest open PRs.

Usage:
  uid=<UID> project_key=<PROJECT> python3 tests/e2e/run_full_preview.py <owner/repo> [N]
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
N = int(_pos[1]) if len(_pos) > 1 else 3
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# --- HARD SAFETY: block every GitHub write verb, no matter what calls it ---
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
print(f"[full-preview] {TARGET}  reviewing {N} newest open PR(s)  (READ-ONLY: no posts, no project writes)\n")

# --- 1. Brain ---
_store["github_selected_resources"] = [{"id": TARGET, "properties": {}}]
_store["reviewed_prs"] = {}
import study_repos  # noqa: E402,F401   (driver builds profile:TARGET into the overlay)
profile = _store.get(f"profile:{TARGET}", {})
fp = profile.get("_fingerprint", {})
stk = profile.get("stack", {})
tech = (stk.get("languages") or []) + (stk.get("frameworks") or [])
print("[1] brain built")
print(f"    branch: {fp.get('branch')}   stack: {', '.join(tech)[:90]}")
print(f"    {len(profile.get('key_files', []))} key files · {len(profile.get('dependencies', []))} deps · "
      f"{len((profile.get('security') or {}).get('routes', []))} routes · "
      f"{len(profile.get('review_focus', []))} review-focus items")

# --- 2. Build pull_requests for the N newest open PRs (bypasses the first-run cap) ---
_store["github_selected_resources"] = []   # neutralise the fetch driver on import
import fetch_pull_requests as fpr  # noqa: E402
resp = _rq.get(f"https://api.github.com/repos/{TARGET}/pulls", headers=H,
               params={"state": "open", "sort": "created", "direction": "desc", "per_page": 100}, timeout=30)
open_prs = resp.json() if resp.status_code == 200 else []
selected = [p for p in open_prs if not fpr.is_bot_pr(p) and not fpr.is_draft_pr(p)][:N]
pulls = []
for p in selected:
    files = fpr.fetch_pr_files(TARGET, p["number"], H)
    pulls.append(fpr.build_pr_data(p, files, "full", p.get("head", {}).get("sha", ""), TARGET, brain_profile=profile))
_store["pull_requests"] = pulls
print(f"\n[2] queued {len(pulls)} PR(s): " + ", ".join(f"#{p['pr_number']}" for p in pulls))

# --- 3. Review (local Claude) ---
print("\n[3] generating reviews (local Claude)...")
import generate_review  # noqa: E402,F401
reviewed = _store.get("pull_requests", [])

# --- 4. Render the summary GitZoid WOULD post (no posting) ---
import post_comment as pc  # noqa: E402   (its driver runs in preview = harmless)
records = []
for p in reviewed:
    rd = p.get("review_dict") or {}
    gated = rd.get("findings", [])
    ledger, new_inline = pc.reconcile_ledger({}, gated, p.get("current_sha", ""), is_update=False)
    changed = sorted({f.get("path") for f in gated if f.get("path")})
    md = pc.build_summary_md(rd, ledger, changed, (p.get("current_sha", "")[:7]))
    records.append({
        "number": p["pr_number"], "title": p.get("title"), "verdict": rd.get("verdict"),
        "sha": p.get("current_sha", ""), "summary_md": md, "inline": new_inline,
        "files": [{"filename": f.get("filename"), "patch": f.get("patch", "")} for f in (p.get("files") or [])],
    })
    print("\n" + "=" * 78)
    print(f"PR #{p['pr_number']}: {p.get('title')}   [verdict={rd.get('verdict')}, {len(new_inline)} inline]")
    print("=" * 78)
    print(md)
out_path = os.environ.get("PREVIEW_JSON", "/tmp/gitzoid_preview.json")
with open(out_path, "w") as fh:
    json.dump({"repo": TARGET, "prs": records}, fh, indent=2, default=str)
print(f"\n[full-preview] wrote {out_path} — READ-ONLY, nothing posted or persisted.")
