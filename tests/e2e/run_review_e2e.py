"""
Manual end-to-end runner for the GitZoid REVIEW pipeline (fetch -> generate -> post), preview-only.

Runs the three real nodes in order against a real open PR, using LOCAL CLAUDE (never OpenRouter)
and an IN-MEMORY store overlay so NOTHING is written to GitHub or the WaveAssist project:
  - reads real config (token, selected repos, brain profile:{repo}) from the project,
  - subsets the repo list to TARGET, seeds reviewed_prs={} to force a clean first review,
  - forces post_comment into preview mode (is_test_run -> True), so it only prints the summary.

Usage:
    uid=<UID> project_key=<PROJECT> \\
      /path/to/waveAssistEnv/bin/python3 tests/e2e/run_review_e2e.py [owner/repo]
"""
import os
import sys
import json
import subprocess

os.environ["LLM_PROVIDER"] = "claude_cli"
os.environ.setdefault("CLAUDE_CLI_MODEL", "claude-sonnet-4-6")
if not os.environ.get("uid") or not os.environ.get("project_key"):
    sys.exit("ERROR: set uid=<...> and project_key=<...> in the environment.")

TARGET = next((a for a in sys.argv[1:] if not a.startswith("--")), "WaveAssist/GitZoid")
LIVE = "--live" in sys.argv   # --live actually POSTS to GitHub; default is preview-only
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

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


# In-memory store overlay: writes stay local; reads fall back to the real project.
_store = {}
_real_fetch = waveassist.fetch_data


def _fetch(key=None, default=None, **k):
    if key in _store:
        return _store[key]
    return _real_fetch(key, default=default, **k)


def _store_data(key, value, **k):
    _store[key] = value
    return True


def _rid(r):
    return r.get("id") if isinstance(r, dict) else r


full_repos = _real_fetch("github_selected_resources", default=[]) or []
_store["github_selected_resources"] = [r for r in full_repos if _rid(r) == TARGET] or [{"id": TARGET, "properties": {}}]
_store["reviewed_prs"] = {}

waveassist.call_llm = _local_call_llm
waveassist.fetch_data = _fetch
waveassist.store_data = _store_data
waveassist.is_test_run = lambda: not LIVE   # default preview; --live actually posts to GitHub

print(f"[review-e2e] target={TARGET}  model={os.environ['CLAUDE_CLI_MODEL']}  "
      f"mode={'LIVE-POST' if LIVE else 'preview-only'}\n")

import fetch_pull_requests  # noqa: E402,F401
pulls = _store.get("pull_requests", [])
print(f"[1/3] fetch_pull_requests -> {len(pulls)} PR(s) queued")
for p in pulls:
    bp = p.get("brain_profile") or {}
    print(f"      PR #{p.get('pr_number')} {p.get('title')!r} | files={len(p.get('files', []))} "
          f"| brain={'yes' if bp else 'no'} ({len(bp.get('key_files', []))} key files)")
if not pulls:
    print("      (nothing to review — PR may be outside the first-run window)"); sys.exit(0)

import generate_review  # noqa: E402,F401
reviewed = _store.get("pull_requests", [])
print(f"\n[2/3] generate_review:")
for p in reviewed:
    rd = p.get("review_dict") or {}
    print(f"      PR #{p.get('pr_number')} verdict={rd.get('verdict')} findings={len(rd.get('findings', []))}")
    for s in (rd.get("summary") or [])[:3]:
        print(f"        summary: {s}")
    for f in rd.get("findings", []):
        loc = f"{f.get('path')}:{f.get('line')}" if f.get("line") else f.get("path") or "(summary)"
        print(f"        [{f.get('severity')}/{f.get('confidence')} {f.get('category')}] {loc} — {f.get('body')}")
    for o in (rd.get("potential_optimizations") or [])[:5]:
        print(f"        opt: {o}")

import post_comment  # noqa: E402,F401
import re
import html as _html
disp = _store.get("display_output", {}).get("html_content", "")
if LIVE:
    urls = re.findall(r'href="([^"]+)"', disp)
    print("\n[3/3] post_comment (LIVE) — posted to GitHub:")
    for u in urls:
        print("      ", _html.unescape(u))
    if not urls:
        print("      (no link captured — see output above)")
    print("\n[review-e2e] done — review posted live (project state NOT mutated; reviewed_prs kept in-memory).")
else:
    print("\n[3/3] post_comment (preview) — summary that WOULD be posted:\n")
    m = re.search(r"<pre[^>]*>(.*?)</pre>", disp, re.S)
    print(_html.unescape(m.group(1)) if m else "(no preview captured)")
    print("\n[review-e2e] done — nothing was written to GitHub or the project.")
