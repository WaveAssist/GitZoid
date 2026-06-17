"""
Manual end-to-end runner for the GitZoid KNOWLEDGE DIGEST pipeline
(fetch_activity -> analyze_activity -> generate_business_report -> generate_technical_report ->
send_digest).

Uses LOCAL CLAUDE (never OpenRouter) and an IN-MEMORY store overlay so NOTHING is written to the
WaveAssist project (no clobbering of any project data). It reads real config (token, selected repos,
any existing brain, the security_findings ledger) from the project.

The digest only READS GitHub (branches via GraphQL, commits, PRs, diffs) and sends ONE email per
group to the account owner. It never posts to GitHub. As a safety net for the prod IshaFoundation
repos, this harness HARD-BLOCKS any GitHub write at the HTTP layer, allowing only the read-only
GraphQL POST that active-branch detection needs.

It also bypasses the gate node (digest_check_and_init) so the test never touches prod credits or the
digest_run_lock; it seeds the gate's outputs (digest_skip_run + digest_resolved_groups) directly,
reproducing the implicit single-group fallback the gate would apply when no digest_groups are set.

Email: preview-only by default (prints + saves the email that WOULD be sent). Pass --send to ACTUALLY
send it to the project owner via the real WaveAssist backend.

Usage:
    uid=<UID> project_key=<PROJECT> \\
      /path/to/python tests/e2e/run_digest_e2e.py [owner/repo ...] [--send] [--out=PATH]
"""
import os
import re
import sys
import json
import html
import time
import subprocess

os.environ["LLM_PROVIDER"] = "claude_cli"
os.environ.setdefault("CLAUDE_CLI_MODEL", "claude-sonnet-4-6")
UID = os.environ.get("uid")
PROJECT = os.environ.get("project_key")
if not UID or not PROJECT:
    sys.exit("ERROR: set uid=<...> and project_key=<...> in the environment.")

SEND = "--send" in sys.argv
OUT = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--out=")), "/tmp/gitzoid_digest_preview.html")
TARGETS = [a for a in sys.argv[1:] if not a.startswith("--")]
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import waveassist  # noqa: E402
from waveassist.utils import create_json_prompt as _cjp, parse_json_response as _pjr  # noqa: E402
waveassist.init(token=UID, project_key=PROJECT)


def _local_call_llm(model, prompt, response_model, **k):
    jp = _cjp(prompt, response_model)
    m = os.environ.get("CLAUDE_CLI_MODEL", "claude-sonnet-4-6")
    cmd = ["claude", "-p", jp, "--output-format", "json", "--model", m,
           "--max-turns", "1", "--tools", "", "--strict-mcp-config"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        raise RuntimeError(f"local claude rc={r.returncode}: {(r.stderr or r.stdout)[:400]}")
    return _pjr(json.loads(r.stdout).get("result", ""), response_model, model)


# ---- hard GitHub-write guard: reads only. Allow the read-only GraphQL POST; block everything else. ----
import requests  # noqa: E402
_real = {"post": requests.post, "patch": requests.patch, "put": requests.put, "delete": requests.delete}


def _guard(method):
    real = _real[method]
    def f(url, *a, **k):
        u = str(url)
        if ("github.com" in u) and not u.rstrip("/").endswith("/graphql"):
            raise AssertionError(f"BLOCKED GitHub write ({method.upper()}) to {u}")
        return real(url, *a, **k)
    return f


for _m in _real:
    setattr(requests, _m, _guard(_m))

# ---- in-memory store overlay: writes stay local, reads fall back to the real project. ----
_store = {}
_real_fetch = waveassist.fetch_data


def _skey(key, run_based):
    return (key, bool(run_based))


def _fetch(key=None, run_based=False, default=None, **k):
    sk = _skey(key, run_based)
    if sk in _store:
        return _store[sk]
    return _real_fetch(key, run_based=run_based, default=default)


def _store_data(key, value, run_based=False, data_type=None, **k):
    if data_type == "json" and not isinstance(value, (dict, list)):
        value = {"value": str(value)}
    _store[_skey(key, run_based)] = value
    return True


# ---- email capture: preview unless --send ----
_sent = []
_real_send = waveassist.send_email


def _send_email(**k):
    _sent.append(k)
    if SEND:
        # The local pip SDK (0.8.0) lacks cc/attachment kwargs that PROD's send_email supports (proven
        # by the cc'd security emails in prod). Pass only what the local signature accepts so the test
        # still delivers; cc is None for the implicit single group anyway.
        import inspect
        allowed = set(inspect.signature(_real_send).parameters)
        return _real_send(**{kk: vv for kk, vv in k.items() if kk in allowed})
    return True


def _rid(r):
    return r.get("id") if isinstance(r, dict) else r


full = _real_fetch("github_selected_resources", default=[]) or []
targets = [t for t in (TARGETS or [_rid(r) for r in full]) if t]
if not targets:
    sys.exit("ERROR: no repos selected in the project and none passed as args.")

# Reproduce the gate's implicit single-group fallback (no digest_groups configured for this project).
groups = [{"name": "All repositories", "repos": targets, "recipients": [], "slug": "all-repositories"}]
_store_data("digest_skip_run", "0", run_based=True, data_type="string")
_store_data("digest_resolved_groups", groups, run_based=True, data_type="json")

waveassist.init = lambda *a, **k: None           # modules re-call init(); keep our setup
waveassist.call_llm = _local_call_llm
waveassist.fetch_data = _fetch
waveassist.store_data = _store_data
waveassist.send_email = _send_email

print(f"[digest-e2e] project={PROJECT} model={os.environ['CLAUDE_CLI_MODEL']} "
      f"email={'SEND (real)' if SEND else 'preview-only'}")
print(f"[digest-e2e] repos: {', '.join(targets)}")
print(f"[digest-e2e] GitHub writes HARD-BLOCKED (GraphQL read allowed); nothing written to project.\n")

t0 = time.monotonic()


def _stage(label, module):
    start = time.monotonic()
    __import__(module)
    dt = time.monotonic() - start
    print(f"      ⏱  {label}: {dt:.1f}s")
    return dt


timings = {}
print("[1/5] fetch_activity (GraphQL branches + commits + PRs) ...")
timings["fetch_activity"] = _stage("fetch_activity", "fetch_activity")
activity = _fetch("github_activity_data", default={}) or {}
dr = _fetch("report_date_range", default={}) or {}
print(f"      window: {dr.get('start_date_formatted')} → {dr.get('end_date_formatted')}")
for r, d in activity.items():
    print(f"      {r}: {len(d.get('commits', []))} commit(s), {len(d.get('pull_requests', []))} PR(s)")

print("\n[2/5] analyze_activity (diffs → structured changes; three-tier splitting) ...")
timings["analyze_activity"] = _stage("analyze_activity", "analyze_activity")
analyses = _fetch("repository_analyses", default=[]) or []
for a in analyses:
    print(f"      {a.get('repository')}: {len(a.get('changes', []))} change(s)")

print("\n[3/5] generate_business_report (per group) ...")
timings["generate_business_report"] = _stage("generate_business_report", "generate_business_report")

print("\n[4/5] generate_technical_report (per group + security roll-up) ...")
timings["generate_technical_report"] = _stage("generate_technical_report", "generate_technical_report")
tech = _fetch("digest_technical_reports", run_based=True, default={}) or {}
for slug, rep in tech.items():
    c = (rep.get("security_rollup") or {}).get("counts", {})
    print(f"      {slug}: {len(rep.get('repository_deep_dive', []))} repo section(s) | "
          f"security: {c.get('new', 0)} new / {c.get('still_open', 0)} open / {c.get('resolved', 0)} resolved")

print("\n[5/5] send_digest (render + email) ...")
timings["send_digest"] = _stage("send_digest", "send_digest")

total = time.monotonic() - t0
print("\n[digest-e2e] ===== TIMING =====")
for k, v in timings.items():
    print(f"   {k:28} {v:6.1f}s")
print(f"   {'TOTAL':28} {total:6.1f}s")

print(f"\n[digest-e2e] email(s) {'SENT to owner' if SEND else 'PREVIEW (not sent)'}: {len(_sent)}")
for e in _sent:
    print(f"   subject: {e.get('subject')} | cc: {e.get('cc')} | "
          f"pdf: {'yes' if e.get('attachment_file') else 'no (weasyprint absent locally)'}")
    body = e.get("html_content", "")
    with open(OUT, "w") as f:
        f.write(body)
    text = html.unescape(re.sub(r"<[^>]+>", " ", body))
    text = re.sub(r"\n\s*\n+", "\n", re.sub(r"[ \t]+", " ", text)).strip()
    print("\n----- rendered digest (text) -----\n")
    print(text)
    print(f"\n----- full HTML saved to: {OUT} -----")

print("\n[digest-e2e] done; nothing written to the project; no GitHub writes.")
