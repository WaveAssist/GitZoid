"""
Manual end-to-end runner for the GitZoid SECURITY pipeline
(study_repos brain -> scan_dependencies -> deep_security_audit -> triage_and_alert).

Uses LOCAL CLAUDE (never OpenRouter) and an IN-MEMORY store overlay so NOTHING is written to the
WaveAssist project (no clobbering of github_selected_resources / profiles / the security_findings
ledger). It reads real config (token, selected repos, any existing brain) from the project.

Security Watch only READS GitHub (manifests, files) — it never posts. As an extra safety net for
the prod IshaFoundation repos, this harness HARD-BLOCKS any GitHub write (POST/PATCH/PUT to
api.github.com) at the HTTP layer; OSV/KEV reads and the real email still work.

Email: preview-only by default (prints the email that WOULD be sent). Pass --send to ACTUALLY send
the email to the project owner's address via the real WaveAssist backend.

Usage:
    uid=<UID> project_key=<PROJECT> \\
      /path/to/waveAssistEnv/bin/python3 tests/e2e/run_security_e2e.py [owner/repo ...] [--send] [--no-brain]
"""
import os
import sys
import json
import subprocess

os.environ["LLM_PROVIDER"] = "claude_cli"
os.environ.setdefault("CLAUDE_CLI_MODEL", "claude-sonnet-4-6")
UID = os.environ.get("uid")
PROJECT = os.environ.get("project_key")
if not UID or not PROJECT:
    sys.exit("ERROR: set uid=<...> and project_key=<...> in the environment.")

SEND = "--send" in sys.argv
NO_BRAIN = "--no-brain" in sys.argv
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
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"local claude rc={r.returncode}: {(r.stderr or r.stdout)[:400]}")
    return _pjr(json.loads(r.stdout).get("result", ""), response_model, model)


# ---- hard GitHub-write guard (these are prod repos: reads only, never writes) ----
import requests  # noqa: E402
_real = {"post": requests.post, "patch": requests.patch, "put": requests.put, "delete": requests.delete}


def _guard(method):
    real = _real[method]
    def f(url, *a, **k):
        if "api.github.com" in str(url) or "github.com" in str(url):
            raise AssertionError(f"BLOCKED GitHub write ({method.upper()}) to {url}")
        return real(url, *a, **k)
    return f


for _m in _real:
    setattr(requests, _m, _guard(_m))

# ---- in-memory store overlay (SDK-faithful): writes stay local; reads fall back to the real
# project. Crucially it scopes by run_based and wraps JSON scalars as {"value": str} exactly like
# the backend, so the run-based handoff (skip flag, security_candidates) is exercised for real and
# can't silently mask a global-vs-run-based mismatch. ----
_store = {}          # keyed by (key, run_based)
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
        value = {"value": str(value)}     # mimic the SDK's scalar wrapping
    _store[_skey(key, run_based)] = value
    return True


def _rid(r):
    return r.get("id") if isinstance(r, dict) else r


full = _real_fetch("github_selected_resources", default=[]) or []
if TARGETS:
    sel = [r for r in full if _rid(r) in TARGETS] or [{"id": t, "properties": {}} for t in TARGETS]
else:
    sel = full
_store_data("github_selected_resources", sel, data_type="json")            # global
_store_data("security_skip_run", "0", run_based=True, data_type="string")  # as the start node sets
_store_data("security_candidates", [], run_based=True, data_type="json")

waveassist.call_llm = _local_call_llm
waveassist.fetch_data = _fetch
waveassist.store_data = _store_data
waveassist.is_test_run = lambda: not SEND   # preview unless --send

targets = [_rid(r) for r in sel]
print(f"[security-e2e] project={PROJECT} model={os.environ['CLAUDE_CLI_MODEL']} "
      f"email={'SEND (real)' if SEND else 'preview-only'}")
print(f"[security-e2e] repos: {', '.join(targets)}")
print(f"[security-e2e] GitHub writes are HARD-BLOCKED; OSV/KEV reads + email allowed.\n")

# 1) Brain — needed for reachability + audit scope. Skip with --no-brain to reuse any existing brain.
if not NO_BRAIN:
    print("[1/4] study_repos (building/refreshing the brain) ...")
    try:
        import study_repos  # noqa: F401
        for t in targets:
            p = _fetch(f"profile:{t}", default={}) or {}
            sec = (p.get("security") or {})
            print(f"      {t}: brain={'built' if p.get('schema_version') else 'MISSING'} "
                  f"| deps={len(p.get('dependencies', []))} routes={len(sec.get('routes', []))} "
                  f"key_files={len(p.get('key_files', []))}")
    except Exception as e:
        print(f"      ⚠️ brain build failed: {e} (continuing — scan still works, audit degrades)")
else:
    print("[1/4] study_repos SKIPPED (--no-brain): using any existing project brain.")

# 2) Dependency scan (real OSV + KEV)
print("\n[2/4] scan_dependencies (OSV + CISA KEV) ...")
import scan_dependencies  # noqa: F401
after_scan = list(_fetch("security_candidates", run_based=True, default=[]))
print(f"      dependency candidates: {len(after_scan)}")
for c in after_scan:
    print(f"        [{c.get('severity')}{'/KEV' if c.get('actively_exploited') else ''}] "
          f"{c.get('name')} {c.get('version')} → fix {c.get('fixed')} | {c.get('impact','')[:90]}")

# 3) Deep code audit (real LLM over scoped files)
print("\n[3/4] deep_security_audit (brain-scoped code audit) ...")
import deep_security_audit  # noqa: F401
after_audit = list(_fetch("security_candidates", run_based=True, default=[]))
code_findings = after_audit[len(after_scan):]
print(f"      code findings: {len(code_findings)}")
for c in code_findings:
    print(f"        [{c.get('category')}/{c.get('confidence')}] {c.get('title')} "
          f"| victim={c.get('named_victim','-')} | {c.get('impact','')[:90]}")

# 4) Triage + alert (dedupe ledger + email)
print("\n[4/4] triage_and_alert (gate + dedupe + email) ...")
import triage_and_alert  # noqa: F401
import re as _re
import html as _html
disp = (_fetch("display_output", run_based=True, default={}) or {}).get("html_content", "")
print(f"\n[security-e2e] total candidates: {len(after_audit)} | "
      f"ledger entries: {len(_fetch('security_findings', default={}) or {})}")
print(f"[security-e2e] email {'SENT to project owner' if SEND else 'PREVIEW (not sent)'} — content:\n")
print(_html.unescape(_re.sub(r'<[^>]+>', '', disp)).strip() or "(no email content — nothing to report)")
print(f"\n[security-e2e] done — nothing written to the project; no GitHub writes.")
