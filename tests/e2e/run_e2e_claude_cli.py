"""
Manual end-to-end runner for the GitZoid brain build (study_repos), using LOCAL CLAUDE only.

This is NOT a pytest test (filename intentionally not test_*.py so pytest never collects it).
It runs the real study_repos node against a real WaveAssist project, but forces all LLM calls
through the local Claude CLI (Claude Max subscription) — OpenRouter is never used.

Usage:
    uid=<UID> project_key=<PROJECT> \\
      /path/to/waveAssistEnv/bin/python3 tests/e2e/run_e2e_claude_cli.py [REPO] [--write] [--all]

    REPO     owner/repo to build (default: the first connected repo). Ignored with --all.
    --all    build every connected repo (default: just one).
    --write  actually persist profile:{repo} / repo_groups / brain_html to the project.
             Without --write it is a DRY RUN: profiles are printed, nothing is stored.

Credentials are read from the environment (uid, project_key) — never hardcoded here.
"""
import os
import sys
import json

# --- Enforce local Claude: this process must NEVER touch OpenRouter ---
os.environ["LLM_PROVIDER"] = "claude_cli"
os.environ.setdefault("CLAUDE_CLI_MODEL", "claude-sonnet-4-6")

if not os.environ.get("uid") or not os.environ.get("project_key"):
    sys.exit("ERROR: set uid=<...> and project_key=<...> in the environment before running.")

ALL = "--all" in sys.argv
WRITE = "--write" in sys.argv
positional = [a for a in sys.argv[1:] if not a.startswith("--")]
TARGET = positional[0] if positional else None

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import subprocess as _subprocess  # noqa: E402
import json as _json  # noqa: E402
import waveassist  # noqa: E402
from waveassist.utils import create_json_prompt as _cjp, parse_json_response as _pjr  # noqa: E402
waveassist.init()


def _local_call_llm(model, prompt, response_model, **k):
    """Tool-free local Claude. The default claude_cli path runs an agentic session that, in a
    tool-rich project dir, can invoke a tool and blow --max-turns 1. We disable all tools/MCP so
    the model answers directly. OpenRouter is never touched."""
    jp = _cjp(prompt, response_model)
    m = os.environ.get("CLAUDE_CLI_MODEL", "claude-sonnet-4-6")
    cmd = ["claude", "-p", jp, "--output-format", "json", "--model", m,
           "--max-turns", "1", "--tools", "", "--strict-mcp-config"]
    r = _subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"local claude rc={r.returncode}: {(r.stderr or r.stdout)[:400]}")
    return _pjr(_json.loads(r.stdout).get("result", ""), response_model, model)


waveassist.call_llm = _local_call_llm
print("[e2e] call_llm -> local Claude (tools disabled); OpenRouter never used")

_real_fetch = waveassist.fetch_data
_real_store = waveassist.store_data

# Resolve the repo subset BEFORE patching, so we know the target(s).
_all_repos = _real_fetch("github_selected_resources", default=[]) or []


def _rid(r):
    return r.get("id") if isinstance(r, dict) else r


if not ALL:
    if TARGET:
        subset = [r for r in _all_repos if _rid(r) == TARGET] or [{"id": TARGET, "properties": {}}]
    else:
        subset = _all_repos[:1]
else:
    subset = _all_repos

print(f"[e2e] mode={'WRITE' if WRITE else 'DRY-RUN'}  model={os.environ['CLAUDE_CLI_MODEL']}  "
      f"targets={[_rid(r) for r in subset]}")


def fetch_data(key=None, default=None, **k):
    if key == "github_selected_resources":
        return subset
    return _real_fetch(key, default=default, **k)


def store_data(key, value, **k):
    if not WRITE:
        if str(key).startswith("profile:"):
            print(f"\n=== [DRY] would store {key} ===")
            print(json.dumps(value, indent=2, default=str)[:6000])
        else:
            print(f"=== [DRY] would store {key} (type={k.get('data_type')}, len={len(str(value))}) ===")
        return True
    ok = _real_store(key, value, **k)
    print(f"[e2e] stored {key} -> {ok}")
    return ok


waveassist.fetch_data = fetch_data
waveassist.store_data = store_data

# Importing study_repos runs its top-level driver against the patched fetch/store + local Claude.
import study_repos  # noqa: E402,F401

print("\n[e2e] done.")
