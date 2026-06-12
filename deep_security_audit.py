"""
deep_security_audit.py — the weekly, brain-scoped deep code audit (Security chain, node 3).

It lives in the daily Security chain but only does work for a repo once every 7 days
(self-throttled via `security_audit_state`, the study_repos pattern), processing repos
oldest-audited-first within a time budget so it never brushes the broker window.

For each due repo it fetches ONLY the security-critical files (auth-ish key files, secret
locations) plus the files the per-PR tripwire queued (`security_audit_queue`), and asks the
configured model to find the class no scanner can: bypassable auth / broken access control,
backdoor-ish code, and live secrets. A finding survives ONLY if it carries a concrete
{entry point → exploit path → named victim → fix} (authz), a real non-placeholder secret, or
concrete backdoor signals — at high confidence. Survivors are appended to the run-based
`security_candidates` key for triage_and_alert; the audit never emails directly.

Conventions: flat script, no __main__ guard, init() first, no sibling imports, fall-through on
empty. Every external call has a timeout; one bad repo never sinks the batch.
"""
import time
import base64
from datetime import datetime, timezone
from typing import List, Literal
import requests
from pydantic import BaseModel, Field
import waveassist

waveassist.init()   # credits gated once upstream in security_check_and_init

print("Processing GitZoid deep security audit (deep_security_audit) node")

GITHUB_API = "https://api.github.com"
HTTP_TIMEOUT = 20
RATE_SLEEP = 0.15
DEFAULT_MODEL = "anthropic/claude-sonnet-4.6"
AUDIT_TTL_DAYS = 7
MAX_FILES_PER_REPO = 20
FILE_CHAR_CAP = 12000
MAX_AUDIT_TOKENS = 4096
RUN_TIME_BUDGET_SECONDS = 1200      # ~20 min: overflow repos resume next daily tick

_AUTH_HINTS = ("auth", "login", "session", "security", "middleware", "token", "jwt", "oauth",
               "permission", "credential", "password", "access", "role", "admin", "reset", "otp")


# ---------------------------------------------------------------- throttle + scope

def needs_audit(state_entry, now=None, ttl_days=AUDIT_TTL_DAYS) -> bool:
    """A repo is due if never audited or its last audit is older than the TTL."""
    if not state_entry or not state_entry.get("last_audit_at"):
        return True
    now = now or datetime.now(timezone.utc)
    try:
        age = (now - datetime.fromisoformat(state_entry["last_audit_at"])).days
    except Exception:
        return True
    return age >= ttl_days


def _is_security_relevant(path, role=""):
    blob = f"{path} {role}".lower()
    return any(h in blob for h in _AUTH_HINTS)


def select_audit_files(brain_profile, queue_files, cap=MAX_FILES_PER_REPO):
    """Pick the files worth deep-reading: auth-ish key files + secret locations that look like files
    + everything the PR tripwire queued. Deduped, capped. Queue files are highest priority."""
    ordered = []
    for p in (queue_files or []):
        if p:
            ordered.append(p)
    for kf in ((brain_profile or {}).get("key_files") or []):
        path = kf.get("path") or ""
        if path and _is_security_relevant(path, kf.get("role", "")):
            ordered.append(path)
    for loc in (((brain_profile or {}).get("security") or {}).get("secret_locations") or []):
        if loc and ("/" in loc or "." in loc):
            ordered.append(loc)
    seen, out = set(), []
    for p in ordered:
        if p not in seen:
            seen.add(p)
            out.append(p)
        if len(out) >= cap:
            break
    return out


# ---------------------------------------------------------------- gate

def audit_gate(f) -> bool:
    """A finding ships only if it is concrete and high-confidence. Authz needs the full
    {entry point, exploit path, named victim, fix}; a secret needs a path + why-it's-real; a
    backdoor needs concrete behavioral signals. Everything else stays silent."""
    if f.get("confidence") != "high":
        return False
    cat = f.get("category")
    if cat == "authz":
        return all(f.get(k) for k in ("entry_point", "exploit_path", "named_victim", "fix"))
    if cat == "secret":
        return bool(f.get("path")) and bool(f.get("why_not_placeholder"))
    if cat == "backdoor":
        return bool(f.get("behavioral_signals"))
    return False


# ---------------------------------------------------------------- structured output

class AuthzFinding(BaseModel):
    entry_point: str = Field(description="The route/handler the attacker hits, e.g. 'POST /reset-password'")
    missing_check: str = Field(description="The authorization/identity check that is missing or bypassable")
    exploit_path: str = Field(description="Concrete steps from entry point to the bypass")
    named_victim: str = Field(description="WHO is harmed, concretely, e.g. 'any user whose email is known'")
    reproduction: str = Field(description="The exact request/sequence that reproduces it")
    fix: str = Field(description="The one specific change that closes it")
    impact: str = Field(description="Plain-English one-liner: what an attacker gains")
    confidence: Literal["high", "medium", "low"] = Field(description="high only if you are certain it is exploitable")


class SecretFinding(BaseModel):
    path: str = Field(description="File where the secret is")
    provider: str = Field(default="", description="What kind of secret/provider, if known")
    why_not_placeholder: str = Field(description="Concrete reason it is a real live secret, not a placeholder/fixture")
    impact: str = Field(description="Plain-English impact if leaked")
    fix: str = Field(default="", description="What to do (rotate + move to a secret store)")
    confidence: Literal["high", "medium", "low"] = Field(description="high only if clearly a live secret")


class BackdoorFinding(BaseModel):
    path: str = Field(description="File or dependency exhibiting the behavior")
    behavioral_signals: List[str] = Field(description="Concrete suspicious behaviors observed")
    impact: str = Field(description="Plain-English description of the risk")
    fix: str = Field(default="", description="Recommended action")
    confidence: Literal["high", "medium", "low"] = Field(description="high only if clearly malicious/suspicious")


class AuditResult(BaseModel):
    authz_findings: List[AuthzFinding] = Field(default_factory=list)
    secret_findings: List[SecretFinding] = Field(default_factory=list)
    backdoor_findings: List[BackdoorFinding] = Field(default_factory=list)


# ---------------------------------------------------------------- prompt

def _xml(s):
    return str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_audit_prompt(repo_path, brain_profile, files):
    arch = (brain_profile or {}).get("architecture_summary", "") or ""
    routes = (((brain_profile or {}).get("security") or {}).get("routes") or [])
    route_xml = "\n".join(
        f"    <route public=\"{bool(r.get('unauthenticated'))}\">{_xml(r.get('route'))}</route>"
        for r in routes)
    files_xml = "\n".join(
        f"<file path=\"{_xml(p)}\">\n{_xml(c)}\n</file>" for p, c in files.items())
    return f"""<role>
You are a senior application-security engineer doing a focused audit of the security-critical code
below. You are NOT reviewing style or general bugs. Find only issues that are real and exploitable.
</role>
<repo>{_xml(repo_path)}</repo>
<architecture>{_xml(arch)}</architecture>
<known_routes>
{route_xml}
</known_routes>
<what_to_find>
- Broken access control / bypassable auth: a protected action reachable without the right check
  (e.g. "login verifies OTP, but reset-password skips it", IDOR where one user reads another's data).
- Live secrets committed in these files (not placeholders/fixtures).
- Backdoor-ish or clearly malicious code.
</what_to_find>
<hard_rules>
- Report an authz issue ONLY if you can state {{entry point, the missing check, a concrete exploit
  path, a NAMED victim, the exact reproducing request, and the fix}}. If you cannot, do NOT report it.
- Report a secret ONLY if you can say concretely why it is a real live secret, not a placeholder.
- Never guess. Never report "could be" or "might be". No finding without a concrete exploit/impact.
- confidence is "high" ONLY when you are certain it is exploitable. Lower confidence findings are dropped.
- Neutral, plain English. Describe who is harmed and how. No CVE/jargon padding.
</hard_rules>
<files note="The security-critical files of this repo. Audit ONLY these.">
{files_xml}
</files>
<task>Return authz_findings[], secret_findings[], backdoor_findings[]. Empty lists if nothing real.</task>"""


# ---------------------------------------------------------------- github fetch

def _gh_headers(token):
    return {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}


def fetch_file(repo_path, filename, branch, headers):
    params = {"ref": branch} if branch else None
    r = requests.get(f"{GITHUB_API}/repos/{repo_path}/contents/{filename}",
                     headers=headers, params=params, timeout=HTTP_TIMEOUT)
    time.sleep(RATE_SLEEP)
    if r.status_code != 200:
        return None
    try:
        data = r.json()
        if data.get("encoding") == "base64" and data.get("content"):
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")[:FILE_CHAR_CAP]
    except Exception as e:
        print(f"⚠️ decode {filename}: {e}")
    return None


def collect_queue_files(queue, repo_path):
    """Flatten the per-PR tripwire queue down to the set of auth-touched file paths for this repo,
    and return (files, remaining_queue) — entries for this repo are consumed."""
    files, remaining = [], []
    for item in (queue or []):
        if item.get("repo") == repo_path:
            files.extend(item.get("files") or [])
        else:
            remaining.append(item)
    # dedupe preserve order
    seen, uniq = set(), []
    for p in files:
        if p and p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq, remaining


def run_audit(model_name, repo_path, brain_profile, files):
    """One model call; gate the results. Returns a list of candidate findings (gated)."""
    try:
        result = waveassist.call_llm(model=model_name, prompt=build_audit_prompt(repo_path, brain_profile, files),
                                     response_model=AuditResult, should_retry=True, max_tokens=MAX_AUDIT_TOKENS)
    except Exception as e:
        print(f"⚠️ audit LLM failed for {repo_path}: {e}")
        return []
    if result is None:
        return []
    out = []
    for f in result.authz_findings:
        d = f.model_dump(); d.update({"category": "authz", "repo": repo_path,
                                      "title": f"Bypassable check: {f.entry_point}",
                                      "entry_point": f.entry_point, "path": "", "severity": "high"})
        if audit_gate(d):
            out.append(d)
    for f in result.secret_findings:
        d = f.model_dump(); d.update({"category": "secret", "repo": repo_path,
                                      "title": f"Live secret in {f.path}", "severity": "high"})
        if audit_gate(d):
            out.append(d)
    for f in result.backdoor_findings:
        d = f.model_dump(); d.update({"category": "backdoor", "repo": repo_path,
                                      "title": f"Suspicious code in {f.path}", "severity": "high"})
        if audit_gate(d):
            out.append(d)
    return out


# ---------------------------------------------------------------- driver (flat, fall-through)

skip = waveassist.fetch_data("security_skip_run", run_based=True, default="0") == "1"
repositories = [] if skip else (waveassist.fetch_data("github_selected_resources", default=[]) or [])

if skip:
    print("GitZoid Security: security_skip_run set; deep_security_audit no-op.")

if repositories:
    access_token = waveassist.fetch_data("github_access_token", default="") or ""
    model_name = waveassist.fetch_data("model_name", default=DEFAULT_MODEL) or DEFAULT_MODEL
    headers = _gh_headers(access_token)
    audit_state = waveassist.fetch_data("security_audit_state", default={}) or {}
    queue = waveassist.fetch_data("security_audit_queue", default=[]) or []

    # Repos due for audit, oldest-audited first, so a large fleet rotates fairly across days.
    repo_paths = [(r.get("id") if isinstance(r, dict) else r) for r in repositories]
    repo_paths = [r for r in repo_paths if r]
    due = [r for r in repo_paths if needs_audit(audit_state.get(r))]
    due.sort(key=lambda r: (audit_state.get(r) or {}).get("last_audit_at", ""))

    candidates = []
    started = time.monotonic()
    for repo_path in due:
        if time.monotonic() - started > RUN_TIME_BUDGET_SECONDS:
            print("GitZoid Security: audit time budget reached; remaining repos resume next tick.")
            break
        try:
            profile = waveassist.fetch_data(f"profile:{repo_path}", default={}) or {}
            branch = (profile.get("_fingerprint") or {}).get("branch") or ""
            queue_files, queue = collect_queue_files(queue, repo_path)
            paths = select_audit_files(profile, queue_files)
            if not paths:
                print(f"✓ {repo_path}: no security-critical files to audit; marking done")
            files = {}
            for p in paths:
                c = fetch_file(repo_path, p, branch, headers)
                if c:
                    files[p] = c
            repo_findings = run_audit(model_name, repo_path, profile, files) if files else []
            candidates.extend(repo_findings)
            audit_state[repo_path] = {"last_audit_at": datetime.now(timezone.utc).isoformat(),
                                      "last_audit_branch": branch}
            print(f"✓ {repo_path}: deep audit done, {len(repo_findings)} finding(s)")
        except Exception as e:
            print(f"⚠️ deep audit failed for {repo_path}: {e}; skipping repo")
            continue

    waveassist.store_data("security_audit_state", audit_state, data_type="json")
    waveassist.store_data("security_audit_queue", queue, data_type="json")   # consumed entries removed
    existing = waveassist.fetch_data("security_candidates", run_based=True, default=[]) or []
    waveassist.store_data("security_candidates", existing + candidates,
                          run_based=True, data_type="json")
    print(f"GitZoid Security: deep_security_audit produced {len(candidates)} candidate(s).")
