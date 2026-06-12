"""
deep_security_audit.py — the weekly, brain-scoped deep code audit (Security chain, node 3).

It lives in the daily Security chain but only does work for a repo once every 7 days
(self-throttled via `security_audit_state`, the study_repos pattern), processing repos
oldest-audited-first within a time budget so it never brushes the broker window.

For each due repo it builds a SCOPE by gathering a broad candidate pool — deterministic security
discovery over the repo tree (path keywords) + the brain's key files/secret locations + the PR
tripwire queue — then ranks every file by security risk (changed-since-last-audit boosted) and
greedily packs the top files into a ~100K-token budget. The brain is one signal among many, so a
noisy brain run can't blank the scope (the old failure mode). It then asks the configured model to
find the class no scanner can: bypassable auth / broken access control, backdoor-ish code, and live
secrets. A finding survives ONLY if it carries a concrete
{entry point → exploit path → named victim → fix} (authz), a real non-placeholder secret, or
concrete backdoor signals — at high confidence. Survivors are appended to the run-based
`security_candidates` key for triage_and_alert; the audit never emails directly.

Conventions: flat script, no __main__ guard, init() first, no sibling imports, fall-through on
empty. Every external call has a timeout; one bad repo never sinks the batch.
"""
import re
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
AUDIT_SAFETY_DAYS = 8   # a missed audit-day still runs within ~a week (safety net)
MAX_AUDIT_TOKENS = 4096
RUN_TIME_BUDGET_SECONDS = 1200      # ~20 min: overflow repos resume next daily tick

# Scope budget: gather a broad, deterministically-discovered candidate pool, rank by security risk,
# then greedily pack the top files into a token budget. The brain is ONE signal among many (path
# discovery + changed-since-last-audit + tripwire + secrets), so a noisy brain run can't blank the
# scope. Start conservative; these are the main cost/coverage levers.
TOKEN_BUDGET = 100_000              # ~100K input tokens of security-dense code per repo / week
PER_FILE_CHAR_CAP = 18_000          # cap one file so a giant file can't eat the budget (~4.5K tokens)
MAX_FILES = 40                      # sanity bound on file count
CHARS_PER_TOKEN = 4                 # rough token estimate from char length
TREE_BLOB_CAP = 4000               # cap on tree entries scanned (rate-limit care)

# Security path keywords → weight. Strong access-control terms outrank generic ones, so the ranker
# puts the real authz/secret files first.
SECURITY_PATH_WEIGHTS = {
    "auth": 5, "login": 5, "permission": 5, "rbac": 5, "authz": 5, "access": 5, "session": 4,
    "middleware": 4, "token": 4, "jwt": 4, "oauth": 4, "admin": 4, "credential": 4, "password": 4,
    "crypto": 4, "secret": 4, "security": 4, "otp": 4, "reset": 3, "webhook": 3, "payment": 3,
    "billing": 3, "route": 2, "router": 2, "api": 2, "endpoint": 2, "handler": 2, "view": 2,
    "controller": 2, "config": 2, "settings": 2,
}
CODE_EXTS = (".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".go", ".rb", ".java", ".php", ".cs",
             ".rs", ".kt", ".scala", ".c", ".cc", ".cpp", ".h")
EXCLUDE_SUBSTR = ("test", "spec", "node_modules", "vendor", "dist", "/build/", ".venv", "site-packages",
                  "migrations", "__mocks__", ".min.", "generated", ".d.ts", "fixture", "mock", "/docs/",
                  "example", "sample")


# ---------------------------------------------------------------- throttle

def needs_audit(state_entry, now=None, audit_weekday=0) -> bool:
    """Due if: never audited (FIRST run, so users see the audit right after setup); OR it's the
    configured audit weekday and we have not already run today; OR a safety window elapsed (so a
    missed weekday still runs within ~a week). audit_weekday: Mon=0 .. Sun=6."""
    if not state_entry or not state_entry.get("last_audit_at"):
        return True
    now = now or datetime.now(timezone.utc)
    try:
        last = datetime.fromisoformat(state_entry["last_audit_at"])
    except Exception:
        return True
    if last.date() == now.date():
        return False                          # already audited today
    if now.weekday() == audit_weekday:
        return True                           # scheduled audit day
    return (now - last).days >= AUDIT_SAFETY_DAYS


# ---------------------------------------------------------------- scope: gather → rank → pack

def is_code_file(path: str) -> bool:
    """A source file worth auditing: a code extension, not a test/vendor/generated/doc file."""
    p = (path or "").lower()
    if not p.endswith(CODE_EXTS):
        return False
    return not any(s in p for s in EXCLUDE_SUBSTR)


def path_security_score(path: str) -> int:
    """Sum the weights of every security keyword present in the path (0 = not security-relevant)."""
    p = (path or "").lower()
    return sum(w for kw, w in SECURITY_PATH_WEIGHTS.items() if kw in p)


def gather_candidates(tree_paths, brain_profile, changed_files, queue_files):
    """Build the ranked candidate pool. A file QUALIFIES if it has a security-keyword path, is a brain
    key file, is a declared secret location, or was queued by the PR tripwire. 'changed since last
    audit' is a ranking BOOST on qualified files (so we audit relevant changes first) — a changed file
    with no security signal is NOT pulled in. Returns [{path, score, changed, queued}] sorted desc."""
    brain = brain_profile or {}
    changed = {p for p in (changed_files or []) if p}
    queued = {p for p in (queue_files or []) if p}
    key_files = {(kf.get("path") or "") for kf in (brain.get("key_files") or []) if kf.get("path")}
    secrets = {s for s in (((brain.get("security") or {}).get("secret_locations")) or []) if s}

    pool = set()
    pool |= {p for p in (tree_paths or []) if is_code_file(p)}     # deterministic discovery
    pool |= {p for p in key_files if p}
    pool |= {p for p in secrets if "/" in p or "." in p}
    pool |= queued

    candidates = []
    for p in pool:
        is_key = p in key_files
        in_secrets = p in secrets
        is_queued = p in queued
        path_score = path_security_score(p)
        # qualify: a security-keyword path, OR an explicitly-flagged file (key/secret/queued)
        if not (path_score > 0 or is_key or in_secrets or is_queued):
            continue
        is_changed = p in changed
        score = (path_score
                 + (10 if is_queued else 0)
                 + (8 if is_changed else 0)
                 + (4 if in_secrets else 0)
                 + (3 if is_key else 0))
        candidates.append({"path": p, "score": score, "changed": is_changed, "queued": is_queued})
    candidates.sort(key=lambda c: (-c["score"], c["path"]))
    return candidates


def pack_to_budget(ranked, sizes, token_budget=TOKEN_BUDGET, per_file_cap=PER_FILE_CHAR_CAP,
                   max_files=MAX_FILES, chars_per_token=CHARS_PER_TOKEN):
    """Greedily select top-ranked files until the token budget or file cap is hit. Each file's cost is
    estimated from its byte size, capped at per_file_cap. Skips an over-budget file but keeps trying
    smaller lower-ranked ones. Returns (selected_paths, dropped_count)."""
    selected, total_tokens, dropped = [], 0, 0
    for c in ranked:
        if len(selected) >= max_files:
            dropped += 1
            continue
        size_chars = min(sizes.get(c["path"], per_file_cap), per_file_cap)
        est_tokens = size_chars / chars_per_token
        if total_tokens + est_tokens > token_budget:
            dropped += 1
            continue
        selected.append(c["path"])
        total_tokens += est_tokens
    return selected, dropped


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
- Do not overstate access barriers: say "unauthenticated" ONLY if the route truly needs no credential
  of any kind. If a shared/system token or any auth gate exists, say "without the per-user authorization
  check" instead.
- Writing style: plain prose in short sentences. Do NOT use em dashes, and do not use a hyphen as a
  connector between clauses. No emojis.
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
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")[:PER_FILE_CHAR_CAP]
    except Exception as e:
        print(f"⚠️ decode {filename}: {e}")
    return None


def get_head_sha(repo_path, branch, headers):
    """Current tip SHA of the audited branch (used to diff against last_audit_sha)."""
    ref = branch or "HEAD"
    r = requests.get(f"{GITHUB_API}/repos/{repo_path}/commits/{ref}", headers=headers, timeout=HTTP_TIMEOUT)
    time.sleep(RATE_SLEEP)
    return r.json().get("sha") if r.status_code == 200 else None


def get_repo_tree(repo_path, branch, headers):
    """Recursive tree of the branch → {path: size_bytes} for code blobs (for deterministic discovery
    and budget packing without fetching content)."""
    ref = branch or "HEAD"
    r = requests.get(f"{GITHUB_API}/repos/{repo_path}/git/trees/{ref}?recursive=1",
                     headers=headers, timeout=HTTP_TIMEOUT)
    time.sleep(RATE_SLEEP)
    if r.status_code != 200:
        return {}
    out = {}
    for it in (r.json().get("tree", []) or [])[:TREE_BLOB_CAP]:
        if it.get("type") == "blob" and it.get("path"):
            out[it["path"]] = it.get("size", 0) or 0
    return out


def fetch_changed_files(repo_path, base_sha, head_sha, headers):
    """Files changed between the last audit and now (Compare API). Returns a list of paths, or None
    if we have no prior SHA (→ caller treats the full security surface as scope)."""
    if not base_sha or not head_sha or base_sha == head_sha:
        return [] if base_sha == head_sha else None
    paths, page = [], 1
    while True:
        r = requests.get(f"{GITHUB_API}/repos/{repo_path}/compare/{base_sha}...{head_sha}",
                         headers=headers, params={"per_page": 100, "page": page}, timeout=HTTP_TIMEOUT)
        if r.status_code != 200:
            return None        # compare failed (e.g. force-push) → fall back to full surface
        files = (r.json().get("files") or [])
        paths += [f.get("filename") for f in files if f.get("filename")]
        if "next" not in (r.links or {}):
            break
        page += 1
        time.sleep(RATE_SLEEP)
    return paths


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


def _route_dedup_key(entry_point):
    """A STABLE identity for an authz finding: the route path(s) it names, not the model's prose
    (which varies week to week). So the same bug keeps one identity and is not re-alerted."""
    routes = re.findall(r"/[A-Za-z0-9_]{2,}[A-Za-z0-9_./-]*", entry_point or "")
    if routes:
        return ",".join(sorted(set(routes)))
    return " ".join((entry_point or "").lower().split())[:60]


def run_audit(model_name, repo_path, brain_profile, files):
    """One model call; gate the results. Returns a list of candidate findings (gated). Each carries a
    stable `dedup_key` (location-based) so triage dedupes it across runs regardless of wording."""
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
                                      "entry_point": f.entry_point, "path": "", "severity": "high",
                                      "dedup_key": "authz:" + _route_dedup_key(f.entry_point)})
        if audit_gate(d):
            out.append(d)
    for f in result.secret_findings:
        d = f.model_dump(); d.update({"category": "secret", "repo": repo_path,
                                      "title": f"Live secret in {f.path}", "severity": "high",
                                      "dedup_key": "secret:" + (f.path or "")})
        if audit_gate(d):
            out.append(d)
    for f in result.backdoor_findings:
        d = f.model_dump(); d.update({"category": "backdoor", "repo": repo_path,
                                      "title": f"Suspicious code in {f.path}", "severity": "high",
                                      "dedup_key": "backdoor:" + (f.path or "")})
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
    try:
        audit_weekday = int(waveassist.fetch_data("audit_day", default="0") or "0")
    except (TypeError, ValueError):
        audit_weekday = 0
    if not (0 <= audit_weekday <= 6):
        audit_weekday = 0

    # Repos due for audit (first run + configured weekday), oldest-audited first so a large fleet
    # rotates fairly across days.
    repo_paths = [(r.get("id") if isinstance(r, dict) else r) for r in repositories]
    repo_paths = [r for r in repo_paths if r]
    due = [r for r in repo_paths if needs_audit(audit_state.get(r), audit_weekday=audit_weekday)]
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
            prev = audit_state.get(repo_path) or {}

            head_sha = get_head_sha(repo_path, branch, headers)
            changed = fetch_changed_files(repo_path, prev.get("last_audit_sha"), head_sha, headers)
            tree = get_repo_tree(repo_path, branch, headers)          # {path: size}
            queue_files, queue = collect_queue_files(queue, repo_path)

            # gather a broad pool (tree discovery + brain + secrets + queue), rank by risk with
            # changed files boosted, then greedily pack the top into the token budget.
            ranked = gather_candidates(list(tree.keys()), profile, changed or [], queue_files)
            selected, dropped = pack_to_budget(ranked, tree)
            n_changed = len(changed) if changed is not None else 0
            print(f"  {repo_path}: {len(ranked)} candidate file(s), {n_changed} changed; "
                  f"auditing {len(selected)}, dropped {dropped} (budget)")

            files = {}
            for p in selected:
                c = fetch_file(repo_path, p, branch, headers)
                if c:
                    files[p] = c
            repo_findings = run_audit(model_name, repo_path, profile, files) if files else []
            candidates.extend(repo_findings)
            audit_state[repo_path] = {"last_audit_at": datetime.now(timezone.utc).isoformat(),
                                      "last_audit_branch": branch, "last_audit_sha": head_sha}
            print(f"✓ {repo_path}: deep audit done over {len(files)} file(s), {len(repo_findings)} finding(s)")
        except Exception as e:
            print(f"⚠️ deep audit failed for {repo_path}: {e}; skipping repo")
            continue

    waveassist.store_data("security_audit_state", audit_state, data_type="json")
    waveassist.store_data("security_audit_queue", queue, data_type="json")   # consumed entries removed
    existing = waveassist.fetch_data("security_candidates", run_based=True, default=[]) or []
    waveassist.store_data("security_candidates", existing + candidates,
                          run_based=True, data_type="json")
    print(f"GitZoid Security: deep_security_audit produced {len(candidates)} candidate(s).")
