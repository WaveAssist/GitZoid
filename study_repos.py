"""
study_repos.py — GitZoid's per-repo "brain" builder (starting node, weekly schedule).

For each connected repo it picks one canonical branch, fetches a small, security-relevant
slice of the codebase, and distills a durable `repo_context_profile_v2` profile stored under
the additive key  profile:{owner/repo}.  Downstream nodes (fetch_pull_requests, generate_review)
read that profile to make reviews and security checks repo-aware.

Conventions: flat script, no __main__ guard, no sibling-node imports. Credits are gated once
upstream in check_credits_and_init (the single starting node), so this node just init()s. The
driver falls through on empty/missing input — it never calls exit()/SystemExit (which would
leave the run STARTED).
"""
import time
import base64
from datetime import datetime, timezone
from typing import List, Literal
import requests
from pydantic import BaseModel, Field
import waveassist

waveassist.init()   # credits already gated upstream in check_credits_and_init

print("Processing GitZoid brain build (study_repos) node")

GITHUB_API = "https://api.github.com"
HTTP_TIMEOUT = 20
RATE_SLEEP = 0.2
# Default to the canonical branch; only switch to a more-recent branch (even a feature branch) if it
# leads the canonical one by at least this many days. So a long-stale main yields to active dev, but a
# branch that is merely a little ahead does not pull profiling off the trunk.
BRANCH_SWITCH_LEAD_DAYS = 30
# Branch names treated as canonical "trunk" lines, used as the fallback when GitHub's default-branch
# lookup fails. Exact names plus the release/* family.
STANDARD_BRANCH_NAMES = ("main", "master", "develop", "dev", "uat",
                         "staging", "stage", "production", "prod", "trunk")
STANDARD_BRANCH_PREFIXES = ("release/", "releases/")
PROFILE_TTL_DAYS = 14                # brain refreshes every 14 days (time-based, not on SHA change)
TREE_BLOB_CAP = 800
FILE_CHAR_CAP = 10000
MAX_ACTIVE_BRANCH_SCAN = 10          # cap branch date lookups (rate-limit care)
# The brain is repo CONTEXT (architecture/conventions/deps) consumed by other nodes, not a user-facing
# artifact, so it runs on the cheaper, faster Haiku to save credits — it is also the biggest token
# consumer (it reads the repo). Decoupled from the per-PR review model; optional override via the
# "lite_model" data key.
LITE_MODEL = "anthropic/claude-haiku-4.5"

KEY_FILE_HINTS = ("auth", "login", "session", "security", "middleware",
                  "route", "router", "api", "settings", "config", "server", "app")
MANIFEST_PATTERNS = ["requirements.txt", "pyproject.toml", "Pipfile", "package.json",
                     "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "Gemfile", "composer.json"]
README_PATTERNS = ["README.md", "README.rst", "README.txt", "README", "readme.md"]


def _days_between(iso_a: str, iso_b: str) -> int:
    """Absolute whole-day difference between two ISO timestamps (Z or +00:00)."""
    def p(s):
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    return abs((p(iso_b) - p(iso_a)).days)


# ---------------------------------------------------------------- profile schema

Ecosystem = Literal["pypi", "npm", "go", "cargo", "maven", "gradle",
                    "rubygems", "nuget", "composer", "other"]


class Dependency(BaseModel):
    name: str = Field(description="Package name exactly as it appears in the manifest")
    version: str = Field(description="Pinned/declared version or range; 'unknown' if not specified")
    ecosystem: Ecosystem = Field(description="Package ecosystem the dependency belongs to")
    in_auth_path: bool = Field(description="True only if used in auth/authz/session/crypto/token code")
    used: bool = Field(description="True if actually imported/used in shown code; False if only declared")


class AuthRoute(BaseModel):
    route: str = Field(description="HTTP method + path or handler name, e.g. 'POST /api/login'")
    unauthenticated: bool = Field(description="True if reachable WITHOUT authentication")


class SecuritySurface(BaseModel):
    routes: List[AuthRoute] = Field(description="Up to 12 most security-relevant routes/handlers")
    secret_locations: List[str] = Field(
        description="Paths/env-vars where secrets are read/stored, e.g. '.env'. Empty list if none.")


class StackInfo(BaseModel):
    languages: List[str] = Field(description="Primary programming languages, most-used first")
    frameworks: List[str] = Field(
        description="Web/app frameworks and stack-defining libraries (e.g. Django, React, Litestar, Celery)")
    datastores: List[str] = Field(
        description="Databases, caches, queues used (e.g. PostgreSQL, Redis, MongoDB). Empty list if none.")
    infrastructure: List[str] = Field(
        description="Deploy/runtime/infra signals (e.g. Docker, AWS, GitHub Actions, Vercel). Empty list if none.")
    package_managers: List[str] = Field(
        description="Package managers / build tools (e.g. pip, npm, poetry, pnpm)")


class KeyFile(BaseModel):
    path: str = Field(description="Repo-relative path of an important file (entry point, core logic, config, auth)")
    role: str = Field(description="One concise sentence: what this file is responsible for")


class Component(BaseModel):
    name: str = Field(description="A major module/area, e.g. 'authentication', 'API layer', 'payments', 'worker'")
    responsibility: str = Field(description="One sentence on what this component does")


class RepoContextProfileV2(BaseModel):
    """Canonical single-branch repository profile (the 'brain'). Schema version v2."""
    schema_version: Literal["repo_context_profile_v2"] = Field(
        description="Always the literal string 'repo_context_profile_v2'")
    architecture_summary: str = Field(
        description="3-5 sentences: what the repo does, architecture, primary language/framework, data flow")
    stack: StackInfo = Field(description="The concrete technology stack actually present in the repo")
    components: List[Component] = Field(
        description="Up to 8 major modules/areas of the codebase and what each is responsible for")
    key_files: List[KeyFile] = Field(
        description="Up to 10 of the most important files (entry points, core logic, config, auth) a new "
                    "engineer should read first, each with its role")
    conventions: List[str] = Field(
        description="Up to 8 concrete, observable conventions a reviewer should enforce. No generic advice.")
    dependencies: List[Dependency] = Field(
        description="Notable deps from manifest(s). Cap 30, prioritise auth/security/network/DB.")
    security: SecuritySurface = Field(description="Security and auth surface of the repository")
    review_focus: List[str] = Field(
        description="Up to 5 areas a PR reviewer should focus on for THIS repo")


# ---------------------------------------------------------------- github helpers

def _gh_get(url, headers, params=None):
    return requests.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)


def get_default_branch(repo_path, headers, attempts=2):
    """GitHub's configured default branch, with a light retry. A transient non-200 (rate limit /
    network blip) must NOT be read as 'no default' — that would silently push branch selection onto a
    feature branch. Returns the branch name, or None only after every attempt fails."""
    for i in range(attempts):
        r = _gh_get(f"{GITHUB_API}/repos/{repo_path}", headers)
        if r.status_code == 200:
            return r.json().get("default_branch")
        print(f"⚠️ repo meta {repo_path}: {r.status_code} (attempt {i + 1}/{attempts})")
        if i < attempts - 1:
            time.sleep(RATE_SLEEP)
    return None


def _is_standard_branch(name):
    """True for canonical 'trunk' names (main/master/dev/uat/staging/...) and the release/* family."""
    n = (name or "").lower()
    return n in STANDARD_BRANCH_NAMES or any(n.startswith(p) for p in STANDARD_BRANCH_PREFIXES)


def most_recent_standard_branch(repo_path, branches, headers):
    """Most recently committed branch among STANDARD-named branches — the canonical fallback when the
    default-branch lookup fails. Bounded: only standard-named branches are date-checked (and at most
    MAX_ACTIVE_BRANCH_SCAN of them) to keep API/rate-limit cost down."""
    std = [b for b in branches if _is_standard_branch(b.get("name"))][:MAX_ACTIVE_BRANCH_SCAN]
    best = None
    for b in std:
        d = branch_tip_date(repo_path, b["commit_sha"], headers)
        if d and (best is None or d > best["date"]):
            best = {**b, "date": d}
    return best


def list_branches(repo_path, headers, max_pages=5):
    branches, page = [], 1
    while page <= max_pages:
        r = _gh_get(f"{GITHUB_API}/repos/{repo_path}/branches", headers,
                    params={"per_page": 100, "page": page})
        if r.status_code != 200:
            break
        chunk = r.json()
        if not chunk:
            break
        for b in chunk:
            branches.append({"name": b["name"], "commit_sha": b.get("commit", {}).get("sha")})
        if "next" not in r.links:
            break
        page += 1
    return branches


def branch_tip_date(repo_path, sha, headers):
    if not sha:
        return None
    r = _gh_get(f"{GITHUB_API}/repos/{repo_path}/commits/{sha}", headers)
    time.sleep(RATE_SLEEP)
    if r.status_code != 200:
        return None
    return r.json().get("commit", {}).get("committer", {}).get("date")


def most_active_branch(repo_path, branches, headers):
    """Most recently committed branch, scanning at most MAX_ACTIVE_BRANCH_SCAN branches."""
    best = None
    for b in branches[:MAX_ACTIVE_BRANCH_SCAN]:
        d = branch_tip_date(repo_path, b["commit_sha"], headers)
        if d and (best is None or d > best["date"]):
            best = {**b, "date": d}
    return best


def select_canonical_branch(repo_path, headers, override=""):
    """Pick the ONE branch to profile. Returns {branch, sha, source[, note]}.

    Preference order:
      1. explicit override (if it exists on the repo),
      2. the CANONICAL branch — GitHub's default branch, or, if that lookup fails, the most-recently
         committed STANDARD-named branch (main/master/dev/uat/staging/release-*) — never a feature
         branch by default,
      3. UNLESS some branch leads the canonical one by >= BRANCH_SWITCH_LEAD_DAYS days, in which case
         that more-recent branch wins (so an actively developed branch is profiled instead of a long
         stale trunk; a branch only a little ahead does not pull profiling off the trunk).
    source in {override, default, standard-fallback, recent-lead, active-fallback, none}."""
    branches = list_branches(repo_path, headers)
    names = {b["name"]: b for b in branches}

    if override and override in names:
        return {"branch": override, "sha": names[override]["commit_sha"], "source": "override"}
    if override:
        print(f"⚠️ override branch '{override}' not on {repo_path}; ignoring")

    # 1. Canonical = GitHub default branch; if that can't be resolved, the most-recent standard branch.
    default = get_default_branch(repo_path, headers)
    if default and default in names:
        canonical = {"branch": default, "sha": names[default]["commit_sha"], "source": "default"}
    else:
        std = most_recent_standard_branch(repo_path, branches, headers)
        canonical = ({"branch": std["name"], "sha": std["commit_sha"], "source": "standard-fallback"}
                     if std else None)

    # 2. Challenger = most recently committed branch overall (may be a feature branch).
    challenger = most_active_branch(repo_path, branches, headers)

    # 3. No canonical at all (no default, no standard branch) → last-resort most-active branch.
    if not canonical:
        if challenger:
            return {"branch": challenger["name"], "sha": challenger["commit_sha"], "source": "active-fallback"}
        return {"branch": None, "sha": None, "source": "none"}

    # 4. Switch off the canonical branch ONLY if another branch leads it by >= BRANCH_SWITCH_LEAD_DAYS.
    if challenger and challenger["name"] != canonical["branch"]:
        canonical_date = branch_tip_date(repo_path, canonical["sha"], headers)
        if canonical_date and challenger["date"] > canonical_date:
            lead = _days_between(canonical_date, challenger["date"])
            if lead >= BRANCH_SWITCH_LEAD_DAYS:
                return {"branch": challenger["name"], "sha": challenger["commit_sha"],
                        "source": "recent-lead",
                        "note": (f"Profiling '{challenger['name']}' instead of '{canonical['branch']}': "
                                 f"it is ~{lead}d more recent.")}

    return canonical


def get_branch_tree(repo_path, branch, headers):
    """Return (blob_paths, truncated). Records GitHub's truncated flag."""
    r = _gh_get(f"{GITHUB_API}/repos/{repo_path}/git/trees/{branch}?recursive=1", headers)
    time.sleep(RATE_SLEEP)
    if r.status_code != 200:
        return [], False
    data = r.json()
    truncated = bool(data.get("truncated"))
    paths = [it.get("path", "") for it in data.get("tree", [])[:TREE_BLOB_CAP]
             if it.get("type") == "blob"]
    if truncated:
        print(f"⚠️ tree truncated for {repo_path}@{branch}; key-file picks may be partial")
    return paths, truncated


def get_file_content(repo_path, file_path, branch, headers):
    r = _gh_get(f"{GITHUB_API}/repos/{repo_path}/contents/{file_path}", headers,
                params={"ref": branch})
    time.sleep(RATE_SLEEP)
    if r.status_code != 200:
        return None
    try:
        data = r.json()
        if data.get("encoding") == "base64" and data.get("content"):
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")[:FILE_CHAR_CAP]
    except Exception as e:
        print(f"⚠️ decode {file_path}: {e}")
    return None


def pick_key_files(file_list, limit=4):
    cand = [f for f in file_list
            if f.endswith((".py", ".js", ".ts", ".go", ".rb", ".java"))
            and not any(s in f.lower() for s in ("test", "node_modules", "vendor", "dist", "/.venv"))
            and any(h in f.lower() for h in KEY_FILE_HINTS)]
    return cand[:limit]


def find_and_fetch(repo_path, file_list, patterns, branch, headers):
    lower = {f.lower(): f for f in file_list}
    for pat in patterns:
        for low, orig in lower.items():
            if low.endswith(pat.lower()):
                c = get_file_content(repo_path, orig, branch, headers)
                if c:
                    return c
    return None


# ---------------------------------------------------------------- prompt + profile build

def build_brain_prompt(repo_path, branch, readme, manifests, key_files, file_list):
    def block(title, body):
        return f"<{title}>\n{body or '(none)'}\n</{title}>" if body else ""
    files_xml = "\n".join(block(f'file path="{p}"', c) for p, c in key_files.items())
    return f"""<role>
You are a senior security-aware code reviewer building a durable profile of a repository.
Profile EXACTLY what is shown. Never invent files, routes, or dependencies you do not see.
</role>
<context><repository>{repo_path}</repository><branch>{branch}</branch></context>
<task>
Produce a repo_context_profile_v2 describing: the architecture, the concrete tech STACK
(languages, frameworks, datastores, infrastructure, package managers), the major COMPONENTS
and their responsibilities, the most important KEY FILES and their roles, conventions,
dependencies, secret locations, the auth/route surface, and per-repo review focus areas.
</task>
<rules>
- High confidence only. If unsure a dep is used or a route is unauthenticated, mark used=false / unauthenticated=false.
- stack: only technologies ACTUALLY present (from manifests, file extensions, imports). Do not guess.
- key_files: real paths taken from the file index; the files a new engineer must read first; one concise role each.
- components: real modules/areas of THIS repo, not generic software concepts.
- secret_locations: only real read/store sites of credentials. Ignore placeholders/examples.
- in_auth_path=true only for deps touching auth/session/crypto/token code.
- Cap dependencies at 30 (prioritise auth/security/network/DB), routes at 12, components at 8, key_files at 10, conventions at 8.
- schema_version is literally "repo_context_profile_v2".
</rules>
<repo_files>
{block("readme", readme)}
{block("manifests", manifests)}
{files_xml}
<file_index>
{chr(10).join(file_list[:200])}
</file_index>
</repo_files>"""


def call_llm_with_retry(model, prompt, response_model, attempts=2, sleep_s=2):
    """call_llm with retries; the LLM path (local Claude / OpenRouter) can fail transiently
    (network, cold CLI). attempts>=1; re-raises the last error if every attempt fails."""
    last = None
    for i in range(attempts):
        try:
            # Explicit cap: without it OpenRouter pre-authorizes the model's full output
            # ceiling (64k for Sonnet) against the key's credit limit and 402s near the cap.
            return waveassist.call_llm(model=model, prompt=prompt,
                                       response_model=response_model, should_retry=True,
                                       max_tokens=8000)
        except Exception as e:
            last = e
            print(f"⚠️ call_llm attempt {i + 1}/{attempts} failed: {e}")
            if i < attempts - 1 and sleep_s:
                time.sleep(sleep_s)
    raise last


def _sanitize_profile(p):
    """soft_parse can null-fill omitted required fields; coerce to safe shapes."""
    p = dict(p or {})
    for k in ("conventions", "dependencies", "review_focus", "components", "key_files"):
        if not isinstance(p.get(k), list):
            p[k] = []
    sec = p.get("security")
    if not isinstance(sec, dict):
        sec = {}
    if not isinstance(sec.get("routes"), list):
        sec["routes"] = []
    if not isinstance(sec.get("secret_locations"), list):
        sec["secret_locations"] = []
    p["security"] = sec
    stk = p.get("stack")
    if not isinstance(stk, dict):
        stk = {}
    for sk in ("languages", "frameworks", "datastores", "infrastructure", "package_managers"):
        if not isinstance(stk.get(sk), list):
            stk[sk] = []
    p["stack"] = stk
    if not isinstance(p.get("architecture_summary"), str):
        p["architecture_summary"] = ""
    p["schema_version"] = "repo_context_profile_v2"
    return p


def store_profile(wa, repo_path, profile_dict):
    """Atomic single-key write of one repo's profile."""
    wa.store_data(f"profile:{repo_path}", profile_dict, data_type="json")


# ---------------------------------------------------------------- staleness gate

def needs_rebuild(existing):
    """Time-based refresh (every PROFILE_TTL_DAYS). Rebuild only if the profile is missing, on an
    old schema, or older than the TTL. Deliberately does NOT rebuild on branch SHA changes — the
    brain is a coarse repo profile refreshed on a fixed cadence, not per commit. The rebuild is a
    full fresh regeneration (no diff against the old profile). Checked from the stored profile alone
    (no GitHub call), so it's a cheap no-op when the profile is still fresh."""
    if not existing:
        return True
    if existing.get("schema_version") != "repo_context_profile_v2":
        return True
    built = existing.get("_fingerprint", {}).get("built_at")
    if not built:
        return True
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(built.replace("Z", "+00:00"))).days
    return age >= PROFILE_TTL_DAYS


# ---------------------------------------------------------------- driver (flat, fall-through)

# Single-run lock (set by check_credits_and_init): if another run holds it, this cycle is a no-op.
# Empty repo list short-circuits the loop AND the post-loop stores below, so we never clobber the
# existing repo_groups / brain. Run-based "1"/"0" string written by check_credits_and_init — read it
# run-based so each run sees its OWN flag (a global read would miss the run-scoped write).
skip_run = waveassist.fetch_data("skip_run", run_based=True, default="0") == "1"
if skip_run:
    print("GitZoid: skip_run set; study_repos no-op (another run in progress).")

repositories = [] if skip_run else (waveassist.fetch_data("github_selected_resources", default=[]) or [])
access_token = waveassist.fetch_data("github_access_token", default="") or ""
model_name = waveassist.fetch_data("lite_model", default=LITE_MODEL)
headers = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github+json"}

repo_paths = []
repo_groups = waveassist.fetch_data("repo_groups", default={}) or {}

for repo in repositories:
    repo_path = repo.get("id") if isinstance(repo, dict) else repo
    if not repo_path:
        continue
    repo_paths.append(repo_path)

    # Cheap freshness check FIRST, from the stored profile alone — no GitHub call when the
    # weekly profile is still fresh, so this node is a fast no-op on most 2-min cycles.
    existing = waveassist.fetch_data(f"profile:{repo_path}", default={}) or {}
    if not needs_rebuild(existing):
        print(f"✓ {repo_path} profile fresh; skip")
        continue

    override = (repo.get("properties", {}) or {}).get("branch", "") if isinstance(repo, dict) else ""

    try:
        chosen = select_canonical_branch(repo_path, headers, override=override)
        if not chosen.get("sha"):
            print(f"⚠️ no canonical branch for {repo_path}; skipping")
            continue

        file_list, truncated = get_branch_tree(repo_path, chosen["branch"], headers)
        readme = find_and_fetch(repo_path, file_list, README_PATTERNS, chosen["branch"], headers)
        manifests = find_and_fetch(repo_path, file_list, MANIFEST_PATTERNS, chosen["branch"], headers)
        key_paths = pick_key_files(file_list)
        key_files = {p: get_file_content(repo_path, p, chosen["branch"], headers) for p in key_paths}
        key_files = {p: c for p, c in key_files.items() if c}

        profile = call_llm_with_retry(
            model_name,
            build_brain_prompt(repo_path, chosen["branch"], readme, manifests, key_files, file_list),
            RepoContextProfileV2, attempts=2)   # one retry only — each Claude CLI call costs
        profile_dict = _sanitize_profile(profile.model_dump())
        profile_dict["_fingerprint"] = {"sha": chosen["sha"], "branch": chosen["branch"],
                                        "built_at": datetime.now(timezone.utc).isoformat(),
                                        "tree_truncated": truncated}
        # When selection switched off the canonical branch (recent-lead), record why. Kept under the
        # existing _branch_suggestion key so the dashboard surface is unchanged.
        if chosen.get("note"):
            profile_dict["_branch_suggestion"] = chosen["note"]
        store_profile(waveassist, repo_path, profile_dict)
        repo_groups[repo_path] = {"branch": chosen["branch"],
                                  "built_at": profile_dict["_fingerprint"]["built_at"]}
        print(f"✓ built profile for {repo_path}@{chosen['branch']}")
    except Exception as e:
        # Soft-fail per repo: a transient error on one repo must not sink the whole brain build.
        print(f"⚠️ failed to build profile for {repo_path}: {e}; skipping")
        continue

if not skip_run:
    waveassist.store_data("repo_groups", repo_groups, data_type="json")
    all_profiles = {r: (waveassist.fetch_data(f"profile:{r}", default={}) or {}) for r in repo_paths}
    # Structured payload the dashboard Knowledge tab renders natively (one fetch, dark-theme
    # React UI). Order-preserving; only well-formed v2 profiles are included.
    brain_repos = [
        {"repo": r, "profile": all_profiles[r]}
        for r in repo_paths
        if isinstance(all_profiles.get(r), dict)
        and all_profiles[r].get("schema_version") == "repo_context_profile_v2"
    ]
    built_ats = [b["profile"].get("_fingerprint", {}).get("built_at", "") for b in brain_repos]
    waveassist.store_data("brain", {
        "schema_version": "brain_v1",
        "count": len(brain_repos),
        "built_at": max([b for b in built_ats if b], default=""),
        "repos": brain_repos,
    }, data_type="json")
