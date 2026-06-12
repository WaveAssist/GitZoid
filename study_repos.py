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


def _flag_is_set(value):
    """Parse a run-based flag from the store. The SDK serialises a JSON-stored scalar as
    {"value": "True"/"False"} and returns that DICT, so a bare bool(...) is ALWAYS truthy — unwrap
    and compare the string. Accepts raw bools too."""
    if isinstance(value, dict):
        value = value.get("value")
    return str(value).strip().lower() in ("true", "1", "yes")

GITHUB_API = "https://api.github.com"
HTTP_TIMEOUT = 20
RATE_SLEEP = 0.2
STALE_BRANCH_LEAD_DAYS = 14
PROFILE_TTL_DAYS = 14                # brain refreshes every 14 days (time-based, not on SHA change)
TREE_BLOB_CAP = 800
FILE_CHAR_CAP = 10000
MAX_ACTIVE_BRANCH_SCAN = 10          # cap branch date lookups (rate-limit care)
# The brain is rare (weekly) + quality-critical, so it uses a strong model decoupled from the
# cheaper per-PR review model. Optional override via the "brain_model" data key.
BRAIN_MODEL = "anthropic/claude-sonnet-4.6"

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


def get_default_branch(repo_path, headers):
    r = _gh_get(f"{GITHUB_API}/repos/{repo_path}", headers)
    if r.status_code != 200:
        print(f"⚠️ repo meta {repo_path}: {r.status_code}")
        return None
    return r.json().get("default_branch")


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
    """Pick the ONE branch to profile. Returns {branch, sha, source[, suggestion]}.
    source in {override, default, active-fallback, none}. Staleness only yields a suggestion."""
    branches = list_branches(repo_path, headers)
    names = {b["name"]: b for b in branches}

    if override and override in names:
        return {"branch": override, "sha": names[override]["commit_sha"], "source": "override"}
    if override:
        print(f"⚠️ override branch '{override}' not on {repo_path}; ignoring")

    default = get_default_branch(repo_path, headers)
    if default and default in names:
        chosen = {"branch": default, "sha": names[default]["commit_sha"], "source": "default"}
        active = most_active_branch(repo_path, branches, headers)
        if active and active["name"] != default:
            d_date = branch_tip_date(repo_path, names[default]["commit_sha"], headers)
            if d_date and active["date"] > d_date and \
                    _days_between(d_date, active["date"]) >= STALE_BRANCH_LEAD_DAYS:
                chosen["suggestion"] = (
                    f"Branch '{active['name']}' is ~{_days_between(d_date, active['date'])}d more "
                    f"recent than default '{default}'. Set the 'branch' override to profile it.")
        return chosen

    active = most_active_branch(repo_path, branches, headers)
    if active:
        return {"branch": active["name"], "sha": active["commit_sha"], "source": "active-fallback"}
    return {"branch": None, "sha": None, "source": "none"}


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
# existing repo_groups / brain. The flag is written run-based and the SDK wraps a JSON scalar as
# {"value": "..."}, so it MUST be read run-based and unwrapped (bare bool() of the dict is always True).
skip_run = _flag_is_set(waveassist.fetch_data("skip_run", run_based=True, default=False))
if skip_run:
    print("GitZoid: skip_run set; study_repos no-op (another run in progress).")

repositories = [] if skip_run else (waveassist.fetch_data("github_selected_resources", default=[]) or [])
access_token = waveassist.fetch_data("github_access_token", default="") or ""
model_name = waveassist.fetch_data("brain_model", default=BRAIN_MODEL)
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
            RepoContextProfileV2, attempts=3)
        profile_dict = _sanitize_profile(profile.model_dump())
        profile_dict["_fingerprint"] = {"sha": chosen["sha"], "branch": chosen["branch"],
                                        "built_at": datetime.now(timezone.utc).isoformat(),
                                        "tree_truncated": truncated}
        if chosen.get("suggestion"):
            profile_dict["_branch_suggestion"] = chosen["suggestion"]
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
