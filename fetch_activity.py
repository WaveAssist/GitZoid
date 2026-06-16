"""
fetch_activity.py — the Knowledge Digest chain's GitHub activity collector (node 2).

Adapted from GitDigest's fetch_github_activity, kept faithful to the parts that work: a 7-day window,
GraphQL active-branch detection (only branches with commits after `since`), REST commit fetch from
those branches with SHA dedupe, open/recently-merged PRs, and a bot filter. It does NOT fetch diffs —
analyze_activity reads the actual diffs per commit.

Two GitZoid adaptations:
  - it honours the chain's `digest_skip_run` no-op (an off/overlapping cycle does zero HTTP), and
  - it scopes to the union of repos across `digest_resolved_groups` (the gate already applied the
    implicit single-group fallback), not the raw selection — a globally-deselected repo never gets a
    network round-trip.

Output (additive keys): `github_activity_data` ({repo: {commits, pull_requests}}) and
`report_date_range`. Flat script, no __main__ guard, init() first, fall-through on empty.
"""
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
import requests
import waveassist

waveassist.init()   # credits gated once upstream in digest_check_and_init

print("GitZoid Digest: starting GitHub activity fetch (fetch_activity) node")

GITHUB_API = "https://api.github.com"
GRAPHQL_URL = "https://api.github.com/graphql"
DAYS_TO_FETCH = 7
RATE_SLEEP = 0.5
HTTP_TIMEOUT = 20
MAX_BRANCH_PAGES = 50      # 50 * 100 = 5,000 branches
MAX_COMMIT_PAGES = 10      # 10 * 100 = 1,000 commits per branch

_COMMON_BOTS = {
    "dependabot", "renovate", "github-actions", "codecov", "greenkeeper", "snyk-bot", "mergify",
    "stale", "allcontributors", "imgbot", "semantic-release-bot", "renovate-bot", "dependabot-preview",
}


# ---------------------------------------------------------------- pure helpers (tested)

def is_bot_user(user) -> bool:
    """A commit/PR author is a bot if GitHub types it Bot, its login ends in [bot], or it is a
    well-known automation account."""
    if not user:
        return False
    if user.get("type") == "Bot":
        return True
    login = (user.get("login") or "").lower()
    if login.endswith("[bot]"):
        return True
    return login in _COMMON_BOTS


def parse_commit(commit) -> Dict[str, Any]:
    """Shape one REST commit into our record, or None if it has no SHA or is bot-authored."""
    sha = commit.get("sha", "")
    if not sha:
        return None
    author = commit.get("author") or {}
    committer = commit.get("committer") or {}
    if is_bot_user(author) or is_bot_user(committer):
        return None
    cdata = commit.get("commit", {}) or {}
    cauthor = cdata.get("author", {}) or {}
    return {
        "sha": sha,
        "message": cdata.get("message", ""),
        "author": author.get("login") if author else cauthor.get("name", "Unknown"),
        "timestamp": cauthor.get("date", ""),
        "url": commit.get("html_url", ""),
    }


def _to_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def pr_in_window(pr, since) -> bool:
    """A PR counts for the week if it was created, merged, or updated at/after `since`."""
    for field in ("created_at", "merged_at", "updated_at"):
        dt = _to_dt(pr.get(field))
        if dt and dt >= since:
            return True
    return False


def parse_pr(pr, state) -> Dict[str, Any]:
    """Shape one REST pull request into our record."""
    user = pr.get("user") or {}
    return {
        "number": pr.get("number"),
        "title": pr.get("title", ""),
        "description": pr.get("body", "") or "",
        "status": state,
        "author": user.get("login", "Unknown"),
        "timestamp": pr.get("created_at", ""),
        "created_at": pr.get("created_at", ""),
        "merged_at": pr.get("merged_at") or "",
        "updated_at": pr.get("updated_at", ""),
        "url": pr.get("html_url", ""),
        "head_sha": (pr.get("head") or {}).get("sha", ""),
        "base_branch": (pr.get("base") or {}).get("ref", ""),
    }


def filter_active_branches(branches, since) -> List[str]:
    """Branch names whose latest commit is at/after `since`. Unparseable dates are excluded (safe)."""
    out = []
    for b in (branches or []):
        dt = _to_dt(b.get("committedDate"))
        if dt and dt >= since:
            out.append(b.get("name"))
    return [n for n in out if n]


def dedupe_commits(commits) -> List[Dict[str, Any]]:
    """Drop repeated SHAs (the same commit reachable from several active branches), preserving order."""
    seen, out = set(), []
    for c in (commits or []):
        sha = c.get("sha", "")
        if sha and sha not in seen:
            seen.add(sha)
            out.append(c)
    return out


def build_date_range(start, end) -> Dict[str, str]:
    """The week window for the email header."""
    return {
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "start_date_formatted": start.strftime("%B %d, %Y"),
        "end_date_formatted": end.strftime("%B %d, %Y"),
    }


def repos_to_scan(resolved_groups) -> List[str]:
    """Union of repos across every resolved group (the gate already applied the implicit fallback)."""
    repos = set()
    for g in (resolved_groups or []):
        for r in (g.get("repos") or []):
            if r:
                repos.add(r)
    return sorted(repos)


# ---------------------------------------------------------------- github fetch (HTTP glue)

def _headers(token):
    return {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}


def fetch_branches_with_dates(repo_path, headers) -> List[Dict[str, str]]:
    """All branches with their latest commit date via GraphQL (paginated)."""
    parts = repo_path.split("/")
    if len(parts) != 2:
        print(f"⚠️ invalid repo path: {repo_path}")
        return []
    owner, name = parts
    query = """
    query($owner: String!, $name: String!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        refs(refPrefix: "refs/heads/", first: 100, after: $cursor) {
          pageInfo { hasNextPage endCursor }
          nodes { name target { ... on Commit { committedDate } } }
        }
      }
    }"""
    branches, cursor, page = [], None, 1
    try:
        while True:
            r = requests.post(GRAPHQL_URL, headers=headers,
                              json={"query": query, "variables": {"owner": owner, "name": name, "cursor": cursor}},
                              timeout=HTTP_TIMEOUT)
            time.sleep(RATE_SLEEP)
            if r.status_code != 200:
                print(f"⚠️ branches GraphQL {repo_path}: HTTP {r.status_code}")
                break
            data = r.json()
            if "errors" in data:
                print(f"⚠️ branches GraphQL {repo_path}: {data['errors']}")
                break
            refs = (((data.get("data") or {}).get("repository") or {}).get("refs") or {})
            for node in (refs.get("nodes") or []):
                cdate = (node.get("target") or {}).get("committedDate", "")
                if node.get("name") and cdate:
                    branches.append({"name": node["name"], "committedDate": cdate})
            info = refs.get("pageInfo") or {}
            if not info.get("hasNextPage") or page >= MAX_BRANCH_PAGES:
                break
            cursor = info.get("endCursor")
            page += 1
    except Exception as e:
        print(f"⚠️ branches fetch failed for {repo_path}: {e}")
    return branches


def fetch_commits(repo_path, headers, branch_name, since) -> List[Dict[str, Any]]:
    """Commits on one branch since `since` (paginated), shaped + bot-filtered."""
    out, page = [], 1
    try:
        while True:
            r = requests.get(f"{GITHUB_API}/repos/{repo_path}/commits", headers=headers,
                             params={"sha": branch_name, "since": since.isoformat(), "per_page": 100, "page": page},
                             timeout=HTTP_TIMEOUT)
            time.sleep(RATE_SLEEP)
            if r.status_code != 200:
                break
            commits = r.json()
            if not commits:
                break
            for c in commits:
                rec = parse_commit(c)
                if rec:
                    out.append(rec)
            if len(commits) < 100 or page >= MAX_COMMIT_PAGES:
                break
            page += 1
    except Exception as e:
        print(f"⚠️ commits fetch failed for {repo_path}@{branch_name}: {e}")
    return out


def fetch_pull_requests(repo_path, headers, since) -> List[Dict[str, Any]]:
    """Open + recently-merged PRs touched within the window, shaped + bot-filtered."""
    out = []
    for state in ("open", "closed"):
        try:
            r = requests.get(f"{GITHUB_API}/repos/{repo_path}/pulls", headers=headers,
                             params={"state": state, "sort": "updated", "direction": "desc", "per_page": 100},
                             timeout=HTTP_TIMEOUT)
            time.sleep(RATE_SLEEP)
            if r.status_code != 200:
                continue
            for pr in r.json():
                if is_bot_user(pr.get("user") or {}):
                    continue
                if not pr_in_window(pr, since):
                    continue
                out.append(parse_pr(pr, state))
        except Exception as e:
            print(f"⚠️ {state} PRs fetch failed for {repo_path}: {e}")
    return out


# ---------------------------------------------------------------- driver (flat, fall-through)

skip = waveassist.fetch_data("digest_skip_run", run_based=True, default="0") == "1"
resolved_groups = [] if skip else (waveassist.fetch_data("digest_resolved_groups", run_based=True, default=[]) or [])

if skip:
    print("GitZoid Digest: digest_skip_run set; fetch_activity no-op.")

repos = repos_to_scan(resolved_groups)
if repos:
    access_token = waveassist.fetch_data("github_access_token", default="") or ""
    headers = _headers(access_token)

    end_date = datetime.now(timezone.utc)
    since = end_date - timedelta(days=DAYS_TO_FETCH)

    github_activity_data = {}
    for repo_path in repos:
        print(f"📊 {repo_path}: fetching activity...")
        try:
            branches = fetch_branches_with_dates(repo_path, headers)
            active = filter_active_branches(branches, since)
            commits = []
            for branch_name in active:
                commits.extend(fetch_commits(repo_path, headers, branch_name, since))
            commits = dedupe_commits(commits)
            prs = fetch_pull_requests(repo_path, headers, since)
            github_activity_data[repo_path] = {"commits": commits, "pull_requests": prs}
            print(f"✓ {repo_path}: {len(commits)} commit(s), {len(prs)} PR(s) over {len(active)} active branch(es)")
        except Exception as e:
            print(f"⚠️ activity fetch failed for {repo_path}: {e}; recording empty")
            github_activity_data[repo_path] = {"commits": [], "pull_requests": []}
        waveassist.store_data("github_activity_data", github_activity_data, data_type="json")

    waveassist.store_data("report_date_range", build_date_range(since, end_date), data_type="json")
    total_commits = sum(len(d["commits"]) for d in github_activity_data.values())
    total_prs = sum(len(d["pull_requests"]) for d in github_activity_data.values())
    print(f"GitZoid Digest: fetched {total_commits} commit(s), {total_prs} PR(s) across {len(repos)} repo(s).")
