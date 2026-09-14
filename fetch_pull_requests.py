import fnmatch
from datetime import datetime, timezone, timedelta
import requests
import waveassist

FIRST_RUN_LIMIT = 2
# Runs UI: estimated seconds per PR for downstream generate_review + post_comment. This refines
# the upfront estimate set by check_credits_and_init once the real open-PR count is known.
PROCESSING_TIME_PER_PR = 2

# --- Per-repo review context (author-provided guidance pulled from the target repo) ---
# review.md carries GitZoid-specific review guidance (+ optional front-matter control fields);
# CLAUDE.md / AGENTS.md are the repo's own conventions. Both are fetched once per repo and
# injected into the review prompt as INFORMATIONAL context (see generate_review). All fetches
# fail open to empty so a missing file / API hiccup never blocks a review.
REVIEW_MD_PATHS = [".gitzoid/review.md", "review.md"]
CONVENTION_PATHS = ["CLAUDE.md", "AGENTS.md"]
MAX_REVIEW_MD_CHARS = 6000        # caps each block so it never crowds out the diff in the prompt
MAX_CONVENTIONS_CHARS = 6000
MAX_COMMENTS_CHARS = 8000
MAX_COMMENTS = 30                 # newest N comments kept before the char cap
REVIEW_FETCH_TIMEOUT = 10
SKIP_LABEL = "gitzoid-skip"       # a PR carrying this label is not reviewed
# Bot logins whose comments are noise in the "existing discussion" context (mirrors is_bot_pr).
_COMMENT_BOT_LOGINS = {
    "dependabot", "renovate", "github-actions", "codecov", "greenkeeper",
    "snyk-bot", "mergify", "stale", "allcontributors", "imgbot",
}

# Credits are gated once upstream in check_credits_and_init (the single starting node).
waveassist.init()


def _has_next_page(resp) -> bool:
    """Defensive Link-header 'next' check. A non-dict .links (e.g. a bare test Mock) means
    'no next page', so legacy single-response mocks stay single-page instead of looping forever."""
    links = getattr(resp, "links", None)
    return isinstance(links, dict) and "next" in links


def fetch_compare_diff(repo_path: str, base_sha: str, head_sha: str, headers: dict) -> list:
    """
    Fetch the changed files between two commits using the GitHub Compare API (paginated).
    GET /repos/{owner}/{repo}/compare/{base_sha}...{head_sha}
    """
    url = f"https://api.github.com/repos/{repo_path}/compare/{base_sha}...{head_sha}"
    processed_files, page = [], 1
    while True:
        response = requests.get(url, headers=headers, params={"per_page": 100, "page": page}, timeout=30)
        if response.status_code != 200:
            print(f"⚠️ Failed to fetch compare diff: {response.status_code}")
            return processed_files
        try:
            compare_data = response.json()
        except Exception as e:
            print(f"❌ Failed to parse compare response: {e}")
            return processed_files
        for f in (compare_data.get("files", []) or []):
            if "filename" in f:
                processed_files.append({
                    "filename": f["filename"],
                    "patch": f.get("patch", ""),
                    "status": f.get("status", "modified"),  # added, removed, modified, renamed
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                })
        if not _has_next_page(response):
            break
        page += 1
    return processed_files


def fetch_pr_files(repo_path: str, pr_number: int, headers: dict) -> list:
    """Fetch all changed files for a PR (full diff, paginated)."""
    files_url = f"https://api.github.com/repos/{repo_path}/pulls/{pr_number}/files"
    processed_files, page = [], 1
    while True:
        resp = requests.get(files_url, headers=headers, params={"per_page": 100, "page": page}, timeout=30)
        if resp.status_code != 200:
            print(f"⚠️ Failed to fetch files for PR #{pr_number}")
            return processed_files
        try:
            files_changed = resp.json()
        except Exception as e:
            print(f"❌ Invalid files JSON for PR #{pr_number}: {e}")
            return processed_files
        if not files_changed:
            break
        for f in files_changed:
            if "filename" in f:
                processed_files.append({
                    "filename": f["filename"],
                    "patch": f.get("patch", ""),
                    "status": f.get("status", "modified"),
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                })
        if not _has_next_page(resp):
            break
        page += 1
    return processed_files


def is_first_run_for_repo(repo_path: str, reviewed_prs: dict) -> bool:
    """Check if this is the first run for this repo."""
    repo_reviewed = {
        k: v for k, v in reviewed_prs.items() 
        if k.startswith(f"{repo_path}#")
    }
    return len(repo_reviewed) == 0


def is_bot_pr(pr: dict) -> bool:
    """Check if PR is from a bot."""
    author = pr.get("user") or {}
    login = (author.get("login") or "").lower()
    
    # Check if type is Bot
    if author.get("type") == "Bot":
        return True
    
    # Check if login ends with [bot]
    if login.endswith("[bot]"):
        return True
    
    # Check for common bot names (even without [bot] suffix)
    common_bots = [
        "dependabot",
        "renovate",
        "github-actions",
        "codecov",
        "greenkeeper",
        "snyk-bot",
        "mergify",
        "stale",
        "allcontributors",
        "imgbot",
    ]
    if login in common_bots:
        return True

    return False


def is_draft_pr(pr: dict) -> bool:
    """Check if a PR is a draft (drafts re-enter review naturally when marked ready)."""
    return bool(pr.get("draft"))


def is_old_pr(pr: dict, days: int = 30) -> bool:
    """Check if PR is older than specified days."""
    try:
        pr_created_at = datetime.fromisoformat(
            pr["created_at"].replace("Z", "+00:00")
        )
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return pr_created_at < cutoff
    except:
        return False


def _cap_text(text: str, limit: int, label: str) -> str:
    """Head-keep a block to `limit` chars with an explicit truncation marker (never silent)."""
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + f"\n…[{label} truncated at {limit} chars]"


def fetch_repo_file(repo_path: str, path: str, access_token: str) -> str:
    """Raw text of `path` from the repo's default branch, or '' on any failure (fail open)."""
    if not (repo_path and path and access_token):
        return ""
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{repo_path}/contents/{path}",
            headers={"Authorization": f"token {access_token}",
                     "Accept": "application/vnd.github.raw+json"},
            timeout=REVIEW_FETCH_TIMEOUT)
        return resp.text if resp.status_code == 200 and isinstance(resp.text, str) else ""
    except Exception:
        return ""


def parse_review_md(text: str):
    """Split optional leading YAML-ish front-matter from the prose body.

    Returns (control: dict, body: str). Front-matter is the block between a leading '---' line
    and the next '---' line. Only keys we understand are parsed — skip (bool), severity_floor
    (high|medium|low), ignore[] (globs), focus[] (strings); everything else is ignored. No YAML
    dependency: a tiny line parser for our fixed, simple schema. Malformed front-matter degrades
    to treating the whole file as prose."""
    control = {}
    if not text:
        return control, ""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return control, text.strip()
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return control, text.strip()
    body = "\n".join(lines[end + 1:]).strip()
    cur_list_key = None
    for raw in lines[1:end]:
        if not raw.strip():
            continue
        stripped = raw.lstrip()
        if cur_list_key and stripped.startswith("- "):
            item = stripped[2:].strip().strip("'\"")
            if item:
                control[cur_list_key].append(item)
            continue
        cur_list_key = None
        if ":" not in raw:
            continue
        key, _, val = raw.partition(":")
        key = key.strip().lower()
        val = val.strip().strip("'\"")
        if key in ("ignore", "focus"):
            if val:  # inline list form: "ignore: [a, b]" or a single value
                control[key] = [v.strip().strip("'\"") for v in val.strip("[]").split(",") if v.strip()]
            else:    # block list form: subsequent "  - item" lines
                control[key] = []
                cur_list_key = key
        elif key == "skip":
            control["skip"] = val.lower() in ("true", "1", "yes", "on")
        elif key == "severity_floor" and val.lower() in ("high", "medium", "low"):
            control["severity_floor"] = val.lower()
    return control, body


def fetch_review_config(repo_path: str, access_token: str) -> dict:
    """Per-repo review guidance pulled from the TARGET repo (fail open to empty).

    - review.md (`.gitzoid/review.md` preferred, then `review.md`): optional front-matter control
      fields + free-text instructions.
    - conventions (`CLAUDE.md` preferred, then `AGENTS.md`): prose, injected as context.
    Returns instructions / focus[] / conventions (all capped) plus control fields skip /
    severity_floor / ignore[], and *_source for logging."""
    cfg = {"instructions": "", "focus": [], "conventions": "", "skip": False,
           "severity_floor": "", "ignore": [], "source": "", "conventions_source": ""}
    for p in REVIEW_MD_PATHS:
        text = fetch_repo_file(repo_path, p, access_token)
        if text.strip():
            control, body = parse_review_md(text)
            cfg["instructions"] = _cap_text(body, MAX_REVIEW_MD_CHARS, "review.md")
            cfg["focus"] = [f for f in (control.get("focus") or []) if f][:20]
            cfg["ignore"] = [g for g in (control.get("ignore") or []) if g][:50]
            cfg["skip"] = bool(control.get("skip"))
            cfg["severity_floor"] = control.get("severity_floor") or ""
            cfg["source"] = p
            break
    for p in CONVENTION_PATHS:
        text = fetch_repo_file(repo_path, p, access_token)
        if text.strip():
            cfg["conventions"] = _cap_text(text, MAX_CONVENTIONS_CHARS, p)
            cfg["conventions_source"] = p
            break
    return cfg


def _matches_glob(path: str, glob: str) -> bool:
    """True if `path` matches `glob` by full path or basename, or falls under a 'dir/' / 'dir/**' prefix."""
    if not path or not glob:
        return False
    if fnmatch.fnmatch(path, glob) or fnmatch.fnmatch(path.split("/")[-1], glob):
        return True
    g = glob.rstrip("/")
    if g.endswith("/**"):
        g = g[:-3]
    return path == g or path.startswith(g + "/")


def apply_ignore_globs(files: list, globs: list) -> list:
    """Drop changed files matching any ignore glob (review.md `ignore:`)."""
    if not globs:
        return files or []
    return [f for f in (files or [])
            if not any(_matches_glob(f.get("filename", ""), g) for g in globs)]


def pr_has_skip_label(pr: dict) -> bool:
    """True if the PR carries the opt-out label (SKIP_LABEL)."""
    for lbl in (pr.get("labels") or []):
        name = (lbl.get("name") if isinstance(lbl, dict) else lbl) or ""
        if str(name).strip().lower() == SKIP_LABEL:
            return True
    return False


def fetch_pr_comments(repo_path: str, pr_number: int, headers: dict) -> str:
    """Existing discussion on the PR (issue comments + inline review comments), newest first,
    bot noise filtered, newest MAX_COMMENTS kept then char-capped. Returns a formatted string or
    '' (fail open on any error). Informational context so the reviewer does not repeat points."""
    collected = []
    # Ask for newest-first so the first page holds the newest comments (the review-comments endpoint
    # honors sort/direction; the issue-comments endpoint ignores them, so on a thread with >100 issue
    # comments only the first page is seen — acceptable, and we still sort client-side below).
    params = {"per_page": 100, "sort": "created", "direction": "desc"}
    for kind, url in (
        ("comment", f"https://api.github.com/repos/{repo_path}/issues/{pr_number}/comments"),
        ("review", f"https://api.github.com/repos/{repo_path}/pulls/{pr_number}/comments"),
    ):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=20)
            if resp.status_code != 200:
                continue
            for c in (resp.json() or []):
                login = ((c.get("user") or {}).get("login") or "")
                low = login.lower()
                if low.endswith("[bot]") or low in _COMMENT_BOT_LOGINS:
                    continue
                body = (c.get("body") or "").strip()
                if not body:
                    continue
                loc = ""
                if kind == "review" and c.get("path"):
                    loc = f" on {c.get('path')}:{c.get('line') or c.get('original_line') or ''}"
                collected.append((c.get("created_at") or "", f"- @{login or '?'}{loc}: {body}"))
        except Exception:
            continue
    if not collected:
        return ""
    collected.sort(key=lambda x: x[0], reverse=True)   # newest first
    text = "\n".join(line for _, line in collected[:MAX_COMMENTS])
    return _cap_text(text, MAX_COMMENTS_CHARS, "comments")


def build_pr_data(
    pr: dict,
    processed_files: list,
    review_type: str,
    current_sha: str,
    repo_path: str,
    previous_sha: str = None,
    previous_review_text: str = None,
    brain_profile: dict = None,
    review_config: dict = None,
    existing_comments: str = None
) -> dict:
    """Build PR data dictionary for review."""
    pr_data = {
        "id": repo_path,  # Store repo_path as "id" for use in post_comment.py
        "pr_number": pr.get("number"),
        "title": pr.get("title"),
        "body": pr.get("body"),
        "pr_created_at": pr.get("created_at"),
        "files": processed_files,
        "review_type": review_type,
        "current_sha": current_sha,
    }
    if previous_sha:
        pr_data["previous_sha"] = previous_sha
    if previous_review_text:
        pr_data["previous_review_text"] = previous_review_text
    if brain_profile:
        pr_data["brain_profile"] = brain_profile
    if review_config:
        if review_config.get("instructions"):
            pr_data["review_instructions"] = review_config["instructions"]
        if review_config.get("focus"):
            pr_data["review_focus"] = review_config["focus"]
        if review_config.get("conventions"):
            pr_data["repo_conventions"] = review_config["conventions"]
        if review_config.get("severity_floor"):
            pr_data["review_severity_floor"] = review_config["severity_floor"]
    if existing_comments:
        pr_data["existing_comments"] = existing_comments
    return pr_data


def fetch_and_process_prs(
    repo_metadata: dict, 
    access_token: str, 
    reviewed_prs: dict
) -> tuple[list, bool]:
    """
    Fetch and process all PRs for a repo.
    Returns (list of PRs to review, reviewed_prs_changed flag).
    """
    repo_path = repo_metadata["id"]
    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github+json",
    }

    # Load the per-repo brain profile (additive key); attached to each PR for downstream review.
    brain_profile = waveassist.fetch_data(f"profile:{repo_path}", default={}) or {}

    # Per-repo review guidance from the TARGET repo (review.md + CLAUDE.md/AGENTS.md), fetched once
    # per repo and attached to each PR. Fail-open. `skip` opts the whole repo out; `ignore` globs
    # drop files from the diff before review.
    review_config = fetch_review_config(repo_path, access_token)
    if review_config.get("skip"):
        print(f"⏭️  {repo_path}: review.md skip=true — skipping this repo.")
        return [], False
    ignore_globs = review_config.get("ignore") or []

    # Detect first run
    is_first_run = is_first_run_for_repo(repo_path, reviewed_prs)
    
    # Fetch all open PRs (single API call)
    prs_url = f"https://api.github.com/repos/{repo_path}/pulls"
    params = {
        "state": "open",
        "sort": "created",
        "direction": "desc",
        "per_page": 100,  # Get all open PRs
    }
    open_prs = []
    params["page"] = 1
    while True:
        response = requests.get(prs_url, headers=headers, params=params, timeout=30)
        if response.status_code != 200:
            print(f"❌ Failed to fetch PRs for {repo_path}: {response.status_code}")
            return [], False
        try:
            page_prs = response.json()
        except Exception as e:
            print(f"❌ Invalid PR JSON response: {e}")
            return [], False
        if not page_prs:
            break
        open_prs.extend(page_prs)
        if not _has_next_page(response):
            break
        params["page"] += 1
    
    # Build lookup
    open_pr_numbers = {pr["number"] for pr in open_prs}
    open_prs_by_number = {pr["number"]: pr for pr in open_prs}
    
    # Process PRs
    prs_to_review = []
    reviewed_prs_changed = False
    processed_count = 0
    
    for pr in open_prs:
        try:
            # Skip bot PRs
            if is_bot_pr(pr):
                continue

            # Skip draft PRs (they re-enter naturally when marked ready for review)
            if is_draft_pr(pr):
                continue

            # Skip old PRs (>60 days)
            if is_old_pr(pr, days=60):
                continue

            # Author opt-out: a PR labeled gitzoid-skip is not reviewed.
            if pr_has_skip_label(pr):
                continue

            pr_number = pr["number"]
            pr_key = f"{repo_path}#{pr_number}"
            head_sha = pr.get("head", {}).get("sha")
            
            if is_first_run:
                # First run: Process first 2, mark rest as skipped
                if processed_count < FIRST_RUN_LIMIT:
                    # Process this PR
                    processed_files = apply_ignore_globs(
                        fetch_pr_files(repo_path, pr_number, headers), ignore_globs)
                    if processed_files:
                        pr_data = build_pr_data(
                            pr, processed_files, "full", head_sha, repo_path,
                            brain_profile=brain_profile, review_config=review_config,
                            existing_comments=fetch_pr_comments(repo_path, pr_number, headers)
                        )
                        prs_to_review.append(pr_data)
                        processed_count += 1
                else:
                    # Mark as skipped
                    reviewed_prs[pr_key] = {
                        "status": "skipped",
                        "skipped_at": datetime.now(timezone.utc).isoformat()
                    }
                    reviewed_prs_changed = True
            else:
                # Subsequent runs
                if pr_key in reviewed_prs:
                    pr_info = reviewed_prs[pr_key]
                    status = pr_info.get("status")
                    if status == "skipped":
                        # Skip this PR permanently
                        continue
                    
                    elif status == "reviewed":
                        # Check for new commits
                        stored_sha = pr_info.get("last_reviewed_sha")
                        previous_review_text = pr_info.get("last_review_text")
                        if stored_sha and head_sha and head_sha != stored_sha and previous_review_text:
                            print(f"🔄 New commits detected on PR #{pr_number}: {stored_sha[:7]} → {head_sha[:7]}")
                            # Re-review the FULL current PR (not just stored_sha..head_sha) so the
                            # open/fixed ledger reflects the real current state — an issue counts as
                            # fixed only when it is truly gone, not merely outside the latest commit.
                            full_files = apply_ignore_globs(
                                fetch_pr_files(repo_path, pr_number, headers), ignore_globs)

                            if full_files:
                                pr_data = build_pr_data(
                                    pr, full_files, "incremental", head_sha, repo_path, stored_sha,
                                    previous_review_text, brain_profile=brain_profile,
                                    review_config=review_config,
                                    existing_comments=fetch_pr_comments(repo_path, pr_number, headers)
                                )
                                prs_to_review.append(pr_data)
                else:
                    # New PR, not in reviewed_prs
                    processed_files = apply_ignore_globs(
                        fetch_pr_files(repo_path, pr_number, headers), ignore_globs)
                    if processed_files:
                        pr_data = build_pr_data(
                            pr, processed_files, "full", head_sha, repo_path,
                            brain_profile=brain_profile, review_config=review_config,
                            existing_comments=fetch_pr_comments(repo_path, pr_number, headers)
                        )
                        prs_to_review.append(pr_data)
        except Exception as e:
            print(f"⚠️ Skipped PR due to error: {e}")
    
    # Lazy cleanup: Remove closed PRs and stale entries
    now = datetime.now(timezone.utc)
    to_remove = []
    
    for pr_key, pr_info in reviewed_prs.items():
        if not pr_key.startswith(f"{repo_path}#"):
            continue
        
        pr_number = int(pr_key.split("#")[1])
        
        # Cleanup 1: Remove closed PRs
        if pr_number not in open_pr_numbers:
            to_remove.append(pr_key)
            continue
        
        # Cleanup 2: Remove stale entries (>90 days)
        timestamp = pr_info.get("reviewed_at") or pr_info.get("skipped_at")
        if timestamp:
            try:
                timestamp_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                age_days = (now - timestamp_dt).days
                if age_days > 90:
                    to_remove.append(pr_key)
            except:
                pass
    
    # Remove entries
    for key in to_remove:
        del reviewed_prs[key]
        reviewed_prs_changed = True
    
    # Sort by creation date
    prs_to_review.sort(key=lambda x: x.get("pr_created_at", ""), reverse=True)
    
    return prs_to_review, reviewed_prs_changed


# Single-run lock (set by check_credits_and_init): if another run holds it, no-op (empty repo list
# means no PRs are queued, so generate_review / post_comment downstream also no-op).
skip_run = waveassist.fetch_data("skip_run", run_based=True, default="0") == "1"
if skip_run:
    print("GitZoid: skip_run set; fetch_pull_requests no-op (another run in progress).")

# Fetch input from WaveAssist
repositories = [] if skip_run else (waveassist.fetch_data("github_selected_resources") or [])
access_token = waveassist.fetch_data("github_access_token") or ""

# Fetch existing reviewed PRs tracker
reviewed_prs = waveassist.fetch_data("reviewed_prs") or {}

all_pull_requests = []
reviewed_prs_changed = False

for repo in repositories:
    prs, changed = fetch_and_process_prs(repo, access_token, reviewed_prs)
    all_pull_requests.extend(prs)
    if changed:
        reviewed_prs_changed = True

# Store reviewed_prs only if changed
if reviewed_prs_changed:
    waveassist.store_data("reviewed_prs", reviewed_prs)

if all_pull_requests:
    time_to_process = len(all_pull_requests) * PROCESSING_TIME_PER_PR
    waveassist.store_data(
        "tentative_time_to_process",
        str(time_to_process),
        run_based=True,
        data_type="string",
    )
    waveassist.store_data("pull_requests", all_pull_requests)
    print(f"✅ Fetched and stored {len(all_pull_requests)} PRs.")
