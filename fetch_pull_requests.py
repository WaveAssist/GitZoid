from datetime import datetime, timezone, timedelta
import requests
import waveassist

FIRST_RUN_LIMIT = 2
# Runs UI: estimated seconds per PR for downstream generate_review + post_comment. This refines
# the upfront estimate set by check_credits_and_init once the real open-PR count is known.
PROCESSING_TIME_PER_PR = 2

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


def build_pr_data(
    pr: dict,
    processed_files: list,
    review_type: str,
    current_sha: str,
    repo_path: str,
    previous_sha: str = None,
    previous_review_text: str = None,
    brain_profile: dict = None
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
            
            pr_number = pr["number"]
            pr_key = f"{repo_path}#{pr_number}"
            head_sha = pr.get("head", {}).get("sha")
            
            if is_first_run:
                # First run: Process first 2, mark rest as skipped
                if processed_count < FIRST_RUN_LIMIT:
                    # Process this PR
                    processed_files = fetch_pr_files(repo_path, pr_number, headers)
                    if processed_files:
                        pr_data = build_pr_data(
                            pr, processed_files, "full", head_sha, repo_path,
                            brain_profile=brain_profile
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
                            full_files = fetch_pr_files(repo_path, pr_number, headers)

                            if full_files:
                                pr_data = build_pr_data(
                                    pr, full_files, "incremental", head_sha, repo_path, stored_sha,
                                    previous_review_text, brain_profile=brain_profile
                                )
                                prs_to_review.append(pr_data)
                else:
                    # New PR, not in reviewed_prs
                    processed_files = fetch_pr_files(repo_path, pr_number, headers)
                    if processed_files:
                        pr_data = build_pr_data(
                            pr, processed_files, "full", head_sha, repo_path,
                            brain_profile=brain_profile
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
skip_run = bool(waveassist.fetch_data("skip_run", default=False))
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
