from datetime import datetime, timezone, timedelta
import requests
import waveassist

FIRST_RUN_LIMIT = 2
MINIMUM_CREDITS_REQUIRED = 0.1

waveassist.init()

success = waveassist.check_credits_and_notify(MINIMUM_CREDITS_REQUIRED, "GitZoid")
if not success:
    display_output = {
        "html_content": "<p>Credits were not available, the run was skipped.</p>",
    }
    waveassist.store_data("display_output", display_output, run_based=True)
    raise Exception("Credits were not available, the run was skipped.")


def fetch_compare_diff(repo_path: str, base_sha: str, head_sha: str, headers: dict) -> list:
    """
    Fetch only the changed files between two commits using GitHub Compare API.
    GET /repos/{owner}/{repo}/compare/{base_sha}...{head_sha}
    """
    url = f"https://api.github.com/repos/{repo_path}/compare/{base_sha}...{head_sha}"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"⚠️ Failed to fetch compare diff: {response.status_code}")
        return []
    
    try:
        compare_data = response.json()
        files = compare_data.get("files", [])
        processed_files = []
        for f in files:
            if "filename" in f:
                processed_files.append({
                    "filename": f["filename"],
                    "patch": f.get("patch", ""),
                    "status": f.get("status", "modified"),  # added, removed, modified, renamed
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                })
        return processed_files
    except Exception as e:
        print(f"❌ Failed to parse compare response: {e}")
        return []


def fetch_pr_files(repo_path: str, pr_number: int, headers: dict) -> list:
    """Fetch all changed files for a PR (full diff)."""
    files_url = f"https://api.github.com/repos/{repo_path}/pulls/{pr_number}/files"
    files_response = requests.get(files_url, headers=headers)
    if files_response.status_code != 200:
        print(f"⚠️ Failed to fetch files for PR #{pr_number}")
        return []
    
    try:
        files_changed = files_response.json()
        processed_files = []
        for f in files_changed:
            if "filename" in f:
                processed_files.append({
                    "filename": f["filename"],
                    "patch": f.get("patch", ""),
                    "status": f.get("status", "modified"),
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                })
        return processed_files
    except Exception as e:
        print(f"❌ Invalid files JSON for PR #{pr_number}: {e}")
        return []


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
    return author.get("type") == "Bot" or login.endswith("[bot]")


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
    previous_sha: str = None,
    previous_review_text: str = None
) -> dict:
    """Build PR data dictionary for review."""
    pr_data = {
        "pr_number": pr["number"],
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
    response = requests.get(prs_url, headers=headers, params=params)
    if response.status_code != 200:
        print(f"❌ Failed to fetch PRs for {repo_path}: {response.status_code}")
        return [], False
    
    try:
        open_prs = response.json()
    except Exception as e:
        print(f"❌ Invalid PR JSON response: {e}")
        return [], False
    
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
                            pr, processed_files, "full", head_sha
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
                            new_files = fetch_compare_diff(repo_path, stored_sha, head_sha, headers)
                            
                            if new_files:
                                pr_data = build_pr_data(
                                    pr, new_files, "incremental", head_sha, stored_sha, previous_review_text
                                )
                                prs_to_review.append(pr_data)
                else:
                    # New PR, not in reviewed_prs
                    processed_files = fetch_pr_files(repo_path, pr_number, headers)
                    if processed_files:
                        pr_data = build_pr_data(
                            pr, processed_files, "full", head_sha
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


# Fetch input from WaveAssist
repositories = waveassist.fetch_data("github_selected_resources")
access_token = waveassist.fetch_data("github_access_token")

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
    waveassist.store_data("pull_requests", all_pull_requests)
    print(f"✅ Fetched and stored {len(all_pull_requests)} PRs.")
