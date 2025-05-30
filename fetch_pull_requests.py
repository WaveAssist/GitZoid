"""
WaveAssist Node: Fetch Open Pull Requests for Accessible Repositories

This node loops over a list of accessible repositories stored in WaveAssist (under the key `accessible_repositories`),
fetches open pull requests created after the last checked time, and stores them along with file diffs.

Expected input keys:
- `repositories`: list of repositories with `repo_name`, `owner_login`, etc.
- `github_access_token`: GitHub personal access token

Output key:
- `pull_requests`: structured list of PRs with metadata and changed files
"""

from datetime import datetime, timezone
import requests
import waveassist

waveassist.init()


def fetch_open_pull_requests(repo_metadata: dict, access_token: str):
    all_prs = []
    repo_owner = repo_metadata["repo_owner"]
    repo_name = repo_metadata["repo_name"]

    # Parse last_checked timestamp
    last_checked_str = repo_metadata.get("last_checked")
    if last_checked_str:
        try:
            last_checked = datetime.fromisoformat(last_checked_str)
        except ValueError:
            last_checked = datetime.min.replace(tzinfo=timezone.utc)
    else:
        last_checked = datetime.min.replace(tzinfo=timezone.utc)

    target_branch = repo_metadata.get("target_branch", "")
    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github+json"
    }

    # Step 1: Fetch open PRs
    prs_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls"
    response = requests.get(prs_url, headers=headers)
    if response.status_code != 200:
        print(f"❌ Failed to fetch PRs for {repo_owner}/{repo_name}: {response.status_code}")
        return []
    try:
        prs = response.json()
    except Exception as e:
        print(f"❌ Invalid PR JSON response: {e}")
        return []

    # Step 2: Filter and enrich PRs
    for pr in prs:
        try:
            pr_target_branch = pr["base"]["ref"]
            pr_created_at = datetime.fromisoformat(pr["created_at"].replace("Z", "+00:00"))

            if pr_created_at <= last_checked:
                continue
            if target_branch and pr_target_branch != target_branch:
                continue
            pr_number = pr["number"]
            # Step 3: Fetch changed files
            files_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/files"
            files_response = requests.get(files_url, headers=headers)
            if files_response.status_code != 200:
                print(f"⚠️  Failed to fetch files for PR #{pr_number}")
                continue

            try:
                files_changed = files_response.json()
            except Exception as e:
                print(f"❌ Invalid files JSON for PR #{pr_number}: {e}")
                continue

            processed_files = []
            for f in files_changed:
                if "filename" in f and "patch" in f:
                    processed_files.append({
                        "filename": f["filename"],
                        "patch": f["patch"]
                    })

            # Step 4: Construct PR data
            pr_data = {
                "pr_number": pr_number,
                "title": pr.get("title"),
                "body": pr.get("body"),
                "pr_created_at": pr_created_at.isoformat(),
                "target_branch": pr_target_branch,
                "files": processed_files,
            }

            # Merge in repo metadata
            for key, value in repo_metadata.items():
                pr_data[key] = value

            all_prs.append(pr_data)
        except Exception as e:
            print(f"⚠️  Skipped PR due to error: {e}")

    all_prs.sort(key=lambda x: x["pr_created_at"], reverse=True)
    return all_prs[:50]  # Limit to most recent 50


# Fetch input from WaveAssist
repositories = waveassist.fetch_data("repositories")
access_token = waveassist.fetch_data("github_ghp_token")

all_pull_requests = []
for repo in repositories:
    prs = fetch_open_pull_requests(repo, access_token)
    all_pull_requests.extend(prs)

waveassist.store_data("pull_requests", all_pull_requests)
print(f"✅ Fetched and stored {len(all_pull_requests)} pull requests.")
