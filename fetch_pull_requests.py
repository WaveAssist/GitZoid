from datetime import datetime, timezone
import requests
import waveassist
FIRST_RUN_LIMIT = 2
RUN_LIMIT = 5
waveassist.init()


def fetch_open_pull_requests(repo_metadata: dict, access_token: str):
    all_prs = []
    repo_path = repo_metadata["id"]
    last_checked_str = repo_metadata.get("last_checked")
    first_run = False
    if last_checked_str:
        try:
            last_checked = datetime.fromisoformat(last_checked_str)
        except ValueError:
            first_run = True
            last_checked = datetime.min.replace(tzinfo=timezone.utc)
    else:
        first_run = True
        last_checked = datetime.min.replace(tzinfo=timezone.utc)

    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github+json",
    }

    # Calculate limit before API call
    limit = FIRST_RUN_LIMIT if first_run else RUN_LIMIT

    # Step 1: Fetch open PRs
    prs_url = f"https://api.github.com/repos/{repo_path}/pulls"
    params = {
        "state": "open",
        "sort": "created",
        "direction": "desc",
        "per_page": limit,
    }
    response = requests.get(prs_url, headers=headers, params=params)
    if response.status_code != 200:
        print(f"❌ Failed to fetch PRs for {repo_path}: {response.status_code}")
        return []
    try:
        prs = response.json()
    except Exception as e:
        print(f"❌ Invalid PR JSON response: {e}")
        return []


    for pr in prs:
        try:
            author = pr.get("user") or {}
            login = (author.get("login") or "").lower()
            if author.get("type") == "Bot" or login.endswith("[bot]"):
                continue

            pr_created_at = datetime.fromisoformat(
                pr["created_at"].replace("Z", "+00:00")
            )
            if pr_created_at <= last_checked:
                continue
            pr_number = pr["number"]
            # Step 3: Fetch changed files
            files_url = (
                f"https://api.github.com/repos/{repo_path}/pulls/{pr_number}/files"
            )
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
                    processed_files.append(
                        {"filename": f["filename"], "patch": f["patch"]}
                    )

            # Step 4: Construct PR data
            pr_data = {
                "pr_number": pr_number,
                "title": pr.get("title"),
                "body": pr.get("body"),
                "pr_created_at": pr_created_at.isoformat(),
                "files": processed_files,
            }

            # Merge in repo metadata
            for key, value in repo_metadata.items():
                pr_data[key] = value
            pr_data.pop("extra", None)

            all_prs.append(pr_data)
            if len(all_prs) >= limit:
                break
        except Exception as e:
            print(f"⚠️  Skipped PR due to error: {e}")

    all_prs.sort(key=lambda x: x["pr_created_at"], reverse=True)
    return all_prs


# Fetch input from WaveAssist
repositories = waveassist.fetch_data("github_selected_resources")
access_token = waveassist.fetch_data("github_access_token")

all_pull_requests = []
for repo in repositories:
    prs = fetch_open_pull_requests(repo, access_token)
    all_pull_requests.extend(prs)

if all_pull_requests:
    waveassist.store_data("pull_requests", all_pull_requests)
    print(f"✅ Fetched and stored {len(all_pull_requests)} pull requests.")
