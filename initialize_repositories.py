"""
WaveAssist Node: Fetch Accessible GitHub Repositories

This node fetches all GitHub repositories accessible by a given GHP token,
filters those with both `pull` and `push` permissions, and stores them in WaveAssist.

Expected stored key from waveassist:
- Input: `github_ghp_token`
- Output: `repositories`
"""

import requests
import waveassist

waveassist.init()

def fetch_repositories_with_access(token: str):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json"
    }

    repositories = []
    page = 1

    while True:
        url = f"https://api.github.com/user/repos?per_page=100&page={page}"
        response = requests.get(url, headers=headers)

        if response.status_code == 401:
            raise ValueError("Unauthorized: Invalid GitHub token.")
        elif response.status_code != 200:
            raise RuntimeError(f"GitHub API error {response.status_code}: {response.text}")

        page_data = response.json()
        if not page_data:
            break

        for repo in page_data:
            permissions = repo.get("permissions", {})
            if permissions.get("pull") and permissions.get("push"):
                repositories.append({
                    "repo_name": repo["name"],
                    "repo_owner": repo["owner"]["login"],
                    "is_enabled": True,
                    "model": "claude-3.5",
                    "target_branch": ""
                })
        page += 1

    return repositories


try:
    token = waveassist.fetch_data("github_ghp_token")
    should_fetch_repositories = str(waveassist.fetch_data("should_fetch_repositories") or "1").strip()
    if should_fetch_repositories == '1':
        print("🔄 Fetching accessible repositories from GitHub...")
        accessible_repos = fetch_repositories_with_access(token)
        if len(accessible_repos) == 0:
            print("⚠️ No accessible repositories found with both pull and push permissions.")
        else:
            waveassist.store_data("repositories", accessible_repos)
            waveassist.store_data("should_fetch_repositories", '0')
            print(f"✅ Stored {len(accessible_repos)} accessible repositories to WaveAssist.")
except Exception as e:
    print(f"❌ Error: {e}")
