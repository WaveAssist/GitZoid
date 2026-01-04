<p align="center">
  <img src="https://waveassist.io/images/templates/gitzoid/GitzoidLogoDark.png" alt="GitZoid Logo" width="200" />
</p>

<h1 align="center">GitZoid: Open-Source AI-Powered GitHub PR Reviewer</h1>

<p align="center">
  <a href="https://waveassist.io/templates/gitzoid-template">
    <img src="https://img.shields.io/badge/Deploy_with-WaveAssist-007F3B" alt="Deploy with WaveAssist" />
  </a>
  <img src="https://img.shields.io/badge/GitZoid-AI%20Powered%20PR%20Reviews-blue" alt="GitZoid Badge" />
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License" />
  </a>
  <a href="https://gitzoid.com/blog/how-to-get-your-github-token-for-gitzoid-fine-grained-classic">
    <img src="https://img.shields.io/badge/Guide-How_to_Get_GitHub_Token-red" alt="How to get GitHub token guide" />
  </a>
</p>

---

## Overview

GitZoid is an **open-source** GitHub bot that automates pull-request reviews using AI models—no separate GPT or Claude keys required! On WaveAssist, your OpenRouter token is included free up to a generous usage limit. WaveAssist handles node orchestration, scheduling, secrets storage, and hosting for you. You can also run GitZoid as a standalone Python app if you prefer.

Try the **hosted version** at [https://gitzoid.com](https://gitzoid.com) — no setup required.

<p align="center">
  <img src="https://waveassist.io/images/templates/gitzoid/pr_review.png" alt="GitZoid UI Preview" width="100%" />
</p>

---

## Three Ways to Get Your PRs Reviewed with GitZoid

### 1. One-Click Deploy on WaveAssist (Recommended)

<p>
  <a href="https://waveassist.io/templates/gitzoid-template" target="_blank">
    <img src="https://waveassist.io/images/templates/Button.png" alt="Deploy on WaveAssist" width="230" />
  </a>
</p>

Deploy instantly on [WaveAssist](https://waveassist.io)—a zero-infra automation platform that handles everything (including your free OpenRouter AI token).

#### How to Use:

1. Click the button or visit [waveassist.io/templates/gitzoid-template](https://waveassist.io/templates/gitzoid-template).
2. Enter your Github Personal Acccess token:
   - `github_ghp_token`
     _(no OpenAI/Anthropic key needed!)_
   - Cick here to know how to generate your GitHub token: [How to Get GitHub Token](https://gitzoid.com/blog/how-to-get-your-github-token-for-gitzoid-fine-grained-classic)
3. Click **Run & Deploy** to schedule automatic reviews.

✅ You’re now running GitZoid on autopilot.

---

### 2. Use GitZoid.com (No API Key Required)

<p>
  <a href="https://gitzoid.com" target="_blank">
    <img src="https://img.shields.io/badge/%20Use%20GitZoid.com-No%20API%20Key%20Needed-0e1c3a" alt="Use GitZoid.com" />
  </a>
</p>

Head to [gitzoid.com](https://gitzoid.com), enter:

- Your GitHub token
- Repositories to monitor

GitZoid uses hosted AI credits to review and comment on your PRs—no keys or setup required.

---

### 3. Manual Deployment

Want full control on your own infra? Clone this repo and schedule scripts however you like (cron, GitHub Actions, Airflow, etc.).

Scripts:

- `initialize_repositories.py`: seed your repos
- `fetch_pull_requests.py`: pull in new PRs
- `generate_review.py`: call OpenRouter’s AI via your free token
- `post_comment.py`: post feedback back to GitHub

---

## Features

- **Zero-Key AI**
  WaveAssist provides an OpenRouter AI token free up to a generous limit—no GPT or Claude keys needed.
- **One-Time Repo Init**
  Seed your repo list into WaveAssist or a local store.
- **Automated PR Monitoring**
  Polls for new pull requests at your chosen interval.
- **AI-Powered Reviews**
  Structured, friendly feedback generated and posted automatically.
- **Incremental Reviews** ✨ **NEW**
  When new commits are pushed to a PR, GitZoid automatically detects the changes and posts a follow-up review covering:
  - **Changes Summary**: What the new commits do
  - **Addressed Issues**: Which previous concerns were fixed
  - **New Observations**: Any new issues or suggestions
- **Configurable**
  Per-repo branch and model settings (Claude or GPT through OpenRouter).

---

## How Incremental Reviews Work

GitZoid tracks the last reviewed commit SHA for each PR. When it detects new commits:

1. **Detection**: Compares `head.sha` from GitHub with the stored `last_reviewed_sha`
2. **Diff Fetching**: Uses GitHub's Compare API to fetch only the new changes
3. **Context-Aware Review**: Fetches previous GitZoid comments to understand what was already flagged
4. **Focused Feedback**: Posts an incremental review that acknowledges addressed issues and highlights new concerns

This ensures your team gets relevant, focused feedback on each iteration—not repeated comments about code that hasn't changed.

---

Built with ❤️ by the WaveAssist team. Have questions or want integrations? [Say hello](https://waveassist.io).
