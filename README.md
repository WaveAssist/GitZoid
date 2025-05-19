<p align="center">
  <img src="https://waveassistapps.s3.us-east-1.amazonaws.com/public/gitzoid_logo_dark.png" alt="GitZoid Logo" width="200" />
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

GitZoid is an **open-source** GitHub bot that automates pull-request reviews and comments using AI models (OpenAI’s GPT-4o-mini or Anthropic’s Claude 3.5). By default, it’s designed to run on the [WaveAssist](https://waveassist.io) platform—which handles node orchestration, scheduling, secrets/variable storage, and hosting—but you can also run it as a standalone Python application.

You can try out the **hosted version** of GitZoid at [https://gitzoid.com](https://gitzoid.com) — no setup required.

<p align="center">
  <img src="https://waveassistapps.s3.us-east-1.amazonaws.com/public/gitzoid-og-home.png" alt="GitZoid UI Preview" width="100%" />
</p>

---

## Three Ways to Get Your PRs Reviewed with GitZoid

GitZoid offers multiple ways to integrate AI-powered code reviews into your workflow:

### 1. One-Click Deploy on WaveAssist (Recommended)

<p>
  <a href="https://waveassist.io/templates/gitzoid-template" target="_blank">
    <img src="https://waveassistapps.s3.us-east-1.amazonaws.com/public/Button.png" alt="Deploy on WaveAssist" width="230" />
  </a>
</p>


Deploy GitZoid instantly on [WaveAssist](https://waveassist.io) — a zero-infrastructure automation platform that handles orchestration, scheduling, secrets, and hosting for you.

> 🔐 You may be prompted to log in or create a free WaveAssist account before continuing.

#### How to Use:

1. Click the button above or go to [waveassist.io/templates/gitzoid-template](https://waveassist.io/templates/gitzoid-template)
2. Paste your credentials under the **Variable tab**:
   - `github_ghp_token`
   - `openai_key` or `anthropic_key`
3. Run the `InitializeRepositories` node once  
   ➤ Then edit the `repositories` variable if needed to select the right repositories.
4. Then run `FetchPRs` — GitZoid will:
   - Fetch PRs
   - Review them using AI
   - Post structured comments directly on your GitHub PRs
5. Finally, click **Deploy** to schedule this automation

✅ You’re now running GitZoid on autopilot.

---

### 2. Use GitZoid.com (No API Key Required)

Want to get started without OpenAI or Anthropic keys?
<p >
  <a href="https://gitzoid.com" target="_blank">
    <img src="https://img.shields.io/badge/%20Use%20GitZoid.com-No%20API%20Key%20Needed-0e1c3a" alt="Use GitZoid.com" />
  </a>
</p>


Just go to [gitzoid.com](https://gitzoid.com), enter:
- Your GitHub token
- The list of repositories to monitor

GitZoid will:
- Review PRs using hosted AI keys
- Post structured comments to your PRs — no setup required

---

### 3. Manual Deployment

Want to run GitZoid on your own infrastructure?

Clone this repo and use your preferred scheduler such as:
- Cron
- GitHub Actions
- Airflow or any scheduler

Scripts:
- `initialize_repositories.py`: seeds your repos
- `fetch_pull_requests.py`: fetches new PRs
- `generate_review.py`: uses AI to generate feedback
- `post_comment.py`: posts the feedback as PR comments
---

## Features

* **One-Time Repo Initialization**
  Seed your list of repositories into WaveAssist or a local store.
* **Automated PR Monitoring**
  Polls your repos for new pull requests at configurable intervals.
* **AI-Powered Code Reviews**
  Uses OpenAI or Anthropic to generate structured feedback.
* **Structured Feedback**
  Sections for Summary, Potential Issues, Optimizations, and Suggestions.
* **GitHub Integration**
  Posts generated reviews directly as comments on your PRs.
* **Configurable Models & Branches**
  Per-repo `target_branch` and `model` settings.

---

Built with ❤️ by the WaveAssist team. Want help or integrations? [Say hello](https://waveassist.io).
