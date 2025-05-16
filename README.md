<p align="center">
  <img src="https://gitzoid.com/logo.png" alt="GitZoid Logo" width="200" />
</p>

<p align="center">
  <img src="https://waveassistapps.s3.us-east-1.amazonaws.com/public/gitzoid-og-home.png" alt="GitZoid UI Preview" width="100%" />
</p>

<h1 align="center">GitZoid: Open-Source AI-Powered GitHub PR Reviewer ⚡</h1>

<p align="center">
  <a href="https://waveassist.io/templates/gitzoid-template" target="_blank">
    <img src="https://img.shields.io/badge/🚀%20Deploy_on_WaveAssist-007F3B?style=for-the-badge" alt="Deploy on WaveAssist" />
  </a>
  <a href="https://gitzoid.com/blog/how-to-get-your-github-token-for-gitzoid-fine-grained-classic" target="_blank">
    <img src="https://img.shields.io/badge/📘%20GitHub_Token_Guide-1E88E5?style=for-the-badge" alt="GitHub Token Guide" />
  </a>
</p>

---

## Overview 📦

GitZoid is an **open-source** GitHub bot that automates pull-request reviews and comments using AI models (OpenAI’s GPT-4o-mini or Anthropic’s Claude 3.5). By default, it’s designed to run on the [WaveAssist](https://waveassist.io) platform—which handles node orchestration, scheduling, secrets/variable storage, and hosting—but you can also run it as a standalone Python application.

👉 Try the hosted version at [https://gitzoid.com](https://gitzoid.com) — no setup required.

---

## 🔧 Features

* **One-Time Repo Initialization**
* **Automated PR Monitoring**
* **AI-Powered Code Reviews**
* **Structured Feedback** (Summary, Issues, Optimizations)
* **GitHub Integration**
* **Configurable Models & Branches**

---

##  3 Ways to Get Your PRs Reviewed with GitZoid

GitZoid offers multiple ways to integrate AI-powered code reviews into your workflow:

---

### 🚀 1. One-Click Deploy on WaveAssist

<p>
  <a href="https://waveassist.io/templates/gitzoid-template" target="_blank">
    <img src="https://waveassistapps.s3.us-east-1.amazonaws.com/public/Button.png" alt="Deploy on WaveAssist" width="280" />
  </a>
</p>


Deploy GitZoid instantly on [WaveAssist](https://waveassist.io) — a zero-infrastructure automation platform that handles orchestration, scheduling, secrets, and hosting for you.

#### How to Use:

1. Click the button above or go to [waveassist.io/templates/gitzoid-template](https://waveassist.io/templates/gitzoid-template)
2. Paste your credentials under the **Data tab**:
   - `github_ghp_token`
   - `openai_key` or `anthropic_key`
3. Run the `InitializeRepositories` node once
4. Then run `FetchPRs` — GitZoid will:
   - Fetch PRs
   - Review them using AI
   - Post structured comments directly on your GitHub PRs
5. Click **Deploy** to schedule the automation

✅ You’re now running GitZoid on autopilot.

---

### 🌐 2. Use GitZoid.com (No API Key Required)

Want to get started without OpenAI or Anthropic keys?

Just go to [gitzoid.com](https://gitzoid.com), enter:
- Your GitHub token
- The list of repositories to monitor

GitZoid will handle the rest using our hosted AI keys.

---

### ⚙️ 3. Manual Deployment (Advanced Users)

Prefer running GitZoid on your own infra?

Clone this repo and run the scripts using:
- Cron
- GitHub Actions
- Airflow or any scheduler

Scripts:
- `initialize_repositories.py`: seeds your repos
- `fetch_pull_requests.py`: fetches new PRs
- `generate_review.py`: uses AI to generate feedback
- `post_comment.py`: posts the feedback as PR comments

---

## ⚙️ How It Works

1. **Initialize Repositories** (`initialize_repositories.py`)  
   Seeds your repository list into a variable store

2. **Fetch Pull Requests** (`fetch_pull_requests.py`)  
   Loads repos, fetches open PRs + diffs → stores them in memory

3. **Generate Reviews** (`generate_review.py`)  
   Uses AI to write feedback for each PR

4. **Post Comments** (`post_comment.py`)  
   Posts feedback back to GitHub PRs as a comment

---

Built with ❤️ by the WaveAssist team. Want help or integrations? [Say hello](https://waveassist.io).
