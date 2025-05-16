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

## One-Click Deploy with WaveAssist

Deploy GitZoid instantly using the button below:

[![Deploy with WaveAssist](https://img.shields.io/badge/Deploy_with-WaveAssist-007F3B)](https://waveassist.io/templates/gitzoid-template)

### How to Use:

1. **Deploy** by clicking on this link: [Deploy GitZoid](https://waveassist.io/templates/gitzoid-template).
   - You’ll be taken to WaveAssist, where you can customize the deployment.
   - **Note**: You need a WaveAssist account (free forever tier available).

2. Once deployed, go to your project and go to the **Variables tab** (you'll see it pre-created) and **paste in your values for**:
   - `github_ghp_token`
   - `openai_key` or `anthropic_key`

3. Now, go to the **Nodes tab**:
   - Trigger `InitializeRepositories` once (only needed the first time).
   - Review the `repositories` variable if you'd like to prune/edit.

4. Trigger `FetchPRs`. Within seconds, GitZoid will:
   - Fetch PRs
   - Review them using AI
   - Post comments directly on your GitHub PRs

5. Once everything works, click the **Deploy** button in WaveAssist to make it run on schedule automatically.

---

### Optional: Enable Real-Time Reviews via GitHub Webhooks

Want GitZoid to respond to new PRs in real-time?

- Go to the **`FetchPRs` node** in WaveAssist
- Copy the **Webhook URL**
- Add it as a GitHub webhook for your repo:
  - Events to select: `Pull requests`
  - Method: `POST`
  - Content-Type: `application/json`

GitZoid will now review PRs as soon as they're opened.

---

## Manual Deployment (Advanced)

You can also run each script locally or schedule with your own orchestrator (like cron or Airflow). But WaveAssist is easier.

## How It Works

1. **Initialize Repositories** (`initialize_repositories.py`)
   - Trigger-only. Seeds your repository list to the `repositories` variable.

2. **Fetch Pull Requests** (`fetch_pull_requests.py`)
   - Scheduled or webhook-triggered.
   - Loads your repos and GHP token.
   - Fetches open PRs and diffs → stores them in `prs_to_review`.

3. **Generate Reviews** (`generate_review.py`)
   - Run after FetchPRs.
   - Uses AI to generate suggestions/comments.
   - Adds review to each PR entry.

4. **Post Comments** (`post_comment.py`)
   - Posts the AI review back to the PR on GitHub.

---

