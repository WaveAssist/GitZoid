# GitZoid: Open-Source AI-Powered GitHub PR Reviewer

![GitZoid Logo](https://img.shields.io/badge/GitZoid-AI%20Powered%20PR%20Reviews-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Deploy on WaveAssist](https://img.shields.io/badge/Deploy%20on-WaveAssist-1D2430?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyBmaWxsPSJ3aGl0ZSIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIiB2aWV3Qm94PSIwIDAgMjQgMjQiPjxwYXRoIGQ9Ik0xMiAybDkgMTYtOSA1LTktNSA5LTE2eiIvPjwvc3ZnPg==)](https://waveassist.io/deploy/gitzoid)


## Overview

GitZoid is an **open-source** GitHub bot that automates pull-request reviews and comments using AI models (OpenAI’s GPT-4o-mini or Anthropic’s Claude 3.5). By default, it’s designed to run on the [WaveAssist](https://waveassist.io) platform—which handles node orchestration, scheduling, secrets/variable storage, and hosting—but you can also run it as a standalone Python application.

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

## How It Works

1. **Initialize Repositories** (`initialize_repositories.py`, one-time)

   * Reads your configured repo list and seeds it under the WaveAssist key `repositories`.
2. **Fetch Pull Requests** (`fetch_pull_requests.py`, scheduled every 5 minutes)

   * Loads `repositories` and `github_access_token`
   * Fetches open PR metadata and diffs
   * Stores results under `prs_to_review`
3. **Generate Reviews** (`generate_review.py`, runs after PR-fetch)

   * Loads `prs_to_review` and AI keys
   * Builds structured prompts
   * Calls OpenAI/Anthropic, writes `comment` into each PR object
4. **Post Comments** (`post_comment.py`, runs after review)

   * Loads `prs_to_review` and `github_access_token`
   * Posts any new `comment` to GitHub
   * Updates `prs_to_review` flags and `repositories` → `last_checked`

Here’s the updated **Deployment** section for your `README.md`, incorporating:

* the 365-day schedule for `InitializeRepositories`
* simplified instructions for adding nodes, variables, and libraries
* and a note on the upcoming **One-Click Deploy** feature.

---

## Deployment / How to Run

### Option 1: Deploy with WaveAssist (Recommended)

Deploy GitZoid effortlessly on [WaveAssist](https://waveassist.io):

1. Visit [waveassist.io](https://waveassist.io)

2. **Create a free account** if you don’t already have one

3. Set up the following four nodes:

   * `InitializeRepositories` (entrypoint: `initialize_repositories.py`, **run every 365 days**)
   * `FetchPRs` (entrypoint: `fetch_pull_requests.py`, **every 5 minutes**)
   * `GenerateReview` (entrypoint: `generate_review.py`, **run\_after: FetchPRs**)
   * `PostComment` (entrypoint: `post_comment.py`, **run\_after: GenerateReview**)

4. Paste the contents of each `.py` file into its respective node

5. Create 3 variables:

   * `github_ghp_token`
   * `openai_key`
   * `anthropic_key` (Optional)

6. Add 2 required libraries: (Both are required)

   * `openai==1.14.3`
   * `anthropic==0.49.0`

✅ Run! GitZoid will now fetch PRs, review them with AI, and post comments on GitHub—all on autopilot.

> 🚀 **One-Click Deploy via WaveAssist UI – Coming Soon**

### Option 2: Standalone Python

You can also run each script locally or through your own scheduler (e.g., cron, Airflow, etc.).
