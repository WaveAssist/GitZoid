# GitZoid: Open-Source AI-Powered GitHub PR Reviewer

![GitZoid Logo](https://img.shields.io/badge/GitZoid-AI%20Powered%20PR%20Reviews-blue)  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

GitZoid is an **open-source** GitHub bot that automates pull-request reviews and comments using AI models (OpenAI’s GPT-4o-mini or Anthropic’s Claude 3.5). By default, it’s designed to run on the WaveAssist platform—which handles node orchestration, scheduling, secrets/variable storage, and hosting—but you can also run it as a standalone Python application.

## Features

- **One-Time Repo Initialization**  
  Seed your list of repositories into WaveAssist or a local store.  
- **Automated PR Monitoring**  
  Polls your repos for new pull requests at configurable intervals.  
- **AI-Powered Code Reviews**  
  Uses OpenAI or Anthropic to generate structured feedback.  
- **Structured Feedback**  
  Sections for Summary, Potential Issues, Optimizations, and Suggestions.  
- **GitHub Integration**  
  Posts generated reviews directly as comments on your PRs.  
- **Configurable Models & Branches**  
  Per-repo `target_branch` and `model` settings.

## How It Works

1. **Initialize Repositories** (`initialize_repositories.py`, one-time)  
   - Reads your configured repo list and seeds it under the WaveAssist key `repositories`.  
2. **Fetch Pull Requests** (`fetch_pull_requests.py`, scheduled every 5 minutes)  
   - Loads `repositories` and `github_access_token`  
   - Fetches open PR metadata and diffs  
   - Stores results under `prs_to_review`  
3. **Generate Reviews** (`generate_review.py`, runs after PR-fetch)  
   - Loads `prs_to_review` and AI keys  
   - Builds structured prompts  
   - Calls OpenAI/Anthropic, writes `comment` into each PR object  
4. **Post Comments** (`post_comment.py`, runs after review)  
   - Loads `prs_to_review` and `github_access_token`  
   - Posts any new `comment` to GitHub  
   - Updates `prs_to_review` flags and `repositories` → `last_checked`

## Deployment

On **WaveAssist**, define four nodes:

* **InitializeRepositories** (one-time/manual)
* **FetchPRs** (every 5 minutes)
* **GenerateReview** (run\_after: FetchPRs)
* **PostComment** (run\_after: GenerateReview)

Standalone usage simply runs each script in sequence or via your own scheduler.
