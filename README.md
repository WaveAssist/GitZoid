<p align="center">
  <img src="https://waveassist.io/images/templates/gitzoid/GitzoidLogoDark.png" alt="GitZoid open source AI agent for GitHub code review, security, and digests" width="200" />
</p>

<h1 align="center">GitZoid: Open Source AI Agent for GitHub</h1>

<p align="center">
  <b>Reviews every pull request, watches your code for security issues, and emails a weekly summary of what shipped.</b><br/>
  No noise, just what matters.
</p>

<p align="center">
  <a href="https://waveassist.io/assistants/gitzoid">
    <img src="https://img.shields.io/badge/Deploy_with-WaveAssist-007F3B" alt="Deploy GitZoid on WaveAssist" />
  </a>
  <img src="https://img.shields.io/badge/GitZoid-Code_Review_•_Security_•_Digest-blue" alt="GitZoid AI agent badge" />
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License" />
  </a>
  <a href="https://gitzoid.com/blog/how-to-get-your-github-token-for-gitzoid-fine-grained-classic">
    <img src="https://img.shields.io/badge/Guide-How_to_Get_GitHub_Token-red" alt="How to get GitHub token guide" />
  </a>
</p>

---

## Overview

GitZoid is an open source AI agent for GitHub that does three things, all inside the GitHub you already use.

1. Reviews every pull request with clear, specific fixes.
2. Watches your code and dependencies for security issues, and emails you only when there is something real to fix.
3. Sends a weekly digest of what actually shipped across your repos.

No separate GPT or Claude keys are required. On WaveAssist, an OpenRouter token is included free up to a generous usage limit, and WaveAssist handles node orchestration, scheduling, secrets storage, and hosting. GitZoid runs on Claude (Sonnet 4.6) through that token. You can also run it as a standalone set of Python scripts on your own infrastructure.

It is read only, so GitZoid comments and emails but never silently changes your code. It works with public and private repos you have access to.

Try the hosted version at [https://gitzoid.com](https://gitzoid.com) with no setup required.

<p align="center">
  <img src="https://waveassist.io/images/templates/gitzoid/pr_review.png" alt="GitZoid AI agent posting an automated GitHub pull request review" width="100%" />
</p>

---

## What GitZoid Does

### AI Code Reviews

Reviews every pull request and comments with clear, specific fixes, automatically, ranked by severity with no noise. When new commits are pushed to a PR, GitZoid detects the changes and posts a focused incremental review instead of repeating itself (see [How Incremental Reviews Work](#how-incremental-reviews-work)).

It runs continuously, about every two minutes or on a webhook. Each repo can steer the reviewer with a `review.md` file — set a severity floor, ignore paths, focus areas, or opt out entirely (see [Customizing Reviews Per Repo](#customizing-reviews-per-repo)).

### Security Watch

Finds real security holes in your code and dependencies, and emails you only when there is something to fix.

* **Daily dependency and supply chain scan.** It reads your manifests and lockfiles, matches installed packages against the public [OSV.dev](https://osv.dev) vulnerability database, and cross checks each hit against the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) feed, which flags what is being exploited right now.
* **Weekly deep code audit.** A slower, deeper pass over your code for authorization holes, leaked secrets, and backdoors.
* **Context, not noise.** Unlike a raw scanner, GitZoid reads each finding in the context of your repo, asking whether the package is actually used and whether it sits in an auth path, and reports only real, exploitable issues, each with who is affected and a fix you can run. When nothing is exploitable, it stays silent. Silence is the all clear.
* **No repeats.** It never alerts you twice about an issue you have already seen. Once it has told you to upgrade a package, a new advisory on that same package does not trigger another email, because the fix is unchanged.

> How is this different from Dependabot or GitHub's built in scanning? Those raw scans are free and noisy. GitZoid reports only what is real and exploitable, with the fix to run.

### Weekly Digest

A plain English summary of what shipped across your repos, every Monday, read from your actual code diffs rather than commit messages, grouped by project, with a security roll up of what is new, still open, and resolved. Even a quiet week gets one short email and a PDF.

> Formerly GitDigest, now built into GitZoid as its weekly digest.

---

## Three Ways to Run GitZoid

### 1. One Click Deploy on WaveAssist (Recommended)

<p>
  <a href="https://waveassist.io/assistants/gitzoid" target="_blank">
    <img src="https://waveassist.io/images/templates/Button.png" alt="Deploy GitZoid on WaveAssist" width="230" />
  </a>
</p>

Deploy instantly on [WaveAssist](https://waveassist.io), a zero infrastructure AI agent platform that handles everything, including your free OpenRouter AI token.

How to use it.

1. Click the button or visit [waveassist.io/assistants/gitzoid](https://waveassist.io/assistants/gitzoid).
2. Connect your GitHub account (or enter a Personal Access Token) and pick the repositories to monitor. No OpenAI or Anthropic key is needed. Learn how to generate a token in [How to Get GitHub Token](https://gitzoid.com/blog/how-to-get-your-github-token-for-gitzoid-fine-grained-classic).
3. Optionally toggle Security Watch and the Knowledge Digest, and add CC recipients for security alerts.
4. Click Run and Deploy to schedule everything automatically.

You are now running GitZoid on autopilot.

---

### 2. Use GitZoid.com (No API Key Required)

<p>
  <a href="https://gitzoid.com" target="_blank">
    <img src="https://img.shields.io/badge/%20Use%20GitZoid.com-No%20API%20Key%20Needed-0e1c3a" alt="Use GitZoid.com hosted AI agent for GitHub" />
  </a>
</p>

Head to [gitzoid.com](https://gitzoid.com), enter your GitHub token and the repositories to monitor. GitZoid uses hosted AI credits, so no keys or setup are required.

---

### 3. Manual Deployment

Want full control on your own infrastructure? Clone this repo and schedule the node scripts however you like, with cron, GitHub Actions, Airflow, or anything else. The agent is organized as three independent chains (see [Architecture](#architecture)), each on its own clock.

---

## Architecture

GitZoid is a set of flat Python node scripts wired into three independent DAG chains, defined in [`config.yaml`](config.yaml). Each chain runs on its own schedule and never blocks the others.

### Review chain (every two minutes)

| Node | What it does |
| --- | --- |
| `check_credits_and_init.py` | Gates on credits and initializes the run. |
| `study_repos.py` | Builds a per repo brain profile of architecture, dependencies, and auth paths, and refreshes it every two weeks. |
| `fetch_pull_requests.py` | Pulls in new and updated pull requests, plus per-repo review config (`review.md`, `CLAUDE.md`/`AGENTS.md`) and existing PR comments. Applies repo/PR/file opt-outs. |
| `generate_review.py` | Generates the structured review, plus incremental reviews on later commits. |
| `post_comment.py` | Posts the review back to GitHub. |

### Security chain (dependency scan daily, deep audit weekly)

| Node | What it does |
| --- | --- |
| `security_check_and_init.py` | Gates on credits and the `enable_security` toggle, then takes the run lock. |
| `scan_dependencies.py` | Daily OSV and CISA KEV dependency and supply chain scan. |
| `deep_security_audit.py` | Weekly deep code audit covering authz, secrets, and backdoors. |
| `triage_and_alert.py` | The single gatekeeper. It dedupes against the persistent ledger, alerts again only on real escalation, and sends one consolidated email. Silent when clean. |

### Knowledge Digest chain (weekly, Monday 08:30 UTC)

| Node | What it does |
| --- | --- |
| `digest_check_and_init.py` | Gates on credits and the `enable_digest` toggle, then resolves the per group working set. |
| `fetch_activity.py` | Collects the week's merged activity per repo. |
| `analyze_activity.py` | Reads the actual diffs to understand what shipped. |
| `generate_business_report.py` | Writes the leadership ready summary. |
| `generate_technical_report.py` | Writes the technical detail. |
| `send_digest.py` | Sends the per group email and PDF. |

Conventions across nodes. Flat scripts, `waveassist.init()` runs first, no sibling node imports, every external call has an explicit timeout, and one bad repo never sinks the batch because each step soft fails.

---

## How Incremental Reviews Work

GitZoid tracks the last reviewed commit SHA for each PR. When it detects new commits it does the following.

1. **Detection.** It compares `head.sha` from GitHub with the stored `last_reviewed_sha`.
2. **Diff fetching.** It uses GitHub's Compare API to fetch only the new changes.
3. **Context aware review.** It reads previous GitZoid comments to understand what was already flagged.
4. **Focused feedback.** It posts an incremental review that acknowledges addressed issues and highlights new concerns.

This ensures your team gets relevant, focused feedback on each iteration, not repeated comments about code that has not changed.

---

## Customizing Reviews Per Repo

GitZoid reads optional configuration from each repo it reviews, so a team can steer the reviewer, teach it their house style, and opt code (or whole repos) out — all without touching GitZoid itself. Everything here is **optional and fail-open**: if a file is missing or malformed, GitZoid simply reviews as usual.

### Context GitZoid picks up automatically

| Source | What it does |
| --- | --- |
| `.gitzoid/review.md` (or `review.md` at the repo root) | Free-form review guidance written by the repo's authors — what to watch for, what to ignore, house conventions. Injected into the review prompt as context. |
| `CLAUDE.md` (or `AGENTS.md`) | The repo's own conventions doc. Injected so reviews judge convention-fit instead of guessing. |
| Existing PR comments | Comments already on the PR (from humans or other tools, bot noise filtered out) are shown to the reviewer so it builds on the discussion instead of repeating points already made. |

All three are treated as **informational context only**. They steer focus and style but never override GitZoid's review rules or output format, and their text is never executed as an instruction to the reviewer (prompt-injection safe).

### Controls in `review.md` front-matter

`review.md` can start with a small YAML-style front-matter block (between `---` fences) to control *how* the repo is reviewed. Only the top-level keys below are recognized; everything else is ignored, and the rest of the file is used as review guidance.

```markdown
---
skip: false                 # true opts this whole repo out of reviews
severity_floor: medium      # only report findings at this severity or higher (high | medium | low)
ignore:                     # skip changed files matching these globs
  - "dist/**"
  - "*.lock"
  - "docs/**"
focus:                      # areas to prioritize in the review
  - "auth and permission checks"
  - "N+1 database queries"
---

Free-form review guidance goes here, after the front-matter.
Anything below the closing --- is passed to the reviewer as context.
```

- **`skip`** — `true` opts the entire repo out of PR review.
- **`severity_floor`** — `high` / `medium` / `low`; only findings at or above this level are posted. Overrides the per-repo severity setting from the dashboard.
- **`ignore`** — glob list; changed files matching any glob are dropped before review. A bare directory name (`docs`) does **not** match its subtree — use `docs/` or `docs/**`. Standard `fnmatch` wildcards apply (`*.lock`, `src/**/*.generated.ts`).
- **`focus`** — free-text areas the reviewer should prioritize.

Inline list form also works: `ignore: [dist/**, "*.lock"]`.

### Skip a single PR

Add the **`gitzoid-skip`** label to any pull request and GitZoid will not review it. Handy for WIP, generated, or vendored PRs without changing repo config.

> **Note:** Per-repo config is cached for about an hour to avoid re-fetching from GitHub on every ~2-minute cycle, so changes to `review.md` (including `skip`) take effect within ~1h.

---

## Development

Tests run with `pytest`.

```bash
pytest tests/unit          # fast, hermetic unit tests
pytest                     # full suite
```

The suite is hermetic. The WaveAssist SDK network I/O is neutralized at import time (see `tests/conftest.py`), so importing a node script never makes a real API call.

---

Built with ❤️ by the WaveAssist team. Have questions or want integrations? [Say hello](https://waveassist.io).
