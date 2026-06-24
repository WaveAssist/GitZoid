"""
analyze_activity.py — the Knowledge Digest chain's diff analyzer (node 3).

Adapted from GitDigest's analyze_repository_activity. The three-tier token-splitting strategy is
preserved exactly (it is the hard-won part): for each repo it fetches the real file diffs per commit
(zero-trust: it reads code, not commit messages), then

  Tier 1 (< 100K tokens): one LLM call for the whole week (max dot-connecting)
  Tier 2 (100K–700K):     split by day, batching adjacent small days up to ~90K
  Tier 3 (> 700K):        hybrid — compress oversized days to a per-commit budget, batch the rest

The one substantive change: GitDigest's per-repo `repository_contexts` summary is replaced by the
BRAIN (`profile:{repo}`), read ONLY if present. The brain is richer (architecture + conventions) and
optional, so a first-run digest that races the brain build still analyzes fine, just with less context.

Output (additive): `repository_analyses` = [{repository, changes:[{summary, category,
contributing_commits}]}], one entry per repo. Grouping into per-group reports happens downstream.

Testability: batch PLANNING (plan_batches / batch_small_days) is separated from LLM EXECUTION so the
tiering is unit-tested without mocking the model. Flat script, no __main__ guard, init() first.
"""
import time
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional
import requests
from pydantic import BaseModel, Field
import waveassist

waveassist.init()   # credits gated once upstream in digest_check_and_init

print("GitZoid Digest: starting repository activity analysis (analyze_activity) node")

# Diff analysis is bulk EXTRACTION (read every commit's diff, list the changes); the business/technical
# report nodes downstream do the user-facing writing on Sonnet. So this reads on the cheaper, faster
# Haiku to save credits and shorten the (slow, per-repo) digest run.
DEFAULT_MODEL = "anthropic/claude-haiku-4.5"
MAX_TOKENS = 8000   # reasoning/"pro" models spend this on hidden reasoning too
TEMPERATURE = 0.4
RATE_SLEEP = 0.5
HTTP_TIMEOUT = 20
GITHUB_API = "https://api.github.com"

# Token thresholds for the splitting strategy (chars→tokens at ~3 chars/token).
TIER_1_THRESHOLD = 100_000   # < 100K: single call
TIER_2_THRESHOLD = 700_000   # 100K–700K: split by day; above → Tier 3 hybrid
BATCH_THRESHOLD = 90_000     # combine adjacent small days up to this many tokens
CHARS_PER_TOKEN = 3
MAX_FILE_DIFF_SIZE = 90_000  # ~30K tokens; cap one file's diff

NON_CODE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff",
    ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm", ".mp3", ".wav", ".ogg", ".flac",
    ".zip", ".tar", ".gz", ".rar", ".7z", ".exe", ".dll", ".so", ".dylib",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".lock",
}


class Change(BaseModel):
    summary: str = Field(description="Brief summary of what changed")
    category: str = Field(description="Category: feature, improvement, fix, refactor, docs, test, chore")
    contributing_commits: List[str] = Field(description="Commit SHAs that contributed to this change")


class RepositoryAnalysis(BaseModel):
    changes: List[Change] = Field(description="Distinct changes identified in this batch")


# ---------------------------------------------------------------- pure helpers (tested)

def is_non_code_file(filename: str) -> bool:
    ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
    return ext in NON_CODE_EXTENSIONS


def estimate_tokens(text: str) -> int:
    return len(text) // CHARS_PER_TOKEN


def choose_tier(total_tokens: int) -> int:
    if total_tokens < TIER_1_THRESHOLD:
        return 1
    if total_tokens < TIER_2_THRESHOLD:
        return 2
    return 3


def group_commits_by_day(commits) -> Dict[str, List[Dict[str, Any]]]:
    by_day = defaultdict(list)
    for c in commits:
        ts = c.get("timestamp", "")
        try:
            day = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d") if ts else "unknown"
        except Exception:
            day = "unknown"
        by_day[day].append(c)
    return dict(by_day)


def build_commit_context(commits, commit_diffs, token_budget: Optional[int] = None) -> str:
    """Render commits + their diffs into one LLM context string. When token_budget is set, files are
    packed smallest-first and a file (or the whole commit) is truncated/dropped once the budget is hit."""
    parts, total_tokens = [], 0
    for commit in commits:
        sha = commit.get("sha", "")
        text = (f"Commit: {sha[:7]}\nAuthor: {commit.get('author', 'Unknown')}\n"
                f"Date: {commit.get('timestamp', '')}\nMessage: {commit.get('message', '')}\n")
        files = commit_diffs.get(sha, [])
        if token_budget:
            files = sorted(files, key=lambda f: len(f.get("patch", "") or ""))
        for f in files:
            file_text = f"File: {f['filename']} ({f.get('status', 'modified')})\n"
            if f.get("patch"):
                file_text += f"```\n{f['patch']}\n```\n"
            if token_budget and (total_tokens + estimate_tokens(file_text) > token_budget):
                file_text = (f"File: {f['filename']} ({f.get('status', 'modified')})\n"
                             f"[TRUNCATED: diff omitted due to token budget.]\n")
            text += file_text
        commit_tokens = estimate_tokens(text)
        if token_budget and (total_tokens + commit_tokens > token_budget):
            break
        parts.append(text)
        total_tokens += commit_tokens
    return "\n---\n".join(parts)


def batch_small_days(day_data, batch_threshold: int = BATCH_THRESHOLD):
    """Combine adjacent small days into batches up to batch_threshold tokens. day_data is a list of
    (day, day_commits, day_tokens). Returns [{commits, token_budget=None}]."""
    batches, cur, cur_tokens = [], [], 0
    for _day, day_commits, day_tokens in day_data:
        if cur and (cur_tokens + day_tokens > batch_threshold):
            batches.append({"commits": cur, "token_budget": None})
            cur, cur_tokens = [], 0
        cur = cur + list(day_commits)
        cur_tokens += day_tokens
    if cur:
        batches.append({"commits": cur, "token_budget": None})
    return batches


def plan_batches(commits, commit_diffs):
    """Decide the LLM calls for one repo's week using the three-tier strategy. Returns a list of
    {commits, token_budget}; each entry is one LLM call. No model is invoked here."""
    total = estimate_tokens(build_commit_context(commits, commit_diffs))
    tier = choose_tier(total)
    if tier == 1:
        return [{"commits": commits, "token_budget": None}]

    by_day = group_commits_by_day(commits)
    days = sorted(by_day)

    if tier == 2:
        day_data = [(d, by_day[d], estimate_tokens(build_commit_context(by_day[d], commit_diffs))) for d in days]
        return batch_small_days(day_data)

    # Tier 3: compress oversized days, batch the rest like Tier 2.
    large, small = [], []
    for d in days:
        dc = by_day[d]
        dt = estimate_tokens(build_commit_context(dc, commit_diffs))
        (large if dt > TIER_1_THRESHOLD else small).append((d, dc, dt))
    batches = []
    for _d, dc, _dt in large:
        budget = TIER_1_THRESHOLD // max(1, len(dc))
        batches.append({"commits": dc, "token_budget": budget})
    batches.extend(batch_small_days(small))
    return batches


def brain_context_section(profile) -> str:
    """A short context block from the brain (architecture + conventions), or "" if no brain yet.
    Optional by design — the digest never hard-depends on study_repos."""
    if not profile:
        return ""
    arch = (profile.get("architecture_summary") or "").strip()
    convs = [str(c) for c in (profile.get("conventions") or []) if c][:5]
    if not arch and not convs:
        return ""
    lines = ["Repository context (from GitZoid's profile):"]
    if arch:
        lines.append(f"- Architecture: {arch}")
    if convs:
        lines.append("- Conventions: " + "; ".join(convs))
    return "\n".join(lines) + "\n---\n"


# ---------------------------------------------------------------- github + llm (glue)

def _headers(token):
    return {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}


def fetch_commit_diff(repo_path, sha, headers) -> List[Dict[str, Any]]:
    """Real file diffs for one commit, non-code files dropped and oversized patches truncated."""
    try:
        r = requests.get(f"{GITHUB_API}/repos/{repo_path}/commits/{sha}", headers=headers, timeout=HTTP_TIMEOUT)
        time.sleep(RATE_SLEEP)
        if r.status_code != 200:
            return []
        files = []
        for f in (r.json().get("files", []) or []):
            filename = f.get("filename", "")
            if is_non_code_file(filename):
                continue
            patch = f.get("patch", "") or ""
            if len(patch) > MAX_FILE_DIFF_SIZE:
                patch = patch[:MAX_FILE_DIFF_SIZE] + "\n\n[TRUNCATED: file diff exceeds size limit.]"
            files.append({"filename": filename, "patch": patch, "status": f.get("status", "modified"),
                          "additions": f.get("additions", 0), "deletions": f.get("deletions", 0)})
        return files
    except Exception as e:
        print(f"⚠️ diff fetch failed for {repo_path}@{sha[:7]}: {e}")
        return []


def analyze_batch(repo_path, context, brain_section, model_name, attempts=2) -> Optional[RepositoryAnalysis]:
    """Returns the parsed analysis, or None if the LLM call errored on EVERY attempt (a real failure,
    distinct from a successful call that found no changes). attempts=2 is one retry — enough to ride out
    a transient `Claude CLI failed:` blip without paying for more than one extra call."""
    prompt = f"""Analyze the following Git commits and code changes from repository {repo_path}.

{brain_section}
Commits and Changes:
{context}

---

Your task:
1. Identify distinct changes/updates from these commits.
2. Group related commits that contribute to the same logical change.
3. Categorize each change as: feature, improvement, fix, refactor, docs, test, or chore.
4. Write a clear, concise summary for each change (1-2 sentences).

Guidelines:
- Focus on WHAT changed.
- Combine small related commits into single logical changes.
- Skip trivial changes (typos, formatting) unless part of a larger change.
- Include the commit SHAs that contributed to each change."""
    for i in range(attempts):
        try:
            return waveassist.call_llm(model=model_name, prompt=prompt, response_model=RepositoryAnalysis,
                                       max_tokens=MAX_TOKENS, temperature=TEMPERATURE)
        except Exception as e:
            print(f"⚠️ analysis LLM attempt {i + 1}/{attempts} failed for {repo_path}: {e}")
            if i < attempts - 1:
                time.sleep(2 ** i)
    return None


def process_repository(repo_path, activity_data, profile, headers, model_name) -> Dict[str, Any]:
    """One repo: fetch diffs, plan the tiered batches, run each, collect changes. Records `commit_count`
    and `analysis_failed` so downstream can tell a genuine quiet week from a broken analysis: an LLM
    error (after its retry) sets analysis_failed=True, which must NOT be rendered as 'nothing shipped'."""
    commits = activity_data.get("commits", []) or []
    if not commits:
        return {"repository": repo_path, "changes": [], "commit_count": 0, "analysis_failed": False}

    commit_diffs = {}
    for c in commits:
        sha = c.get("sha", "")
        if sha:
            diffs = fetch_commit_diff(repo_path, sha, headers)
            if diffs:
                commit_diffs[sha] = diffs

    brain_section = brain_context_section(profile)
    all_changes, failed = [], False
    for batch in plan_batches(commits, commit_diffs):
        context = build_commit_context(batch["commits"], commit_diffs, batch["token_budget"])
        result = analyze_batch(repo_path, context, brain_section, model_name)
        if result is None:
            failed = True            # LLM errored after its retry — don't trust an empty result as "quiet"
            continue
        all_changes.extend([c.model_dump(by_alias=True) for c in result.changes])
    return {"repository": repo_path, "changes": all_changes,
            "commit_count": len(commits), "analysis_failed": failed}


# ---------------------------------------------------------------- driver (flat, fall-through)

skip = waveassist.fetch_data("digest_skip_run", run_based=True, default="0") == "1"
github_activity_data = {} if skip else (waveassist.fetch_data("github_activity_data", default={}) or {})

if skip:
    print("GitZoid Digest: digest_skip_run set; analyze_activity no-op.")

if isinstance(github_activity_data, dict) and github_activity_data:
    access_token = waveassist.fetch_data("github_access_token", default="") or ""
    model_name = waveassist.fetch_data("lite_model", default=DEFAULT_MODEL) or DEFAULT_MODEL
    headers = _headers(access_token)

    repository_analyses = []
    for repo_path, activity_data in github_activity_data.items():
        print(f"🔍 analyzing {repo_path}...")
        try:
            profile = waveassist.fetch_data(f"profile:{repo_path}", default={}) or {}   # brain, optional
            analysis = process_repository(repo_path, activity_data or {}, profile, headers, model_name)
            repository_analyses.append(analysis)
            print(f"✓ {repo_path}: {len(analysis['changes'])} change(s)")
        except Exception as e:
            print(f"⚠️ analysis failed for {repo_path}: {e}; recording empty")
            repository_analyses.append({"repository": repo_path, "changes": [],
                                        "commit_count": len((activity_data or {}).get("commits") or []),
                                        "analysis_failed": True})
        waveassist.store_data("repository_analyses", repository_analyses, data_type="json")

    total_changes = sum(len(a["changes"]) for a in repository_analyses)
    print(f"GitZoid Digest: analysis complete — {total_changes} change(s) across "
          f"{len(repository_analyses)} repo(s).")
