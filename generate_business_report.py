"""
generate_business_report.py — the Knowledge Digest chain's business report (node 4, per group).

Adapted from GitDigest: same BusinessReport shape (executive_summary + 1-3 shipped_features) and the
rolling 1-week history for continuity, but fanned out PER resolved group — each group is its own
"project" with its own report and its own history. Repository context comes from the brain
(profile:{repo}, optional) instead of the dropped repository_contexts node.

For each group it filters the per-repo analyses to that group's repos; an idle group (no changes)
gets a deterministic empty report with no LLM call. Per-group reports are published run-based as
`digest_business_reports = {slug: report}` for the technical node and send_digest; per-group history
lives in the persistent `digest_state = {slug: {business_report_history, ...}}`.

Flat script, no __main__ guard, init() first, no sibling imports (helpers duplicated by design).
"""
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from pydantic import BaseModel, Field
import waveassist

waveassist.init()   # credits gated once upstream in digest_check_and_init

print("GitZoid Digest: starting business report generation (generate_business_report) node")

DEFAULT_MODEL = "anthropic/claude-sonnet-4.6"
MAX_TOKENS = 8000   # reasoning/"pro" models spend this on hidden reasoning too


class BusinessReport(BaseModel):
    executive_summary: str = Field(description="2 sentences on the week's biggest impact")
    shipped_features: List[str] = Field(description="Top 1-3 user-facing capabilities completed")


# ---------------------------------------------------------------- pure helpers (tested)

def filter_analyses(repository_analyses, group_repos):
    s = set(group_repos or [])
    return [a for a in (repository_analyses or []) if a.get("repository") in s]


def count_changes(analyses):
    return sum(len(a.get("changes", []) or []) for a in (analyses or []))


def build_changes_context(analyses) -> str:
    """Compact JSON of {repo: changes} for repos that actually changed (the PRIMARY source)."""
    result = {a.get("repository", "Unknown"): a.get("changes", [])
              for a in (analyses or []) if a.get("changes")}
    return json.dumps(result, default=str, ensure_ascii=False, separators=(",", ":")) if result else ""


def build_history_context(history) -> str:
    if not history:
        return ""
    parts = ["Previous week's business report, for context only:"]
    for entry in history:
        parts.append(f"Week of {entry.get('week', 'Unknown')}:\n"
                     f"{json.dumps(entry.get('report', {}), default=str, ensure_ascii=False, separators=(',', ':'))}")
    return "\n---\n".join(parts)


def roll_history(history, week, report):
    """Keep the most recent prior week, then append this week (max 2 entries)."""
    hist = list(history) if isinstance(history, list) else []
    hist = hist[-1:]
    hist.append({"week": week, "report": report})
    return hist


def brain_block(profiles_by_repo) -> str:
    """Concatenated brain context (architecture) for the group's active repos, or "" if no brain."""
    parts = []
    for repo, profile in (profiles_by_repo or {}).items():
        arch = ((profile or {}).get("architecture_summary") or "").strip()
        if arch:
            parts.append(f"- {repo}: {arch}")
    return ("Repository context (from GitZoid's profile):\n" + "\n".join(parts)) if parts else ""


def build_prompt(project_name, changes_context, history_context, brain_context) -> str:
    parts = [
        ("You are a business-focused advisor reporting to a busy CEO. "
         f"Review the development activity for {project_name}. "
         "Extract the 2-3 biggest user-facing wins. Ignore the plumbing. "
         "If a section has no significant updates, strictly return an empty list."),
    ]
    if brain_context:
        parts.append("\n<Repo Context>\n" + brain_context)
    if history_context:
        parts.append("\n<Previous Report Context>\n" + history_context)
    if changes_context:
        parts.append("\n*** PRIMARY SOURCE: Code Changes Summarized ***\n" + changes_context)
    parts.append("""
Create a concise business report identifying the headline features (The Signal).

CRITICAL INSTRUCTIONS:
- Extract headlines only: the 2-3 biggest user-facing features. Ignore internal refactors and fixes
  unless they directly enable a major new capability.
- Translate technical changes into user-facing benefits and business outcomes.
- Skip plumbing, maintenance, and minor improvements.

1. executive_summary: exactly 2 sentences on the week's biggest impact, outcome-focused.
2. shipped_features: MAXIMUM 3 (ideally 1-3) completed, user-facing capabilities in plain language.

Write for a busy CEO. Avoid jargon. Be honest but positive. Plain prose in short sentences. Do NOT
use em dashes, and do not use a hyphen as a connector between clauses. No emojis in the text.""")
    return "".join(parts)


def empty_report(project_name):
    return {"executive_summary": f"No development activity was recorded for {project_name} this week.",
            "shipped_features": []}


def maintenance_report(project_name, commit_count):
    """Honest wording for a week that HAD commits but no user-facing changes. Prevents the contradiction
    of a 'no activity' summary sitting next to a non-zero commit counter in the email."""
    word = "commit" if commit_count == 1 else "commits"
    return {"executive_summary": (f"{commit_count} {word} landed for {project_name} this week, all "
                                  f"maintenance or internal work, with nothing user-facing to report."),
            "shipped_features": []}


def group_commit_count(analyses):
    return sum(int(a.get("commit_count", 0) or 0) for a in (analyses or []))


def group_analysis_failed(analyses):
    """True if ANY repo in the group failed analysis (LLM/diff error). We then refuse to call it a quiet
    week — better to send nothing than a false 'nothing shipped'."""
    return any(a.get("analysis_failed") for a in (analyses or []))


# ---------------------------------------------------------------- driver (flat, fall-through)

skip = waveassist.fetch_data("digest_skip_run", run_based=True, default="0") == "1"
groups = [] if skip else (waveassist.fetch_data("digest_resolved_groups", run_based=True, default=[]) or [])

if skip:
    print("GitZoid Digest: digest_skip_run set; generate_business_report no-op.")

if groups:
    repository_analyses = waveassist.fetch_data("repository_analyses", default=[]) or []
    model_name = waveassist.fetch_data("model_name", default=DEFAULT_MODEL) or DEFAULT_MODEL
    digest_state = waveassist.fetch_data("digest_state", default={}) or {}
    week = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    business_reports = {}
    for group in groups:
        slug = group.get("slug")
        name = group.get("name") or "your repositories"
        analyses = filter_analyses(repository_analyses, group.get("repos") or [])
        state = digest_state.get(slug) or {}

        if count_changes(analyses) == 0:
            # No user-facing changes. Three sub-cases, and only the last is a real "quiet week":
            if group_analysis_failed(analyses):
                # The analysis broke (e.g. transient `Claude CLI failed:`). NOT a quiet week — flag so
                # send_digest's existing generation_failed gate skips this group (no false email).
                rep = empty_report(name)
                rep["generation_failed"] = True
                business_reports[slug] = rep
                print(f"⚠️ {slug}: upstream analysis failed; flagged to skip (no false 'quiet week' email)")
                continue
            commits = group_commit_count(analyses)
            if commits > 0:
                # Commits happened but nothing user-facing — say so honestly (matches the commit counter).
                business_reports[slug] = maintenance_report(name, commits)
                print(f"· {slug}: {commits} commit(s), no user-facing changes; maintenance-week report")
                continue
            business_reports[slug] = empty_report(name)
            print(f"· {slug}: genuinely quiet (no commits); empty business report")
            continue

        profiles = {a["repository"]: (waveassist.fetch_data(f"profile:{a['repository']}", default={}) or {})
                    for a in analyses if a.get("changes")}
        prompt = build_prompt(name, build_changes_context(analyses),
                              build_history_context(state.get("business_report_history") or []),
                              brain_block(profiles))
        try:
            result = waveassist.call_llm(model=model_name, prompt=prompt, response_model=BusinessReport,
                                         max_tokens=MAX_TOKENS)
        except Exception as e:
            print(f"⚠️ business LLM failed for {slug}: {e}")
            result = None

        if result:
            report = result.model_dump(by_alias=True)
            business_reports[slug] = report
            state["business_report_history"] = roll_history(state.get("business_report_history") or [], week, report)
            digest_state[slug] = state
            print(f"✓ {slug}: business report generated")
        else:
            report = empty_report(name)
            report["generation_failed"] = True   # LLM raised — NOT a quiet week; send_digest must skip this group
            business_reports[slug] = report
            print(f"⚠️ {slug}: business report generation FAILED (LLM error); flagged")

    waveassist.store_data("digest_business_reports", business_reports, run_based=True, data_type="json")
    waveassist.store_data("digest_state", digest_state, data_type="json")
    print(f"GitZoid Digest: business reports for {len(business_reports)} group(s).")
