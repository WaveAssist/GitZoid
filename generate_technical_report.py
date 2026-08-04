"""
generate_technical_report.py — the Knowledge Digest chain's technical report (node 5, per group).

Adapted from GitDigest: same TechnicalReport shape (repository_deep_dive + poem), fanned out per
resolved group, with the business report as context to avoid duplication. The substantive addition is
the deterministic SECURITY ROLL-UP: for each group it reads the shared `security_findings` ledger and
partitions this group's repos' findings into new (alerted in the last 7 days), still-open (carried),
and resolved-this-week. No LLM — the plain-English finding text was written upstream by the Security
chain; here we only count and list. This roll-up is the weekly "we watched, here is the state"
reassurance that makes Security Watch's silence trustworthy, so it ships even in a quiet, no-code week.

Output (additive, run-based): `digest_technical_reports = {slug: {repository_deep_dive, poem,
security_rollup}}` consumed by send_digest. Flat script, no __main__ guard, no sibling imports.
"""
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from pydantic import BaseModel, Field
import waveassist

waveassist.init()   # credits gated once upstream in digest_check_and_init

print("GitZoid Digest: starting technical report generation (generate_technical_report) node")

DEFAULT_MODEL = "anthropic/claude-sonnet-4.6"
MAX_TOKENS = 8000   # reasoning/"pro" models spend this on hidden reasoning too
ROLLUP_WINDOW_DAYS = 7
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

QUIET_POEM = [
    "Quiet repos rest, untouched branches dreaming of merge lights",
    "Product sleeps softly, backlog whispers promises for next sprint",
    "Engineers sip coffee, plotting fresh commits for Monday",
    "Calm before velocity, waiting for ideas to spark",
]


class RepoUpdate(BaseModel):
    repo_name: str = Field(description="Repository name (owner/repo)")
    status: str = Field(description="1-2 words for the repo's status (e.g. 'Heavy Refactor', 'Feature Dev')")
    technical_changes: List[str] = Field(description="MAX 2-3 specific fixes/improvements in this repo")


class TechnicalReport(BaseModel):
    repository_deep_dive: List[RepoUpdate] = Field(description="Updates grouped by repository")
    poem: List[str] = Field(description="4 lines, tech-focused, rhyming, each 6-10 words")


# ---------------------------------------------------------------- pure helpers (tested)

def filter_analyses(repository_analyses, group_repos):
    s = set(group_repos or [])
    return [a for a in (repository_analyses or []) if a.get("repository") in s]


def count_changes(analyses):
    return sum(len(a.get("changes", []) or []) for a in (analyses or []))


def group_commit_count(analyses):
    return sum(int(a.get("commit_count", 0) or 0) for a in (analyses or []))


def build_changes_context(analyses) -> str:
    result = {a.get("repository", "Unknown"): a.get("changes", [])
              for a in (analyses or []) if a.get("changes")}
    return json.dumps(result, default=str, ensure_ascii=False, separators=(",", ":")) if result else ""


def build_business_report_context(business_report) -> str:
    if not business_report:
        return ""
    parts = ["The Business Report already summarised the headline features. "
             "Focus on repository-specific technical details:"]
    if business_report.get("executive_summary"):
        parts.append(f"Executive Summary: {business_report['executive_summary']}")
    if business_report.get("shipped_features"):
        parts.append(f"Shipped Features: {json.dumps(business_report['shipped_features'], ensure_ascii=False)}")
    return "\n".join(parts)


def _within_days(iso, now, days) -> bool:
    if not iso:
        return False
    try:
        return (now - datetime.fromisoformat(iso)).total_seconds() <= days * 86400
    except Exception:
        return False


def _slim(e, count=1):
    # Dependency entries carry no human title; build a package+version label (a bare "django" with no
    # version was the bug). count = how many advisories this grouped item represents.
    if e.get("category") == "dependency":
        title = f"{e.get('name') or ''} {e.get('version') or ''}".strip() or "dependency"
    else:
        title = e.get("title") or e.get("name") or e.get("category")
    return {"title": title, "repo": e.get("repo"), "severity": e.get("severity"),
            "actively_exploited": bool(e.get("actively_exploited")), "count": count}


def _group_rollup_entries(entries):
    """Group a bucket's entries the SAME way the alert email does: a dependency package
    (repo, name, version) is ONE item (count = #advisories); code findings stay individual. This
    keeps the digest's counts/list consistent with the alert (the '17 vs 6' class of bug)."""
    groups, order = {}, []
    for e in entries:
        if e.get("category") == "dependency":
            key = ("dep", e.get("repo"), e.get("name"), e.get("version"))
        else:
            key = ("code", e.get("sig") or id(e))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(e)
    items = []
    for key in order:
        g = groups[key]
        worst = sorted(g, key=lambda x: _SEV_RANK.get(x.get("severity"), 4))[0]
        items.append(_slim(worst, count=len(g)))
    return items


def security_rollup(ledger, group_repos, now, days=ROLLUP_WINDOW_DAYS):
    """Partition this group's security findings into new (first alerted in the window), still-open
    (carried from before), and resolved-this-week, then GROUP per package so the digest count matches
    the alert. Deterministic; the finding text was written upstream."""
    repos = set(group_repos or [])
    new_e, open_e, res_e = [], [], []
    for e in (ledger or {}).values():
        if not isinstance(e, dict) or e.get("repo") not in repos:
            continue
        status = e.get("status")
        if status == "open":
            (new_e if _within_days(e.get("first_seen"), now, days) else open_e).append(e)
        elif status == "resolved" and _within_days(e.get("resolved_at"), now, days):
            res_e.append(e)

    new = _group_rollup_entries(new_e)
    still_open = _group_rollup_entries(open_e)
    resolved = _group_rollup_entries(res_e)

    def keyf(x):
        return (0 if x["actively_exploited"] else 1, _SEV_RANK.get(x["severity"], 4))
    new.sort(key=keyf)
    still_open.sort(key=keyf)
    resolved.sort(key=keyf)
    return {"new": new, "still_open": still_open, "resolved": resolved,
            "counts": {"new": len(new), "still_open": len(still_open), "resolved": len(resolved)}}


def group_scanned(group_repos):
    """True iff Security Watch has actually scanned at least one of this group's repos — i.e. a
    `dependency_snapshot:{repo}` exists (scan_dependencies writes one for every repo it processes).
    An empty roll-up then means one of two very different things: a genuine clean week (scanned,
    found nothing) OR 'not scanned yet' (e.g. the very first digest firing before Security Watch has
    run, or a digest-group repo that no security group covers). Only the former is a trustworthy
    all-clear; the latter is a false one that would contradict the first security alert email. This
    flag lets send_digest hide the section until a scan has genuinely happened."""
    for r in (group_repos or []):
        if waveassist.fetch_data(f"dependency_snapshot:{r}", default=None):
            return True
    return False


def build_prompt(project_name, changes_context, business_report_context, brain_context) -> str:
    parts = [
        ("You are a technical advisor reporting to a busy CTO. "
         f"Review the development activity for {project_name}. The Business Report already covered the big "
         "features. Now go repository by repository and list the technical work that matters. "
         "If a section has no significant updates, strictly return an empty list."),
    ]
    if business_report_context:
        parts.append("\n<Business Report Context>\n" + business_report_context)
    if brain_context:
        parts.append("\n<Repo Context>\n" + brain_context)
    if changes_context:
        parts.append("\n*** PRIMARY SOURCE: Code Changes Summarized ***\n" + changes_context)
    parts.append("""
Create a repository-by-repository technical deep dive.

CRITICAL INSTRUCTIONS:
- Go through each repository that had activity and list what happened there.
- Aggressively consolidate: do not list individual commits; group related changes.
- Ignore trivia (typos, formatting, dependency bumps) unless a major version shift.
- MAXIMUM 2-3 technical changes per repository.

1. repository_deep_dive: one RepoUpdate per repository with activity (repo_name, status, technical_changes).
2. poem: exactly 4 lines, each 6-10 words, tech-focused, rhyming, one connected poem.

Plain prose in short sentences. Do NOT use em dashes, and do not use a hyphen as a connector between
clauses. No emojis in the deep-dive text.""")
    return "".join(parts)


def brain_block(profiles_by_repo) -> str:
    parts = []
    for repo, profile in (profiles_by_repo or {}).items():
        arch = ((profile or {}).get("architecture_summary") or "").strip()
        if arch:
            parts.append(f"- {repo}: {arch}")
    return ("Repository context (from GitZoid's profile):\n" + "\n".join(parts)) if parts else ""


# ---------------------------------------------------------------- driver (flat, fall-through)

skip = waveassist.fetch_data("digest_skip_run", run_based=True, default="0") == "1"
groups = [] if skip else (waveassist.fetch_data("digest_resolved_groups", run_based=True, default=[]) or [])

if skip:
    print("GitZoid Digest: digest_skip_run set; generate_technical_report no-op.")

if groups:
    repository_analyses = waveassist.fetch_data("repository_analyses", default=[]) or []
    business_reports = waveassist.fetch_data("digest_business_reports", run_based=True, default={}) or {}
    ledger = waveassist.fetch_data("security_findings", default={}) or {}
    model_name = waveassist.fetch_data("model_name", default=DEFAULT_MODEL) or DEFAULT_MODEL
    now = datetime.now(timezone.utc)

    technical_reports = {}
    for group in groups:
        slug = group.get("slug")
        name = group.get("name") or "your repositories"
        repos = group.get("repos") or []
        analyses = filter_analyses(repository_analyses, repos)
        rollup = security_rollup(ledger, repos, now)
        rollup["scanned"] = group_scanned(repos)   # distinguishes a real clean week from 'not scanned yet'

        if count_changes(analyses) == 0:
            # Quiet code week, but the security roll-up still ships the reassurance. No LLM needed.
            # The "quiet repos" poem only fits a genuinely idle week; if commits landed (maintenance
            # week) it would contradict the commit counter, so drop it then.
            poem = QUIET_POEM if group_commit_count(analyses) == 0 else []
            technical_reports[slug] = {"repository_deep_dive": [], "poem": poem,
                                       "security_rollup": rollup}
            print(f"· {slug}: no code activity; security roll-up only "
                  f"({rollup['counts']['new']} new, {rollup['counts']['resolved']} resolved)")
            continue

        profiles = {a["repository"]: (waveassist.fetch_data(f"profile:{a['repository']}", default={}) or {})
                    for a in analyses if a.get("changes")}
        prompt = build_prompt(name, build_changes_context(analyses),
                              build_business_report_context(business_reports.get(slug) or {}),
                              brain_block(profiles))
        try:
            result = waveassist.call_llm(model=model_name, prompt=prompt, response_model=TechnicalReport,
                                         max_tokens=MAX_TOKENS)
        except Exception as e:
            print(f"⚠️ technical LLM failed for {slug}: {e}")
            result = None

        if result:
            report = result.model_dump(by_alias=True)
            report["security_rollup"] = rollup
            technical_reports[slug] = report
            print(f"✓ {slug}: technical report generated")
        else:
            # LLM raised — NOT a quiet week. No fallback poem; flag so send_digest skips this group.
            report = {"repository_deep_dive": [], "poem": [], "generation_failed": True,
                      "security_rollup": rollup}
            technical_reports[slug] = report
            print(f"⚠️ {slug}: technical report generation FAILED (LLM error); flagged, no fallback poem")

    waveassist.store_data("digest_technical_reports", technical_reports, run_based=True, data_type="json")
    print(f"GitZoid Digest: technical reports for {len(technical_reports)} group(s).")
