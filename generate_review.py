"""
generate_review.py — brain-aware, precision-first PR review.

For each pending PR it builds a review prompt enriched with the repo's brain profile
(profile:{owner/repo}, attached by fetch_pull_requests as `brain_profile`), calls the LLM for
structured findings, then runs a DETERMINISTIC gate + a light security sweep so only
high-signal, anchored findings survive. The gate (not the model) is the single authority for
the verdict. Conventions: flat script, no __main__ guard, init() first, fall-through on empty.
"""
import hashlib
import re
import requests
import waveassist
from datetime import datetime, timezone
from typing import List, Literal, Optional
from pydantic import BaseModel, Field

# Constants
TOKEN_MULTIPLIER = 2.5
MAX_TOKENS = 4096
MAX_INLINE_FINDINGS = 8
DEFAULT_MODEL = "anthropic/claude-sonnet-4.6"
_SEV_RANK = {"high": 0, "medium": 1, "low": 2}
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}

waveassist.init()   # credits gated once upstream in check_credits_and_init

print("Processing AI Review Generation node")


def format_changed_files(files, max_chars=25000):
    """Format file diffs into blocks, capping total length at max_chars."""
    try:
        max_chars = int(max_chars)
    except (TypeError, ValueError):
        max_chars = 25000

    if not isinstance(files, (list, tuple)) or not files:
        return "No files changed."

    blocks, total = [], 0
    for idx, f in enumerate(files, 1):
        try:
            patch = f.get("patch", "")
            status = f.get("status", "modified")
            additions = f.get("additions", 0)
            deletions = f.get("deletions", 0)

            status_badge = f"[{status}]" if status != "modified" else ""
            stats = f"(+{additions}/-{deletions})" if additions or deletions else ""

            if not patch:
                block = f"{idx}. Filename: `{f['filename']}` {status_badge} {stats}\n*No diff available for this file.*"
            else:
                block = f"{idx}. Filename: `{f['filename']}` {status_badge} {stats}\n```\n{patch}\n```"

            length = len(block)
            blocks.append((length, block))
        except:
            pass

    blocks.sort(key=lambda x: x[0])
    included, remaining = [], []

    for length, block in blocks:
        if total + length <= max_chars:
            included.append(block)
            total += length
        else:
            remaining.append((length, block))

    if remaining:
        try:
            budget = (max_chars - total) + int(0.1 * max_chars)
            per_block = budget // len(remaining)
            for _, block in remaining:
                truncated = block.split("```", 1)[1][:per_block]
                included.append(
                    f"...\n```{truncated}\n... (file truncated for tokens optimisation, post your analysis based on available context.)\n```"
                )
        except:
            pass

    return "\n\n".join(included)


# ---------------------------------------------------------------- models

class Finding(BaseModel):
    """One review finding. line/side optional → unanchored findings degrade to summary-only."""
    path: str = Field(default="", description="Repo-relative path, or '' if cross-cutting")
    line: Optional[int] = Field(default=None,
        description="1-based line in the NEW file that is part of this PR's diff")
    side: Optional[Literal["RIGHT", "LEFT"]] = Field(default="RIGHT",
        description="RIGHT for added/context lines (almost always); LEFT only for a removed line")
    severity: Literal["high", "medium", "low"] = Field(
        description="high=likely bug/security/breakage; medium=correctness smell; low=nit")
    confidence: Literal["high", "medium", "low"] = Field(
        description="how sure this is real on this exact line")
    category: Literal["bug", "security"] = Field(
        description="bug=correctness; security=secret/injection/authz")
    body: str = Field(description="One or two PLAIN-ENGLISH sentences: the problem and its real-world impact, NOT code internals (no variable/function narration). Neutral, no praise, no alarm, no emojis.")
    suggested_replacement: Optional[str] = Field(default=None,
        description="ONLY for a mechanical single-line fix: exact replacement for `line`. Omit otherwise.")


class ReviewResult(BaseModel):
    """Full (first-time) PR review. No verdict field — the gate computes the verdict."""
    summary: List[str] = Field(default_factory=list,
        description="1-2 simple sentences a non-author understands: what this PR does and why. No variable/function walkthrough.")
    findings: List[Finding] = Field(default_factory=list)
    potential_optimizations: List[str] = Field(default_factory=list,
        description="Non-blocking improvements stated as a PLAIN problem (e.g. 'the same data is loaded twice, can be cached'), not code mechanics.")
    suggestions: List[str] = Field(default_factory=list, description="Nits, free-form, capped at render time")


class UpdateReviewResult(BaseModel):
    """Re-review after new commits. Reviews the FULL current PR (not just the new diff) so the
    open/fixed ledger stays accurate — an issue is 'fixed' only when it is truly gone from the
    code, not merely absent from the latest commit's diff. Same Finding shape; gate computes verdict."""
    summary: List[str] = Field(default_factory=list,
        description="1-2 simple sentences: what this PR does as it stands now.")
    findings: List[Finding] = Field(default_factory=list,
        description="ALL concerns present in the current code. Re-state a still-present prior finding using the SAME wording as before so it is recognized as the same issue.")
    addressed_issues: List[str] = Field(default_factory=list,
        description="Prior findings that are now genuinely fixed in the current code.")
    potential_optimizations: List[str] = Field(default_factory=list)
    suggestions: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------- v2 brain adapters

_AUTH_HINTS = ("auth", "login", "session", "security", "middleware", "token",
               "jwt", "oauth", "permission", "credential", "password")


def _xml(s):
    return str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def brain_secret_locations(profile):
    """Secret read/store locations from the v2 profile (nested under security)."""
    if not isinstance(profile, dict):
        return []
    return (profile.get("security") or {}).get("secret_locations") or []


def brain_auth_files(profile):
    """Derive auth-sensitive file paths from the v2 key_files (path/role mentions auth-ish terms)."""
    out = set()
    if not isinstance(profile, dict):
        return out
    for kf in (profile.get("key_files") or []):
        path = (kf.get("path") or "")
        role = (kf.get("role") or "").lower()
        if path and (any(h in path.lower() for h in _AUTH_HINTS) or any(h in role for h in _AUTH_HINTS)):
            out.add(path)
    return out


def auth_touched_files(files, brain_profile):
    """Paths among the PR's changed files that match an auth-flagged file in the brain (by full path
    or basename). These get queued for the weekly deep_security_audit."""
    auth = brain_auth_files(brain_profile)
    auth_bases = {a.split("/")[-1] for a in auth}
    out = []
    for f in (files or []):
        fn = f.get("filename", "")
        if not fn:
            continue
        if fn in auth or fn.split("/")[-1] in auth_bases:
            out.append(fn)
    return out


def build_audit_queue_entry(repo_path, pr_number, files, current_sha, brain_profile):
    """Build a tripwire queue entry for a PR that touched auth files, or None. The weekly audit
    consumes these and prioritizes the named files."""
    touched = auth_touched_files(files, brain_profile)
    if not touched:
        return None
    return {"repo": repo_path, "pr": pr_number, "files": touched, "sha": current_sha,
            "queued_at": datetime.now(timezone.utc).isoformat()}


def merge_audit_queue(queue, entry):
    """Upsert a queue entry by (repo, pr) — the latest push for a PR replaces its prior entry."""
    if not entry:
        return queue or []
    key = (entry.get("repo"), entry.get("pr"))
    out = [q for q in (queue or []) if (q.get("repo"), q.get("pr")) != key]
    out.append(entry)
    return out


def _format_brain_profile(profile):
    """Render the v2 repo profile into an XML block the model can use to reduce false positives."""
    if not isinstance(profile, dict) or not profile:
        return ""
    arch = (profile.get("architecture_summary") or "").strip()
    conv = [c for c in (profile.get("conventions") or []) if c]
    focus = [r for r in (profile.get("review_focus") or []) if r]
    stk = profile.get("stack") or {}
    tech = (stk.get("languages") or []) + (stk.get("frameworks") or [])
    sec = profile.get("security") or {}
    routes = sec.get("routes") or []
    secrets = sec.get("secret_locations") or []
    if not (arch or conv or focus or tech or routes or secrets):
        return ""

    def items(xs):
        return "\n".join(f"      <item>{_xml(x)}</item>" for x in xs)

    route_items = "\n".join(
        f"      <route public=\"{bool(r.get('unauthenticated'))}\">{_xml(r.get('route'))}</route>"
        for r in routes)
    return f"""
  <repo_profile note="Known facts about THIS repo (GitZoid's brain). Use to reduce false positives and judge convention-fit. Do NOT invent issues just because something is listed.">
    <architecture>{_xml(arch)}</architecture>
    <stack>{_xml(', '.join(tech))}</stack>
    <conventions>
{items(conv)}
    </conventions>
    <review_focus>
{items(focus)}
    </review_focus>
    <security_surface>
{route_items}
    </security_surface>
    <secret_locations>
{items(secrets)}
    </secret_locations>
  </repo_profile>"""


def _format_context(additional_context):
    if not additional_context or not str(additional_context).strip():
        return ""
    return f"""
  <additional_context note="Reference only. Use only the parts that help.">
{str(additional_context).strip()}
  </additional_context>"""


_REVIEW_RULES = """
  <instructions>
    You are a precise, senior code reviewer. Review ONLY the provided diff.
    Output findings as structured objects. Each finding MUST have severity, confidence, category.
    AUDIENCE & LANGUAGE (read this first — it matters most):
    - Your reader is a busy tech lead reviewing a teammate's PR. They may NOT know this codebase's variables, functions, or internal layout. They need the PROBLEM and its real-world IMPACT in plain English, nothing more.
    - Write like you are telling a colleague in one sentence. Do NOT narrate code mechanics: no variable names, no "X is not in scope", no function-call chains, no "it re-fetches via Y". The engineer/AI will handle the fix; the reader only needs to grasp the problem and why it matters.
    - Name a specific function/file ONLY if essential to locate the issue, never as the explanation itself. (The line number already locates inline findings.)
    - BAD (too technical): "In submit_form_step_api, registration_array is not in scope at the call site, so check_join_booking_capacity re-fetches it with an extra DB round-trip."
    - GOOD (plain, problem-first): "The same registration data is loaded from the database twice for one request; the duplicate query can be avoided."
    - summary: 1-2 simple sentences on what this PR does and why, in words a non-author understands. No variable/function walkthrough.
    PRECISION RULES (most important):
    - Only report something you can justify directly from the shown diff lines.
    - If unsure, lower confidence — do not omit it.
    - Do NOT speculate about code you cannot see. Truncated files may be present to optimise for tokens, thats ok. review what is visible.
    - Do NOT restate what the code does. Findings are actionable concerns or concrete improvements.
    - Neutral framing: describe issue + impact. No praise, no alarm, no emojis.
    - Avoid ; and - and emdash as much as possible. but not forced. 
    SEVERITY: high=likely runtime bug/data loss/breakage/real security hole; medium=should fix (edge case, weak error handling, convention violation); low=minor/style.
    CATEGORY (findings[] only): bug | security. Put perf/readability in potential_optimizations[] and nits/style in suggestions[], NOT as findings. Use 'security' only for the sweep items below.
    LIMIT: potential_optimizations[] and suggestions[] are low-priority and mostly unused — emit at most 3 of EACH, only the most useful, and do not pad. Rate findings honestly by the SEVERITY scale; never inflate a minor issue to high just to surface it (a real medium/low belongs in medium/low, or in these two lists).
    SUGGESTION: when a fix is small and unambiguous, include committable code in suggested_replacement; else omit.
    SECURITY SWEEP (light, high-confidence only):
    - Newly ADDED line that looks like a live secret (high-entropy token/key). Skip placeholders/test fixtures/examples.
    - Obvious injection in ADDED lines (string-built SQL/shell/HTML from untrusted input).
    Suppress placeholders, examples, fixtures. Never report a security item without a concrete added line as basis.
  </instructions>"""


def get_full_review_prompt(review_pr, max_input_tokens=20000, additional_context=None):
    """Brain-aware prompt for a first-time full PR review."""
    formatted_files = format_changed_files(review_pr.get("files"), int(max_input_tokens * TOKEN_MULTIPLIER))
    return f"""<pr_review type="full">
{_REVIEW_RULES}
{_format_brain_profile(review_pr.get("brain_profile"))}
{_format_context(additional_context)}
  <pr_metadata>
    <number>{review_pr.get("pr_number")}</number>
    <title>{review_pr.get("title")}</title>
    <description>{review_pr.get("body")}</description>
  </pr_metadata>
  <changed_files note="Some files may be truncated; review what is visible.">
{formatted_files}
  </changed_files>
  <task>Produce: summary (1-2 sentences), findings[], potential_optimizations[], suggestions[]. Apply the security sweep. Be precise.</task>
</pr_review>
"""


def get_update_review_prompt(review_pr, previous_review=None, max_input_tokens=20000, additional_context=None):
    """Re-review prompt after new commits. Reviews the FULL current PR (all changed files), with the
    prior review in context. Reviewing the whole PR — not just the new diff — is what makes the
    open/fixed ledger correct: a prior issue is only 'fixed' if it is genuinely gone now."""
    formatted_files = format_changed_files(review_pr.get("files"), int(max_input_tokens * TOKEN_MULTIPLIER))
    prev_sha = (review_pr.get("previous_sha") or "")[:7]
    cur_sha = (review_pr.get("current_sha") or "")[:7]
    previous_block = ""
    if previous_review:
        previous_block = f"""
  <previous_review note="GitZoid's prior review of this PR. New commits have since been pushed.">
{previous_review}
  </previous_review>"""
    return f"""<pr_review type="update" previous_sha="{prev_sha}" current_sha="{cur_sha}">
{_REVIEW_RULES}
{_format_brain_profile(review_pr.get("brain_profile"))}
{_format_context(additional_context)}{previous_block}
  <pr_metadata>
    <number>{review_pr.get("pr_number")}</number>
    <title>{review_pr.get("title")}</title>
    <description>{review_pr.get("body")}</description>
  </pr_metadata>
  <changed_files note="The FULL current diff of this PR (state as of {cur_sha}). Some files may be truncated.">
{formatted_files}
  </changed_files>
  <task>
    This PR was reviewed before; new commits have landed. Review the FULL current code shown above and report its CURRENT state:
    - findings[]: EVERY concern present in the code as it stands now. For any prior-review issue that is STILL present, re-state it with the SAME wording as before so it is recognized as the same issue (do not reword unchanged issues). Include genuinely new concerns too.
    - addressed_issues[]: prior-review issues that are now actually fixed in the current code.
    - summary[]: 1-2 plain sentences on what the PR does now.
    - potential_optimizations[], suggestions[]. Apply the security sweep.
    Decide 'fixed vs still-present' from the current code, never from which file the latest commit happened to touch.
  </task>
</pr_review>
"""


# ---------------------------------------------------------------- diff parsing

def build_diff_lines(files):
    """Set of (path, side, line) that are commentable: added+context -> RIGHT, removed -> LEFT."""
    diff_lines = set()
    for f in (files or []):
        path = f.get("filename", "")
        new_ln = old_ln = 0
        for raw in (f.get("patch", "") or "").splitlines():
            if raw.startswith("@@"):
                m = re.search(r"-(\d+)(?:,\d+)?\s+\+(\d+)", raw)
                if m:
                    old_ln, new_ln = int(m.group(1)) - 1, int(m.group(2)) - 1
                continue
            if raw.startswith("+") and not raw.startswith("+++"):
                new_ln += 1
                diff_lines.add((path, "RIGHT", new_ln))
            elif raw.startswith("-") and not raw.startswith("---"):
                old_ln += 1
                diff_lines.add((path, "LEFT", old_ln))
            else:
                new_ln += 1
                old_ln += 1
                diff_lines.add((path, "RIGHT", new_ln))
    return diff_lines


def _added_lines(patch):
    """Yield (lineno_in_new_file, text) for '+' lines only (used by the security sweep)."""
    new_ln = 0
    for raw in (patch or "").splitlines():
        if raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            new_ln = (int(m.group(1)) - 1) if m else new_ln
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            new_ln += 1
            yield new_ln, raw[1:]
        elif not raw.startswith("-"):
            new_ln += 1


# ---------------------------------------------------------------- gate

def _sanitize_findings(findings):
    """soft_parse may null-fill required fields; drop/repair before gating."""
    out = []
    for f in (findings or []):
        f = dict(f)
        if f.get("severity") not in _SEV_RANK:
            f["severity"] = "medium"
        if f.get("confidence") not in _CONF_RANK:
            f["confidence"] = "low"
        if f.get("category") not in ("bug", "security"):
            f["category"] = "bug"
        if f.get("side") not in ("RIGHT", "LEFT"):
            f["side"] = "RIGHT"
        if not isinstance(f.get("path"), str):
            f["path"] = ""
        if not isinstance(f.get("line"), int):
            f["line"] = None
        if not isinstance(f.get("body"), str):
            f["body"] = ""
        out.append(f)
    return out


def finding_sig(f):
    """Position-independent identity. Deliberately EXCLUDES line/side so a finding keeps the
    same signature across commits even when surrounding edits shift its line number — otherwise
    a still-present issue would look 'fixed' (old sig gone) AND 'new' (new sig) on every push.
    Identity = category + file + the normalized problem text."""
    raw = f"{f.get('category', '')}|{f.get('path', '')}|" \
          f"{' '.join((f.get('body') or '').lower().split())[:160]}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def apply_gate(findings, diff_lines, seen_sigs=None, severity_threshold="high"):
    """Single source of truth for the verdict. Returns (kept_findings, verdict, new_sigs)."""
    seen_sigs = seen_sigs or set()
    findings = _sanitize_findings(findings)
    thr = _SEV_RANK.get(severity_threshold, 0)
    kept, new_sigs, blocking = [], [], False
    for f in findings:
        sig = finding_sig(f)
        if sig in seen_sigs or sig in new_sigs:        # de-dup against ledger + within batch
            continue
        cat, sev, conf = f["category"], f["severity"], f["confidence"]
        # precision gate for bug/security: high sev OR (medium sev + high conf)
        if cat in ("bug", "security"):
            if not (sev == "high" or (sev == "medium" and conf == "high")):
                continue
            # per-repo severity threshold floor
            if _SEV_RANK[sev] > thr:
                continue
        # anchored findings must be in the diff; unanchored (no line) allowed → summary-only
        if f.get("line") is not None and (f["path"], f["side"], f["line"]) not in diff_lines:
            continue
        kept.append(f)
        new_sigs.append(sig)
        if cat in ("bug", "security") and sev == "high":   # any high-severity bug/security blocks
            blocking = True
    kept.sort(key=lambda f: (f["category"] != "security", _SEV_RANK[f["severity"]],
                             f.get("path") or "", f.get("line") or 0))
    kept = kept[:MAX_INLINE_FINDINGS]
    verdict = "needs_changes" if blocking else ("minor_comments" if kept else "looks_good")
    return kept, verdict, new_sigs


# ---------------------------------------------------------------- light security sweep

_SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Generic assigned secret", re.compile(
        r"""(?i)(?:secret|passwd|password|api[_-]?key|token|access[_-]?key)\s*[:=]\s*['"][^'"]{12,}['"]""")),
]
_PLACEHOLDER_HINTS = re.compile(r"(?i)(your[_-]?|example|placeholder|changeme|xxxx|dummy|sample|<.*?>|redacted|\.\.\.)")
_INJECTION_PATTERNS = [
    ("SQL string concatenation", re.compile(r"""(?i)(?:execute|executemany|query|cursor\.execute)\s*\(\s*(?:f?['"].*?\+|.*?%\s*\()""")),
    ("Shell with shell=True", re.compile(r"""(?i)subprocess\.[a-z_]+\([^)]*shell\s*=\s*True""")),
    ("os.system with interpolation", re.compile(r"""(?i)os\.system\(\s*f?['"].*?\{""")),
]


def _is_known_placeholder_location(filename, secret_locations):
    fn = (filename or "").lower()
    if any(loc and loc.lower() in fn for loc in (secret_locations or [])):
        return True
    return bool(re.search(r"(?i)(test|fixture|example|sample|\.lock$|mock)", fn))


def security_sweep(files, brain_profile):
    """Deterministic high-confidence security Findings (secrets + injection + auth-file tripwire)."""
    secret_locations = brain_secret_locations(brain_profile)
    auth_files = brain_auth_files(brain_profile)
    findings, touched_auth = [], set()
    for f in (files or []):
        fname = f.get("filename", "")
        patch = f.get("patch", "")
        base = fname.split("/")[-1]
        if (fname in auth_files or base in {a.split("/")[-1] for a in auth_files}) and fname not in touched_auth:
            touched_auth.add(fname)
            findings.append({"path": fname, "line": None, "side": "RIGHT",
                "severity": "medium", "confidence": "high", "category": "security",
                "title": "Auth-sensitive file changed — queued for weekly audit",
                "body": f"`{fname}` is flagged auth-related in the repo profile; deep authz review is deferred to the weekly audit.",
                "suggested_replacement": None})
        if _is_known_placeholder_location(fname, secret_locations):
            continue
        for ln, text in _added_lines(patch):
            for label, pat in _SECRET_PATTERNS:
                if pat.search(text) and not _PLACEHOLDER_HINTS.search(text):
                    findings.append({"path": fname, "line": ln, "side": "RIGHT",
                        "severity": "high", "confidence": "high", "category": "security",
                        "title": f"Possible live {label} committed",
                        "body": f"An added line in `{fname}` matches a {label} pattern and is not a placeholder. Rotate it and move to a secret store if real.",
                        "suggested_replacement": None})
                    break
            for label, pat in _INJECTION_PATTERNS:
                if pat.search(text):
                    findings.append({"path": fname, "line": ln, "side": "RIGHT",
                        "severity": "high", "confidence": "medium", "category": "security",
                        "title": f"Possible {label}",
                        "body": f"Added line in `{fname}` builds a command/query from interpolated input. Use parameterized queries / avoid shell=True.",
                        "suggested_replacement": None})
                    break
    return findings


# ---------------------------------------------------------------- verify pass (refute before posting)
#
# The find pass + gate are deliberately a bit trigger-happy (they only see the diff hunk). Before a
# finding is posted, an adversarial second pass re-checks it against the FULL surrounding code so
# out-of-hunk context (a guard/early-return above the change) can refute false positives — exactly
# the class that a diff-only reviewer can't see. It also corrects inflated severity, then RE-GATES
# the survivors so the verdict reflects reality. Only the gate-kept (postable) findings are verified.
#
# Fail-open: if the token/file/LLM is unavailable, the finding is kept as-is. Verification only ever
# removes a finding it can ACTIVELY refute — a transient failure must never silently drop a real bug.

VERIFY_TIMEOUT = 10
VERIFY_WHOLE_FILE_MAX_LINES = 400   # pass the whole file at/under this; otherwise a window
VERIFY_WINDOW_RADIUS = 80           # lines above/below the finding when the file is large


class VerifyVerdict(BaseModel):
    """Adversarial re-check of ONE gate-kept finding against the full surrounding code."""
    is_real: bool = Field(
        description="False ONLY if the full code shows this cannot actually happen on that line "
                    "(e.g. an earlier guard/early-return makes it unreachable with the problematic "
                    "value, or the finding misreads the code). If it can happen, or you cannot rule "
                    "it out, True. Do not invent hypothetical preconditions.")
    true_severity: Literal["high", "medium", "low"] = Field(
        description="Severity judged WITH the full context. high=real runtime bug/data loss/"
                    "breakage/security hole; medium=should-fix correctness smell; low=minor/non-issue.")
    reason: str = Field(
        description="If real: the concrete trigger — the input and path that reaches the line. "
                    "If not real: exactly why it cannot occur.")


def _gh_raw_headers(token):
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.raw+json"}


def fetch_file_text(repo_path, path, ref, token):
    """Full text of `path` at commit `ref` from GitHub, or '' on any failure (caller fails open)."""
    if not (repo_path and path and ref and token):
        return ""
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{repo_path}/contents/{path}",
            headers=_gh_raw_headers(token), params={"ref": ref}, timeout=VERIFY_TIMEOUT)
        return resp.text if resp.status_code == 200 else ""
    except Exception:
        return ""


def context_window(file_text, line):
    """Whole file when short enough, else a generous window around `line` (1-based) so the verifier
    sees the enclosing function and any guards above/below the changed hunk."""
    lines = file_text.splitlines()
    if len(lines) <= VERIFY_WHOLE_FILE_MAX_LINES:
        return file_text
    if not isinstance(line, int) or line < 1:
        return "\n".join(lines[:VERIFY_WHOLE_FILE_MAX_LINES])
    lo = max(0, line - 1 - VERIFY_WINDOW_RADIUS)
    hi = min(len(lines), line - 1 + VERIFY_WINDOW_RADIUS)
    return "\n".join(lines[lo:hi])


def get_verify_prompt(finding, context_code):
    line = finding.get("line")
    loc = f"{finding.get('path') or '(cross-cutting)'}:{line}" if line else (finding.get("path") or "(cross-cutting)")
    return f"""You are adversarially RE-CHECKING one code-review finding before it is posted. Default
to skeptical: it survives only if it genuinely holds against the FULL code below.

FINDING (claimed {finding.get('severity')} {finding.get('category')} at {loc}):
{finding.get('body')}

SURROUNDING CODE (the full file when available, otherwise the diff — trace it, do not assume):
```
{context_code}
```

- is_real: False ONLY if the code shows this cannot actually happen on that line (a guard/early-return
  makes it unreachable, or the finding misreads the code). If it can happen, or you can't rule it out, True.
- true_severity: judge impact WITH the full context (a guarded or edge case is medium/low, not high).
- reason: if real, name the concrete trigger (input + path to the line); if not, say exactly why it can't occur.
Return only the structured verdict."""


def verify_posted_findings(findings, pr, token, model_name, diff_lines, severity_threshold="high"):
    """Refute each gate-kept finding against its full function, drop clear false positives, correct
    inflated severity, then re-gate so the verdict reflects reality. Returns (kept, verdict, dropped).
    Fails open per-finding (see module note above)."""
    if not findings:
        return findings, "looks_good", []
    repo_path, head_sha = pr.get("id", ""), pr.get("current_sha", "")
    patches = {fl.get("filename"): (fl.get("patch") or "") for fl in (pr.get("files") or [])}
    cache, survivors, dropped = {}, [], []
    for f in findings:
        path = f.get("path") or ""
        if not path:
            survivors.append(f); continue                       # unanchored → fail open
        if token and path not in cache:
            cache[path] = fetch_file_text(repo_path, path, head_sha, token)
        file_text = cache.get(path) or ""
        # Full file is best (it sees guards OUTSIDE the diff hunk); fall back to the diff when the
        # file can't be fetched — weaker, but better than skipping the check entirely.
        ctx = context_window(file_text, f.get("line")) if file_text else patches.get(path, "")
        if not ctx:
            survivors.append(f); continue                       # no context at all → fail open
        verdict = waveassist.call_llm(
            model=model_name, prompt=get_verify_prompt(f, ctx),
            response_model=VerifyVerdict, should_retry=True, max_tokens=MAX_TOKENS)
        if verdict is None:
            survivors.append(f); continue                       # LLM unavailable → fail open
        v = verdict.model_dump()
        if not v.get("is_real"):
            dropped.append({**f, "_drop_reason": v.get("reason", "")}); continue
        # Verified real → trust the re-judged severity, and treat confidence as high.
        survivors.append({**f, "severity": v.get("true_severity") or f.get("severity"), "confidence": "high"})
    kept, verdict, _ = apply_gate(survivors, diff_lines, seen_sigs=set(), severity_threshold=severity_threshold)
    return kept, verdict, dropped


# ---------------------------------------------------------------- driver (flat, fall-through)

prs = waveassist.fetch_data("pull_requests", default=[]) or []
if prs:
    repositories = waveassist.fetch_data("github_selected_resources", default=[]) or []
    repo_config = {r["id"]: r.get("properties", {}) for r in repositories if isinstance(r, dict) and r.get("id")}
    global_model = waveassist.fetch_data("model_name", default=DEFAULT_MODEL) or DEFAULT_MODEL
    global_context = waveassist.fetch_data("additional_context", default="") or ""
    audit_queue_entries = []   # PRs touching auth files → queued for the weekly deep_security_audit

    for pr in prs:
        try:
            if pr.get("comment_generated", False):
                continue

            repo_path = pr.get("id", "")
            props = repo_config.get(repo_path, {})
            model_name = props.get("model_name") or global_model
            additional_context = props.get("additional_context") or global_context
            severity_threshold = props.get("severity_threshold") or "high"
            review_type = pr.get("review_type", "full")

            if review_type == "incremental":
                # Re-review the FULL current PR (with the prior review in context), not just the new diff,
                # so the open/fixed ledger reflects the real current state of the code.
                prompt = get_update_review_prompt(
                    pr, previous_review=pr.get("previous_review_text"), additional_context=additional_context)
                result = waveassist.call_llm(model=model_name, prompt=prompt,
                                             response_model=UpdateReviewResult,
                                             should_retry=True, max_tokens=MAX_TOKENS)
            else:
                prompt = get_full_review_prompt(pr, additional_context=additional_context)
                result = waveassist.call_llm(model=model_name, prompt=prompt,
                                             response_model=ReviewResult,
                                             should_retry=True, max_tokens=MAX_TOKENS)

            if not result:
                raise Exception("Review not generated.")

            review_dict = result.model_dump()
            # Low-priority lists are mostly unused downstream — hard-cap at 3 each (the prompt asks
            # for this too; this is the guarantee).
            review_dict["potential_optimizations"] = (review_dict.get("potential_optimizations") or [])[:3]
            review_dict["suggestions"] = (review_dict.get("suggestions") or [])[:3]
            diff_lines = build_diff_lines(pr.get("files"))
            raw = (review_dict.get("findings") or []) + security_sweep(pr.get("files"), pr.get("brain_profile"))
            kept, verdict, _ = apply_gate(raw, diff_lines, seen_sigs=set(),
                                          severity_threshold=severity_threshold)
            # Adversarial verify pass: refute each posted finding against its full function before it ships.
            access_token = waveassist.fetch_data("github_access_token", default="") or ""
            kept, verdict, dropped = verify_posted_findings(
                kept, pr, access_token, model_name, diff_lines, severity_threshold)
            if dropped:
                print(f"   verify: dropped {len(dropped)} finding(s) that didn't hold against full context.")
            review_dict["findings"] = kept
            review_dict["verdict"] = verdict

            pr.update(review_dict=review_dict, comment_generated=True,
                      comment_posted=False, review_type=review_type)

            # Tripwire: if this PR touched an auth-flagged file, queue it for the weekly deep audit
            # (closes the "deferred to the weekly audit" promise the security sweep already prints).
            entry = build_audit_queue_entry(repo_path, pr.get("pr_number"), pr.get("files"),
                                            pr.get("current_sha", ""), pr.get("brain_profile"))
            if entry:
                audit_queue_entries.append(entry)
            print(f"✅ PR #{pr.get('pr_number')} {review_type} review generated "
                  f"(model={model_name}, verdict={verdict}, findings={len(kept)}).")
        except Exception as e:
            print(f"❌ PR #{pr.get('pr_number')} failed: {e}")
            pr.update(review_dict={}, comment_generated=False, comment_posted=False)

    waveassist.store_data("pull_requests", prs, data_type="json")

    # Persist the audit tripwire queue for the weekly deep_security_audit (additive; merges by PR).
    if audit_queue_entries:
        queue = waveassist.fetch_data("security_audit_queue", default=[]) or []
        for entry in audit_queue_entries:
            queue = merge_audit_queue(queue, entry)
        waveassist.store_data("security_audit_queue", queue, data_type="json")
        print(f"Queued {len(audit_queue_entries)} auth-touched PR(s) for the weekly deep audit.")
    print("All PR reviews processed and stored.")
