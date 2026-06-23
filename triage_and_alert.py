"""
triage_and_alert.py — the single gatekeeper for everything Security (chain node 4).

Both scan_dependencies (daily) and deep_security_audit (weekly) append candidate findings to the
run-based `security_candidates` key. This node is the ONE authority over what a user actually sees:
it dedupes every candidate against the persistent `security_findings` ledger, re-alerts only on
escalation or a fix becoming available, detects newly-resolved issues (saved for the digest, never
emailed), ranks, caps, and — only if something genuinely new and serious exists — sends one
consolidated email. Silent otherwise (silence IS the all-clear). No LLM: the plain-English text was
written upstream where each finding was found; this node only gates and delivers.

It also releases the `security_run_lock` taken by security_check_and_init (token-matched), as the
last node in the chain.

Conventions: flat script, no __main__ guard, init() first, no sibling imports (lock_is_active /
finding_sig are duplicated by design), fall-through on empty.
"""
import re
import json
import html
import hashlib
from datetime import datetime, timezone
import waveassist

waveassist.init()   # credits gated once upstream in security_check_and_init

MAX_CODE_ALERTS = 5     # cap on the code/access section only; dependencies are listed in full (issue #1)
MAX_RESOLVED_KEPT = 60
LEDGER_KEY = "security_findings"
RUN_LOCK_KEY = "security_run_lock"
LOCK_TTL_SECONDS = 2700
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_CODE_CATEGORIES = ("authz", "secret", "backdoor")


def lock_is_active(lock, now=None) -> bool:
    """Duplicated from security_check_and_init (nodes never import siblings)."""
    if not isinstance(lock, dict) or not lock.get("at"):
        return False
    now = now or datetime.now(timezone.utc)
    try:
        return (now - datetime.fromisoformat(lock["at"])).total_seconds() < LOCK_TTL_SECONDS
    except Exception:
        return False


def _norm(s):
    return " ".join((s or "").lower().split())[:160]


def finding_sig(f) -> str:
    """Position-independent identity shared by every security source, kept STABLE across re-runs.
    Dependency findings key on package + vuln id. Code findings (authz/secret/backdoor) carry an
    explicit `dedup_key` built from their location (route paths / file) rather than the model's prose,
    so the same bug keeps one identity even when the model rewords it week to week. Falls back to
    location + normalized title only when no stable key is available."""
    cat = f.get("category", "")
    repo = f.get("repo", "")
    explicit = f.get("dedup_key")
    if explicit:
        raw = f"{cat}|{repo}|{explicit}"
    else:
        key = f.get("name") or f.get("path") or f.get("entry_point") or ""
        ident = f.get("vuln_id") or _norm(f.get("title") or f.get("summary") or "")
        raw = f"{cat}|{repo}|{key}|{ident}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def should_escalate(prior: dict, new: dict) -> bool:
    """Re-alert an already-seen finding only if it got genuinely worse than the worst we ALREADY
    alerted. Comparing against the high-water mark `max_alerted_severity` (not the last-seen
    severity) means a feed flapping high<->critical re-alerts at most once; once we have alerted that
    a fix exists (`fix_alerted`), a later fix-field flicker never re-alerts. Legacy entries without
    these keys fall back to the old fields, so they self-heal."""
    hwm = prior.get("max_alerted_severity", prior.get("severity"))
    if _SEV_RANK.get(new.get("severity"), 4) < _SEV_RANK.get(hwm, 4):   # lower rank = more severe
        return True
    already_alerted_fix = prior.get("fix_alerted", bool(prior.get("fixed")))
    if not already_alerted_fix and new.get("fixed"):
        return True
    return False


def _entry_from(f, sig, now_iso):
    return {"sig": sig, "category": f.get("category"), "repo": f.get("repo"),
            "name": f.get("name"), "version": f.get("version"),
            "path": f.get("path"), "entry_point": f.get("entry_point"),
            "title": f.get("title"), "vuln_id": f.get("vuln_id"),
            "aliases": f.get("aliases") or [], "dedup_key": f.get("dedup_key"),
            "named_victim": f.get("named_victim"),
            "severity": f.get("severity"), "fixed": f.get("fixed"),
            "actively_exploited": f.get("actively_exploited", False),
            "impact": f.get("impact") or f.get("summary") or "",
            "fix": f.get("fix") or f.get("fixed") or "",
            "max_alerted_severity": f.get("severity"),       # high-water mark for escalation
            "fix_alerted": bool(f.get("fixed")),             # have we already alerted a fix?
            "status": "open", "alerted": True,
            "first_seen": now_iso, "last_seen": now_iso}


def reconcile_ledger(prior_ledger, candidates, scanned_ok_deps=None, scanned_ok_code=None, now=None):
    """Returns (new_ledger, to_alert, resolved). Alert new or reappeared findings and escalations;
    carry unchanged ones silently; mark a currently-open finding resolved ONLY when its OWN class was
    actually re-checked this run — a dependency finding resolves only when its repo is in
    `scanned_ok_deps` (the daily dep scan ran clean), a code finding (authz/secret/backdoor) only when
    its repo is in `scanned_ok_code` (the weekly deep audit ran). This is category-scoped on purpose:
    a daily dependency scan must NOT silently resolve an un-re-examined auth hole (which would then
    re-alert at the next weekly audit — the very churn issue #1 is about). Absence with no matching
    scan carries the finding forward."""
    now_iso = (now or datetime.now(timezone.utc)).isoformat()
    new_ledger = {k: dict(v) for k, v in (prior_ledger or {}).items()}
    ok_deps = set(scanned_ok_deps or [])
    ok_code = set(scanned_ok_code or [])
    current_sigs, to_alert = set(), []

    for f in (candidates or []):
        sig = finding_sig(f)
        current_sigs.add(sig)
        prior = new_ledger.get(sig)
        if prior is None or prior.get("status") == "resolved":
            entry = _entry_from(f, sig, now_iso)
            if prior:
                entry["first_seen"] = prior.get("first_seen", now_iso)
            new_ledger[sig] = entry
            to_alert.append(entry)
        elif should_escalate(prior, f):
            new_sev = f.get("severity")
            prior.update({"severity": new_sev, "fixed": f.get("fixed"),
                          "actively_exploited": f.get("actively_exploited", prior.get("actively_exploited")),
                          "impact": f.get("impact") or prior.get("impact"),
                          "status": "open", "alerted": True, "last_seen": now_iso})
            # raise the high-water mark and record that a fix was alerted, so a later flap is quiet
            hwm = prior.get("max_alerted_severity", new_sev)
            if _SEV_RANK.get(new_sev, 4) < _SEV_RANK.get(hwm, 4):
                prior["max_alerted_severity"] = new_sev
            if f.get("fixed"):
                prior["fix_alerted"] = True
            to_alert.append(prior)
        else:
            prior["last_seen"] = now_iso
            prior["status"] = "open"

    resolved = []
    for sig, entry in new_ledger.items():
        if entry.get("status") != "open" or sig in current_sigs:
            continue
        repo = entry.get("repo")
        is_code = entry.get("category") in _CODE_CATEGORIES
        rescanned = (repo in ok_code) if is_code else (repo in ok_deps)
        if rescanned:                      # only resolve when this finding's OWN class was re-checked
            entry["status"] = "resolved"
            entry["resolved_at"] = now_iso
            resolved.append(entry)

    # Prune oldest resolved entries beyond the cap (keep the ledger from growing forever).
    resolved_entries = [(s, e) for s, e in new_ledger.items() if e.get("status") == "resolved"]
    if len(resolved_entries) > MAX_RESOLVED_KEPT:
        resolved_entries.sort(key=lambda se: se[1].get("resolved_at", ""))
        for s, _ in resolved_entries[:-MAX_RESOLVED_KEPT]:
            new_ledger.pop(s, None)

    return new_ledger, to_alert, resolved


def rank_findings(findings):
    """Actively-exploited first, then exploitable code findings, then by severity."""
    def key(f):
        kev = 0 if f.get("actively_exploited") else 1
        sev = _SEV_RANK.get(f.get("severity"), 4)
        code = 0 if f.get("category") in _CODE_CATEGORIES else 1
        return (kev, sev, code)
    return sorted(findings, key=key)


# ---------------------------------------------------------------- email rendering (deterministic)
# A security alert reads clean and serious: no emoji, no em dashes, plain prose. Severity is plain
# text; a coloured left border carries the visual weight.

_SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
              "low": "Low", "unknown": "Unknown"}


def _meta_line(parts):
    """Join header bits with a clean separator (no middot, no em dash)."""
    return " &nbsp;|&nbsp; ".join(p for p in parts if p)


def _finding_block(f) -> str:
    repo = html.escape(str(f.get("repo") or ""))
    sev = _SEV_LABEL.get(f.get("severity"), "")
    kev = "<b>Actively exploited in the wild</b>" if f.get("actively_exploited") else ""
    impact = html.escape(str(f.get("impact") or ""))
    if f.get("category") == "dependency":
        pkg = html.escape(f"{f.get('name') or ''} {f.get('version') or ''}".strip())
        fix = f.get("fix") or f.get("fixed")
        fix_line = (f"<div style='color:#1b5e20;margin-top:4px'>Fix: upgrade {html.escape(pkg.split(' ')[0])} "
                    f"to {html.escape(str(fix))}.</div>") if fix else \
                   "<div style='color:#8a6d3b;margin-top:4px'>No fixed version is published yet.</div>"
        ref = f.get("vuln_id") or ", ".join(f.get("aliases") or [])
        ref_line = f"<div style='color:#888;font-size:11px;margin-top:4px'>Reference: {html.escape(str(ref))}</div>" if ref else ""
        header = _meta_line([f"<b>{repo}</b>", html.escape(f"Severity: {sev}") if sev else "", kev])
        return (f"<div style='margin:12px 0;padding:11px 13px;border-left:4px solid #b91c1c;background:#fbf6f6'>"
                f"<div>{header}</div>"
                f"<div style='font-weight:600;margin-top:3px'>{pkg}</div>"
                f"<div style='margin-top:4px'>{impact}</div>{fix_line}{ref_line}</div>")
    # code finding (authz / secret / backdoor)
    title = html.escape(str(f.get("title") or f.get("category")))
    victim = html.escape(str(f.get("named_victim") or ""))
    fix = html.escape(str(f.get("fix") or ""))
    where = html.escape(str(f.get("path") or f.get("entry_point") or ""))
    victim_line = f"<div style='margin-top:4px'>Who is affected: {victim}</div>" if victim else ""
    fix_line = f"<div style='color:#1b5e20;margin-top:4px'>Fix: {fix}</div>" if fix else ""
    where_line = f"<div style='color:#888;font-size:11px;margin-top:4px'>Location: {where}</div>" if where else ""
    header = _meta_line([f"<b>{repo}</b>", html.escape(f"Severity: {sev}") if sev else "", kev])
    return (f"<div style='margin:12px 0;padding:11px 13px;border-left:4px solid #b91c1c;background:#fbf6f6'>"
            f"<div>{header}</div>"
            f"<div style='font-weight:600;margin-top:3px'>{title}</div>"
            f"<div style='margin-top:4px'>{impact}</div>{victim_line}{fix_line}{where_line}</div>")


def split_findings(findings):
    """Partition findings into (code, deps). Code = authz/secret/backdoor (the exploitable-code
    issues); deps = vulnerable dependencies. They render in separate labelled sections so a real
    auth hole is never visually buried among routine dependency CVEs (issue #4)."""
    code = [f for f in findings if f.get("category") in _CODE_CATEGORIES]
    deps = [f for f in findings if f.get("category") not in _CODE_CATEGORIES]
    return code, deps


def cap_code_findings(code):
    """Cap the code/access section at MAX_CODE_ALERTS, but NEVER drop an actively-exploited (KEV)
    finding — those always make the cut. Dependencies are not passed here: they are listed in full."""
    kept = [f for f in code if f.get("actively_exploited")]
    for f in code:
        if not f.get("actively_exploited") and len(kept) < MAX_CODE_ALERTS:
            kept.append(f)
    return rank_findings(kept)


def _section(title, findings):
    if not findings:
        return ""
    blocks = "".join(_finding_block(f) for f in findings)
    return f"<h3 style='margin:18px 0 2px;font-size:14px;color:#374151'>{html.escape(title)}</h3>" + blocks


def _max_version(versions):
    """Highest version among a package's fix targets (numeric-tuple compare). A package with many
    advisories then shows ONE upgrade target ('upgrade to the highest fixed version') instead of a
    dozen conflicting ones."""
    def key(v):
        return [int(p) for p in re.findall(r"\d+", str(v or ""))]
    vs = [v for v in versions if v]
    return max(vs, key=key) if vs else None


def _dep_group_block(group):
    """One block for ALL advisories affecting the same (repo, package, version). Shows the worst
    severity, a count, the single recommended upgrade, the worst-case impact, and every reference —
    so 13 Django CVEs read as one 'Django 4.2 — 13 issues, upgrade to X' entry, not 13 conflicting ones.
    Rendered in a calm slate accent (not the red of code/access holes) so routine package upgrades
    never carry the same visual urgency as an exploitable code finding (issue #4)."""
    by_sev = sorted(group, key=lambda g: _SEV_RANK.get(g.get("severity"), 4))
    worst = by_sev[0]
    repo = html.escape(str(worst.get("repo") or ""))
    sev = _SEV_LABEL.get(worst.get("severity"), "")
    kev = "<b>Actively exploited in the wild</b>" if any(g.get("actively_exploited") for g in group) else ""
    name = worst.get("name") or ""
    pkg = html.escape(f"{name} {worst.get('version') or ''}".strip())
    n = len(group)
    count_line = (f"<div style='color:#666;font-size:12px;margin-top:2px'>{n} known vulnerabilities</div>"
                  if n > 1 else "")
    impact = html.escape(str(worst.get("impact") or worst.get("summary") or ""))
    target = _max_version([g.get("fix") or g.get("fixed") for g in group])
    if target:
        more = f" (resolves {n} advisories)" if n > 1 else ""
        fix_line = (f"<div style='color:#1b5e20;margin-top:4px'>Fix: upgrade {html.escape(str(name))} to "
                    f"{html.escape(str(target))} or later{more}.</div>")
    else:
        fix_line = "<div style='color:#8a6d3b;margin-top:4px'>No fixed version is published yet.</div>"
    refs = []
    for g in group:
        r = g.get("vuln_id") or ", ".join(g.get("aliases") or [])
        if r:
            refs.append(r)
    refs = list(dict.fromkeys(refs))   # de-dupe, keep order
    ref_line = (f"<div style='color:#9aa3af;font-size:11px;margin-top:4px'>"
                f"{'References' if len(refs) > 1 else 'Reference'}: {html.escape(', '.join(refs))}</div>"
                if refs else "")
    header = _meta_line([f"<b>{repo}</b>", html.escape(f"Severity: {sev}") if sev else "", kev])
    return (f"<div style='margin:10px 0;padding:11px 13px;border-left:4px solid #475569;background:#f8fafc'>"
            f"<div style='color:#475569;font-size:13px'>{header}</div>"
            f"<div style='font-weight:600;margin-top:3px;color:#1f2937'>{pkg}</div>{count_line}"
            f"<div style='margin-top:4px;color:#374151'>{impact}</div>{fix_line}{ref_line}</div>")


def _dep_section(dep_findings):
    """The 'Vulnerable dependencies' section: its own clearly-marked block at the END of the email
    (below code/access issues), introduced by a labelled header and a one-line explainer so it reads
    as a distinct, lower-temperature category — routine package upgrades, not code holes (issue #4).
    Grouped one block per (repo, package, version) so a package's many advisories consolidate instead
    of repeating with conflicting fixes (issue #1)."""
    if not dep_findings:
        return ""
    groups, order = {}, []
    for f in dep_findings:
        k = (f.get("repo"), f.get("name"), f.get("version"))
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(f)
    blocks = "".join(_dep_group_block(groups[k]) for k in order)
    header = ("<div style='margin:20px 0 10px'>"
              "<div style='font-size:11px;font-weight:700;letter-spacing:.08em;color:#475569;"
              "text-transform:uppercase'>Vulnerable dependencies</div>"
              "<div style='color:#6b7280;font-size:12px;margin-top:3px'>Known vulnerabilities in "
              "third-party packages you depend on. The fix is to upgrade the package.</div></div>")
    return header + blocks


def _issue_count(findings):
    """Count issues the way the email DISPLAYS them: each code finding is one issue; each vulnerable
    dependency PACKAGE (repo, name, version) is ONE issue no matter how many advisories it carries.
    So 12 Django CVEs shown as one block count as one issue, not twelve."""
    code = sum(1 for f in (findings or []) if f.get("category") in _CODE_CATEGORIES)
    dep_pkgs = {(f.get("repo"), f.get("name"), f.get("version"))
                for f in (findings or []) if f.get("category") not in _CODE_CATEGORIES}
    return code + len(dep_pkgs)


def build_alert_email(code_findings, dep_findings, scanned_repos):
    """Owner-facing HTML for the consolidated alert. Two labelled sections: code/access issues on
    top (rarer, more serious), then vulnerable dependencies below. code_findings is already ranked +
    capped; dep_findings is listed in full (no cap — issue #1)."""
    n = _issue_count(code_findings + dep_findings)
    head = (f"<div style=\"font-family:-apple-system,Segoe UI,sans-serif;padding:16px;line-height:1.5;color:#1f2937\">"
            f"<h2 style='margin:0 0 4px;font-size:18px'>GitZoid Security Review</h2>"
            f"<div style='color:#666;font-size:12px'>{n} issue{'s' if n != 1 else ''} found across {scanned_repos} "
            f"repositor{'ies' if scanned_repos != 1 else 'y'}. Only real, exploitable issues are shown.</div>")
    # A thin divider separates the two sections only when BOTH are present, so a deps-only email does
    # not open with a stray rule.
    code_html = _section("Code and access issues", code_findings)
    dep_html = _dep_section(dep_findings)
    divider = ("<div style='height:1px;background:#e5e7eb;margin:26px 0 0'></div>"
               if code_html and dep_html else "")
    body = code_html + divider + dep_html
    foot = ("<div style='margin-top:14px;color:#888;font-size:11px'>"
            "GitZoid stays silent unless it finds something real, and will not re-alert you about an "
            "issue you have already seen.</div></div>")
    return head + body + foot


def build_subject(findings):
    top = findings[0]
    repos = {f.get("repo") for f in findings if f.get("repo")}
    multi = len(repos) > 1
    n = _issue_count(findings)              # count grouped issues (a package = 1), not raw CVEs
    count = f"{n} issues" if n != 1 else "1 issue"
    if top.get("actively_exploited"):
        where = (top.get("repo") or "your repos") + (f" and {len(repos) - 1} more" if multi else "")
        return f"GitZoid Security: actively exploited issue in {where}"
    where = f"{len(repos)} repositories" if multi else (top.get("repo") or "your repos")
    return f"GitZoid Security: {count} in {where}"


def parse_recipients(value):
    """Parse a comma/semicolon/space separated email string into a clean list (best-effort). These
    are CC'd on security alerts; the account owner is always the primary recipient via the SDK."""
    if not value:
        return []
    parts = re.split(r"[,;\s]+", str(value).strip())
    return [p for p in parts if "@" in p and "." in p.split("@")[-1]]


# ---------------------------------------------------------------- group routing (per-group delivery)
# A separate `security_groups` config var (mirrors the digest's digest_groups) lets alerts for
# different repos go to different people. Grouping is purely a DELIVERY-time partition: the scan
# pipeline and the persistent `security_findings` ledger stay GLOBAL (reconcile once above, split at
# send), so dedup / escalation / resolved logic is untouched. resolve_groups / parse_groups / slugify
# are duplicated from digest_check_and_init by the same no-sibling-imports convention as the lock
# helpers above.

def parse_groups(raw):
    """The security_groups input is stored by the dashboard as a JSON string; fetch may return it
    already-parsed or as a string. Normalize to a list; anything malformed -> []."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            v = json.loads(raw)
            return v if isinstance(v, list) else []
        except Exception:
            return []
    return []


def slugify(name, index) -> str:
    """Stable kebab-case identity for a group. Empty name -> group-{1-based index}."""
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s or f"group-{index + 1}"


def _selected_ids(repositories):
    out = []
    for r in (repositories or []):
        rid = r.get("id") if isinstance(r, dict) else r
        if rid:
            out.append(rid)
    return out


def resolve_groups(security_groups, repositories):
    """Normalize the security_groups input into this run's delivery map. Each configured group's
    repos are intersected with the globally-selected set (a repo deselected globally drops out);
    groups left with no selected repo are dropped. If no non-empty group survives, fall back to ONE
    implicit group over ALL selected repos (recipients empty -> owner only) — the 'default all'.
    Slugs are unique and stable. Returns [{name, repos, recipients, slug, implicit}]."""
    selected = _selected_ids(repositories)
    selected_set = set(selected)

    groups = []
    for g in (security_groups or []):
        if not isinstance(g, dict):
            continue
        repos = [p for p in (g.get("repos") or []) if p in selected_set]
        if not repos:
            continue
        groups.append({"name": (g.get("name") or "").strip(),
                       "repos": repos,
                       "recipients": [e for e in (g.get("recipients") or []) if e],
                       "implicit": False})

    if not groups and selected:
        groups = [{"name": "", "repos": selected, "recipients": [], "implicit": True}]

    seen, out = set(), []
    for i, g in enumerate(groups):
        base = slugify(g["name"], i)
        slug, n = base, 2
        while slug in seen:
            slug = f"{base}-{n}"
            n += 1
        seen.add(slug)
        g["slug"] = slug
        out.append(g)
    return out


def clean_email_list(values):
    """Validate + de-dupe an email list, preserving order. The owner is always the primary recipient
    (added by the SDK); these are CC'd on top."""
    out = []
    for e in (values or []):
        e = str(e).strip()
        if "@" in e and "." in e.split("@")[-1] and e not in out:
            out.append(e)
    return out


def group_alerts(to_alert, groups):
    """Partition the reconciled to-alert findings into per-group send units, by the finding's repo.
    Each explicit group with at least one finding becomes one unit (its recipients CC'd; the owner is
    always primary). A finding whose repo is in no group collects into ONE owner-only catch-all unit,
    so a security finding is NEVER silently dropped because its repo was left out of every group.
    Groups with no findings this run produce no unit (no empty emails). The code-section cap is
    applied later, per unit, so it becomes per-group. Returns
    [{slug, recipients, repo_count, findings}] with the catch-all (if any) last."""
    repo_to_group = {}
    for g in (groups or []):
        for r in (g.get("repos") or []):
            repo_to_group.setdefault(r, g)        # first group wins (membership is exclusive anyway)
    units, by_slug, ungrouped = [], {}, []
    for f in (to_alert or []):
        g = repo_to_group.get(f.get("repo"))
        if g is None:
            ungrouped.append(f)
            continue
        slug = g.get("slug")
        unit = by_slug.get(slug)
        if unit is None:
            unit = {"slug": slug, "recipients": list(g.get("recipients") or []),
                    "repo_count": len(g.get("repos") or []), "findings": []}
            by_slug[slug] = unit
            units.append(unit)
        unit["findings"].append(f)
    if ungrouped:
        repos = {f.get("repo") for f in ungrouped if f.get("repo")}
        units.append({"slug": "ungrouped", "recipients": [],
                      "repo_count": len(repos), "findings": ungrouped})
    return units


def release_run_lock():
    """Release the security lock only if THIS run owns it (token match)."""
    my_token = waveassist.fetch_data("security_run_lock_token", run_based=True, default="") or ""
    if not my_token:
        return
    lock = waveassist.fetch_data(RUN_LOCK_KEY, default={}) or {}
    if isinstance(lock, dict) and lock.get("token") == my_token:
        waveassist.store_data(RUN_LOCK_KEY, {}, data_type="json")
        print("GitZoid Security: released run lock.")


# ---------------------------------------------------------------- driver (flat, fall-through)

skip = waveassist.fetch_data("security_skip_run", run_based=True, default="0") == "1"

if not skip:
    candidates = waveassist.fetch_data("security_candidates", run_based=True, default=[]) or []
    prior_ledger = waveassist.fetch_data(LEDGER_KEY, default={}) or {}
    scanned_ok_deps = waveassist.fetch_data("security_scanned_ok_deps", run_based=True, default=[]) or []
    scanned_ok_code = waveassist.fetch_data("security_scanned_ok_code", run_based=True, default=[]) or []
    new_ledger, to_alert, resolved = reconcile_ledger(prior_ledger, candidates,
                                                      scanned_ok_deps=scanned_ok_deps,
                                                      scanned_ok_code=scanned_ok_code)

    repositories = waveassist.fetch_data("github_selected_resources", default=[]) or []
    scanned_repos = len(repositories) if isinstance(repositories, list) else 0

    waveassist.store_data(LEDGER_KEY, new_ledger, data_type="json")

    preview = False
    try:
        preview = waveassist.is_test_run()
    except Exception:
        preview = False

    if to_alert:
        # Grouping is a delivery-time split ONLY: the ledger was reconciled once globally above; here
        # we fan the to-alert set out per group (resolve_groups applies the implicit 'default all'
        # fallback) so different repos route to different people. The code cap is applied per unit
        # below, so it is per-group; a repo in no group still alerts the owner via the catch-all unit.
        groups = resolve_groups(parse_groups(waveassist.fetch_data("security_groups", default=[])),
                                repositories)
        units = group_alerts(to_alert, groups)
        # Global extras are CC'd on EVERY group email (the org-wide security distro); each group's own
        # recipients are added on top. The owner is always the primary recipient (SDK).
        global_cc = parse_recipients(waveassist.fetch_data("security_recipients", default="") or "")

        sent_count, total_issues, last_html, results = 0, 0, "", []
        for unit in units:
            ranked = rank_findings(unit["findings"])
            code, deps = split_findings(ranked)
            kept_code = cap_code_findings(code)          # per unit -> per-group cap; deps in full
            displayed = rank_findings(kept_code + deps)  # exactly what THIS group's email shows
            subject = build_subject(displayed)           # subject + count agree with the body
            email_html = build_alert_email(kept_code, deps, unit["repo_count"])
            cc = clean_email_list(list(unit["recipients"]) + global_cc)
            last_html = email_html
            n = _issue_count(displayed)
            total_issues += n
            # A preview/test run builds the email but sends nothing — so `sent` must reflect real
            # delivery only, never a previewed unit. `previewed` records that the unit was prepared.
            delivered = False
            if not preview:
                try:
                    delivered = bool(waveassist.send_email(subject=subject, html_content=email_html,
                                                           cc=cc or None, raise_on_failure=False))
                except Exception as e:
                    print(f"⚠️ security alert email failed for {unit['slug']}: {e}")
                    delivered = False
            if delivered:
                sent_count += 1
            results.append({"group": unit["slug"], "issues": n,
                            "sent": delivered, "previewed": preview})

        title = (f"GitZoid Security (preview): {len(units)} group email(s) prepared"
                 if preview else
                 f"GitZoid Security: {sent_count} alert email(s) sent across {len(units)} group(s)")
        waveassist.store_data("display_output",
                              {"title": title, "html_content": last_html, "groups": results,
                               "sent": sent_count, "preview": preview},
                              run_based=True, data_type="json")
        if preview:
            print(f"GitZoid Security (preview): prepared {len(units)} group email(s), "
                  f"{total_issues} issue(s); nothing sent.")
        else:
            print(f"GitZoid Security: alerted {total_issues} issue(s) across {len(units)} group(s); "
                  f"{sent_count} email(s) sent; {len(resolved)} resolved.")
    else:
        msg = (f"<p>GitZoid scanned {scanned_repos} repo(s) — nothing new to report. "
               f"{len(resolved)} issue(s) resolved since last time.</p>")
        waveassist.store_data("display_output", {"html_content": msg}, run_based=True, data_type="json")
        print(f"GitZoid Security: silent (no new findings); {len(resolved)} resolved.")
        waveassist.mark_run_idle()      # scanned, nothing new to alert → idle
else:
    waveassist.mark_run_idle()          # skipped cycle (another security run in progress)

release_run_lock()
