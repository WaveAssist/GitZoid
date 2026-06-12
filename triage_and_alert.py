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
import html
import hashlib
from datetime import datetime, timezone
import waveassist

waveassist.init()   # credits gated once upstream in security_check_and_init

MAX_ALERTS = 5
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
    """Position-independent identity shared by every security source. A dependency finding is keyed
    by package + the vuln id (or its normalized title if no id); a code finding by its location +
    normalized title. So the same root issue keeps one identity across runs and sources."""
    cat = f.get("category", "")
    repo = f.get("repo", "")
    key = f.get("name") or f.get("path") or f.get("entry_point") or ""
    ident = f.get("vuln_id") or _norm(f.get("title") or f.get("summary") or "")
    return hashlib.sha1(f"{cat}|{repo}|{key}|{ident}".encode()).hexdigest()[:12]


def should_escalate(prior: dict, new: dict) -> bool:
    """Re-alert an already-seen finding only if it got worse: severity rose, or a fix is now
    published where there wasn't one before."""
    prior_sev = _SEV_RANK.get(prior.get("severity"), 4)
    new_sev = _SEV_RANK.get(new.get("severity"), 4)
    if new_sev < prior_sev:                      # lower rank number = more severe
        return True
    if not prior.get("fixed") and new.get("fixed"):
        return True
    return False


def _entry_from(f, sig, now_iso):
    return {"sig": sig, "category": f.get("category"), "repo": f.get("repo"),
            "name": f.get("name"), "path": f.get("path"), "entry_point": f.get("entry_point"),
            "title": f.get("title"), "vuln_id": f.get("vuln_id"),
            "severity": f.get("severity"), "fixed": f.get("fixed"),
            "actively_exploited": f.get("actively_exploited", False),
            "impact": f.get("impact") or f.get("summary") or "",
            "fix": f.get("fix") or f.get("fixed") or "",
            "status": "open", "alerted": True,
            "first_seen": now_iso, "last_seen": now_iso}


def reconcile_ledger(prior_ledger, candidates, now=None):
    """Returns (new_ledger, to_alert, resolved). Alert new or reappeared findings and escalations;
    carry unchanged ones silently; mark currently-open findings that disappeared as resolved."""
    now_iso = (now or datetime.now(timezone.utc)).isoformat()
    new_ledger = {k: dict(v) for k, v in (prior_ledger or {}).items()}
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
            prior.update({"severity": f.get("severity"), "fixed": f.get("fixed"),
                          "actively_exploited": f.get("actively_exploited", prior.get("actively_exploited")),
                          "impact": f.get("impact") or prior.get("impact"),
                          "status": "open", "alerted": True, "last_seen": now_iso})
            to_alert.append(prior)
        else:
            prior["last_seen"] = now_iso
            prior["status"] = "open"

    resolved = []
    for sig, entry in new_ledger.items():
        if entry.get("status") == "open" and sig not in current_sigs:
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

_SEV_BADGE = {"critical": "🔴 Critical", "high": "🔴 High", "medium": "🟡 Medium",
              "low": "🔵 Low", "unknown": "⚪ Unknown"}


def _finding_block(f) -> str:
    repo = html.escape(str(f.get("repo") or ""))
    sev = _SEV_BADGE.get(f.get("severity"), "")
    kev = " · <b>actively exploited in the wild</b>" if f.get("actively_exploited") else ""
    impact = html.escape(str(f.get("impact") or ""))
    if f.get("category") == "dependency":
        pkg = html.escape(f"{f.get('name') or ''} {f.get('version') or ''}".strip())
        fix = f.get("fix") or f.get("fixed")
        fix_line = (f"<div style='color:#1b5e20'>→ Fix: upgrade {html.escape(pkg.split(' ')[0])} "
                    f"to {html.escape(str(fix))}.</div>") if fix else \
                   "<div style='color:#8a6d3b'>→ No fixed version published yet.</div>"
        ref = f.get("vuln_id") or ", ".join(f.get("aliases") or [])
        ref_line = f"<div style='color:#888;font-size:11px'>Ref: {html.escape(str(ref))}</div>" if ref else ""
        return (f"<div style='margin:10px 0;padding:10px 12px;border-left:3px solid #b91c1c;background:#fbf6f6'>"
                f"<div><b>{html.escape(repo)}</b> — {pkg} · {sev}{kev}</div>"
                f"<div style='margin:4px 0'>{impact}</div>{fix_line}{ref_line}</div>")
    # code finding (authz / secret / backdoor)
    title = html.escape(str(f.get("title") or f.get("category")))
    victim = html.escape(str(f.get("named_victim") or ""))
    fix = html.escape(str(f.get("fix") or ""))
    where = html.escape(str(f.get("path") or f.get("entry_point") or ""))
    victim_line = f"<div>Who's affected: {victim}</div>" if victim else ""
    fix_line = f"<div style='color:#1b5e20'>→ Fix: {fix}</div>" if fix else ""
    where_line = f"<div style='color:#888;font-size:11px'>{where}</div>" if where else ""
    return (f"<div style='margin:10px 0;padding:10px 12px;border-left:3px solid #b91c1c;background:#fbf6f6'>"
            f"<div><b>{html.escape(repo)}</b> — {title} · {sev}{kev}</div>"
            f"<div style='margin:4px 0'>{impact}</div>{victim_line}{fix_line}{where_line}</div>")


def build_alert_email(findings, scanned_repos):
    """Owner-facing HTML for the consolidated alert. findings already ranked + capped."""
    n = len(findings)
    head = (f"<div style=\"font-family:-apple-system,Segoe UI,sans-serif;padding:16px;line-height:1.5\">"
            f"<h2 style='margin:0 0 4px'>🛡️ GitZoid Security — {n} issue{'s' if n != 1 else ''} found</h2>"
            f"<div style='color:#666;font-size:12px'>Reviewed across {scanned_repos} "
            f"repo{'s' if scanned_repos != 1 else ''}. Only real, exploitable issues are shown.</div>")
    body = "".join(_finding_block(f) for f in findings)
    foot = ("<div style='margin-top:14px;color:#888;font-size:11px'>"
            "GitZoid stays silent unless it finds something real. "
            "You will not be re-alerted about an issue you've already seen.</div></div>")
    return head + body + foot


def build_subject(findings):
    top = findings[0]
    where = top.get("repo") or "your repos"
    if top.get("actively_exploited"):
        return f"🛡️ GitZoid Security: actively-exploited issue in {where}"
    sev = top.get("severity", "")
    return f"🛡️ GitZoid Security: {sev} issue in {where}" if sev else f"🛡️ GitZoid Security: issue in {where}"


def release_run_lock():
    """Release the security lock only if THIS run owns it (token match)."""
    my_token = waveassist.fetch_data("security_run_lock_token", default="") or ""
    if not my_token:
        return
    lock = waveassist.fetch_data(RUN_LOCK_KEY, default={}) or {}
    if isinstance(lock, dict) and lock.get("token") == my_token:
        waveassist.store_data(RUN_LOCK_KEY, {}, data_type="json")
        print("GitZoid Security: released run lock.")


# ---------------------------------------------------------------- driver (flat, fall-through)

skip = bool(waveassist.fetch_data("security_skip_run", default=False))

if not skip:
    candidates = waveassist.fetch_data("security_candidates", default=[]) or []
    prior_ledger = waveassist.fetch_data(LEDGER_KEY, default={}) or {}
    new_ledger, to_alert, resolved = reconcile_ledger(prior_ledger, candidates)

    repositories = waveassist.fetch_data("github_selected_resources", default=[]) or []
    scanned_repos = len(repositories) if isinstance(repositories, list) else 0

    waveassist.store_data(LEDGER_KEY, new_ledger, data_type="json")

    preview = False
    try:
        preview = waveassist.is_test_run()
    except Exception:
        preview = False

    if to_alert:
        ranked = rank_findings(to_alert)[:MAX_ALERTS]
        subject = build_subject(ranked)
        email_html = build_alert_email(ranked, scanned_repos)
        if not preview:
            try:
                waveassist.send_email(subject=subject, html_content=email_html, raise_on_failure=False)
            except Exception as e:
                print(f"⚠️ security alert email failed: {e}")
        waveassist.store_data("display_output", {"html_content": email_html},
                              run_based=True, data_type="json")
        print(f"GitZoid Security: alerted {len(ranked)} finding(s); {len(resolved)} resolved.")
    else:
        msg = (f"<p>GitZoid scanned {scanned_repos} repo(s) — nothing new to report. "
               f"{len(resolved)} issue(s) resolved since last time.</p>")
        waveassist.store_data("display_output", {"html_content": msg}, run_based=True, data_type="json")
        print(f"GitZoid Security: silent (no new findings); {len(resolved)} resolved.")

release_run_lock()
