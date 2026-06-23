"""
send_digest.py — the Knowledge Digest chain's delivery node (node 6, per group).

Adapted from GitDigest's send_emails: the same combined HTML email (stats bar, summary, primary
updates, repository deep dive, poem) plus a WeasyPrint PDF attachment, but fanned out PER resolved
group. Each group's email goes to the account owner (always primary, via the SDK) with the group's
configured recipients CC'd, and carries the group's SECURITY ROLL-UP — the weekly reassurance that
makes Security Watch's silence trustworthy. The digest sends every week, even a quiet one.

As the chain's last node it releases `digest_run_lock`, token-matched (only if this run owns it),
exactly like triage_and_alert.

WeasyPrint is imported lazily inside generate_pdf so the module loads without it and PDF generation
soft-fails to "no attachment" rather than crashing the send. Flat script, no __main__ guard, no
sibling imports.
"""
import io
import html as html_lib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import waveassist

waveassist.init()   # credits gated once upstream in digest_check_and_init

print("GitZoid Digest: starting digest delivery (send_digest) node")

RUN_LOCK_KEY = "digest_run_lock"
_SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "unknown": "Unknown"}


def _esc(value) -> str:
    return html_lib.escape(str(value), quote=True) if value is not None else ""


def _ul(items) -> str:
    if not items:
        return "<p class='muted'>None this week.</p>"
    return "<ul>" + "".join(f"<li>{_esc(i)}</li>" for i in items) + "</ul>"


# ---------------------------------------------------------------- pure helpers (tested)

def compute_stats(activity, group_repos) -> Dict[str, int]:
    """Commits, distinct contributors, total + active repos — scoped to this group's repos."""
    repos = set(group_repos or [])
    commits, contributors, active = 0, set(), 0
    for repo, data in (activity or {}).items():
        if repo not in repos:
            continue
        cs = (data or {}).get("commits", []) or []
        if cs:
            active += 1
        commits += len(cs)
        for c in cs:
            if c.get("author"):
                contributors.add(c["author"])
    return {"commits": commits, "contributors": len(contributors),
            "total_repos": len(repos), "active_repos": active}


def clean_recipients(recipients) -> List[str]:
    """Validated CC list (the owner is always the primary recipient, added by the SDK)."""
    out = []
    for e in (recipients or []):
        e = str(e).strip()
        if "@" in e and "." in e.split("@")[-1]:
            out.append(e)
    return out


def digest_status(sent, attempted):
    """'success' ONLY if at least one group was attempted and every attempt delivered. If groups
    existed but all were skipped because report generation failed upstream (attempted == 0), that's a
    failure, not a silent green run."""
    if attempted == 0:
        return "generation_failed"
    return "success" if sent == attempted else "email_failed"


def render_group_preview(group_name, recipients, sent, body_html):
    """One labelled section for the dashboard run-output preview, so a run with N groups shows ALL N
    (not just the last one processed). The owner is always the primary recipient; `recipients` are the
    CC'd group members. Purely presentational — the emails themselves are unchanged."""
    who = ", ".join(recipients) if recipients else "owner only"
    status = "sent" if sent else "not sent"
    header = (f"<div style=\"font-family:Inter,-apple-system,sans-serif;margin:18px 0 6px;"
              f"padding:8px 12px;background:#f1f5f9;border-left:4px solid #1ED66C;border-radius:6px\">"
              f"<b>{_esc(group_name)}</b>"
              f"<span style=\"color:#6b7280;font-size:12px\"> &nbsp;|&nbsp; CC: {_esc(who)}"
              f" &nbsp;|&nbsp; {status}</span></div>")
    return header + (body_html or "")


def render_security_rollup_html(rollup) -> str:
    """The 'we watched, here is the state' section. Always rendered, even at zero (that IS the value)."""
    rollup = rollup or {}
    counts = rollup.get("counts", {"new": 0, "still_open": 0, "resolved": 0})

    def line(item):
        kev = " <span class='kev'>actively exploited</span>" if item.get("actively_exploited") else ""
        sev = _SEV_LABEL.get(item.get("severity"), "")
        n = item.get("count", 1)
        adv = f", {n} advisories" if n and n > 1 else ""
        return (f"<li><b>{_esc(item.get('title'))}</b> "
                f"<span class='muted'>({_esc(item.get('repo'))}{', ' + sev if sev else ''}{adv})</span>{kev}</li>")

    if not (counts.get("new") or counts.get("still_open") or counts.get("resolved")):
        body = ("<p class='success'>No security issues found this week. GitZoid watched your dependencies "
                "and code and found nothing exploitable.</p>")
    else:
        body = (f"<p class='muted'>{counts.get('new', 0)} new, {counts.get('still_open', 0)} still open, "
                f"{counts.get('resolved', 0)} resolved this week.</p>")
        if rollup.get("new"):
            body += "<h3>New this week</h3><ul>" + "".join(line(i) for i in rollup["new"]) + "</ul>"
        if rollup.get("still_open"):
            body += "<h3>Still open</h3><ul>" + "".join(line(i) for i in rollup["still_open"]) + "</ul>"
        if rollup.get("resolved"):
            body += "<h3>Resolved this week</h3><ul>" + "".join(line(i) for i in rollup["resolved"]) + "</ul>"
    return f"<h2>🔒 SECURITY</h2>{body}"


def digest_title(group_name, implicit=False) -> str:
    """Brand title shared by the inbox SUBJECT and the email H1 so the two always match. Unnamed/
    implicit -> "GitZoid Digest"; a named group reads as "GitZoid <name> Digest". The bare
    "All repositories" default is never surfaced."""
    name = (group_name or "").strip()
    if implicit or not name or name == "All repositories":
        return "GitZoid Digest"
    return f"GitZoid {name} Digest"


def build_subject(group_name, period_end="", implicit=False) -> str:
    """Branded subject in the same shape as the security alert ("GitZoid Security: ..."):
    "GitZoid <name> Digest: Week of <date>" (or just "GitZoid Digest:" when unnamed)."""
    week = f"Week of {period_end}" if period_end else "Weekly update"
    return f"{digest_title(group_name, implicit)}: {week}"


def group_generation_failed(business_report, technical_report) -> bool:
    """True iff an LLM call RAISED while generating this group's report (set by the report nodes).
    A deterministic quiet-week empty report does NOT set this flag, so a quiet group still sends."""
    return bool((business_report or {}).get("generation_failed")
                or (technical_report or {}).get("generation_failed"))


def pdf_filename(group_name, now=None) -> str:
    now = now or datetime.now(timezone.utc)
    safe = "".join(c if c.isalnum() else "_" for c in (group_name or "digest"))
    return f"GitZoid_Digest_{safe}_{now.strftime('%Y%m%d_%H%M')}.pdf"


_STYLE = """
body { font-family: Inter, -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif; color: #0f172a; margin: 18px; }
.container { max-width: 700px; margin: 0 auto; background: #fff; border-radius: 12px; border: 1px solid #e5e7eb; border-top: 4px solid #1ED66C; overflow: hidden; }
.header { padding: 14px; border-bottom: 1px solid #e5e7eb; }
.header h1 { margin: 0; font-size: 22px; color: #0f1116; }
.subtitle { color: #6b7280; font-size: 12px; margin-top: 6px; }
/* Table, not flexbox: WeasyPrint (PDF) and email clients render flex unreliably and wrap the 4 stats;
   a 4-column table keeps them on one row everywhere. */
.stats-bar { width: 100%; border-collapse: collapse; border-bottom: 1px solid #e5e7eb; }
.stats-bar td { width: 25%; text-align: center; padding: 16px 6px; vertical-align: top; }
.stat-value { font-size: 24px; font-weight: 700; color: #1ED66C; }
.stat-label { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; }
.content { padding: 14px; }
h2 { color: #0f1116; font-size: 20px; margin-top: 28px; padding: 10px 0 10px 12px; border-left: 4px solid #1ED66C; border-bottom: 1px solid #e5e7eb; }
h2:first-child { margin-top: 0; }
h3 { color: #0f1116; font-size: 14px; margin: 14px 0 8px 0; }
h4 { color: #0f1116; font-size: 14px; margin: 0 0 4px 0; }
p { margin: 8px 0; line-height: 1.45; }
ul { margin: 6px 0 10px 18px; padding: 0; }
li { margin: 4px 0; line-height: 1.45; }
.summary-box { padding: 12px; border-radius: 8px; border: 1px solid #e5e7eb; border-left: 3px solid #1ED66C; margin-bottom: 20px; }
.repo-card { padding: 12px; border-radius: 12px; border: 1px solid #e5e7eb; border-left: 3px solid #1ED66C; margin: 10px 0; }
.repo-status { color: #6b7280; font-weight: normal; font-size: 12px; }
.muted { color: #6b7280; font-size: 12px; }
.success { color: #148F47; font-weight: 500; }
.kev { color: #b91c1c; font-weight: 600; font-size: 12px; }
.poem { background: #f9fafb; padding: 16px; border-radius: 8px; border-left: 3px solid #1ED66C; margin: 20px 0; }
.poem-line { margin: 2px 0; color: #374151; font-style: italic; }
.footer { text-align: center; padding: 20px; border-top: 1px solid #e5e7eb; }
.footer p { margin: 4px 0; font-size: 12px; color: #6b7280; }
@page { margin: 0.75in; size: letter; }
"""


def build_email_html(group_name, business_report, technical_report, stats, date_range, implicit=False) -> str:
    """The combined per-group digest email (also rendered to PDF). The H1 matches the inbox subject's
    brand title (digest_title): "GitZoid <name> Digest" for a named group, "GitZoid Digest" unnamed."""
    business_report = business_report or {}
    technical_report = technical_report or {}
    summary = business_report.get("executive_summary", "No summary available.")
    features = business_report.get("shipped_features", []) or []
    deep_dive = technical_report.get("repository_deep_dive", []) or []
    poem = [l for l in (technical_report.get("poem", []) or []) if l]
    rollup_html = render_security_rollup_html(technical_report.get("security_rollup"))

    repo_html = ""
    for ru in deep_dive:
        if isinstance(ru, dict):
            repo_html += (f"<div class='repo-card'><h4>{_esc(ru.get('repo_name', 'Unknown'))} "
                          f"<span class='repo-status'>({_esc(ru.get('status', ''))})</span></h4>"
                          f"{_ul(ru.get('technical_changes', []))}</div>")
    if not repo_html:
        repo_html = "<p class='muted'>No repository updates this week.</p>"

    poem_html = ""
    poem_divider = ""
    if poem:
        poem_html = ("<div class='poem'><h3>A small poem for this week:</h3><em>"
                     + "".join(f"<p class='poem-line'>{_esc(l)}</p>" for l in poem) + "</em></div>")
        # Separate the poem from the security section above it (on a clean week the short "nothing
        # found" line otherwise runs straight into the poem).
        poem_divider = "<hr style='border:0;border-top:1px solid #e5e7eb;margin:22px 0' />"

    period = ""
    if date_range and date_range.get("start_date_formatted"):
        period = (f"<div class='subtitle'>Report period: {_esc(date_range.get('start_date_formatted'))} - "
                  f"{_esc(date_range.get('end_date_formatted'))}</div>")

    return f"""<html><head><meta charset="utf-8" /><style>{_STYLE}</style></head><body>
<div class="container">
  <div class="header"><h1>{_esc(digest_title(group_name, implicit))}</h1>{period}</div>
  <table class="stats-bar" role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>
    <td><div class="stat-value">{stats.get('commits', 0)}</div><div class="stat-label">Commits</div></td>
    <td><div class="stat-value">{stats.get('contributors', 0)}</div><div class="stat-label">Contributors</div></td>
    <td><div class="stat-value">{stats.get('total_repos', 0)}</div><div class="stat-label">Total Repos</div></td>
    <td><div class="stat-value">{stats.get('active_repos', 0)}</div><div class="stat-label">Active Repos</div></td>
  </tr></table>
  <div class="content">
    <h2>SUMMARY</h2><div class="summary-box"><p>{_esc(summary)}</p></div>
    <h2>🚀 PRIMARY UPDATES</h2>{_ul(features)}
    <h2>🛠️ REPOSITORY DEEP DIVE</h2>{repo_html}
    {rollup_html}
    {poem_divider}
    {poem_html}
  </div>
  <div class="footer">
    <p>Generated by <a href="https://gitzoid.com" style="color:#1ED66C;text-decoration:none;">GitZoid</a>
       · Powered by <a href="https://waveassist.io" style="color:#1ED66C;text-decoration:none;">WaveAssist</a></p>
    <p class="muted">A PDF version is attached for easy sharing and printing.</p>
  </div>
</div></body></html>"""


def generate_pdf(html_content, group_name):
    """Render the email HTML to a PDF BytesIO. Soft-fails to (None, error) if WeasyPrint is unavailable
    or rendering fails — the email still goes, just without the attachment."""
    name = pdf_filename(group_name)
    try:
        from weasyprint import HTML   # lazy: keep the module importable without WeasyPrint
        pdf = io.BytesIO(HTML(string=html_content).write_pdf())
        setattr(pdf, "name", name)
        pdf.seek(0)
        return pdf, name, None
    except Exception as e:
        return None, name, f"PDF generation failed: {e}"


def release_run_lock():
    """Release the digest lock only if THIS run owns it (token match)."""
    my_token = waveassist.fetch_data("digest_run_lock_token", run_based=True, default="") or ""
    if not my_token:
        return
    lock = waveassist.fetch_data(RUN_LOCK_KEY, default={}) or {}
    if isinstance(lock, dict) and lock.get("token") == my_token:
        waveassist.store_data(RUN_LOCK_KEY, {}, data_type="json")
        print("GitZoid Digest: released run lock.")


# ---------------------------------------------------------------- driver (flat, fall-through)

skip = waveassist.fetch_data("digest_skip_run", run_based=True, default="0") == "1"

if not skip:
    groups = waveassist.fetch_data("digest_resolved_groups", run_based=True, default=[]) or []
    business_reports = waveassist.fetch_data("digest_business_reports", run_based=True, default={}) or {}
    technical_reports = waveassist.fetch_data("digest_technical_reports", run_based=True, default={}) or {}
    activity = waveassist.fetch_data("github_activity_data", default={}) or {}
    date_range = waveassist.fetch_data("report_date_range", default={}) or {}
    digest_state = waveassist.fetch_data("digest_state", default={}) or {}
    now_iso = datetime.now(timezone.utc).isoformat()

    sent, results = 0, []
    preview_blocks = []
    for group in groups:
        slug = group.get("slug")
        name = group.get("name") or "your repositories"
        business_report = business_reports.get(slug) or {}
        technical_report = technical_reports.get(slug) or {}

        if group_generation_failed(business_report, technical_report):
            # An LLM call raised; do NOT send a broken/empty email. Skip and log; last_sent_at untouched.
            print(f"⚠️ {slug}: report generation failed upstream; skipping send (no broken email)")
            results.append({"group": name, "sent": False, "skipped": True,
                            "reason": "generation_failed", "pdf": None, "pdf_error": None})
            preview_blocks.append(render_group_preview(
                name, clean_recipients(group.get("recipients")), False,
                "<p style='color:#8a6d3b;padding:0 12px'>Report generation failed upstream — not sent.</p>"))
            continue

        stats = compute_stats(activity, group.get("repos") or [])
        html = build_email_html(name, business_report, technical_report, stats, date_range,
                                implicit=group.get("implicit"))
        pdf_file, pdf_name, pdf_error = generate_pdf(html, name)
        cc = clean_recipients(group.get("recipients"))
        try:
            ok = waveassist.send_email(subject=build_subject(name, date_range.get("end_date_formatted", ""),
                                                             implicit=group.get("implicit")),
                                       html_content=html, attachment_file=pdf_file,
                                       cc=cc or None, raise_on_failure=False)
        except Exception as e:
            print(f"⚠️ digest email failed for {slug}: {e}")
            ok = False
        if ok:
            sent += 1
            # Only stamp last_sent_at on a REAL delivery (mirrors the generation-failed skip path);
            # a failed send must not look delivered.
            state = digest_state.get(slug) or {}
            state["last_sent_at"] = now_iso
            digest_state[slug] = state
        results.append({"group": name, "sent": bool(ok), "pdf": pdf_name, "pdf_error": pdf_error})
        preview_blocks.append(render_group_preview(name, cc, ok, html))
        print(f"{'✓' if ok else '⚠️'} {slug}: digest {'sent' if ok else 'send failed'}")

    waveassist.store_data("digest_state", digest_state, data_type="json")
    attempted = len([r for r in results if not r.get("skipped")])
    waveassist.store_data("display_output", {
        "title": f"GitZoid Digest: {sent} email(s) sent",
        "html_content": "".join(preview_blocks) or "<p>No groups to send.</p>",
        "attempted": attempted,
        "status": digest_status(sent, attempted),
        "groups": results,
    }, run_based=True, data_type="json")
    print(f"GitZoid Digest: sent {sent}/{len(results)} group digest(s).")
    if sent == 0:
        waveassist.mark_run_idle()      # no digest delivered this run → idle
else:
    print("GitZoid Digest: digest_skip_run set; send_digest no-op.")
    waveassist.mark_run_idle()          # skipped cycle (off-week, disabled, or overlapping run)

release_run_lock()
