"""
security_check_and_init.py — the Security Watch chain's daily starting node.

Mirrors check_credits_and_init (the Review chain's gate) but on a separate daily clock and its
OWN overlap lock, so the security scan never blocks PR reviews and vice-versa. It:
  1. waveassist.init()
  2. skips the whole chain cleanly if Security is toggled off (enable_security) or no repos
  3. check_credits_and_notify(...) — stop the run if the account is out of credits
  4. acquires `security_run_lock` so overlapping daily ticks don't double-scan
  5. stores run-based `security_skip_run` so downstream security nodes no-op on a skipped cycle

Why a separate lock from the Review chain: the two chains are disconnected subgraphs on different
schedules and touch different data keys. Sharing the review `run_lock` would let a slow daily scan
delay PR reviews. triage_and_alert (the last security node) releases this lock; a crashed run frees
it via LOCK_TTL_SECONDS.

Flat script, no __main__ guard. On no-credits it stores a display_output and raises (the run is
marked failed — the intended "skipped, buy credits" signal). It does NOT raise on security-disabled,
missing repos, or a lock-skip: those are clean daily no-ops, not failed runs.
"""
import re
import json
import uuid
from datetime import datetime, timezone
import waveassist

# A daily security run may include a weekly deep audit of several repos, so this matches the
# Review/GitDigest gate (0.3), not a tiny per-scan figure.
CREDITS_NEEDED_FOR_RUN = 0.3

# Single-run lock for the security chain. Held from here until triage_and_alert releases it. The TTL
# is a crash safety net generous enough for the slowest legit run (a weekly deep audit of every repo).
RUN_LOCK_KEY = "security_run_lock"
# 2 hours, matching the Review lock. A legit run can wait in the Celery queue under load AND then run a
# ~20-min deep audit, so a short TTL risked expiring mid-run (the premature-expiry class the Review lock
# was bumped for). The chain fires only daily, so a generous TTL never serializes normal cycles; it just
# frees a genuinely crashed run instead of wedging the next day's scan.
LOCK_TTL_SECONDS = 7200   # 2 hours

# Upfront progress-bar budget (seconds), mirroring the Review gate so the dashboard bar shows from
# second 0. The weekly deep audit dominates a security run (one large-context LLM call per repo), so
# budget per repo for a possible audit. Over-estimating is safe: the frontend caps the bar at 80%.
# Note: for large fleets the deep audit self-throttles at its own 1200s/run budget and rolls the
# remainder to the next daily tick, so this estimate can exceed a single run's real duration past
# ~12 repos — that just means the bar fills slowly, never that it stalls.
SECURITY_SECONDS_PER_REPO = 100   # budget for a possible weekly deep audit, per repo
SECURITY_BASE_SECONDS = 10        # small base for the daily dependency scan + triage


def estimate_time_to_process(num_repos: int) -> int:
    """Upfront seconds estimate for the whole security chain, covering a possible weekly deep audit.
    Over-estimating is safe: the frontend caps the bar at 80%."""
    if not isinstance(num_repos, int) or num_repos < 0:
        num_repos = 0
    return num_repos * SECURITY_SECONDS_PER_REPO + SECURITY_BASE_SECONDS


def lock_is_active(lock, now=None) -> bool:
    """A security run is in progress iff a lock exists, has a timestamp, and is younger than the TTL."""
    if not isinstance(lock, dict) or not lock.get("at"):
        return False
    now = now or datetime.now(timezone.utc)
    try:
        age = (now - datetime.fromisoformat(lock["at"])).total_seconds()
    except Exception:
        return False
    return age < LOCK_TTL_SECONDS


def security_enabled(value) -> bool:
    """Parse the optional `enable_security` toggle. Default ON (unset/empty) — existing users get
    Security on by default. Only an explicit falsey value turns it off."""
    if value is None or value == "":
        return True
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("false", "no", "off", "0")


def _parse_groups(raw):
    """security_groups may be stored as a JSON string or already-parsed list."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            v = json.loads(raw)
            return v if isinstance(v, list) else []
        except Exception:
            return []
    return []


def _slugify(name, index) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s or f"group-{index + 1}"


def _resolve_security_groups(security_groups, repositories):
    """Resolve security_groups against the globally-selected repos. Exclusive membership: first group
    to claim a repo owns it (no cross-group CC leak). Falls back to one implicit group of all repos
    when no groups are configured. Mirrors triage_and_alert.resolve_groups exactly — resolved once
    here so every downstream node (scan, audit, triage) works from the same scoped set."""
    selected = [r.get("id") if isinstance(r, dict) else r for r in (repositories or []) if
                (r.get("id") if isinstance(r, dict) else r)]
    selected_set = set(selected)

    groups, claimed = [], set()
    for g in (security_groups or []):
        if not isinstance(g, dict):
            continue
        repos = []
        for p in (g.get("repos") or []):
            if p in selected_set and p not in claimed:
                repos.append(p)
                claimed.add(p)
        if not repos:
            continue
        groups.append({"name": (g.get("name") or "").strip(), "repos": repos,
                       "recipients": [e for e in (g.get("recipients") or []) if e],
                       "implicit": False})

    if not groups and selected:
        groups = [{"name": "", "repos": selected, "recipients": [], "implicit": True}]

    seen, out = set(), []
    for i, g in enumerate(groups):
        base = _slugify(g["name"], i)
        slug, n = base, 2
        while slug in seen:
            slug = f"{base}-{n}"
            n += 1
        seen.add(slug)
        g["slug"] = slug
        out.append(g)
    return out


waveassist.init()

print("GitZoid Security: starting daily credits check and initialization...")

enabled = security_enabled(waveassist.fetch_data("enable_security", default=None))
repositories = waveassist.fetch_data("github_selected_resources", default=[]) or []
groups = _resolve_security_groups(
    _parse_groups(waveassist.fetch_data("security_groups", default=[])), repositories)
num_repos = sum(len(g["repos"]) for g in groups)

if not enabled or not groups:
    reason = "Security Watch is turned off" if not enabled else "no repositories are connected"
    print(f"GitZoid Security: {reason}; skipping this cycle (clean no-op).")
    # Run-based STRING "1"/"0" — NOT a json bool (the SDK wraps that as a truthy {"value":"False"} dict).
    waveassist.store_data("security_skip_run", "1", run_based=True, data_type="string")
    waveassist.store_data("display_output", {
        "html_content": f"<p>GitZoid Security run skipped — {reason}.</p>",
    }, run_based=True, data_type="json")
    waveassist.mark_run_idle()
else:
    success = waveassist.check_credits_and_notify(
        required_credits=CREDITS_NEEDED_FOR_RUN,
        assistant_name="GitZoid Security",
    )
    if not success:
        waveassist.store_data("display_output", {
            "html_content": "<p>Credits were not available, the GitZoid Security run was skipped.</p>",
        }, run_based=True, data_type="json")
        raise Exception("Credits were not available, the GitZoid Security run was skipped.")

    existing_lock = waveassist.fetch_data(RUN_LOCK_KEY, default={}) or {}
    if lock_is_active(existing_lock):
        print("GitZoid Security: previous security run still in progress; skipping this cycle.")
        waveassist.store_data("security_skip_run", "1", run_based=True, data_type="string")
        waveassist.store_data("display_output", {
            "html_content": "<p>GitZoid is already running a security scan. This cycle will be skipped.</p>",
        }, run_based=True, data_type="json")
        waveassist.mark_run_idle()
    else:
        token = str(uuid.uuid4())
        waveassist.store_data(RUN_LOCK_KEY,
                              {"at": datetime.now(timezone.utc).isoformat(), "token": token},
                              data_type="json")
        # run-based so downstream security nodes in THIS run know they hold the lock (and may release it).
        waveassist.store_data("security_run_lock_token", token, run_based=True, data_type="string")
        waveassist.store_data("security_skip_run", "0", run_based=True, data_type="string")
        # The resolved working set every downstream node fans out over.
        waveassist.store_data("security_resolved_groups", groups, run_based=True, data_type="json")
        # Upfront so the dashboard progress bar shows from second 0, through a possible deep audit.
        waveassist.store_data("tentative_time_to_process",
                              str(estimate_time_to_process(num_repos)),
                              run_based=True, data_type="string")
        group_names = [g["name"] or "(all)" for g in groups]
        print(f"GitZoid Security: credits OK, lock acquired. Scanning {num_repos} repo(s) across "
              f"{len(groups)} group(s): {', '.join(group_names)}; est ~{estimate_time_to_process(num_repos)}s.")
