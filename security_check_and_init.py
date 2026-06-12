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
import uuid
from datetime import datetime, timezone
import waveassist

# A daily security run may include a weekly deep audit of several repos, so this matches the
# Review/GitDigest gate (0.3), not a tiny per-scan figure.
CREDITS_NEEDED_FOR_RUN = 0.3

# Single-run lock for the security chain. Held from here until triage_and_alert releases it. The TTL
# is a crash safety net generous enough for the slowest legit run (a weekly deep audit of every repo).
RUN_LOCK_KEY = "security_run_lock"
LOCK_TTL_SECONDS = 2700   # 45 min


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


waveassist.init()

print("GitZoid Security: starting daily credits check and initialization...")

enabled = security_enabled(waveassist.fetch_data("enable_security", default=None))
repositories = waveassist.fetch_data("github_selected_resources", default=[]) or []
num_repos = len(repositories) if isinstance(repositories, list) else 0

if not enabled or num_repos == 0:
    reason = "Security Watch is turned off" if not enabled else "no repositories are connected"
    print(f"GitZoid Security: {reason}; skipping this cycle (clean no-op).")
    # Run-based STRING "1"/"0" — NOT a json bool (the SDK wraps that as a truthy {"value":"False"} dict).
    waveassist.store_data("security_skip_run", "1", run_based=True, data_type="string")
    waveassist.store_data("display_output", {
        "html_content": f"<p>GitZoid Security run skipped — {reason}.</p>",
    }, run_based=True, data_type="json")
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
    else:
        token = str(uuid.uuid4())
        waveassist.store_data(RUN_LOCK_KEY,
                              {"at": datetime.now(timezone.utc).isoformat(), "token": token},
                              data_type="json")
        # run-based so downstream security nodes in THIS run know they hold the lock (and may release it).
        waveassist.store_data("security_run_lock_token", token, run_based=True, data_type="string")
        waveassist.store_data("security_skip_run", "0", run_based=True, data_type="string")
        print(f"GitZoid Security: credits OK, lock acquired. Scanning {num_repos} repo(s).")
