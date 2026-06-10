"""
check_credits_and_init.py — GitZoid's single starting node (house pattern, matches
GitDigest / WaveContent / WavePredict).

It runs FIRST in the one DAG, before any expensive work, and does four things:
  1. waveassist.init() (no check flag — credits are gated here, once).
  2. check_credits_and_notify(...) — stop the run cleanly if the account is out of credits.
  3. acquire a single-run LOCK so overlapping runs don't double-build the brain / double-review.
  4. store `tentative_time_to_process` UPFRONT so the dashboard progress bar shows from
     second 0 — through the (occasionally slow) brain build in study_repos, which runs next.

Why the lock: GitZoid runs every ~2 min, but the first run loops over every connected repo
building a brain each (can take many minutes), and the platform's celery beat fires the next run
regardless of whether the previous one finished (run_dag is fire-and-forget). Without a lock,
concurrent runs all see "no profile yet" and rebuild it, and race on reviewed_prs / post
duplicate comments. So: the entry node acquires `run_lock`; if a fresh lock already exists, this
cycle skips (sets run-based `skip_run`, downstream nodes no-op); post_comment releases the lock
when the run finishes. The lock is stale-aware (LOCK_TTL_SECONDS) so a crashed run can't wedge
GitZoid forever.

Why the gate lives here and not in study_repos / fetch_pull_requests: the brain build uses a
strong model and is the most expensive step, so the credit check must happen *before* it. The
PR-count estimate is refined later by fetch_pull_requests once the real open-PR count is known.

Flat script, no __main__ guard. On no-credits it stores a display_output and raises (the run is
marked failed, which is the intended "skipped, buy credits" signal — same as every sibling). It
does NOT raise on missing repos/token or on a lock-skip: GitZoid runs every couple of minutes and
an unconfigured/overlapping cycle should be a clean no-op downstream, not a stream of failed runs.
"""
import uuid
from datetime import datetime, timezone
import waveassist

# Credits required to start a run. Default model is Sonnet, and a run may include a weekly brain
# rebuild + a couple of reviews, so this matches GitDigest (0.3), not the old 0.1 PR-only gate.
CREDITS_NEEDED_FOR_RUN = 0.3

# Single-run lock. A run holds the lock from this node until post_comment releases it. The TTL is a
# crash safety net: generous enough for the slowest legit run (first full brain build of all repos
# + reviews), so it never serializes normal fast cycles, but frees a wedged lock automatically.
RUN_LOCK_KEY = "run_lock"
LOCK_TTL_SECONDS = 1800   # 30 min


def lock_is_active(lock, now=None) -> bool:
    """A run is in progress iff a lock exists, has a timestamp, and is younger than the TTL."""
    if not isinstance(lock, dict) or not lock.get("at"):
        return False
    now = now or datetime.now(timezone.utc)
    try:
        age = (now - datetime.fromisoformat(lock["at"])).total_seconds()
    except Exception:
        return False
    return age < LOCK_TTL_SECONDS

# Upfront progress-bar budget (seconds). The brain rebuild is the slow, rare part; reviews are
# refined later by fetch_pull_requests from the real PR count.
BRAIN_SECONDS_PER_REPO = 45   # budget for a possible weekly brain rebuild, per repo
PR_REVIEW_BASE_SECONDS = 10   # small base for the review pipeline (fetch_pull_requests refines it)


def estimate_time_to_process(num_repos: int) -> int:
    """Upfront seconds estimate for the whole DAG, covering a possible brain rebuild + reviews.
    Over-estimating is safe: the frontend caps the bar at 80% and fetch_pull_requests refines it."""
    if not isinstance(num_repos, int) or num_repos < 0:
        num_repos = 0
    return num_repos * BRAIN_SECONDS_PER_REPO + PR_REVIEW_BASE_SECONDS


waveassist.init()

print("GitZoid: Starting credits check and initialization...")

repositories = waveassist.fetch_data("github_selected_resources", default=[]) or []
num_repos = len(repositories) if isinstance(repositories, list) else 0
time_to_process = estimate_time_to_process(num_repos)

success = waveassist.check_credits_and_notify(
    required_credits=CREDITS_NEEDED_FOR_RUN,
    assistant_name="GitZoid",
)

if not success:
    display_output = {
        "html_content": "<p>Credits were not available, the GitZoid run was skipped.</p>",
    }
    waveassist.store_data("display_output", display_output, run_based=True, data_type="json")
    raise Exception("Credits were not available, the GitZoid run was skipped.")

# Single-run lock: skip this cycle if a previous run is still in progress.
existing_lock = waveassist.fetch_data(RUN_LOCK_KEY, default={}) or {}
if lock_is_active(existing_lock):
    print("GitZoid: previous run still in progress; skipping this cycle.")
    waveassist.store_data("skip_run", True, run_based=True, data_type="json")
    display_output = {
        "html_content": "<p>GitZoid is already reviewing your pull requests. This run will be skipped.</p>",
    }
    waveassist.store_data("display_output", display_output, run_based=True, data_type="json")
else:
    token = str(uuid.uuid4())
    waveassist.store_data(
        RUN_LOCK_KEY,
        {"at": datetime.now(timezone.utc).isoformat(), "token": token},
        data_type="json",
    )
    # run-based so downstream nodes in THIS run know they hold the lock (and may release it).
    waveassist.store_data("run_lock_token", token, run_based=True, data_type="string")
    waveassist.store_data("skip_run", False, run_based=True, data_type="json")
    waveassist.store_data(
        "tentative_time_to_process", str(time_to_process), run_based=True, data_type="string"
    )
    print(f"GitZoid: Credits OK, lock acquired. Tracking {num_repos} repo(s); est ~{time_to_process}s.")
    print("GitZoid: Credits check complete and initialization finished.")
