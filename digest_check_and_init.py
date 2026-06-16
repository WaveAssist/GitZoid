"""
digest_check_and_init.py — the Knowledge Digest chain's weekly starting node.

Mirrors security_check_and_init (the Security chain's gate) but on a weekly clock and its OWN overlap
lock, so the multi-repo activity analysis never blocks PR reviews or the daily security scan. It:
  1. waveassist.init()
  2. skips the whole chain cleanly if Digest is toggled off (enable_digest) or no repos are connected
  3. resolves the per-group working set (with an implicit single-group fallback) ONCE, up front, so
     every downstream node fans out over the same `digest_resolved_groups`
  4. check_credits_and_notify(...) — stop the run if the account is out of credits
  5. acquires `digest_run_lock` so overlapping weekly ticks don't double-send
  6. stores `tentative_time_to_process` UPFRONT so the dashboard progress bar shows from second 0,
     through the (slow) per-repo diff analysis in analyze_activity

Why `enable_digest` defaults to OFF when unset (the OPPOSITE of enable_security): the digest is a
recurring weekly EMAIL, not a silent watch. The config default_value is "true", so a NEW user's setup
wizard stores "true" and the digest is ON for them. EXISTING users never stored the key, so an unset
value reads as OFF here and they get no surprise email until they turn it on in one click. No backfill
needed — the unset-vs-stored distinction does the work.

Why resolve groups here and not downstream: the implicit single-group fallback (no configured groups →
one digest over all selected repos) is a single decision that the whole chain must agree on. Computing
it once in the gate and publishing `digest_resolved_groups` (run-based) keeps fetch/analyze/report/send
fanning out over an identical working set.

Why the brain is never a dependency: the digest READS profile:{repo} if present (see analyze_activity)
but cannot run_after study_repos — that would merge the digest and review subgraphs into one connected
graph with two starting nodes and fail deploy validation.

Flat script, no __main__ guard. On no-credits it stores a display_output and raises (the run is marked
failed — the intended "skipped, buy credits" signal). It does NOT raise on digest-disabled, missing
repos, or a lock-skip: those are clean weekly no-ops, not failed runs.
"""
import re
import json
import uuid
from datetime import datetime, timezone
import waveassist

# A weekly digest run analyzes a week of diffs across several repos plus two report syntheses, so this
# matches the Review / Security / GitDigest gate (0.3), not a tiny per-call figure.
CREDITS_NEEDED_FOR_RUN = 0.3

# Single-run lock for the digest chain. Held from here until send_digest releases it. The TTL is a crash
# safety net generous enough for the slowest legit run (a full week of diffs across every repo + PDF).
RUN_LOCK_KEY = "digest_run_lock"
LOCK_TTL_SECONDS = 3600   # 60 min

# Upfront progress-bar budget (seconds). The per-repo activity analysis (0-7+ LLM calls over a week of
# diffs) dominates a digest run; the two report syntheses + email/PDF are a small fixed tail. Budget per
# repo so the dashboard bar shows from second 0. Over-estimating is safe: the frontend caps the bar at 80%.
DIGEST_SECONDS_PER_REPO = 150  # budget for a week of diff analysis per repo (fetch + tiered LLM);
                               # measured ~130-220s/repo end-to-end, so a slight over-estimate is right
DIGEST_BASE_SECONDS = 30       # business + technical report synthesis + render/send


def lock_is_active(lock, now=None) -> bool:
    """A digest run is in progress iff a lock exists, has a timestamp, and is younger than the TTL."""
    if not isinstance(lock, dict) or not lock.get("at"):
        return False
    now = now or datetime.now(timezone.utc)
    try:
        age = (now - datetime.fromisoformat(lock["at"])).total_seconds()
    except Exception:
        return False
    return age < LOCK_TTL_SECONDS


def digest_enabled(value) -> bool:
    """Parse the optional `enable_digest` toggle. Default OFF (unset/empty) — EXISTING users who never
    stored it get no surprise weekly email. Only an explicit truthy value turns it on; a NEW user's setup
    wizard stores the config default "true". This is the OPPOSITE of security_enabled by design."""
    if value is None or value == "":
        return False
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "yes", "on", "1")


def estimate_time_to_process(num_repos: int) -> int:
    """Upfront seconds estimate for the whole digest chain, dominated by per-repo diff analysis.
    Over-estimating is safe: the frontend caps the bar at 80%."""
    if not isinstance(num_repos, int) or num_repos < 0:
        num_repos = 0
    return num_repos * DIGEST_SECONDS_PER_REPO + DIGEST_BASE_SECONDS


def parse_groups(raw):
    """The digest_groups input is stored by the dashboard as a JSON string (data_type "list"); fetch may
    return it already-parsed or as a string. Normalize to a list; anything malformed → []."""
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
    """Stable kebab-case identity for a group's per-group state. Empty name → group-{1-based index}."""
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s or f"group-{index + 1}"


def _selected_ids(repositories):
    out = []
    for r in (repositories or []):
        rid = r.get("id") if isinstance(r, dict) else r
        if rid:
            out.append(rid)
    return out


def resolve_groups(digest_groups, repositories):
    """Normalize the digest_groups input into this run's working set. Each configured group's repos are
    intersected with the globally-selected set (a repo deselected globally drops out silently); groups
    left with no selected repo are dropped. If no non-empty group survives, fall back to ONE implicit
    group over ALL selected repos (recipients empty → owner only). Slugs are unique and stable.
    Returns [{name, repos, recipients, slug}]."""
    selected = _selected_ids(repositories)
    selected_set = set(selected)

    groups = []
    for g in (digest_groups or []):
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
        # Implicit single-group fallback: unnamed + flagged so render leads with the brand title, not a
        # bare "All repositories" label. Empty name slugifies to a stable "group-1".
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


waveassist.init()

print("GitZoid Digest: starting weekly credits check and initialization...")

enabled = digest_enabled(waveassist.fetch_data("enable_digest", default=None))
repositories = waveassist.fetch_data("github_selected_resources", default=[]) or []
groups = resolve_groups(parse_groups(waveassist.fetch_data("digest_groups", default=[])), repositories)
num_repos = sum(len(g["repos"]) for g in groups)

if not enabled or not groups:
    reason = "Knowledge Digest is turned off" if not enabled else "no repositories are connected"
    print(f"GitZoid Digest: {reason}; skipping this cycle (clean no-op).")
    # Run-based STRING "1"/"0" — NOT a json bool (the SDK wraps that as a truthy {"value":"False"} dict).
    waveassist.store_data("digest_skip_run", "1", run_based=True, data_type="string")
    waveassist.store_data("display_output", {
        "html_content": f"<p>GitZoid Digest run skipped — {reason}.</p>",
    }, run_based=True, data_type="json")
else:
    success = waveassist.check_credits_and_notify(
        required_credits=CREDITS_NEEDED_FOR_RUN,
        assistant_name="GitZoid Digest",
    )
    if not success:
        waveassist.store_data("display_output", {
            "html_content": "<p>Credits were not available, the GitZoid Digest run was skipped.</p>",
        }, run_based=True, data_type="json")
        raise Exception("Credits were not available, the GitZoid Digest run was skipped.")

    existing_lock = waveassist.fetch_data(RUN_LOCK_KEY, default={}) or {}
    if lock_is_active(existing_lock):
        print("GitZoid Digest: previous digest run still in progress; skipping this cycle.")
        waveassist.store_data("digest_skip_run", "1", run_based=True, data_type="string")
        waveassist.store_data("display_output", {
            "html_content": "<p>GitZoid is already preparing a digest. This cycle will be skipped.</p>",
        }, run_based=True, data_type="json")
    else:
        token = str(uuid.uuid4())
        waveassist.store_data(RUN_LOCK_KEY,
                              {"at": datetime.now(timezone.utc).isoformat(), "token": token},
                              data_type="json")
        # run-based so downstream digest nodes in THIS run know they hold the lock (and may release it).
        waveassist.store_data("digest_run_lock_token", token, run_based=True, data_type="string")
        waveassist.store_data("digest_skip_run", "0", run_based=True, data_type="string")
        # The resolved working set every downstream node fans out over (implicit fallback already applied).
        waveassist.store_data("digest_resolved_groups", groups, run_based=True, data_type="json")
        # Upfront so the dashboard progress bar shows from second 0, through the slow per-repo analysis.
        waveassist.store_data("tentative_time_to_process",
                              str(estimate_time_to_process(num_repos)),
                              run_based=True, data_type="string")
        print(f"GitZoid Digest: credits OK, lock acquired. {len(groups)} group(s), {num_repos} repo(s); "
              f"est ~{estimate_time_to_process(num_repos)}s.")
