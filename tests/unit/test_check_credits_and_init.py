"""
Unit tests for check_credits_and_init.py (GitZoid's single starting gate node).
"""
import sys
import os
from datetime import datetime, timezone, timedelta

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from check_credits_and_init import (
    estimate_time_to_process,
    lock_is_active,
    CREDITS_NEEDED_FOR_RUN,
    BRAIN_SECONDS_PER_REPO,
    PR_REVIEW_BASE_SECONDS,
    LOCK_TTL_SECONDS,
)


class TestCreditsThreshold:
    def test_sonnet_aware_threshold(self):
        # Raised from the old PR-only 0.1 to cover a Sonnet brain build + reviews (matches GitDigest).
        assert CREDITS_NEEDED_FOR_RUN == 0.3


class TestTimeEstimate:
    def test_zero_repos_is_just_the_review_base(self):
        assert estimate_time_to_process(0) == PR_REVIEW_BASE_SECONDS

    def test_scales_with_repo_count(self):
        assert estimate_time_to_process(3) == 3 * BRAIN_SECONDS_PER_REPO + PR_REVIEW_BASE_SECONDS

    def test_negative_coerced_to_zero(self):
        assert estimate_time_to_process(-5) == PR_REVIEW_BASE_SECONDS

    def test_non_int_coerced_to_zero(self):
        assert estimate_time_to_process(None) == PR_REVIEW_BASE_SECONDS
        assert estimate_time_to_process("2") == PR_REVIEW_BASE_SECONDS

    def test_monotonic(self):
        assert estimate_time_to_process(2) > estimate_time_to_process(1)


class TestRunLock:
    def test_no_lock_is_inactive(self):
        assert lock_is_active({}) is False
        assert lock_is_active(None) is False

    def test_lock_without_timestamp_is_inactive(self):
        assert lock_is_active({"token": "x"}) is False

    def test_fresh_lock_is_active(self):
        # A run that started 2 minutes ago (the schedule interval) must still read as active,
        # so the next cycle skips instead of double-running.
        fresh = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
        assert lock_is_active({"at": fresh, "token": "x"}) is True

    def test_stale_lock_is_inactive(self):
        # Past the TTL (e.g. a crashed run) the lock is ignored so GitZoid self-heals.
        stale = (datetime.now(timezone.utc) - timedelta(seconds=LOCK_TTL_SECONDS + 60)).isoformat()
        assert lock_is_active({"at": stale, "token": "x"}) is False

    def test_just_inside_ttl_is_active(self):
        edge = (datetime.now(timezone.utc) - timedelta(seconds=LOCK_TTL_SECONDS - 30)).isoformat()
        assert lock_is_active({"at": edge, "token": "x"}) is True

    def test_garbage_timestamp_is_inactive(self):
        assert lock_is_active({"at": "not-a-date"}) is False
