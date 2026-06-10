"""
Unit tests for check_credits_and_init.py (GitZoid's single starting gate node).
"""
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from check_credits_and_init import (
    estimate_time_to_process,
    CREDITS_NEEDED_FOR_RUN,
    BRAIN_SECONDS_PER_REPO,
    PR_REVIEW_BASE_SECONDS,
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
