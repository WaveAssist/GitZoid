"""
Unit tests for security_check_and_init.py — the Security chain's daily starting node.
"""
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from security_check_and_init import lock_is_active, security_enabled, LOCK_TTL_SECONDS


class TestLockActive:
    def test_empty_lock_inactive(self):
        assert lock_is_active({}) is False
        assert lock_is_active(None) is False

    def test_fresh_lock_active(self):
        lock = {"at": datetime.now(timezone.utc).isoformat(), "token": "t"}
        assert lock_is_active(lock) is True

    def test_stale_lock_inactive(self):
        old = (datetime.now(timezone.utc) - timedelta(seconds=LOCK_TTL_SECONDS + 60)).isoformat()
        assert lock_is_active({"at": old, "token": "t"}) is False

    def test_malformed_timestamp_inactive(self):
        assert lock_is_active({"at": "not-a-date"}) is False


class TestDriverNoOp:
    """Driver-level: a disabled/empty cycle is a clean no-op (sets skip flag, never raises)."""

    def test_disabled_sets_skip_and_does_not_check_credits(self, monkeypatch):
        import runpy, waveassist
        fetch_map = {"enable_security": "false", "github_selected_resources": [{"id": "o/r"}]}
        stored = {}
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        monkeypatch.setattr(waveassist, "check_credits_and_notify",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no credit check when disabled")))
        runpy.run_path("security_check_and_init.py", run_name="__main__")
        assert stored.get("security_skip_run") == "1"
        assert "security_run_lock" not in stored      # never took the lock

    def test_active_lock_skips_cycle(self, monkeypatch):
        import runpy, waveassist
        fresh_lock = {"at": datetime.now(timezone.utc).isoformat(), "token": "other"}
        fetch_map = {"enable_security": "true", "github_selected_resources": [{"id": "o/r"}],
                     "security_run_lock": fresh_lock}
        stored = {}
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        monkeypatch.setattr(waveassist, "check_credits_and_notify", lambda *a, **k: True)
        runpy.run_path("security_check_and_init.py", run_name="__main__")
        assert stored.get("security_skip_run") == "1"
        assert "security_run_lock_token" not in stored   # did not overwrite the held lock


class TestSecurityEnabled:
    def test_default_on_when_unset(self):
        # Existing users get Security ON by default.
        assert security_enabled(None) is True
        assert security_enabled("") is True

    def test_explicit_false_strings(self):
        assert security_enabled("false") is False
        assert security_enabled("False") is False
        assert security_enabled("no") is False
        assert security_enabled("off") is False
        assert security_enabled("0") is False

    def test_explicit_true(self):
        assert security_enabled("true") is True
        assert security_enabled(True) is True

    def test_bool_false(self):
        assert security_enabled(False) is False
