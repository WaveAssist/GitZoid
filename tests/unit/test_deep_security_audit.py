"""
Unit tests for deep_security_audit.py — the weekly, brain-scoped deep code audit.

Covers: the per-repo weekly throttle, audit-scope file selection from the brain + tripwire queue,
the strict gate (named victim + exploit path + fix, or silence), and the structured models.
"""
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from deep_security_audit import (
    needs_audit,
    select_audit_files,
    audit_gate,
    AuditResult,
    AuthzFinding,
)


class TestNeedsAudit:
    def test_missing_state_needs_audit(self):
        assert needs_audit({}) is True
        assert needs_audit(None) is True

    def test_recent_audit_skips(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        assert needs_audit({"last_audit_at": recent}) is False

    def test_old_audit_runs(self):
        old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        assert needs_audit({"last_audit_at": old}) is True

    def test_malformed_timestamp_runs(self):
        assert needs_audit({"last_audit_at": "garbage"}) is True


class TestSelectAuditFiles:
    def test_auth_keyfiles_secrets_and_queue(self):
        brain = {
            "key_files": [
                {"path": "src/auth/login.py", "role": "handles login"},
                {"path": "src/utils/format.py", "role": "string helpers"},
                {"path": "src/middleware.py", "role": "request middleware"},
            ],
            "security": {"routes": [], "secret_locations": [".env", "config/settings.py"]},
        }
        files = select_audit_files(brain, ["src/reset_password.py"])
        assert "src/auth/login.py" in files          # auth-ish key file
        assert "src/middleware.py" in files           # middleware is security-relevant
        assert "src/reset_password.py" in files       # from the PR tripwire queue
        assert ".env" in files                        # secret location
        assert "src/utils/format.py" not in files     # not security-relevant

    def test_dedupes_and_caps(self):
        brain = {"key_files": [{"path": "auth.py", "role": "auth"}],
                 "security": {"secret_locations": []}}
        files = select_audit_files(brain, ["auth.py", "auth.py"], cap=5)
        assert files.count("auth.py") == 1

    def test_empty_brain_uses_queue_only(self):
        assert select_audit_files({}, ["x/auth.py"]) == ["x/auth.py"]


class TestAuditGate:
    def _authz(self, **kw):
        base = {"category": "authz", "entry_point": "POST /reset-password",
                "exploit_path": "skip OTP step", "named_victim": "any user account",
                "fix": "re-check OTP", "confidence": "high"}
        base.update(kw)
        return base

    def test_complete_authz_passes(self):
        assert audit_gate(self._authz()) is True

    def test_low_confidence_dropped(self):
        assert audit_gate(self._authz(confidence="medium")) is False

    def test_missing_victim_dropped(self):
        assert audit_gate(self._authz(named_victim="")) is False

    def test_missing_exploit_path_dropped(self):
        assert audit_gate(self._authz(exploit_path="")) is False

    def test_missing_fix_dropped(self):
        assert audit_gate(self._authz(fix="")) is False

    def test_secret_requires_path_and_reason(self):
        good = {"category": "secret", "path": "config.py",
                "why_not_placeholder": "looks like a live AWS key", "confidence": "high"}
        assert audit_gate(good) is True
        assert audit_gate({**good, "why_not_placeholder": ""}) is False
        assert audit_gate({**good, "confidence": "low"}) is False

    def test_backdoor_requires_signals(self):
        good = {"category": "backdoor", "behavioral_signals": ["exfiltrates env on import"],
                "confidence": "high"}
        assert audit_gate(good) is True
        assert audit_gate({**good, "behavioral_signals": []}) is False

    def test_unknown_category_dropped(self):
        assert audit_gate({"category": "style", "confidence": "high"}) is False


class TestDriverNoOp:
    def test_skip_run_makes_no_network_calls(self, monkeypatch):
        import runpy, waveassist, requests
        fetch_map = {"security_skip_run": True, "github_selected_resources": [{"id": "o/r"}],
                     "github_access_token": "t"}
        stored = {}
        monkeypatch.setattr(waveassist, "fetch_data",
                            lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data",
                            lambda key, value, **k: stored.__setitem__(key, value))
        monkeypatch.setattr(requests, "get",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network on skip")))
        runpy.run_path("deep_security_audit.py", run_name="__main__")
        assert "security_audit_state" not in stored     # never wrote audit state on a skipped cycle


class TestModels:
    def test_audit_result_validates(self):
        r = AuditResult.model_validate({
            "authz_findings": [{
                "entry_point": "POST /reset-password",
                "missing_check": "OTP re-verification",
                "exploit_path": "call reset directly after requesting OTP",
                "named_victim": "any account whose email is known",
                "reproduction": "POST /reset-password with target email",
                "fix": "require OTP token on reset",
                "impact": "account takeover without the OTP",
                "confidence": "high",
            }],
            "secret_findings": [],
            "backdoor_findings": [],
        })
        assert r.authz_findings[0].confidence == "high"
        assert r.secret_findings == []

    def test_authz_finding_defaults(self):
        f = AuthzFinding.model_validate({
            "entry_point": "x", "missing_check": "y", "exploit_path": "z",
            "named_victim": "v", "reproduction": "r", "fix": "f",
            "impact": "i", "confidence": "high"})
        assert f.entry_point == "x"
