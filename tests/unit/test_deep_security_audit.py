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
    is_code_file,
    path_security_score,
    gather_candidates,
    pack_to_budget,
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


class TestCodeFileFilter:
    def test_keeps_code_drops_noise(self):
        assert is_code_file("src/auth/login.py") is True
        assert is_code_file("src/api/routes.ts") is True
        assert is_code_file("tests/test_auth.py") is False        # test
        assert is_code_file("node_modules/x/route.js") is False   # vendored
        assert is_code_file("db/migrations/0001_init.py") is False
        assert is_code_file("README.md") is False                 # not code
        assert is_code_file("bundle.min.js") is False             # generated


class TestPathSecurityScore:
    def test_security_paths_score_positive(self):
        assert path_security_score("src/auth/login.py") > 0
        assert path_security_score("src/services/access_service.py") > 0   # 'access'
        assert path_security_score("src/payments/billing.py") > 0
        assert path_security_score("src/utils/format.py") == 0

    def test_strong_keywords_outscore_weak(self):
        assert path_security_score("src/permissions.py") > path_security_score("src/config.py")


class TestGatherCandidates:
    BRAIN = {
        "key_files": [{"path": "src/auth/login.py"}, {"path": "src/services/access_service.py"}],
        "security": {"routes": [], "secret_locations": [".env", "config/settings.py"]},
    }
    TREE = ["src/auth/login.py", "src/middleware/permissions.py", "src/services/access_service.py",
            "src/utils/format.py", "tests/test_auth.py", "src/api/routes.py", "README.md",
            "src/payments/billing.py", "config/settings.py"]

    def test_includes_security_surface_excludes_noise(self):
        paths = [c["path"] for c in gather_candidates(self.TREE, self.BRAIN, [], [])]
        assert "src/auth/login.py" in paths
        assert "src/services/access_service.py" in paths        # the flakily-missed file — now deterministic
        assert "src/middleware/permissions.py" in paths
        assert "config/settings.py" in paths                    # secret location
        assert "tests/test_auth.py" not in paths
        assert "README.md" not in paths
        assert "src/utils/format.py" not in paths               # no security signal, not key/queued/changed

    def test_changed_files_rank_higher(self):
        ranked = gather_candidates(self.TREE, self.BRAIN, changed_files=["src/api/routes.py"], queue_files=[])
        paths = [c["path"] for c in ranked]
        assert paths.index("src/api/routes.py") < paths.index("src/payments/billing.py")

    def test_changed_nonsecurity_not_pulled_in(self):
        # "Extract relevant from changes": a changed file with no security signal stays out.
        ranked = gather_candidates(self.TREE + ["src/utils/strings.py"], self.BRAIN,
                                   changed_files=["src/utils/strings.py"], queue_files=[])
        assert "src/utils/strings.py" not in [c["path"] for c in ranked]

    def test_queued_file_qualifies_even_without_security_path(self):
        ranked = gather_candidates([], self.BRAIN, changed_files=[], queue_files=["weird/zzz.py"])
        assert "weird/zzz.py" in [c["path"] for c in ranked]     # tripwire forces inclusion

    def test_ranked_descending(self):
        ranked = gather_candidates(self.TREE, self.BRAIN, [], [])
        scores = [c["score"] for c in ranked]
        assert scores == sorted(scores, reverse=True)


class TestPackToBudget:
    def test_respects_token_budget_with_per_file_cap(self):
        ranked = [{"path": f"f{i}.py", "score": 100 - i} for i in range(10)]
        sizes = {f"f{i}.py": 40000 for i in range(10)}          # 40k chars each, capped to 20k
        sel, dropped = pack_to_budget(ranked, sizes, token_budget=20000,
                                      per_file_cap=20000, max_files=80, chars_per_token=4)
        assert sel == ["f0.py", "f1.py", "f2.py", "f3.py"]      # 5k tokens each → 4 fit in 20k
        assert dropped == 6

    def test_respects_max_files(self):
        ranked = [{"path": f"f{i}.py", "score": 1} for i in range(100)]
        sizes = {f"f{i}.py": 100 for i in range(100)}
        sel, dropped = pack_to_budget(ranked, sizes, token_budget=10_000_000,
                                      per_file_cap=20000, max_files=80)
        assert len(sel) == 80
        assert dropped == 20

    def test_keeps_packing_smaller_after_a_skip(self):
        ranked = [{"path": "big.py", "score": 100}, {"path": "small.py", "score": 50}]
        sizes = {"big.py": 1_000_000, "small.py": 400}
        sel, dropped = pack_to_budget(ranked, sizes, token_budget=1000,
                                      per_file_cap=1_000_000, max_files=80, chars_per_token=4)
        assert sel == ["small.py"]                              # big skipped (over budget), small still fits
        assert dropped == 1


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
        fetch_map = {"security_skip_run": "1", "github_selected_resources": [{"id": "o/r"}],
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
