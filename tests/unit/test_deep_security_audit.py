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
    _route_dedup_key,
    AuditResult,
    AuthzFinding,
)


class TestRouteDedupKey:
    """The authz dedup key must be STABLE when the model rewords the entry point — in particular it
    must ignore the controller file path that the model sometimes appends and sometimes omits."""

    def test_stable_across_file_suffix(self):
        with_file = "POST /acl/list_records (and POST /acl/model_check) in Admin/Controllers/admin_access_controller.py"
        no_file = "POST /acl/list_records (and POST /acl/model_check)."
        assert _route_dedup_key(with_file) == _route_dedup_key(no_file)
        assert _route_dedup_key(with_file) == "/acl/list_records,/acl/model_check"

    def test_order_independent(self):
        a = _route_dedup_key("POST /acl/model_check, POST /acl/list_records")
        b = _route_dedup_key("POST /acl/list_records, POST /acl/model_check")
        assert a == b

    def test_differs_by_route(self):
        assert _route_dedup_key("/acl/list_records") != _route_dedup_key("/admin/coupons/create")


class TestNeedsAudit:
    NOW = datetime(2026, 6, 17, 8, 0, tzinfo=timezone.utc)   # a Wednesday (weekday 2)

    def test_first_run_always_audits(self):
        assert needs_audit({}) is True
        assert needs_audit(None) is True

    def test_already_audited_today_skips(self):
        entry = {"last_audit_at": self.NOW.isoformat()}
        assert needs_audit(entry, now=self.NOW, audit_weekday=self.NOW.weekday()) is False

    def test_runs_on_configured_weekday(self):
        entry = {"last_audit_at": (self.NOW - timedelta(days=3)).isoformat()}
        assert needs_audit(entry, now=self.NOW, audit_weekday=self.NOW.weekday()) is True

    def test_skips_on_off_weekday_within_window(self):
        entry = {"last_audit_at": (self.NOW - timedelta(days=2)).isoformat()}
        other = (self.NOW.weekday() + 1) % 7
        assert needs_audit(entry, now=self.NOW, audit_weekday=other) is False

    def test_safety_net_runs_after_long_gap(self):
        entry = {"last_audit_at": (self.NOW - timedelta(days=9)).isoformat()}
        other = (self.NOW.weekday() + 1) % 7
        assert needs_audit(entry, now=self.NOW, audit_weekday=other) is True

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


# ---------------------------------------------------------------- fewer, proper alerts

import deep_security_audit as dsa

AUTH_PY = '''def get_user(request, user_id):
    if not request.user.is_authenticated:
        raise PermissionDenied()
    return User.objects.get(id=user_id)   # no ownership check
'''


def _authz_finding(entry="GET /users/<id>", handler="api/auth.py"):
    return {"category": "authz", "repo": "o/r", "entry_point": entry, "handler_file": handler, "path": "",
            "title": f"Bypassable check: {entry}", "impact": "reads any user's profile",
            "exploit_path": "call it with another id", "confidence": "high", "severity": "high"}


class TestQuoteInFiles:
    def test_whitespace_insensitive_exact_quote(self):
        assert dsa.quote_in_files("return  User.objects.get(id=user_id)", {"a.py": AUTH_PY})

    def test_edited_or_invented_quote_rejected(self):
        assert not dsa.quote_in_files("if request.user.id != user_id: raise", {"a.py": AUTH_PY})

    def test_too_short_quote_rejected(self):
        assert not dsa.quote_in_files("raise", {"a.py": AUTH_PY})


class TestPriorOpenFindings:
    LEDGER = {
        "a1": {"repo": "o/r", "status": "open", "category": "authz", "entry_point": "GET /x", "first_seen": "2"},
        "s1": {"repo": "o/r", "status": "open", "category": "secret", "path": "cfg/a.ts, cfg/b.ts", "first_seen": "1"},
        "s2": {"repo": "o/r", "status": "open", "category": "secret", "path": "other.ts", "first_seen": "1"},
        "r1": {"repo": "o/r", "status": "resolved", "category": "authz", "entry_point": "GET /y"},
        "o1": {"repo": "o/other", "status": "open", "category": "authz", "entry_point": "GET /z"},
        "d1": {"repo": "o/r", "status": "open", "category": "dependency", "name": "x"},
    }

    def test_lists_open_authz_and_secrets_in_audited_files_only(self):
        out = dsa.prior_open_findings(self.LEDGER, "o/r", {"cfg/b.ts": "x"})
        assert [p["id"] for p in out] == ["s1", "a1"]      # oldest first; s2's file not audited

    def test_prompt_lists_them_and_the_not_findings(self):
        prior = dsa.prior_open_findings(self.LEDGER, "o/r", {"cfg/b.ts": "x"})
        p = dsa.build_audit_prompt("o/r", {}, {"cfg/b.ts": "x"}, prior)
        assert "<already_reported" in p and 'id="a1"' in p and "<not_findings>" in p
        assert "<already_reported" not in dsa.build_audit_prompt("o/r", {}, {"cfg/b.ts": "x"})


class TestPriorOutcomes:
    PRIOR = [{"id": "a1"}, {"id": "a2"}, {"id": "a3"}]

    def test_fixed_needs_a_real_quote(self):
        statuses = [{"id": "a1", "status": "fixed", "evidence": "raise PermissionDenied()"},
                    {"id": "a2", "status": "fixed", "evidence": "if user.owns(obj): return obj  # invented"},
                    {"id": "a3", "status": "still_present"},
                    {"id": "zz", "status": "fixed", "evidence": "raise PermissionDenied()"}]
        fixed, present = dsa.prior_outcomes(statuses, self.PRIOR, {"api/auth.py": AUTH_PY})
        assert [r["sig"] for r in fixed] == ["a1"]
        assert present == ["a3"]


class TestVerifyFindings:
    def _llm(self, monkeypatch, verdicts=None, raise_exc=False):
        def call_llm(**k):
            if raise_exc:
                raise RuntimeError("provider down")
            return dsa.VerifyResult.model_validate({"verdicts": verdicts})
        monkeypatch.setattr(dsa.waveassist, "call_llm", call_llm)

    def test_keeps_only_confirmed_with_real_evidence(self, monkeypatch):
        self._llm(monkeypatch, [
            {"index": 0, "verdict": "confirmed", "evidence": "return User.objects.get(id=user_id)"},
            {"index": 1, "verdict": "confirmed", "evidence": "something not in the code at all"},
            {"index": 2, "verdict": "refuted", "reason": "public docs route"}])
        fs = [_authz_finding(), _authz_finding("GET /a"), _authz_finding("GET /docs")]
        kept, ok = dsa.verify_findings("m", "o/r", fs, {"api/auth.py": AUTH_PY})
        assert ok and [f["entry_point"] for f in kept] == ["GET /users/<id>"]

    def test_failed_call_sends_nothing(self, monkeypatch):
        self._llm(monkeypatch, raise_exc=True)
        assert dsa.verify_findings("m", "o/r", [_authz_finding()], {"api/auth.py": AUTH_PY}) == ([], False)

    def test_no_findings_needs_no_call(self, monkeypatch):
        self._llm(monkeypatch, raise_exc=True)
        assert dsa.verify_findings("m", "o/r", [], {"api/auth.py": AUTH_PY}) == ([], True)


class TestRunAuditFailure:
    def test_failed_model_call_is_not_an_audit(self, monkeypatch):
        monkeypatch.setattr(dsa.waveassist, "call_llm", lambda **k: (_ for _ in ()).throw(RuntimeError("x")))
        assert dsa.run_audit("m", "o/r", {}, {"a.py": "x"}) == ([], [], False)


class TestAuditDriver:
    """End to end over a fake GitHub: a failed model call must not count as an audit, and only a
    verified finding reaches triage."""

    def _run(self, monkeypatch, audit=None, verify=None, fail=False):
        import base64, runpy, requests, waveassist
        fetch_map = {"security_skip_run": "0", "github_access_token": "t",
                     "security_resolved_groups": [{"slug": "g", "repos": ["o/r"]}],
                     "security_audit_state": {}, "security_audit_queue": [], "security_findings": {}}
        stored = {}

        class R:
            def __init__(self, data, code=200):
                self.status_code, self._d = code, data

            def json(self):
                return self._d

        def get(url, *a, **k):
            if "/git/trees/" in url:
                return R({"tree": [{"type": "blob", "path": "api/auth.py", "size": 200}]})
            if "/contents/" in url:
                return R({"encoding": "base64", "content": base64.b64encode(AUTH_PY.encode()).decode()})
            if "/commits/" in url:
                return R({"sha": "abc"})
            return R({}, 404)

        def call_llm(**k):
            if fail:
                raise RuntimeError("provider down")
            return audit if k["response_model"].__name__ == "AuditResult" else verify

        monkeypatch.setattr(requests, "get", get)
        monkeypatch.setattr(waveassist, "fetch_data", lambda key=None, default=None, **k: fetch_map.get(key, default))
        monkeypatch.setattr(waveassist, "store_data", lambda key, value, **k: stored.__setitem__(key, value))
        monkeypatch.setattr(waveassist, "call_llm", call_llm)
        runpy.run_path("deep_security_audit.py", run_name="__main__")
        return stored

    def test_failed_audit_is_retried_not_recorded(self, monkeypatch):
        stored = self._run(monkeypatch, fail=True)
        assert "o/r" not in stored["security_audit_state"]
        assert stored["security_candidates"] == [] and stored["security_scanned_ok_code"] == []

    def test_only_verified_findings_reach_triage(self, monkeypatch):
        audit = dsa.AuditResult.model_validate({"authz_findings": [
            {"entry_point": "GET /users/<id>", "handler_file": "api/auth.py", "missing_check": "ownership",
             "exploit_path": "call with another id", "named_victim": "any user", "reproduction": "GET /users/2",
             "fix": "check owner", "impact": "reads any user's profile", "confidence": "high"},
            {"entry_point": "GET /docs", "handler_file": "api/auth.py", "missing_check": "auth",
             "exploit_path": "open it", "named_victim": "anyone", "reproduction": "GET /docs",
             "fix": "add auth", "impact": "sees API docs", "confidence": "high"}]})
        verify = dsa.VerifyResult.model_validate({"verdicts": [
            {"index": 0, "verdict": "confirmed", "evidence": "return User.objects.get(id=user_id)"},
            {"index": 1, "verdict": "refuted", "reason": "public docs"}]})
        stored = self._run(monkeypatch, audit=audit, verify=verify)
        assert [c["entry_point"] for c in stored["security_candidates"]] == ["GET /users/<id>"]
        assert "o/r" in stored["security_audit_state"]
