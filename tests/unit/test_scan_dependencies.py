"""
Unit tests for scan_dependencies.py — the daily dependency / supply-chain watch.

Covers the deterministic core: manifest/lockfile parsing, OSV query + response parsing,
CISA-KEV "actively exploited" matching, severity normalisation, brain reachability, the
feed gate (what's allowed to reach the model), snapshot diffing.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from scan_dependencies import (
    parse_requirements_txt,
    parse_package_lock,
    parse_package_json,
    parse_toml_lock,
    parse_pipfile_lock,
    parse_manifest,
    ecosystem_for_osv,
    build_osv_batch,
    parse_osv_vuln,
    cve_aliases,
    parse_kev_feed,
    is_actively_exploited,
    normalize_severity,
    dep_reachability,
    passes_feed_gate,
    content_hash,
    changed_dependencies,
)


class TestRequirementsTxt:
    def test_pinned_versions(self):
        out = parse_requirements_txt("requests==2.31.0\nurllib3==2.0.0\n")
        assert ("requests", "2.31.0") in out
        assert ("urllib3", "2.0.0") in out

    def test_skips_comments_blanks_and_flags(self):
        text = "# comment\n\nrequests==2.31.0\n-r other.txt\n--index-url https://x\n"
        out = parse_requirements_txt(text)
        assert out == [("requests", "2.31.0")]

    def test_strips_extras_and_markers(self):
        out = parse_requirements_txt("celery[redis]==5.3.0 ; python_version>='3.8'\n")
        assert out == [("celery", "5.3.0")]

    def test_unpinned_skipped(self):
        # No concrete == version → we cannot match precisely, so skip (precision over recall).
        out = parse_requirements_txt("flask>=2.0\nrequests\n")
        assert out == []


class TestPackageLock:
    def test_v3_packages_key(self):
        data = {"packages": {
            "": {"name": "root"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/@scope/pkg": {"version": "1.2.3"},
        }}
        out = dict(parse_package_lock(data))
        assert out["lodash"] == "4.17.20"
        assert out["@scope/pkg"] == "1.2.3"
        assert "root" not in out

    def test_v1_dependencies_key(self):
        data = {"dependencies": {"lodash": {"version": "4.17.20"}}}
        out = dict(parse_package_lock(data))
        assert out["lodash"] == "4.17.20"


class TestPackageJson:
    def test_strips_range_prefixes(self):
        data = {"dependencies": {"react": "^18.2.0"}, "devDependencies": {"jest": "~29.0.0"}}
        out = dict(parse_package_json(data))
        assert out["react"] == "18.2.0"
        assert out["jest"] == "29.0.0"

    def test_skips_non_concrete(self):
        data = {"dependencies": {"x": "*", "y": "workspace:*", "z": "latest"}}
        assert parse_package_json(data) == []


class TestTomlLock:
    def test_poetry_and_uv_blocks(self):
        text = '''
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.0.0"
'''
        out = dict(parse_toml_lock(text))
        assert out["requests"] == "2.31.0"
        assert out["urllib3"] == "2.0.0"


class TestPipfileLock:
    def test_default_and_develop(self):
        data = {"default": {"requests": {"version": "==2.31.0"}},
                "develop": {"pytest": {"version": "==8.0.0"}}}
        out = dict(parse_pipfile_lock(data))
        assert out["requests"] == "2.31.0"
        assert out["pytest"] == "8.0.0"


class TestManifestDispatch:
    def test_routes_by_filename_with_ecosystem(self):
        deps = parse_manifest("requirements.txt", "requests==2.31.0\n")
        assert deps == [{"name": "requests", "version": "2.31.0", "ecosystem": "pypi"}]

    def test_package_lock_is_npm(self):
        deps = parse_manifest("package-lock.json", '{"packages": {"node_modules/lodash": {"version": "4.17.20"}}}')
        assert deps == [{"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}]

    def test_unknown_file_empty(self):
        assert parse_manifest("README.md", "hello") == []

    def test_bad_json_soft_fails(self):
        assert parse_manifest("package-lock.json", "{not json") == []


class TestOsvEcosystem:
    def test_maps_to_osv_names(self):
        assert ecosystem_for_osv("pypi") == "PyPI"
        assert ecosystem_for_osv("npm") == "npm"
        assert ecosystem_for_osv("cargo") == "crates.io"
        assert ecosystem_for_osv("composer") == "Packagist"


class TestOsvBatch:
    def test_builds_query_shape(self):
        deps = [{"name": "requests", "version": "2.31.0", "ecosystem": "pypi"}]
        q = build_osv_batch(deps)
        assert q["queries"][0]["package"]["name"] == "requests"
        assert q["queries"][0]["package"]["ecosystem"] == "PyPI"
        assert q["queries"][0]["version"] == "2.31.0"


class TestOsvVulnParse:
    def test_extracts_fix_and_severity_and_aliases(self):
        vuln = {
            "id": "GHSA-xxxx",
            "summary": "Auth bypass in foo",
            "aliases": ["CVE-2024-1234"],
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "2.31.1"}]}]}],
            "database_specific": {"severity": "HIGH"},
        }
        p = parse_osv_vuln(vuln)
        assert p["id"] == "GHSA-xxxx"
        assert p["fixed"] == "2.31.1"
        assert p["severity"] == "high"
        assert "CVE-2024-1234" in p["aliases"]
        assert "Auth bypass" in p["summary"]

    def test_cvss_score_to_severity_when_no_label(self):
        vuln = {"id": "OSV-1", "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                "affected": [{"ranges": [{"events": [{"fixed": "1.0.1"}]}]}]}
        p = parse_osv_vuln(vuln)
        assert p["severity"] == "critical"

    def test_no_fix_available(self):
        vuln = {"id": "OSV-2", "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}
        p = parse_osv_vuln(vuln)
        assert p["fixed"] is None


class TestCveAliases:
    def test_only_cve_ids(self):
        vuln = {"id": "GHSA-aaa", "aliases": ["CVE-2024-1", "GHSA-bbb", "PYSEC-2024-1"]}
        assert cve_aliases(vuln) == {"CVE-2024-1"}


class TestKev:
    def test_parse_feed(self):
        data = {"vulnerabilities": [{"cveID": "CVE-2024-1"}, {"cveID": "CVE-2023-9"}]}
        s = parse_kev_feed(data)
        assert s == {"CVE-2024-1", "CVE-2023-9"}

    def test_actively_exploited_match(self):
        kev = {"CVE-2024-1"}
        assert is_actively_exploited({"CVE-2024-1"}, kev) is True
        assert is_actively_exploited({"CVE-2024-2"}, kev) is False
        assert is_actively_exploited(set(), kev) is False


class TestSeverityNormalize:
    def test_labels(self):
        assert normalize_severity("CRITICAL") == "critical"
        assert normalize_severity("High") == "high"
        assert normalize_severity("moderate") == "medium"
        assert normalize_severity("LOW") == "low"
        assert normalize_severity(None) == "unknown"
        assert normalize_severity("garbage") == "unknown"


class TestReachability:
    def test_uses_brain_flags_when_present(self):
        brain = {"dependencies": [
            {"name": "requests", "used": True, "in_auth_path": True},
            {"name": "pytest", "used": False, "in_auth_path": False},
        ]}
        assert dep_reachability("requests", brain) == {"used": True, "in_auth_path": True}
        assert dep_reachability("pytest", brain) == {"used": False, "in_auth_path": False}

    def test_unknown_dep_assumed_used_not_auth(self):
        # Brain lists only notable deps; absence must NOT suppress (avoid false negatives).
        assert dep_reachability("leftpad", {"dependencies": []}) == {"used": True, "in_auth_path": False}

    def test_handles_missing_brain(self):
        assert dep_reachability("x", {}) == {"used": True, "in_auth_path": False}


class TestFeedGate:
    def _f(self, **kw):
        base = {"severity": "high", "actively_exploited": False, "used": True}
        base.update(kw)
        return base

    def test_kev_always_passes_even_unused_or_low(self):
        assert passes_feed_gate(self._f(actively_exploited=True, used=False, severity="low")) is True

    def test_high_used_passes(self):
        assert passes_feed_gate(self._f(severity="high", used=True)) is True
        assert passes_feed_gate(self._f(severity="critical", used=True)) is True

    def test_unused_high_suppressed(self):
        assert passes_feed_gate(self._f(severity="high", used=False)) is False

    def test_low_medium_suppressed(self):
        assert passes_feed_gate(self._f(severity="medium", used=True)) is False
        assert passes_feed_gate(self._f(severity="low", used=True)) is False


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
        boom = lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network on skip"))
        monkeypatch.setattr(requests, "get", boom)
        monkeypatch.setattr(requests, "post", boom)
        runpy.run_path("scan_dependencies.py", run_name="__main__")
        assert "security_candidates" not in stored      # nothing produced on a skipped cycle


class TestSnapshotDiff:
    def test_content_hash_stable(self):
        assert content_hash("a\nb") == content_hash("a\nb")
        assert content_hash("a") != content_hash("b")

    def test_changed_detects_new_and_version_change(self):
        old = [{"name": "a", "version": "1.0", "ecosystem": "pypi"},
               {"name": "b", "version": "1.0", "ecosystem": "pypi"}]
        new = [{"name": "a", "version": "1.1", "ecosystem": "pypi"},   # changed
               {"name": "b", "version": "1.0", "ecosystem": "pypi"},   # same
               {"name": "c", "version": "2.0", "ecosystem": "pypi"}]   # new
        changed = changed_dependencies(old, new)
        assert ("a", "1.1") in changed
        assert ("c", "2.0") in changed
        assert ("b", "1.0") not in changed
