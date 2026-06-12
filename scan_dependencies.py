"""
scan_dependencies.py — GitZoid's daily dependency / supply-chain watch (Security chain, node 2).

For each repo it reads the manifests + lockfiles, builds the list of packages actually installed,
and matches them against the free public vulnerability database OSV.dev (no API key). Each hit is
cross-checked against the free CISA "Known Exploited Vulnerabilities" feed (the "being hacked right
now" signal) and judged for reachability using the brain profile (is the package used? in the auth
path?). A deterministic FEED GATE keeps only the ones worth a human's attention; survivors get a
plain-English impact + a realism judgement from the configured model. Output is a list of candidate
findings appended to the run-based `security_candidates` key, which triage_and_alert consumes.

How it knows something is vulnerable: the feeds, not the model. The model only writes the English
and decides whether the exploit is realistic (vs needing a chain of unlikely preconditions).

Conventions: flat script, no __main__ guard, init() first, no sibling-node imports, fall-through on
empty. Every external call has an explicit timeout; one bad repo never sinks the batch (soft-fail).
"""
import re
import json
import time
import base64
import hashlib
from typing import List, Optional
import requests
from pydantic import BaseModel, Field
import waveassist

waveassist.init()   # credits gated once upstream in security_check_and_init

print("Processing GitZoid dependency scan (scan_dependencies) node")

GITHUB_API = "https://api.github.com"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HTTP_TIMEOUT = 20
RATE_SLEEP = 0.15
DEFAULT_MODEL = "anthropic/claude-sonnet-4.6"
MAX_ASSESS_TOKENS = 1200
MAX_DEPS_PER_REPO = 1500              # OSV querybatch sanity cap

# Lockfiles are authoritative (concrete pinned versions). Manifests are a fallback used only when a
# repo has no lockfile, since their ranges are imprecise. Both map to an OSV ecosystem.
LOCKFILE_NAMES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
    "poetry.lock": "pypi", "uv.lock": "pypi", "Pipfile.lock": "pypi",
    "yarn.lock": "npm",  # parsed best-effort below
}
MANIFEST_NAMES = {
    "requirements.txt": "pypi", "package.json": "npm",
}
# Files we fetch per repo, lockfiles first so they win over manifests for the same ecosystem.
FETCH_ORDER = ["package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock", "poetry.lock", "uv.lock",
               "requirements.txt", "package.json"]

_OSV_ECOSYSTEM = {
    "pypi": "PyPI", "npm": "npm", "go": "Go", "cargo": "crates.io", "maven": "Maven",
    "gradle": "Maven", "rubygems": "RubyGems", "nuget": "NuGet", "composer": "Packagist",
}


# ---------------------------------------------------------------- manifest / lockfile parsers

def parse_requirements_txt(text: str):
    """Pinned `pkg==x.y.z` only (precision over recall — unpinned can't be matched exactly).
    Strips extras `pkg[extra]` and environment markers `; python_version<...`. Skips comments/flags."""
    out = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()           # drop environment marker
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-]+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def parse_package_lock(data: dict):
    """npm lockfile. v2/v3 `packages` (keys like 'node_modules/<name>'); v1 `dependencies`."""
    out = []
    pkgs = data.get("packages") if isinstance(data, dict) else None
    if isinstance(pkgs, dict):
        for path, meta in pkgs.items():
            if not path or not isinstance(meta, dict):
                continue                                 # "" is the root project
            name = path.split("node_modules/")[-1]
            ver = meta.get("version")
            if name and ver:
                out.append((name, ver))
        return out
    deps = data.get("dependencies") if isinstance(data, dict) else None
    if isinstance(deps, dict):
        for name, meta in deps.items():
            ver = meta.get("version") if isinstance(meta, dict) else None
            if name and ver:
                out.append((name, ver))
    return out


def parse_package_json(data: dict):
    """package.json fallback. Ranges (^1.2.3, ~1.0) → strip the operator to a concrete base version.
    Skip non-concrete specs (*, latest, workspace:, git/url)."""
    out = []
    if not isinstance(data, dict):
        return out
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            m = re.match(r"^[\^~>=<\s]*v?(\d+\.\d+(?:\.\d+)?)", spec.strip())
            if m:
                out.append((name, m.group(1)))
    return out


def parse_toml_lock(text: str):
    """poetry.lock / uv.lock — extract name+version from each `[[package]]` block (no TOML dep)."""
    out, cur = [], {}
    in_pkg = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line == "[[package]]":
            if cur.get("name") and cur.get("version"):
                out.append((cur["name"], cur["version"]))
            cur, in_pkg = {}, True
            continue
        if line.startswith("[") and line != "[[package]]":
            in_pkg = False                                # left the package block (e.g. [package.deps])
        if not in_pkg:
            continue
        m = re.match(r'^(name|version)\s*=\s*"([^"]+)"', line)
        if m:
            cur[m.group(1)] = m.group(2)
    if cur.get("name") and cur.get("version"):
        out.append((cur["name"], cur["version"]))
    return out


def parse_pipfile_lock(data: dict):
    """Pipfile.lock — `default` + `develop`, each {pkg: {version: '==x.y.z'}}."""
    out = []
    if not isinstance(data, dict):
        return out
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = (meta or {}).get("version", "") if isinstance(meta, dict) else ""
            ver = ver.lstrip("=") if isinstance(ver, str) else ""
            if name and ver:
                out.append((name, ver))
    return out


def parse_manifest(filename: str, content: str):
    """Dispatch a manifest/lockfile to its parser; return [{name, version, ecosystem}]. Soft-fails
    (bad JSON, unknown file) to []."""
    base = (filename or "").split("/")[-1]
    eco = LOCKFILE_NAMES.get(base) or MANIFEST_NAMES.get(base)
    if not eco:
        return []
    try:
        if base in ("package-lock.json", "npm-shrinkwrap.json"):
            pairs = parse_package_lock(json.loads(content))
        elif base == "package.json":
            pairs = parse_package_json(json.loads(content))
        elif base == "Pipfile.lock":
            pairs = parse_pipfile_lock(json.loads(content))
        elif base in ("poetry.lock", "uv.lock"):
            pairs = parse_toml_lock(content)
        elif base == "requirements.txt":
            pairs = parse_requirements_txt(content)
        elif base == "yarn.lock":
            pairs = _parse_yarn_lock(content)
        else:
            pairs = []
    except Exception as e:
        print(f"⚠️ failed to parse {filename}: {e}")
        return []
    seen, deps = set(), []
    for name, ver in pairs:
        key = (name, ver)
        if key in seen:
            continue
        seen.add(key)
        deps.append({"name": name, "version": ver, "ecosystem": eco})
    return deps


def _parse_yarn_lock(text: str):
    """Best-effort yarn v1: blocks like `pkg@^1.0:` then an indented `version "1.2.3"`."""
    out, name = [], None
    for raw in (text or "").splitlines():
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            head = raw.split(",")[0].strip().strip('"')
            at = head.rfind("@")
            name = head[:at] if at > 0 else head.rstrip(":")
        elif name and raw.strip().startswith("version"):
            m = re.search(r'"([^"]+)"', raw)
            if m:
                out.append((name, m.group(1)))
                name = None
    return out


# ---------------------------------------------------------------- OSV + KEV

def ecosystem_for_osv(eco: str) -> str:
    return _OSV_ECOSYSTEM.get((eco or "").lower(), "")


def build_osv_batch(deps) -> dict:
    """OSV /v1/querybatch payload: one query per (name, version, ecosystem)."""
    queries = []
    for d in deps:
        osv_eco = ecosystem_for_osv(d.get("ecosystem"))
        if not osv_eco or not d.get("name") or not d.get("version"):
            continue
        queries.append({"package": {"name": d["name"], "ecosystem": osv_eco},
                        "version": d["version"]})
    return {"queries": queries}


def normalize_severity(raw) -> str:
    """Map varied severity labels / CVSS scores to critical|high|medium|low|unknown."""
    if raw is None:
        return "unknown"
    s = str(raw).strip().lower()
    if s in ("critical",):
        return "critical"
    if s in ("high",):
        return "high"
    if s in ("medium", "moderate"):
        return "medium"
    if s in ("low",):
        return "low"
    return "unknown"


def _severity_from_cvss(score) -> str:
    try:
        v = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if v >= 9.0:
        return "critical"
    if v >= 7.0:
        return "high"
    if v >= 4.0:
        return "medium"
    if v > 0:
        return "low"
    return "unknown"


def parse_osv_vuln(vuln: dict) -> dict:
    """Pull the fields we use from a full OSV vuln record: id, aliases, fixed version, severity,
    plain summary."""
    vid = vuln.get("id", "")
    aliases = list(vuln.get("aliases") or [])
    summary = vuln.get("summary") or (vuln.get("details") or "")[:300]

    fixed = None
    for aff in (vuln.get("affected") or []):
        for rng in (aff.get("ranges") or []):
            for ev in (rng.get("events") or []):
                if ev.get("fixed"):
                    fixed = ev["fixed"]
                    break
            if fixed:
                break
        if fixed:
            break

    severity = normalize_severity((vuln.get("database_specific") or {}).get("severity"))
    if severity == "unknown":
        for sev in (vuln.get("severity") or []):
            severity = _severity_from_cvss(sev.get("score"))
            if severity != "unknown":
                break

    return {"id": vid, "aliases": aliases, "fixed": fixed,
            "severity": severity, "summary": summary}


def cve_aliases(vuln: dict) -> set:
    """The CVE ids among a vuln's id+aliases (what the KEV feed is keyed on)."""
    ids = set(vuln.get("aliases") or [])
    if vuln.get("id"):
        ids.add(vuln["id"])
    return {i for i in ids if isinstance(i, str) and i.upper().startswith("CVE-")}


def parse_kev_feed(data: dict) -> set:
    """CISA KEV → set of actively-exploited CVE ids."""
    out = set()
    for v in (data.get("vulnerabilities") or []):
        cid = v.get("cveID")
        if cid:
            out.add(cid)
    return out


def is_actively_exploited(aliases, kev_set) -> bool:
    return bool(set(aliases) & set(kev_set))


# ---------------------------------------------------------------- reachability + gate

def dep_reachability(name: str, brain_profile: dict) -> dict:
    """Reachability from the brain. A dep listed in the profile uses its used/in_auth_path flags;
    a dep NOT listed is assumed used (the brain lists only notable deps — absence must not suppress)."""
    for d in ((brain_profile or {}).get("dependencies") or []):
        if (d.get("name") or "").lower() == (name or "").lower():
            return {"used": bool(d.get("used", True)), "in_auth_path": bool(d.get("in_auth_path", False))}
    return {"used": True, "in_auth_path": False}


def passes_feed_gate(finding: dict) -> bool:
    """Deterministic pre-gate before the model ever sees a candidate. Surface only if it's being
    exploited in the wild (KEV) OR it's a high/critical-severity flaw in a package actually used."""
    if finding.get("actively_exploited"):
        return True
    return finding.get("severity") in ("high", "critical") and bool(finding.get("used"))


# ---------------------------------------------------------------- snapshot diff

def content_hash(text: str) -> str:
    return hashlib.sha1((text or "").encode("utf-8", "ignore")).hexdigest()


def changed_dependencies(old, new) -> set:
    """(name, version) pairs that are new or version-changed vs the previous snapshot."""
    old_map = {d["name"]: d["version"] for d in (old or []) if d.get("name")}
    changed = set()
    for d in (new or []):
        if d.get("name") and old_map.get(d["name"]) != d.get("version"):
            changed.add((d["name"], d["version"]))
    return changed


# ---------------------------------------------------------------- model assessment (English + realism)

class DependencyRisk(BaseModel):
    """The model's job: write the human-facing impact and judge whether the exploit is realistic.
    It never decides IF something is a vulnerability — the feeds already did."""
    is_real_risk: bool = Field(
        description="True only if this is a realistic, serious risk for THIS codebase. False if it "
                    "needs a chain of unlikely preconditions, or the package isn't meaningfully used.")
    impact: str = Field(
        description="One or two plain-English sentences: what an attacker could do and to whom. No "
                    "CVE jargon, no CVSS scores, no code internals. Empty if is_real_risk is false.")
    reason: str = Field(description="One short sentence on why you kept or dropped it.")


def build_assessment_prompt(finding: dict, brain_profile: dict) -> str:
    arch = (brain_profile or {}).get("architecture_summary", "") or ""
    kev = "YES — confirmed exploited in the wild right now" if finding.get("actively_exploited") else "no"
    return f"""<role>
You are a security engineer triaging a dependency vulnerability for a specific codebase. The
vulnerability is already confirmed (it comes from a public vulnerability database). Your ONLY jobs
are (1) decide if it is a realistic, serious risk for THIS codebase, and (2) describe the impact in
plain English a busy engineer instantly understands.
</role>
<repo_context>{arch}</repo_context>
<vulnerability>
  <package>{finding.get('name')} {finding.get('version')}</package>
  <severity_from_feed>{finding.get('severity')}</severity_from_feed>
  <actively_exploited_in_wild>{kev}</actively_exploited_in_wild>
  <used_in_codebase>{finding.get('used')}</used_in_codebase>
  <in_auth_or_sensitive_path>{finding.get('in_auth_path')}</in_auth_or_sensitive_path>
  <fix_version>{finding.get('fixed') or 'no fix published yet'}</fix_version>
  <summary>{finding.get('summary')}</summary>
</vulnerability>
<rules>
- If exploiting it needs many unlikely conditions to line up, set is_real_risk=false.
- If it's confirmed exploited in the wild, it is almost always a real risk.
- impact: plain English, who is affected and what an attacker gains. No CVE ids, no CVSS, no jargon.
- Do not restate the package name and version mechanically; describe the danger.
</rules>"""


def assess_finding(model_name, finding, brain_profile):
    """Ask the model for impact + realism. On any LLM failure, fail OPEN to a feed-only finding
    (the feed gate already vouched for it) rather than dropping a real issue."""
    try:
        risk = waveassist.call_llm(model=model_name,
                                   prompt=build_assessment_prompt(finding, brain_profile),
                                   response_model=DependencyRisk, should_retry=True,
                                   max_tokens=MAX_ASSESS_TOKENS)
    except Exception as e:
        print(f"⚠️ assessment LLM failed for {finding.get('name')}: {e}; keeping feed-based finding")
        return True, ""
    if risk is None:
        return True, ""
    return bool(risk.is_real_risk), (risk.impact or "").strip()


# ---------------------------------------------------------------- github fetch helpers

def _gh_headers(token):
    return {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}


def fetch_file(repo_path, filename, branch, headers):
    """Fetch one file's text via the Contents API. Returns None if absent."""
    params = {"ref": branch} if branch else None
    r = requests.get(f"{GITHUB_API}/repos/{repo_path}/contents/{filename}",
                     headers=headers, params=params, timeout=HTTP_TIMEOUT)
    time.sleep(RATE_SLEEP)
    if r.status_code != 200:
        return None
    try:
        data = r.json()
        if data.get("encoding") == "base64" and data.get("content"):
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"⚠️ decode {filename}: {e}")
    return None


def collect_repo_dependencies(repo_path, branch, headers):
    """Fetch known manifests/lockfiles and merge into a deduped dependency list. Lockfiles win:
    if any lockfile is present for an ecosystem, the loose manifest for it is skipped."""
    found, raw_blobs = {}, []
    for fname in FETCH_ORDER:
        content = fetch_file(repo_path, fname, branch, headers)
        if content is None:
            continue
        raw_blobs.append(content)
        eco = LOCKFILE_NAMES.get(fname) or MANIFEST_NAMES.get(fname)
        is_lock = fname in LOCKFILE_NAMES
        # skip a manifest if we already have a lockfile for the same ecosystem
        if not is_lock and any(found.get(e) == "lock" for e in [eco]):
            continue
        for dep in parse_manifest(fname, content):
            found[(dep["name"], dep["version"], dep["ecosystem"])] = dep
        if is_lock:
            found[eco] = "lock"
    deps = [v for k, v in found.items() if isinstance(v, dict)]
    return deps[:MAX_DEPS_PER_REPO], content_hash("\n".join(sorted(raw_blobs)))


def query_osv(deps):
    """OSV querybatch → {(name,version): [vuln_id,...]} then hydrate each id to a full record."""
    batch = build_osv_batch(deps)
    if not batch["queries"]:
        return {}
    try:
        r = requests.post(OSV_BATCH_URL, json=batch, timeout=HTTP_TIMEOUT)
        if r.status_code != 200:
            print(f"⚠️ OSV batch HTTP {r.status_code}")
            return {}
        results = r.json().get("results", [])
    except Exception as e:
        print(f"⚠️ OSV batch failed: {e}")
        return {}
    out = {}
    for dep, res in zip(deps, results):
        ids = [v.get("id") for v in (res.get("vulns") or []) if v.get("id")]
        if ids:
            out[(dep["name"], dep["version"])] = ids
    return out


def hydrate_vuln(vuln_id):
    try:
        r = requests.get(f"{OSV_VULN_URL}/{vuln_id}", timeout=HTTP_TIMEOUT)
        time.sleep(RATE_SLEEP)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"⚠️ OSV hydrate {vuln_id} failed: {e}")
    return None


def fetch_kev_set():
    try:
        r = requests.get(KEV_URL, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            return parse_kev_feed(r.json())
        print(f"⚠️ KEV HTTP {r.status_code}")
    except Exception as e:
        print(f"⚠️ KEV fetch failed: {e}")
    return set()      # soft-fail: no KEV data just means no auto-escalation this run


# ---------------------------------------------------------------- driver (flat, fall-through)

skip = waveassist.fetch_data("security_skip_run", run_based=True, default="0") == "1"
repositories = [] if skip else (waveassist.fetch_data("github_selected_resources", default=[]) or [])

if skip:
    print("GitZoid Security: security_skip_run set; scan_dependencies no-op.")

if repositories:
    access_token = waveassist.fetch_data("github_access_token", default="") or ""
    model_name = waveassist.fetch_data("model_name", default=DEFAULT_MODEL) or DEFAULT_MODEL
    headers = _gh_headers(access_token)
    kev_set = fetch_kev_set()
    candidates = []

    for repo in repositories:
        repo_path = repo.get("id") if isinstance(repo, dict) else repo
        if not repo_path:
            continue
        try:
            profile = waveassist.fetch_data(f"profile:{repo_path}", default={}) or {}
            branch = (profile.get("_fingerprint") or {}).get("branch") or ""

            deps, blob_hash = collect_repo_dependencies(repo_path, branch, headers)
            if not deps:
                print(f"✓ {repo_path}: no parseable dependencies; skip")
                continue

            prev = waveassist.fetch_data(f"dependency_snapshot:{repo_path}", default={}) or {}
            if prev.get("hash") == blob_hash and prev.get("scanned_clean"):
                # Manifests unchanged AND last scan found nothing — safe to skip the OSV round-trip.
                # (Feeds still change daily, so we only skip when the last scan was clean.)
                print(f"✓ {repo_path}: lockfiles unchanged since a clean scan; skip")
                continue

            osv_hits = query_osv(deps)
            repo_findings = []
            for (name, version), vuln_ids in osv_hits.items():
                reach = dep_reachability(name, profile)
                for vid in vuln_ids:
                    full = hydrate_vuln(vid)
                    if not full:
                        continue
                    parsed = parse_osv_vuln(full)
                    finding = {
                        "category": "dependency", "repo": repo_path,
                        "name": name, "version": version,
                        "ecosystem": next((d["ecosystem"] for d in deps if d["name"] == name), ""),
                        "vuln_id": parsed["id"], "aliases": parsed["aliases"],
                        "fixed": parsed["fixed"], "severity": parsed["severity"],
                        "summary": parsed["summary"],
                        "actively_exploited": is_actively_exploited(cve_aliases(full), kev_set),
                        "used": reach["used"], "in_auth_path": reach["in_auth_path"],
                    }
                    if not passes_feed_gate(finding):
                        continue
                    is_real, impact = assess_finding(model_name, finding, profile)
                    if not is_real:
                        print(f"· dropped {name} {parsed['id']} (model: not a realistic risk)")
                        continue
                    finding["impact"] = impact
                    repo_findings.append(finding)

            candidates.extend(repo_findings)
            waveassist.store_data(f"dependency_snapshot:{repo_path}",
                                  {"hash": blob_hash, "scanned_clean": len(repo_findings) == 0,
                                   "deps": deps},
                                  data_type="json")
            print(f"✓ {repo_path}: scanned {len(deps)} deps, {len(repo_findings)} real finding(s)")
        except Exception as e:
            print(f"⚠️ scan failed for {repo_path}: {e}; skipping repo")
            continue

    # Hand candidates to triage (run-based; deep_security_audit appends to the same key next).
    existing = waveassist.fetch_data("security_candidates", run_based=True, default=[]) or []
    waveassist.store_data("security_candidates", existing + candidates,
                          run_based=True, data_type="json")
    print(f"GitZoid Security: scan_dependencies produced {len(candidates)} candidate(s).")
