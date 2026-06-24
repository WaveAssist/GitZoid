# GitZoid — Agent Context

GitZoid is a WaveAssist AI agent for GitHub engineering teams. It does three jobs, each as an
independent DAG on its own schedule and its own lock:

1. **PR Review** — reviews open pull requests and posts inline + summary comments.
2. **Security Watch** — scans dependencies (OSV + CISA KEV) and runs a deep code audit, then alerts.
3. **Knowledge Digest** — summarises repo activity into a periodic email digest.

The three chains are disconnected subgraphs that share no run-state, so a slow security scan never
blocks PR reviews and vice-versa. GitZoid runs on a shared Celery/ECS worker pool; the same code runs
for any number of tenant projects, each identified by a `project_key`.

---

## Conventions (every node follows these)

- **Flat scripts, no `__main__` guard.** Each node is a top-to-bottom script; the DAG runner imports it.
- **`waveassist.init()` first**, before any data access.
- **No sibling-node imports.** Shared helpers (lock logic, group resolution, signatures) are
  *duplicated* across nodes on purpose — a node must be runnable in isolation.
- **Fall-through on empty.** A node with nothing to do prints and exits cleanly; it does not raise.
  Raising is reserved for real failures (e.g. out of credits).
- **Soft-fail per item.** One bad repo/PR never sinks the batch — it's caught, logged, and skipped.
- **Run-based vs global state.** `run_based=True` keys are scoped to one DAG run (handoffs between
  nodes in the same run). Global keys persist across runs (ledgers, snapshots, config). Booleans are
  stored as the STRINGS `"0"`/`"1"`, never JSON bools (the SDK wraps a JSON bool as a truthy dict).

---

## Chain 1 — PR Review

Schedule: frequent (e.g. every ~2 min).
```
check_credits_and_init → study_repos → fetch_pull_requests → generate_review → post_comment
```

- **check_credits_and_init** — gates credits, then acquires the run lock `run_lock`
  (TTL **7200s / 2h**). If a fresh lock already exists, this cycle is a no-op: it sets run-based
  `skip_run="1"`, marks the run idle, and downstream nodes short-circuit. On acquire it writes a UUID
  `run_lock_token` (run-based) used for safe release.
- **study_repos** — builds/refreshes a brain profile per repo (`profile:{repo}`): dependencies,
  routes, key files, an architecture summary. LLM-heavy on first run; skips already-fresh profiles.
- **fetch_pull_requests** — fetches open PRs, diffs, and prior-review context. Respects `skip_run`.
  On a repo's first run it processes only `FIRST_RUN_LIMIT` PRs; the overflow is marked
  `status:"skipped"` (by design) so a first sync doesn't review a huge backlog at once.
- **generate_review** — produces a full or incremental review per PR (LLM), runs a deterministic gate
  plus an adversarial verify pass that refutes each finding against its full function before it ships.
  **Checks `skip_run`** and no-ops if set; never mutates the global `pull_requests` on a skip.
- **post_comment** — posts the inline GitHub PR Review + a single editable summary comment, made
  idempotent by a hidden `SUMMARY_MARKER` (it edits its own marked comment instead of duplicating).
  **Checks `skip_run`**: on a skip it marks idle and returns without posting. Releases `run_lock` in a
  `finally` — but only if the run-based token matches, so a skipped/overlapping cycle can never free
  the holder's lock.

---

## Chain 2 — Security Watch (group-scoped)

Schedule: daily.
```
security_check_and_init → scan_dependencies → deep_security_audit → triage_and_alert
```

- **security_check_and_init** — gates credits, acquires `security_run_lock` (TTL **7200s / 2h**).
  Resolves the `security_groups` config against the selected repos into a working set and stores it as
  run-based `security_resolved_groups`. Membership is **exclusive** — the first group to claim a repo
  owns it, so no repo's findings can route to two groups. If no groups are configured it falls back to
  one implicit group over all selected repos. **Scan scope = group repos only.**
- **scan_dependencies** — for each repo in the working set: collect installed packages from
  manifests/lockfiles, query OSV.dev, cross-check the CISA KEV feed, gate by severity + reachability,
  and run an LLM realism check on survivors. (Internals below.)
- **deep_security_audit** — brain-scoped code audit (authorization gaps, secrets, backdoors) over a
  risk-ranked, token-budgeted file selection. Self-throttles to `RUN_TIME_BUDGET_SECONDS` (~20 min);
  overflow repos resume on the next tick. Rotates fairly across repos by oldest-audited-first.
- **triage_and_alert** — reconciles all candidates against the persistent `security_findings` ledger
  (dedup, escalation, resolution), then fans the to-alert set out **per group** so each group's repos
  email only that group's recipients. Sends nothing when there's nothing genuinely new (silence is the
  all-clear). Releases the security lock.

**Grouping is both scan scope and delivery.** Resolving the groups once in the init node and handing
them down via `security_resolved_groups` keeps every node working from the same set.

### scan_dependencies internals

OSV `/v1/querybatch` returns only **`{id, modified}` stubs** per hit — no severity, aliases, or
detail. So each hit must be **hydrated** via `/v1/vulns/{id}` to get the data the gate and the model
need. Per advisory:

```
querybatch (stubs) → suppress-if-already-alerted? → hydrate → parse → feed gate?
  → ledger says already-open? reuse verdict : assess_finding (LLM) → keep / drop
```

- **`hydrated_vulns`** (within-run cache, `advisory_id → record`): the same advisory recurs across
  repos that share a dependency, and hydration is a pure function of the id, so caching removes the
  bulk of the per-advisory HTTP round-trips (the dominant cost of a large scan). **Successes only** —
  a transient failure retries on the next repo instead of caching a miss that would hide a real CVE.
- **`assess_finding` is deliberately NOT cached across repos.** Its verdict depends on the repo's brain
  profile (architecture summary + reachability), so the same advisory can be a real risk in one repo
  and noise in another. The ledger cache still avoids re-judging an already-open finding across days,
  and the feed gate keeps low/medium-non-KEV findings away from the model entirely.
- **Feed gate** (`passes_feed_gate`): keep iff actively-exploited (in KEV) OR (severity high/critical
  AND the package is actually used). The model never decides *whether* something is a vulnerability —
  the feeds do; the model only writes the plain-English impact and judges realism for this codebase.
- **Reachability** (`dep_reachability`): a dependency not listed in the brain profile defaults to
  `used=True` — absence must never suppress a finding — so a fresh/empty brain lets all high/critical
  advisories through the gate.
- **Snapshot skip**: if a repo's manifest hash is unchanged since a scan that found nothing, the OSV
  round-trip is skipped entirely (feeds still change daily, so only *clean* repos are skipped).

---

## Chain 3 — Knowledge Digest (group-scoped)

Schedule: weekly.
```
digest_check_and_init → fetch_activity → analyze_activity → generate_technical_report
  → generate_business_report → send_digest
```

- **digest_check_and_init** — gates credits, acquires `digest_run_lock` (TTL **3600s / 1h**), resolves
  `digest_groups` into run-based `digest_resolved_groups`.
- The remaining nodes scope to the union of `digest_resolved_groups` repos, produce a technical and a
  business-facing report, and email each group its own digest.

---

## Lock design (shared by all three chains)

1. The init node acquires the lock with a UUID token stored **globally** (in the lock value) and
   **run-based** (`*_run_lock_token`).
2. The final node (post_comment / triage_and_alert / send_digest) releases the lock only if the
   run-based token matches the lock's token — so **only the acquiring run can release it**.
3. A skipped/overlapping cycle never writes a token, so its release is always a no-op; it can never
   free the holder's lock.
4. The TTL is a crash safety net (frees a wedged lock if a run dies before releasing). PR review uses
   2h because its cadence is high (a short TTL expiring mid-run under queue load let two real runs hold
   the lock at once — the original duplicate-comment bug). Security uses 2h for the same reason; digest
   1h. The daily/weekly chains never re-fire fast, so a generous TTL never serializes normal cycles.

---

## Key persistent state

| Key | Scope | Description |
|---|---|---|
| `run_lock` / `security_run_lock` / `digest_run_lock` | global | `{at, token}`; empty `{}` = free. TTL 2h / 2h / 1h. |
| `run_lock_token` / `security_run_lock_token` / `digest_run_lock_token` | run-based | UUID; the releaser matches it before clearing the lock. |
| `skip_run` / `security_skip_run` / `digest_skip_run` | run-based | `"0"`/`"1"`; every downstream node in that chain checks it. |
| `security_resolved_groups` / `digest_resolved_groups` | run-based | `[{name, repos, recipients, slug, implicit}]`. Set by the init node; scan/audit/triage (or fetch/analyze/send) fan over it. |
| `security_groups` / `digest_groups` | global | Dashboard config: `[{name, repos, recipients}]`. |
| `github_selected_resources` | global | All repos configured for this project (each may carry per-repo `properties`). |
| `pull_requests` | global | PR dicts with `comment_generated` / `comment_posted`; written by fetch, mutated by generate, cleared by post. |
| `reviewed_prs` | global | `{"{repo}#{pr}": {status, last_reviewed_sha, findings, summary_comment_id, ...}}`. |
| `profile:{repo}` | global | Brain profile (deps, routes, key files, architecture summary). |
| `security_findings` | global | Dependency + code finding ledger (dedup / escalation / resolution across runs). |
| `dependency_snapshot:{repo}` | global | `{hash, scanned_clean, deps}`; drives the OSV snapshot-skip. |
| `security_audit_state` / `security_audit_queue` | global | Per-repo deep-audit rotation state + files queued by PR review for the next audit. |

---

## Known issues

- **yarn.lock not scanned.** `yarn.lock` is in `LOCKFILE_NAMES` but missing from `FETCH_ORDER`, so Yarn
  repos fall back to `package.json` (imprecise ranges → fewer OSV hits). Add it to `FETCH_ORDER`.
- **scan_dependencies has no checkpointing.** A long scan killed by ECS auto-scaling restarts from the
  first repo. Per-repo checkpoint + resume would make restarts cheap.
- **NodeRun stuck at STARTED.** When ECS kills a worker mid-task the run record never transitions out of
  STARTED (platform-level, not fixable in node code).

---

## Testing

- `tests/unit/`, `tests/integration/`, `tests/e2e/` (`pytest tests/unit/` etc.).
- E2E runners drive a chain against a real project's config through an **in-memory store overlay**
  (nothing is written back to the project), **hard-block GitHub writes**, and default email to
  **preview-only** (`--send` to actually send). They simulate the init node by injecting the resolved
  group set, so scan/audit/triage exercise the real run-based handoffs.
- **Test gap:** no unit test asserting generate_review / post_comment no-op when `skip_run="1"` with
  existing `pull_requests` data (the duplicate-comment regression guard).

---

## Infrastructure

- **Broker/queue:** Redis (ElastiCache) + Celery; workers on ECS Fargate, shared across tenants.
- **LLM:** configured per project via `model_name`.
- **External feeds (no key):** OSV.dev (`/v1/querybatch`, `/v1/vulns/{id}`) and the CISA KEV JSON feed.
