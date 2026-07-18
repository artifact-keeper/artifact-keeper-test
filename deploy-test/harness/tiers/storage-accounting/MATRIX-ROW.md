# MATRIX-ROW — storage-accounting (PKT-D, feature #2056)

Integrator: merge the row below into `matrix.md` (feature-coverage block), and
see the shared-file note at the bottom (the tier is standalone-testable today;
the `run.sh`/`compose` passthrough is an OPTIONAL cleanup, not required).

## Row for matrix.md

| # | Class / capability | Profile-set | Discriminating oracle | DTF tier | Status |
|---|---|---|---|---|---|
| 14 | **Deduplicated storage accounting per repo** — #2056 | storage=**s3** (instance dedup scope), fast `STORAGE_STATS_SCHEDULE` | `oracle.sh`: push the SAME OCI layer blob X to repos A+B and a DISTINCT blob Y to repo C on shared S3 → wait for `repository_storage_stats` materialization (poll `computed_at`) → read admin `GET /api/v1/repositories/{key}/storage` → assert dedup-aware figures: `shared_bytes(A)==shared_bytes(B)==Sx`, `shared_bytes(C)==0`, `instance_unique_bytes==Sx+Sy==naive_sum-Sx` (shared blob counted ONCE). FAILS on the naive double-count (`instance_unique==2*Sx+Sy`, `shared==0`). | **storage-accounting** | **COVERED** (PKT-D) — green (exit 0, 12/12) on `ak-backend:candidate-a4d7f9d1`; DISCRIMINATING: `NAIVE_ORACLE=1 ./harness/run.sh storage-accounting ...` asserts the pre-#2056 naive expectations and reds on the same fixed candidate (`shared_bytes(A)` is 262144 not 0; `instance_unique` is 393216 not 655360), tier exits non-zero. A pre-#2056 backend (empty `repository_storage_stats` / naive sum) reds the same way. Covers #2056 repo-level + OCI-layer dedup; **folder-rollup #2601 deferred (no HTTP surface — see OPEN QUESTION below).** |

## Surface verified against the running candidate (`ak-backend:candidate-a4d7f9d1`)

- **Endpoint works as the plan says.** `GET /api/v1/repositories/{key}/storage`
  returns `RepositoryStorageStatsResponse{logical_bytes, physical_bytes,
  unique_bytes, shared_bytes, dedup_ratio, blob_count, dedup_scope,
  instance_unique_bytes, computed_at}` read from the materialized
  `repository_storage_stats` cache. On the s3 stack `dedup_scope=="instance"`.
  The cross-tenant-derivable figures (`physical/unique/shared/dedup_ratio`) and
  the `instance_unique_bytes` singleton are **admin-only** on instance scope
  (#2560/#2559) — the oracle authenticates as admin.
- **`STORAGE_STATS_SCHEDULE` knob works as the plan says.** It is read at
  `config.rs:1061` (6-field cron, default `0 0 */4 * * *`) and drives the
  scheduler's stats refresher (`scheduler_service.rs:508`). Set to
  `*/10 * * * * *`, the materialized cache refreshed and `computed_at` advanced.
  **Timing caveat the plan under-stated:** the refresher task sleeps
  `jittered_startup_delay(150)` (≈150-180s) BEFORE its first pass, so the first
  materialization lands ~180s after backend start regardless of cron period.
  Observed live: `computed_at` appeared at **181s**. The oracle budgets 300s and
  overlaps uploads with the wait. There is **no on-demand refresh trigger**: the
  manual `POST /api/v1/admin/storage-gc` calls `run_gc` only — it does NOT call
  `recompute_all` (that is scheduler-only, post-GC + cron). So the fast cron is
  the only deployment-drivable path to materialization.
- **Exact observed figures (green run):**
  `A: logical=262144 physical=262144 unique=0 shared=262144 blob_count=1` ·
  `B: physical=262144 shared=262144` · `C: physical=131072 unique=131072
  shared=0` · `instance_unique_bytes=393216` (== Sx+Sy) vs naive_sum 655360
  (== 2*Sx+Sy). Dedup savings = exactly one copy of the shared blob (Sx=262144).

## Why OCI, not Maven (design note for reviewers)

The obvious "same content to two repos" via a shared Maven coordinate does NOT
work on the candidate: the #2584 `guard_flat_key_writable` REFUSES a cross-repo
overwrite of a shared flat key on cloud storage (that is the isolation fix). So
a shared Maven dedup key cannot be created. **OCI blobs are the correct dedup
vehicle**: they are digest-addressed and stored per `(repository_id, digest)` in
`oci_blobs`; the same layer pushed to two repos yields two rows sharing the
digest (migration 162 adds `idx_oci_blobs_digest` precisely for this cross-repo
grouping). The oracle pushes blobs via the raw OCI v2 monolithic upload with
`curl` + Basic auth (no docker daemon needed); a committed blob PUT inserts the
`oci_blobs` row the stats union counts, so a blob-only push is sufficient and
keeps exactly one dedup row per repo for clean, exact numbers.

## Why s3, not filesystem

On filesystem the backend forces `DedupScope::PerRepo`, so `shared_bytes==0` by
construction and cross-repo dedup CANNOT manifest — the "dedup-aware vs
naive-sum" discriminator is only observable on a shared object store. The
manifest therefore pins `storage.s3` (reused as-is; NO new storage profile).

**Optional filesystem CONTRACT leg (integrator, trivial):** the oracle branches
on the reported `dedup_scope`, so a sibling tier `storage-accounting-fs` with a
manifest setting `PROFILES="storage.filesystem"` could reuse the SAME oracle to
assert the per_repo contract (`dedup_scope=="per_repo"`, `shared_bytes==0` even
for shared content, `physical==logical`). Not built in this packet because it
does not add a discriminating dedup assertion (filesystem cannot show dedup) —
it would only be a documented-contract guard. Flagged, not faked.

## OPEN QUESTION #1 finding — folder rollup #2601 (per build-plan §5.1)

**No folder/tree storage rollup HTTP surface exists on the candidate.** I
grepped the running API's routes and `repositories.rs`: the ONLY storage read is
`GET /{key}/storage` (whole-repository). The only `rollup` hits are the scan-status
rollup #1497 (`repositories.rs:4922`, `9965`) — unrelated to storage. There is no
`folder`/`tree`/`subtree`/`path`-scoped storage-usage endpoint. Per the
build-plan's explicit instruction ("Do NOT fake a folder-rollup oracle"),
**folder rollup #2601 is DEFERRED: no deployment-drivable surface exists.** This
tier covers the #2056 core — repo-level dedup + OCI-layer accounting — which is
fully coverable and discriminating. If a folder-scoped storage surface is added
later, extend this oracle with a per-folder assertion.

## Files owned by this packet (isolated; no shared-file edits)

- `harness/tiers/storage-accounting/manifest`
- `harness/tiers/storage-accounting/oracle.sh`
- `harness/tiers/storage-accounting/MATRIX-ROW.md` (this file)
- Reuses `profiles/storage.s3.yml` as-is (NO new/edited storage profile).

## Shared-file note for the integrator (OFF-LIMITS files)

- **The tier is standalone-testable today with NO `run.sh`/`compose` edit.**
  `compose.base.yml` does not reference `STORAGE_STATS_SCHEDULE` and `run.sh`
  only exports `RATE_LIMIT_ENABLED`, so a stock run would leave the backend on
  the 4-hourly default and the stats cache empty. The oracle handles this in
  scope it owns: `ensure_fast_stats_cron()` detects the missing env and
  recreates ONLY the backend (`docker compose ... up -d --no-deps
  --force-recreate --wait backend`) with an in-scope compose override that adds
  `STORAGE_STATS_SCHEDULE`. Postgres/MinIO and their volumes are untouched. This
  is the "prefer a compose override in scope you own" path from the PKT-D brief.
- **OPTIONAL cleanup (integrator, not required):** if you would rather the
  backend boot with the fast cron directly (skipping the one-time recreate), add
  `STORAGE_STATS_SCHEDULE: ${STORAGE_STATS_SCHEDULE:-0 0 */4 * * *}` to
  `compose.base.yml` `backend.environment` AND add `STORAGE_STATS_SCHEDULE` to
  the manifest-env export in `run.sh` (next to the existing `RATE_LIMIT_ENABLED`
  line). The oracle auto-detects the already-present env and skips its recreate,
  so both paths work — no oracle change needed.
- **`matrix.md`, `ports.sh`:** no new ports; reuses the slot's `S3_PORT` /
  `S3_CONSOLE_PORT`. Only the row above needs merging into `matrix.md`.
- **`run.sh` `all` list:** this tier is green on the single
  `candidate-a4d7f9d1` image, so it CAN join the `all` run — but it adds ~200s
  (the scheduler startup delay before first materialization). Sequence it late.
