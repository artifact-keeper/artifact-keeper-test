# MATRIX-ROW — scanner-collapse (PKT-F, P7, issue #2471)

Integrator: merge the row below into `matrix.md` (new row after the current last
row). One tier, `scanner-collapse`.

| # | Class / capability | Profile-set | Discriminating oracle | DTF tier | Status |
|---|---|---|---|---|---|
| 18 | **Scanner `not_applicable` row collapse** — #2471 | scanners=**trivy** (+ filesystem/single) | upload a non-image `.bin`; image + filesystem + incus decline by TYPE -> >=2 `not_applicable` rows. Scan-results API (`/security/scans?artifact_id=`) must return **exactly ONE** not_applicable row — the synthetic summary (`scan_type=not_applicable`, `collapsed_not_applicable_count>=2`, `collapsed_scan_types` len==count). GUARD: no non-na row carries `collapsed_*`. DB cross-check: raw `scan_results` holds >=2 na rows while the API shows 1 | **scanner-collapse** | **COVERED** — server-side/API-observable (OQ#3); a pre-#2471 backend returns >=2 separate not_applicable rows with no `collapsed_*` field -> tier red |

## OQ#3 RESOLVED — server-side / API-observable (NOT UI-only) => oracle BUILT

The build plan (OQ#3) said to confirm `collapse_*` runs server-side in the
scan-results API payload before building an oracle, and to mark #2471 out of DTF
scope if it were only a web-render change. **Verified against `candidate-a4d7f9d1`:
it is server-side.**

- `collapse_not_applicable_rows` lives in `api/handlers/security.rs` and is
  called by **three scan-results API handlers** before serialization:
  `list_scans` (`GET /api/v1/security/scans`), `list_artifact_scans`
  (`GET /api/v1/security/artifacts/{id}/scans`), and `list_repo_scans`
  (`GET /api/v1/repositories/{key}/security/scans`).
- The fold is visible **on the wire**: the summary `ScanResponse` carries
  `collapsed_not_applicable_count: Option<i32>` and
  `collapsed_scan_types: Option<Vec<String>>` (both `skip_serializing_if =
  Option::is_none`), and its `scan_type`/`status` become `"not_applicable"` with
  `error_message = "Not applicable to this artifact"`.
- Collapse fires only for groups of **>= 2** not_applicable rows per artifact; a
  lone not_applicable row passes through untouched; non-na rows pass verbatim.

Because it is genuinely API-observable, the oracle is BUILT (not marked
out-of-scope). Deterministic driver: a `.bin` artifact (outside
`TrivyFsScanner`'s scannable extensions) makes image + filesystem + incus all
decline by TYPE — three fast `not_applicable` rows, no engine call, no trivy-DB
dependency — which the collapse folds to one.

## Shared-file needs (integrator single-pass)

- **`run.sh` `all` list:** add `scanner-collapse`. Runs green on the single
  candidate image, so it joins the one-image `all` run.
- **`ports.sh`:** NO new published port. Reuses the slot's `${TRIVY_PORT}` from
  `scanners.trivy`.
- **`run.sh` manifest-env passthrough:** NONE new. Only `RATE_LIMIT_ENABLED`,
  already special-cased.
- **New owned files (this packet only):**
  `harness/tiers/scanner-collapse/{manifest,oracle.sh,MATRIX-ROW.md}`. No new
  profile (reuses `scanners.trivy`).

## EXPECT_FAILURE self-test

EXPECT_FAILURE-aware via `end_suite` (no extra code). The "exactly 1
not_applicable row + `collapsed_*` present" assertion is impossible on a non-
collapsing backend (which returns >=2 separate na rows, `collapsed_*` omitted).
To belt-and-suspenders against a real pre-#2471 build, run `EXPECT_FAILURE=1
./harness/run.sh scanner-collapse --backend-image <pre-#2471>` and confirm the
tier exits 0. No pre-fix image is required for the primary gate.
