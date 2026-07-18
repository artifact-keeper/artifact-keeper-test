# MATRIX-ROW — debian-remote (PKT-A, epic #2458)

Integrator: merge the two rows below into `matrix.md` (new rows after #12; both
are one tier, `debian-remote`). Keep the must-have framing consistent.

| # | Class / capability | Profile-set | Discriminating oracle | DTF tier | Status |
|---|---|---|---|---|---|
| 13 | **Debian remote proxy integrity** (index sha/size vs signed Release) — #2459 (epic #2458) | upstreams=**debian** (+ filesystem/single) | mock APT upstream serves a clean `bookworm` + a tampered `bookworm-evil` (Release pins the clean sha, served Packages is poisoned). `enforce_dists_integrity`: clean index 200 (body hashes to the Release-pinned sha); tampered index **502** "integrity verification" + repeat GET still 502 (no poisoned-cache serve) | **debian-remote** | **COVERED** — self-discriminating via the clean-vs-tampered fixture (no pre-fix image needed); a backend missing the guard serves the tampered index 200 -> tier red |
| 14 | **Debian dist/component/arch filtering** — #2460 (epic #2458) | upstreams=**debian** (+ filesystem/single) | set `debian_config` = `{distribution_paths:[bookworm],components:[main],architectures:[amd64]}` via the repo-update `debian` field: included `main/binary-amd64` 200; filtered-out `contrib` and `binary-arm64` **404** (`debian_filter_denied`). Allow-all guard: clear the filter (`debian:null`) and both re-serve 200 (proves the 404 is filter-driven, not a dead route) | **debian-remote** | **COVERED** — self-discriminating via filtered-vs-included + the allow-all guard; a backend ignoring the filter serves the excluded targets 200 -> tier red |

## Shared-file needs (integrator single-pass)

- **`run.sh` `all` list:** add `debian-remote`. It runs green on the single
  candidate image (`ak-backend:candidate-a4d7f9d1`), so it can join the one-image
  `all` run alongside smoke/isolation/etc.
- **`ports.sh`:** NO new published port. `deb-upstream` is reached
  container-to-container on the slot's private `debupstream` net
  (172.31.<slot>.0/24); nothing is host-published.
- **`run.sh` manifest-env passthrough:** NONE new. The only manifest override is
  `RATE_LIMIT_ENABLED`, which `run.sh` already special-cases and exports.
- **New owned files (this packet only):** `harness/tiers/debian-remote/{manifest,oracle.sh,MATRIX-ROW.md}`, `profiles/upstreams.debian.yml`, `fixtures/debian/build.sh`.

## EXPECT_FAILURE self-test

The oracle is EXPECT_FAILURE-aware via `end_suite` (no extra code). The allow-all
guard already proves filter-drivenness inline. To belt-and-suspenders the fail
path against a real pre-fix build (e.g. a `1.6.0`-minus-#2459/#2460 image), run
`EXPECT_FAILURE=1 ./harness/run.sh debian-remote --backend-image <pre-fix>` and
confirm the tier exits 0 (i.e. it correctly caught the served-tampered-200 /
filtered-out-200 reds). No pre-fix image is required for the primary gate.

## Backend-surface deviations from the build plan (verified against candidate-a4d7f9d1)

- **Config is set via the repo request field `debian` (NOT `debian_config`).**
  The plan (§0/§2 P1) called it `debian_config`; that string is only the internal
  `repository_config` table KEY (`DEBIAN_CONFIG_KEY`). The create request field is
  `debian: DebianRepositoryConfig` and the update field is
  `debian: Option<Option<DebianConfigPatch>>` (`{"debian":null}` clears it).
- **Filter dist key is `distribution_paths`** (accepts `distributions` as an
  alias); components/architectures as specced. Empty list or `["*"]` = allow-all.
- Everything else matches: `/debian/{key}/dists/...` proxy path, 502 body
  "Upstream index failed integrity verification against the signed Release",
  filtered path -> 404 (deliberately not 403).
