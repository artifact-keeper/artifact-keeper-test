# PTF — Performance Test Framework

Performance sibling of DTF. A DTF **tier** is a correctness oracle (RED->GREEN);
a PTF **profile** is a repeatable performance scenario that measures the service
and compares against a stored per-version baseline (**baseline->delta**:
PASS / REGRESSION / IMPROVED).

- Full design + build plan: `../../scratchpad-ptf-design.md`
- Reuses DTF's `../compose.base.yml` + storage overlays under `../profiles/`,
  the corpus `tests/lib/common.sh`, and the slot/port claim discipline.

## Status: Phase 2a complete — shared harness hardened + ready for fan-out

`upload-throughput` runs end-to-end on BOTH generator paths (GEN=bash and
GEN=k6). The harness is now hardened so the baseline->delta verdict is stable on
the noisy shared rig, the k6 containerized generator path is wired, and a bulk
seeder exists for the scale profiles. The other four profiles are Phase 2b.

### What Phase 2a added
- **Stable verdict.** The per-run combine is a **trimmed mean** (drop the single
  highest + lowest iteration), default `RUNS=5` (configurable), plus warm-up
  discard. Each baseline-relative guard fires REGRESSION only when it breaches
  **both** its percentage budget **and** an absolute **tolerance band** (the
  rig's noise floor), so drift within noise no longer flaps the gate. Percentile
  metrics (p95, tail ratio) get wider bands than deterministic ones. All budgets
  + bands are env-overridable via `PTF_<NAME>`.
- **Rig-quiesce guard.** `--baseline` refuses to run if the host 1-min loadavg
  exceeds `QUIESCE_LOADAVG_MAX` (default ~0.6*nproc); override with
  `--force-baseline`. Baselines must be captured quiesced.
- **k6 generator path.** `GEN=k6` runs the containerized `grafana/k6` generator
  (`scenario.js`) joined to the slot's compose network; its summary maps into the
  SAME normalized `metrics.json`. Selectable per invocation (`--gen k6` / `GEN=k6`).
- **Bulk seeder.** `harness/lib/seed.sh` DB-direct-inserts K artifacts across R
  repos in seconds (~17k rows/s) for the scale profiles.

## Usage

```bash
# stand up + measure + record the per-version baseline (refuses if rig is busy)
bash harness/run.sh upload-throughput --backend-image <IMG> --slot 3 --baseline

# stand up + measure + diff against the baseline (default when a baseline exists)
bash harness/run.sh upload-throughput --backend-image <IMG> --slot 3 --compare
#   -> exit 0 on PASS/IMPROVED, exit 1 on REGRESSION (fleet/CI gate signal)

# drive the SAME profile with the containerized k6 generator instead of bash
GEN=k6 bash harness/run.sh upload-throughput --backend-image <IMG> --slot 3 --compare

# deliberately-throttled run to exercise the regression path
bash harness/run.sh upload-throughput --backend-image <IMG> --slot 3 --compare --throttle-ms 40

# bulk-seed a running slot's DB for a scale profile
bash harness/lib/seed.sh --db-container ak-perf3-db --count 50000 --repos 5 \
     --format generic --size-bytes 4096 --prefix myscale --run-id $RUN_ID

bash harness/run.sh ports --slot 3        # show the slot's port block
```

Flags: `--baseline` | `--compare` (auto when a baseline exists) | `--force-baseline`,
`--keep`, `--slot N`, `--version V` (default: image tag), `--throttle-ms MS`,
`--runs N` (`PTF_RUNS`), `--warmup N` (`PTF_WARMUP`), `--gen bash|k6` (`GEN=`).

## Layout

```
perf/
  compose.metrics.yml        # overlay: unauth /metrics (METRICS_PORT) + pg_stat_statements
                             #          + re-namespaces the slot to ak-perf<N>
  harness/
    run.sh                   # entrypoint: stand-up, quiesce-guard, warm-up, RUNS iters, combine, verdict
    lib/ports.sh             # PERF slot/port block (8300+N etc.), collision-free vs DTF
    lib/collect.sh           # 4-layer capture -> normalized per-iteration metrics.json; k6 runner + token fetch; quiesce guard
    lib/report.sh            # trimmed-mean combine + baseline->delta verdict (budget + band) + report.md
    lib/seed.sh              # bulk DB-direct dataset seeder for the scale profiles
  profiles/upload-throughput/
    manifest                 # GEN, storage overlay, RUNS/WARMUP, workload knobs
    scenario.sh              # GEN=bash generator (concurrency/size/format sweep + bigfile + dedup)
    scenario.js              # GEN=k6 generator (VU upload workload; handleSummary -> Layer-A schema)
    thresholds               # per-metric regression budget + noise-floor bands
  baselines/<version>/<profile>.json   # committed known-good number
  results/<profile>/                   # metrics.json + report.md + raw jsonl (gitignored)
```

## The four metric layers (all in one `metrics.json`)

| Layer | Source | Signals |
|---|---|---|
| A client | the generator (bash raw log OR k6 summary) | p50/p90/p95/p99, MB/s, req/s, error-rate, tail p99/p50 |
| B resource | `docker stats` @1Hz + synchronous end-sample | backend/pg CPU%, peak/mean RSS, block IO |
| C backend-internal | AK unauth `/metrics` (start/end + @1Hz) + `pg_stat_statements` | server mean latency, db-pool saturation, in-flight peak, 5xx, slow queries |
| D storage | docker-volume `du` ground-truth (gauge lags on a scheduler tick) | bytes uploaded, storage delta, dedup ratio |

Recon-grounded caveats (verified against 1.6.2-rc): `ak_http_request_duration_seconds`
is a Prometheus *summary* (no buckets) so Layer C latency is a server-side MEAN,
not p95; the storage/artifact gauges refresh on a scheduler tick and read 0 during
a short run, so Layer D uses volume `du`; no webhook/proxy-cache/upload-size series
are emitted by this build (those fields are `null`, reported as n/a).

---

## `scan-cost` profile (scan-stack resource cost model)

`profiles/scan-cost/` profiles the vulnerability-scan stack
(scanner-adapter + Trivy + in-backend grype) resource cost vs the scan-submission
RATE, to feed a per-component cost model (baseline backend+pg + scan tier). It
stacks the existing `scanners.trivy` overlay, enables real scans over a REAL
vulnerable fixture (grype/trivy find genuine CVEs), sweeps steady rates
(`SCAN_RATES`) + a repo-wide-rescan burst, and captures per-container CPU cores
+ RSS via **cgroup `cpu.stat` accounting** (host-side, so it works on the
shell-less hardened backend image and catches short bursty scan CPU that
`docker stats` sampling misses). Headline side-artifact:
`results/scan-cost/scan-cost.{json,md}` — a per-rate table of scan-stack
cores/RSS/scans-min/in-flight-vs-cap; the standard `metrics.json`/`report.md`
still capture the backend under scan load.

```bash
bash harness/run.sh scan-cost --backend-image <IMG> --slot 5 --baseline
# quick: FIXTURE_PACKAGES=150 SCAN_RATES="10 60" SUSTAIN_SECS=20 POOL_ARTIFACTS=6 \
#        BURST_ARTIFACTS=12 bash harness/run.sh scan-cost --backend-image <IMG> --slot 5
```

Empirical finding (baseline-main, filesystem/lockfile scan path): the adapter's
dominant cost is a **fixed ~1.2 GiB RSS (the Trivy vuln DB), flat across rate**;
adapter CPU is trivial (<0.02 cores) because lockfile scans are CPU-light; the
scan **CPU** cost lives in the BACKEND orchestration and scales with rate
(~0.06 cores @6/min → ~0.76 cores peak at burst). The heavy-CPU container-IMAGE
scan path (trivy image = layer unpack + OS-package scan) needs an OCI push driver
and is the next increment. NB: `scans/min`/in-flight under-read at high rate
because the repo scans list collapses `not_applicable` rows — the cgroup cores
are unaffected.

---

## `opensearch-cost` profile (search-index cost model)

`profiles/opensearch-cost/` profiles OpenSearch resource cost vs stored ARTIFACT
COUNT (the COUNT-driven component, unlike scan/dtrack which are rate/count-of-
SBOM driven). It stacks a new `opensearch` overlay (`profiles/opensearch.yml`,
opensearchproject/opensearch:2.19.1, the product pin), and for each rung in
`COUNTS` (default 10k/100k/500k): DB-direct-seeds the artifacts, runs a full
`POST /api/v1/admin/reindex` bulk index capturing INGEST cores, records the
index store bytes, then fires a `/search/quick` mix capturing STEADY-STATE QUERY
cores — separately. Cores/RSS via host-side cgroup accounting. Headline:
`results/opensearch-cost/opensearch-cost.{json,md}`.

```bash
bash harness/run.sh opensearch-cost --backend-image <IMG> --slot 5 --baseline
# quick: COUNTS="10000 50000" QUERY_SECS=15 bash harness/run.sh opensearch-cost --backend-image <IMG> --slot 5
```

Empirical finding (baseline-main): index bytes scale linearly (~300 B/artifact:
3/30/149 MiB at 10k/100k/500k); OS RSS grows with count (1.1 → 1.7 GiB);
INGEST is an O(N) one-time bulk at ~1.5-2 cores (duration 1s/5s/23s); steady
QUERY CPU stays low (<0.05 cores mean) but query LATENCY grows sharply with
count (p50 129ms → 1.3s → 2.1s). The manifest disables the DTF-base rate limiter
so the query-CPU sample isn't polluted by 429s. NB: the reindex measures the
bulk-cutover ingest cost; per-upload single-doc indexing is a separate cheap
async op. The broad prefix query is a worst-case (matches all seeded docs); a
selective query is faster.

---

## `dtrack-cost` profile (Dependency-Track cost model)

`profiles/dtrack-cost/` profiles Dependency-Track's fixed heavy-JVM RSS floor +
cores + its Postgres DB growth vs the number of SBOMs/components tracked. It
stacks a new `dependency-track` overlay (`profiles/dependency-track.yml`,
dependencytrack/apiserver:4.14.2 + a `dependency_track` DB on the shared
Postgres), provisions a permissioned API key from the default admin at run time
(the init-dtrack login→team→grant→key flow), measures the IDLE JVM floor, then
uploads synthetic CycloneDX SBOMs (`COMPONENTS_PER_BOM` each) in cumulative
`RUNG_BOMS` rungs, capturing DT cores/RSS during ingest + the dependency_track
DB size. Headline: `results/dtrack-cost/dtrack-cost.{json,md}`.

```bash
bash harness/run.sh dtrack-cost --backend-image <IMG> --slot 5 --baseline
# quick: RUNG_BOMS="3 5" COMPONENTS_PER_BOM=50 IDLE_SECS=15 SETTLE_SECS=25 bash harness/run.sh dtrack-cost --backend-image <IMG> --slot 5
```

NVD/OSV mirroring is OFF (network/hours-heavy), so this measures INGEST +
STORAGE; the vuln-ANALYSIS CPU (mirror sync + matching) is a separate periodic
cost reported as unexercised. DT boots slowly (schema migration; ~90s
healthcheck start_period).

See `COST-MODEL.md` for the consolidated four-component cost model.

---

## Shared-harness contract (read this before writing a Phase 2b profile)

A profile is a directory `profiles/<name>/` with three files. The harness
(`run.sh` + `lib/*`) is generator-agnostic and profile-agnostic; a profile only
declares WHAT to run and WHAT budget to hold it to. You do NOT edit `run.sh`,
`report.sh`, or the combine/verdict logic.

### 1. `profiles/<name>/manifest` — declare the scenario
Sourced KV. Required: `GEN` (`bash`|`k6`), `PROFILES` (DTF storage overlay
basename(s), e.g. `storage.filesystem`). For `GEN=bash` set `SCENARIO`
(default `scenario.sh`); for `GEN=k6` set `SCENARIO_K6` (default `scenario.js`).
Optional: `THRESHOLDS` (default `thresholds`), `RUNS` (default 5), `WARMUP`
(default 1), plus any workload knobs your scenario reads (they are just env vars
you export downstream — add your own; existing ones: `CONCURRENCY`, `FORMATS`,
`SWEEP_SIZE_MB`, `REQUESTS_PER_CELL`, `BIGFILE_*`, `DEDUP_COUNT`). One profile
may ship both a `scenario.sh` and a `scenario.js` and be driven either way.

### 2. `profiles/<name>/scenario.sh` (GEN=bash) or `scenario.js` (GEN=k6) — the load
- **bash:** source `$COMMON_SH` for auth/repo helpers, drive the workload, and
  append ONE line per request to `$RAW_LOG` in the exact field order
  `<phase> <concurrency> <format> <size_bytes> <http_code> <time_total_s> <upload_bytes>`.
  `collect.sh` reduces that into Layer A (percentiles, MB/s, error-rate, tail).
  Inputs are exported by `run.sh`: `BASE_URL`, `ADMIN_USER`, `ADMIN_PASS`,
  `ADMIN_TOKEN` (after `auth_admin`), `RUN_ID`, `PERF_WORK_DIR`, `RAW_LOG`, `ITER`.
- **k6:** an ES-module scenario. The container gets `BASE_URL`
  (`http://backend:8080`, in-network), `TOKEN`, `RUN_ID`, `RUN_NONCE` (unique per
  iteration — fold it into upload paths to avoid 409 on immutable re-PUT), `VUS`,
  `ITERATIONS`, `SIZE_BYTES`, `THROTTLE_MS`. Your `handleSummary()` MUST write
  `/out/summary.json` shaped as the Layer-A `app` object:
  `{requests, errors, error_rate, throughput_rps, throughput_mbps, bytes_uploaded,
  max_concurrency, latency_ms:{p50,p90,p95,p99,max}}`. The harness already passes
  `--summary-trend-stats="avg,min,med,max,p(50),p(90),p(95),p(99)"`. See
  `upload-throughput/scenario.js` as the reference.

### 3. `profiles/<name>/thresholds` — declare the budget + bands
Sourced KV. Override only what you care about; unset keys fall to the defaults in
`report.sh`. Percentage budgets compare to the baseline; `*_ABS_*` are absolute
hard ceilings. Each baseline-relative metric ALSO needs a **tolerance band** (the
noise floor) — a REGRESSION requires breaching both. Keys:
`P95_REGRESSION_PCT` + `P95_TOLERANCE_MS`; `THROUGHPUT_REGRESSION_PCT` +
`THROUGHPUT_TOLERANCE_MBPS`; `RSS_REGRESSION_PCT` + `RSS_TOLERANCE_BYTES`;
`TAIL_FAIRNESS_RATIO_PCT` + `TAIL_TOLERANCE_RATIO`; hard ceilings
`ERROR_RATE_ABS_MAX`, `POOL_SAT_ABS_MAX`. Every one is env-overridable as
`PTF_<KEY>`. Give percentile/tail metrics WIDER bands than deterministic ones.

### metrics.json fields a profile must populate
The combine + verdict currently guard: `app.latency_ms.p95`,
`app.throughput_mbps`, `resource.backend.rss_bytes_peak`,
`app.tail_at_max_conc.p99_over_p50`, `app.error_rate`,
`backend_internal.db_pool.saturation_pct_peak`. Layer A is generator-produced;
Layers B/C/D are captured by the harness automatically (docker stats, `/metrics`
scrape, volume `du`) as long as your scenario actually drives the backend — you
do not write them. If your profile guards a NEW metric (e.g. a scaling-slope or
cache-hit-ratio), add its guard + band to `report.sh` and its budget to your
`thresholds` (extend, do not fork).

### Scale profiles: use `seed.sh`
`metadata-scale` / `search-at-scale` / `million-artifact-lite` seed with
`harness/lib/seed.sh --db-container ak-perf<N>-db --count K --repos R --format F
--size-bytes S --prefix <p> --run-id $RUN_ID`. It DB-direct-inserts artifacts (+
`artifact_metadata`) round-robin across R repos; list/quick+advanced search/
`admin/stats`/repo-browse all see the rows. `--blobs 1 --volume ak-perf<N>_data`
additionally writes a minimal placeholder blob per repo (downloads are otherwise
not backed — the scale profiles measure the metadata/read plane, not transfer).

### Guardrails carried from the rig memory
Runs claim a dedicated slot and never co-schedule (rocky wedges on CPU load).
Baselines are per-`(version, profile, GENERATOR)` — **a k6 baseline and a bash
baseline are NOT interchangeable** (different client, different numbers), so
compare k6-to-k6 and bash-to-bash only. Capture baselines on a quiesced slot (the
guard enforces it). Clean stale `/tmp` clones before a big fleet campaign.
