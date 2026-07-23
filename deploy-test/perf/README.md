# PTF — Performance Test Framework

Performance sibling of DTF. A DTF **tier** is a correctness oracle (RED->GREEN);
a PTF **profile** is a repeatable performance scenario that measures the service
and compares against a stored per-version baseline (**baseline->delta**:
PASS / REGRESSION / IMPROVED).

- Full design + build plan: `../../scratchpad-ptf-design.md`
- Reuses DTF's `../compose.base.yml` + storage overlays under `../profiles/`,
  the corpus `tests/lib/common.sh`, and the slot/port claim discipline.

## Status: Phase 1 complete (`upload-throughput`, GEN=bash)

`upload-throughput` runs end-to-end: stack stand-up, load generation, all four
metric layers into one `metrics.json`, a markdown report, and a
`--baseline`/`--compare` delta verdict. The other four profiles are Phase 2.

## Usage

```bash
# stand up + measure + record the per-version baseline
bash harness/run.sh upload-throughput --backend-image <IMG> --slot 3 --baseline

# stand up + measure + diff against the baseline (default when a baseline exists)
bash harness/run.sh upload-throughput --backend-image <IMG> --slot 3 --compare
#   -> exit 0 on PASS/IMPROVED, exit 1 on REGRESSION (fleet/CI gate signal)

# deliberately-throttled run to exercise the regression path
bash harness/run.sh upload-throughput --backend-image <IMG> --slot 3 --compare --throttle-ms 60

bash harness/run.sh ports --slot 3        # show the slot's port block
```

Flags: `--baseline` | `--compare` (auto when a baseline exists), `--keep` (leave
the stack up), `--slot N`, `--version V` (default: image tag), `--throttle-ms MS`
(injects per-request client latency to force a regression).

## Layout

```
perf/
  compose.metrics.yml        # overlay: unauth /metrics (METRICS_PORT) + pg_stat_statements
                             #          + re-namespaces the slot to ak-perf<N>
  harness/
    run.sh                   # entrypoint: stand-up, warm-up, RUNS iterations, median, verdict
    lib/ports.sh             # PERF slot/port block (8300+N etc.), collision-free vs DTF
    lib/collect.sh           # 4-layer capture -> normalized per-iteration metrics.json
    lib/report.sh            # median-combine + baseline->delta verdict + report.md
  profiles/upload-throughput/
    manifest                 # GEN, storage overlay, RUNS, workload sweep knobs
    scenario.sh              # GEN=bash generator (concurrency/size/format sweep + bigfile + dedup)
    thresholds               # per-metric regression budget
  baselines/<version>/<profile>.json   # committed known-good number
  results/<profile>/                   # metrics.json + report.md + raw jsonl (gitignored)
```

## The four metric layers (all in one `metrics.json`)

| Layer | Source | Signals |
|---|---|---|
| A client | the load generator's raw per-request log | p50/p90/p95/p99, MB/s, req/s, error-rate, tail p99/p50 |
| B resource | `docker stats` @1Hz + synchronous end-sample | backend/pg CPU%, peak/mean RSS, block IO |
| C backend-internal | AK unauth `/metrics` (start/end + @1Hz) + `pg_stat_statements` | server mean latency, db-pool saturation, in-flight peak, 5xx, slow queries |
| D storage | docker-volume `du` ground-truth (gauge lags on a scheduler tick) | bytes uploaded, storage delta, dedup ratio |

Recon-grounded caveats (verified against 1.6.2-rc): `ak_http_request_duration_seconds`
is a Prometheus *summary* (no buckets) so Layer C latency is a server-side MEAN,
not p95; the storage/artifact gauges refresh on a scheduler tick and read 0 during
a short run, so Layer D uses volume `du`; no webhook/proxy-cache/upload-size series
are emitted by this build (those fields are `null`, reported as n/a).

## Noise control

Every profile runs one warm-up iteration (discarded) then `RUNS` measured
iterations; the reported number is the **median**. Runs claim a dedicated slot
and never co-schedule (rocky wedges on CPU load). NOTE: absolute p95/MB/s still
drift ~2-3x run-to-run on the shared rig (k3s/kube co-tenant load) — capture the
committed baseline on a **quiesced** slot, and see the Phase-2 notes about making
the between-run delta more robust (trimmed mean / higher RUNS / per-metric
env-tolerance).
