# Artifact Keeper — Component Cost Model (measured)

Consolidated output of the PTF cost profiles (`scan-cost`, `opensearch-cost`,
`dtrack-cost`). Every number below is measured on the shared rig against
`ak-backend:baseline-main`, with per-container CPU cores + RSS captured via
host-side cgroup `cpu.stat`/`memory.current` accounting (exact CPU-seconds/sec,
independent of sampling jitter; works on the shell-less hardened backend image).
Reproduce/refresh any row with `bash harness/run.sh <profile> --backend-image
<IMG> --slot N --baseline`.

**cores** = CPU-seconds per wall second (host-normalized; 1.0 = one full core).
**All four auxiliary components are OPT-IN** — each is dark unless its env is set
(`TRIVY_ADAPTER_URL` / `OPENSEARCH_URL` / `DEPENDENCY_TRACK_ENABLED`), so a bare
AK is just `backend + postgres`. That makes each a clean pricing tier.

---

## The one-line cost driver per component

| Component (tier) | Opt-in gate | Cost DRIVER | Fixed floor | Slope |
|---|---|---|---|---|
| **scanner-adapter + Trivy** | `TRIVY_ADAPTER_URL` | scan RATE (uploads×scan-on-upload, or re-scan bursts) | **~1.2 GiB RSS** (Trivy vuln DB), flat | CPU trivial for fs/lockfile scans; **container-IMAGE scan = the heavy path (unmeasured)** |
| **backend scan orchestration** | (same tier) | scan RATE | ~0 | ~0.06 cores @6 scans/min → **~0.76 cores peak at burst**; hard-capped ~4 concurrent |
| **OpenSearch** | `OPENSEARCH_URL` | stored artifact COUNT | ~1.1 GiB RSS (512m heap + base) | index **~300 B/artifact**; RSS → 1.7 GiB @500k; **ingest O(N) ~1.5-2 cores**; query LATENCY grows with count |
| **Dependency-Track** | `DEPENDENCY_TRACK_ENABLED` | # components tracked | **~726 MiB idle JVM** (+ its own PG) | DB **~4.5 KB/component**; ingest **9-11 cores peak** (mean → 3.5); RSS → 2.4 GiB; **vuln-analysis CPU unmeasured** |

Cost-driver classes: **scan = RATE-driven**, **OpenSearch = COUNT-driven**,
**Dependency-Track = big fixed STEP + per-component slope**. None of the compute
scales with stored artifact count *except* OpenSearch (index/RSS) and DT (its own
DB) — a registry that has finished ingesting and does no re-scan burns ~0
incremental scan/DT-ingest CPU.

---

## 1. Scan tier — scanner-adapter + Trivy + in-backend grype  (`scan-cost`)

Driven by REAL uploads of a real vulnerable fixture + real scans (per-artifact
trigger at steady rates + a repo-wide-rescan burst). Baseline (filesystem/
lockfile scan path):

| rate/min | scans/min | adapter cores pk/mean | adapter RSS | backend cores peak | in-flight vs cap |
|---|---|---|---|---|---|
| 6 | 20.9 | 0.013 / 0.002 | 1184 MiB | 0.057 | 0 / 4 |
| 30 | 52.4 | 0.013 / 0.003 | 1184 MiB | 0.247 | 3 / 4 |
| 120 | (soft) | 0.014 / 0.003 | 1186 MiB | 0.283 | 2 / 4 |
| burst (repo rescan) | — | 0.019 / 0.003 | 1186 MiB | 0.758 | — |

- **Dominant cost = a fixed ~1.2 GiB adapter RSS** (the Trivy vuln DB), flat vs
  rate. Adapter CPU is trivial (<0.02 cores) — lockfile/fs scans are CPU-light.
- The scan **CPU** lives in the **backend orchestration** (extraction, DB
  writes, fan-out) and scales with rate, hard-capped at ~4 concurrent
  (`MAX_CONCURRENT_SCAN_EXTRACTIONS`) — an ingest spike lengthens the queue, not
  the peak CPU.
- **Unmeasured (honest gap):** the container-IMAGE scan path (Trivy image = layer
  unpack + OS-package scan) is the recon-identified heavy-CPU path; it needs an
  OCI push driver (the daemon allows `127.0.0.0/8` insecure push, but no
  crane/skopeo/oras is on the rig). Filed as the next increment.

## 2. Search tier — OpenSearch  (`opensearch-cost`)

Seed to each count rung, full `/admin/reindex` bulk (ingest), then a
`/search/quick` mix (steady query). Baseline:

| artifact count | index bytes | ingest s | ingest OS cores pk/mean | OS RSS (ingest) | query qps | query OS cores mean | query p50 / p95 |
|---|---|---|---|---|---|---|---|
| 10,000 | 3 MiB | 1.1 | 4.82 / 4.82 | 1094 MiB | 28.1 | 0.022 | 129 / 157 ms |
| 100,000 | 30 MiB | 5.1 | 1.87 / 1.69 | 1231 MiB | 3.3 | 0.035 | 1314 / 1361 ms |
| 500,000 | 149 MiB | 23.4 | 2.90 / 1.48 | 1729 MiB | 1.5 | 0.010 | 2112 / 4851 ms |

- **Index bytes scale linearly ~300 B/artifact** (3/30/149 MiB) → extrapolates to
  ~1.5 GiB at 5M. **OS RSS grows with count** (1.1 → 1.7 GiB @500k): the JVM
  working set + segment caches, on top of the 512m heap floor.
- **INGEST is a one-time O(N) bulk** at ~1.5-2 cores sustained (duration scales
  1s/5s/23s with count) — the cost of a cold cutover / full reindex. Steady
  per-upload indexing is a separate cheap async single-doc op (not the reindex).
- **Query CPU stays low (<0.05 cores mean)** but **query LATENCY grows sharply
  with count** (p50 129 ms → 2.1 s; p95 4.8 s @500k). Caveat: the profile's broad
  prefix query matches ALL seeded docs (worst case); a selective query is faster.
  The takeaway for sizing: at 500k a busy search UI needs more OS heap/CPU to
  hold latency, and search routes have no rate limit (recon).

## 3. SBOM tier — Dependency-Track  (`dtrack-cost`)

Stand up DT (+ its own `dependency_track` Postgres DB), provision a permissioned
API key, measure the idle JVM floor, then upload synthetic CycloneDX SBOMs (100
components each) in cumulative rungs. Baseline:

**Idle JVM floor (the fixed per-enable STEP):** RSS **726 MiB**, ~0.006 cores,
own DB base 17 MiB.

| components | DT cores pk/mean | DT RSS | DT-DB delta | DT-DB total |
|---|---|---|---|---|
| 1,000 | 11.34 / 0.74 | 1626 MiB | +2 MiB | 19 MiB |
| 5,000 | 9.74 / 1.98 | 1626 MiB | +36 MiB | 53 MiB |
| 20,000 | 11.11 / 3.50 | 2382 MiB | +89 MiB | 106 MiB |

- **Enabling DT is a large fixed STEP** (~726 MiB idle JVM + a dedicated Postgres
  DB), even with zero SBOMs.
- **Ingest is very CPU-hungry: 9-11 cores PEAK** (DT parallelizes BOM
  processing/analysis events aggressively); sustained mean rises with load
  (0.74 → 3.5 cores). This is bursty per-upload cost, not a steady floor.
- **DT's own Postgres grows ~4.5 KB/component** (20k comp → +89 MiB); **RSS
  climbs to ~2.4 GiB** under sustained ingest.
- **Unmeasured (honest gap):** NVD/OSV mirroring is OFF (network/hours-heavy), so
  the vuln-ANALYSIS CPU (mirror sync + per-component matching) is NOT in these
  numbers — it is a separate periodic cost on top of ingest. Note also the idle
  ~726 MiB is far below the ~4 GiB rule-of-thumb, which assumes a large
  configured heap + a populated NVD mirror.

---

## Pricing-tier guidance (set on measured numbers)

- **Baseline (backend + pg only):** all four tiers dark. Cheapest SKU.
- **Scan tier** (+scanner-adapter+Trivy): price a **fixed ~1.2 GiB RAM** reservation
  (vuln DB) + a **rate-metered CPU** allowance (≤~4 cores worst-case burst, backend
  side; adapter CPU ~free for fs scans). Biggest lever: `scan_on_upload` on/off +
  re-scan cadence. Image-scan CPU is a further add-on once the image path is priced.
- **Search tier** (+OpenSearch): price **RAM + disk that scale with stored artifact
  COUNT** (~300 B/artifact index + a 1.1→1.7 GiB RSS band to 500k) + a **one-time
  reindex CPU burst** (~1.5-2 cores × O(N) seconds) at cutover. Query CPU is cheap;
  query LATENCY at scale is the SLA knob (more heap/replicas).
- **SBOM tier** (+Dependency-Track): price a **large fixed STEP** (~1-2.4 GiB JVM RAM
  + its own Postgres) the moment it is on, plus a **per-component DB slope
  (~4.5 KB/comp)** and a **bursty ingest-CPU** allowance (up to ~3.5 cores sustained,
  9-11 peak). The vuln-analysis CPU (NVD mirror) is a further periodic add-on.

**Net:** the scan and DT tiers are CPU-bursty and RAM-heavy (fixed floors);
OpenSearch is the one that scales its RAM/disk with stored artifact count. A
500k-artifact customer's incremental bill is dominated by (a) OpenSearch
RAM/disk (~1.7 GiB + 150 MiB index), (b) the fixed DT JVM step if SBOMs are on,
and (c) rate-metered scan/DT-ingest CPU bursts — *not* by a per-stored-artifact
compute cost.

_Method note: all cores/RSS from host-side cgroup accounting; profiles at
`profiles/{scan-cost,opensearch-cost,dtrack-cost}/`, overlays at
`../profiles/{scanners.trivy,opensearch,dependency-track}.yml`, baselines at
`baselines/baseline-main/`. Numbers are single-run on a shared rig (indicative,
not certified); re-run `--baseline` on a quiesced slot to tighten._
