// =============================================================================
// profiles/download-concurrency/scenario.js — GEN=k6 generator  (Phase 2b)
// =============================================================================
// Speed + robustness dimension: download tail latency and cache behavior under
// increasing concurrent download load (design doc §6.3). Drives GETs against
//   GET /api/v1/repositories/{key}/download/{path}
// from a PRE-SEEDED working set of M artifacts in a local repo, with bearer auth,
// joined to the slot's compose network (http://backend:8080).
//
// Phases, run SEQUENTIALLY (fixed startTime windows so they never overlap and
// contend — overlap would corrupt the per-level percentiles):
//   1. cold : C=1, GET each of the M keys exactly once  -> Trend dl_cold
//   2. warm : C=1, GET each of the M keys again          -> Trend dl_warm
//              (cold-vs-warm read latency = the storage/OS page-cache signal;
//               the proxy-cache HIT/MISS counter ak_proxy_cache_lookups_total is
//               a PROXY-repo-only series — not emitted on a LOCAL download path,
//               so Layer C shows it n/a here. See the profile's thresholds file.)
//   3. ladder: constant-vus at C in CONC_LADDER (default 1,10,50,100) for
//              LEVEL_SECONDS each, Zipf-skewed key pick -> per-level Trends
//              dl_c{1,10,50,100} + byte/req Counters. The HEADLINE app.latency_ms
//              the harness guards is taken from the MAX-concurrency level, so
//              p95/p99/tail all reflect "at max concurrency" (design §6.3).
//
// handleSummary() writes /out/summary.json shaped as the Layer-A `app` object
// (identical contract to upload-throughput/scenario.js) plus an informational
// `_ladder` (latency-vs-concurrency) and `_cache` (cold/warm) block that the
// harness ignores but is printed to stdout for the operator.
//
// Env passed by harness/lib/collect.sh: perf_run_k6:
//   BASE_URL, TOKEN, RUN_ID, RUN_NONCE, VUS (= max concurrency), ITERATIONS,
//   SIZE_BYTES (per-artifact size), THROTTLE_MS.
// Profile-local knobs (defaults apply; the harness does not set these):
//   SEED_COUNT (M artifacts, def 60), CONC_LADDER (def "1,10,50,100"),
//   LEVEL_SECONDS (per-level duration, def 8), COLDWARM_SECONDS (def 12),
//   ZIPF_POW (power-law skew exponent, def 2.5; higher => hotter hot-keys).
// =============================================================================
import http from 'k6/http';
import { check } from 'k6';
import { Trend, Counter } from 'k6/metrics';
import exec from 'k6/execution';

const BASE = __ENV.BASE_URL;
const TOKEN = __ENV.TOKEN;
const RUN_ID = __ENV.RUN_ID || `k6-${Date.now()}`;
const VUS = parseInt(__ENV.VUS || '100', 10);
const SIZE = parseInt(__ENV.SIZE_BYTES || '2097152', 10);
const THROTTLE = parseInt(__ENV.THROTTLE_MS || '0', 10);
const M = parseInt(__ENV.SEED_COUNT || '60', 10);
const LSEC = parseInt(__ENV.LEVEL_SECONDS || '8', 10);
const CWSEC = parseInt(__ENV.COLDWARM_SECONDS || '12', 10);
const ZPOW = parseFloat(__ENV.ZIPF_POW || '2.5');
const REPO = `perf-dl-${RUN_ID}`;

// concurrency ladder, capped at the VU budget the harness allocated (= max sweep)
let LEVELS = (__ENV.CONC_LADDER || '1,10,50,100')
  .split(',').map((x) => parseInt(x, 10)).filter((x) => x > 0 && x <= VUS);
if (LEVELS.length === 0) LEVELS = [1];
const MAXC = LEVELS[LEVELS.length - 1];

// ---- metrics (created at init) ---------------------------------------------
const tCold = new Trend('dl_cold', true);
const tWarm = new Trend('dl_warm', true);
const levelTrend = {};
const levelBytes = {};
const levelReqs = {};
for (const c of LEVELS) {
  levelTrend[c] = new Trend(`dl_c${c}`, true);
  levelBytes[c] = new Counter(`bytes_c${c}`);
  levelReqs[c] = new Counter(`reqs_c${c}`);
}
const dlAll = new Counter('dl_all');

// ---- upload payload (seed), generated once ----------------------------------
const PAYLOAD = new Uint8Array(SIZE);
for (let i = 0; i < SIZE; i++) { PAYLOAD[i] = (i * 131 + 7) & 0xff; }

const AUTH = { Authorization: `Bearer ${TOKEN}` };

// ---- scenario schedule ------------------------------------------------------
// fixed, non-overlapping startTime windows: cold [0,CW) warm [CW,2CW) then each
// ladder level LSEC apart starting at 2*CW.
const scenarios = {
  cold: {
    executor: 'per-vu-iterations', vus: 1, iterations: M, maxDuration: `${CWSEC}s`,
    startTime: '0s', exec: 'coldRead',
  },
  warm: {
    executor: 'per-vu-iterations', vus: 1, iterations: M, maxDuration: `${CWSEC}s`,
    startTime: `${CWSEC}s`, exec: 'warmRead',
  },
};
LEVELS.forEach((c, i) => {
  scenarios[`c${c}`] = {
    executor: 'constant-vus', vus: c, duration: `${LSEC}s`,
    startTime: `${2 * CWSEC + i * LSEC}s`, exec: 'ladderRead',
    tags: { clevel: String(c) },
  };
});

export const options = {
  scenarios,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(90)', 'p(95)', 'p(99)'],
  discardResponseBodies: true, // we track transferred bytes by known SIZE, not body
};

// ---- seed: create repo + upload M artifacts (idempotent across iterations) ---
export function setup() {
  http.post(
    `${BASE}/api/v1/repositories`,
    JSON.stringify({ key: REPO, name: REPO, format: 'generic', repo_type: 'local', is_public: true }),
    {
      headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
      responseCallback: http.expectedStatuses(200, 201, 409),
    },
  );
  const keys = [];
  for (let i = 0; i < M; i++) {
    const path = `dl/obj-${i}.bin`;
    keys.push(path);
    // FIXED paths (no nonce): the stack persists across warm-up + all measured
    // iterations, so iteration 1 uploads (201) and later iterations 409 (already
    // present, immutable) — both leave the object downloadable. 409 is expected.
    http.put(
      `${BASE}/api/v1/repositories/${REPO}/artifacts/${path}`,
      PAYLOAD.buffer,
      {
        headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/octet-stream' },
        responseCallback: http.expectedStatuses(200, 201, 409),
      },
    );
  }
  return { repo: REPO, keys };
}

// Zipf-like power-law index in [0, n): hot keys cluster at low indices.
function zipfIdx(n) {
  const i = Math.floor(n * Math.pow(Math.random(), ZPOW));
  return i >= n ? n - 1 : i;
}

function get(repo, path) {
  const res = http.get(`${BASE}/api/v1/repositories/${repo}/download/${path}`, { headers: AUTH });
  const ok = res.status === 200;
  check(res, { 'download 200': (r) => r.status === 200 });
  dlAll.add(1);
  return { res, ok };
}

export function coldRead(data) {
  const path = data.keys[exec.scenario.iterationInTest % data.keys.length];
  const { res, ok } = get(data.repo, path);
  if (ok) tCold.add(res.timings.duration);
}

export function warmRead(data) {
  const path = data.keys[exec.scenario.iterationInTest % data.keys.length];
  const { res, ok } = get(data.repo, path);
  if (ok) tWarm.add(res.timings.duration);
}

export function ladderRead(data) {
  const c = parseInt(exec.scenario.name.slice(1), 10); // "c100" -> 100
  const path = data.keys[zipfIdx(data.keys.length)];
  const { res, ok } = get(data.repo, path);
  if (ok) {
    levelTrend[c].add(res.timings.duration);
    levelBytes[c].add(SIZE);
    levelReqs[c].add(1);
  }
  if (THROTTLE > 0) { const t0 = Date.now(); while (Date.now() - t0 < THROTTLE) { /* busy hold */ } }
}

export function handleSummary(data) {
  const m = data.metrics || {};
  const v = (name) => (m[name] && m[name].values) || {};
  const failed = v('http_req_failed');
  const dlall = v('dl_all');

  // headline = MAX-concurrency level percentiles (design §6.3 "at max concurrency")
  const hd = v(`dl_c${MAXC}`);
  const bytesMax = (v(`bytes_c${MAXC}`).count) || 0;
  const reqsMax = (v(`reqs_c${MAXC}`).count) || 0;
  const p = (o, k, alt) => (o[k] != null ? o[k] : (o[alt] || 0));

  const app = {
    requests: dlall.count || 0,
    errors: Math.round((failed.rate || 0) * (dlall.count || 0)),
    error_rate: failed.rate || 0,
    throughput_rps: LSEC > 0 ? reqsMax / LSEC : 0,
    throughput_mbps: LSEC > 0 ? bytesMax / 1000000 / LSEC : 0,
    bytes_uploaded: 0, // download profile: measured phase transfers OUT, not IN
    max_concurrency: MAXC,
    latency_ms: {
      p50: p(hd, 'p(50)', 'med'),
      p90: hd['p(90)'] || 0,
      p95: hd['p(95)'] || 0,
      p99: hd['p(99)'] || 0,
      max: hd.max || 0,
    },
  };

  // informational: latency-vs-concurrency ladder + cold/warm cache signal.
  const ladder = LEVELS.map((c) => {
    const lv = v(`dl_c${c}`);
    return {
      c,
      reqs: (v(`reqs_c${c}`).count) || 0,
      p50: p(lv, 'p(50)', 'med'),
      p95: lv['p(95)'] || 0,
      p99: lv['p(99)'] || 0,
      max: lv.max || 0,
      mbps: LSEC > 0 ? ((v(`bytes_c${c}`).count) || 0) / 1000000 / LSEC : 0,
    };
  });
  const cold = v('dl_cold');
  const warm = v('dl_warm');
  const cache = {
    cold_p50: p(cold, 'p(50)', 'med'), cold_p95: cold['p(95)'] || 0,
    warm_p50: p(warm, 'p(50)', 'med'), warm_p95: warm['p(95)'] || 0,
    warm_speedup_p50: (warm['med'] > 0) ? (p(cold, 'p(50)', 'med') / p(warm, 'p(50)', 'med')) : 0,
  };
  app._ladder = ladder;
  app._cache = cache;

  let out = 'download-concurrency latency vs concurrency:\n';
  out += '  C   reqs   p50(ms)  p95(ms)  p99(ms)  MB/s\n';
  for (const r of ladder) {
    out += `  ${String(r.c).padStart(3)} ${String(r.reqs).padStart(6)} `
      + `${r.p50.toFixed(1).padStart(8)} ${r.p95.toFixed(1).padStart(8)} `
      + `${r.p99.toFixed(1).padStart(8)} ${r.mbps.toFixed(1).padStart(6)}\n`;
  }
  const tailMax = app.latency_ms.p50 > 0 ? app.latency_ms.p99 / app.latency_ms.p50 : 0;
  out += `  tail p99/p50 @C${MAXC} = ${tailMax.toFixed(2)}\n`;
  out += `cache (cold vs warm read, C=1): cold_p50=${cache.cold_p50.toFixed(1)}ms `
    + `warm_p50=${cache.warm_p50.toFixed(1)}ms speedup=${cache.warm_speedup_p50.toFixed(2)}x\n`;
  out += `error_rate=${(app.error_rate).toFixed(4)}  downloads=${app.requests}\n`;

  return { '/out/summary.json': JSON.stringify(app), stdout: out };
}
