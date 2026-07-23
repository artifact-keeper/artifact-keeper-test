// =============================================================================
// profiles/upload-throughput/scenario.js — GEN=k6 generator  (Phase 2a)
// =============================================================================
// The k6 alternative to scenario.sh. Drives the SAME upload workload
// (PUT /api/v1/repositories/{key}/artifacts/{path}) with bearer auth, joined to
// the slot's compose network so it reaches the backend by its in-network
// service name (http://backend:8080). handleSummary() maps k6's native metrics
// into the EXACT Layer-A schema the bash path produces, so collect.sh /
// report.sh stay generator-agnostic (design doc §1/§3): only the summary->schema
// mapping differs, and it lives here (emitted) + a straight jq read in collect.sh.
//
// Env (passed by harness/lib/collect.sh: perf_run_k6):
//   BASE_URL              in-network backend base (http://backend:8080)
//   TOKEN                 admin bearer token (fetched once by the harness)
//   RUN_ID                unique run id (repo-name scoping)
//   VUS                   concurrent virtual users (= max sweep concurrency)
//   ITERATIONS            total upload requests
//   SIZE_BYTES            per-upload payload size
//   THROTTLE_MS           optional per-request sleep (deliberate-regression knob)
//
// Output: /out/summary.json  (mounted results dir) — the normalized `app` object.
// =============================================================================
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.BASE_URL;
const TOKEN = __ENV.TOKEN;
const RUN_ID = __ENV.RUN_ID || `k6-${Date.now()}`;
const VUS = parseInt(__ENV.VUS || '8', 10);
const ITER = parseInt(__ENV.ITERATIONS || '150', 10);
const SIZE = parseInt(__ENV.SIZE_BYTES || '4194304', 10);
const THROTTLE = parseInt(__ENV.THROTTLE_MS || '0', 10);
const REPO = `perf-k6-${RUN_ID}`;
// per-invocation nonce so warm-up + each measured iteration write UNIQUE paths
// into the (shared) repo — an immutable artifact 409s on a re-PUT otherwise.
const NONCE = __ENV.RUN_NONCE || `${Date.now()}`;

// One payload, generated once at module load. Non-trivial byte pattern so the
// backend cannot trivially collapse it (keeps the transfer honest).
const PAYLOAD = new Uint8Array(SIZE);
for (let i = 0; i < SIZE; i++) { PAYLOAD[i] = (i * 131 + 7) & 0xff; }

export const options = {
  scenarios: {
    upload: {
      executor: 'shared-iterations',
      vus: VUS,
      iterations: ITER,
      maxDuration: '10m',
    },
  },
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(90)', 'p(95)', 'p(99)'],
  // treat only >=400 as failed (k6 default); keeps error_rate == HTTP error rate
};

const AUTH = { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/octet-stream' };

export function setup() {
  // The same REPO is (re)created once per k6 invocation (warm-up + each measured
  // iteration is a fresh container). On the 2nd+ run the create returns 409;
  // mark 200/201/409 expected on THIS request only so the benign 409 does not
  // count against http_req_failed / error_rate. Uploads keep the default
  // (>=400 == failed), so a real upload collision still shows up.
  const res = http.post(
    `${BASE}/api/v1/repositories`,
    JSON.stringify({ key: REPO, name: REPO, format: 'generic', repo_type: 'local', is_public: true }),
    {
      headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
      responseCallback: http.expectedStatuses(200, 201, 409),
    },
  );
  // 2xx = created; 409 = already exists (idempotent re-run). Anything else warns.
  if (!(res.status >= 200 && res.status < 300) && res.status !== 409) {
    console.warn(`setup: repo create returned HTTP ${res.status}: ${String(res.body).slice(0, 200)}`);
  }
  return { repo: REPO };
}

export default function (data) {
  const path = `k6/${NONCE}/vu${__VU}/n${__ITER}.bin`;
  const url = `${BASE}/api/v1/repositories/${data.repo}/artifacts/${path}`;
  const res = http.put(url, PAYLOAD.buffer, { headers: AUTH });
  check(res, { 'upload 2xx': (r) => r.status >= 200 && r.status < 300 });
  if (THROTTLE > 0) sleep(THROTTLE / 1000);
}

export function handleSummary(data) {
  const m = data.metrics || {};
  const dur = (m.http_req_duration && m.http_req_duration.values) || {};
  const reqs = (m.http_reqs && m.http_reqs.values) || { count: 0, rate: 0 };
  const failed = (m.http_req_failed && m.http_req_failed.values) || { rate: 0 };
  const sent = (m.data_sent && m.data_sent.values) || { count: 0, rate: 0 };

  const count = reqs.count || 0;
  const errRate = failed.rate || 0;

  // Normalized Layer-A `app` object — identical shape to the bash path.
  const app = {
    requests: count,
    errors: Math.round(errRate * count),
    error_rate: errRate,
    throughput_rps: reqs.rate || 0,
    throughput_mbps: (sent.rate || 0) / 1000000,   // data_sent includes headers
    bytes_uploaded: sent.count || 0,
    max_concurrency: VUS,
    latency_ms: {
      p50: dur['p(50)'] != null ? dur['p(50)'] : (dur.med || 0),
      p90: dur['p(90)'] || 0,
      p95: dur['p(95)'] || 0,
      p99: dur['p(99)'] || 0,
      max: dur.max || 0,
    },
  };

  const line = `k6: ${count} reqs, err_rate=${errRate.toFixed(4)}, ` +
    `p50=${app.latency_ms.p50.toFixed(1)}ms p95=${app.latency_ms.p95.toFixed(1)}ms ` +
    `p99=${app.latency_ms.p99.toFixed(1)}ms rps=${app.throughput_rps.toFixed(1)} ` +
    `mbps=${app.throughput_mbps.toFixed(1)}\n`;

  return {
    '/out/summary.json': JSON.stringify(app),
    stdout: line,
  };
}
