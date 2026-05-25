/**
 * k6 throughput ceiling benchmark
 *
 * Finds the maximum sustained RPS that steer can handle by ramping VUs
 * against a mock upstream (no real LLM).
 *
 * Methodology (Bifrost-comparable):
 *   1. Mock upstream returns canned response in ~60ms (matches Bifrost benchmark)
 *   2. k6 ramps from 10 → 250 → 500 VUs over stages
 *   3. Measures: RPS achieved, p50/p95/p99 latency, error rate
 *   4. The "ceiling" is the highest sustained RPS before errors spike
 *      or p99 degrades beyond 100ms
 *
 * Prerequisites:
 *   1. Start mock upstream:  node k6/mock-upstream.js
 *   2. Start steer locally:
 *        cargo build --release
 *        STEER_PORT=8080 OPENAI_API_KEY=fake \
 *          ./target/release/steer --config steer.example.yaml
 *   3. Run this script:
 *        k6 run k6/throughput-ceiling.js
 *
 * Required env vars:
 *   STEER_URL     — local steer URL (default: http://127.0.0.1:8080)
 *
 * Optional:
 *   EG_API_KEY    — EG-Api-Key header (default: empty = dev mode, no auth)
 *   MAX_VUS       — peak VUs to ramp to (default: 500)
 *   RAMP_TIME     — duration of each ramp stage (default: 30s)
 *   HOLD_TIME     — duration to hold at peak (default: 60s)
 */

import http from 'k6/http';
import { check } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

// ── Custom metrics ──────────────────────────────────────────────────────────

const latency     = new Trend('steer_latency_ms', true);
const errorRate   = new Rate('steer_errors');
const totalReqs   = new Counter('steer_total_reqs');

// ── Config ──────────────────────────────────────────────────────────────────

const STEER_URL   = __ENV.STEER_URL   || 'http://127.0.0.1:8080';
const EG_API_KEY  = __ENV.EG_API_KEY  || '';
const MAX_VUS     = parseInt(__ENV.MAX_VUS    || '500', 10);
const RAMP_TIME   = __ENV.RAMP_TIME   || '30s';
const HOLD_TIME   = __ENV.HOLD_TIME   || '60s';

// Ramp stages: warm-up → ramp → peak hold → ramp-down
const MID_VUS = Math.floor(MAX_VUS / 2);

export const options = {
  stages: [
    { duration: '10s',      target: 10 },        // warm-up
    { duration: RAMP_TIME,  target: MID_VUS },    // ramp to 50%
    { duration: RAMP_TIME,  target: MAX_VUS },    // ramp to peak
    { duration: HOLD_TIME,  target: MAX_VUS },    // hold at peak
    { duration: '10s',      target: 0 },          // ramp-down
  ],
  thresholds: {
    'steer_latency_ms': ['p(50) < 60000', 'p(95) < 60000', 'p(99) < 60000'],
    'steer_errors':     ['rate < 0.05'],   // alert if >5% errors
  },
};

// ── Payload ─────────────────────────────────────────────────────────────────

const BODY = JSON.stringify({
  model: 'gpt-4o-mini',
  max_tokens: 1,
  messages: [{ role: 'user', content: 'Say OK' }],
});

const HEADERS = {
  'Content-Type':  'application/json',
  'Authorization': 'Bearer fake-key',
  ...(EG_API_KEY ? { 'EG-Api-Key': EG_API_KEY } : {}),
  'EG-Agent-Id':   'k6-throughput-bench',
};

// ── Default function ────────────────────────────────────────────────────────

export default function () {
  const res = http.post(`${STEER_URL}/v1/chat/completions`, BODY, {
    headers: HEADERS,
    tags: { name: 'throughput' },
  });

  latency.add(res.timings.duration);
  totalReqs.add(1);

  const ok = check(res, {
    'status 200': (r) => r.status === 200,
  });
  if (!ok) {
    errorRate.add(1);
    if (res.status !== 200) {
      // Log first few errors, not all — avoid flooding
      if (totalReqs.name && res.status >= 500) {
        console.warn(`${res.status}: ${res.body?.substring(0, 200)}`);
      }
    }
  } else {
    errorRate.add(0);
  }
}

// ── Summary ─────────────────────────────────────────────────────────────────

export function handleSummary(data) {
  function val(metric, key) {
    const m = data.metrics[metric];
    if (!m || !m.values) return null;
    return m.values[key] ?? null;
  }

  function fmt(v) {
    return v !== null ? v.toFixed(1) : '—';
  }

  const p50  = val('steer_latency_ms', 'med') || val('steer_latency_ms', 'p(50)');
  const p95  = val('steer_latency_ms', 'p(95)');
  const p99  = val('steer_latency_ms', 'p(99)');
  const avg  = val('steer_latency_ms', 'avg');
  const min  = val('steer_latency_ms', 'min');
  const max  = val('steer_latency_ms', 'max');

  const count = val('iterations', 'count') || val('steer_latency_ms', 'count') || 0;
  const errRate = val('steer_errors', 'rate') || 0;

  // Compute approximate peak RPS from the hold phase
  // Total duration is roughly: 10 + RAMP + RAMP + HOLD + 10
  const holdSecs = parseInt(HOLD_TIME, 10) || 60;
  const totalSecs = 10 + parseInt(RAMP_TIME, 10) * 2 + holdSecs + 10;

  // Rough overall RPS (total reqs / total time)
  const overallRps = count / totalSecs;

  // k6's built-in iteration rate is more accurate for peak RPS
  const iterRate = val('iterations', 'rate') || overallRps;

  const summary = `
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Steer Throughput Ceiling Benchmark
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Config
    Steer URL:     ${STEER_URL}
    Max VUs:       ${MAX_VUS}
    Mock upstream:  ~60ms delay (Bifrost-comparable)
    Auth:          ${EG_API_KEY ? 'API key' : 'dev mode (no auth)'}

  Results — ${Math.round(count)} total requests
    Avg RPS:       ${overallRps.toFixed(0)} req/s
    Peak RPS:      ~${iterRate.toFixed(0)} req/s (k6 iteration rate)

  Latency
    min:   ${fmt(min)} ms
    p50:   ${fmt(p50)} ms
    p95:   ${fmt(p95)} ms
    p99:   ${fmt(p99)} ms
    max:   ${fmt(max)} ms

  Errors:  ${(errRate * 100).toFixed(2)}%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`;

  const results = {
    timestamp: new Date().toISOString(),
    config: {
      steer_url: STEER_URL,
      max_vus: MAX_VUS,
      ramp_time: RAMP_TIME,
      hold_time: HOLD_TIME,
      mock_upstream: true,
    },
    results: {
      total_requests: Math.round(count),
      overall_rps: Math.round(overallRps),
      peak_rps: Math.round(iterRate),
      latency_ms: { min, p50, p95, p99, max, avg },
      error_rate: errRate,
    },
  };

  return {
    stdout: summary,
    'k6/throughput-results.json': JSON.stringify(results, null, 2),
  };
}
