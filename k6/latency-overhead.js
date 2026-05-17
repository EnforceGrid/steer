/**
 * k6 latency overhead benchmark
 *
 * Measures the added latency of the steer proxy vs direct upstream.
 * Sends identical chat completion requests to both paths and compares.
 *
 * Usage:
 *   # Full benchmark (proxy + direct baseline)
 *   k6 run k6/latency-overhead.js
 *
 *   # Proxy-only (skip baseline)
 *   k6 run k6/latency-overhead.js --env SKIP_BASELINE=1
 *
 * Required env vars:
 *   STEER_URL         — steer public URL (default: https://steer-production.up.railway.app)
 *   EG_API_KEY        — EG-Api-Key header value
 *   OPENAI_API_KEY    — upstream OpenAI key (used by both paths)
 *
 * Optional:
 *   SKIP_BASELINE=1   — skip direct-to-OpenAI requests (halves cost)
 *   VUS=10            — virtual users (default: 10)
 *   DURATION=60s      — test duration (default: 60s)
 */

import http from 'k6/http';
import { check, group } from 'k6';
import { Trend, Counter } from 'k6/metrics';

// ── Custom metrics ──────────────────────────────────────────────────────────

const proxyLatency  = new Trend('proxy_latency_ms',  true);
const directLatency = new Trend('direct_latency_ms', true);
const overheadMs    = new Trend('overhead_ms',       true);
const proxyErrors   = new Counter('proxy_errors');
const directErrors  = new Counter('direct_errors');

// ── Config ──────────────────────────────────────────────────────────────────

const STEER_URL      = __ENV.STEER_URL      || 'https://steer-production.up.railway.app';
const EG_API_KEY     = __ENV.EG_API_KEY      || '';
const OPENAI_API_KEY = __ENV.OPENAI_API_KEY  || '';
const SKIP_BASELINE  = __ENV.SKIP_BASELINE   === '1';

if (!EG_API_KEY)     throw new Error('EG_API_KEY env var required');
if (!OPENAI_API_KEY) throw new Error('OPENAI_API_KEY env var required');

const VUS      = parseInt(__ENV.VUS || '10', 10);
const DURATION = __ENV.DURATION || '60s';

export const options = {
  scenarios: {
    proxy: {
      executor:  'constant-vus',
      vus:       VUS,
      duration:  DURATION,
      exec:      'proxyRequest',
    },
    ...(SKIP_BASELINE ? {} : {
      direct: {
        executor:  'constant-vus',
        vus:       Math.max(1, Math.floor(VUS / 2)),
        duration:  DURATION,
        exec:      'directRequest',
      },
    }),
  },
  // Thresholds force k6 to compute these percentiles (we don't fail on them)
  thresholds: {
    'proxy_latency_ms':  ['p(50) < 60000', 'p(90) < 60000', 'p(95) < 60000', 'p(99) < 60000'],
    'direct_latency_ms': ['p(50) < 60000', 'p(90) < 60000', 'p(95) < 60000', 'p(99) < 60000'],
  },
};

// ── Payload ─────────────────────────────────────────────────────────────────
// Tiny prompt + max_tokens=1 — minimises upstream LLM time so we can
// isolate the proxy overhead. Cost: ~2 tokens per request ≈ $0.000003.

const BODY = JSON.stringify({
  model: 'gpt-4o-mini',
  max_tokens: 1,
  messages: [{ role: 'user', content: 'Say OK' }],
});

// ── Proxy path ──────────────────────────────────────────────────────────────

export function proxyRequest() {
  const res = http.post(`${STEER_URL}/v1/chat/completions`, BODY, {
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${OPENAI_API_KEY}`,
      'EG-Api-Key':    EG_API_KEY,
      'EG-Agent-Id':   'k6-bench',
    },
    tags: { name: 'proxy' },
  });

  proxyLatency.add(res.timings.duration);

  const ok = check(res, {
    'proxy 200': (r) => r.status === 200,
  });
  if (!ok) {
    proxyErrors.add(1);
    if (res.status !== 200) {
      console.warn(`proxy ${res.status}: ${res.body?.substring(0, 200)}`);
    }
  }
}

// ── Direct path (baseline) ──────────────────────────────────────────────────

export function directRequest() {
  const res = http.post('https://api.openai.com/v1/chat/completions', BODY, {
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${OPENAI_API_KEY}`,
    },
    tags: { name: 'direct' },
  });

  directLatency.add(res.timings.duration);

  const ok = check(res, {
    'direct 200': (r) => r.status === 200,
  });
  if (!ok) {
    directErrors.add(1);
    if (res.status !== 200) {
      console.warn(`direct ${res.status}: ${res.body?.substring(0, 200)}`);
    }
  }
}

// ── Summary ─────────────────────────────────────────────────────────────────

export function handleSummary(data) {
  // k6 Trend value keys: med (=p50), p(90), p(95), p(99) — p(50)/p(99) only
  // appear if a threshold references them. We set dummy thresholds to force them.
  function val(metric, key) {
    const m = data.metrics[metric];
    if (!m || !m.values) return null;
    const v = m.values[key];
    return typeof v === 'number' ? v : null;
  }

  function fmt(v) {
    return v !== null ? v.toFixed(1) : '—';
  }

  // med = median = p50; thresholds force p(50), p(90), p(95), p(99)
  const pp50 = val('proxy_latency_ms', 'med')  || val('proxy_latency_ms', 'p(50)');
  const pp90 = val('proxy_latency_ms', 'p(90)');
  const pp95 = val('proxy_latency_ms', 'p(95)');
  const pp99 = val('proxy_latency_ms', 'p(99)');
  const dp50 = val('direct_latency_ms', 'med') || val('direct_latency_ms', 'p(50)');
  const dp90 = val('direct_latency_ms', 'p(90)');
  const dp95 = val('direct_latency_ms', 'p(95)');
  const dp99 = val('direct_latency_ms', 'p(99)');

  const overhead50 = (pp50 !== null && dp50 !== null) ? (pp50 - dp50).toFixed(1) : '—';
  const overhead99 = (pp99 !== null && dp99 !== null) ? (pp99 - dp99).toFixed(1) : '—';

  // count is derived from thresholds data or iterations
  const pCount = data.metrics['proxy_latency_ms']  ? Math.round(data.metrics['proxy_latency_ms'].values.count  || data.metrics['proxy_latency_ms'].values.rate * 60 || 0) : 0;
  const dCount = data.metrics['direct_latency_ms'] ? Math.round(data.metrics['direct_latency_ms'].values.count || data.metrics['direct_latency_ms'].values.rate * 60 || 0) : 0;

  const summary = `
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Steer Latency Overhead Benchmark
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Proxy (through steer) — ${pCount} requests
    p50:  ${fmt(pp50)} ms
    p90:  ${fmt(pp90)} ms
    p95:  ${fmt(pp95)} ms
    p99:  ${fmt(pp99)} ms

  Direct (to OpenAI) — ${dCount} requests
    p50:  ${fmt(dp50)} ms
    p90:  ${fmt(dp90)} ms
    p95:  ${fmt(dp95)} ms
    p99:  ${fmt(dp99)} ms

  Added overhead (proxy − direct)
    p50:  ${overhead50} ms
    p99:  ${overhead99} ms

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`;

  const results = {
    timestamp: new Date().toISOString(),
    config: { vus: VUS, duration: DURATION, model: 'gpt-4o-mini', max_tokens: 1 },
    proxy:  { p50: pp50, p90: pp90, p95: pp95, p99: pp99, count: pCount },
    direct: { p50: dp50, p90: dp90, p95: dp95, p99: dp99, count: dCount },
    overhead_ms: {
      p50: pp50 !== null && dp50 !== null ? pp50 - dp50 : null,
      p90: pp90 !== null && dp90 !== null ? pp90 - dp90 : null,
      p95: pp95 !== null && dp95 !== null ? pp95 - dp95 : null,
      p99: pp99 !== null && dp99 !== null ? pp99 - dp99 : null,
    },
  };

  return {
    stdout: summary,
    'k6/results.json': JSON.stringify(results, null, 2),
  };
}
