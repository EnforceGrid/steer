# Performance

Steer is written in Rust. Cedar evaluation is sub-millisecond. Detector overhead scales with payload size. End-to-end latency is dominated by the upstream LLM (100ms–5s for chat completions). Steer adds ~1.8ms at p99 — measurable but small against any real provider.

This page documents the methodology, the benchmark commands you can run yourself, and the headline numbers.

---

## 1. Headline

| Scenario | p50 | p99 | Hardware |
|---|---|---|---|
| Tier 0 — Cedar only, sparse context | ~10 µs | ~50 µs | M3 Pro |
| Tier 1 — Cedar with full production context | ~12 µs | ~80 µs | M3 Pro |
| Tier 2 — Cedar + 5 regex detectors | ~45 µs | ~600 µs | M3 Pro |
| Tier 3 — full pipeline (Cedar + PII + 5 detectors) | ~67 µs | ~1.8 ms | M3 Pro |

Methodology: Criterion microbenchmarks, 500-char prompt payloads, mock upstream (no network), no streaming. The full-pipeline number includes Cedar evaluation, PII regex scan against the 19-pattern set enabled in `steer.example.yaml`, the 5 content detectors used by `tier3_full_pipeline` in `proxy_overhead.rs` (injection, jailbreak, threat, identity-claim, confidential), and audit serialization. **Note:** the production pipeline (`src/main.rs`) instantiates 7 content detectors — adding `exfiltration` and `bias` on top of the benched 5 — so production overhead is slightly higher than the tier3 number.

**Real-world latency is bounded below by the upstream LLM's response time** — typically 100ms–5s for chat completions. Steer's p99 is ~1.8ms — between 0.04% and 2% of typical LLM response time.

---

## 2. Reproducing the benchmarks

### Cargo bench (microbenchmarks)

```bash
cargo bench --bench proxy_overhead
```

This runs Criterion against every tier. HTML reports land in `target/criterion/`. The benchmark tiers correspond to:

| Tier | What's measured |
|---|---|
| `tier0_cedar_sparse_context` | Cedar evaluation only, minimal context |
| `tier1_cedar_full_context_production_policies` | Cedar with the full 50-field production context against the shipped policy set |
| `tier2_cedar_plus_detectors` | Cedar + 5 content detectors (no PII) |
| `tier3_full_pipeline` | Cedar + PII + 5 content detectors — the benchmark baseline |
| `tier4_tool_governance` | Tool-call evaluation path |
| `pii_scan` | PII scan latency parameterized by payload size |
| `content_detectors_5x` | Content-detector latency parameterized by payload size |

Run a single tier:

```bash
cargo bench --bench proxy_overhead -- tier3_full_pipeline
```

### k6 load tests (end-to-end)

```bash
cd k6
node mock-upstream.js &              # mock OpenAI-compatible upstream
steer --config steer-bench.yaml &
k6 run latency-overhead.js           # 500 concurrent VUs, 60s
k6 run throughput-ceiling.js         # ramp until p99 breaks
```

`steer-bench.yaml` points at the local mock upstream and disables file audit (stdout only) to isolate proxy overhead from disk latency.

---

## 3. Methodology disclosures

### What the headline numbers measure

- **Pure Steer overhead.** Mock upstream that returns instantly. Real proxy operations only — request parse, detector pass, Cedar eval, response serialize, audit emit.
- **500-character prompt payloads.** Representative of typical chat-completion bodies; not representative of long-context (32k+) requests.
- **M3 Pro laptop, single instance.** Numbers scale roughly linearly with CPU clock and core count. Server-grade Linux hosts (e.g., c7g.4xlarge) see slightly better numbers due to higher sustained clocks.
- **No streaming.** Streaming adds the buffer-window delay configured by `streaming.buffer_timeout_ms` (default 200ms) — that's a user-visible *time-to-first-byte* delay, not Steer overhead.
- **No SIEM sink.** Audit writes go to stdout. File or remote sinks add I/O latency dependent on the sink.

### What changes the numbers

| Factor | Effect |
|---|---|
| Payload size | PII scan and detector latency scale roughly linearly with body size |
| Number of detectors enabled | Each detector is independent; cost is roughly additive |
| `pii.patterns` count | Each enabled regex compiles + runs per request |
| Custom Cedar policies | Cedar eval cost scales with policy count and complexity of `when` clauses |
| Streaming buffer window | Larger window = more buffered detector passes = slightly higher CPU |
| Async enrichment | Stage-2 entries run after the response is on the wire; no effect on client-visible latency |

### What we have not measured

- **High-concurrency contention.** Single-instance numbers; multi-instance behind a load balancer is bottlenecked by the LB, not Steer.
- **Sustained 24-hour throughput.** Microbenches are 60-second runs.
- **GC pauses.** Rust has no GC; benchmarks run without warmup artifacts after Criterion's calibration phase.
- **False-positive rate** against a public corpus. The shipped default policies have **not been false-positive-reviewed** against high-volume production traffic. The recommended posture for the first 1–2 weeks of a rollout is `policy.mode: observe`. See [docs/quickstart.md#5-going-to-production](quickstart.md#5-going-to-production).

A false-positive-rate methodology section is on the v0.2 roadmap; it gates on a public benchmark corpus being curated (or a partner willing to release one).

---

## 4. Capacity planning

Capacity planning for a single Steer instance (M3 Pro baseline; scale linearly with CPU clock):

- **CPU-bound** at sustained ~5,000 RPS per core for the full pipeline with 500-char payloads. Two-core minimum for production.
- **Memory** is approximately constant: ~50 MB resident at idle, ~100 MB under load. No streaming buffer growth observed in 24-hour soak.
- **Network** is determined by upstream payload — Steer adds no meaningful overhead beyond the JSON serialization of audit entries.

For target throughput `R` (req/s) with `C` cores per host, provision `ceil(R / (5000 × C))` instances, plus one for HA — two-instance minimum behind an L4 load balancer. Scale horizontally; Steer is stateless apart from the audit sink.

---

## 5. Tuning knobs

| Knob | Default | Effect |
|---|---|---|
| `pii.patterns` (count) | 19 enabled by default | Disable patterns you don't need to reduce per-request regex cost |
| `streaming.buffer_size_bytes` | 512 | Larger = fewer detector passes, but worse time-to-first-byte |
| `streaming.buffer_timeout_ms` | 200 | Maximum time a buffered window can sit before flushing |
| `policy.watch` | `false` | Enable for hot-reload; adds a filesystem watcher with negligible CPU |
| `audit.format` | `json` | `compact` is faster to render but less SIEM-friendly |
| `audit.backend` | `stdout` | `file` adds I/O latency; size your disk |

If proxy overhead becomes the bottleneck (rare), the highest-leverage optimization is reducing `pii.patterns` to the secrets you actually care about. Each enabled pattern is a regex compiled at startup and run per-request.

---

## 6. Where to go next

- [Architecture and the two-stage audit](architecture.md#4-two-stage-audit)
- [Tuning policies for your traffic](policies.md#8-detection-scope-and-limits)
- [Going to production via observation mode](quickstart.md#5-going-to-production)
