// Criterion benchmark harness for the Steer enforcement pipeline.
//
// Tiers mirror the BENCHMARKS.md methodology:
//
//   Tier 0 — Cedar only, sparse context (no PII, no detectors)
//   Tier 1 — Cedar only, full 50-field production context
//   Tier 2 — Cedar + all 5 regex detectors (no PII)
//   Tier 3 — Cedar + PII + all 5 detectors  ← production baseline
//
// Run:    cargo bench --bench proxy_overhead
// Report: target/criterion/
//
// Targets (from BENCHMARKS.md):
//   Tier 0 p99 < 500µs   (pure Cedar overhead)
//   Tier 3 p99 < 8ms     (full pipeline, 500-char payload)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::{json, Value};
use std::collections::HashSet;

use steer_core::detectors::{
    confidential::ConfidentialDetector,
    identity::IdentityClaimDetector,
    injection::InjectionDetector,
    jailbreak::JailbreakDetector,
    run_detectors,
    threat::ThreatDetector,
    tool_governance::{ToolGovernanceConfig, ToolGovernanceDetector},
    ContentDetector,
};
use steer_core::pii::RegexPiiEngine;
use steer_core::policy::cedar::CedarEngine;
use steer_core::policy::{build_context, ContextParams, PolicyDecision, PolicyEngine};

// ── Policies ─────────────────────────────────────────────────────────────────

const PERMIT_ALL: &str = "permit(principal, action, resource);";

/// 10 default policies that mirror production `_managed.cedar`.
/// Uses real Cedar annotations but no condition predicates so every request
/// gets the same evaluation path as production.
const PRODUCTION_POLICIES: &str = r#"
@id("default-permit-baseline")
@enforcement("allow")
permit(principal, action, resource);

@id("default-pii-flag")
@enforcement("flag")
@description("PII detected in prompt — flagged for review")
forbid(principal, action, resource)
when { context has pii_detected && context.pii_detected == true };

@id("default-injection-block")
@enforcement("block")
@description("Prompt injection attempt blocked")
forbid(principal, action, resource)
when { context has injection_detected && context.injection_detected == true };

@id("default-jailbreak-block")
@enforcement("block")
@description("Jailbreak attempt blocked")
forbid(principal, action, resource)
when { context has jailbreak_detected && context.jailbreak_detected == true };

@id("default-threat-block")
@enforcement("block")
@description("Threat or harassment detected")
forbid(principal, action, resource)
when { context has threat_detected && context.threat_detected == true };
"#;

// ── Payloads ─────────────────────────────────────────────────────────────────

/// Clean 100-char prompt (no PII, no threats).
fn payload_100() -> String {
    "Summarize the key differences between supervised and unsupervised learning in machine learning."
        .to_string()
}

/// Clean ~500-char prompt (production-representative).
fn payload_500() -> String {
    "You are a helpful assistant. The user is asking about compliance frameworks for AI systems. \
     Explain the key requirements of the EU AI Act for high-risk AI systems, including conformity \
     assessment procedures, technical documentation, transparency obligations, and human oversight \
     requirements. Keep the answer concise and cite Article numbers where relevant. The request ID \
     is 550e8400-e29b-41d4-a716-446655440000 and was submitted at 2026-04-28T09:15:00Z."
        .to_string()
}

/// Clean ~2000-char prompt (large context window).
fn payload_2000() -> String {
    let base = "The proxy intercepts every LLM request and enforces configured Cedar policies. \
                Compliance frameworks such as GDPR, EU AI Act, and NIST AI RMF mandate audit trails. \
                Machine learning models require large datasets and rigorous evaluation procedures. ";
    base.repeat(12) // ~2100 chars
}

/// Full 50-field Cedar context matching production `build_context()` output.
fn full_production_context() -> Value {
    build_context(&ContextParams {
        model: "gpt-4o",
        streaming: false,
        pii_detected: false,
        risk_level: "limited",
        tool_name: "",
        tool_names: &[],
        tool_count: 0,
        requested_tools: &[],
        budget_remaining_cents: 5000,
        budget_utilization_pct: 10,
        injection_detected: false,
        jailbreak_detected: false,
        threat_detected: false,
        identity_claim_detected: false,
        confidential_detected: false,
        exfiltration_detected: false,
        exfiltration_type: "",
        unauthorized_tool_detected: false,
        tool_categories: "",
        tool_highest_risk_category: "",
        tool_allowlist_mode: false,
        ..Default::default()
    })
}

fn build_detectors() -> Vec<Box<dyn ContentDetector>> {
    vec![
        Box::new(InjectionDetector::new()),
        Box::new(JailbreakDetector::new()),
        Box::new(ThreatDetector::new()),
        Box::new(IdentityClaimDetector::new()),
        Box::new(ConfidentialDetector::new()),
    ]
}

// ── Tier 0: Cedar eval, sparse context ───────────────────────────────────────

fn bench_tier0_cedar_sparse(c: &mut Criterion) {
    let engine = CedarEngine::from_policy_str(PERMIT_ALL).expect("parse");
    let context = json!({"model": "gpt-4o", "pii_detected": false});

    c.bench_function("tier0_cedar_sparse_context", |b| {
        b.iter(|| {
            let d = engine
                .evaluate_request("bench", "llm.request", &Value::Null, black_box(&context))
                .unwrap_or_else(|_| PolicyDecision::allow());
            black_box(d);
        })
    });
}

// ── Tier 1: Cedar eval, full production context ───────────────────────────────

fn bench_tier1_cedar_full_context(c: &mut Criterion) {
    let engine = CedarEngine::from_policy_str(PRODUCTION_POLICIES).expect("parse");
    let context = full_production_context();

    c.bench_function("tier1_cedar_full_context_production_policies", |b| {
        b.iter(|| {
            let d = engine
                .evaluate_request("bench", "llm.request", &Value::Null, black_box(&context))
                .unwrap_or_else(|_| PolicyDecision::allow());
            black_box(d);
        })
    });
}

// ── Tier 2: Cedar + 5 regex detectors (no PII), 3 payload sizes ─────────────

fn bench_tier2_cedar_plus_detectors(c: &mut Criterion) {
    let engine = CedarEngine::from_policy_str(PRODUCTION_POLICIES).expect("parse");
    let detectors = build_detectors();

    let payloads = [
        ("100c", payload_100()),
        ("500c", payload_500()),
        ("2000c", payload_2000()),
    ];

    let mut group = c.benchmark_group("tier2_cedar_plus_detectors");
    for (label, text) in &payloads {
        group.bench_with_input(BenchmarkId::from_parameter(label), text, |b, text| {
            b.iter(|| {
                // Detectors
                let results = run_detectors(&detectors, black_box(text));
                let threat = results
                    .iter()
                    .any(|r| r.detector_type == "threat" && r.detected);
                let injection = results
                    .iter()
                    .any(|r| r.detector_type == "injection" && r.detected);
                let jailbreak = results
                    .iter()
                    .any(|r| r.detector_type == "jailbreak" && r.detected);

                // Cedar eval with detector signals
                let context = build_context(&ContextParams {
                    model: "gpt-4o",
                    threat_detected: threat,
                    injection_detected: injection,
                    jailbreak_detected: jailbreak,
                    ..Default::default()
                });
                let d = engine
                    .evaluate_request("bench", "llm.request", &Value::Null, black_box(&context))
                    .unwrap_or_else(|_| PolicyDecision::allow());
                black_box((results, d));
            })
        });
    }
    group.finish();
}

// ── Tier 3: Cedar + PII + all detectors (production baseline) ────────────────

fn bench_tier3_full_pipeline(c: &mut Criterion) {
    let pii_engine = RegexPiiEngine::new(&[]);
    let cedar_engine = CedarEngine::from_policy_str(PRODUCTION_POLICIES).expect("parse");
    let detectors = build_detectors();

    let payloads = [
        ("100c", payload_100()),
        ("500c", payload_500()),
        ("2000c", payload_2000()),
    ];

    let mut group = c.benchmark_group("tier3_full_pipeline");
    for (label, text) in &payloads {
        group.bench_with_input(BenchmarkId::from_parameter(label), text, |b, text| {
            b.iter(|| {
                // PII scan
                let pii = pii_engine.scan_and_redact(black_box(text), "request");

                // Content detectors
                let results = run_detectors(&detectors, black_box(text));
                let threat = results
                    .iter()
                    .any(|r| r.detector_type == "threat" && r.detected);
                let injection = results
                    .iter()
                    .any(|r| r.detector_type == "injection" && r.detected);
                let jailbreak = results
                    .iter()
                    .any(|r| r.detector_type == "jailbreak" && r.detected);

                // Cedar eval
                let context = build_context(&ContextParams {
                    model: "gpt-4o",
                    pii_detected: !pii.findings.is_empty(),
                    threat_detected: threat,
                    injection_detected: injection,
                    jailbreak_detected: jailbreak,
                    risk_level: "limited",
                    budget_remaining_cents: 5000,
                    budget_utilization_pct: 10,
                    ..Default::default()
                });
                let d = cedar_engine
                    .evaluate_request("bench", "llm.request", &Value::Null, black_box(&context))
                    .unwrap_or_else(|_| PolicyDecision::allow());
                black_box((pii, results, d));
            })
        });
    }
    group.finish();
}

// ── Tier 4: Tool governance (request + response enforcement path) ─────────────
//
// Baseline: pre-built detector (the fixed, production path)
// vs. naive: rebuilt from Vec<String> + HashSet on every iteration (the old path).
// Demonstrates why storing ToolGovernanceDetector in PipelineState matters.

fn bench_tier4_tool_governance(c: &mut Criterion) {
    let tools_3 = vec![
        "execute_query".to_string(),
        "read_file".to_string(),
        "http_request".to_string(),
    ];
    let tools_10 = (0..10).map(|i| format!("tool_{i}")).collect::<Vec<_>>();

    // Pre-built detector — mirrors fixed pipeline (one allocation at startup).
    let detector = ToolGovernanceDetector::new(ToolGovernanceConfig {
        allowed_tools: HashSet::new(),
        block_in_allowlist_mode: false,
    });

    let mut group = c.benchmark_group("tier4_tool_governance");

    group.bench_function("prebuilt_3_tools", |b| {
        b.iter(|| black_box(detector.scan_tools(black_box(&tools_3))))
    });

    group.bench_function("prebuilt_10_tools", |b| {
        b.iter(|| black_box(detector.scan_tools(black_box(&tools_10))))
    });

    // Naive path — builds HashSet + new detector on every call (old per-request pattern).
    let allowed: Vec<String> = vec![];
    group.bench_function("naive_rebuild_3_tools", |b| {
        b.iter(|| {
            let det = ToolGovernanceDetector::new(ToolGovernanceConfig {
                allowed_tools: allowed.iter().cloned().collect::<HashSet<_>>(),
                block_in_allowlist_mode: false,
            });
            black_box(det.scan_tools(black_box(&tools_3)))
        })
    });

    group.finish();
}

// ── Individual phase isolation ────────────────────────────────────────────────

fn bench_pii_scan_by_size(c: &mut Criterion) {
    let engine = RegexPiiEngine::new(&[]);
    let payloads = [
        ("100c", payload_100()),
        ("500c", payload_500()),
        ("2000c", payload_2000()),
    ];

    let mut group = c.benchmark_group("pii_scan");
    for (label, text) in &payloads {
        group.bench_with_input(BenchmarkId::from_parameter(label), text, |b, text| {
            b.iter(|| black_box(engine.scan_and_redact(black_box(text), "request")))
        });
    }
    group.finish();
}

fn bench_detectors_by_size(c: &mut Criterion) {
    let detectors = build_detectors();
    let payloads = [
        ("100c", payload_100()),
        ("500c", payload_500()),
        ("2000c", payload_2000()),
    ];

    let mut group = c.benchmark_group("content_detectors_5x");
    for (label, text) in &payloads {
        group.bench_with_input(BenchmarkId::from_parameter(label), text, |b, text| {
            b.iter(|| black_box(run_detectors(&detectors, black_box(text))))
        });
    }
    group.finish();
}

// ── Streaming buffer ──────────────────────────────────────────────────────────

fn bench_word_boundary_buffer(c: &mut Criterion) {
    use steer_core::streaming::buffer::WordBoundaryBuffer;
    let frames: Vec<Vec<u8>> = (0..100)
        .map(|i| {
            format!(r#"data: {{"choices":[{{"delta":{{"content":"token{i} "}}}}]}}"#).into_bytes()
        })
        .collect();

    c.bench_function("streaming_buffer_100_frames", |b| {
        b.iter(|| {
            let mut buf = WordBoundaryBuffer::new(4096);
            let mut flushes: Vec<Vec<u8>> = Vec::new();
            for frame in &frames {
                if let Some((flushed, _)) = buf.push(black_box(frame)) {
                    flushes.push(flushed);
                }
            }
            if let Some(tail) = buf.flush_end() {
                flushes.push(tail);
            }
            black_box(flushes);
        })
    });
}

// ── Groups ────────────────────────────────────────────────────────────────────

criterion_group!(
    tier_benchmarks,
    bench_tier0_cedar_sparse,
    bench_tier1_cedar_full_context,
    bench_tier2_cedar_plus_detectors,
    bench_tier3_full_pipeline,
    bench_tier4_tool_governance,
);

criterion_group!(
    phase_benchmarks,
    bench_pii_scan_by_size,
    bench_detectors_by_size,
    bench_word_boundary_buffer,
);

criterion_main!(tier_benchmarks, phase_benchmarks);
