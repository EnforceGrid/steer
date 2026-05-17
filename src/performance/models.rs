use serde::{Deserialize, Serialize};

/// Canonical ordering of the 14 measurable proxy phases.
pub const PHASE_NAMES: &[&str] = &[
    "auth",
    "agent_extract",
    "model_routing",
    "pii_request",
    "detectors_request",
    "cedar_request",
    "custom_policy",
    "pii_response",
    "tool_check",
    "cedar_response",
    "handover",
    "audit_write",
    "event_store",
    "sandbox_enrich",
];

/// Per-request latency observation. All phase fields are Option — not every phase runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSample {
    pub timestamp: String,
    pub agent_id: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub streaming: bool,

    /// Total EnforceGrid-side overhead (excludes upstream).
    pub total_ms: f64,
    /// LLM round-trip.
    pub upstream_ms: f64,

    pub auth_ms: Option<f64>,
    pub agent_extract_ms: Option<f64>,
    pub model_routing_ms: Option<f64>,
    pub pii_request_ms: Option<f64>,
    /// Time spent running the 6 regex content detectors on the request body.
    pub detectors_request_ms: Option<f64>,
    pub cedar_request_ms: Option<f64>,
    pub custom_policy_ms: Option<f64>,
    pub pii_response_ms: Option<f64>,
    pub tool_check_ms: Option<f64>,
    pub cedar_response_ms: Option<f64>,
    pub handover_ms: Option<f64>,
    pub audit_write_ms: Option<f64>,
    pub event_store_ms: Option<f64>,
    pub sandbox_enrich_ms: Option<f64>,
}

/// Hourly aggregate of latency samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceRollup {
    pub hour: String,
    pub agent_id: Option<String>,
    pub model: Option<String>,
    pub sample_count: usize,

    pub total_ms_p50: f64,
    pub total_ms_p95: f64,
    pub total_ms_p99: f64,

    pub upstream_ms_p50: f64,

    /// total_ms / (total_ms + upstream_ms) * 100 at p50
    pub overhead_pct_p50: f64,

    pub pii_request_ms_p50: Option<f64>,
    pub cedar_request_ms_p50: Option<f64>,
    pub audit_write_ms_p50: Option<f64>,
}

/// Timing accumulator used during pipeline execution.
#[derive(Debug, Default, Clone)]
pub struct PhaseTiming {
    pub auth_ms: Option<f64>,
    pub agent_extract_ms: Option<f64>,
    pub model_routing_ms: Option<f64>,
    pub pii_request_ms: Option<f64>,
    pub detectors_request_ms: Option<f64>,
    pub cedar_request_ms: Option<f64>,
    pub custom_policy_ms: Option<f64>,
    pub pii_response_ms: Option<f64>,
    pub tool_check_ms: Option<f64>,
    pub cedar_response_ms: Option<f64>,
    pub handover_ms: Option<f64>,
    pub audit_write_ms: Option<f64>,
    pub event_store_ms: Option<f64>,
    pub sandbox_enrich_ms: Option<f64>,
    pub upstream_ms: f64,
}

impl PhaseTiming {
    /// Sum all non-upstream phase durations.
    pub fn total_overhead_ms(&self) -> f64 {
        [
            self.auth_ms,
            self.agent_extract_ms,
            self.model_routing_ms,
            self.pii_request_ms,
            self.detectors_request_ms,
            self.cedar_request_ms,
            self.custom_policy_ms,
            self.pii_response_ms,
            self.tool_check_ms,
            self.cedar_response_ms,
            self.handover_ms,
            self.audit_write_ms,
            self.event_store_ms,
            self.sandbox_enrich_ms,
        ]
        .iter()
        .filter_map(|v| *v)
        .sum()
    }
}
