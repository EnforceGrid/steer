use crate::pii::PiiFinding;
use crate::policy::{DetectionLabel, MatchedRule};
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub audit_id: String,
    pub timestamp: String,
    // Omitted in OSS (always ""). Enterprise populates for hash-chain verification.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prev_hash: String,

    pub request: RequestInfo,
    pub response: ResponseInfo,
    pub latency: LatencyInfo,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pii_findings: Vec<PiiFinding>,

    pub enforcement: EnforcementInfo,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub streaming: Option<StreamingInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// Tenant that originated this request. `None` only for legacy entries
    /// written before multi-tenancy was introduced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Detection labels from all pipeline phases (PII, content detectors, policy).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<DetectionLabel>,

    /// Detector snapshot — typed signals from all detectors, keyed by detector name.
    /// Contains flag, score, version, metadata for each detector that ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector_snapshot: Option<serde_json::Value>,

    /// Control facts — namespaced facts derived from detector signals.
    /// e.g., {"agent_integrity.injection_detected": true, "data_protection.pii_present": false}
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_facts: Option<serde_json::Value>,

    /// Evidence labels — for compliance queries without understanding policy internals.
    /// e.g., ["agent_integrity", "injection", "data_protection"]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_labels: Vec<String>,

    /// Payload redaction status: "inline" (redacted in this entry),
    /// "deferred" (will be redacted in enrichment entry), or "none"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_redaction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequestInfo {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub streaming: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseInfo {
    pub status_code: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LatencyInfo {
    pub upstream_ms: f64,
    /// kept as cadabra_ms for wire compat with existing cloud
    pub cadabra_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnforcementInfo {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steer_message: Option<String>,
    /// Human-readable policy description from `@description("...")` Cedar annotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Regulatory frameworks this policy maps to (e.g. "EU_AI_ACT_ART_9", "AIUC1_C007").
    /// Populated from `@regulatory_mapping` annotation on the Cedar policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regulatory_mapping: Vec<String>,
    /// Hold ID when enforcement action is "steer" (human-in-the-loop).
    /// Links this audit entry to the corresponding hold in the decision inbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_id: Option<String>,
    /// True when the deciding policy is in observation mode (action == "flag").
    /// Convenience field for Force to distinguish observed vs enforced decisions
    /// without parsing the action string.
    #[serde(default, skip_serializing_if = "is_false")]
    pub observed: bool,
    /// All Cedar policies that contributed to this decision — not just the winner.
    /// Empty for requests where only the baseline permit fires.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_rules: Vec<MatchedRule>,
}

fn is_false(v: &bool) -> bool {
    !v
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingInfo {
    pub provider: String,
    pub action: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<PiiFinding>,
    pub bytes_received: usize,
    pub bytes_emitted: usize,
    pub buffer_flushes: BufferFlushCounts,
    pub latency: StreamLatency,
    pub streaming_scan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BufferFlushCounts {
    pub on_boundary: usize,
    pub on_size_cap: usize,
    pub on_stream_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StreamLatency {
    pub first_byte_ms: f64,
    pub stream_duration_ms: f64,
    pub cadabra_ms: f64,
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn audit_entry_new_sets_expected_defaults() {
        let entry = AuditEntry::new("test-id-123".to_string());
        assert_eq!(entry.audit_id, "test-id-123");
        assert!(!entry.timestamp.is_empty(), "timestamp must be set");
        assert_eq!(entry.prev_hash, "");
        assert_eq!(entry.pii_findings.len(), 0);
        assert!(entry.streaming.is_none());
        assert!(entry.agent_id.is_none());
        assert!(entry.tenant_id.is_none());
        assert!(entry.provider.is_none());
        assert!(entry.detector_snapshot.is_none());
        assert!(entry.control_facts.is_none());
        assert!(entry.evidence_labels.is_empty());
        assert!(entry.payload_redaction.is_none());
    }

    #[test]
    fn audit_entry_serializes_and_deserializes() {
        let mut entry = AuditEntry::new("abc123".to_string());
        entry.agent_id = Some("agent-1".to_string());
        entry.tenant_id = Some("tenant-a".to_string());
        entry.enforcement.action = "block".to_string();
        entry.enforcement.rule_id = Some("P001".to_string());
        entry.enforcement.regulatory_mapping = vec!["EU_AI_ACT_ART_9".to_string()];

        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["audit_id"], "abc123");
        assert_eq!(json["agent_id"], "agent-1");
        assert_eq!(json["tenant_id"], "tenant-a");
        assert_eq!(json["enforcement"]["action"], "block");
        assert_eq!(json["enforcement"]["rule_id"], "P001");

        // Roundtrip
        let decoded: AuditEntry = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.audit_id, "abc123");
        assert_eq!(
            decoded.enforcement.regulatory_mapping,
            vec!["EU_AI_ACT_ART_9".to_string()]
        );
    }

    #[test]
    fn audit_entry_optional_fields_skip_in_serialization() {
        let entry = AuditEntry::new("x".to_string());
        let json = serde_json::to_value(&entry).unwrap();
        // Optional fields with skip_serializing_if = "Option::is_none" should not appear
        assert!(
            json.get("agent_id").is_none(),
            "agent_id should be omitted when None"
        );
        assert!(
            json.get("tenant_id").is_none(),
            "tenant_id should be omitted when None"
        );
        assert!(
            json.get("streaming").is_none(),
            "streaming should be omitted when None"
        );
    }

    #[test]
    fn enforcement_info_default_has_empty_action() {
        let info = EnforcementInfo::default();
        assert_eq!(info.action, "");
        assert!(info.rule_id.is_none());
        assert!(info.steer_message.is_none());
        assert!(info.description.is_none());
        assert!(info.regulatory_mapping.is_empty());
        assert!(info.hold_id.is_none());
    }

    #[test]
    fn latency_info_default_has_zero_values() {
        let info = LatencyInfo::default();
        assert_eq!(info.upstream_ms, 0.0);
        assert_eq!(info.cadabra_ms, 0.0);
    }

    #[test]
    fn request_info_default_has_empty_fields() {
        let info = RequestInfo::default();
        assert_eq!(info.method, "");
        assert_eq!(info.path, "");
        assert!(info.model.is_none());
        assert!(!info.streaming);
    }

    #[test]
    fn streaming_info_serialization() {
        let info = StreamingInfo {
            provider: "openai".to_string(),
            action: "allow".to_string(),
            findings: vec![],
            bytes_received: 100,
            bytes_emitted: 100,
            buffer_flushes: BufferFlushCounts::default(),
            latency: StreamLatency::default(),
            streaming_scan: "enabled".to_string(),
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["provider"], "openai");
        assert_eq!(json["bytes_received"], 100);
    }
}

impl AuditEntry {
    pub fn new(audit_id: String) -> Self {
        Self {
            audit_id,
            timestamp: Utc::now().to_rfc3339(),
            prev_hash: String::new(),
            request: RequestInfo::default(),
            response: ResponseInfo::default(),
            latency: LatencyInfo::default(),
            pii_findings: vec![],
            enforcement: EnforcementInfo::default(),
            streaming: None,
            agent_id: None,
            tenant_id: None,
            provider: None,
            labels: vec![],
            detector_snapshot: None,
            control_facts: None,
            evidence_labels: vec![],
            payload_redaction: None,
        }
    }
}
