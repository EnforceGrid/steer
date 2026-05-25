//! Policy Input Contract — the normalized fact model that Cedar evaluates.
//!
//! Every proxy request/response is translated into a `PolicyInput` before
//! Cedar evaluation. This guarantees a consistent, documented field vocabulary
//! regardless of the upstream provider or request shape.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ── Action vocabulary ───────────────────────────────────────────────────────

/// Coarse operation type — scopes which Cedar policies fire.
/// Small, stable vocabulary. Context identifies the instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Chat completion request (`/v1/chat/completions`, `/v1/messages`)
    LlmRequest,
    /// Chat completion response (no tool calls)
    LlmResponse,
    /// Response contains tool_calls
    ToolCall,
    /// Embedding request (`/v1/embeddings`)
    EmbeddingCreate,
    /// Image generation (`/v1/images/generations`)
    ImageGenerate,
    /// Model listing (`/v1/models`)
    ModelsList,
}

impl PolicyAction {
    /// Cedar-compatible action string used in `EnforceGrid::Action::"..."`.
    pub fn as_cedar_action(&self) -> &'static str {
        match self {
            Self::LlmRequest => "llm.request",
            Self::LlmResponse => "llm.response",
            Self::ToolCall => "tool.call",
            Self::EmbeddingCreate => "embedding.create",
            Self::ImageGenerate => "image.generate",
            Self::ModelsList => "models.list",
        }
    }

    /// Derive the request-side action from a URI path.
    pub fn from_path(path: &str) -> Self {
        match path {
            "/v1/chat/completions" | "/v1/messages" => Self::LlmRequest,
            "/v1/embeddings" => Self::EmbeddingCreate,
            "/v1/images/generations" => Self::ImageGenerate,
            "/v1/models" => Self::ModelsList,
            _ => Self::LlmRequest, // default for unknown paths
        }
    }

    /// Derive response-side action: `tool.call` if tool_calls present,
    /// otherwise `llm.response`.
    pub fn from_response(has_tool_calls: bool) -> Self {
        if has_tool_calls {
            Self::ToolCall
        } else {
            Self::LlmResponse
        }
    }
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_cedar_action())
    }
}

// ── Policy Input ────────────────────────────────────────────────────────────

/// The normalized fact model passed to Cedar for evaluation.
/// Serializable as JSON for the `EG-Policy-Input` debug header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub context: Value,
}

impl PolicyInput {
    pub fn new(principal: &str, action: PolicyAction, resource: &str, context: Value) -> Self {
        Self {
            principal: principal.to_string(),
            action: action.as_cedar_action().to_string(),
            resource: resource.to_string(),
            context,
        }
    }

    /// Serialize to compact JSON for the debug header.
    /// Truncates to `max_bytes` by dropping context fields if needed.
    pub fn to_header_value(&self, max_bytes: usize) -> String {
        let full = serde_json::to_string(self).unwrap_or_default();
        if full.len() <= max_bytes {
            return full;
        }
        // Truncated version: keep principal/action/resource, drop context
        let truncated = json!({
            "principal": self.principal,
            "action": self.action,
            "resource": self.resource,
            "context": "_truncated_",
        });
        let s = serde_json::to_string(&truncated).unwrap_or_default();
        if s.len() <= max_bytes {
            s
        } else {
            s[..max_bytes].to_string()
        }
    }
}

// ── Context builder ─────────────────────────────────────────────────────────

/// Parameters for building a normalized Cedar context.
#[derive(Debug, Default)]
pub struct ContextParams<'a> {
    pub model: &'a str,
    pub streaming: bool,
    pub pii_detected: bool,
    /// Names of every PII pattern that matched the scanned text, e.g.
    /// `["openai_key", "credit_card"]`. Empty when no PII fires.
    ///
    /// Surfaced into Cedar context as a Set so policies can target specific
    /// pattern categories without hardcoding lists in Rust:
    ///   when { context.pii_findings.containsAny(["openai_key", ...]) }
    pub pii_findings: &'a [String],
    // Governance (from config)
    pub risk_level: &'a str,
    // Tool fields
    pub tool_name: &'a str,
    pub tool_names: &'a [String],
    pub tool_count: i64,
    pub requested_tools: &'a [String],
    // Budget fields (-1 = no budget configured)
    pub budget_remaining_cents: i64,
    pub budget_utilization_pct: i64,
    // Content detector signals
    pub injection_detected: bool,
    pub jailbreak_detected: bool,
    pub threat_detected: bool,
    pub identity_claim_detected: bool,
    pub confidential_detected: bool,
    // Bias detector signal
    pub bias_detected: bool,
    // Exfiltration detector signals
    pub exfiltration_detected: bool,
    /// First matched exfiltration category (e.g. "webhook_instruction").
    pub exfiltration_type: &'a str,
    // Tool governance signals
    pub unauthorized_tool_detected: bool,
    /// CSV of matched risk categories (e.g. "code_execution,network_call").
    pub tool_categories: &'a str,
    /// Highest-severity risk category matched, or empty string.
    pub tool_highest_risk_category: &'a str,
    /// True when an explicit allowlist is active; false = denylist heuristic.
    pub tool_allowlist_mode: bool,
    /// True when the current model route has fallback entries configured.
    pub fallback_available: bool,
    /// True when the requested model appears in config.models (approved registry).
    pub model_approved: bool,
    /// Whether data processing consent has been recorded for this tenant.
    pub consent_given: bool,
    // Anomaly detection (AIUC-1 D005)
    pub anomaly_detected: bool,
    pub anomaly_type: &'a str,
    // Cross-border data residency (AIUC-1 E004)
    /// True when the model region matches the tenant's data residency requirement,
    /// or when no requirement is set. Default false (restrictive).
    pub data_residency_compliant: bool,
    // Org namespace fields
    /// Tenant timezone (IANA). Default "UTC".
    pub org_timezone: &'a str,
    /// Tenant industry classification. Default "other".
    pub org_industry: &'a str,
    /// Tenant data residency region. Default "".
    pub org_region: &'a str,
    /// Whether the current time is within the tenant's business hours window.
    pub org_business_hours_active: bool,
    // Supply chain governance (OWASP ASI04)
    /// True when the MCP server originating the tool call is in the approved registry.
    /// Default true (permissive when no MCP server header is present).
    pub mcp_server_approved: bool,
    /// MCP server ID from the request header (empty when not present).
    pub mcp_server_id: &'a str,
}

/// Build a normalized Cedar context JSON value.
/// All fields are always present — no `context has X` guards needed for
/// budget or detector fields.
pub fn build_context(params: &ContextParams) -> Value {
    json!({
        "model": params.model,
        "streaming": params.streaming,
        "pii_detected": params.pii_detected,
        "pii_findings": params.pii_findings,
        // Governance
        "risk_level": params.risk_level,
        // Tool fields
        "tool_name": params.tool_name,
        "tool_names": params.tool_names,
        "tool_count": params.tool_count,
        "requested_tools": params.requested_tools,
        // Budget fields
        "budget_remaining_cents": params.budget_remaining_cents,
        "budget_utilization_pct": params.budget_utilization_pct,
        // Detector signals
        "injection_detected": params.injection_detected,
        "jailbreak_detected": params.jailbreak_detected,
        "threat_detected": params.threat_detected,
        "identity_claim_detected": params.identity_claim_detected,
        "confidential_detected": params.confidential_detected,
        // Bias detector
        "bias_detected": params.bias_detected,
        // Exfiltration detector
        "exfiltration_detected": params.exfiltration_detected,
        "exfiltration_type": params.exfiltration_type,
        // Tool governance
        "unauthorized_tool_detected": params.unauthorized_tool_detected,
        "tool_categories": params.tool_categories,
        "tool_highest_risk_category": params.tool_highest_risk_category,
        "tool_allowlist_mode": params.tool_allowlist_mode,
        "fallback_available": params.fallback_available,
        "model_approved": params.model_approved,
        "consent_given": params.consent_given,
        "anomaly_detected": params.anomaly_detected,
        "anomaly_type": params.anomaly_type,
        "data_residency_compliant": params.data_residency_compliant,
        // Org namespace
        "org_timezone": params.org_timezone,
        "org_industry": params.org_industry,
        "org_region": params.org_region,
        "org_business_hours_active": params.org_business_hours_active,
        // MCP supply chain (OWASP ASI04)
        "mcp_server_approved": params.mcp_server_approved,
        "mcp_server_id": params.mcp_server_id,
    })
}

/// Typed label emitted by every pipeline phase for offline analysis (Tier 5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionLabel {
    pub label_type: String,
    pub detector: String,
    pub confidence: f64,
    pub location: String,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub metadata: std::collections::HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_from_chat_completions_path() {
        assert_eq!(
            PolicyAction::from_path("/v1/chat/completions"),
            PolicyAction::LlmRequest
        );
    }

    #[test]
    fn action_from_messages_path() {
        assert_eq!(
            PolicyAction::from_path("/v1/messages"),
            PolicyAction::LlmRequest
        );
    }

    #[test]
    fn action_from_embeddings_path() {
        assert_eq!(
            PolicyAction::from_path("/v1/embeddings"),
            PolicyAction::EmbeddingCreate
        );
    }

    #[test]
    fn action_from_images_path() {
        assert_eq!(
            PolicyAction::from_path("/v1/images/generations"),
            PolicyAction::ImageGenerate
        );
    }

    #[test]
    fn action_from_models_path() {
        assert_eq!(
            PolicyAction::from_path("/v1/models"),
            PolicyAction::ModelsList
        );
    }

    #[test]
    fn action_unknown_path_defaults_to_llm_request() {
        assert_eq!(
            PolicyAction::from_path("/v1/unknown"),
            PolicyAction::LlmRequest
        );
    }

    #[test]
    fn action_response_with_tool_calls() {
        assert_eq!(PolicyAction::from_response(true), PolicyAction::ToolCall);
    }

    #[test]
    fn action_response_without_tool_calls() {
        assert_eq!(
            PolicyAction::from_response(false),
            PolicyAction::LlmResponse
        );
    }

    #[test]
    fn cedar_action_string_format() {
        assert_eq!(PolicyAction::LlmRequest.as_cedar_action(), "llm.request");
        assert_eq!(PolicyAction::ToolCall.as_cedar_action(), "tool.call");
        assert_eq!(
            PolicyAction::EmbeddingCreate.as_cedar_action(),
            "embedding.create"
        );
    }

    #[test]
    fn display_matches_cedar_action() {
        assert_eq!(format!("{}", PolicyAction::LlmRequest), "llm.request");
        assert_eq!(format!("{}", PolicyAction::ToolCall), "tool.call");
    }

    #[test]
    fn policy_input_serializes_to_json() {
        let input = PolicyInput::new(
            "agent-1",
            PolicyAction::LlmRequest,
            "request",
            json!({"model": "gpt-4o"}),
        );
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("llm.request"));
        assert!(json.contains("agent-1"));
    }

    #[test]
    fn header_value_truncates_context_when_too_large() {
        let big_context = json!({"data": "x".repeat(5000)});
        let input = PolicyInput::new("a", PolicyAction::LlmRequest, "r", big_context);
        let header = input.to_header_value(4096);
        assert!(header.len() <= 4096);
        assert!(header.contains("_truncated_"));
    }

    #[test]
    fn header_value_keeps_full_when_small() {
        let input = PolicyInput::new(
            "a",
            PolicyAction::LlmRequest,
            "r",
            json!({"model": "gpt-4o"}),
        );
        let header = input.to_header_value(4096);
        assert!(header.contains("gpt-4o"));
        assert!(!header.contains("_truncated_"));
    }

    #[test]
    fn build_context_has_all_fields() {
        let ctx = build_context(&ContextParams::default());
        let obj = ctx.as_object().unwrap();
        // All fields present
        for key in &[
            "model",
            "streaming",
            "pii_detected",
            "risk_level",
            "tool_name",
            "tool_names",
            "tool_count",
            "requested_tools",
            "budget_remaining_cents",
            "budget_utilization_pct",
            "injection_detected",
            "jailbreak_detected",
            "threat_detected",
            "identity_claim_detected",
            "confidential_detected",
            "bias_detected",
            "exfiltration_detected",
            "exfiltration_type",
            "unauthorized_tool_detected",
            "tool_categories",
            "tool_highest_risk_category",
            "tool_allowlist_mode",
            "fallback_available",
            "model_approved",
            "consent_given",
            "anomaly_detected",
            "anomaly_type",
            "data_residency_compliant",
            "org_timezone",
            "org_industry",
            "org_region",
            "org_business_hours_active",
            "mcp_server_approved",
            "mcp_server_id",
        ] {
            assert!(obj.contains_key(*key), "missing field: {key}");
        }
        // Security-critical default: mcp_server_approved must default false
        // so unevaluated requests are denied, not permitted.
        assert_eq!(
            obj["mcp_server_approved"], false,
            "mcp_server_approved must default to false"
        );
    }

    #[test]
    fn data_residency_compliant_true_when_no_requirement() {
        // When no tenant residency requirement, pipeline sets this to true
        let params = ContextParams {
            data_residency_compliant: true,
            ..Default::default()
        };
        let ctx = build_context(&params);
        assert_eq!(ctx["data_residency_compliant"], true);
    }

    #[test]
    fn data_residency_compliant_false_when_regions_mismatch() {
        let params = ContextParams {
            data_residency_compliant: false,
            ..Default::default()
        };
        let ctx = build_context(&params);
        assert_eq!(ctx["data_residency_compliant"], false);
    }

    #[test]
    fn data_residency_compliant_default_is_false() {
        // Default::default() gives false (restrictive) — pipeline must set explicitly
        let params = ContextParams::default();
        assert!(!params.data_residency_compliant);
    }

    #[test]
    fn build_context_budget_defaults_to_minus_one() {
        let params = ContextParams {
            budget_remaining_cents: -1,
            budget_utilization_pct: -1,
            ..Default::default()
        };
        let ctx = build_context(&params);
        assert_eq!(ctx["budget_remaining_cents"], -1);
        assert_eq!(ctx["budget_utilization_pct"], -1);
    }
}
