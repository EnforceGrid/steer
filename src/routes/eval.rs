//! Policy evaluation and detector discovery endpoints.
//!
//! # Endpoints
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | POST   | /api/v1/policies/eval     | Stateless Cedar eval — no persistence |
//! | GET    | /api/v1/detectors         | List built-in and customer-wired context fields |
//!
//! ## POST /api/v1/policies/eval
//!
//! Evaluates a candidate Cedar policy against a synthetic request without
//! writing anything to the policy store. Primary consumer: Abra's Author+Tester
//! stage (the `test_send` tool), which runs ≥12 test fixtures per iteration.
//!
//! The endpoint also serves as the canonical "does this Cedar do what I think?"
//! scratch-pad for operators testing changes before promoting to live.
//!
//! ## GET /api/v1/detectors
//!
//! Returns the static list of built-in context fields Steer populates on every
//! request/response, plus a placeholder for tenant-wired custom fields.
//! Abra's Analyst validates every field reference in an intent against this list
//! before compiling Cedar — any unknown field becomes a MISSING_DETECTOR decision.

use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::policy::cedar::CedarEngine;
use crate::policy::PolicyEngine;

// ── POST /api/v1/policies/eval ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EvalRequest {
    /// Cedar policy text to evaluate. Must be valid Cedar DSL.
    pub cedar_text: String,

    /// Principal identifier. Defaults to `"api-caller"`.
    /// For agent self-governance tests use `"agent.pipeline.author"` etc.
    #[serde(default = "default_principal")]
    pub principal: String,

    /// Cedar action string. Must be one of the supported vocabulary values.
    /// Defaults to `"llm.request"`.
    /// Valid values: llm.request · llm.response · tool.call ·
    ///               embedding.create · image.generate · models.list
    #[serde(default = "default_action")]
    pub action: String,

    /// Whether to evaluate as a request or response side.
    /// `"request"` → resource entity `EnforceGrid::Request::"request"`
    /// `"response"` → resource entity `EnforceGrid::Response::"response"`
    /// Defaults to `"request"`.
    #[serde(default = "default_resource")]
    pub resource: String,

    /// Cedar context attributes. Keys must match the built-in field vocabulary
    /// (see GET /api/v1/detectors for the full list). Unknown keys are passed
    /// through and evaluated as-is — Cedar will ignore keys not referenced by
    /// the policy.
    #[serde(default)]
    pub context: Value,
}

fn default_principal() -> String { "api-caller".to_string() }
fn default_action() -> String { "llm.request".to_string() }
fn default_resource() -> String { "request".to_string() }

#[derive(Debug, Serialize)]
pub struct EvalResponse {
    /// Enforcement decision: allow · transform · flag · steer · block
    pub decision: String,
    /// `@id` annotation of the winning rule, or Cedar's internal policy ID.
    pub rule_id: Option<String>,
    /// `@description` annotation of the winning rule.
    pub description: Option<String>,
    /// `@steer_message` annotation (only set when decision = steer).
    pub steer_message: Option<String>,
    /// `@transform_pattern\x1f@transform_replace` (only set when decision = transform).
    pub transform_to: Option<String>,
    /// `@regulatory_mapping` annotation values, split by comma.
    pub regulatory_mapping: Vec<String>,
    /// ISO-8601 timestamp of the evaluation.
    pub evaluated_at: String,
}

pub async fn eval_policy(
    Json(req): Json<EvalRequest>,
) -> Result<Json<EvalResponse>, (StatusCode, String)> {
    let engine = CedarEngine::from_policy_str(&req.cedar_text)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, format!("cedar parse error: {e}")))?;

    let resource_attrs = Value::Null;
    let decision = if req.resource == "response" {
        engine.evaluate_response(&req.principal, &req.action, &resource_attrs, &req.context)
    } else {
        engine.evaluate_request(&req.principal, &req.action, &resource_attrs, &req.context)
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(EvalResponse {
        decision: decision.action.to_string(),
        rule_id: decision.rule_id,
        description: decision.description,
        steer_message: decision.steer_message,
        transform_to: decision.transform_to,
        regulatory_mapping: decision.regulatory_mapping,
        evaluated_at: Utc::now().to_rfc3339(),
    }))
}

// ── GET /api/v1/detectors ────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct BuiltinDetector {
    /// Cedar context field name (e.g. `injection_detected`).
    pub name: String,
    /// JSON-compatible return type descriptor.
    pub returns: &'static str,
    /// Short description of what the signal represents.
    pub description: &'static str,
    /// Whether the field is always present (true) or may be absent.
    pub always_present: bool,
}

#[derive(Serialize)]
pub struct CustomerWiredField {
    /// Context field name as the customer passes it on the request.
    pub name: String,
    /// JSON schema type hint, if declared.
    pub schema: Option<String>,
    /// Where the value is read from (e.g. "request_body").
    pub source: &'static str,
}

#[derive(Serialize)]
pub struct DetectorsResponse {
    /// Fields Steer populates on every request/response automatically.
    pub builtin: Vec<BuiltinDetector>,
    /// Customer-provided context fields passed in the request body.
    /// Populated at runtime from observed traffic; empty for new tenants.
    pub customer_wired: Vec<CustomerWiredField>,
    /// Fields referenced by pipeline runs that aren't in builtin ∪ customer_wired.
    /// Populated when an Abra pipeline run raises a MISSING_DETECTOR decision.
    pub requested_but_missing: Vec<String>,
}

pub async fn list_detectors() -> Json<DetectorsResponse> {
    Json(DetectorsResponse {
        builtin: builtin_detectors(),
        customer_wired: vec![],          // populated at runtime from audit entries in v1
        requested_but_missing: vec![],   // populated by failed pipeline runs in v1
    })
}

fn builtin_detectors() -> Vec<BuiltinDetector> {
    vec![
        // ── Request / response metadata ──────────────────────────────────────
        BuiltinDetector { name: "model".into(),           returns: "string",   description: "Model identifier from the upstream request (e.g. gpt-4o, claude-3-5-sonnet)", always_present: true },
        BuiltinDetector { name: "provider".into(),        returns: "string",   description: "Upstream provider identifier (openai, anthropic, google, bedrock)", always_present: true },
        BuiltinDetector { name: "path".into(),            returns: "string",   description: "Request path (e.g. /v1/chat/completions)", always_present: true },
        BuiltinDetector { name: "streaming".into(),       returns: "bool",     description: "Whether the request uses streaming", always_present: true },
        BuiltinDetector { name: "agent_id".into(),        returns: "string",   description: "Principal / agent identifier from the API key or X-Agent-ID header", always_present: true },
        BuiltinDetector { name: "risk_level".into(),      returns: "string",   description: "Risk tier from policy config (low · medium · high · critical)", always_present: true },

        // ── Content detectors (request side) ─────────────────────────────────
        BuiltinDetector { name: "injection_detected".into(),       returns: "bool",   description: "Prompt injection pattern detected in the request", always_present: true },
        BuiltinDetector { name: "injection_type".into(),           returns: "string", description: "First matched injection sub-category (e.g. role_injection, system_override)", always_present: true },
        BuiltinDetector { name: "jailbreak_detected".into(),       returns: "bool",   description: "Jailbreak attempt detected (DAN, persona override, etc.)", always_present: true },
        BuiltinDetector { name: "jailbreak_type".into(),           returns: "string", description: "First matched jailbreak sub-category", always_present: true },
        BuiltinDetector { name: "identity_claim_detected".into(),  returns: "bool",   description: "Agent claims to be a system, admin, or another identity", always_present: true },

        // ── Content detectors (response side) ────────────────────────────────
        BuiltinDetector { name: "pii_detected".into(),             returns: "bool",   description: "PII (name, email, phone, SSN) detected in the response", always_present: true },
        BuiltinDetector { name: "confidential_detected".into(),    returns: "bool",   description: "Confidential data pattern detected (API keys, credentials, internal codes)", always_present: true },
        BuiltinDetector { name: "threat_detected".into(),          returns: "bool",   description: "Threat content detected (violence, extremism, CBRN)", always_present: true },
        BuiltinDetector { name: "threat_score_pct".into(),         returns: "int[0-100]", description: "ML sidecar threat score as percentage; -1 if sidecar not configured", always_present: true },
        BuiltinDetector { name: "exfiltration_detected".into(),    returns: "bool",   description: "Data exfiltration pattern detected (webhook instruction, URL with params)", always_present: true },
        BuiltinDetector { name: "exfiltration_type".into(),        returns: "string", description: "First matched exfiltration category (e.g. webhook_instruction)", always_present: true },
        BuiltinDetector { name: "exfiltration_url_count".into(),   returns: "int",    description: "Number of distinct external URLs found in the content", always_present: true },
        BuiltinDetector { name: "exfiltration_has_params".into(),  returns: "bool",   description: "True if any external URL contained query parameters", always_present: true },
        BuiltinDetector { name: "content_preview".into(),          returns: "string", description: "First 200 chars of streaming content (available mid-stream for early exit policies)", always_present: true },

        // ── Tool governance ───────────────────────────────────────────────────
        BuiltinDetector { name: "tool_name".into(),                returns: "string", description: "Name of the primary tool called (tool.call events)", always_present: true },
        BuiltinDetector { name: "tool_names".into(),               returns: "string[]", description: "All tool names in the response (tool.call events)", always_present: true },
        BuiltinDetector { name: "tool_count".into(),               returns: "int",    description: "Number of tool calls in the response", always_present: true },
        BuiltinDetector { name: "requested_tools".into(),          returns: "string[]", description: "Tool names declared in the request (available for llm.request policies)", always_present: true },
        BuiltinDetector { name: "requested_tool_count".into(),     returns: "int",    description: "Number of tools declared in the request", always_present: true },
        BuiltinDetector { name: "unauthorized_tool_detected".into(), returns: "bool", description: "A tool call matched the unauthorized-tool allowlist/denylist", always_present: true },
        BuiltinDetector { name: "unauthorized_tool_names".into(),  returns: "string", description: "CSV of unauthorized tool names (max 10)", always_present: true },
        BuiltinDetector { name: "tool_categories".into(),          returns: "string", description: "CSV of risk categories matched (e.g. code_execution,network_call)", always_present: true },
        BuiltinDetector { name: "tool_highest_risk_category".into(), returns: "string", description: "Highest-severity risk category matched, or empty string", always_present: true },
        BuiltinDetector { name: "tool_allowlist_mode".into(),      returns: "bool",   description: "True when an explicit allowlist is active; false = denylist heuristic", always_present: true },

        // ── Budget ────────────────────────────────────────────────────────────
        BuiltinDetector { name: "budget_remaining_cents".into(),   returns: "int",    description: "Remaining token budget in cents; -1 if no budget configured", always_present: true },
        BuiltinDetector { name: "budget_utilization_pct".into(),   returns: "int[0-100]", description: "Budget consumed as a percentage; -1 if no budget configured", always_present: true },
        BuiltinDetector { name: "estimated_cost_cents".into(),     returns: "int",    description: "Estimated cost of this request in cents", always_present: true },
    ]
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn eval_permit_returns_allow() {
        let req = EvalRequest {
            cedar_text: "permit(principal, action, resource);".into(),
            principal: default_principal(),
            action: default_action(),
            resource: default_resource(),
            context: json!({}),
        };
        let Json(res) = eval_policy(Json(req)).await.unwrap();
        assert_eq!(res.decision, "allow");
        assert!(res.regulatory_mapping.is_empty());
    }

    #[tokio::test]
    async fn eval_forbid_returns_block() {
        let req = EvalRequest {
            cedar_text: "forbid(principal, action, resource);".into(),
            principal: default_principal(),
            action: default_action(),
            resource: default_resource(),
            context: json!({}),
        };
        let Json(res) = eval_policy(Json(req)).await.unwrap();
        assert_eq!(res.decision, "block");
    }

    #[tokio::test]
    async fn eval_flag_annotation_returns_flag() {
        let cedar = r#"
            @id("flag-pii")
            @enforcement("flag")
            @regulatory_mapping("SOC2_CC6.1, EU_AI_ACT_9")
            forbid(principal, action, resource)
            when { context has pii_detected && context.pii_detected == true };
        "#;
        let req = EvalRequest {
            cedar_text: cedar.into(),
            principal: default_principal(),
            action: default_action(),
            resource: default_resource(),
            context: json!({ "pii_detected": true }),
        };
        let Json(res) = eval_policy(Json(req)).await.unwrap();
        assert_eq!(res.decision, "flag");
        assert_eq!(res.rule_id.as_deref(), Some("flag-pii"));
        assert_eq!(res.regulatory_mapping, vec!["SOC2_CC6.1", "EU_AI_ACT_9"]);
    }

    #[tokio::test]
    async fn eval_invalid_cedar_returns_422() {
        let req = EvalRequest {
            cedar_text: "this is not cedar".into(),
            principal: default_principal(),
            action: default_action(),
            resource: default_resource(),
            context: json!({}),
        };
        let result = eval_policy(Json(req)).await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn eval_response_side_evaluates_correctly() {
        let cedar = r#"
            permit(principal, action, resource);
            @id("block-tool")
            @enforcement("block")
            forbid(principal, action, resource)
            when { context has tool_names && context.tool_names.contains("execute_trade") };
        "#;
        let req = EvalRequest {
            cedar_text: cedar.into(),
            principal: "ops-bot".into(),
            action: "tool.call".into(),
            resource: "response".into(),
            context: json!({ "tool_names": ["execute_trade"], "tool_count": 1 }),
        };
        let Json(res) = eval_policy(Json(req)).await.unwrap();
        assert_eq!(res.decision, "block");
        assert_eq!(res.rule_id.as_deref(), Some("block-tool"));
    }

    #[tokio::test]
    async fn eval_allows_when_condition_not_met() {
        let cedar = r#"
            permit(principal, action, resource);
            @enforcement("block")
            forbid(principal, action, resource)
            when { context has pii_detected && context.pii_detected == true };
        "#;
        let req = EvalRequest {
            cedar_text: cedar.into(),
            principal: default_principal(),
            action: default_action(),
            resource: default_resource(),
            context: json!({ "pii_detected": false }),
        };
        let Json(res) = eval_policy(Json(req)).await.unwrap();
        assert_eq!(res.decision, "allow");
    }

    #[test]
    fn detectors_list_is_non_empty_and_all_builtin_always_present() {
        let detectors = builtin_detectors();
        assert!(!detectors.is_empty());
        // Every built-in detector should have a non-empty name and description
        for d in &detectors {
            assert!(!d.name.is_empty(), "detector missing name");
            assert!(!d.description.is_empty(), "detector {} missing description", d.name);
        }
    }

    #[test]
    fn detectors_covers_all_context_params_fields() {
        // Spot-check the fields from ContextParams are represented
        let detectors = builtin_detectors();
        let names: Vec<&str> = detectors.iter().map(|d| d.name.as_str()).collect();
        for expected in &[
            "injection_detected", "jailbreak_detected", "pii_detected",
            "threat_detected", "exfiltration_detected",
            "tool_names", "budget_remaining_cents",
            "model", "agent_id",
        ] {
            assert!(names.contains(expected), "missing detector: {expected}");
        }
    }
}
