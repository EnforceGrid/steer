pub mod action;
pub mod cedar;
pub mod control_mapper;
pub mod input;
pub mod registry;
pub mod sync_promoter;
pub mod watcher;

pub use action::EnforcementAction;
pub use input::{PolicyAction, PolicyInput, ContextParams, build_context, DetectionLabel};
pub use cedar::CedarEngine;
pub use watcher::PolicyWatcher;

use crate::error::SteerResult;

/// Static coverage metadata for a single policy — used by the compliance
/// coverage endpoint to report which frameworks are mapped.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyCoverageEntry {
    pub id: String,
    pub description: Option<String>,
    pub enforcement: String,
    pub frameworks: Vec<String>,
}

/// Metadata for a single Cedar policy that matched during evaluation.
/// Captured for every matching policy — not just the most-restrictive winner.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MatchedRule {
    pub rule_id: String,
    /// The `@enforcement` annotation value: allow|transform|flag|steer|block.
    /// Always the annotation value — NOT Cedar's binary permit/forbid effect.
    pub action: String,
    /// The `@category` annotation value (e.g. "data_protection", "tool_governance").
    #[serde(skip_serializing_if = "String::is_empty")]
    pub category: String,
    /// Regulatory frameworks from `@regulatory_mapping` annotation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regulatory_mapping: Vec<String>,
}

/// A policy evaluation result for a single request/response.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub action: EnforcementAction,
    /// Which rule triggered this decision (if any). Always the most-restrictive winner.
    pub rule_id: Option<String>,
    /// Steer message to inject (only populated when action == Steer).
    pub steer_message: Option<String>,
    /// Transform replacement (only populated when action == Transform).
    pub transform_to: Option<String>,
    /// Human-readable description from `@description("...")` annotation.
    pub description: Option<String>,
    /// Regulatory frameworks from `@regulatory_mapping("...")` annotation (winner only).
    pub regulatory_mapping: Vec<String>,
    /// All Cedar policies that contributed to this decision — not just the winner.
    /// Preserves every matched rule's action, category, and regulatory_mapping.
    pub matched_rules: Vec<MatchedRule>,
}

impl PolicyDecision {
    pub fn allow() -> Self {
        Self {
            action: EnforcementAction::Allow,
            rule_id: None,
            steer_message: None,
            transform_to: None,
            description: None,
            regulatory_mapping: vec![],
            matched_rules: vec![],
        }
    }
}

/// Trait for policy engines. Cedar is the only implementation for now;
/// Rego/OPA and OpenFGA are future extensions.
pub trait PolicyEngine: Send + Sync {
    fn evaluate_request(
        &self,
        principal: &str,
        action: &str,
        resource_attrs: &serde_json::Value,
        context_attrs: &serde_json::Value,
    ) -> SteerResult<PolicyDecision>;

    fn evaluate_response(
        &self,
        principal: &str,
        action: &str,
        resource_attrs: &serde_json::Value,
        context_attrs: &serde_json::Value,
    ) -> SteerResult<PolicyDecision>;
}
