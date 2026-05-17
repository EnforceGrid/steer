use std::path::Path;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Effect, Entities, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, Response, Schema, ValidationMode, Validator,
};
use once_cell::sync::Lazy;
use serde_json::Value;
use tracing::{debug, warn};

use crate::config::PolicyConfig;
use crate::error::{SteerError, SteerResult};
use super::action::EnforcementAction;
use super::{PolicyCoverageEntry, PolicyDecision, PolicyEngine};

// ── Static EnforceGrid schema (parsed once at startup) ───────────────────────
// Used by validate_with_schema() to catch mis-typed context field references
// at policy-write time rather than letting them silently evaluate to false.

static ENFORCED_SCHEMA: Lazy<Option<Schema>> = Lazy::new(|| {
    Schema::from_cedarschema_str(include_str!("../../dsl/schema.cedarschema"))
        .map(|(schema, warnings)| {
            for w in warnings {
                tracing::warn!(warning = %w, "cedar schema parse warning");
            }
            schema
        })
        .map_err(|e| tracing::warn!(error = %e, "failed to parse dsl/schema.cedarschema — schema validation disabled"))
        .ok()
});

// ── Cached entity type names (parsed once at startup) ────────────────────────
// EntityTypeName::from_str is non-trivial (string parsing + validation).
// Caching these four constants avoids re-parsing on every request.

static PRINCIPAL_TYPE: Lazy<EntityTypeName> = Lazy::new(|| {
    EntityTypeName::from_str("EnforceGrid::Principal").expect("static entity type name")
});
static ACTION_TYPE: Lazy<EntityTypeName> = Lazy::new(|| {
    EntityTypeName::from_str("EnforceGrid::Action").expect("static entity type name")
});
static REQUEST_RESOURCE_TYPE: Lazy<EntityTypeName> = Lazy::new(|| {
    EntityTypeName::from_str("EnforceGrid::Request").expect("static entity type name")
});
static RESPONSE_RESOURCE_TYPE: Lazy<EntityTypeName> = Lazy::new(|| {
    EntityTypeName::from_str("EnforceGrid::Response").expect("static entity type name")
});

pub struct CedarEngine {
    policy_set: PolicySet,
    authorizer: Authorizer,
    /// Original policy source text — used by SyncRequirements::analyze()
    /// to determine which detectors must run synchronously.
    source_text: String,
}

impl CedarEngine {
    /// Load all .cedar files from a directory.
    pub fn from_dir(dir: &str) -> SteerResult<Self> {
        let path = Path::new(dir);
        let mut combined = String::new();

        if path.exists() && path.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(path)
                .map_err(|e| SteerError::Config(format!("cannot read policy dir {dir}: {e}")))?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "cedar"))
                .collect();
            entries.sort_by_key(|e| e.path());

            for entry in entries {
                let content = std::fs::read_to_string(entry.path())
                    .map_err(|e| SteerError::Config(format!("cannot read {:?}: {e}", entry.path())))?;
                combined.push_str(&content);
                combined.push('\n');
            }
        }

        // If no policies found, use a permissive default
        if combined.trim().is_empty() {
            combined = DEFAULT_POLICY.to_string();
        }

        Self::from_policy_str(&combined)
    }

    /// Load from a single policy file.
    pub fn from_file(path: &str) -> SteerResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| SteerError::Config(format!("cannot read policy file {path}: {e}")))?;
        Self::from_policy_str(&content)
    }

    /// Build a permissive engine that allows all traffic.
    /// Used as a safe fallback when tenant policy loading fails.
    pub fn permissive() -> Self {
        Self::from_policy_str(DEFAULT_POLICY)
            .expect("DEFAULT_POLICY is always valid Cedar")
    }

    /// Load from a [`PolicyConfig`]: uses `policy_file` when set, otherwise
    /// loads all `.cedar` files from `policy_dir`.
    pub fn load_from_config(config: &PolicyConfig) -> SteerResult<Self> {
        if let Some(ref file) = config.policy_file {
            Self::from_file(file)
        } else {
            Self::from_dir(&config.policy_dir)
        }
    }

    /// Return the number of policies currently loaded.
    pub fn policy_count(&self) -> usize {
        self.policy_set.policies().count()
    }

    /// Return all `@id` annotation values in the loaded policy set.
    /// Used for collision detection when adding new policies.
    pub fn policy_ids(&self) -> Vec<String> {
        self.policy_set
            .policies()
            .filter_map(|p| p.annotation("id").map(String::from))
            .collect()
    }

    /// Return a summary of each policy: (id_annotation, effect, enforcement).
    pub fn policy_summaries(&self) -> Vec<(String, &'static str, String)> {
        self.policy_set.policies().map(|p| {
            let id = p.annotation("id").map(String::from)
                .unwrap_or_else(|| p.id().to_string());
            let effect = match p.effect() {
                cedar_policy::Effect::Permit => "permit",
                cedar_policy::Effect::Forbid => "forbid",
            };
            let enforcement = p.annotation("enforcement")
                .map(String::from)
                .unwrap_or_else(|| match p.effect() {
                    cedar_policy::Effect::Permit => "allow".to_string(),
                    cedar_policy::Effect::Forbid => "block".to_string(),
                });
            (id, effect, enforcement)
        }).collect()
    }

    /// Return per-policy coverage metadata: id, description, enforcement action,
    /// and regulatory framework mappings.  Used by `GET /api/v1/compliance/coverage`
    /// to report which frameworks are covered by the active policy set.
    pub fn policy_coverage(&self) -> Vec<PolicyCoverageEntry> {
        self.policy_set.policies().filter_map(|p| {
            let mappings_raw = p.annotation("regulatory_mapping")?;
            let frameworks: Vec<String> = mappings_raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if frameworks.is_empty() {
                return None;
            }
            let id = p.annotation("id").map(String::from)
                .unwrap_or_else(|| p.id().to_string());
            let description = p.annotation("description").map(String::from);
            let enforcement = p.annotation("enforcement")
                .map(String::from)
                .unwrap_or_else(|| match p.effect() {
                    Effect::Permit => "allow".to_string(),
                    Effect::Forbid => "block".to_string(),
                });
            Some(PolicyCoverageEntry { id, description, enforcement, frameworks })
        }).collect()
    }

    pub fn from_policy_str(policy_text: &str) -> SteerResult<Self> {
        let policy_set = PolicySet::from_str(policy_text)
            .map_err(|e| SteerError::CedarPolicy(format!("policy parse error: {e}")))?;
        Ok(Self {
            policy_set,
            authorizer: Authorizer::new(),
            source_text: policy_text.to_string(),
        })
    }

    /// Return the original policy source text.
    /// Used by `SyncRequirements::analyze()` to determine which detectors
    /// must run synchronously for enforcement-linked policies.
    pub fn policy_text(&self) -> &str {
        &self.source_text
    }

    /// Type-check this engine's policy set against the static EnforceGrid schema.
    ///
    /// Returns a list of human-readable error strings.  An empty list means
    /// the policy set is schema-valid.  Returns `None` if the schema failed to
    /// load at startup (should not happen in a correctly built binary).
    pub fn validate_with_schema(&self) -> Option<Vec<String>> {
        let schema = ENFORCED_SCHEMA.as_ref()?;
        let result = Validator::new(schema.clone()).validate(&self.policy_set, ValidationMode::Strict);
        let errors: Vec<String> = result
            .validation_errors()
            .map(|e| e.to_string())
            .collect();
        Some(errors)
    }

    fn make_entity_uid(type_name: &str, id: &str) -> SteerResult<EntityUid> {
        // Use cached EntityTypeName for the four known static types; fall back
        // to parsing for any other type (e.g., in tests or future extensions).
        let etype = match type_name {
            "EnforceGrid::Principal"  => PRINCIPAL_TYPE.clone(),
            "EnforceGrid::Action"     => ACTION_TYPE.clone(),
            "EnforceGrid::Request"    => REQUEST_RESOURCE_TYPE.clone(),
            "EnforceGrid::Response"   => RESPONSE_RESOURCE_TYPE.clone(),
            other => EntityTypeName::from_str(other)
                .map_err(|e| SteerError::CedarPolicy(format!("invalid entity type '{other}': {e}")))?,
        };
        let eid = EntityId::from_str(id)
            .map_err(|e| SteerError::CedarPolicy(format!("invalid entity id '{id}': {e}")))?;
        Ok(EntityUid::from_type_name_and_id(etype, eid))
    }

    #[allow(clippy::too_many_arguments)] // 3 Cedar entity (type, id) pairs + context is the correct interface
    fn evaluate_inner(
        &self,
        principal_type: &str,
        principal_id: &str,
        action_type: &str,
        action_id: &str,
        resource_type: &str,
        resource_id: &str,
        context_attrs: &Value,
    ) -> SteerResult<PolicyDecision> {
        let principal_uid = Self::make_entity_uid(principal_type, principal_id)?;
        let action_uid = Self::make_entity_uid(action_type, action_id)?;
        let resource_uid = Self::make_entity_uid(resource_type, resource_id)?;

        // Build context directly from the JSON Value — avoids an intermediate
        // serialize-to-string + re-parse that from_json_str would require.
        let context = Context::from_json_value(context_attrs.clone(), None)
            .map_err(|e| SteerError::CedarPolicy(format!("context parse error: {e}")))?;

        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            context,
            None,
        )
        .map_err(|e| SteerError::CedarPolicy(format!("request build error: {e}")))?;

        let entities = Entities::empty();
        let response = self.authorizer.is_authorized(&request, &self.policy_set, &entities);

        debug!(decision = ?response.decision(), "cedar authorization");

        self.resolve_decision(&response)
    }

    /// Resolve a Cedar authorization response into a [`PolicyDecision`] by
    /// reading `@enforcement`, `@steer_message`, `@transform_pattern`, and
    /// `@transform_replace` annotations from every determining policy.
    ///
    /// When multiple determining policies fire, the most restrictive
    /// [`EnforcementAction`] wins (via `Ord`-based max).  Metadata
    /// (`steer_message`, `transform_to`) is taken from the policy that
    /// contributed the winning action.
    fn resolve_decision(&self, response: &Response) -> SteerResult<PolicyDecision> {
        let decision = response.decision();
        let reason_ids: Vec<_> = response.diagnostics().reason().collect();

        // Defaults when there are no determining policies or no annotations.
        let default_action = match decision {
            Decision::Allow => EnforcementAction::Allow,
            Decision::Deny  => EnforcementAction::Block,
        };

        if reason_ids.is_empty() {
            return Ok(PolicyDecision {
                action: default_action,
                rule_id: None,
                steer_message: None,
                transform_to: None,
                description: None,
                regulatory_mapping: vec![],
                matched_rules: vec![],
            });
        }

        let mut resolved_action = None::<EnforcementAction>;
        let mut winning_rule_id = None::<String>;
        let mut steer_message = None::<String>;
        let mut transform_to = None::<String>;
        let mut description = None::<String>;
        let mut regulatory_mapping = Vec::<String>::new();
        let mut matched_rules = Vec::<crate::policy::MatchedRule>::new();

        for pid in &reason_ids {
            let policy = match self.policy_set.policy(pid) {
                Some(p) => p,
                None => continue,
            };

            let effect = policy.effect();

            // Determine the enforcement action for this policy.
            // Always use the @enforcement annotation — NOT Cedar's binary effect.
            let action = match policy.annotation("enforcement") {
                Some(val) => match val.to_lowercase().as_str() {
                    "allow"     => EnforcementAction::Allow,
                    "transform" => EnforcementAction::Transform,
                    "flag"      => EnforcementAction::Flag,
                    "steer"     => EnforcementAction::Steer,
                    "block"     => EnforcementAction::Block,
                    other => {
                        warn!(
                            policy_id = %pid,
                            annotation = other,
                            "unknown @enforcement annotation value — using effect default"
                        );
                        match effect {
                            Effect::Forbid => EnforcementAction::Block,
                            Effect::Permit => EnforcementAction::Allow,
                        }
                    }
                },
                None => match effect {
                    Effect::Forbid => EnforcementAction::Block,
                    Effect::Permit => EnforcementAction::Allow,
                },
            };

            // Only authored policies have @id — baseline permit(principal, action, resource)
            // has no @id and should not appear in matched_rules.
            let maybe_rule_id = policy.annotation("id").map(String::from);

            let this_regulatory_mapping: Vec<String> = policy.annotation("regulatory_mapping")
                .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default();

            // Accumulate every authored matched policy — not just the winner.
            if let Some(ref id) = maybe_rule_id {
                matched_rules.push(crate::policy::MatchedRule {
                    rule_id: id.clone(),
                    action: action.to_string(),
                    category: policy.annotation("category").map(String::from).unwrap_or_default(),
                    regulatory_mapping: this_regulatory_mapping.clone(),
                });
            }

            let this_rule_id = maybe_rule_id.unwrap_or_else(|| pid.to_string());

            // Track the most restrictive action seen so far.
            let dominated = match &resolved_action {
                Some(prev) => action > *prev,
                None => true,
            };

            if dominated {
                // Capture metadata from the winning policy.
                steer_message = policy.annotation("steer_message").map(String::from);
                transform_to = Self::build_transform_replacement(policy);
                description = policy.annotation("description").map(String::from);
                regulatory_mapping = this_regulatory_mapping;
                winning_rule_id = Some(this_rule_id);
                resolved_action = Some(action);
            }
        }

        let final_action = resolved_action.unwrap_or(default_action);

        Ok(PolicyDecision {
            action: final_action,
            rule_id: winning_rule_id.or_else(|| reason_ids.first().map(|id| id.to_string())),
            steer_message,
            transform_to,
            description,
            regulatory_mapping,
            matched_rules,
        })
    }

    /// Build the transform replacement string from `@transform_pattern` and
    /// `@transform_replace` annotations.  Returns `Some("pattern→replace")`
    /// when at least `@transform_pattern` is present.
    fn build_transform_replacement(policy: &cedar_policy::Policy) -> Option<String> {
        let pattern = policy.annotation("transform_pattern")?;
        let replace = policy.annotation("transform_replace").unwrap_or("[REDACTED]");
        Some(format!("{pattern}\x1f{replace}"))
    }
}

impl PolicyEngine for CedarEngine {
    fn evaluate_request(
        &self,
        principal: &str,
        action: &str,
        _resource_attrs: &Value,
        context_attrs: &Value,
    ) -> SteerResult<PolicyDecision> {
        match self.evaluate_inner(
            "EnforceGrid::Principal",
            principal,
            "EnforceGrid::Action",
            action,
            "EnforceGrid::Request",
            "request",
            context_attrs,
        ) {
            Ok(d) => Ok(d),
            Err(e) => {
                warn!(error = %e, "cedar request eval error — defaulting to allow");
                Ok(PolicyDecision::allow())
            }
        }
    }

    fn evaluate_response(
        &self,
        principal: &str,
        action: &str,
        _resource_attrs: &Value,
        context_attrs: &Value,
    ) -> SteerResult<PolicyDecision> {
        match self.evaluate_inner(
            "EnforceGrid::Principal",
            principal,
            "EnforceGrid::Action",
            action,
            "EnforceGrid::Response",
            "response",
            context_attrs,
        ) {
            Ok(d) => Ok(d),
            Err(e) => {
                warn!(error = %e, "cedar response eval error — defaulting to allow");
                Ok(PolicyDecision::allow())
            }
        }
    }
}

/// Rewrite `@enforcement` annotations in Cedar policy text for observation mode.
///
/// When `mode` is `"observation"`:
/// - `@enforcement("block")` → `@enforcement("flag")`
/// - `@enforcement("steer")` → `@enforcement("flag")`
/// - `forbid` rules with no `@enforcement` annotation get `@enforcement("flag")` injected
///
/// `permit` rules, `@enforcement("flag")`, `@enforcement("allow")`, and
/// `@enforcement("transform")` are left untouched.
///
/// When `mode` is `"enforced"` (or any other value), the text is returned unchanged.
pub fn rewrite_enforcement_annotations(cedar_text: &str, mode: &str) -> String {
    if mode != "observation" {
        return cedar_text.to_string();
    }

    use regex::Regex;
    use once_cell::sync::Lazy;

    // Match @enforcement("block") or @enforcement("steer")
    static ENFORCEMENT_BLOCK_STEER: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"@enforcement\(\s*"(?i)(block|steer)"\s*\)"#).expect("valid regex")
    });

    let mut result = String::with_capacity(cedar_text.len());
    let lines: Vec<&str> = cedar_text.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Rewrite existing block/steer enforcement annotations to flag
        if ENFORCEMENT_BLOCK_STEER.is_match(trimmed) {
            let indent = &line[..line.len() - line.trim_start().len()];
            let replaced = ENFORCEMENT_BLOCK_STEER.replace(trimmed, r#"@enforcement("flag")"#);
            result.push_str(indent);
            result.push_str(&replaced);
            result.push('\n');
            continue;
        }

        // Check if this is a forbid line — if so, ensure it has @enforcement("flag")
        if trimmed.starts_with("forbid(") {
            // Walk backwards through annotations, blanks, and comments
            let mut has_enforcement = false;
            for j in (0..i).rev() {
                let prev = lines[j].trim();
                if prev.is_empty() || prev.starts_with("//") {
                    continue; // skip blanks and comments
                } else if prev.starts_with('@') {
                    if prev.starts_with("@enforcement(") {
                        has_enforcement = true;
                    }
                    // Keep scanning — there may be more annotations above
                } else {
                    break; // hit a non-annotation, non-comment line — stop
                }
            }

            if !has_enforcement {
                let indent = &line[..line.len() - line.trim_start().len()];
                result.push_str(indent);
                result.push_str("@enforcement(\"flag\")\n");
            }
        }

        result.push_str(line);
        result.push('\n');
    }

    // Preserve original trailing newline behavior
    if !cedar_text.ends_with('\n') && result.ends_with('\n') {
        result.pop();
    }

    result
}

const DEFAULT_POLICY: &str = r#"
// Default permissive policy — replace with your Cedar policies in ./dsl/policies/
permit(principal, action, resource);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Helper: build a CedarEngine from inline policy text and evaluate a
    /// request with the given context.
    fn eval(policy_text: &str, context: &Value) -> PolicyDecision {
        let engine = CedarEngine::from_policy_str(policy_text).expect("parse policy");
        engine
            .evaluate_request("test-user", "llm.request", &json!({}), context)
            .expect("evaluate")
    }

    // 1. Default permit → Allow (no annotation)
    #[test]
    fn default_permit_returns_allow() {
        let d = eval("permit(principal, action, resource);", &json!({}));
        assert_eq!(d.action, EnforcementAction::Allow);
        assert!(d.steer_message.is_none());
        assert!(d.transform_to.is_none());
    }

    // 2. Default forbid → Block (no annotation)
    #[test]
    fn default_forbid_returns_block() {
        let d = eval("forbid(principal, action, resource);", &json!({}));
        assert_eq!(d.action, EnforcementAction::Block);
    }

    // 3. @enforcement("steer") on forbid → Steer with steer_message populated
    #[test]
    fn steer_annotation_on_forbid() {
        let policy = r#"
            @enforcement("steer")
            @steer_message("Please contact compliance.")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.action, EnforcementAction::Steer);
        assert_eq!(d.steer_message.as_deref(), Some("Please contact compliance."));
    }

    // 4. @enforcement("flag") on forbid → Flag (not Block)
    #[test]
    fn flag_annotation_on_forbid() {
        let policy = r#"
            @enforcement("flag")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.action, EnforcementAction::Flag);
    }

    // 5. @enforcement("flag") on permit → Flag (not Allow)
    #[test]
    fn flag_annotation_on_permit() {
        let policy = r#"
            @enforcement("flag")
            permit(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.action, EnforcementAction::Flag);
    }

    // 6. @enforcement("transform") on permit → Transform
    #[test]
    fn transform_annotation_on_permit() {
        let policy = r#"
            @enforcement("transform")
            @transform_pattern("\\bsecret\\b")
            @transform_replace("[REDACTED]")
            permit(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.action, EnforcementAction::Transform);
        assert!(d.transform_to.is_some());
        let parts: Vec<&str> = d.transform_to.as_ref().unwrap().split('\x1f').collect();
        assert_eq!(parts[0], "\\bsecret\\b");
        assert_eq!(parts[1], "[REDACTED]");
    }

    // 7. Multiple determining policies → most restrictive action wins
    #[test]
    fn multiple_policies_most_restrictive_wins() {
        // Cedar evaluates all matching forbids; both fire → Steer < Block → Block wins
        let policy = r#"
            @id("flag-rule")
            @enforcement("flag")
            forbid(principal, action, resource);

            @id("block-rule")
            @enforcement("block")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.action, EnforcementAction::Block);
    }

    // 8. Fail-open on Cedar eval error (invalid context) — PolicyEngine trait
    //    wraps evaluate_inner errors with allow.
    #[test]
    fn fail_open_on_eval_error() {
        // Construct an engine then call evaluate_request, which catches errors.
        let engine = CedarEngine::from_policy_str(
            "permit(principal, action, resource);",
        )
        .unwrap();

        // Pass a principal with an invalid entity type to trigger an error
        // inside evaluate_inner.
        let result = engine.evaluate_inner(
            "!!!Invalid", // invalid entity type name
            "user",
            "EnforceGrid::Action",
            "llm.request",
            "EnforceGrid::Request",
            "request",
            &json!({}),
        );
        // evaluate_inner itself should error
        assert!(result.is_err());

        // But evaluate_request wraps it with allow
        let d = engine
            .evaluate_request("!!!Invalid", "llm.request", &json!({}), &json!({}))
            .unwrap();
        assert_eq!(d.action, EnforcementAction::Allow);
    }

    // Description annotation is captured from the winning policy
    #[test]
    fn description_annotation_captured() {
        let policy = r#"
            @enforcement("block")
            @description("Prompt injection attempt blocked")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.action, EnforcementAction::Block);
        assert_eq!(d.description.as_deref(), Some("Prompt injection attempt blocked"));
    }

    // Regulatory mapping annotation is parsed and split on comma
    #[test]
    fn regulatory_mapping_annotation_parsed() {
        let policy = r#"
            @enforcement("block")
            @regulatory_mapping("OWASP_AGENTIC_ASI01, EU_AI_ACT_ART_9")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.action, EnforcementAction::Block);
        assert_eq!(d.regulatory_mapping, vec!["OWASP_AGENTIC_ASI01", "EU_AI_ACT_ART_9"]);
    }

    // No regulatory_mapping annotation → empty vec
    #[test]
    fn no_regulatory_mapping_is_empty() {
        let policy = r#"
            @enforcement("block")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert!(d.regulatory_mapping.is_empty());
    }

    // @id annotation is used as rule_id (not Cedar's internal policy0 numbering)
    #[test]
    fn id_annotation_used_as_rule_id() {
        let policy = r#"
            @id("block-pii-leaks")
            @enforcement("block")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.rule_id.as_deref(), Some("block-pii-leaks"));
    }

    // Without @id annotation, rule_id falls back to Cedar's internal numbering
    #[test]
    fn no_id_annotation_falls_back_to_internal() {
        let policy = r#"
            @enforcement("block")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        // Should have some rule_id (Cedar internal like "policy0"), not None
        assert!(d.rule_id.is_some());
    }

    // No description annotation → description is None
    #[test]
    fn no_description_annotation_is_none() {
        let policy = r#"
            @enforcement("block")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.action, EnforcementAction::Block);
        assert!(d.description.is_none());
    }

    // Steer without steer_message annotation — steer_message should be None
    #[test]
    fn steer_without_message_annotation() {
        let policy = r#"
            @enforcement("steer")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.action, EnforcementAction::Steer);
        assert!(d.steer_message.is_none());
    }

    // Unknown annotation value falls back to effect default
    #[test]
    fn unknown_enforcement_value_falls_back() {
        let policy = r#"
            @enforcement("quarantine")
            forbid(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        // Unknown on forbid → Block (effect default)
        assert_eq!(d.action, EnforcementAction::Block);
    }

    // Forbid with condition + permit baseline → forbid wins when condition is true
    #[test]
    fn forbid_with_pii_detected_blocks_when_true() {
        let policy = r#"
            permit(principal, action, resource);

            @id("block-pii-leaks")
            @enforcement("block")
            forbid(principal, action, resource)
            when { context has pii_detected && context.pii_detected == true };
        "#;
        let d = eval(policy, &json!({"pii_detected": true}));
        assert_eq!(d.action, EnforcementAction::Block);
    }

    #[test]
    fn forbid_with_pii_detected_allows_when_false() {
        let policy = r#"
            permit(principal, action, resource);

            @id("block-pii-leaks")
            @enforcement("block")
            forbid(principal, action, resource)
            when { context has pii_detected && context.pii_detected == true };
        "#;
        let d = eval(policy, &json!({"pii_detected": false}));
        assert_eq!(d.action, EnforcementAction::Allow);
    }

    // Transform annotation with pattern but no replace → defaults to [REDACTED]
    #[test]
    fn transform_default_replace() {
        let policy = r#"
            @enforcement("transform")
            @transform_pattern("\\d{3}-\\d{2}-\\d{4}")
            permit(principal, action, resource);
        "#;
        let d = eval(policy, &json!({}));
        assert_eq!(d.action, EnforcementAction::Transform);
        let parts: Vec<&str> = d.transform_to.as_ref().unwrap().split('\x1f').collect();
        assert_eq!(parts[1], "[REDACTED]");
    }

    /// Helper: evaluate a response policy with the given context.
    fn eval_response(policy_text: &str, context: &Value) -> PolicyDecision {
        let engine = CedarEngine::from_policy_str(policy_text).expect("parse policy");
        engine
            .evaluate_response("test-user", "tool.call", &json!({}), context)
            .expect("evaluate")
    }

    // ── T-905: Cedar tool-call governance tests ─────────────────────────────

    #[test]
    fn tool_block_policy_blocks_forbidden_tool() {
        let policy = r#"
            permit(principal, action, resource);
            @id("block-tool-execute-trade")
            @enforcement("block")
            forbid(principal, action, resource)
            when { context has tool_names && context.tool_names.contains("execute_trade") };
        "#;
        let d = eval_response(policy, &json!({
            "tool_names": ["execute_trade", "get_price"],
            "tool_count": 2,
        }));
        assert_eq!(d.action, EnforcementAction::Block);
        assert!(d.rule_id.is_some(), "should have a rule_id");
    }

    #[test]
    fn tool_block_policy_allows_safe_tool() {
        let policy = r#"
            permit(principal, action, resource);
            @id("block-tool-execute-trade")
            @enforcement("block")
            forbid(principal, action, resource)
            when { context has tool_names && context.tool_names.contains("execute_trade") };
        "#;
        let d = eval_response(policy, &json!({
            "tool_names": ["get_weather"],
            "tool_count": 1,
        }));
        assert_eq!(d.action, EnforcementAction::Allow);
    }

    #[test]
    fn tool_flag_policy_flags_monitored_tool() {
        let policy = r#"
            permit(principal, action, resource);
            @id("flag-tool-send-email")
            @enforcement("flag")
            forbid(principal, action, resource)
            when { context has tool_names && context.tool_names.contains("send_email") };
        "#;
        let d = eval_response(policy, &json!({
            "tool_names": ["send_email"],
            "tool_count": 1,
        }));
        assert_eq!(d.action, EnforcementAction::Flag);
    }

    #[test]
    fn tool_count_limit_flags_excessive_calls() {
        let policy = r#"
            permit(principal, action, resource);
            @id("flag-excessive-tool-calls")
            @enforcement("flag")
            forbid(principal, action, resource)
            when { context has tool_count && context.tool_count > 3 };
        "#;
        let d = eval_response(policy, &json!({
            "tool_names": ["a", "b", "c", "d"],
            "tool_count": 4,
        }));
        assert_eq!(d.action, EnforcementAction::Flag);
    }

    #[test]
    fn tool_count_limit_allows_under_threshold() {
        let policy = r#"
            permit(principal, action, resource);
            @id("flag-excessive-tool-calls")
            @enforcement("flag")
            forbid(principal, action, resource)
            when { context has tool_count && context.tool_count > 3 };
        "#;
        let d = eval_response(policy, &json!({
            "tool_names": ["a", "b"],
            "tool_count": 2,
        }));
        assert_eq!(d.action, EnforcementAction::Allow);
    }

    #[test]
    fn request_tool_block_prevents_forbidden_tool_in_request() {
        let policy = r#"
            permit(principal, action, resource);
            @id("block-request-with-dangerous-tool")
            @enforcement("block")
            forbid(principal, action, resource)
            when { context has requested_tools && context.requested_tools.contains("delete_all_data") };
        "#;
        let d = eval(policy, &json!({
            "model": "gpt-4o",
            "requested_tools": ["get_weather", "delete_all_data"],
            "requested_tool_count": 2,
        }));
        assert_eq!(d.action, EnforcementAction::Block);
    }

    #[test]
    fn request_tool_block_allows_safe_tools() {
        let policy = r#"
            permit(principal, action, resource);
            @id("block-request-with-dangerous-tool")
            @enforcement("block")
            forbid(principal, action, resource)
            when { context has requested_tools && context.requested_tools.contains("delete_all_data") };
        "#;
        let d = eval(policy, &json!({
            "model": "gpt-4o",
            "requested_tools": ["get_weather", "send_email"],
            "requested_tool_count": 2,
        }));
        assert_eq!(d.action, EnforcementAction::Allow);
    }

    #[test]
    fn no_tool_context_does_not_trigger_tool_policy() {
        // When no tools in request/response, tool policies should not fire
        let policy = r#"
            permit(principal, action, resource);
            @id("block-tool")
            @enforcement("block")
            forbid(principal, action, resource)
            when { context has tool_names && context.tool_names.contains("execute_trade") };
        "#;
        let d = eval_response(policy, &json!({
            "model": "gpt-4o",
            "streaming": false,
        }));
        assert_eq!(d.action, EnforcementAction::Allow);
    }

    // ── Observation mode annotation rewriting tests ────────────────────────

    #[test]
    fn rewrite_block_to_flag_in_observation_mode() {
        let input = r#"@enforcement("block")
forbid(principal, action, resource);"#;
        let output = super::rewrite_enforcement_annotations(input, "observation");
        assert!(output.contains(r#"@enforcement("flag")"#));
        assert!(!output.contains(r#"@enforcement("block")"#));
    }

    #[test]
    fn rewrite_steer_to_flag_in_observation_mode() {
        let input = r#"@enforcement("steer")
@steer_message("Contact compliance.")
forbid(principal, action, resource);"#;
        let output = super::rewrite_enforcement_annotations(input, "observation");
        assert!(output.contains(r#"@enforcement("flag")"#));
        assert!(!output.contains(r#"@enforcement("steer")"#));
        // steer_message annotation preserved
        assert!(output.contains("@steer_message"));
    }

    #[test]
    fn rewrite_leaves_flag_untouched() {
        let input = r#"@enforcement("flag")
forbid(principal, action, resource);"#;
        let output = super::rewrite_enforcement_annotations(input, "observation");
        assert_eq!(output.matches(r#"@enforcement("flag")"#).count(), 1);
    }

    #[test]
    fn rewrite_leaves_permit_untouched() {
        let input = r#"permit(principal, action, resource);"#;
        let output = super::rewrite_enforcement_annotations(input, "observation");
        assert!(!output.contains("@enforcement"));
        assert!(output.contains("permit(principal, action, resource);"));
    }

    #[test]
    fn rewrite_leaves_transform_untouched() {
        let input = r#"@enforcement("transform")
@transform_pattern("\bsecret\b")
permit(principal, action, resource);"#;
        let output = super::rewrite_enforcement_annotations(input, "observation");
        assert!(output.contains(r#"@enforcement("transform")"#));
    }

    #[test]
    fn rewrite_injects_flag_on_bare_forbid() {
        let input = r#"@id("bare-forbid")
@description("No enforcement annotation")
forbid(principal, action, resource);"#;
        let output = super::rewrite_enforcement_annotations(input, "observation");
        assert!(output.contains(r#"@enforcement("flag")"#));
        assert!(output.contains("forbid(principal, action, resource);"));
    }

    #[test]
    fn rewrite_no_op_for_enforced_mode() {
        let input = r#"@enforcement("block")
forbid(principal, action, resource);"#;
        let output = super::rewrite_enforcement_annotations(input, "enforced");
        assert_eq!(output, input);
    }

    #[test]
    fn rewrite_handles_multi_policy_text() {
        let input = r#"permit(principal, action, resource);

@id("injection-block")
@enforcement("block")
forbid(principal, action, resource)
when { context.injection_detected == true };

@id("pii-flag")
@enforcement("flag")
forbid(principal, action, resource)
when { context.pii_detected == true };

@id("bare-forbid")
forbid(principal, action, resource)
when { context.threat_detected == true };"#;
        let output = super::rewrite_enforcement_annotations(input, "observation");
        // block → flag
        assert!(!output.contains(r#"@enforcement("block")"#));
        // existing flag stays
        assert!(output.contains(r#"@enforcement("flag")"#));
        // bare forbid gets flag injected
        // Count: injection-block rewritten + pii-flag kept + bare-forbid injected = 3
        assert_eq!(output.matches(r#"@enforcement("flag")"#).count(), 3);
        // permit untouched
        assert!(!output.contains("@enforcement") || output.lines().any(|l| l.contains("permit")));
    }

    #[test]
    fn rewrite_preserves_indentation() {
        let input = "    @enforcement(\"block\")\n    forbid(principal, action, resource);";
        let output = super::rewrite_enforcement_annotations(input, "observation");
        // Should preserve 4-space indent
        assert!(output.contains("    @enforcement(\"flag\")"));
    }

    #[test]
    fn rewrite_handles_comments_between_annotations_and_forbid() {
        let input = r#"@id("test")
// This is a comment
@enforcement("block")
forbid(principal, action, resource);"#;
        let output = super::rewrite_enforcement_annotations(input, "observation");
        assert!(output.contains(r#"@enforcement("flag")"#));
        assert!(!output.contains(r#"@enforcement("block")"#));
    }

    #[test]
    fn rewritten_policy_still_parses_as_valid_cedar() {
        let input = r#"
            permit(principal, action, resource);
            @id("test-block")
            @enforcement("block")
            forbid(principal, action, resource)
            when { context.injection_detected == true };
        "#;
        let rewritten = super::rewrite_enforcement_annotations(input, "observation");
        let engine = CedarEngine::from_policy_str(&rewritten);
        assert!(engine.is_ok(), "rewritten policy must parse: {:?}", engine.err());
    }

    #[test]
    fn rewritten_bare_forbid_still_parses() {
        let input = r#"
            permit(principal, action, resource);
            @id("bare-test")
            forbid(principal, action, resource)
            when { context.pii_detected == true };
        "#;
        let rewritten = super::rewrite_enforcement_annotations(input, "observation");
        assert!(rewritten.contains(r#"@enforcement("flag")"#));
        let engine = CedarEngine::from_policy_str(&rewritten);
        assert!(engine.is_ok(), "rewritten policy must parse: {:?}", engine.err());
    }

    // ── matched_rules: all fired policies captured, not just winner ──────────

    #[test]
    fn matched_rules_captures_all_fired_policies() {
        // Two forbid rules fire; winner is block but both should appear in matched_rules.
        let policy = r#"
            permit(principal, action, resource);
            @id("consent-flag")
            @category("data_protection")
            @enforcement("flag")
            @regulatory_mapping("AIUC1_E005, GDPR_ART_6")
            forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
            when { context.consent_given == false };

            @id("budget-block")
            @category("operational")
            @enforcement("block")
            @regulatory_mapping("AIUC1_B004")
            forbid(principal, action, resource)
            when { context.budget_remaining_cents == 0 };
        "#;
        let d = eval(policy, &json!({
            "consent_given": false,
            "budget_remaining_cents": 0,
        }));

        // Winner is block (more restrictive)
        assert_eq!(d.action, EnforcementAction::Block);
        assert_eq!(d.rule_id.as_deref(), Some("budget-block"));

        // Both rules must appear in matched_rules
        assert_eq!(d.matched_rules.len(), 2);
        let ids: Vec<&str> = d.matched_rules.iter().map(|r| r.rule_id.as_str()).collect();
        assert!(ids.contains(&"consent-flag"), "consent-flag missing from matched_rules");
        assert!(ids.contains(&"budget-block"), "budget-block missing from matched_rules");
    }

    #[test]
    fn matched_rules_preserves_per_rule_action_and_category() {
        let policy = r#"
            permit(principal, action, resource);
            @id("pii-flag")
            @category("data_protection")
            @enforcement("flag")
            @regulatory_mapping("GDPR_ART_5, AIUC1_E001")
            forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
            when { context.pii_detected == true };

            @id("injection-flag")
            @category("injection")
            @enforcement("flag")
            @regulatory_mapping("OWASP_AGENTIC_ASI01")
            forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
            when { context.injection_detected == true };
        "#;
        let d = eval(policy, &json!({
            "pii_detected": true,
            "injection_detected": true,
        }));

        assert_eq!(d.matched_rules.len(), 2);

        let pii = d.matched_rules.iter().find(|r| r.rule_id == "pii-flag").expect("pii-flag");
        assert_eq!(pii.action, "flag");
        assert_eq!(pii.category, "data_protection");
        assert!(pii.regulatory_mapping.contains(&"GDPR_ART_5".to_string()));
        assert!(pii.regulatory_mapping.contains(&"AIUC1_E001".to_string()));

        let inj = d.matched_rules.iter().find(|r| r.rule_id == "injection-flag").expect("injection-flag");
        assert_eq!(inj.action, "flag");
        assert_eq!(inj.category, "injection");
        assert!(inj.regulatory_mapping.contains(&"OWASP_AGENTIC_ASI01".to_string()));
    }

    #[test]
    fn matched_rules_empty_when_only_baseline_permit_fires() {
        // Baseline permit only — no forbid rules fire — matched_rules should be empty.
        let policy = r#"
            permit(principal, action, resource);
            @id("pii-flag")
            @enforcement("flag")
            forbid(principal, action, resource)
            when { context.pii_detected == true };
        "#;
        let d = eval(policy, &json!({ "pii_detected": false }));
        assert_eq!(d.action, EnforcementAction::Allow);
        assert!(d.matched_rules.is_empty(), "no forbid rules fired — matched_rules must be empty");
    }

    #[test]
    fn matched_rules_action_uses_enforcement_annotation_not_cedar_effect() {
        // A permit rule with @enforcement("transform") must appear with action="transform",
        // not "allow" (Cedar's permit effect). This is the default-confidential-redact pattern.
        let policy = r#"
            @id("confidential-redact")
            @category("data_protection")
            @enforcement("transform")
            permit(principal, action == EnforceGrid::Action::"llm.response", resource);
        "#;
        // evaluate_response so the permit rule fires on llm.response
        let engine = CedarEngine::from_policy_str(policy).expect("parse");
        let d = engine.evaluate_response("test-user", "llm.response", &json!({}), &json!({}))
            .expect("evaluate");

        assert_eq!(d.action, EnforcementAction::Transform);
        assert_eq!(d.matched_rules.len(), 1);
        assert_eq!(d.matched_rules[0].action, "transform",
            "action must be annotation value, not Cedar's permit effect");
    }
}
