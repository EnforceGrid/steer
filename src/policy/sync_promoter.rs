use std::collections::HashSet;

use regex::Regex;

/// Which detectors must run synchronously for a given policy set.
///
/// Cedar's default semantics: an unannotated `forbid` is a hard deny (block).
/// Only `@enforcement("flag")` and `@enforcement("allow")` are non-enforcing.
/// Everything else promotes the referenced detectors to synchronous execution.
#[derive(Debug, Clone)]
pub struct SyncRequirements {
    /// Control fact keys referenced by enforcement policies.
    pub enforced_facts: HashSet<String>,
    /// Detector names that must run sync (reverse-mapped from facts).
    pub sync_detectors: HashSet<String>,
    /// Whether PII must run sync (scan_and_redact vs scan_only).
    pub pii_sync: bool,
    /// Whether response-side enforcement exists.
    pub has_response_enforcement: bool,
}

impl SyncRequirements {
    /// Analyze Cedar policy text. Conservative: if a control fact appears
    /// anywhere in an enforcement forbid rule, the detector that produces
    /// it runs sync.
    pub fn analyze(cedar_policy: &str) -> Self {
        let mut enforced_facts = HashSet::new();
        let mut sync_detectors = HashSet::new();
        let mut pii_sync = false;
        let mut has_response_enforcement = false;

        let context_re = Regex::new(r"context\.(\w+(?:\.\w+)*)").expect("valid regex");

        for block in PolicyBlockIter::new(cedar_policy) {
            if !block.is_enforcing() {
                continue;
            }

            // Check for response-side or tool-side actions
            if block.text.contains("llm.response") || block.text.contains("tool.call") {
                has_response_enforcement = true;
            }

            // Extract context field references from when clauses
            if let Some(when_body) = extract_when_clause(&block.text) {
                for cap in context_re.captures_iter(when_body) {
                    let fact = cap[1].to_string();

                    if let Some(detector) = detector_for_fact(&fact) {
                        sync_detectors.insert(detector.to_string());

                        if detector == "pii" {
                            pii_sync = true;
                        }
                    }

                    enforced_facts.insert(fact);
                }
            }
        }

        Self {
            enforced_facts,
            sync_detectors,
            pii_sync,
            has_response_enforcement,
        }
    }

    /// True if no detectors need sync execution.
    pub fn all_async(&self) -> bool {
        self.sync_detectors.is_empty() && !self.pii_sync
    }

    /// True if the named detector must run sync.
    pub fn needs_sync(&self, detector_name: &str) -> bool {
        self.sync_detectors.contains(detector_name)
    }
}

// ── Policy block parsing ────────────────────────────────────────────────

#[derive(Debug)]
struct PolicyBlock {
    text: String,
    kind: PolicyKind,
    enforcement: Option<String>,
}

#[derive(Debug, PartialEq)]
enum PolicyKind {
    Forbid,
    Permit,
}

impl PolicyBlock {
    /// Whether this block promotes detectors to sync.
    fn is_enforcing(&self) -> bool {
        match &self.enforcement {
            Some(e) => matches!(e.as_str(), "block" | "steer" | "transform"),
            // Unannotated forbid → conservative block; unannotated permit → no.
            None => self.kind == PolicyKind::Forbid,
        }
    }
}

/// Iterator that splits Cedar policy text into individual policy blocks.
struct PolicyBlockIter<'a> {
    remaining: &'a str,
}

impl<'a> PolicyBlockIter<'a> {
    fn new(text: &'a str) -> Self {
        Self { remaining: text }
    }
}

impl<'a> Iterator for PolicyBlockIter<'a> {
    type Item = PolicyBlock;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let remaining = self.remaining.trim_start();
            if remaining.is_empty() {
                return None;
            }

            // Find the next forbid or permit keyword, including any preceding
            // annotations (lines starting with @).
            let block_start = find_block_start(remaining)?;
            let search_from = block_start;

            // Find the semicolon that ends this policy statement, accounting
            // for brace nesting (when clauses use { }).
            let block_end = find_block_end(&remaining[search_from..])?;
            let full_end = search_from + block_end + 1; // include the semicolon

            let block_text = &remaining[..full_end];
            self.remaining = &remaining[full_end..];

            // Determine kind
            let after_annotations = &remaining[search_from..];
            let kind = if after_annotations.starts_with("forbid") {
                PolicyKind::Forbid
            } else if after_annotations.starts_with("permit") {
                PolicyKind::Permit
            } else {
                continue; // skip unrecognized blocks
            };

            // Extract @enforcement annotation
            let enforcement = extract_enforcement(block_text);

            return Some(PolicyBlock {
                text: block_text.to_string(),
                kind,
                enforcement,
            });
        }
    }
}

/// Find the start of annotations (if any) before a forbid/permit keyword.
/// Returns the offset of the forbid/permit keyword itself, but the block
/// text includes everything from position 0 (annotations).
fn find_block_start(text: &str) -> Option<usize> {
    // Look for forbid( or permit( as the start of a policy statement.
    // Walk backwards to include any @ annotations on preceding lines.
    let keyword_pos = text
        .find("forbid(")
        .into_iter()
        .chain(text.find("permit("))
        .min()?;

    Some(keyword_pos)
}

/// Find the end of a policy block (the terminating semicolon), respecting
/// brace nesting.
fn find_block_end(text: &str) -> Option<usize> {
    let mut depth: i32 = 0;
    for (i, ch) in text.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => depth -= 1,
            ';' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// Extract the enforcement mode from `@enforcement("...")` annotation.
fn extract_enforcement(block_text: &str) -> Option<String> {
    let re = Regex::new(r#"@enforcement\("(\w+)"\)"#).expect("valid regex");
    re.captures(block_text).map(|c| c[1].to_string())
}

/// Extract the body of the `when { ... }` clause from a policy block.
fn extract_when_clause(block_text: &str) -> Option<&str> {
    let when_pos = block_text.find("when")?;
    let after_when = &block_text[when_pos..];
    let open = after_when.find('{')?;
    let mut depth = 0;
    for (i, ch) in after_when[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&after_when[open + 1..open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Reverse-map a control fact key to the detector that produces it.
fn detector_for_fact(fact_key: &str) -> Option<&'static str> {
    // Flat names (current Cedar policies)
    if fact_key.contains("injection") {
        return Some("injection");
    }
    if fact_key.contains("jailbreak") {
        return Some("jailbreak");
    }
    if fact_key.contains("pii") {
        return Some("pii");
    }
    if fact_key.contains("exfiltration") {
        return Some("exfiltration");
    }
    if fact_key.contains("confidential") {
        return Some("confidential");
    }
    if fact_key.contains("threat") && !fact_key.contains("toxicity") {
        return Some("threat");
    }
    if fact_key.contains("toxicity") {
        return Some("toxicity");
    }
    if fact_key.contains("identity_claim") || fact_key.contains("disclosure") {
        return Some("identity_claim");
    }
    if fact_key.contains("unauthorized_tool") || fact_key.contains("tool_governance") {
        return Some("tool_governance");
    }

    // Namespaced names (future)
    match fact_key.split('.').next() {
        Some("agent_integrity") => {
            if fact_key.contains("injection") {
                Some("injection")
            } else if fact_key.contains("jailbreak") {
                Some("jailbreak")
            } else {
                None
            }
        }
        Some("data_protection") => {
            if fact_key.contains("pii") {
                Some("pii")
            } else if fact_key.contains("exfiltration") {
                Some("exfiltration")
            } else if fact_key.contains("confidential") {
                Some("confidential")
            } else {
                None
            }
        }
        Some("content_safety") => {
            if fact_key.contains("threat") {
                Some("threat")
            } else if fact_key.contains("toxicity") {
                Some("toxicity")
            } else {
                None
            }
        }
        Some("identity_safety") => Some("identity_claim"),
        Some("tool_governance") => Some("tool_governance"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policies_sync_detectors() {
        let cedar = include_str!("../../dsl/policies/default.cedar");
        let req = SyncRequirements::analyze(cedar);

        // v2 observation mode: injection, jailbreak, confidential are now flag-only
        assert!(
            !req.needs_sync("injection"),
            "injection should NOT be sync (flag only in v2)"
        );
        assert!(
            !req.needs_sync("jailbreak"),
            "jailbreak should NOT be sync (flag only in v2)"
        );
        assert!(
            !req.needs_sync("confidential"),
            "confidential should NOT be sync (flag only in v2)"
        );
        // exfiltration block policies remain
        assert!(
            req.needs_sync("exfiltration"),
            "exfiltration should be sync"
        );
        // PII is now sync because `default-secrets-block` is a block-action
        // policy that references `context.pii_findings`. Without sync PII,
        // auth secrets would be forwarded upstream unredacted before the
        // hot-path block decision could fire. See `default-secrets-block`
        // in default.cedar.
        assert!(
            req.needs_sync("pii"),
            "pii must be sync — default-secrets-block needs hot-path findings"
        );
        assert!(
            req.pii_sync,
            "pii_sync flag must mirror needs_sync(\"pii\")"
        );
        assert!(
            !req.needs_sync("threat"),
            "threat should NOT be sync (flag only)"
        );
        assert!(
            !req.needs_sync("identity_claim"),
            "identity_claim should NOT be sync (flag only)"
        );

        assert!(!req.all_async());
        assert!(req.has_response_enforcement);
    }

    #[test]
    fn all_flag_policies_are_async() {
        let cedar = r#"
            @enforcement("flag")
            forbid(principal, action, resource)
            when { context.injection_detected == true };

            @enforcement("flag")
            forbid(principal, action, resource)
            when { context.pii_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(req.all_async());
        assert!(req.sync_detectors.is_empty());
        assert!(!req.pii_sync);
    }

    #[test]
    fn block_on_injection_promotes() {
        let cedar = r#"
            @enforcement("block")
            forbid(principal, action, resource)
            when { context.injection_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(req.needs_sync("injection"));
        assert!(!req.all_async());
    }

    #[test]
    fn flag_on_injection_does_not_promote() {
        let cedar = r#"
            @enforcement("flag")
            forbid(principal, action, resource)
            when { context.injection_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(!req.needs_sync("injection"));
        assert!(req.all_async());
    }

    #[test]
    fn empty_policy_is_all_async() {
        let req = SyncRequirements::analyze("");
        assert!(req.all_async());
        assert!(req.sync_detectors.is_empty());
        assert!(!req.pii_sync);
        assert!(!req.has_response_enforcement);
    }

    #[test]
    fn permit_all_is_all_async() {
        let cedar = "permit(principal, action, resource);";
        let req = SyncRequirements::analyze(cedar);
        assert!(req.all_async());
    }

    #[test]
    fn unannotated_forbid_treated_as_block() {
        let cedar = r#"
            forbid(principal, action, resource)
            when { context.injection_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(req.needs_sync("injection"));
        assert!(!req.all_async());
    }

    #[test]
    fn response_enforcement_detected() {
        let cedar = r#"
            @enforcement("block")
            forbid(principal, action == EnforceGrid::Action::"llm.response", resource)
            when { context.confidential_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(req.has_response_enforcement);
    }

    #[test]
    fn tool_call_enforcement_detected() {
        let cedar = r#"
            @enforcement("block")
            forbid(principal, action == EnforceGrid::Action::"tool.call", resource)
            when { context.exfiltration_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(req.has_response_enforcement);
    }

    #[test]
    fn pii_sync_when_block_enforced() {
        let cedar = r#"
            @enforcement("block")
            forbid(principal, action, resource)
            when { context.pii_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(req.pii_sync);
        assert!(req.needs_sync("pii"));
    }

    #[test]
    fn pii_findings_set_reference_promotes_to_sync() {
        // `context.pii_findings.containsAny([...])` must also promote PII to
        // sync. Without this, the secrets-block policy would never run in the
        // hot path and credentials would be forwarded upstream unredacted —
        // the original v0.1.0-rc2 bug that drove the pii_findings plumbing.
        let cedar = r#"
            @enforcement("block")
            forbid(principal, action, resource)
            when {
              context.pii_findings.containsAny(["openai_key", "anthropic_key"])
            };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(
            req.pii_sync,
            "pii_findings reference must promote PII to sync"
        );
        assert!(req.needs_sync("pii"));
    }

    #[test]
    fn steer_enforcement_promotes() {
        let cedar = r#"
            @enforcement("steer")
            forbid(principal, action, resource)
            when { context.injection_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(req.needs_sync("injection"));
    }

    #[test]
    fn transform_enforcement_promotes() {
        let cedar = r#"
            @enforcement("transform")
            permit(principal, action, resource)
            when { context.pii_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(req.needs_sync("pii"));
        assert!(req.pii_sync);
    }

    #[test]
    fn namespaced_facts_resolve() {
        let cedar = r#"
            @enforcement("block")
            forbid(principal, action, resource)
            when { context.agent_integrity.injection_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(req.needs_sync("injection"));
        assert!(req
            .enforced_facts
            .contains("agent_integrity.injection_detected"));
    }

    #[test]
    fn allow_enforcement_does_not_promote() {
        let cedar = r#"
            @enforcement("allow")
            permit(principal, action, resource)
            when { context.injection_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(!req.needs_sync("injection"));
        assert!(req.all_async());
    }

    #[test]
    fn unannotated_permit_does_not_promote() {
        let cedar = r#"
            permit(principal, action, resource)
            when { context.injection_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(!req.needs_sync("injection"));
        assert!(req.all_async());
    }

    #[test]
    fn multiple_context_fields_in_one_when() {
        let cedar = r#"
            @enforcement("block")
            forbid(principal, action, resource)
            when { context.injection_detected == true && context.jailbreak_detected == true };
        "#;
        let req = SyncRequirements::analyze(cedar);

        assert!(req.needs_sync("injection"));
        assert!(req.needs_sync("jailbreak"));
    }

    #[test]
    fn detector_for_fact_coverage() {
        assert_eq!(detector_for_fact("injection_detected"), Some("injection"));
        assert_eq!(detector_for_fact("jailbreak_detected"), Some("jailbreak"));
        assert_eq!(detector_for_fact("pii_detected"), Some("pii"));
        assert_eq!(
            detector_for_fact("exfiltration_detected"),
            Some("exfiltration")
        );
        assert_eq!(
            detector_for_fact("confidential_detected"),
            Some("confidential")
        );
        assert_eq!(detector_for_fact("threat_detected"), Some("threat"));
        assert_eq!(
            detector_for_fact("identity_claim_detected"),
            Some("identity_claim")
        );
        assert_eq!(
            detector_for_fact("unauthorized_tool_detected"),
            Some("tool_governance")
        );
        assert_eq!(detector_for_fact("budget_remaining_cents"), None);
        assert_eq!(detector_for_fact("risk_level"), None);
    }
}
