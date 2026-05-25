//! Cross-validation between Cedar policy text and the active PII pattern set.
//!
//! Several baseline Cedar rules (e.g. `default-pii-flag`, `default-secrets-block`)
//! use `context.pii_findings.containsAny([...])` to react when the PII engine
//! emits a finding whose `pattern` name is in the listed set. If an operator
//! removes a name from `pii.patterns` in `steer.yaml`, the regex is never
//! compiled — and the Cedar rule that depends on it silently degrades to
//! "never fires", with no error.
//!
//! This module provides a pure, testable function `find_missing_patterns`
//! that takes Cedar policy text + the active pattern names and returns a
//! `Vec<MissingPattern>` describing every degraded rule. `main.rs` calls
//! this at startup and emits one `warn!` per finding.
//!
//! Tracked in stage/doc_requirements.md §16.7 (consistency check at startup).

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// One Cedar policy that references a PII pattern name not present in the
/// compiled engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingPattern {
    /// Value of the policy's `@id("...")` annotation. Empty if the policy
    /// was authored without an `@id` (Cedar does not require one).
    pub policy_id: String,
    /// The pattern name referenced inside `containsAny([...])` that is not
    /// in the engine's compiled set.
    pub pattern_name: String,
}

/// Match `@id("anything")` — capture group 1 is the id value.
static ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"@id\(\s*"([^"]*)"\s*\)"#).expect("ID_RE compiles"));

/// Match `containsAny([...])` — capture group 1 is the bracketed content.
/// We accept whitespace/newlines inside the list, which is why we use `[^\]]+`.
static CONTAINS_ANY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"containsAny\(\s*\[([^\]]+)\]\s*\)"#).expect("CONTAINS_ANY_RE compiles")
});

/// Walk every Cedar policy in `cedar_text`, find `containsAny([...])`
/// expressions, and report any quoted name inside them that is not in
/// `compiled_pattern_names`.
///
/// The Cedar text is operator-supplied; we treat it as untrusted-but-not-
/// adversarial and use regex (not a full parser) because:
///   1. The set of `containsAny` call sites is small and well-formed
///   2. False positives just produce extra warnings — they cannot impact
///      enforcement, which still runs on the actual Cedar AST.
///
/// Policy boundaries are detected by scanning for `@id("...")` annotations
/// followed by a forbid/permit block. A `containsAny` expression is attributed
/// to the *most recent* `@id` that appeared before it in the text. Policies
/// without an `@id` get `policy_id = ""`.
pub fn find_missing_patterns(
    cedar_text: &str,
    compiled_pattern_names: &[&str],
) -> Vec<MissingPattern> {
    let compiled: HashSet<&str> = compiled_pattern_names.iter().copied().collect();
    let mut missing = Vec::new();
    let mut seen = HashSet::<(String, String)>::new();

    // Collect all @id annotations with their byte offsets in the text.
    let id_positions: Vec<(usize, String)> = ID_RE
        .captures_iter(cedar_text)
        .filter_map(|c| {
            let m = c.get(0)?;
            let id = c.get(1)?.as_str().to_string();
            Some((m.start(), id))
        })
        .collect();

    for cap in CONTAINS_ANY_RE.captures_iter(cedar_text) {
        let full = match cap.get(0) {
            Some(m) => m,
            None => continue,
        };
        let inner = match cap.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };

        // Attribute this containsAny call to the most recent @id annotation
        // that appears before it in the source.
        let policy_id = id_positions
            .iter()
            .rev()
            .find(|(off, _)| *off < full.start())
            .map(|(_, id)| id.clone())
            .unwrap_or_default();

        for raw in inner.split(',') {
            let token = raw.trim().trim_matches(|c: char| c == '"' || c == '\'');
            if token.is_empty() {
                continue;
            }
            if !compiled.contains(token) {
                let key = (policy_id.clone(), token.to_string());
                if seen.insert(key) {
                    missing.push(MissingPattern {
                        policy_id: policy_id.clone(),
                        pattern_name: token.to_string(),
                    });
                }
            }
        }
    }

    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_text_returns_empty() {
        let out = find_missing_patterns("", &["openai_key"]);
        assert!(out.is_empty());
    }

    #[test]
    fn no_contains_any_returns_empty() {
        let text = r#"
            @id("rule-a")
            forbid(principal, action, resource)
            when { context.threat_detected == true };
        "#;
        let out = find_missing_patterns(text, &["openai_key"]);
        assert!(out.is_empty());
    }

    #[test]
    fn all_patterns_present_returns_empty() {
        let text = r#"
            @id("default-secrets-block")
            forbid(principal, action, resource)
            when {
              context.pii_findings.containsAny([
                "openai_key",
                "anthropic_key"
              ])
            };
        "#;
        let out = find_missing_patterns(text, &["openai_key", "anthropic_key", "ssn"]);
        assert!(out.is_empty(), "got: {out:?}");
    }

    #[test]
    fn one_missing_pattern_reported_once() {
        let text = r#"
            @id("default-secrets-block")
            forbid(principal, action, resource)
            when {
              context.pii_findings.containsAny([
                "openai_key",
                "anthropic_key",
                "missing_pattern"
              ])
            };
        "#;
        let out = find_missing_patterns(text, &["openai_key", "anthropic_key"]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].policy_id, "default-secrets-block");
        assert_eq!(out[0].pattern_name, "missing_pattern");
    }

    #[test]
    fn missing_in_two_distinct_policies_reports_both() {
        let text = r#"
            @id("rule-a")
            forbid(principal, action, resource)
            when { context.pii_findings.containsAny(["alpha"]) };

            @id("rule-b")
            forbid(principal, action, resource)
            when { context.pii_findings.containsAny(["beta"]) };
        "#;
        let out = find_missing_patterns(text, &[]);
        assert_eq!(out.len(), 2);
        let ids: HashSet<_> = out.iter().map(|m| m.policy_id.as_str()).collect();
        assert!(ids.contains("rule-a"));
        assert!(ids.contains("rule-b"));
    }

    #[test]
    fn duplicate_within_same_policy_deduped() {
        let text = r#"
            @id("rule-a")
            forbid(principal, action, resource)
            when {
              context.pii_findings.containsAny(["missing", "missing"])
            };
        "#;
        let out = find_missing_patterns(text, &[]);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn handles_single_quotes_and_whitespace() {
        // Cedar uses double-quotes for strings, but the regex is defensive
        // about mixed-quote operator hand-edits.
        let text = r#"
            @id("rule-a")
            forbid(principal, action, resource)
            when {
              context.pii_findings.containsAny([   "alpha"  ,  "beta"   ])
            };
        "#;
        let out = find_missing_patterns(text, &["alpha"]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern_name, "beta");
    }

    #[test]
    fn policy_without_id_uses_empty_string() {
        let text = r#"
            forbid(principal, action, resource)
            when { context.pii_findings.containsAny(["orphan"]) };
        "#;
        let out = find_missing_patterns(text, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].policy_id, "");
        assert_eq!(out[0].pattern_name, "orphan");
    }
}
