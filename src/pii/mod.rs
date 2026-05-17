pub mod patterns;

use std::cmp::Reverse;
use std::collections::HashSet;
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiFinding {
    pub pattern: String,
    pub redacted_to: String,
    pub count: usize,
    pub location: String,
    /// Matched content — for PII findings this is absent (redacted_to carries the replacement);
    /// for policy findings (e.g. tool-call governance) this carries the actual matched value
    /// (e.g. a CSV of the tool names that triggered the policy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_text: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PiiScanResult {
    pub redacted_text: String,
    pub findings: Vec<PiiFinding>,
}

/// A single compiled PII rule — either a built-in static pattern or a
/// user-defined custom pattern loaded from config at startup.
struct CompiledPattern {
    name: String,
    regex: Regex,
    redact_to: String,
}

pub struct RegexPiiEngine {
    /// All active patterns (built-ins + custom) in scan order.
    compiled: Vec<CompiledPattern>,
    /// Pre-compiled RegexSet for fast "any match?" check in a single pass.
    /// Indices correspond 1:1 with `compiled`.
    match_set: RegexSet,
}

impl RegexPiiEngine {
    /// Build the engine from:
    /// - `enabled`: name-filter for built-in patterns (empty = all built-ins).
    /// - `custom`: user-defined patterns from config; invalid regex is logged
    ///   and skipped — the engine will not panic on bad input.
    pub fn new(enabled: &[String]) -> Self {
        Self::with_custom(enabled, &[])
    }

    /// Extended constructor used when custom patterns are available from config.
    pub fn with_custom(
        enabled: &[String],
        custom: &[crate::config::CustomPiiPattern],
    ) -> Self {
        let enabled_set: HashSet<&str> = enabled.iter().map(|s| s.as_str()).collect();

        // Built-in patterns (static, pre-compiled via Lazy).
        let mut compiled: Vec<CompiledPattern> = patterns::all_patterns()
            .into_iter()
            .filter(|p| enabled_set.is_empty() || enabled_set.contains(p.name))
            .map(|p| CompiledPattern {
                name: p.name.to_string(),
                // Clone the pre-compiled Regex (cheap — just bumps an Arc).
                regex: p.regex.clone(),
                redact_to: p.redact_to.to_string(),
            })
            .collect();

        // User-defined custom patterns — compiled at startup.
        for cp in custom {
            match Regex::new(&cp.regex) {
                Ok(re) => {
                    compiled.push(CompiledPattern {
                        name: cp.name.clone(),
                        regex: re,
                        redact_to: cp.redact_to.clone(),
                    });
                    tracing::debug!(name = %cp.name, "custom PII pattern loaded");
                }
                Err(err) => {
                    tracing::warn!(
                        name = %cp.name,
                        regex = %cp.regex,
                        error = %err,
                        "custom PII pattern has invalid regex — skipping"
                    );
                }
            }
        }

        // Build a RegexSet from all compiled patterns for single-pass matching.
        // This lets scan_and_redact skip patterns that can't possibly match,
        // avoiding N individual regex passes on clean text.
        let set_patterns: Vec<&str> = compiled.iter()
            .map(|p| p.regex.as_str())
            .collect();
        let match_set = RegexSet::new(&set_patterns)
            .unwrap_or_else(|_| RegexSet::empty());

        Self { compiled, match_set }
    }

    /// Fast boolean check — does the text contain any PII? No allocation.
    #[inline]
    pub fn has_pii(&self, text: &str) -> bool {
        self.match_set.is_match(text)
    }

    /// Fast scan-only pass — returns findings without performing redaction.
    /// No string allocation for the common (no-PII) path. Used by the
    /// observation-mode pipeline to provide `pii_detected` for Cedar context
    /// without paying the full redaction cost.
    pub fn scan_only(&self, text: &str, location: &str) -> Vec<PiiFinding> {
        if text.len() < 5 {
            return vec![];
        }

        let matching: Vec<usize> = self.match_set.matches(text).into_iter().collect();
        if matching.is_empty() {
            return vec![];
        }

        let mut findings = Vec::new();
        for idx in matching {
            let pat = &self.compiled[idx];
            let count = pat.regex.find_iter(text).count();
            if count > 0 {
                findings.push(PiiFinding {
                    pattern: pat.name.clone(),
                    redacted_to: pat.redact_to.clone(),
                    count,
                    location: location.to_string(),
                    matched_text: None,
                });
            }
        }
        // Sort by count descending (match scan_and_redact ordering)
        findings.sort_by_key(|f| Reverse(f.count));
        findings
    }

    pub fn scan_and_redact(&self, text: &str, location: &str) -> PiiScanResult {
        // Micro fast-path: texts shorter than the shortest possible PII token
        // (e.g. "a@b.c" = 5 chars) can never match any pattern.
        if text.len() < 5 {
            return PiiScanResult { redacted_text: text.to_string(), findings: vec![] };
        }

        // Fast path: single-pass RegexSet check tells us which patterns could
        // match. On clean text (the common case) this returns an empty set and
        // we skip all individual regex passes entirely.
        let hits: Vec<usize> = self.match_set.matches(text).into_iter().collect();

        if hits.is_empty() {
            return PiiScanResult {
                redacted_text: text.to_string(),
                findings: Vec::new(),
            };
        }

        let mut result = text.to_string();
        let mut findings = Vec::new();

        // Only run replace_all for patterns that the RegexSet flagged.
        for &idx in &hits {
            let pat = &self.compiled[idx];
            let replaced = pat.regex.replace_all(&result, pat.redact_to.as_str());
            if let std::borrow::Cow::Owned(ref new_text) = replaced {
                let old_len = result.len();
                let new_len = new_text.len();
                let count = count_non_overlapping(new_text, &pat.redact_to)
                    - count_non_overlapping(&result, &pat.redact_to);
                let count = if count > 0 { count } else {
                    if old_len != new_len || result != *new_text { 1 } else { 0 }
                };
                if count > 0 {
                    findings.push(PiiFinding {
                        pattern: pat.name.clone(),
                        redacted_to: pat.redact_to.clone(),
                        count,
                        location: location.to_string(),
                        matched_text: None,
                    });
                }
                result = replaced.into_owned();
            }
        }

        PiiScanResult {
            redacted_text: result,
            findings,
        }
    }

    /// Scan only message content in an LLM JSON response without full JSON
    /// parsing.  Uses string search to locate `"content":"..."` values,
    /// scans them for PII, and does in-place replacement if found.
    /// Falls back to full-body scan for non-JSON or unusual formats.
    pub fn scan_and_redact_response(&self, text: &str, location: &str) -> PiiScanResult {
        // Fast path: extract content strings by string search — no serde_json.
        // Handles OpenAI ("content":"...") and Anthropic ("text":"...").
        let content_slices = extract_json_string_values(text, &["content", "text"]);

        if content_slices.is_empty() {
            // No content fields found — not a recognized LLM response format.
            // Fall back to full-body scan.
            return self.scan_and_redact(text, location);
        }

        // Pre-check: run is_match (boolean, no allocation) on each slice.
        // The common case is clean text — this avoids per-slice String
        // allocations that scan_and_redact would create and immediately drop.
        // Minimum PII match length is 7 chars (IP address "1.2.3.4"), so
        // skip slices shorter than that.
        const MIN_PII_LEN: usize = 7;
        let any_pii = content_slices.iter().any(|(start, end)| {
            let len = end - start;
            len >= MIN_PII_LEN && self.match_set.is_match(&text[*start..*end])
        });

        if !any_pii {
            return PiiScanResult {
                redacted_text: text.to_string(),
                findings: Vec::new(),
            };
        }

        // PII detected in at least one slice — do the full scan + redact.
        let mut all_findings = Vec::new();
        let mut output = text.to_string();
        // Process slices in reverse order so byte offsets stay valid.
        let mut slices = content_slices;
        slices.sort_by_key(|a| Reverse(a.0));

        for (start, end) in slices {
            let slice_len = end - start;
            if slice_len < MIN_PII_LEN {
                continue; // too short for any PII pattern
            }
            let content = &text[start..end];
            let r = self.scan_and_redact(content, location);
            if !r.findings.is_empty() {
                output.replace_range(start..end, &r.redacted_text);
                all_findings.extend(r.findings);
            }
        }

        PiiScanResult {
            redacted_text: output,
            findings: all_findings,
        }
    }

    /// Scan bytes (for SSE streaming). Returns (redacted_bytes, findings).
    pub fn scan_bytes(&self, data: &[u8], location: &str) -> (Vec<u8>, Vec<PiiFinding>) {
        match std::str::from_utf8(data) {
            Ok(text) => {
                let r = self.scan_and_redact(text, location);
                (r.redacted_text.into_bytes(), r.findings)
            }
            Err(_) => (data.to_vec(), vec![]),
        }
    }
}

fn count_non_overlapping(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() { return 0; }
    haystack.matches(needle).count()
}

/// Extract (start, end) byte offsets of JSON string values for the given keys.
/// Uses simple string scanning — no JSON parser. Handles escaped quotes in values.
/// Returns offsets into the original `text` pointing at the string *content*
/// (inside the quotes, not including them).
fn extract_json_string_values(text: &str, keys: &[&str]) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut results = Vec::new();

    for key in keys {
        // Search for `"key":"` or `"key": "` patterns
        let patterns = [
            format!("\"{}\":\"", key),
            format!("\"{}\": \"", key),
        ];

        for pat in &patterns {
            let pat_bytes = pat.as_bytes();
            let mut search_from = 0;
            while search_from + pat_bytes.len() < len {
                if let Some(pos) = find_bytes(&bytes[search_from..], pat_bytes) {
                    let abs_pos = search_from + pos;
                    let value_start = abs_pos + pat_bytes.len();
                    // Find the closing unescaped quote
                    let mut i = value_start;
                    while i < len {
                        if bytes[i] == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
                            break;
                        }
                        i += 1;
                    }
                    if i < len {
                        // Skip "null" and very short values (likely not message content)
                        let value = &text[value_start..i];
                        if value != "null" && !value.is_empty() {
                            results.push((value_start, i));
                        }
                    }
                    search_from = if i < len { i + 1 } else { len };
                } else {
                    break;
                }
            }
        }
    }

    results
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_content_from_openai_response() {
        let json = r#"{"choices":[{"message":{"role":"assistant","content":"Hello world"},"finish_reason":"stop"}]}"#;
        let slices = extract_json_string_values(json, &["content"]);
        assert_eq!(slices.len(), 1);
        assert_eq!(&json[slices[0].0..slices[0].1], "Hello world");
    }

    #[test]
    fn extract_text_from_anthropic_response() {
        let json = r#"{"content":[{"type":"text","text":"Hello from Claude"}]}"#;
        let slices = extract_json_string_values(json, &["text"]);
        assert_eq!(slices.len(), 1);
        assert_eq!(&json[slices[0].0..slices[0].1], "Hello from Claude");
    }

    #[test]
    fn skips_null_content() {
        let json = r#"{"message":{"content":null}}"#;
        let slices = extract_json_string_values(json, &["content"]);
        assert!(slices.is_empty());
    }

    #[test]
    fn handles_escaped_quotes() {
        let json = r#"{"content":"He said \"hello\""}"#;
        let slices = extract_json_string_values(json, &["content"]);
        assert_eq!(slices.len(), 1);
        assert_eq!(&json[slices[0].0..slices[0].1], r#"He said \"hello\""#);
    }

    #[test]
    fn response_scan_redacts_pii_in_content_only() {
        let engine = RegexPiiEngine::new(&["email".to_string()]);
        let json = r#"{"choices":[{"message":{"content":"Contact me at test@example.com please"},"finish_reason":"stop"}],"usage":{"total_tokens":10}}"#;
        let result = engine.scan_and_redact_response(json, "response");
        assert!(!result.findings.is_empty());
        assert!(result.redacted_text.contains("[REDACTED_EMAIL]"));
        // Metadata should be untouched
        assert!(result.redacted_text.contains("total_tokens"));
    }

    #[test]
    fn response_scan_no_pii_returns_original() {
        let engine = RegexPiiEngine::new(&["email".to_string()]);
        let json = r#"{"choices":[{"message":{"content":"Hello world"},"finish_reason":"stop"}]}"#;
        let result = engine.scan_and_redact_response(json, "response");
        assert!(result.findings.is_empty());
        assert_eq!(result.redacted_text, json);
    }

    // ── Custom pattern tests ─────────────────────────────────────────────────

    fn make_custom(name: &str, regex: &str, redact_to: &str) -> crate::config::CustomPiiPattern {
        crate::config::CustomPiiPattern {
            name: name.to_string(),
            regex: regex.to_string(),
            redact_to: redact_to.to_string(),
        }
    }

    #[test]
    fn custom_account_number_matches() {
        let custom = vec![make_custom(
            "account_number",
            r"\b[0-9]{8,12}\b",
            "[REDACTED_ACCOUNT]",
        )];
        let engine = RegexPiiEngine::with_custom(&[], &custom);
        let result = engine.scan_and_redact("account 12345678 ok", "test");
        assert!(!result.findings.is_empty());
        assert!(result.redacted_text.contains("[REDACTED_ACCOUNT]"));
        assert_eq!(result.findings[0].pattern, "account_number");
    }

    #[test]
    fn custom_employee_id_matches() {
        let custom = vec![make_custom(
            "employee_id",
            r"\bEMP-[0-9]{6}\b",
            "[REDACTED_EMP_ID]",
        )];
        let engine = RegexPiiEngine::with_custom(&[], &custom);
        let result = engine.scan_and_redact("employee EMP-123456 here", "test");
        assert!(!result.findings.is_empty());
        assert!(result.redacted_text.contains("[REDACTED_EMP_ID]"));
    }

    #[test]
    fn invalid_custom_regex_is_skipped_not_panic() {
        // An invalid regex must not crash the engine.
        let custom = vec![
            make_custom("bad_pattern", r"[invalid(regex", "[REDACTED]"),
            make_custom("good_pattern", r"\bGOOD\b", "[REDACTED_GOOD]"),
        ];
        let engine = RegexPiiEngine::with_custom(&[], &custom);
        // The bad pattern is skipped; the good one still fires.
        let result = engine.scan_and_redact("has GOOD token here", "test");
        assert!(!result.findings.is_empty(), "good_pattern should have fired");
        assert_eq!(result.findings[0].pattern, "good_pattern");
        // Bad pattern is excluded: it should NOT appear in findings.
        let bad_fired = result.findings.iter().any(|f| f.pattern == "bad_pattern");
        assert!(!bad_fired, "bad_pattern must be skipped");
        // Text that would only match bad_pattern remains unchanged.
        let result2 = engine.scan_and_redact("some text 123", "test");
        assert!(result2.findings.is_empty());
    }

    #[test]
    fn custom_and_builtin_work_together() {
        let custom = vec![make_custom(
            "account_number",
            r"\b[0-9]{8,12}\b",
            "[REDACTED_ACCOUNT]",
        )];
        // Enable built-in email + custom account number.
        let engine = RegexPiiEngine::with_custom(&["email".to_string()], &custom);
        let text = "email user@example.com account 98765432";
        let result = engine.scan_and_redact(text, "test");
        assert!(result.redacted_text.contains("[REDACTED_EMAIL]"));
        assert!(result.redacted_text.contains("[REDACTED_ACCOUNT]"));
        assert_eq!(result.findings.len(), 2);
    }

    #[test]
    fn custom_no_match_returns_original() {
        let custom = vec![make_custom(
            "employee_id",
            r"\bEMP-[0-9]{6}\b",
            "[REDACTED_EMP_ID]",
        )];
        let engine = RegexPiiEngine::with_custom(&[], &custom);
        let result = engine.scan_and_redact("no employee id here", "test");
        assert!(result.findings.is_empty());
        assert_eq!(result.redacted_text, "no employee id here");
    }
}
