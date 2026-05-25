//! Tool governance detector — unauthorized tool use prevention.
//!
//! Two-mode detector that flags or blocks tool calls not in an explicit
//! allowlist (Mode A) or matching dangerous heuristic patterns (Mode B).
//!
//! **Mode A — Allowlist (explicit):** When `allowed_tools` is configured,
//! any tool not in the set is flagged/blocked. Default action: block.
//!
//! **Mode B — Denylist heuristic (default):** When no allowlist is configured,
//! flags tools whose names match dangerous name-prefix patterns across 9
//! risk categories. Default action: flag (fail-open for zero-config deploys).
//!
//! This is not a text detector — it operates on parsed tool name lists from
//! the proxy pipeline rather than free-form text. The `ContentDetector` trait
//! implementation scans text for tool call JSON formats (OpenAI function_call,
//! Anthropic tool_use); for structured tool lists use `scan_tools()` directly.
//!
//! Pattern taxonomy based on OWASP LLM06 (Excessive Agency) and empirical
//! naming conventions from LangChain, AutoGen, LlamaIndex, and CrewAI.

use crate::detectors::{
    truncate_match, ContentDetector, DetectionResult, DetectorFinding, DetectorSignal,
};
use once_cell::sync::Lazy;
use regex::RegexSet;
use std::collections::HashMap;
use std::collections::HashSet;

/// Risk categories for dangerous tool patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ToolRiskCategory {
    CodeExecution,
    FileSystemWrite,
    NetworkCall,
    DatabaseWrite,
    EmailMessaging,
    PaymentFinancial,
    CredentialAccess,
    ProcessControl,
    PrivilegeEscalation,
}

impl ToolRiskCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CodeExecution => "code_execution",
            Self::FileSystemWrite => "filesystem_write",
            Self::NetworkCall => "network_call",
            Self::DatabaseWrite => "database_write",
            Self::EmailMessaging => "email_messaging",
            Self::PaymentFinancial => "payment_financial",
            Self::CredentialAccess => "credential_access",
            Self::ProcessControl => "process_control",
            Self::PrivilegeEscalation => "privilege_escalation",
        }
    }

    /// Severity rank (1 = highest risk). Used to select `tool_highest_risk_category`.
    pub fn rank(&self) -> u8 {
        match self {
            Self::PrivilegeEscalation => 1,
            Self::CredentialAccess => 2,
            Self::CodeExecution => 3,
            Self::PaymentFinancial => 4,
            Self::ProcessControl => 5,
            Self::DatabaseWrite => 6,
            Self::NetworkCall => 7,
            Self::FileSystemWrite => 8,
            Self::EmailMessaging => 9,
        }
    }
}

// (pattern, category) — order matches DENYLIST_PATTERNS.
static DENYLIST_META: Lazy<Vec<(&str, ToolRiskCategory)>> = Lazy::new(|| {
    vec![
        // Code / shell execution
        (
            r"(?i)\b(?:exec|execute|shell|bash|sh|zsh|cmd|powershell|eval|run_code|subprocess|spawn_shell|terminal|execute_code|run_script|interpreter)\b",
            ToolRiskCategory::CodeExecution,
        ),
        // File system write
        (
            r"(?i)\b(?:write_file|delete_file|create_file|overwrite_file|rm|remove_file|rename_file|move_file|copy_file|chmod|chown|truncate|unlink)\b",
            ToolRiskCategory::FileSystemWrite,
        ),
        // Network / HTTP calls
        (
            r"(?i)\b(?:http_request|fetch_url|curl|wget|http_get|http_post|send_request|make_request|web_request|webhook|call_api|api_call|send_http)\b",
            ToolRiskCategory::NetworkCall,
        ),
        // Database write
        (
            r"(?i)\b(?:db_write|db_execute|sql_exec|execute_sql|run_query|insert_record|delete_record|update_record|drop_table|create_table|db_delete|db_insert|db_update|db_drop)\b",
            ToolRiskCategory::DatabaseWrite,
        ),
        // Email / messaging
        (
            r"(?i)\b(?:send_email|send_message|send_sms|send_slack|send_discord|post_to_slack|post_to_discord|notify|send_notification|email|smtp_send|message_user|dm_user)\b",
            ToolRiskCategory::EmailMessaging,
        ),
        // Payment / financial
        (
            r"(?i)\b(?:charge|transfer|payment|withdraw|refund|debit|credit_card|process_payment|make_payment|bank_transfer|financial_transaction|stripe_charge)\b",
            ToolRiskCategory::PaymentFinancial,
        ),
        // Credential access
        (
            r"(?i)\b(?:get_secret|read_credentials?|vault_read|get_api_key|fetch_token|read_token|get_password|read_secret|secret_manager|credential_lookup)\b",
            ToolRiskCategory::CredentialAccess,
        ),
        // Process control
        (
            r"(?i)\b(?:kill_process|spawn_process|restart_service|shutdown|reboot|start_service|stop_service|signal_process|kill_pid|terminate_process)\b",
            ToolRiskCategory::ProcessControl,
        ),
        // Admin / privilege escalation
        (
            r"(?i)\b(?:sudo|grant_permission|add_user|create_role|delete_user|assign_role|elevate_privilege|privilege_escalate|admin_access|root_access|iam_create|iam_delete|add_admin)\b",
            ToolRiskCategory::PrivilegeEscalation,
        ),
    ]
});

static DENYLIST_SET: Lazy<RegexSet> = Lazy::new(|| {
    let patterns: Vec<&str> = DENYLIST_META.iter().map(|(p, _)| *p).collect();
    RegexSet::new(&patterns).expect("tool governance denylist regex compilation failed")
});

/// Result from scanning a list of tool names.
#[derive(Debug, Clone, Default)]
pub struct ToolGovernanceResult {
    pub detected: bool,
    /// Tool names flagged as unauthorized (max 10).
    pub unauthorized_names: Vec<String>,
    /// Risk categories matched across all flagged tools.
    pub categories: Vec<String>,
    /// Highest-severity risk category (empty if none).
    pub highest_risk_category: String,
    /// True if this result was produced in allowlist mode.
    pub allowlist_mode: bool,
}

impl ToolGovernanceResult {
    /// Comma-separated unauthorized tool names (for Cedar context, max 10).
    pub fn unauthorized_names_csv(&self) -> String {
        self.unauthorized_names.join(",")
    }

    /// Comma-separated risk categories (for Cedar context).
    pub fn categories_csv(&self) -> String {
        self.categories.join(",")
    }
}

/// Configuration for the tool governance detector.
/// Loaded from `steer.yaml` under `detectors.tool_governance`.
#[derive(Debug, Clone, Default)]
pub struct ToolGovernanceConfig {
    /// Explicit allowlist. When non-empty, any tool not in this set is unauthorized.
    /// Empty = denylist heuristic mode.
    pub allowed_tools: HashSet<String>,
    /// When true, unauthorized tools are blocked (not just flagged) in allowlist mode.
    /// Denylist mode always defaults to flag.
    pub block_in_allowlist_mode: bool,
}

pub struct ToolGovernanceDetector {
    config: ToolGovernanceConfig,
}

impl ToolGovernanceDetector {
    pub fn new(config: ToolGovernanceConfig) -> Self {
        // Trigger lazy initialization at construction.
        let _ = &*DENYLIST_SET;
        Self { config }
    }

    /// Scan a list of tool names and return a governance result.
    /// This is the primary API — call this when you have structured tool names.
    pub fn scan_tools(&self, tool_names: &[String]) -> ToolGovernanceResult {
        if tool_names.is_empty() {
            return ToolGovernanceResult::default();
        }

        let allowlist_mode = !self.config.allowed_tools.is_empty();
        let meta = &*DENYLIST_META;

        let mut unauthorized_names: Vec<String> = Vec::new();
        let mut category_set: HashSet<String> = HashSet::new();
        let mut highest_rank: u8 = u8::MAX;
        let mut highest_category = String::new();

        for tool_name in tool_names {
            let flagged = if allowlist_mode {
                !self.config.allowed_tools.contains(tool_name.as_str())
            } else {
                // Denylist mode: check against dangerous patterns.
                // Tool names are typically snake_case — also check individual
                // underscore-separated words so "execute_shell_command" matches
                // the "execute" pattern even though \b doesn't split on _.
                let full_match = DENYLIST_SET
                    .matches(tool_name.as_str())
                    .into_iter()
                    .next()
                    .is_some();
                let word_match = if !full_match && tool_name.contains('_') {
                    tool_name
                        .split('_')
                        .any(|word| DENYLIST_SET.matches(word).into_iter().next().is_some())
                } else {
                    false
                };
                full_match || word_match
            };

            if flagged {
                if unauthorized_names.len() < 10 {
                    unauthorized_names.push(tool_name.clone());
                }

                // Find matching categories for this tool (also check word components)
                if !allowlist_mode {
                    let matched_indices: Vec<usize> = {
                        let full: Vec<usize> = DENYLIST_SET
                            .matches(tool_name.as_str())
                            .into_iter()
                            .collect();
                        if full.is_empty() && tool_name.contains('_') {
                            // Collect indices from any matching word component
                            let mut word_indices = Vec::new();
                            for word in tool_name.split('_') {
                                word_indices.extend(DENYLIST_SET.matches(word));
                            }
                            word_indices.sort_unstable();
                            word_indices.dedup();
                            word_indices
                        } else {
                            full
                        }
                    };
                    for idx in matched_indices {
                        let category = &meta[idx].1;
                        category_set.insert(category.as_str().to_string());
                        if category.rank() < highest_rank {
                            highest_rank = category.rank();
                            highest_category = category.as_str().to_string();
                        }
                    }
                }
            }
        }

        if unauthorized_names.is_empty() {
            return ToolGovernanceResult {
                allowlist_mode,
                ..Default::default()
            };
        }

        let mut categories: Vec<String> = category_set.into_iter().collect();
        categories.sort();

        ToolGovernanceResult {
            detected: true,
            unauthorized_names,
            categories,
            highest_risk_category: highest_category,
            allowlist_mode,
        }
    }
}

impl ContentDetector for ToolGovernanceDetector {
    fn name(&self) -> &str {
        "Tool Governance Detector"
    }
    fn version(&self) -> &str {
        "v1.0"
    }
    fn detector_type(&self) -> &str {
        "tool_governance"
    }

    fn signal(&self, text: &str) -> DetectorSignal {
        let tool_names = extract_tool_names_from_text(text);
        let gov_result = self.scan_tools(&tool_names);
        let mut metadata = HashMap::new();
        metadata.insert(
            "tool_names".to_string(),
            serde_json::json!(gov_result.unauthorized_names),
        );
        metadata.insert(
            "risk_category".to_string(),
            serde_json::json!(gov_result.highest_risk_category),
        );
        metadata.insert(
            "categories".to_string(),
            serde_json::json!(gov_result.categories),
        );
        let scan_result = self.scan(text);
        DetectorSignal {
            detector: self.detector_type().to_string(),
            version: self.version().to_string(),
            flag: scan_result.detected,
            score: scan_result.confidence,
            metadata,
        }
    }

    /// Text-based scan: extracts tool names from OpenAI function_call JSON format
    /// and delegates to `scan_tools`. Returns clean result for non-JSON text.
    fn scan(&self, text: &str) -> DetectionResult {
        // Extract tool names from OpenAI tool_calls format in the text
        let tool_names = extract_tool_names_from_text(text);
        if tool_names.is_empty() {
            return DetectionResult::clean("tool_governance");
        }

        let result = self.scan_tools(&tool_names);
        if !result.detected {
            return DetectionResult::clean("tool_governance");
        }

        let findings: Vec<DetectorFinding> = result
            .unauthorized_names
            .iter()
            .map(|name| DetectorFinding {
                pattern_name: "unauthorized_tool".to_string(),
                category: if result.allowlist_mode {
                    "not_in_allowlist".to_string()
                } else {
                    result.highest_risk_category.clone()
                },
                confidence: 1.0,
                offset: None,
                matched_text: truncate_match(name, 200),
            })
            .collect();

        DetectionResult {
            detected: true,
            detector_type: "tool_governance".to_string(),
            confidence: 1.0,
            findings,
        }
    }
}

/// Extract tool/function names from OpenAI tool_calls JSON format embedded in text.
/// Looks for `"name": "..."` patterns adjacent to function_call or tool_calls context.
fn extract_tool_names_from_text(text: &str) -> Vec<String> {
    static NAME_RE: Lazy<regex::Regex> = Lazy::new(|| {
        // Matches "function": {"name": "tool_name"} or "name": "tool_name" in tool_calls context
        regex::Regex::new(r#""name"\s*:\s*"([^"]{1,100})""#).unwrap()
    });
    // Only scan if the text looks like it contains tool call JSON
    if !text.contains("tool_calls") && !text.contains("function_call") && !text.contains("tool_use")
    {
        return Vec::new();
    }
    NAME_RE
        .captures_iter(text)
        .map(|c| c[1].to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denylist_detector() -> ToolGovernanceDetector {
        ToolGovernanceDetector::new(ToolGovernanceConfig::default())
    }

    #[allow(clippy::field_reassign_with_default)]
    fn allowlist_detector(allowed: &[&str]) -> ToolGovernanceDetector {
        let mut config = ToolGovernanceConfig::default();
        config.allowed_tools = allowed.iter().map(|s| s.to_string()).collect();
        config.block_in_allowlist_mode = true;
        ToolGovernanceDetector::new(config)
    }

    // ── Denylist mode ────────────────────────────────────────────────────────

    #[test]
    fn flags_shell_execution_tool() {
        let det = denylist_detector();
        let r = det.scan_tools(&["bash".to_string()]);
        assert!(r.detected);
        assert!(r.unauthorized_names.contains(&"bash".to_string()));
        assert!(r.categories.contains(&"code_execution".to_string()));
        assert_eq!(r.highest_risk_category, "code_execution");
    }

    #[test]
    fn flags_file_write_tool() {
        let det = denylist_detector();
        let r = det.scan_tools(&["write_file".to_string(), "read_file".to_string()]);
        assert!(r.detected);
        assert!(r.unauthorized_names.contains(&"write_file".to_string()));
        assert!(!r.unauthorized_names.contains(&"read_file".to_string()));
    }

    #[test]
    fn flags_credential_access_tool() {
        let det = denylist_detector();
        let r = det.scan_tools(&["get_secret".to_string()]);
        assert!(r.detected);
        assert_eq!(r.highest_risk_category, "credential_access");
    }

    #[test]
    fn flags_privilege_escalation_tool() {
        let det = denylist_detector();
        let r = det.scan_tools(&["sudo".to_string()]);
        assert!(r.detected);
        assert_eq!(r.highest_risk_category, "privilege_escalation");
    }

    #[test]
    fn flags_network_call_tool() {
        let det = denylist_detector();
        let r = det.scan_tools(&["http_request".to_string()]);
        assert!(r.detected);
        assert!(r.categories.contains(&"network_call".to_string()));
    }

    #[test]
    fn flags_payment_tool() {
        let det = denylist_detector();
        let r = det.scan_tools(&["stripe_charge".to_string()]);
        assert!(r.detected);
        assert!(r.categories.contains(&"payment_financial".to_string()));
    }

    #[test]
    fn safe_tools_not_flagged() {
        let det = denylist_detector();
        let r = det.scan_tools(&[
            "get_weather".to_string(),
            "search_web".to_string(),
            "read_file".to_string(),
            "calculate".to_string(),
            "format_text".to_string(),
        ]);
        assert!(!r.detected);
        assert!(r.unauthorized_names.is_empty());
    }

    #[test]
    fn empty_tool_list_returns_clean() {
        let det = denylist_detector();
        let r = det.scan_tools(&[]);
        assert!(!r.detected);
    }

    #[test]
    fn flags_snake_case_dangerous_tool() {
        // "execute_shell_command" — \b doesn't split on _, so word-component scan is needed
        let det = denylist_detector();
        let r = det.scan_tools(&["execute_shell_command".to_string()]);
        assert!(
            r.detected,
            "execute_shell_command should match code_execution denylist"
        );
        assert!(r
            .unauthorized_names
            .contains(&"execute_shell_command".to_string()));
        assert!(r.categories.contains(&"code_execution".to_string()));
    }

    #[test]
    fn flags_snake_case_shell_tool() {
        let det = denylist_detector();
        let r = det.scan_tools(&["run_shell_script".to_string()]);
        assert!(r.detected);
    }

    #[test]
    fn flags_send_email_compound() {
        // "send_email" — "send" alone isn't dangerous, but "email" matches email_messaging
        let det = denylist_detector();
        let r = det.scan_tools(&["send_email".to_string()]);
        assert!(r.detected);
        assert!(r.categories.contains(&"email_messaging".to_string()));
    }

    #[test]
    fn multiple_dangerous_tools_captured() {
        let det = denylist_detector();
        let tools = vec![
            "exec".to_string(),
            "send_email".to_string(),
            "vault_read".to_string(),
        ];
        let r = det.scan_tools(&tools);
        assert!(r.detected);
        assert_eq!(r.unauthorized_names.len(), 3);
        // highest risk should be credential_access (rank 2) over code_execution (3) and email (9)
        assert_eq!(r.highest_risk_category, "credential_access");
    }

    // ── Allowlist mode ───────────────────────────────────────────────────────

    #[test]
    fn allowlist_permits_listed_tools() {
        let det = allowlist_detector(&["search_web", "get_weather", "read_file"]);
        let r = det.scan_tools(&["search_web".to_string(), "get_weather".to_string()]);
        assert!(!r.detected);
    }

    #[test]
    fn allowlist_blocks_unlisted_tool() {
        let det = allowlist_detector(&["search_web", "get_weather"]);
        let r = det.scan_tools(&["search_web".to_string(), "bash".to_string()]);
        assert!(r.detected);
        assert!(r.unauthorized_names.contains(&"bash".to_string()));
        assert!(r.allowlist_mode);
    }

    #[test]
    fn allowlist_mode_flag_set() {
        let det = allowlist_detector(&["safe_tool"]);
        let r = det.scan_tools(&["safe_tool".to_string()]);
        assert!(r.allowlist_mode);
        assert!(!r.detected);
    }

    #[test]
    fn denylist_mode_flag_not_set() {
        let det = denylist_detector();
        let r = det.scan_tools(&["search".to_string()]);
        assert!(!r.allowlist_mode);
    }

    // ── CSV helpers ──────────────────────────────────────────────────────────

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn unauthorized_names_csv() {
        let mut r = ToolGovernanceResult::default();
        r.unauthorized_names = vec!["exec".to_string(), "bash".to_string()];
        assert_eq!(r.unauthorized_names_csv(), "exec,bash");
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn categories_csv_sorted() {
        let mut r = ToolGovernanceResult::default();
        r.categories = vec!["network_call".to_string(), "code_execution".to_string()];
        r.categories.sort();
        assert_eq!(r.categories_csv(), "code_execution,network_call");
    }

    // ── Text-based scan (ContentDetector trait) ──────────────────────────────

    #[test]
    fn scan_text_detects_tool_calls_json() {
        let det = denylist_detector();
        let text =
            r#"{"tool_calls": [{"function": {"name": "bash", "arguments": "{\"cmd\":\"ls\"}"}}]}"#;
        let result = det.scan(text);
        assert!(result.detected);
    }

    #[test]
    fn scan_text_clean_response() {
        let det = denylist_detector();
        let result = det.scan("The capital of France is Paris.");
        assert!(!result.detected);
    }
}
