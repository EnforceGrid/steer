use std::collections::HashMap;
use anyhow::Context;
use serde::{Deserialize, Serialize};

/// OIDC configuration — optional section in `SteerConfig`.
/// Defined here (not in sso/oidc) so steer-core config doesn't depend on openidconnect.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct OidcConfig {
    /// OIDC issuer URL (e.g. `https://dev-123.okta.com`).
    /// When empty/absent, OIDC endpoints return 501.
    #[serde(default)]
    pub oidc_issuer: String,
    #[serde(default)]
    pub oidc_client_id: String,
    #[serde(default)]
    pub oidc_client_secret: String,
    /// Full redirect URI — must match what's registered with the IdP.
    #[serde(default)]
    pub oidc_redirect_uri: String,
}

impl OidcConfig {
    pub fn is_configured(&self) -> bool {
        !self.oidc_issuer.is_empty()
            && !self.oidc_client_id.is_empty()
            && !self.oidc_redirect_uri.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SteerConfig {
    pub proxy: ProxyConfig,
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
    #[serde(default)]
    pub models: HashMap<String, ModelRouteConfig>,
    #[serde(default)]
    pub pii: PiiConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub streaming: StreamingConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub handover: HandoverConfig,
    #[serde(default)]
    pub performance: PerformanceConfig,
    /// Per-model token cost table for cost estimation.
    /// Ships with sensible defaults for top 10 models (as of 2026-04).
    #[serde(default = "default_token_costs")]
    pub token_costs: HashMap<String, ModelCostConfig>,
    /// Governance: AI system risk level (minimal | limited | high | prohibited).
    /// Injected into every Cedar context as `context.risk_level`.
    #[serde(default)]
    pub risk_level: String,
    /// Content detector configuration — regex hot path + optional ML sidecar.
    #[serde(default)]
    pub detectors: DetectorsConfig,
    /// OIDC/SSO configuration — optional. When present, enables
    /// `GET /api/v1/auth/oidc/authorize` and `/callback`.
    #[serde(default)]
    pub auth: OidcConfig,
    /// MCP server allowlist — approved MCP server identifiers (OWASP ASI04).
    /// When non-empty, tool calls from MCP servers not in this list are flagged/blocked
    /// via the `mcp_server_approved` Cedar context field.
    #[serde(default)]
    pub mcp_allowlist: McpAllowlistConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_true")]
    pub fail_open: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_retry")]
    pub retry_attempts: u32,
    /// Maximum number of idle connections per upstream host kept in the pool.
    /// Higher values reduce TCP handshake overhead under concurrent load.
    #[serde(default = "default_pool_max_idle_per_host")]
    pub pool_max_idle_per_host: usize,
    /// TCP keep-alive interval in seconds.  Prevents idle connections from
    /// being silently dropped by NAT/firewalls between Steer and the upstream.
    #[serde(default = "default_tcp_keepalive_secs")]
    pub tcp_keepalive_secs: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            fail_open: true,
            timeout_ms: default_timeout_ms(),
            retry_attempts: default_retry(),
            pool_max_idle_per_host: default_pool_max_idle_per_host(),
            tcp_keepalive_secs: default_tcp_keepalive_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct UpstreamConfig {
    #[serde(default = "default_openai_base")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    pub default_model: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderConfig {
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelRouteConfig {
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub fallback: Vec<FallbackConfig>,
    /// Operator-declared deployment region (e.g., "eu", "us", "apac", "global").
    /// Used for cross-border data residency checks (AIUC-1 E004).
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FallbackConfig {
    pub provider: String,
    pub model: String,
    /// Optional condition for this fallback entry.
    /// `"budget_exceeded"` — only activate when the budget for the current
    /// api_key or agent scope is exhausted.  `None` means unconditional.
    #[serde(default)]
    pub condition: Option<String>,
}

/// A user-defined PII pattern loaded from `steer.yaml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomPiiPattern {
    /// Unique name used in findings / logs.
    pub name: String,
    /// Regular expression string (compiled at startup).
    pub regex: String,
    /// Replacement string, e.g. `[REDACTED_ACCOUNT]`.
    pub redact_to: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PiiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_pii_patterns")]
    pub patterns: Vec<String>,
    /// User-defined patterns compiled at startup. Invalid regex is logged and
    /// skipped — the proxy will not crash on a bad pattern.
    #[serde(default)]
    pub custom_patterns: Vec<CustomPiiPattern>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    #[serde(default = "default_policy_format")]
    pub format: String,
    #[serde(default = "default_policy_dir")]
    pub policy_dir: String,
    pub policy_file: Option<String>,
    /// When true, spawn a file watcher that hot-reloads .cedar files on change.
    #[serde(default)]
    pub watch: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            format: default_policy_format(),
            policy_dir: default_policy_dir(),
            policy_file: None,
            watch: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StreamingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_buffer_size_bytes")]
    pub buffer_size_bytes: usize,
    #[serde(default = "default_buffer_timeout_ms")]
    pub buffer_timeout_ms: u64,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size_bytes: 512,
            buffer_timeout_ms: 200,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditConfig {
    #[serde(default = "default_audit_backend")]
    pub backend: String,
    #[serde(default = "default_audit_path")]
    pub log_path: String,
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
    /// What to store: `"never"` | `"masked"` (post-PII-scan) | `"raw"`.
    /// Default: `"masked"` — stores payloads with PII redacted.
    #[serde(default = "default_retain_payloads")]
    pub retain_payloads: String,
    /// When to retain payloads: `"always"` | `"on_enforcement"` | `"never"`.
    /// Default: `"on_enforcement"` — only when action != allow.
    #[serde(default = "default_retain_on")]
    pub retain_on: String,
    /// Maximum payload size in bytes to store per request/response.
    /// Truncates with "[…truncated]" suffix. Default: 32768 (32KB).
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
    /// Retention period in days for audit data. 0 = retain forever. Default: 90.
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,
    /// Retention period in days for performance data. 0 = retain forever. Default: 30.
    #[serde(default = "default_perf_retention_days")]
    pub performance_retention_days: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            backend: default_audit_backend(),
            log_path: default_audit_path(),
            max_size_mb: default_max_size_mb(),
            retain_payloads: default_retain_payloads(),
            retain_on: default_retain_on(),
            max_payload_bytes: default_max_payload_bytes(),
            retention_days: default_retention_days(),
            performance_retention_days: default_perf_retention_days(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HandoverConfig {
    #[serde(default)]
    pub enabled: bool,
    pub reviewer_url: Option<String>,
    #[serde(default = "default_max_holds")]
    pub max_concurrent_holds: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerformanceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_perf_buffer")]
    pub buffer_size: usize,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_s: f64,
    pub store_url: Option<String>,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size: 1000,
            flush_interval_s: 5.0,
            store_url: None,
        }
    }
}

/// Tool governance configuration — zero-config allowlist/denylist enforcement.
/// Loaded from `steer.yaml` under `detectors.tool_governance`.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ToolGovernanceConfig {
    /// Explicit allowlist. When non-empty, any tool not listed is unauthorized.
    /// Empty list (default) = denylist heuristic mode.
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// When true and allowlist is active, unauthorized tools are blocked (not flagged).
    /// Denylist mode always flags, never blocks by default.
    #[serde(default)]
    pub block_in_allowlist_mode: bool,
}

/// Configuration for content detectors — regex hot path + optional ML sidecar.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DetectorsConfig {
    /// URL of an optional ML toxicity scoring sidecar (e.g. Detoxify/FastAPI).
    /// When set, `threat_score_pct` (0–100) is added to Cedar context on each request.
    /// Absent or `-1` when the sidecar is not configured or times out (fail-open).
    ///
    /// Expected POST endpoint: `<url>` with body `{"text": "..."}`, returning
    /// `{"threat": 0.95, "toxicity": 0.8, "self_harm": 0.0, "harassment": 0.1}`.
    pub toxicity_sidecar_url: Option<String>,
    /// Maximum wait for the sidecar before skipping and failing open (default: 100ms).
    #[serde(default = "default_toxicity_timeout_ms")]
    pub toxicity_sidecar_timeout_ms: u64,
    /// Tool governance configuration — allowlist/denylist for tool call enforcement.
    #[serde(default)]
    pub tool_governance: ToolGovernanceConfig,
}

/// MCP server allowlist for supply chain security (OWASP ASI04).
///
/// When `enabled` is true and `approved_servers` is non-empty, the proxy checks
/// the `X-MCP-Server-ID` request header against this list and sets
/// `mcp_server_approved` in the Cedar context.
///
/// ```yaml
/// mcp_allowlist:
///   enabled: true
///   approved_servers:
///     - "github-mcp-server"
///     - "filesystem-mcp-server"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McpAllowlistConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub approved_servers: Vec<String>,
}

impl Default for McpAllowlistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            approved_servers: Vec::new(),
        }
    }
}

/// Per-model cost entry in `cadabra.yaml`.
///
/// ```yaml
/// token_costs:
///   gpt-4o:
///     prompt_per_1k: 0.005
///     completion_per_1k: 0.015
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelCostConfig {
    pub prompt_per_1k: f64,
    pub completion_per_1k: f64,
}

// ── Defaults ────────────────────────────────────────────────────────────────

fn default_host() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 8080 }
fn default_true() -> bool { true }
fn default_timeout_ms() -> u64 { 30_000 }
fn default_retry() -> u32 { 2 }
fn default_pool_max_idle_per_host() -> usize { 25 }
fn default_tcp_keepalive_secs() -> u64 { 30 }
fn default_openai_base() -> String { "https://api.openai.com".to_string() }
fn default_pii_patterns() -> Vec<String> {
    vec!["credit_card".into(), "ssn".into(), "email".into(), "phone".into()]
}
fn default_policy_format() -> String { "cedar".to_string() }
fn default_policy_dir() -> String { "./dsl/policies".to_string() }
fn default_buffer_size_bytes() -> usize { 512 }
fn default_buffer_timeout_ms() -> u64 { 200 }
fn default_audit_backend() -> String { "stdout".to_string() }
fn default_audit_path() -> String { "./audit.jsonl".to_string() }
fn default_max_size_mb() -> u64 { 100 }
fn default_max_holds() -> usize { 100 }
fn default_retain_payloads() -> String { "masked".to_string() }
fn default_retain_on() -> String { "on_enforcement".to_string() }
fn default_max_payload_bytes() -> usize { 32_768 }
fn default_retention_days() -> u64 { 90 }
fn default_perf_retention_days() -> u64 { 30 }
fn default_perf_buffer() -> usize { 1000 }
fn default_flush_interval() -> f64 { 5.0 }
fn default_toxicity_timeout_ms() -> u64 { 100 }

/// Default token costs for top 10 models (as of 2026-04).
/// Update monthly — model pricing changes without notice.
fn default_token_costs() -> HashMap<String, ModelCostConfig> {
    [
        // OpenAI
        ("gpt-4o", ModelCostConfig { prompt_per_1k: 0.0025, completion_per_1k: 0.01 }),
        ("gpt-4o-mini", ModelCostConfig { prompt_per_1k: 0.00015, completion_per_1k: 0.0006 }),
        ("gpt-4.1", ModelCostConfig { prompt_per_1k: 0.002, completion_per_1k: 0.008 }),
        ("gpt-4.1-mini", ModelCostConfig { prompt_per_1k: 0.0004, completion_per_1k: 0.0016 }),
        ("gpt-4.1-nano", ModelCostConfig { prompt_per_1k: 0.0001, completion_per_1k: 0.0004 }),
        ("o3-mini", ModelCostConfig { prompt_per_1k: 0.0011, completion_per_1k: 0.0044 }),
        // Anthropic
        ("claude-opus-4-6", ModelCostConfig { prompt_per_1k: 0.015, completion_per_1k: 0.075 }),
        ("claude-sonnet-4-6", ModelCostConfig { prompt_per_1k: 0.003, completion_per_1k: 0.015 }),
        ("claude-haiku-4-5-20251001", ModelCostConfig { prompt_per_1k: 0.0008, completion_per_1k: 0.004 }),
        // Google
        ("gemini-2.5-pro", ModelCostConfig { prompt_per_1k: 0.00125, completion_per_1k: 0.01 }),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_config(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "{}", content).unwrap();
        f
    }

    #[test]
    fn proxy_config_default_values() {
        let cfg = ProxyConfig::default();
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.port, 8080);
        assert!(cfg.fail_open);
        assert_eq!(cfg.timeout_ms, 30_000);
        assert_eq!(cfg.retry_attempts, 2);
        assert_eq!(cfg.pool_max_idle_per_host, 25);
        assert_eq!(cfg.tcp_keepalive_secs, 30);
    }

    #[test]
    fn policy_config_default_values() {
        let cfg = PolicyConfig::default();
        assert_eq!(cfg.format, "cedar");
        assert_eq!(cfg.policy_dir, "./dsl/policies");
        assert!(cfg.policy_file.is_none());
        assert!(!cfg.watch);
    }

    #[test]
    fn streaming_config_default_values() {
        let cfg = StreamingConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.buffer_size_bytes, 512);
        assert_eq!(cfg.buffer_timeout_ms, 200);
    }

    #[test]
    fn audit_config_default_values() {
        let cfg = AuditConfig::default();
        assert_eq!(cfg.backend, "stdout");
        assert_eq!(cfg.log_path, "./audit.jsonl");
        assert_eq!(cfg.retain_payloads, "masked");
        assert_eq!(cfg.retain_on, "on_enforcement");
        assert_eq!(cfg.max_payload_bytes, 32_768);
        assert_eq!(cfg.retention_days, 90);
        assert_eq!(cfg.performance_retention_days, 30);
    }

    #[test]
    fn performance_config_default_values() {
        let cfg = PerformanceConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.buffer_size, 1000);
        assert_eq!(cfg.flush_interval_s, 5.0);
        assert!(cfg.store_url.is_none());
    }

    #[test]
    fn pii_config_serde_default_patterns_include_standard_types() {
        // When PiiConfig is deserialized without fields, serde applies default functions
        let cfg: PiiConfig = serde_yaml::from_str("{}").unwrap();
        assert!(cfg.enabled, "pii.enabled defaults to true via serde");
        assert!(cfg.patterns.contains(&"credit_card".to_string()));
        assert!(cfg.patterns.contains(&"ssn".to_string()));
        assert!(cfg.patterns.contains(&"email".to_string()));
        assert!(cfg.patterns.contains(&"phone".to_string()));
    }

    #[test]
    fn load_minimal_valid_config() {
        let yaml = r#"
proxy:
  host: "127.0.0.1"
  port: 9090
upstream:
  base_url: "https://api.openai.com"
  api_key: "sk-test"
"#;
        let f = write_temp_config(yaml);
        let config = load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(config.proxy.host, "127.0.0.1");
        assert_eq!(config.proxy.port, 9090);
        assert_eq!(config.upstream.api_key, "sk-test");
    }

    #[test]
    fn load_config_with_defaults_filled_in() {
        let yaml = r#"
proxy:
  host: "0.0.0.0"
  port: 8080
upstream:
  base_url: "https://api.openai.com"
  api_key: ""
pii:
  enabled: true
"#;
        let f = write_temp_config(yaml);
        let config = load(f.path().to_str().unwrap()).unwrap();
        // Serde defaults should be applied during deserialization
        assert_eq!(config.policy.format, "cedar");
        assert!(!config.token_costs.is_empty(), "default token costs must be present");
        assert!(config.pii.enabled, "pii.enabled should be true when set");
    }

    #[test]
    fn load_config_missing_file_returns_error() {
        let result = load("/tmp/no-such-steer-config-file.yaml");
        assert!(result.is_err(), "should fail on missing file");
    }

    #[test]
    fn load_config_invalid_yaml_returns_error() {
        let yaml = "{ not: valid: yaml: ::: }";
        let f = write_temp_config(yaml);
        let result = load(f.path().to_str().unwrap());
        assert!(result.is_err(), "should fail on invalid YAML");
    }

    #[test]
    fn expand_env_vars_substitutes_set_variable() {
        std::env::set_var("STEER_TEST_VAR_XYZ", "hello");
        let yaml = r#"
proxy:
  host: "0.0.0.0"
  port: 8080
upstream:
  base_url: "https://api.openai.com"
  api_key: "${STEER_TEST_VAR_XYZ}"
"#;
        let f = write_temp_config(yaml);
        let config = load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(config.upstream.api_key, "hello");
        std::env::remove_var("STEER_TEST_VAR_XYZ");
    }

    #[test]
    fn expand_env_vars_uses_default_when_var_unset() {
        std::env::remove_var("STEER_NOT_SET_VAR");
        let yaml = r#"
proxy:
  host: "0.0.0.0"
  port: 8080
upstream:
  base_url: "https://api.openai.com"
  api_key: "${STEER_NOT_SET_VAR:-fallback-key}"
"#;
        let f = write_temp_config(yaml);
        let config = load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(config.upstream.api_key, "fallback-key");
    }

    #[test]
    fn default_token_costs_contains_expected_models() {
        let costs: HashMap<String, ModelCostConfig> = super::default_token_costs();
        assert!(costs.contains_key("gpt-4o"), "gpt-4o must be in default costs");
        assert!(costs.contains_key("claude-sonnet-4-6"), "claude-sonnet-4-6 must be in default costs");
        assert!(costs.contains_key("gemini-2.5-pro"), "gemini-2.5-pro must be in default costs");
    }

    #[test]
    fn fallback_config_condition_defaults_to_none() {
        let yaml_config = r#"
provider: openai
model: gpt-4o-mini
"#;
        let fc: FallbackConfig = serde_yaml::from_str(yaml_config).unwrap();
        assert!(fc.condition.is_none(), "condition should default to None");
    }

    #[test]
    fn tool_governance_config_default() {
        let cfg = ToolGovernanceConfig::default();
        assert!(cfg.allowed_tools.is_empty());
        assert!(!cfg.block_in_allowlist_mode);
    }

    #[test]
    fn detectors_config_serde_default_timeout() {
        // When DetectorsConfig is deserialized without the field, serde applies default_toxicity_timeout_ms=100
        let cfg: DetectorsConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(cfg.toxicity_sidecar_timeout_ms, 100, "default timeout must be 100ms");
        assert!(cfg.toxicity_sidecar_url.is_none());
    }

    #[test]
    fn mcp_allowlist_config_default_disabled() {
        let cfg = McpAllowlistConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.approved_servers.is_empty());
    }

    #[test]
    fn mcp_allowlist_config_serde_from_yaml() {
        let yaml = r#"
enabled: true
approved_servers:
  - "github-mcp-server"
  - "filesystem-mcp-server"
"#;
        let cfg: McpAllowlistConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.approved_servers.len(), 2);
        assert!(cfg.approved_servers.contains(&"github-mcp-server".to_string()));
    }

    #[test]
    fn full_config_with_mcp_allowlist() {
        let yaml = r#"
proxy:
  host: "0.0.0.0"
  port: 8080
upstream:
  base_url: "https://api.openai.com"
  api_key: "test"
mcp_allowlist:
  enabled: true
  approved_servers:
    - "github-mcp"
    - "slack-mcp"
"#;
        let f = write_temp_config(yaml);
        let config = load(f.path().to_str().unwrap()).unwrap();
        assert!(config.mcp_allowlist.enabled);
        assert_eq!(config.mcp_allowlist.approved_servers.len(), 2);
    }
}

// ── Loader ───────────────────────────────────────────────────────────────────

pub fn load(path: &str) -> anyhow::Result<SteerConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config file: {path}"))?;
    let expanded = expand_env_vars(&content);
    let config: SteerConfig = serde_yaml::from_str(&expanded)
        .with_context(|| format!("cannot parse config file: {path}"))?;
    Ok(config)
}

fn expand_env_vars(s: &str) -> String {
    let mut result = s.to_string();
    // Match ${VAR} and ${VAR:-default}
    let re = regex::Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-(.*?))?\}").unwrap();
    let owned = result.clone();
    for cap in re.captures_iter(&owned) {
        let var = &cap[1];
        let default = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let val = std::env::var(var)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| default.to_string());
        result = result.replace(&cap[0], &val);
    }
    result
}
