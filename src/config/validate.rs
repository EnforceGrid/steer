//! Startup-time configuration sanity checks.
//!
//! Catches the most common `steer.yaml` misconfigurations BEFORE they manifest
//! as confusing upstream 401s in production:
//! - `${VAR}` placeholders that didn't resolve (env var unset)
//! - Whitespace-only or whitespace-padded keys (copy-paste accidents)
//! - Known-vendor prefix mismatches (soft warning, since prefixes drift)
//!
//! v0.1.1 scope: WARN only. Refuse-to-start is v0.2 work — see Item 2 of
//! the v0.1.1 spec.

use super::SteerConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    pub field: String,
    pub message: String,
}

/// Run all sanity checks against `config`. Returns a list of warnings.
/// Caller is responsible for surfacing them via tracing or stderr.
pub fn validate(config: &SteerConfig) -> Vec<ConfigWarning> {
    let mut warnings = Vec::new();

    validate_api_key(
        "upstream.api_key",
        &config.upstream.api_key,
        infer_provider(&config.upstream.base_url),
        &mut warnings,
    );

    for (name, provider) in &config.providers {
        let field = format!("providers.{name}.api_key");
        validate_api_key(
            &field,
            &provider.api_key,
            infer_provider(&provider.base_url).or(Some(name.as_str())),
            &mut warnings,
        );
    }

    warnings
}

/// Detect the most common misconfig modes for an api_key value.
fn validate_api_key(
    field: &str,
    raw: &str,
    provider_hint: Option<&str>,
    warnings: &mut Vec<ConfigWarning>,
) {
    if raw.is_empty() {
        return; // empty is a valid choice (client passthrough) — no warning
    }

    if looks_like_unresolved_placeholder(raw) {
        warnings.push(ConfigWarning {
            field: field.to_string(),
            message: format!(
                "value looks like an unresolved env-var placeholder ({raw:?}). \
                 Did you forget to export the variable, or is your YAML loader \
                 not expanding ${{...}}? This will be sent literally to upstream and rejected."
            ),
        });
        return;
    }

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        warnings.push(ConfigWarning {
            field: field.to_string(),
            message: "value is whitespace-only — upstream will reject as invalid auth"
                .to_string(),
        });
        return;
    }
    if trimmed.len() != raw.len() {
        warnings.push(ConfigWarning {
            field: field.to_string(),
            message: format!(
                "value has leading/trailing whitespace ({} bytes raw, {} trimmed). \
                 Most upstreams reject padded keys.",
                raw.len(),
                trimmed.len()
            ),
        });
    }
    if raw.contains('\n') || raw.contains('\r') {
        warnings.push(ConfigWarning {
            field: field.to_string(),
            message: "value contains a newline — copy-paste artifact? Upstream will reject."
                .to_string(),
        });
    }

    if let Some(provider) = provider_hint {
        if let Some(expected_prefixes) = known_prefixes(provider) {
            let trimmed = raw.trim();
            if !expected_prefixes.iter().any(|p| trimmed.starts_with(p)) {
                warnings.push(ConfigWarning {
                    field: field.to_string(),
                    message: format!(
                        "value does not start with any known {provider} key prefix ({}). \
                         If this is a new key format, ignore this warning.",
                        expected_prefixes.join(" / ")
                    ),
                });
            }
        }
    }
}

fn looks_like_unresolved_placeholder(raw: &str) -> bool {
    let s = raw.trim();
    (s.starts_with("${") && s.ends_with('}'))
        || (s.starts_with("{{") && s.ends_with("}}"))
        || s == "REPLACE_ME"
        || s == "CHANGEME"
        || s == "your-api-key-here"
}

fn infer_provider(base_url: &str) -> Option<&'static str> {
    let u = base_url.to_lowercase();
    if u.contains("anthropic.com") {
        Some("anthropic")
    } else if u.contains("openai.com") {
        Some("openai")
    } else if u.contains("googleapis.com") || u.contains("generativelanguage") {
        Some("google")
    } else {
        None
    }
}

/// Known key prefixes as of 2026-05. Vendor formats drift — this is a soft
/// hint, not a hard validator. Keep this list small and current.
fn known_prefixes(provider: &str) -> Option<&'static [&'static str]> {
    match provider {
        "anthropic" => Some(&["sk-ant-api03-", "sk-ant-oat01-", "sk-ant-"]),
        "openai" => Some(&["sk-proj-", "sk-svcacct-", "sk-"]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warn(field: &str, msg_contains: &str, ws: &[ConfigWarning]) -> bool {
        ws.iter()
            .any(|w| w.field == field && w.message.contains(msg_contains))
    }

    #[test]
    fn empty_value_emits_no_warning() {
        let mut w = vec![];
        validate_api_key("upstream.api_key", "", Some("anthropic"), &mut w);
        assert!(w.is_empty());
    }

    #[test]
    fn valid_anthropic_key_emits_no_warning() {
        let mut w = vec![];
        validate_api_key(
            "upstream.api_key",
            "sk-ant-api03-AAAA-BBBB-CCCC",
            Some("anthropic"),
            &mut w,
        );
        assert!(w.is_empty(), "no warnings expected, got: {w:?}");
    }

    #[test]
    fn valid_openai_service_account_key_emits_no_warning() {
        let mut w = vec![];
        validate_api_key(
            "upstream.api_key",
            "sk-svcacct-EXAMPLE_KEY",
            Some("openai"),
            &mut w,
        );
        assert!(w.is_empty());
    }

    #[test]
    fn unresolved_env_var_placeholder_warns() {
        let mut w = vec![];
        validate_api_key(
            "upstream.api_key",
            "${ANTHROPIC_API_KEY}",
            Some("anthropic"),
            &mut w,
        );
        assert!(warn(
            "upstream.api_key",
            "unresolved env-var placeholder",
            &w
        ));
    }

    #[test]
    fn whitespace_only_warns() {
        let mut w = vec![];
        validate_api_key("upstream.api_key", "   \t  ", Some("anthropic"), &mut w);
        assert!(warn("upstream.api_key", "whitespace-only", &w));
    }

    #[test]
    fn trailing_newline_warns() {
        let mut w = vec![];
        validate_api_key(
            "upstream.api_key",
            "sk-ant-api03-real-key\n",
            Some("anthropic"),
            &mut w,
        );
        assert!(warn("upstream.api_key", "newline", &w));
    }

    #[test]
    fn trailing_whitespace_warns() {
        let mut w = vec![];
        validate_api_key(
            "upstream.api_key",
            "sk-ant-api03-real-key  ",
            Some("anthropic"),
            &mut w,
        );
        assert!(warn("upstream.api_key", "leading/trailing whitespace", &w));
    }

    #[test]
    fn anthropic_key_with_wrong_prefix_warns() {
        let mut w = vec![];
        validate_api_key(
            "upstream.api_key",
            "sk-proj-this-is-an-openai-key",
            Some("anthropic"),
            &mut w,
        );
        assert!(warn(
            "upstream.api_key",
            "does not start with any known anthropic",
            &w
        ));
    }

    #[test]
    fn openai_field_with_non_sk_value_warns() {
        // OpenAI's `sk-` prefix is broad (sk-, sk-proj-, sk-svcacct-) and overlaps
        // with Anthropic-shaped keys (sk-ant-...). We can only catch values that
        // don't start with `sk-` at all.
        let mut w = vec![];
        validate_api_key(
            "upstream.api_key",
            "ya29.googleoauthtoken",
            Some("openai"),
            &mut w,
        );
        assert!(warn(
            "upstream.api_key",
            "does not start with any known openai",
            &w
        ));
    }

    #[test]
    fn unknown_provider_skips_prefix_check() {
        let mut w = vec![];
        validate_api_key("upstream.api_key", "any-format-here", None, &mut w);
        assert!(w.is_empty());
    }

    #[test]
    fn changeme_placeholder_warns() {
        let mut w = vec![];
        validate_api_key("upstream.api_key", "CHANGEME", Some("anthropic"), &mut w);
        assert!(warn("upstream.api_key", "placeholder", &w));
    }

    #[test]
    fn infer_provider_recognizes_anthropic() {
        assert_eq!(infer_provider("https://api.anthropic.com"), Some("anthropic"));
        assert_eq!(infer_provider("https://api.openai.com/v1"), Some("openai"));
        assert_eq!(infer_provider("https://localhost:11434"), None);
    }
}
