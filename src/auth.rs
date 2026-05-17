use std::collections::HashMap;

/// Resolve the auth header to use for upstream requests.
/// Precedence:
///   1. Caller's existing auth header (Authorization or x-api-key, if present)
///   2. Configured api_key from steer.yaml / environment, injected with the
///      correct header format for the provider
///   3. Neither present → Err
///
/// `provider_name`: when `Some("anthropic")`, injects `x-api-key` instead of
/// `Authorization: Bearer`.  All other providers use Bearer.
pub fn resolve_auth(
    headers: &mut HashMap<String, String>,
    configured_api_key: &str,
) -> Result<(), String> {
    resolve_auth_for_provider(headers, configured_api_key, None)
}

pub fn resolve_auth_for_provider(
    headers: &mut HashMap<String, String>,
    configured_api_key: &str,
    provider_name: Option<&str>,
) -> Result<(), String> {
    let is_anthropic = provider_name
        .is_some_and(|p| p.eq_ignore_ascii_case("anthropic"));

    // Check if the caller already sent valid auth
    let has_auth = headers.get("authorization")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .is_some();
    let has_x_api_key = headers.get("x-api-key")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .is_some();

    if !configured_api_key.is_empty() {
        if is_anthropic {
            // Always override x-api-key with the upstream key when configured:
            // the caller's x-api-key may be a Steer auth credential (eg_sk_live_...)
            // rather than a real Anthropic key.  Replacing it ensures the correct
            // key reaches Anthropic regardless of what the client sent.
            headers.insert("x-api-key".to_string(), configured_api_key.to_string());
        } else {
            // Non-Anthropic: only inject if no auth already present
            if !has_auth {
                headers.insert("authorization".to_string(), format!("Bearer {configured_api_key}"));
            }
        }
        return Ok(());
    }

    // No configured upstream key — pass through whatever the caller sent
    if has_auth || has_x_api_key {
        return Ok(());
    }

    Err("No API key. Set OPENAI_API_KEY / ANTHROPIC_API_KEY or add api_key to steer.yaml under upstream.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_auth_uses_existing_authorization() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer existing-token".to_string());
        let result = resolve_auth(&mut headers, "configured-key");
        assert!(result.is_ok());
        assert_eq!(headers.get("authorization").unwrap(), "Bearer existing-token");
    }

    #[test]
    fn resolve_auth_injects_configured_key_when_missing() {
        let mut headers = HashMap::new();
        let result = resolve_auth(&mut headers, "configured-key");
        assert!(result.is_ok());
        assert_eq!(headers.get("authorization").unwrap(), "Bearer configured-key");
    }

    #[test]
    fn resolve_auth_returns_error_when_neither_present() {
        let mut headers = HashMap::new();
        let result = resolve_auth(&mut headers, "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No API key"));
    }

    #[test]
    fn resolve_auth_ignores_empty_existing_auth() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "   ".to_string());
        let result = resolve_auth(&mut headers, "fallback-key");
        assert!(result.is_ok());
        assert_eq!(headers.get("authorization").unwrap(), "Bearer fallback-key");
    }

    #[test]
    fn resolve_auth_anthropic_injects_x_api_key() {
        let mut headers = HashMap::new();
        let result = resolve_auth_for_provider(&mut headers, "sk-ant-key", Some("anthropic"));
        assert!(result.is_ok());
        assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-key");
        assert!(!headers.contains_key("authorization"));
    }

    #[test]
    fn resolve_auth_anthropic_overrides_caller_x_api_key_when_upstream_configured() {
        // When Steer has an upstream Anthropic key, it ALWAYS replaces the caller's
        // x-api-key — the caller may have sent a Steer auth key (eg_sk_live_...) rather
        // than a real Anthropic key, so we must not forward it blindly.
        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_string(), "eg_sk_live_caller-steer-key".to_string());
        let result = resolve_auth_for_provider(&mut headers, "sk-ant-upstream", Some("anthropic"));
        assert!(result.is_ok());
        assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-upstream");
    }

    #[test]
    fn resolve_auth_anthropic_passthrough_when_no_upstream_key() {
        // No configured upstream key → caller's real Anthropic key passes through unchanged.
        // This is the local cargo-run case: ANTHROPIC_BASE_URL=http://localhost:3000.
        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_string(), "sk-ant-real-anthropic-key".to_string());
        let result = resolve_auth_for_provider(&mut headers, "", Some("anthropic"));
        assert!(result.is_ok());
        assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-real-anthropic-key");
    }

    #[test]
    fn resolve_auth_openai_uses_bearer_even_when_explicit() {
        let mut headers = HashMap::new();
        let result = resolve_auth_for_provider(&mut headers, "sk-openai", Some("openai"));
        assert!(result.is_ok());
        assert_eq!(headers.get("authorization").unwrap(), "Bearer sk-openai");
        assert!(!headers.contains_key("x-api-key"));
    }

    #[test]
    fn resolve_auth_none_provider_defaults_to_bearer() {
        let mut headers = HashMap::new();
        let result = resolve_auth_for_provider(&mut headers, "some-key", None);
        assert!(result.is_ok());
        assert_eq!(headers.get("authorization").unwrap(), "Bearer some-key");
    }
}
