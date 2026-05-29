use crate::config::{FallbackConfig, SteerConfig};

pub struct ResolvedRoute {
    pub base_url: String,
    pub api_key: String,
    pub actual_model: Option<String>,
    pub provider_name: Option<String>,
    pub fallback: Vec<FallbackConfig>,
    /// Operator-declared region for this model route (AIUC-1 E004).
    pub region: Option<String>,
}

pub fn resolve_route(model: Option<&str>, config: &SteerConfig) -> ResolvedRoute {
    if let Some(model_name) = model {
        if let Some(route) = config.models.get(model_name) {
            if let Some(provider) = config.providers.get(&route.provider) {
                // Use the provider's own key. Do NOT fall back to upstream.api_key:
                // that key belongs to a different provider (e.g. the OpenAI key must
                // not be sent to Anthropic). An empty provider key means "no upstream
                // key configured — let the caller's own auth (session token / x-api-key)
                // pass through unchanged."
                let api_key = provider.api_key.clone();
                return ResolvedRoute {
                    base_url: provider.base_url.clone(),
                    api_key,
                    actual_model: Some(route.model.clone()),
                    provider_name: Some(route.provider.clone()),
                    fallback: route.fallback.clone(),
                    region: route.region.clone(),
                };
            }
        }
    }

    // Fall through to upstream defaults
    let actual_model = match model {
        None | Some("") | Some("default") => config.upstream.default_model.clone(),
        Some(m) => Some(m.to_string()),
    };

    ResolvedRoute {
        base_url: config.upstream.base_url.clone(),
        api_key: config.upstream.api_key.clone(),
        actual_model,
        provider_name: None,
        fallback: vec![],
        region: None,
    }
}

/// Replace the `"model"` field in a JSON body with `model`. Returns original bytes on parse failure.
pub fn rewrite_model_in_body(body: &[u8], model: &str) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(body) else {
        return body.to_vec();
    };
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(text) else {
        return body.to_vec();
    };
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "model".to_string(),
            serde_json::Value::String(model.to_string()),
        );
    }
    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
}

pub fn build_upstream_url(base_url: &str, path: &str, query: Option<&str>) -> String {
    let mut url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    if let Some(q) = query {
        if !q.is_empty() {
            url.push('?');
            url.push_str(q);
        }
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn mock_config() -> SteerConfig {
        let mut models = HashMap::new();
        let mut providers = HashMap::new();

        providers.insert(
            "openai".to_string(),
            crate::config::ProviderConfig {
                base_url: "https://api.openai.com".to_string(),
                api_key: "sk-openai-123".to_string(),
            },
        );

        models.insert(
            "gpt-4".to_string(),
            crate::config::ModelRouteConfig {
                provider: "openai".to_string(),
                model: "gpt-4".to_string(),
                fallback: vec![],
                region: None,
            },
        );

        SteerConfig {
            proxy: crate::config::ProxyConfig::default(),
            upstream: crate::config::UpstreamConfig {
                base_url: "https://api.fallback.com".to_string(),
                api_key: "sk-fallback-456".to_string(),
                default_model: Some("gpt-3.5-turbo".to_string()),
            },
            models,
            providers,
            pii: crate::config::PiiConfig::default(),
            policy: crate::config::PolicyConfig::default(),
            streaming: crate::config::StreamingConfig::default(),
            audit: crate::config::AuditConfig::default(),
            handover: crate::config::HandoverConfig::default(),
            performance: crate::config::PerformanceConfig::default(),
            token_costs: std::collections::HashMap::new(),
            risk_level: String::new(),
            detectors: crate::config::DetectorsConfig::default(),
            auth: crate::config::OidcConfig::default(),
            mcp_allowlist: crate::config::McpAllowlistConfig::default(),
            tenant: crate::config::TenantConfig::default(),
            budget: crate::config::BudgetConfig::default(),
        }
    }

    #[test]
    fn rewrite_model_in_body_replaces_model_field() {
        let body = r#"{"model":"gpt-3.5","messages":[]}"#;
        let result = rewrite_model_in_body(body.as_bytes(), "gpt-4");
        let text = std::str::from_utf8(&result).unwrap();
        assert!(text.contains("\"model\":\"gpt-4\""));
        assert!(!text.contains("\"model\":\"gpt-3.5\""));
    }

    #[test]
    fn rewrite_model_in_body_handles_invalid_json() {
        let body = b"not json";
        let result = rewrite_model_in_body(body, "gpt-4");
        assert_eq!(result, body);
    }

    #[test]
    fn resolve_route_returns_explicit_route_when_model_matches() {
        let config = mock_config();
        let route = resolve_route(Some("gpt-4"), &config);
        assert_eq!(route.base_url, "https://api.openai.com");
        assert_eq!(route.api_key, "sk-openai-123");
        assert_eq!(route.actual_model, Some("gpt-4".to_string()));
        assert_eq!(route.provider_name, Some("openai".to_string()));
    }

    #[test]
    fn resolve_route_falls_through_to_upstream_when_model_not_configured() {
        let config = mock_config();
        let route = resolve_route(Some("unknown-model"), &config);
        assert_eq!(route.base_url, "https://api.fallback.com");
        assert_eq!(route.api_key, "sk-fallback-456");
        assert_eq!(route.actual_model, Some("unknown-model".to_string()));
        assert_eq!(route.provider_name, None);
    }

    #[test]
    fn resolve_route_rewrites_default_model_to_upstream_default() {
        let config = mock_config();
        let route = resolve_route(Some("default"), &config);
        assert_eq!(route.base_url, "https://api.fallback.com");
        assert_eq!(route.actual_model, Some("gpt-3.5-turbo".to_string()));
    }

    #[test]
    fn resolve_route_uses_upstream_default_when_no_model_provided() {
        let config = mock_config();
        let route = resolve_route(None, &config);
        assert_eq!(route.base_url, "https://api.fallback.com");
        assert_eq!(route.actual_model, Some("gpt-3.5-turbo".to_string()));
    }

    #[test]
    fn resolve_route_does_not_fall_back_to_upstream_key_for_different_provider() {
        // When Anthropic provider has no api_key (e.g. ANTHROPIC_API_KEY not set),
        // the route's api_key must be empty — NOT the upstream (OpenAI) key.
        // Sending an OpenAI key to Anthropic causes "invalid x-api-key".
        let mut config = mock_config();
        config.providers.insert(
            "anthropic".to_string(),
            crate::config::ProviderConfig {
                base_url: "https://api.anthropic.com".to_string(),
                api_key: String::new(), // not configured
            },
        );
        config.models.insert(
            "claude-sonnet-4-6".to_string(),
            crate::config::ModelRouteConfig {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                fallback: vec![],
                region: None,
            },
        );
        let route = resolve_route(Some("claude-sonnet-4-6"), &config);
        assert_eq!(route.base_url, "https://api.anthropic.com");
        // Must be empty — NOT "sk-fallback-456" (the upstream/OpenAI key)
        assert_eq!(
            route.api_key, "",
            "provider key must not fall back to upstream key"
        );
        assert_eq!(route.provider_name, Some("anthropic".to_string()));
    }
}
