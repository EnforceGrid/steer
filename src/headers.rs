use std::collections::HashMap;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use uuid::Uuid;

/// RFC 7230 §6.1 hop-by-hop headers — never forwarded between hops.
/// Also strip content-encoding: httpx/reqwest auto-decompresses, forwarding causes body mismatch.
static HOP_BY_HOP: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host",
        "content-length", "content-encoding",
    ]
    .into_iter()
    .collect()
});

/// EG-* headers are consumed by EnforceGrid and must never be leaked upstream.
static EG_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "eg-agent", "eg-agent-name", "eg-agent-tags", "eg-agent-id",
        "eg-sandbox", "eg-api-key", "x-mcp-server-id",
    ]
    .into_iter()
    .collect()
});

/// Strip hop-by-hop and EG-* headers from incoming request headers for upstream forwarding.
pub fn forward_headers(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            let key = k.as_str().to_lowercase();
            if HOP_BY_HOP.contains(key.as_str()) || EG_HEADERS.contains(key.as_str()) {
                return None;
            }
            let val = v.to_str().ok()?.trim().to_string();
            if val.is_empty() {
                return None;
            }
            Some((key, val))
        })
        .collect()
}

/// Strip hop-by-hop headers from upstream response headers.
/// content-encoding is stripped because reqwest (with gzip feature) auto-decompresses
/// upstream responses — the body bytes Steer forwards are always uncompressed.
pub fn response_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let map: HashMap<String, String> = headers
        .iter()
        .filter_map(|(k, v)| {
            let key = k.as_str().to_lowercase();
            if HOP_BY_HOP.contains(key.as_str()) {
                return None;
            }
            let val = v.to_str().ok()?.to_string();
            Some((key, val))
        })
        .collect();
    map
}

/// Extract EG-specific metadata headers from a request.
pub struct EgHeaders {
    pub agent_id: Option<String>,
    pub agent_name: Option<String>,
    pub sandbox: bool,
    pub api_key: Option<String>,
    pub request_id: String,
    /// MCP server identifier from `X-MCP-Server-ID` header (OWASP ASI04).
    pub mcp_server_id: Option<String>,
}

impl EgHeaders {
    pub fn extract(headers: &axum::http::HeaderMap) -> Self {
        let get = |k: &str| -> Option<String> {
            headers.get(k)?.to_str().ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        };
        let request_id = get("eg-request-id")
            .or_else(|| get("x-request-id"))
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        Self {
            agent_id: get("eg-agent-id").or_else(|| get("eg-agent")),
            agent_name: get("eg-agent-name"),
            sandbox: get("eg-sandbox").is_some_and(|v| v == "true" || v == "1"),
            api_key: get("eg-api-key"),
            request_id,
            mcp_server_id: get("x-mcp-server-id"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn eg_headers_extract_eg_request_id() {
        let mut headers = HeaderMap::new();
        headers.insert("eg-request-id", "test-id-123".parse().unwrap());
        let eg = EgHeaders::extract(&headers);
        assert_eq!(eg.request_id, "test-id-123");
    }

    #[test]
    fn eg_headers_extract_x_request_id_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "x-id-456".parse().unwrap());
        let eg = EgHeaders::extract(&headers);
        assert_eq!(eg.request_id, "x-id-456");
    }

    #[test]
    fn eg_headers_generates_uuid_when_neither_present() {
        let headers = HeaderMap::new();
        let eg = EgHeaders::extract(&headers);
        // UUID should be non-empty and valid
        assert!(!eg.request_id.is_empty());
        // Check it can parse as UUID
        assert!(Uuid::parse_str(&eg.request_id).is_ok());
    }

    #[test]
    fn forward_headers_strips_eg_agent_id() {
        let mut headers = HeaderMap::new();
        headers.insert("eg-agent-id", "agent-123".parse().unwrap());
        headers.insert("authorization", "Bearer token".parse().unwrap());
        let forwarded = forward_headers(&headers);
        assert!(!forwarded.contains_key("eg-agent-id"));
        assert!(forwarded.contains_key("authorization"));
    }

    #[test]
    fn forward_headers_strips_content_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        headers.insert("authorization", "Bearer token".parse().unwrap());
        let forwarded = forward_headers(&headers);
        assert!(!forwarded.contains_key("content-encoding"));
        assert!(forwarded.contains_key("authorization"));
    }

    #[test]
    fn forward_headers_passes_x_api_key_through() {
        // x-api-key must NOT be stripped: when a client sends a real Anthropic
        // key via ANTHROPIC_API_KEY, it should reach resolve_auth_for_provider
        // so it can be passed through (no upstream key) or replaced (upstream key set).
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "sk-ant-real".parse().unwrap());
        let forwarded = forward_headers(&headers);
        assert!(forwarded.contains_key("x-api-key"), "x-api-key must pass through");
    }

    #[test]
    fn forward_headers_strips_empty_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom-header", "".parse().unwrap());
        headers.insert("x-valid-header", "value".parse().unwrap());
        let forwarded = forward_headers(&headers);
        assert!(!forwarded.contains_key("x-custom-header"));
        assert!(forwarded.contains_key("x-valid-header"));
    }

    #[test]
    fn eg_headers_extracts_mcp_server_id() {
        let mut headers = HeaderMap::new();
        headers.insert("x-mcp-server-id", "github-mcp-server".parse().unwrap());
        let eg = EgHeaders::extract(&headers);
        assert_eq!(eg.mcp_server_id, Some("github-mcp-server".to_string()));
    }

    #[test]
    fn eg_headers_mcp_server_id_none_when_absent() {
        let headers = HeaderMap::new();
        let eg = EgHeaders::extract(&headers);
        assert!(eg.mcp_server_id.is_none());
    }

    #[test]
    fn forward_headers_strips_mcp_server_id() {
        let mut headers = HeaderMap::new();
        headers.insert("x-mcp-server-id", "github-mcp".parse().unwrap());
        headers.insert("authorization", "Bearer token".parse().unwrap());
        let forwarded = forward_headers(&headers);
        assert!(!forwarded.contains_key("x-mcp-server-id"), "X-MCP-Server-ID must not leak upstream");
        assert!(forwarded.contains_key("authorization"));
    }
}
