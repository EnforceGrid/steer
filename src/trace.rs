//! W3C Trace Context (traceparent) parsing.
//!
//! Steer is not an OTel exporter — it only extracts trace IDs from inbound
//! requests so they can be stamped into audit entries. Operators with an
//! existing trace tool (Honeycomb, Tempo, Datadog, Jaeger) can then pivot
//! between a trace span and the Steer audit row that recorded the decision.
//!
//! Spec: https://www.w3.org/TR/trace-context/#traceparent-header

use axum::http::HeaderMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub parent_span_id: String,
}

/// Parse a W3C `traceparent` header value.
///
/// Format: `{version}-{trace_id}-{parent_id}-{flags}`
/// - version: 2 hex chars (only `00` accepted; future versions ignored)
/// - trace_id: 32 hex chars, not all zeros
/// - parent_id: 16 hex chars, not all zeros
/// - flags: 2 hex chars (not validated; passed through)
///
/// Returns `None` for any malformed input; never panics.
pub fn parse_traceparent(value: &str) -> Option<TraceContext> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 4 {
        return None;
    }
    if parts[0] != "00" {
        return None;
    }
    let trace_id = parts[1];
    let parent_id = parts[2];
    if trace_id.len() != 32 || !trace_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if parent_id.len() != 16 || !parent_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if trace_id == "00000000000000000000000000000000" {
        return None;
    }
    if parent_id == "0000000000000000" {
        return None;
    }
    if parts[3].len() != 2 || !parts[3].chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(TraceContext {
        trace_id: trace_id.to_string(),
        parent_span_id: parent_id.to_string(),
    })
}

/// Extract `TraceContext` from request headers. Honors `traceparent` only.
pub fn extract(headers: &HeaderMap) -> Option<TraceContext> {
    let value = headers.get("traceparent")?.to_str().ok()?;
    parse_traceparent(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_traceparent() {
        let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let ctx = parse_traceparent(tp).unwrap();
        assert_eq!(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(ctx.parent_span_id, "b7ad6b7169203331");
    }

    #[test]
    fn rejects_unsupported_version() {
        assert!(
            parse_traceparent("01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01").is_none()
        );
    }

    #[test]
    fn rejects_all_zero_trace_id() {
        assert!(
            parse_traceparent("00-00000000000000000000000000000000-b7ad6b7169203331-01").is_none()
        );
    }

    #[test]
    fn rejects_all_zero_parent_id() {
        assert!(
            parse_traceparent("00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01").is_none()
        );
    }

    #[test]
    fn rejects_wrong_length_trace_id() {
        assert!(parse_traceparent("00-0af76-b7ad6b7169203331-01").is_none());
    }

    #[test]
    fn rejects_non_hex_chars() {
        assert!(
            parse_traceparent("00-0af7651916cd43dd8448eb211c80319g-b7ad6b7169203331-01").is_none()
        );
    }

    #[test]
    fn rejects_too_few_parts() {
        assert!(
            parse_traceparent("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331").is_none()
        );
    }

    #[test]
    fn extract_from_headers_returns_none_when_absent() {
        let headers = HeaderMap::new();
        assert!(extract(&headers).is_none());
    }

    #[test]
    fn extract_from_headers_succeeds() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
                .parse()
                .unwrap(),
        );
        let ctx = extract(&headers).unwrap();
        assert_eq!(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c");
    }
}
