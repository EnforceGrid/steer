use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

pub type SteerResult<T> = Result<T, SteerError>;

#[derive(Debug, Error)]
pub enum SteerError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("upstream unreachable: {0}")]
    UpstreamUnreachable(String),

    #[error("upstream timeout after {ms}ms")]
    UpstreamTimeout { ms: u64 },

    #[error("blocked by policy: {rule}")]
    PolicyBlock { rule: String },

    #[error("PII detected: {pattern}")]
    PiiBlock { pattern: String },

    #[error("no API key configured")]
    NoApiKey,

    #[error("audit write failure: {0}")]
    AuditWrite(String),

    #[error("Cedar policy error: {0}")]
    CedarPolicy(String),

    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for SteerError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            SteerError::UpstreamUnreachable(_) => (
                StatusCode::BAD_GATEWAY,
                "upstream_unreachable",
                self.to_string(),
            ),
            SteerError::UpstreamTimeout { .. } => (
                StatusCode::GATEWAY_TIMEOUT,
                "upstream_timeout",
                self.to_string(),
            ),
            SteerError::PolicyBlock { .. } => {
                (StatusCode::BAD_REQUEST, "policy_block", self.to_string())
            }
            SteerError::PiiBlock { .. } => (StatusCode::BAD_REQUEST, "pii_block", self.to_string()),
            SteerError::NoApiKey => (StatusCode::BAD_REQUEST, "no_api_key", self.to_string()),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                self.to_string(),
            ),
        };

        // OpenAI-compatible error shape so client SDKs parse it correctly
        let body = json!({
            "error": {
                "message": message,
                "type": code,
                "code": code
            }
        });

        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    fn status_of(err: SteerError) -> axum::http::StatusCode {
        err.into_response().status()
    }

    #[test]
    fn upstream_unreachable_returns_502() {
        let err = SteerError::UpstreamUnreachable("connection refused".to_string());
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn upstream_timeout_returns_504() {
        let err = SteerError::UpstreamTimeout { ms: 5000 };
        assert_eq!(status_of(err), axum::http::StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn policy_block_returns_400() {
        let err = SteerError::PolicyBlock {
            rule: "no-pii".to_string(),
        };
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn pii_block_returns_400() {
        let err = SteerError::PiiBlock {
            pattern: "ssn".to_string(),
        };
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn no_api_key_returns_400() {
        let err = SteerError::NoApiKey;
        assert_eq!(status_of(err), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn config_error_returns_500() {
        let err = SteerError::Config("bad config".to_string());
        assert_eq!(
            status_of(err),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn audit_write_error_returns_500() {
        let err = SteerError::AuditWrite("disk full".to_string());
        assert_eq!(
            status_of(err),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn cedar_policy_error_returns_500() {
        let err = SteerError::CedarPolicy("policy parse error".to_string());
        assert_eq!(
            status_of(err),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            SteerError::UpstreamUnreachable("host".to_string()).to_string(),
            "upstream unreachable: host"
        );
        assert_eq!(
            SteerError::UpstreamTimeout { ms: 1000 }.to_string(),
            "upstream timeout after 1000ms"
        );
        assert_eq!(
            SteerError::PolicyBlock {
                rule: "R1".to_string()
            }
            .to_string(),
            "blocked by policy: R1"
        );
        assert_eq!(
            SteerError::PiiBlock {
                pattern: "ssn".to_string()
            }
            .to_string(),
            "PII detected: ssn"
        );
        assert_eq!(SteerError::NoApiKey.to_string(), "no API key configured");
    }
}
