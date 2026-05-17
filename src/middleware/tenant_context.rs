//! `TenantContext` request extension — resolved tenant identity for the current request.
//!
//! Injected by `ApiKeyLayer` after key validation:
//!   - DB-backed key  → tenant_id from `api_keys.tenant_id`
//!   - Env-var key    → `"default"` (single-tenant backward compat)
//!   - Dev mode / exempt path → `"default"`
//!
//! Route handlers extract it via `Extension(ctx): Extension<TenantContext>`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Clone, Debug)]
pub struct TenantContext {
    pub tenant_id: String,
    /// RBAC roles from the API key. Empty = admin (full access).
    pub roles: Vec<String>,
    /// Authenticated agent identity bound to the API key.
    /// When set, overrides the `eg-agent-id` request header.
    pub bound_agent_id: Option<String>,
}

impl TenantContext {
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            roles: vec![],
            bound_agent_id: None,
        }
    }

    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    pub fn with_bound_agent_id(mut self, bound_agent_id: Option<String>) -> Self {
        self.bound_agent_id = bound_agent_id;
        self
    }

    pub fn default_tenant() -> Self {
        Self::new("default")
    }

    /// Returns true if this context has admin-level access.
    /// Admin = no roles assigned (backwards compat) or explicit "admin" role.
    pub fn is_admin(&self) -> bool {
        self.roles.is_empty() || self.roles.iter().any(|r| r == "admin")
    }

    /// Check whether this context satisfies the required role.
    /// Role hierarchy: admin > policy:approver > policy:author > policy:auditor
    pub fn has_role(&self, required: &str) -> bool {
        if self.is_admin() {
            return true;
        }
        self.roles.iter().any(|r| role_satisfies(r, required))
    }
}

/// Returns true if `held` role satisfies the `required` role.
/// Hierarchy: policy:approver ⊃ policy:author ⊃ policy:auditor
fn role_satisfies(held: &str, required: &str) -> bool {
    if held == required {
        return true;
    }
    match required {
        "policy:auditor" => matches!(held, "policy:author" | "policy:approver"),
        "policy:author" => held == "policy:approver",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tenant_context_defaults() {
        let ctx = TenantContext::new("tenant-abc");
        assert_eq!(ctx.tenant_id, "tenant-abc");
        assert!(ctx.roles.is_empty());
        assert!(ctx.bound_agent_id.is_none());
    }

    #[test]
    fn with_roles_sets_roles() {
        let ctx = TenantContext::new("t1").with_roles(vec!["policy:auditor".to_string()]);
        assert_eq!(ctx.roles, vec!["policy:auditor"]);
    }

    #[test]
    fn with_bound_agent_id_sets_agent() {
        let ctx = TenantContext::new("t1").with_bound_agent_id(Some("agent-x".to_string()));
        assert_eq!(ctx.bound_agent_id, Some("agent-x".to_string()));
    }

    #[test]
    fn default_tenant_returns_default_tenant_id() {
        let ctx = TenantContext::default_tenant();
        assert_eq!(ctx.tenant_id, "default");
        assert!(ctx.roles.is_empty());
    }

    #[test]
    fn is_admin_true_when_no_roles() {
        let ctx = TenantContext::new("t1");
        assert!(ctx.is_admin(), "empty roles = admin");
    }

    #[test]
    fn is_admin_true_when_admin_role() {
        let ctx = TenantContext::new("t1").with_roles(vec!["admin".to_string()]);
        assert!(ctx.is_admin());
    }

    #[test]
    fn is_admin_false_when_non_admin_roles() {
        let ctx = TenantContext::new("t1").with_roles(vec!["policy:auditor".to_string()]);
        assert!(!ctx.is_admin());
    }

    #[test]
    fn has_role_admin_satisfies_any_role() {
        let ctx = TenantContext::new("t1"); // no roles = admin
        assert!(ctx.has_role("policy:auditor"));
        assert!(ctx.has_role("policy:author"));
        assert!(ctx.has_role("policy:approver"));
        assert!(ctx.has_role("anything"));
    }

    #[test]
    fn has_role_auditor_only_satisfies_auditor() {
        let ctx = TenantContext::new("t1").with_roles(vec!["policy:auditor".to_string()]);
        assert!(ctx.has_role("policy:auditor"), "auditor satisfies auditor");
        assert!(
            !ctx.has_role("policy:author"),
            "auditor does not satisfy author"
        );
        assert!(
            !ctx.has_role("policy:approver"),
            "auditor does not satisfy approver"
        );
    }

    #[test]
    fn has_role_author_satisfies_auditor_and_author() {
        let ctx = TenantContext::new("t1").with_roles(vec!["policy:author".to_string()]);
        assert!(ctx.has_role("policy:auditor"), "author satisfies auditor");
        assert!(ctx.has_role("policy:author"), "author satisfies author");
        assert!(
            !ctx.has_role("policy:approver"),
            "author does not satisfy approver"
        );
    }

    #[test]
    fn has_role_approver_satisfies_all_policy_roles() {
        let ctx = TenantContext::new("t1").with_roles(vec!["policy:approver".to_string()]);
        assert!(ctx.has_role("policy:auditor"));
        assert!(ctx.has_role("policy:author"));
        assert!(ctx.has_role("policy:approver"));
    }

    #[test]
    fn require_role_ok_when_authorized() {
        let ctx = TenantContext::new("t1"); // admin
        let result = require_role(&ctx, "policy:author");
        assert!(result.is_ok());
    }

    #[test]
    fn require_role_err_when_unauthorized() {
        let ctx = TenantContext::new("t1").with_roles(vec!["policy:auditor".to_string()]);
        let result = require_role(&ctx, "policy:author");
        assert!(result.is_err());
    }

    #[test]
    fn require_role_returns_403_response() {
        use axum::response::IntoResponse;
        let ctx = TenantContext::new("t1").with_roles(vec!["policy:auditor".to_string()]);
        let err = require_role(&ctx, "policy:author").unwrap_err();
        assert_eq!(err.status(), axum::http::StatusCode::FORBIDDEN);
    }
}

/// Call at the top of gated handlers: `require_role(&ctx, "policy:author")?;`
#[allow(clippy::result_large_err)]
pub fn require_role(ctx: &TenantContext, role: &str) -> Result<(), Response> {
    if ctx.has_role(role) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": {
                    "code": "forbidden",
                    "message": format!(
                        "This API key lacks the '{}' role required for this operation.",
                        role
                    )
                }
            })),
        )
            .into_response())
    }
}
