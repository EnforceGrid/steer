//! Domain types for per-tenant policy configuration and managed policy versions.
//! These structs are defined in steer-core so the registry trait and TenantPolicyRegistry
//! can use them without depending on SQLite (which lives in steer-ee).

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// The current managed policy version assigned to new tenants.
pub const CURRENT_MANAGED_VERSION: &str = "v2";

/// Per-tenant policy configuration row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPolicyConfig {
    pub tenant_id: String,
    /// Which managed ruleset version this tenant is pinned to.
    pub managed_version: String,
    /// When true the tenant automatically receives the newest managed version on publish.
    pub auto_upgrade_managed: bool,
    pub updated_at: String,
}

impl TenantPolicyConfig {
    /// Default config for an unknown/new tenant — latest managed version, auto-upgrade on.
    pub fn default_for(tenant_id: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            managed_version: CURRENT_MANAGED_VERSION.to_string(),
            auto_upgrade_managed: true,
            updated_at: Utc::now().to_rfc3339(),
        }
    }
}

/// A single immutable managed-policy snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedPolicyVersion {
    pub version: String,
    pub description: String,
    pub content: String,
    pub content_hash: String,
    pub published_at: String,
    pub published_by: Option<String>,
}
