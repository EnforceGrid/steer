//! Per-tenant Cedar policy engine registry.
//!
//! Each tenant gets its own `Arc<ArcSwap<CedarEngine>>` slot in a `DashMap`.
//! Engines are loaded lazily on first request and reloaded in-place on upgrade.
//!
//! # Engine composition per tenant
//!
//! ```text
//! managed_policy_versions[tenant.managed_version].content   ← immutable baseline
//!   +
//! dsl/policies/{tenant_id}/*.cedar                        ← tenant customisations
//! ```
//!
//! Tenants without a row in `tenant_policy_config` receive:
//!   - managed version: "v1"
//!   - auto_upgrade_managed: true   (suitable for startups / single-tenant deployments)
//!
//! Enterprise tenants set auto_upgrade_managed = false and are upgraded explicitly via
//! `PUT /api/v1/admin/tenants/{id}/managed-version` after internal change approval.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use tracing::{info, warn};

use crate::policy::cedar::{rewrite_enforcement_annotations, CedarEngine};
use crate::tenants::TenantSettingsProvider;

/// Trait abstracting the SQLite-backed TenantPolicyConfigStore so steer-core
/// doesn't depend on rusqlite. Implemented by steer-ee's TenantPolicyConfigStore.
pub trait PolicyRegistryBackend: Send + Sync {
    fn get_tenant_config(
        &self,
        tenant_id: &str,
    ) -> Result<crate::tenants::policy_config::TenantPolicyConfig>;
    fn get_managed_version(
        &self,
        version: &str,
    ) -> Result<Option<crate::tenants::policy_config::ManagedPolicyVersion>>;
    fn tenants_with_auto_upgrade(&self) -> Result<Vec<String>>;
    fn upgrade_tenant_version(&self, tenant_id: &str, version: &str) -> Result<()>;
    fn managed_policy_count_for_version(&self, version: &str) -> usize;
}

/// Domain types re-exported so downstream code doesn't need to import from policy_config.
pub use crate::tenants::policy_config::{
    ManagedPolicyVersion, TenantPolicyConfig, CURRENT_MANAGED_VERSION,
};

pub struct TenantPolicyRegistry {
    /// Live Cedar engines, keyed by tenant_id. Populated lazily.
    engines: DashMap<String, Arc<ArcSwap<CedarEngine>>>,
    config_store: Arc<dyn PolicyRegistryBackend>,
    /// Base directory for per-tenant policy files: `{policy_dir}/{tenant_id}/*.cedar`
    policy_dir: String,
    /// Optional tenant settings provider. When set, `load_engine_for` consults
    /// `TenantSettings.observation_mode` and rewrites `@enforcement("block"|"steer")`
    /// to `@enforcement("flag")` in the combined cedar text before engine creation.
    /// Left as `None` in callsites that don't surface observation mode (e.g. tests).
    settings_provider: Option<Arc<dyn TenantSettingsProvider>>,
}

impl TenantPolicyRegistry {
    pub fn new(config_store: Arc<dyn PolicyRegistryBackend>, policy_dir: &str) -> Self {
        Self {
            engines: DashMap::new(),
            config_store,
            policy_dir: policy_dir.to_string(),
            settings_provider: None,
        }
    }

    /// Attach a tenant settings provider so observation-mode rewriting can fire
    /// on policy load. Additive — callers that don't need observation mode can
    /// skip this. EE wires the DB-backed provider; OSS wires `SingleTenantSettings`.
    pub fn with_settings_provider(mut self, provider: Arc<dyn TenantSettingsProvider>) -> Self {
        self.settings_provider = Some(provider);
        self
    }

    /// Get (or lazily load) the Cedar engine for a tenant.
    /// Falls back to a permissive engine on load failure so the proxy stays up.
    pub fn engine_for(&self, tenant_id: &str) -> Arc<CedarEngine> {
        if let Some(swap) = self.engines.get(tenant_id) {
            return swap.load_full();
        }

        // Lazy-load: build the engine, insert, then return.
        let engine = self.load_engine_for(tenant_id)
            .unwrap_or_else(|e| {
                warn!(tenant_id, error = %e, "failed to load tenant engine — using permissive fallback");
                CedarEngine::permissive()
            });

        let swap = Arc::new(ArcSwap::new(Arc::new(engine)));
        self.engines
            .insert(tenant_id.to_string(), Arc::clone(&swap));
        swap.load_full()
    }

    /// Hot-reload a single tenant's engine without affecting other tenants.
    pub fn reload_tenant(&self, tenant_id: &str) -> Result<()> {
        let engine = self.load_engine_for(tenant_id)?;
        if let Some(swap) = self.engines.get(tenant_id) {
            swap.store(Arc::new(engine));
        } else {
            self.engines.insert(
                tenant_id.to_string(),
                Arc::new(ArcSwap::new(Arc::new(engine))),
            );
        }
        info!(tenant_id, "tenant policy engine reloaded");
        Ok(())
    }

    /// Evict a tenant's cached engine so it reloads on next request.
    /// Use after `TenantPolicyConfigStore::upgrade_tenant_version` to pick up new content.
    pub fn evict(&self, tenant_id: &str) {
        self.engines.remove(tenant_id);
    }

    /// Called after publishing a new managed version:
    /// immediately reloads all tenants with auto_upgrade_managed = true.
    /// Returns the count of tenants upgraded.
    pub fn apply_auto_upgrades(&self, new_version: &str) -> Result<usize> {
        let auto_tenants = self.config_store.tenants_with_auto_upgrade()?;
        let mut count = 0;
        for tenant_id in &auto_tenants {
            self.config_store
                .upgrade_tenant_version(tenant_id, new_version)?;
            self.evict(tenant_id);
            count += 1;
        }
        if count > 0 {
            info!(
                version = new_version,
                count, "auto-upgraded tenants to new managed version"
            );
        }
        Ok(count)
    }

    /// Count Cedar policies in the current managed version.
    /// Used by the capabilities endpoint so the frontend can display the
    /// managed policy count without a per-tenant directory lookup.
    pub fn managed_policy_count(&self) -> usize {
        self.config_store
            .managed_policy_count_for_version(CURRENT_MANAGED_VERSION)
    }

    // ── Internal ──────────────────────────────────────────────────────────

    fn load_engine_for(&self, tenant_id: &str) -> Result<CedarEngine> {
        let config = self.config_store.get_tenant_config(tenant_id)?;
        let managed = self
            .config_store
            .get_managed_version(&config.managed_version)?;

        let mut combined = match managed {
            Some(v) => v.content,
            None => {
                warn!(tenant_id, version = %config.managed_version,
                    "managed version not found — falling back to permissive policy");
                String::new()
            }
        };

        // Append tenant-specific policy files if the directory exists.
        let tenant_dir = format!("{}/{}", self.policy_dir, tenant_id);
        if Path::new(&tenant_dir).is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(&tenant_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "cedar"))
                .collect();
            entries.sort_by_key(|e| e.path());
            for entry in entries {
                let content = std::fs::read_to_string(entry.path())?;
                combined.push('\n');
                combined.push_str(&content);
            }
        }

        if combined.trim().is_empty() {
            return Ok(CedarEngine::permissive());
        }

        // Observation-mode rewriting. Looks up tenant settings if a provider
        // is attached; if `observation_mode` is true, downgrades every
        // `@enforcement("block")` and `@enforcement("steer")` annotation to
        // `@enforcement("flag")` so decisions surface as observation events
        // without blocking traffic.
        let final_text = match self.settings_provider.as_ref() {
            Some(p) if p.get_settings(tenant_id).observation_mode => {
                info!(tenant_id, "loading policies in observation mode");
                rewrite_enforcement_annotations(&combined, "observation")
            }
            _ => combined,
        };

        CedarEngine::from_policy_str(&final_text).map_err(|e| anyhow::anyhow!("{e:?}"))
    }
}

// Tests for TenantPolicyRegistry live in steer-ee where TenantPolicyConfigStore
// (SQLite-backed) is available to implement PolicyRegistryBackend.
