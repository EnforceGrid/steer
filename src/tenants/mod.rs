pub mod policy_config;

pub use policy_config::{TenantPolicyConfig, ManagedPolicyVersion, CURRENT_MANAGED_VERSION};

use anyhow::Result;

#[derive(Clone, Debug, Default)]
pub struct TenantSettings {
    pub consent_given: bool,
    pub observation_mode: bool,
    pub data_processing_consent: bool,
    pub data_residency_region: Option<String>,
    pub timezone: Option<String>,
    pub industry: Option<String>,
    pub business_hours_window: Option<String>,
}

pub trait TenantAuthProvider: Send + Sync {
    fn resolve_key(&self, api_key: &str) -> Result<ResolvedKey>;
}

#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub tenant_id: String,
    pub agent_id: Option<String>,
    pub roles: Vec<String>,
}

pub trait TenantSettingsProvider: Send + Sync {
    fn get_settings(&self, tenant_id: &str) -> TenantSettings;
}

pub trait PolicyConfigProvider: Send + Sync {
    fn get_policy_config(&self, tenant_id: &str) -> crate::config::PolicyConfig;
}

/// Single-tenant stub: always returns "default" tenant, accepts any key.
pub struct SingleTenantAuth;

impl TenantAuthProvider for SingleTenantAuth {
    fn resolve_key(&self, _api_key: &str) -> Result<ResolvedKey> {
        Ok(ResolvedKey {
            tenant_id: "default".to_string(),
            agent_id: None,
            roles: vec![],
        })
    }
}

/// Single-tenant stub: returns settings from the global config.
pub struct SingleTenantSettings {
    pub settings: TenantSettings,
}

impl TenantSettingsProvider for SingleTenantSettings {
    fn get_settings(&self, _tenant_id: &str) -> TenantSettings {
        self.settings.clone()
    }
}
