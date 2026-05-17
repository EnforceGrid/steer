use std::collections::HashMap;
use std::sync::Arc;
use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HoldStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hold {
    pub hold_id: String,
    pub status: HoldStatus,
    pub created_at: String,
    pub reason: String,
    pub agent_id: Option<String>,
    pub request_hash: String,
    /// The Cedar policy rule_id that triggered this hold.
    #[serde(default)]
    pub policy_id: Option<String>,
    /// Tenant ID for tenant-scoped listing.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Debug)]
pub struct HoldStore {
    holds: Mutex<HashMap<String, Hold>>,
    max_concurrent: usize,
}

impl HoldStore {
    pub fn new(max_concurrent: usize) -> Arc<Self> {
        Arc::new(Self {
            holds: Mutex::new(HashMap::new()),
            max_concurrent,
        })
    }

    pub fn create(
        &self,
        reason: &str,
        agent_id: Option<String>,
        request_hash: &str,
        policy_id: Option<String>,
        tenant_id: Option<String>,
    ) -> Result<Hold, &'static str> {
        let mut holds = self.holds.lock();
        let active = holds.values().filter(|h| h.status == HoldStatus::Pending).count();
        if active >= self.max_concurrent {
            return Err("max_concurrent_holds exceeded");
        }
        let hold = Hold {
            hold_id: Uuid::new_v4().to_string(),
            status: HoldStatus::Pending,
            created_at: Utc::now().to_rfc3339(),
            reason: reason.to_string(),
            agent_id,
            request_hash: request_hash.to_string(),
            policy_id,
            tenant_id,
        };
        holds.insert(hold.hold_id.clone(), hold.clone());
        Ok(hold)
    }

    /// List all holds for a specific tenant, optionally filtered by status.
    pub fn list_for_tenant(&self, tenant_id: &str, status_filter: Option<&HoldStatus>) -> Vec<Hold> {
        let holds = self.holds.lock();
        holds.values()
            .filter(|h| {
                h.tenant_id.as_deref() == Some(tenant_id)
                    && status_filter.map_or(true, |s| h.status == *s)
            })
            .cloned()
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<Hold> {
        self.holds.lock().get(id).cloned()
    }

    pub fn update_status(&self, id: &str, status: HoldStatus) -> bool {
        let mut holds = self.holds.lock();
        if let Some(h) = holds.get_mut(id) {
            h.status = status;
            true
        } else {
            false
        }
    }
}
