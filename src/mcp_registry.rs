//! ASI04 — Approved MCP server registry traits.
//!
//! The hot-path enforcement interface is defined here (steer-core).
//! The SQLite-backed implementation lives in steer-ee.

use serde::{Deserialize, Serialize};

/// A registered MCP server entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub created_at: String,
}

/// Request body for registering a new MCP server.
#[derive(Debug, Deserialize)]
pub struct RegisterMcpServerRequest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// Trait for the MCP server approved registry.
pub trait McpRegistryProvider: Send + Sync {
    fn is_approved(&self, server_id: &str) -> bool;
    fn list(&self) -> Vec<McpServer>;
    fn register(&self, req: &RegisterMcpServerRequest) -> anyhow::Result<McpServer>;
    fn remove(&self, server_id: &str) -> anyhow::Result<bool>;
}

/// Concrete in-memory-only registry for open-core builds (no persistence).
pub struct McpServerRegistry {
    servers: parking_lot::RwLock<std::collections::HashMap<String, McpServer>>,
}

impl McpServerRegistry {
    pub fn new() -> Self {
        Self { servers: parking_lot::RwLock::new(std::collections::HashMap::new()) }
    }
}

impl Default for McpServerRegistry {
    fn default() -> Self { Self::new() }
}

impl McpRegistryProvider for McpServerRegistry {
    fn is_approved(&self, server_id: &str) -> bool {
        self.servers.read().contains_key(server_id)
    }

    fn list(&self) -> Vec<McpServer> {
        self.servers.read().values().cloned().collect()
    }

    fn register(&self, req: &RegisterMcpServerRequest) -> anyhow::Result<McpServer> {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let server = McpServer {
            id: req.id.clone(),
            name: req.name.clone(),
            description: req.description.clone(),
            created_at: now,
        };
        self.servers.write().insert(req.id.clone(), server.clone());
        Ok(server)
    }

    fn remove(&self, server_id: &str) -> anyhow::Result<bool> {
        Ok(self.servers.write().remove(server_id).is_some())
    }
}
