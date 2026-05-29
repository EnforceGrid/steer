pub mod cache;
pub mod costs;
pub mod usage;
pub mod yaml_source;

pub use cache::{BudgetCache, BudgetEntry, BudgetStatus};
pub use costs::{CostEstimator, ModelCost};
pub use usage::{parse_anthropic_usage, parse_openai_usage, parse_usage, TokenUsage};

use anyhow::Result;

/// Fields needed to insert a new usage record. Mirrors store::NewTokenUsage but
/// defined here so steer-core pipeline can construct records without depending on
/// the SQLite store.
#[derive(Debug, Clone)]
pub struct NewTokenUsage {
    pub request_id: String,
    pub api_key_hash: Option<String>,
    pub agent_id: Option<String>,
    pub tenant_id: Option<String>,
    pub model: String,
    pub provider: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
    pub estimated_cost_usd: f64,
}

/// Result of a rate limit check.
#[derive(Debug)]
pub enum RateLimitCheckResult {
    Allowed,
    Exceeded {
        limit_type: String,
        window: String,
        limit_value: f64,
        current: f64,
    },
}

/// Trait for token usage recording and rate limiting. Implemented by steer-ee's
/// TokenStore and stubbed by NoopTokenStore in open-core builds.
pub trait TokenProvider: Send + Sync {
    fn record_usage(&self, record: &NewTokenUsage) -> Result<()>;
    fn update_budget_spend(&self, scope: &str, scope_id: &str, cost_usd: f64) -> Result<()>;
    fn check_and_increment(
        &self,
        scope: &str,
        scope_id: &str,
        metric: &str,
        value: f64,
        now: &str,
    ) -> Result<RateLimitCheckResult>;
}

/// No-op token provider for open-core builds.
pub struct NoopTokenProvider;

impl TokenProvider for NoopTokenProvider {
    fn record_usage(&self, _record: &NewTokenUsage) -> Result<()> {
        Ok(())
    }
    fn update_budget_spend(&self, _scope: &str, _scope_id: &str, _cost_usd: f64) -> Result<()> {
        Ok(())
    }
    fn check_and_increment(
        &self,
        _scope: &str,
        _scope_id: &str,
        _metric: &str,
        _value: f64,
        _now: &str,
    ) -> Result<RateLimitCheckResult> {
        Ok(RateLimitCheckResult::Allowed)
    }
}
