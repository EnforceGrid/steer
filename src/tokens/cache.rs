use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Domain types ──────────────────────────────────────────────────────────────

/// Minimal budget record returned by the store. Defined here so steer-core
/// can drive BudgetCache refreshes without depending on the SQLite store.
#[derive(Debug, Clone)]
pub struct BudgetRecord {
    pub scope: String,
    pub scope_id: String,
    pub budget_usd: f64,
    pub period: String,
    pub spent_usd: f64,
    pub reset_at: String,
}

/// Trait implemented by steer-ee's TokenStore; allows BudgetCache to refresh
/// from the database without a direct dependency on rusqlite.
pub trait BudgetSource: Send + Sync {
    fn get_budgets(&self) -> anyhow::Result<Vec<BudgetRecord>>;
}

// ──────────────────────────────────────────────────────────────────────────────

/// A single entry in the in-memory budget cache.
#[derive(Debug, Clone)]
pub struct BudgetEntry {
    pub budget_usd: f64,
    pub spent_usd: f64,
    pub period: String,
    pub reset_at: DateTime<Utc>,
}

/// Summary returned by `BudgetCache::check`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetStatus {
    pub budget_usd: f64,
    pub spent_usd: f64,
    pub remaining_usd: f64,
    pub utilization_pct: f64,
}

impl BudgetStatus {
    fn from_entry(entry: &BudgetEntry) -> Self {
        let remaining = (entry.budget_usd - entry.spent_usd).max(0.0);
        let utilization = if entry.budget_usd > 0.0 {
            (entry.spent_usd / entry.budget_usd * 100.0).min(100.0)
        } else {
            0.0
        };
        Self {
            budget_usd: entry.budget_usd,
            spent_usd: entry.spent_usd,
            remaining_usd: remaining,
            utilization_pct: utilization,
        }
    }
}

// ── BudgetCache ───────────────────────────────────────────────────────────────

/// Thread-safe in-memory budget cache.
///
/// Keys are `"{scope}:{scope_id}"` (e.g. `"agent:agent-x"`).
/// Reads never touch the database; writes only update this map.
/// Periodically refreshed from the `TokenStore` via `spawn_refresh_task`.
#[derive(Clone)]
pub struct BudgetCache {
    inner: Arc<RwLock<HashMap<String, BudgetEntry>>>,
}

impl BudgetCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn cache_key(scope: &str, scope_id: &str) -> String {
        format!("{scope}:{scope_id}")
    }

    /// Look up the budget status for `(scope, scope_id)`.
    ///
    /// Returns `None` when no budget has been set (cache-only, no DB hit).
    pub fn check(&self, scope: &str, scope_id: &str) -> Option<BudgetStatus> {
        let key = Self::cache_key(scope, scope_id);
        let map = self.inner.read();
        map.get(&key).map(BudgetStatus::from_entry)
    }

    /// Increment `spent_usd` for `(scope, scope_id)` in the cache.
    ///
    /// No-ops silently if the key does not exist (budget not configured).
    pub fn record_spend(&self, scope: &str, scope_id: &str, amount: f64) {
        let key = Self::cache_key(scope, scope_id);
        let mut map = self.inner.write();
        if let Some(entry) = map.get_mut(&key) {
            entry.spent_usd += amount;
        }
    }

    /// Reload all budgets from the database.
    ///
    /// Entries whose `reset_at` has passed have their `spent_usd` zeroed —
    /// the DB row's `spent_usd` will also be stale, but we treat the cache as
    /// the source of truth for spent amounts in the current period.
    pub fn refresh_from_store(&self, store: &dyn BudgetSource) -> anyhow::Result<()> {
        let budgets = store.get_budgets()?;
        let now = Utc::now();

        let mut new_map: HashMap<String, BudgetEntry> = HashMap::new();

        for b in budgets {
            let reset_at: DateTime<Utc> = b
                .reset_at
                .parse::<DateTime<Utc>>()
                .or_else(|_| {
                    // Try naive datetime + UTC
                    chrono::NaiveDateTime::parse_from_str(&b.reset_at, "%Y-%m-%dT%H:%M:%SZ")
                        .map(|ndt| DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc))
                })
                .unwrap_or(now);

            // If the period has reset, zero out spent_usd.
            let spent_usd = if reset_at <= now { 0.0 } else { b.spent_usd };

            let key = Self::cache_key(&b.scope, &b.scope_id);
            // If there's already an entry (from a duplicate scope/scope_id
            // with a different period), we keep the one with more budget.
            new_map
                .entry(key)
                .and_modify(|e| {
                    if b.budget_usd > e.budget_usd {
                        e.budget_usd = b.budget_usd;
                        e.spent_usd = spent_usd;
                        e.period = b.period.clone();
                        e.reset_at = reset_at;
                    }
                })
                .or_insert_with(|| BudgetEntry {
                    budget_usd: b.budget_usd,
                    spent_usd,
                    period: b.period.clone(),
                    reset_at,
                });
        }

        *self.inner.write() = new_map;
        Ok(())
    }

    /// Direct insertion for warm-up or testing without a DB round-trip.
    pub fn insert(&self, scope: &str, scope_id: &str, entry: BudgetEntry) {
        let key = Self::cache_key(scope, scope_id);
        self.inner.write().insert(key, entry);
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

impl Default for BudgetCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn a background tokio task that refreshes the cache every `interval_secs` seconds.
pub fn spawn_refresh_task(
    cache: Arc<BudgetCache>,
    store: Arc<dyn BudgetSource>,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(interval_secs);
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = cache.refresh_from_store(&*store) {
                tracing::warn!("BudgetCache refresh failed: {e}");
            }
        }
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn future_reset() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::hours(24)
    }

    fn past_reset() -> DateTime<Utc> {
        Utc::now() - chrono::Duration::hours(1)
    }

    // ── check ─────────────────────────────────────────────────────────────────

    #[test]
    fn check_returns_none_when_no_budget() {
        let cache = BudgetCache::new();
        assert!(cache.check("agent", "agent-x").is_none());
    }

    #[test]
    fn check_returns_correct_status() {
        let cache = BudgetCache::new();
        cache.insert(
            "agent",
            "agent-x",
            BudgetEntry {
                budget_usd: 10.0,
                spent_usd: 4.0,
                period: "daily".to_string(),
                reset_at: future_reset(),
            },
        );

        let status = cache.check("agent", "agent-x").expect("should have budget");
        assert!((status.budget_usd - 10.0).abs() < 1e-9);
        assert!((status.spent_usd - 4.0).abs() < 1e-9);
        assert!((status.remaining_usd - 6.0).abs() < 1e-9);
        assert!((status.utilization_pct - 40.0).abs() < 1e-9);
    }

    #[test]
    fn check_utilization_capped_at_100() {
        let cache = BudgetCache::new();
        cache.insert(
            "agent",
            "over-budget",
            BudgetEntry {
                budget_usd: 10.0,
                spent_usd: 15.0,
                period: "daily".to_string(),
                reset_at: future_reset(),
            },
        );
        let status = cache.check("agent", "over-budget").unwrap();
        assert!((status.utilization_pct - 100.0).abs() < 1e-9);
        assert_eq!(status.remaining_usd, 0.0);
    }

    #[test]
    fn check_zero_budget_utilization_is_zero() {
        let cache = BudgetCache::new();
        cache.insert(
            "agent",
            "zero-budget",
            BudgetEntry {
                budget_usd: 0.0,
                spent_usd: 0.0,
                period: "daily".to_string(),
                reset_at: future_reset(),
            },
        );
        let status = cache.check("agent", "zero-budget").unwrap();
        assert_eq!(status.utilization_pct, 0.0);
    }

    // ── record_spend ──────────────────────────────────────────────────────────

    #[test]
    fn record_spend_updates_remaining() {
        let cache = BudgetCache::new();
        cache.insert(
            "agent",
            "agent-y",
            BudgetEntry {
                budget_usd: 20.0,
                spent_usd: 0.0,
                period: "daily".to_string(),
                reset_at: future_reset(),
            },
        );

        cache.record_spend("agent", "agent-y", 5.0);
        cache.record_spend("agent", "agent-y", 3.0);

        let status = cache.check("agent", "agent-y").unwrap();
        assert!((status.spent_usd - 8.0).abs() < 1e-9);
        assert!((status.remaining_usd - 12.0).abs() < 1e-9);
    }

    #[test]
    fn record_spend_noop_when_no_budget() {
        let cache = BudgetCache::new();
        // Should not panic
        cache.record_spend("agent", "nonexistent", 1.0);
    }

    // Note: refresh_from_store tests live in steer-ee where TokenStore (SQLite) is available.

    #[test]
    fn cache_key_format() {
        assert_eq!(BudgetCache::cache_key("agent", "agent-x"), "agent:agent-x");
        assert_eq!(BudgetCache::cache_key("provider", "openai"), "provider:openai");
    }

    // ── past_reset helper usage ───────────────────────────────────────────────

    #[test]
    fn past_reset_is_in_the_past() {
        assert!(past_reset() < Utc::now());
    }
}
