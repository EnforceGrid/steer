//! Yaml-driven, in-memory budget source for OSS.
//!
//! OSS users declare budgets in `steer.yaml`; this module populates
//! `BudgetCache` at startup and handles period rollover in a background task.
//! Spent amounts are tracked in `BudgetCache` (in-memory). Spent state does
//! not survive a restart — that's an acknowledged OSS limitation. EE
//! persists via SQLite.

use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Utc};
use std::sync::Arc;

use super::cache::{BudgetCache, BudgetEntry as CacheEntry};
use crate::config::BudgetEntry as YamlEntry;

/// Compute the next period boundary (UTC). Returns `now + 1 day` for unknown
/// period strings — fail-soft so a typo doesn't crash startup.
pub fn next_reset(now: DateTime<Utc>, period: &str) -> DateTime<Utc> {
    match period {
        "daily" => next_day_utc(now),
        "weekly" => next_monday_utc(now),
        "monthly" => next_month_utc(now),
        _ => now + Duration::days(1),
    }
}

fn next_day_utc(now: DateTime<Utc>) -> DateTime<Utc> {
    let tomorrow: NaiveDate = now.date_naive() + Duration::days(1);
    Utc.from_utc_datetime(&tomorrow.and_hms_opt(0, 0, 0).unwrap())
}

fn next_monday_utc(now: DateTime<Utc>) -> DateTime<Utc> {
    let today_dow = now.weekday().num_days_from_monday(); // Mon=0..Sun=6
    let add = if today_dow == 0 { 7 } else { 7 - today_dow as i64 };
    let target = now.date_naive() + Duration::days(add);
    Utc.from_utc_datetime(&target.and_hms_opt(0, 0, 0).unwrap())
}

fn next_month_utc(now: DateTime<Utc>) -> DateTime<Utc> {
    let (y, m) = if now.month() == 12 {
        (now.year() + 1, 1)
    } else {
        (now.year(), now.month() + 1)
    };
    Utc.with_ymd_and_hms(y, m, 1, 0, 0, 0)
        .single()
        .unwrap_or_else(|| now + Duration::days(30))
}

/// Populate `BudgetCache` from the yaml budget list. Called once at startup.
pub fn populate_cache(cache: &BudgetCache, budgets: &[YamlEntry]) {
    let now = Utc::now();
    for b in budgets {
        let reset_at = next_reset(now, &b.period);
        cache.insert(
            &b.scope,
            &b.scope_id,
            CacheEntry {
                budget_usd: b.amount_usd,
                spent_usd: 0.0,
                period: b.period.clone(),
                reset_at,
            },
        );
    }
}

/// Background task that resets `spent_usd` to 0 at each budget's period
/// boundary. Held state is `(yaml_entry, reset_at)` per budget; on each tick
/// we check whether the boundary has passed and, if so, re-insert with a
/// fresh window.
pub async fn run_rollover_task(
    cache: Arc<BudgetCache>,
    budgets: Vec<YamlEntry>,
    check_interval_secs: u64,
) {
    let mut state: Vec<(YamlEntry, DateTime<Utc>)> = budgets
        .into_iter()
        .map(|b| {
            let reset = next_reset(Utc::now(), &b.period);
            (b, reset)
        })
        .collect();

    let mut interval =
        tokio::time::interval(tokio::time::Duration::from_secs(check_interval_secs.max(1)));
    interval.tick().await; // first tick is immediate; skip it

    loop {
        interval.tick().await;
        let now = Utc::now();
        for (b, reset_at) in state.iter_mut() {
            if *reset_at <= now {
                let new_reset = next_reset(now, &b.period);
                cache.insert(
                    &b.scope,
                    &b.scope_id,
                    CacheEntry {
                        budget_usd: b.amount_usd,
                        spent_usd: 0.0,
                        period: b.period.clone(),
                        reset_at: new_reset,
                    },
                );
                tracing::info!(
                    scope = %b.scope,
                    scope_id = %b.scope_id,
                    period = %b.period,
                    "budget period reset"
                );
                *reset_at = new_reset;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(y: i32, m: u32, d: u32, h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap()
    }

    #[test]
    fn next_reset_daily_advances_to_midnight() {
        let now = ts(2026, 5, 28, 14);
        let next = next_reset(now, "daily");
        assert_eq!(next, ts(2026, 5, 29, 0));
    }

    #[test]
    fn next_reset_weekly_advances_to_next_monday() {
        // 2026-05-28 is a Thursday
        let now = ts(2026, 5, 28, 14);
        let next = next_reset(now, "weekly");
        // Next Monday = 2026-06-01
        assert_eq!(next, ts(2026, 6, 1, 0));
    }

    #[test]
    fn next_reset_weekly_on_monday_advances_to_next_monday() {
        // 2026-06-01 is a Monday
        let now = ts(2026, 6, 1, 12);
        let next = next_reset(now, "weekly");
        assert_eq!(next, ts(2026, 6, 8, 0));
    }

    #[test]
    fn next_reset_monthly_advances_to_first_of_next_month() {
        let now = ts(2026, 5, 28, 14);
        let next = next_reset(now, "monthly");
        assert_eq!(next, ts(2026, 6, 1, 0));
    }

    #[test]
    fn next_reset_monthly_december_rolls_year() {
        let now = ts(2026, 12, 15, 10);
        let next = next_reset(now, "monthly");
        assert_eq!(next, ts(2027, 1, 1, 0));
    }

    #[test]
    fn next_reset_unknown_period_defaults_to_one_day() {
        let now = ts(2026, 5, 28, 14);
        let next = next_reset(now, "bogus");
        assert_eq!(next, ts(2026, 5, 29, 14));
    }

    #[test]
    fn populate_cache_inserts_each_budget() {
        let cache = BudgetCache::new();
        let budgets = vec![
            YamlEntry {
                scope: "agent".to_string(),
                scope_id: "claude-code".to_string(),
                amount_usd: 5.0,
                period: "daily".to_string(),
            },
            YamlEntry {
                scope: "tenant".to_string(),
                scope_id: "tenant-a".to_string(),
                amount_usd: 20.0,
                period: "monthly".to_string(),
            },
        ];
        populate_cache(&cache, &budgets);
        assert_eq!(cache.len(), 2);

        let s = cache.check("agent", "claude-code").unwrap();
        assert!((s.budget_usd - 5.0).abs() < 1e-9);
        assert!((s.spent_usd - 0.0).abs() < 1e-9);
        assert!((s.remaining_usd - 5.0).abs() < 1e-9);
    }

    #[test]
    fn populate_cache_empty_list_is_noop() {
        let cache = BudgetCache::new();
        populate_cache(&cache, &[]);
        assert!(cache.is_empty());
    }

    #[test]
    fn populate_cache_record_spend_decrements_remaining() {
        let cache = BudgetCache::new();
        let budgets = vec![YamlEntry {
            scope: "agent".to_string(),
            scope_id: "x".to_string(),
            amount_usd: 10.0,
            period: "daily".to_string(),
        }];
        populate_cache(&cache, &budgets);
        cache.record_spend("agent", "x", 3.50);
        let s = cache.check("agent", "x").unwrap();
        assert!((s.spent_usd - 3.50).abs() < 1e-9);
        assert!((s.remaining_usd - 6.50).abs() < 1e-9);
        assert!((s.utilization_pct - 35.0).abs() < 1e-6);
    }
}
