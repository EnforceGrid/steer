use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use axum::Json;
use serde_json::json;

static REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_REQUEST_AT: AtomicU64 = AtomicU64::new(0);
static STARTED_AT: AtomicU64 = AtomicU64::new(0);

/// Call once at startup to record boot time.
pub fn init() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    STARTED_AT.store(now, Ordering::Relaxed);
}

/// Call after each proxied request to update counters.
pub fn record_request() {
    REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    LAST_REQUEST_AT.store(now, Ordering::Relaxed);
}

pub async fn health() -> Json<serde_json::Value> {
    let count = REQUEST_COUNT.load(Ordering::Relaxed);
    let last_at = LAST_REQUEST_AT.load(Ordering::Relaxed);
    let started = STARTED_AT.load(Ordering::Relaxed);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let uptime_s = now.saturating_sub(started);

    let mut resp = json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "service": "steer",
        "requests_total": count,
        "uptime_s": uptime_s,
    });

    if last_at > 0 {
        resp["last_request_at"] = json!(last_at);
        resp["last_request_ago_s"] = json!(now.saturating_sub(last_at));
    }

    Json(resp)
}
