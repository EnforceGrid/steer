pub mod entry;

pub trait AuditSink: Send + Sync {
    fn write(&self, entry: serde_json::Value);
}

/// Open-core stub: writes JSON to stdout. Used in single-tenant mode.
pub struct StdoutAuditSink;

impl AuditSink for StdoutAuditSink {
    fn write(&self, entry: serde_json::Value) {
        if let Ok(json) = serde_json::to_string(&entry) {
            println!("{}", json);
        }
    }
}

use uuid::Uuid;
use serde_json::json;

pub fn generate_audit_id() -> String {
    Uuid::new_v4().to_string().replace('-', "")[..16].to_string()
}

/// Build an enrichment entry that links to a parent audit entry.
/// Used for async evidence: detector signals, control facts, and
/// redacted payloads that arrive after the base entry was written.
pub fn build_enrichment_entry(
    parent_audit_id: &str,
    request_payload: Option<&str>,
    response_payload: Option<&str>,
    async_detector_snapshot: Option<&serde_json::Value>,
    async_control_facts: Option<&serde_json::Value>,
    evidence_labels: &[String],
    enrichment_latency_ms: f64,
) -> serde_json::Value {
    json!({
        "audit_id": Uuid::new_v4().to_string(),
        "parent_audit_id": parent_audit_id,
        "type": "enrichment",
        "timestamp": chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "request_payload": request_payload,
        "response_payload": response_payload,
        "detector_snapshot": async_detector_snapshot,
        "control_facts": async_control_facts,
        "evidence_labels": evidence_labels,
        "enrichment_latency_ms": enrichment_latency_ms,
    })
}

/// Purge entries older than `retention_days` from the JSONL file at `path`.
/// Uses a temp file + atomic rename to avoid corruption.
pub fn purge_jsonl_file(path: &str, retention_days: u64) -> std::io::Result<usize> {
    use std::io::{BufRead, Write};

    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
    let cutoff_str = cutoff.to_rfc3339();

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };

    let reader = std::io::BufReader::new(file);
    let tmp_path = format!("{}.tmp", path);
    let mut tmp = std::fs::File::create(&tmp_path)?;
    let mut purged = 0usize;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let keep = match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(v) => {
                v.get("timestamp")
                    .and_then(|t| t.as_str())
                    .map(|ts| ts >= cutoff_str.as_str())
                    .unwrap_or(true)
            }
            Err(_) => true,
        };
        if keep {
            writeln!(tmp, "{}", line)?;
        } else {
            purged += 1;
        }
    }

    tmp.flush()?;
    drop(tmp);
    std::fs::rename(&tmp_path, path)?;
    Ok(purged)
}
