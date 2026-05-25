pub mod entry;

use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::sync::Mutex;

// ANSI escape codes for the compact-format colorizer. Honored only when
// stdout is a TTY and the `NO_COLOR` env var is unset (no-color.org).
const C_RESET: &str = "\x1b[0m";
const C_BOLD: &str = "\x1b[1m";
const C_DIM: &str = "\x1b[2m";
const C_GREEN: &str = "\x1b[32m";
const C_YELLOW: &str = "\x1b[33m";
const C_RED: &str = "\x1b[31m";
const C_CYAN: &str = "\x1b[36m";
const C_MAGENTA: &str = "\x1b[35m";

/// Map an enforcement action to its ANSI color. Ordering reflects severity:
/// green (allow) → yellow (flag) → cyan (transform) → magenta (steer) → red (block).
fn action_color(action: &str) -> &'static str {
    match action {
        "allow" => C_GREEN,
        "flag" => C_YELLOW,
        "transform" => C_CYAN,
        "steer" => C_MAGENTA,
        "block" => C_RED,
        _ => "", // unknown → no color
    }
}

/// Pick a latency color band. Quick visual triage of slow requests.
fn latency_color(ms: f64) -> &'static str {
    if ms < 5.0 {
        C_GREEN
    } else if ms < 20.0 {
        ""
    } else if ms < 50.0 {
        C_YELLOW
    } else {
        C_RED
    }
}

/// Decide whether to emit color codes for stdout.
/// True only when stdout is a TTY AND `NO_COLOR` is unset.
fn stdout_colorize() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

pub trait AuditSink: Send + Sync {
    fn write(&self, entry: serde_json::Value);
}

/// Output format for human-readable audit lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFormat {
    /// Single-line JSON — machine-readable, default for SIEM ingestion.
    Json,
    /// One-line human-readable summary — for developer terminals.
    Compact,
    /// Multi-line indented JSON — for ad-hoc inspection.
    Pretty,
}

impl AuditFormat {
    pub fn parse(s: &str) -> Self {
        match s {
            "compact" => Self::Compact,
            "pretty" => Self::Pretty,
            _ => Self::Json,
        }
    }
}

fn render(entry: &serde_json::Value, format: AuditFormat, colorize: bool) -> String {
    match format {
        AuditFormat::Json => serde_json::to_string(entry).unwrap_or_default(),
        AuditFormat::Pretty => serde_json::to_string_pretty(entry).unwrap_or_default(),
        AuditFormat::Compact => format_compact(entry, colorize),
    }
}

/// Render an audit entry as a single human-readable line.
///
/// Example:
/// `[BLOCK] POST /v1/messages model=claude-sonnet-4-6 block=default-exfiltration-request-block flag=default-no-fallback-flag,default-no-consent-flag,default-unapproved-model-flag matched=markdown_img_data_url,url_data_param latency=2.6ms`
///
/// Grouping: every rule in `enforcement.matched_rules` is shown, grouped by
/// its action (`block=`, `steer=`, `flag=`). The leading `[ACTION]` is the
/// deciding action (what actually happened); the per-action groups give the
/// full picture of which policies contributed.
/// Return `code` if `on`, else empty string. Used everywhere we splice
/// optional ANSI escapes into the compact line.
fn ansi(on: bool, code: &'static str) -> &'static str {
    if on {
        code
    } else {
        ""
    }
}

fn format_compact(entry: &serde_json::Value, colorize: bool) -> String {
    let reset = ansi(colorize, C_RESET);
    let bold = ansi(colorize, C_BOLD);
    let dim = ansi(colorize, C_DIM);

    // Enrichment entries have a different shape — emit a short marker so
    // they don't pollute the compact stream but stay greppable.
    if entry.get("type").and_then(|v| v.as_str()) == Some("enrichment") {
        let parent = entry
            .get("parent_audit_id")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        return format!("{dim}[ENRICH] parent={parent}{reset}");
    }

    let action = entry
        .pointer("/enforcement/action")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let method = entry
        .pointer("/request/method")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let path = entry
        .pointer("/request/path")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let model = entry
        .pointer("/request/model")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let latency = entry
        .pointer("/latency/cadabra_ms")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // Group every matched rule by its action. Order in output: block, steer,
    // flag — strictest first.
    let mut block = Vec::<&str>::new();
    let mut steer = Vec::<&str>::new();
    let mut flag = Vec::<&str>::new();
    if let Some(rules) = entry
        .pointer("/enforcement/matched_rules")
        .and_then(|v| v.as_array())
    {
        for r in rules {
            let id = r.get("rule_id").and_then(|v| v.as_str()).unwrap_or("");
            let a = r.get("action").and_then(|v| v.as_str()).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            match a {
                "block" => block.push(id),
                "steer" => steer.push(id),
                "flag" => flag.push(id),
                _ => {}
            }
        }
    }

    // Fallback: if matched_rules is empty but enforcement.rule_id is set,
    // bucket it under the deciding action so the line is never empty.
    if block.is_empty() && steer.is_empty() && flag.is_empty() {
        if let Some(id) = entry
            .pointer("/enforcement/rule_id")
            .and_then(|v| v.as_str())
        {
            match action {
                "block" => block.push(id),
                "steer" => steer.push(id),
                "flag" => flag.push(id),
                _ => {}
            }
        }
    }

    let mut parts = Vec::new();
    if !block.is_empty() {
        parts.push(format!("block={}", block.join(",")));
    }
    if !steer.is_empty() {
        parts.push(format!("steer={}", steer.join(",")));
    }
    if !flag.is_empty() {
        parts.push(format!("flag={}", flag.join(",")));
    }

    // Detector patterns from all labels, deduplicated, excluding the
    // synthetic "policy" labels (those just point back to the rule_id).
    let mut patterns: Vec<&str> = Vec::new();
    if let Some(labels) = entry.pointer("/labels").and_then(|v| v.as_array()) {
        for l in labels {
            let lt = l.get("label_type").and_then(|v| v.as_str()).unwrap_or("");
            if lt == "policy" {
                continue;
            }
            if let Some(p) = l
                .pointer("/metadata/pattern")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                if !patterns.contains(&p) {
                    patterns.push(p);
                }
            }
        }
    }
    if !patterns.is_empty() {
        parts.push(format!("matched={}", patterns.join(",")));
    }

    // `enforcement.observed == true` just means action == "flag". That's true
    // for both intrinsic flag policies (e.g. `default-unapproved-model-flag`,
    // which ships with `@enforcement("flag")`) and observation-mode rewrites
    // (block -> flag at load time). Don't try to disambiguate them in the
    // compact line — it's misleading. Whether observation mode is active is
    // already announced at startup: `loading policies in observation mode`.
    let action_clr = ansi(colorize, action_color(action));
    let prefix = format!("{bold}{action_clr}[{}]{reset}", action.to_uppercase());

    let mid = if parts.is_empty() {
        String::new()
    } else {
        format!(" {}", parts.join(" "))
    };

    let lat_clr = ansi(colorize, latency_color(latency));
    format!("{prefix} {method} {path} model={model}{mid} latency={lat_clr}{latency:.1}ms{reset}")
}

/// Writes audit entries to stdout in the configured format.
/// Captures whether stdout is a TTY at construction so colorization is a
/// no-op when piped to a file or `docker logs`.
pub struct StdoutAuditSink {
    format: AuditFormat,
    colorize: bool,
}

impl StdoutAuditSink {
    pub fn new(format: AuditFormat) -> Self {
        let colorize = format == AuditFormat::Compact && stdout_colorize();
        Self { format, colorize }
    }
}

impl Default for StdoutAuditSink {
    fn default() -> Self {
        Self::new(AuditFormat::Json)
    }
}

impl AuditSink for StdoutAuditSink {
    fn write(&self, entry: serde_json::Value) {
        println!("{}", render(&entry, self.format, self.colorize));
    }
}

/// Append-only file sink. Single-tenant, no rotation (operator is expected
/// to handle log rotation via logrotate or equivalent).
pub struct FileAuditSink {
    writer: Mutex<File>,
    format: AuditFormat,
}

impl FileAuditSink {
    pub fn open(path: &str, format: AuditFormat) -> std::io::Result<Self> {
        // Ensure the parent directory exists — common operator pitfall.
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: Mutex::new(file),
            format,
        })
    }
}

impl AuditSink for FileAuditSink {
    fn write(&self, entry: serde_json::Value) {
        // File sinks never colorize — ANSI codes would corrupt grep/jq
        // pipelines and SIEM ingestion.
        let line = render(&entry, self.format, false);
        if let Ok(mut f) = self.writer.lock() {
            // Best-effort: a failed write is logged to stderr but never
            // panics the request path. Operators monitor for stderr noise.
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Construct the configured audit sink from `audit.backend`,
/// `audit.log_path`, and `audit.format`.
///
/// **Fail-loud contract**: if the operator selects `backend = "file"` and the
/// log path is not openable, this function returns `Err`. The binary must
/// refuse to start rather than silently degrade to stdout — Steer's value
/// proposition is evidentiary, so a missing audit trail is a defect, not a
/// recoverable warning.
///
/// CISO review (v0.1.0 doc audit) flagged the prior silent-fallback behavior
/// as a blocker. Reference: stage/doc_requirements.md §16.7 (audit fail-loud).
pub fn build_sink(
    backend: &str,
    log_path: &str,
    format: &str,
) -> std::io::Result<std::sync::Arc<dyn AuditSink>> {
    let format = AuditFormat::parse(format);
    match backend {
        "file" => match FileAuditSink::open(log_path, format) {
            Ok(sink) => Ok(std::sync::Arc::new(sink)),
            Err(e) => Err(std::io::Error::new(
                e.kind(),
                format!(
                    "failed to open audit log file '{log_path}': {e}. \
                     Check that the parent directory exists and is writable by the steer process, \
                     and that the path is not a directory or a path on a read-only filesystem. \
                     Refusing to start: silently falling back to stdout would compromise the audit trail."
                ),
            )),
        },
        _ => Ok(std::sync::Arc::new(StdoutAuditSink::new(format))),
    }
}

use serde_json::json;
use uuid::Uuid;

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
            Ok(v) => v
                .get("timestamp")
                .and_then(|t| t.as_str())
                .map(|ts| ts >= cutoff_str.as_str())
                .unwrap_or(true),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `FileAuditSink::open` must surface I/O failures rather than silently
    /// succeeding. The fail-loud contract on `build_sink` relies on this.
    ///
    /// We aim at a path under a known-unwritable parent so the
    /// `create_dir_all` inside `open` fails. `/proc` is read-only on Linux
    /// and does not exist on macOS — on macOS the `mkdir` attempt fails for
    /// a different reason (parent does not exist + no permission to create
    /// it under /). Either failure mode satisfies the test.
    #[test]
    fn file_audit_sink_open_errors_on_unwritable_path() {
        // A path that cannot be created on either Linux or macOS as an
        // unprivileged user.
        let result =
            FileAuditSink::open("/proc/steer-test-cant-write/audit.jsonl", AuditFormat::Json);
        if result.is_ok() {
            // Fall back to a second candidate that is unwritable on macOS.
            let result2 = FileAuditSink::open(
                "/System/steer-test-cant-write/audit.jsonl",
                AuditFormat::Json,
            );
            assert!(
                result2.is_err(),
                "FileAuditSink::open should fail for an unwritable path"
            );
        }
    }

    /// `build_sink` with backend="file" must return Err when the path is
    /// unopenable. The binary then refuses to start, preserving the
    /// evidentiary guarantee.
    #[test]
    fn build_sink_file_backend_fails_loud_on_bad_path() {
        // Try both candidates: one is unwritable on Linux, the other on macOS.
        let candidates = [
            "/proc/steer-test-cant-write/audit.jsonl",
            "/System/steer-test-cant-write/audit.jsonl",
        ];
        let mut last_err: Option<String> = None;
        for path in candidates {
            match build_sink("file", path, "json") {
                Ok(_) => continue,
                Err(e) => {
                    last_err = Some(e.to_string());
                    break;
                }
            }
        }
        let err = last_err.expect("build_sink(file, unwritable) should refuse to start");
        assert!(
            err.contains("Refusing to start") || err.contains("audit log file"),
            "error should explain refusal: {err}"
        );
    }

    /// stdout backend continues to succeed.
    #[test]
    fn build_sink_stdout_backend_always_ok() {
        assert!(build_sink("stdout", "", "json").is_ok());
    }
}
