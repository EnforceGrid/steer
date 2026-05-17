//! ML toxicity sidecar client (Tier 3 — optional HTTP sidecar).
//!
//! Calls an external scoring service (e.g. Detoxify / KoalaAI via FastAPI)
//! and returns a `ToxicityScore`. The result feeds `threat_score_pct` into
//! Cedar context, enabling ML-backed policies alongside the regex hot path.
//!
//! Design principles:
//! - Always fails open: timeouts and connection errors return `None`.
//! - Non-blocking: the caller drives the timeout via `tokio::time::timeout`.
//! - No panics: all error paths are handled gracefully.
//!
//! Expected sidecar API:
//!   POST <toxicity_sidecar_url>
//!   Body: {"text": "..."}
//!   Response: {"threat": 0.0-1.0, "toxicity": 0.0-1.0, "self_harm": 0.0-1.0, "harassment": 0.0-1.0}
//!
//! See `scripts/toxicity-sidecar/` for a reference FastAPI implementation.

use std::time::Duration;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Scores returned by the ML sidecar. All values in [0.0, 1.0].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToxicityScore {
    /// Probability of a direct threat (violence, harm, cyber attack).
    pub threat: f64,
    /// General toxicity probability.
    #[serde(default)]
    pub toxicity: f64,
    /// Self-harm ideation probability.
    #[serde(default)]
    pub self_harm: f64,
    /// Harassment probability.
    #[serde(default)]
    pub harassment: f64,
}

impl ToxicityScore {
    /// Threat score as an integer percentage (0–100) suitable for Cedar context.
    /// Cedar uses `Long` (i64) — multiply by 100 and round.
    pub fn threat_score_pct(&self) -> i64 {
        (self.threat * 100.0).round() as i64
    }
}

#[derive(Serialize)]
struct ClassifyRequest<'a> {
    text: &'a str,
}

/// Call the ML toxicity sidecar with the given text.
///
/// Returns `None` on timeout, connection error, non-2xx response, or parse failure.
/// The caller should treat `None` as "sidecar unavailable — fail open" and set
/// `threat_score_pct = -1` in Cedar context.
pub async fn score(
    client: &reqwest::Client,
    url: &str,
    text: &str,
    timeout_ms: u64,
) -> Option<ToxicityScore> {
    let result = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        client
            .post(url)
            .json(&ClassifyRequest { text })
            .send(),
    )
    .await;

    match result {
        Ok(Ok(resp)) if resp.status().is_success() => {
            match resp.json::<ToxicityScore>().await {
                Ok(score) => Some(score),
                Err(e) => {
                    warn!(error = %e, "toxicity sidecar: failed to parse response");
                    None
                }
            }
        }
        Ok(Ok(resp)) => {
            warn!(status = %resp.status(), "toxicity sidecar: non-2xx response");
            None
        }
        Ok(Err(e)) => {
            warn!(error = %e, "toxicity sidecar: request failed");
            None
        }
        Err(_) => {
            warn!(timeout_ms, "toxicity sidecar: timed out");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_score_pct_rounds_correctly() {
        let s = ToxicityScore { threat: 0.956, toxicity: 0.8, self_harm: 0.0, harassment: 0.1 };
        assert_eq!(s.threat_score_pct(), 96);
    }

    #[test]
    fn threat_score_pct_zero() {
        let s = ToxicityScore { threat: 0.0, toxicity: 0.0, self_harm: 0.0, harassment: 0.0 };
        assert_eq!(s.threat_score_pct(), 0);
    }

    #[test]
    fn threat_score_pct_full() {
        let s = ToxicityScore { threat: 1.0, toxicity: 1.0, self_harm: 0.0, harassment: 0.0 };
        assert_eq!(s.threat_score_pct(), 100);
    }
}
