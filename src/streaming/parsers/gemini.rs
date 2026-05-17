use bytes::Bytes;
use serde_json::json;
use crate::streaming::parsers::{SseFrame, StreamParser};

pub struct GeminiParser;

impl StreamParser for GeminiParser {
    fn provider(&self) -> &str { "gemini" }

    fn parse_frame(&self, raw: &[u8]) -> Vec<SseFrame> {
        // TODO(v1.1): implement Gemini streamGenerateContent SSE + NDJSON parser
        // Gemini SSE uses "data: {...}" lines with payload: {"candidates":[{"content":{"parts":[{"text":"..."}]}}]}
        // NDJSON variant: each line is a raw JSON object with the same structure
        // Auto-detect: if first non-empty line starts with "data: " it's SSE, otherwise NDJSON
        // NOTE: When implementing real SSE parsing here, the pipeline-level SSE
        // line-buffering (sse_buf + extract_complete_sse_events in pipeline/mod.rs)
        // already ensures this function receives complete \n\n-terminated events,
        // so no parser-level buffering is needed.
        // For now: pass raw bytes through as a single passthrough frame
        vec![SseFrame {
            event: None,
            data: String::from_utf8_lossy(raw).to_string(),
            raw: Bytes::copy_from_slice(raw),
            is_done: raw.windows(6).any(|w| w == b"[DONE]"),
            is_error: false,
        }]
    }

    fn encode_frame(&self, frame: &SseFrame) -> Bytes {
        // TODO(v1.1): encode as Gemini SSE or NDJSON depending on variant
        frame.raw.clone()
    }

    fn encode_error(&self, message: &str, _prev_hash: &str) -> Bytes {
        // TODO(v1.1): Gemini error shape: {"error":{"code":400,"message":"...","status":"INVALID_ARGUMENT"}}
        let payload = json!({"error":{"code":400,"message":message,"status":"ENFORCEGRID_BLOCK"}});
        Bytes::from(format!("data: {}\n\n", payload))
    }

    fn encode_steer(&self, message: &str, _prev_hash: &str) -> Bytes {
        // TODO(v1.1): Gemini steer shape
        let payload = json!({"candidates":[{"content":{"parts":[{"text":message}]},"finishReason":"STOP"}]});
        Bytes::from(format!("data: {}\n\n", payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::parsers::StreamParser;

    fn parser() -> GeminiParser { GeminiParser }

    #[test]
    fn parse_frame_passthrough() {
        let raw = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello\"}]}}]}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_done);
        assert!(!frames[0].is_error);
    }

    #[test]
    fn parse_frame_marks_done() {
        let raw = b"data: [DONE]\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_done);
    }

    #[test]
    fn encode_error_shape() {
        let encoded = parser().encode_error("blocked", "hash123");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains("ENFORCEGRID_BLOCK"));
        assert!(text.contains("blocked"));
    }

    #[test]
    fn encode_steer_shape() {
        let encoded = parser().encode_steer("steered content", "hash123");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains("steered content"));
        assert!(text.contains("STOP"));
    }

    #[test]
    fn provider_name() {
        assert_eq!(parser().provider(), "gemini");
    }
}
