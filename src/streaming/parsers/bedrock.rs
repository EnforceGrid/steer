use crate::streaming::parsers::{SseFrame, StreamParser};
use bytes::Bytes;
use serde_json::json;

pub struct BedrockParser;

impl StreamParser for BedrockParser {
    fn provider(&self) -> &str {
        "bedrock"
    }

    fn parse_frame(&self, raw: &[u8]) -> Vec<SseFrame> {
        // TODO(v1.1): decode application/vnd.amazon.eventstream binary frames
        // Frame structure: [total_len:4][headers_len:4][prelude_crc:4][headers:N][payload:M][msg_crc:4]
        // Headers contain ":event-type", ":content-type", ":message-type"
        // Payload for claude models: {"type":"content_block_delta","delta":{"type":"text_delta","text":"..."}}
        // NOTE: Bedrock uses a binary eventstream format, not text-based SSE.
        // The pipeline-level SSE line-buffering (\n\n splitting) may not be
        // appropriate for binary frames — when implementing real Bedrock parsing,
        // consider whether a separate binary-frame accumulator is needed.
        // For now: pass raw bytes through as a single passthrough frame
        vec![SseFrame {
            event: Some("bedrock_raw".to_string()),
            data: format!("[{} bytes]", raw.len()),
            raw: Bytes::copy_from_slice(raw),
            is_done: false,
            is_error: false,
        }]
    }

    fn encode_frame(&self, frame: &SseFrame) -> Bytes {
        // TODO(v1.1): re-encode as eventstream binary with correct CRC32
        frame.raw.clone()
    }

    fn encode_error(&self, message: &str, _prev_hash: &str) -> Bytes {
        // TODO(v1.1): eventstream error frame encoding
        // For now emit a JSON error that clients can detect
        let payload = json!({"__type":"ValidationException","message":message});
        Bytes::from(serde_json::to_vec(&payload).unwrap_or_default())
    }

    fn encode_steer(&self, message: &str, _prev_hash: &str) -> Bytes {
        // TODO(v1.1): eventstream steer frame encoding
        let payload =
            json!({"type":"content_block_delta","delta":{"type":"text_delta","text":message}});
        Bytes::from(serde_json::to_vec(&payload).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::parsers::StreamParser;

    fn parser() -> BedrockParser {
        BedrockParser
    }

    #[test]
    fn parse_frame_passthrough() {
        let raw = b"[binary data]";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event, Some("bedrock_raw".to_string()));
        assert!(!frames[0].is_done);
        assert!(!frames[0].is_error);
    }

    #[test]
    fn encode_error_shape() {
        let encoded = parser().encode_error("blocked", "hash123");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains("ValidationException"));
        assert!(text.contains("blocked"));
    }

    #[test]
    fn encode_steer_shape() {
        let encoded = parser().encode_steer("steered content", "hash123");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains("steered content"));
        assert!(text.contains("content_block_delta"));
    }

    #[test]
    fn provider_name() {
        assert_eq!(parser().provider(), "bedrock");
    }

    #[test]
    fn encode_frame_preserves_raw() {
        let raw = b"test binary";
        let frame = SseFrame {
            event: Some("test".to_string()),
            data: "data".to_string(),
            raw: Bytes::copy_from_slice(raw),
            is_done: false,
            is_error: false,
        };
        let encoded = parser().encode_frame(&frame);
        assert_eq!(encoded.as_ref(), raw);
    }
}
