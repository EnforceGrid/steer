use bytes::Bytes;
use serde_json::json;
use crate::streaming::parsers::{SseFrame, StreamParser};

pub struct GeminiParser;

impl StreamParser for GeminiParser {
    fn provider(&self) -> &str { "gemini" }

    fn parse_frame(&self, raw: &[u8]) -> Vec<SseFrame> {
        let text = match std::str::from_utf8(raw) {
            Ok(t) => t,
            Err(_) => return vec![],
        };

        let mut frames = vec![];
        for line in text.lines() {
            let line = line.trim();
            // Skip keep-alive comments and empty lines
            if line.is_empty() || line.starts_with(':') {
                continue;
            }
            let data = match line.strip_prefix("data: ") {
                Some(d) => d,
                None => continue,
            };
            let v = match serde_json::from_str::<serde_json::Value>(data) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Stream is done when finishReason is present and a terminal value.
            // "UNSPECIFIED"/"FINISH_REASON_UNSPECIFIED" is used mid-stream for non-terminal
            // chunks and must NOT signal done — see LiteLLM issues #12240/#21041.
            let finish_reason_done = v.get("candidates")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("finishReason"))
                .and_then(|r| r.as_str())
                .map(|r| !r.is_empty() && r != "UNSPECIFIED" && r != "FINISH_REASON_UNSPECIFIED")
                .unwrap_or(false);

            // promptFeedback.blockReason is set when the prompt is blocked before generating
            // any candidates (e.g., SAFETY). Treat as terminal — no further chunks will arrive.
            let prompt_blocked = v.get("promptFeedback")
                .and_then(|f| f.get("blockReason"))
                .and_then(|r| r.as_str())
                .map(|r| !r.is_empty())
                .unwrap_or(false);

            let is_done = finish_reason_done || prompt_blocked;

            // Store per-line bytes (not the whole chunk) so frame.raw is a single SSE event.
            frames.push(SseFrame {
                event: None,
                data: data.to_string(),
                raw: Bytes::from(format!("{}\n\n", line)),
                is_done,
                is_error: false,
            });
        }

        frames
    }

    fn encode_frame(&self, frame: &SseFrame) -> Bytes {
        Bytes::from(format!("data: {}\n\n", frame.data))
    }

    fn encode_error(&self, message: &str, _prev_hash: &str) -> Bytes {
        let payload = json!({
            "error": {
                "code": 400,
                "message": message,
                "status": "ENFORCEGRID_BLOCK"
            }
        });
        Bytes::from(format!("data: {}\n\n", payload))
    }

    fn encode_steer(&self, message: &str, _prev_hash: &str) -> Bytes {
        let payload = json!({
            "candidates": [{
                "content": { "parts": [{ "text": message }], "role": "model" },
                "finishReason": "STOP"
            }]
        });
        Bytes::from(format!("data: {}\n\n", payload))
    }

    fn encode_text_delta(&self, text: &str) -> Bytes {
        let payload = json!({
            "candidates": [{
                "content": {"parts": [{"text": text}], "role": "model"}
            }]
        });
        Bytes::from(format!("data: {}\n\n", payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::parsers::StreamParser;

    fn parser() -> GeminiParser { GeminiParser }

    #[test]
    fn provider_name() {
        assert_eq!(parser().provider(), "gemini");
    }

    #[test]
    fn parse_frame_extracts_text_delta() {
        let raw = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello\"}],\"role\":\"model\"}}]}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_done);
        assert!(!frames[0].is_error);
        assert!(frames[0].data.contains("hello"));
    }

    #[test]
    fn parse_frame_marks_finish_reason_as_done() {
        let raw = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"bye\"}],\"role\":\"model\"},\"finishReason\":\"STOP\"}]}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_done);
    }

    #[test]
    fn parse_frame_does_not_mark_done_without_finish_reason() {
        let raw = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]}}]}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_done);
    }

    #[test]
    fn parse_frame_skips_keepalive_comments() {
        let raw = b": keep-alive\ndata: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"x\"}]}}]}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].data.contains("\"x\""));
    }

    #[test]
    fn parse_frame_handles_empty_candidates_gracefully() {
        // Blocked response: empty candidates with blockReason — terminal, no more chunks follow.
        let raw = b"data: {\"candidates\":[],\"promptFeedback\":{\"blockReason\":\"SAFETY\"}}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_done, "promptFeedback.blockReason should mark stream as done");
    }

    #[test]
    fn parse_frame_unspecified_finish_reason_is_not_done() {
        // UNSPECIFIED is used for mid-stream chunks — must not mark stream as done.
        let raw = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]},\"finishReason\":\"UNSPECIFIED\"}]}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_done, "UNSPECIFIED finishReason should not mark stream done");
    }

    #[test]
    fn parse_frame_raw_is_per_line_not_whole_chunk() {
        // raw should be per-line bytes, not the entire input buffer
        let raw = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"a\"}]}}]}\ndata: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"b\"}]}}]}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 2);
        // Each frame's raw should contain only its own line
        let raw0 = std::str::from_utf8(&frames[0].raw).unwrap();
        let raw1 = std::str::from_utf8(&frames[1].raw).unwrap();
        assert!(raw0.contains("\"a\"") && !raw0.contains("\"b\""), "first frame raw should only contain first line");
        assert!(raw1.contains("\"b\"") && !raw1.contains("\"a\""), "second frame raw should only contain second line");
    }

    #[test]
    fn parse_frame_handles_function_call_part() {
        let raw = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"location\":\"Paris\"}}}]}}]}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].data.contains("get_weather"));
    }

    #[test]
    fn encode_frame_wraps_as_sse() {
        let frame = SseFrame {
            event: None,
            data: "{\"candidates\":[]}".to_string(),
            raw: Bytes::new(),
            is_done: false,
            is_error: false,
        };
        let encoded = parser().encode_frame(&frame);
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.starts_with("data: "));
        assert!(text.ends_with("\n\n"));
    }

    #[test]
    fn encode_error_shape() {
        let encoded = parser().encode_error("blocked", "hash123");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains("ENFORCEGRID_BLOCK"));
        assert!(text.contains("blocked"));
    }

    // ─── encode_text_delta tests ─────────────────────────────────────────────

    #[test]
    fn encode_text_delta_produces_valid_sse_frame() {
        let encoded = parser().encode_text_delta("hello world");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.starts_with("data: "), "must start with SSE data prefix");
        assert!(text.ends_with("\n\n"), "must end with SSE event terminator");
    }

    #[test]
    fn encode_text_delta_content_round_trips() {
        let encoded = parser().encode_text_delta("hello world");
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_done, "text delta must not be marked done");
        assert!(!frames[0].is_error);
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        let text = v["candidates"][0]["content"]["parts"][0]["text"].as_str().unwrap();
        assert_eq!(text, "hello world");
    }

    #[test]
    fn encode_text_delta_no_finish_reason() {
        let encoded = parser().encode_text_delta("some text");
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_done, "text delta without finishReason must not be done");
    }

    #[test]
    fn encode_text_delta_pii_redacted_text_round_trips() {
        let redacted = "user ID is [REDACTED_ID]";
        let encoded = parser().encode_text_delta(redacted);
        let frames = parser().parse_frame(&encoded);
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        let text = v["candidates"][0]["content"]["parts"][0]["text"].as_str().unwrap();
        assert_eq!(text, redacted);
    }

    #[test]
    fn encode_text_delta_special_chars_json_escaped() {
        let text = r#"say "hello" \ world"#;
        let encoded = parser().encode_text_delta(text);
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        let recovered = v["candidates"][0]["content"]["parts"][0]["text"].as_str().unwrap();
        assert_eq!(recovered, text);
    }

    #[test]
    fn encode_steer_shape() {
        let encoded = parser().encode_steer("steered content", "hash123");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains("steered content"));
        assert!(text.contains("STOP"));
    }
}
