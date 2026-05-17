use crate::streaming::parsers::{SseFrame, StreamParser};
use bytes::Bytes;
use serde_json::json;

pub struct AnthropicParser;

impl StreamParser for AnthropicParser {
    fn provider(&self) -> &str {
        "anthropic"
    }

    fn parse_frame(&self, raw: &[u8]) -> Vec<SseFrame> {
        let text = match std::str::from_utf8(raw) {
            Ok(t) => t,
            Err(_) => return vec![],
        };

        let mut frames = vec![];
        let mut current_event: Option<String> = None;
        for line in text.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                current_event = None;
                continue;
            }
            if let Some(event) = line.strip_prefix("event: ") {
                current_event = Some(event.to_string());
            } else if let Some(data) = line.strip_prefix("data: ") {
                let event_name = current_event.clone().unwrap_or_default();
                let is_done = event_name == "message_stop";
                frames.push(SseFrame {
                    event: Some(event_name),
                    data: data.to_string(),
                    raw: Bytes::copy_from_slice(line.as_bytes()),
                    is_done,
                    is_error: false,
                });
            }
        }
        frames
    }

    fn encode_frame(&self, frame: &SseFrame) -> Bytes {
        let mut out = String::new();
        if let Some(ev) = &frame.event {
            out.push_str(&format!("event: {}\n", ev));
        }
        out.push_str(&format!("data: {}\n\n", frame.data));
        Bytes::from(out)
    }

    fn encode_error(&self, message: &str, prev_hash: &str) -> Bytes {
        let payload = json!({
            "type": "error",
            "error": { "type": "enforcegrid_block", "message": message },
            "x_enforcegrid": prev_hash
        });
        Bytes::from(format!("event: error\ndata: {}\n\n", payload))
    }

    fn encode_steer(&self, message: &str, prev_hash: &str) -> Bytes {
        let delta = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": { "type": "text_delta", "text": message },
            "x_enforcegrid": prev_hash
        });
        let stop = json!({ "type": "message_stop" });
        Bytes::from(format!(
            "event: content_block_delta\ndata: {}\n\nevent: message_stop\ndata: {}\n\n",
            delta, stop
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::parsers::StreamParser;

    fn parser() -> AnthropicParser {
        AnthropicParser
    }

    #[test]
    fn parse_frame_extracts_content_block_delta() {
        let raw = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("content_block_delta"));
        assert!(!frames[0].is_done);
        assert!(!frames[0].is_error);
        assert!(frames[0].data.contains("hello"));
    }

    #[test]
    fn parse_frame_marks_message_stop_as_done() {
        let raw = b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_done);
    }

    #[test]
    fn encode_frame_round_trips() {
        let raw = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        let encoded = parser().encode_frame(&frames[0]);
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains("content_block_delta"));
        assert!(text.contains("hi"));
    }

    #[test]
    fn encode_error_includes_enforcegrid_marker() {
        let encoded = parser().encode_error("blocked", "hash123");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains("x_enforcegrid"));
        assert!(text.contains("hash123"));
        assert!(text.contains("blocked"));
    }

    #[test]
    fn parse_frame_ignores_non_data_lines() {
        let raw = b"event: ping\n\n";
        let frames = parser().parse_frame(raw);
        assert!(frames.is_empty());
    }

    // --- Cross-chunk boundary tests (T-SSE-fix) ---
    // These confirm the Anthropic parser works correctly on complete events
    // as delivered by the fixed pipeline using extract_complete_sse_events.
    // The helper splits on \n\n — the universal SSE terminator — so it
    // covers both OpenAI ("data: ...\n\n") and Anthropic ("event: ...\ndata: ...\n\n").

    #[test]
    fn parse_frame_handles_chunk_split_mid_event() {
        use crate::streaming::parsers::extract_complete_sse_events;

        // Anthropic event split across two TCP chunks
        let chunk1 = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hel";
        let chunk2 = b"lo\"}}\n\n";

        let mut sse_buf: Vec<u8> = Vec::new();

        sse_buf.extend_from_slice(chunk1);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert!(events.is_empty(), "No complete event yet after chunk 1");

        sse_buf.extend_from_slice(chunk2);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert_eq!(events.len(), 1, "One complete event after chunk 2");

        let frames = parser().parse_frame(&events[0]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("content_block_delta"));
        assert!(!frames[0].is_done);
        assert!(
            frames[0].data.contains("hello"),
            "Content should be 'hello', got: {}",
            frames[0].data
        );
    }

    #[test]
    fn parse_frame_handles_split_at_event_boundary() {
        use crate::streaming::parsers::extract_complete_sse_events;

        // Chunk 1: complete content_block_delta + first \n of next boundary
        let chunk1 = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n\n";
        // Chunk 2: second \n completing boundary + message_stop event
        let chunk2 = b"\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

        let mut sse_buf: Vec<u8> = Vec::new();

        // After chunk 1: first event is complete
        sse_buf.extend_from_slice(chunk1);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert!(events.len() >= 1, "First event should be complete");

        let frames1 = parser().parse_frame(&events[0]);
        assert_eq!(frames1.len(), 1);
        assert!(frames1[0].data.contains("hi"));
        assert!(!frames1[0].is_done);

        // After chunk 2: message_stop should be extractable
        sse_buf.extend_from_slice(chunk2);
        let events2 = extract_complete_sse_events(&mut sse_buf);
        assert!(
            !events2.is_empty(),
            "message_stop event should be extractable"
        );

        let mut found_done = false;
        for ev in &events2 {
            let frames = parser().parse_frame(ev);
            for f in &frames {
                if f.is_done {
                    found_done = true;
                }
            }
        }
        assert!(
            found_done,
            "Should find message_stop frame after reassembly"
        );
    }

    #[test]
    fn parse_frame_tool_use_first_delta_split() {
        use crate::streaming::parsers::extract_complete_sse_events;

        // Anthropic tool_use: content_block_start with tool info, split across chunks
        let chunk1 = b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_ABC\",\"name\":\"my_tool\",\"input\":{";
        let chunk2 = b"}}}\n\n";

        let mut sse_buf: Vec<u8> = Vec::new();

        sse_buf.extend_from_slice(chunk1);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert!(events.is_empty(), "No complete event yet");

        sse_buf.extend_from_slice(chunk2);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert_eq!(events.len(), 1, "One complete event after chunk 2");

        let frames = parser().parse_frame(&events[0]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("content_block_start"));
        assert!(!frames[0].is_done);

        // Verify tool id and name are extractable from parsed data
        let parsed: serde_json::Value =
            serde_json::from_str(&frames[0].data).expect("Should parse as valid JSON");
        let content_block = &parsed["content_block"];
        assert_eq!(content_block["id"].as_str().unwrap(), "toolu_ABC");
        assert_eq!(content_block["name"].as_str().unwrap(), "my_tool");
        assert_eq!(content_block["type"].as_str().unwrap(), "tool_use");
    }

    #[test]
    fn parse_frame_multiple_events_in_one_chunk() {
        // Two complete Anthropic events in a single chunk — regression test
        let raw = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"a\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"b\"}}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(
            frames.len(),
            2,
            "Two complete events should produce two frames"
        );
        assert!(
            frames[0].data.contains("\"a\""),
            "First frame should contain 'a'"
        );
        assert!(
            frames[1].data.contains("\"b\""),
            "Second frame should contain 'b'"
        );
        assert!(!frames[0].is_done);
        assert!(!frames[1].is_done);
    }
}
