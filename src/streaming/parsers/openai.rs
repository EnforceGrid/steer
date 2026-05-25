use crate::streaming::parsers::{SseFrame, StreamParser};
use bytes::Bytes;
use serde_json::{json, Value};

pub struct OpenAiParser;

impl StreamParser for OpenAiParser {
    fn provider(&self) -> &str {
        "openai"
    }

    fn parse_frame(&self, raw: &[u8]) -> Vec<SseFrame> {
        let text = match std::str::from_utf8(raw) {
            Ok(t) => t,
            Err(_) => return vec![],
        };

        let mut frames = vec![];
        for line in text.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(data) = line.strip_prefix("data: ") {
                let is_done = data.trim() == "[DONE]";
                let is_error = !is_done
                    && serde_json::from_str::<Value>(data)
                        .map(|v| v.get("error").is_some())
                        .unwrap_or(false);
                frames.push(SseFrame {
                    event: None,
                    data: data.to_string(),
                    raw: Bytes::copy_from_slice(line.as_bytes()),
                    is_done,
                    is_error,
                });
            }
        }
        frames
    }

    fn encode_frame(&self, frame: &SseFrame) -> Bytes {
        Bytes::from(format!("data: {}\n\n", frame.data))
    }

    fn encode_error(&self, message: &str, prev_hash: &str) -> Bytes {
        let payload = json!({
            "error": {
                "message": message,
                "type": "enforcegrid_block",
                "code": "policy_violation",
                "x_enforcegrid": prev_hash
            }
        });
        Bytes::from(format!("data: {}\n\n", payload))
    }

    fn encode_steer(&self, message: &str, prev_hash: &str) -> Bytes {
        let payload = json!({
            "id": "chatcmpl-steer",
            "object": "chat.completion.chunk",
            "choices": [{
                "index": 0,
                "delta": { "content": message },
                "finish_reason": "stop",
                "x_enforcegrid": prev_hash
            }]
        });
        Bytes::from(format!("data: {}\n\ndata: [DONE]\n\n", payload))
    }

    fn encode_text_delta(&self, text: &str) -> Bytes {
        let payload = json!({
            "choices": [{"delta": {"content": text}, "finish_reason": null, "index": 0}]
        });
        Bytes::from(format!("data: {}\n\n", payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::parsers::StreamParser;

    fn parser() -> OpenAiParser {
        OpenAiParser
    }

    #[test]
    fn parse_frame_extracts_data_line() {
        let raw = b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_done);
        assert!(!frames[0].is_error);
        assert!(frames[0].data.contains("hello"));
    }

    #[test]
    fn parse_frame_marks_done() {
        let raw = b"data: [DONE]\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_done);
        assert!(!frames[0].is_error);
    }

    #[test]
    fn parse_frame_marks_error() {
        let raw = b"data: {\"error\":{\"message\":\"oops\",\"type\":\"server_error\"}}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_error);
        assert!(!frames[0].is_done);
    }

    #[test]
    fn encode_frame_round_trips() {
        let raw = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 1);
        let encoded = parser().encode_frame(&frames[0]);
        // encoded must contain the data payload
        assert!(std::str::from_utf8(&encoded).unwrap().contains("hi"));
    }

    #[test]
    fn encode_error_includes_x_enforcegrid_marker() {
        let encoded = parser().encode_error("blocked", "abc123");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains("x_enforcegrid"));
        assert!(text.contains("abc123"));
        assert!(text.contains("blocked"));
    }

    #[test]
    fn parse_frame_ignores_non_data_lines() {
        let raw = b"event: update\nid: 1\n\n";
        let frames = parser().parse_frame(raw);
        assert!(frames.is_empty());
    }

    #[test]
    fn parse_frame_handles_multi_line_chunk() {
        let raw = b"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\ndata: [DONE]\n\n";
        let frames = parser().parse_frame(raw);
        assert_eq!(frames.len(), 2);
        assert!(!frames[0].is_done);
        assert!(frames[1].is_done);
    }

    // --- Cross-chunk boundary tests (T-SSE-fix) ---
    // These tests verify parse_frame works correctly on complete events,
    // as the fixed pipeline (with SSE line-buffering) will deliver them.

    #[test]
    fn parse_frame_handles_chunk_split_mid_event() {
        use crate::streaming::parsers::extract_complete_sse_events;

        // Chunk 1: partial SSE event (no terminating \n\n)
        let chunk1 = b"data: {\"choices\":[{\"delta\":{\"content\":\"hel";
        // Chunk 2: rest of the event with terminator
        let chunk2 = b"lo\"}}]}\n\n";

        // Simulate SSE buffer accumulation
        let mut sse_buf: Vec<u8> = Vec::new();

        sse_buf.extend_from_slice(chunk1);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert!(events.is_empty(), "No complete event yet after chunk 1");

        sse_buf.extend_from_slice(chunk2);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert_eq!(events.len(), 1, "One complete event after chunk 2");

        // Parse the reassembled complete event
        let frames = parser().parse_frame(&events[0]);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_done);
        assert!(!frames[0].is_error);
        assert!(
            frames[0].data.contains("hello"),
            "Content should be 'hello', got: {}",
            frames[0].data
        );
    }

    #[test]
    fn parse_frame_handles_split_at_event_boundary() {
        use crate::streaming::parsers::extract_complete_sse_events;

        // Chunk 1: complete event + first \n of the boundary
        let chunk1 = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\n";
        // Chunk 2: starts with second \n completing boundary + DONE event
        let chunk2 = b"\ndata: [DONE]\n\n";

        // Simulate SSE buffer
        let mut sse_buf: Vec<u8> = Vec::new();

        // After chunk 1: first event is complete
        sse_buf.extend_from_slice(chunk1);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert!(!events.is_empty(), "First event should be complete");

        // Parse first event
        let frames1 = parser().parse_frame(&events[0]);
        assert_eq!(frames1.len(), 1);
        assert!(frames1[0].data.contains("hi"));

        // After chunk 2: DONE event should be complete
        sse_buf.extend_from_slice(chunk2);
        let events2 = extract_complete_sse_events(&mut sse_buf);
        assert!(!events2.is_empty(), "DONE event should be extractable");

        // Find the DONE frame in the extracted events
        let mut found_done = false;
        for ev in &events2 {
            let frames = parser().parse_frame(ev);
            for f in &frames {
                if f.is_done {
                    found_done = true;
                }
            }
        }
        assert!(found_done, "Should find [DONE] frame after reassembly");
    }

    #[test]
    fn parse_frame_tool_call_first_delta_split() {
        use crate::streaming::parsers::extract_complete_sse_events;

        // First tool call delta with id, name, and empty arguments — split across two chunks
        let chunk1 = b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_ABC\",\"type\":\"function\",\"function\":{\"name\":\"my_tool\",\"arguments\":\"";
        let chunk2 = b"\"}}]}}]}\n\n";

        let mut sse_buf: Vec<u8> = Vec::new();

        sse_buf.extend_from_slice(chunk1);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert!(events.is_empty(), "No complete event yet");

        sse_buf.extend_from_slice(chunk2);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert_eq!(events.len(), 1, "One complete event after chunk 2");

        // Parse the reassembled event
        let frames = parser().parse_frame(&events[0]);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_done);
        assert!(!frames[0].is_error);

        // Verify tool call id and name are extractable from the parsed data
        let parsed: serde_json::Value =
            serde_json::from_str(&frames[0].data).expect("Should parse as valid JSON");
        let tool_call = &parsed["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tool_call["id"].as_str().unwrap(), "call_ABC");
        assert_eq!(tool_call["function"]["name"].as_str().unwrap(), "my_tool");
        assert_eq!(tool_call["function"]["arguments"].as_str().unwrap(), "");
    }

    #[test]
    fn parse_frame_multiple_events_in_one_chunk() {
        // Two complete events in a single chunk — regression test
        let raw = b"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n";
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

    #[test]
    fn parse_frame_interior_argument_split() {
        use crate::streaming::parsers::extract_complete_sse_events;

        // Interior argument delta split mid-string — replicates the "M" drop
        // observed as company "Musk" → "usk" in Force's voice agent logs.
        let chunk1 = b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"M";
        let chunk2 = b"usk\\\"\"}}]}}]}\n\n";

        let mut sse_buf: Vec<u8> = Vec::new();
        sse_buf.extend_from_slice(chunk1);
        assert!(
            extract_complete_sse_events(&mut sse_buf).is_empty(),
            "Partial event stays buffered"
        );

        sse_buf.extend_from_slice(chunk2);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert_eq!(events.len(), 1);

        let frames = parser().parse_frame(&events[0]);
        assert_eq!(frames.len(), 1);

        let parsed: serde_json::Value = serde_json::from_str(&frames[0].data)
            .expect("Interior arg delta must parse cleanly after reassembly");
        let args = parsed["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert_eq!(
            args, "\"Musk\"",
            "Full argument must be preserved, got: {args}"
        );
    }

    /// Regression test: enforce path must use encode_frame (not frame.raw)
    /// for non-text frames. frame.raw stores just the trimmed `data: ...` line
    /// without the `\n\n` SSE event terminator. Emitting raw directly produces
    /// malformed SSE that downstream parsers cannot split into discrete events.
    #[test]
    fn enforce_path_finish_reason_tool_calls_has_sse_terminator() {
        let raw_input =
            b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n";
        let frames = parser().parse_frame(raw_input);
        assert_eq!(frames.len(), 1, "Should parse one frame");

        // frame.raw is the trimmed data line — NO \n\n terminator (the bug)
        let raw_str = std::str::from_utf8(&frames[0].raw).unwrap();
        assert!(
            raw_str.starts_with("data: "),
            "raw should start with 'data: ', got: {raw_str}"
        );
        assert!(
            !raw_str.ends_with("\n\n"),
            "raw must NOT end with \\n\\n (that's the bug this test guards against)"
        );

        // encode_frame produces correct SSE framing with \n\n
        let encoded = parser().encode_frame(&frames[0]);
        let encoded_str = std::str::from_utf8(&encoded).unwrap();
        assert!(
            encoded_str.ends_with("\n\n"),
            "encode_frame must produce \\n\\n terminated SSE event, got: {encoded_str}"
        );
        assert!(
            encoded_str.starts_with("data: "),
            "encode_frame must start with 'data: '"
        );

        // Verify the finish_reason payload survives the round-trip
        let reparsed: serde_json::Value =
            serde_json::from_str(encoded_str.trim().strip_prefix("data: ").unwrap())
                .expect("Encoded frame data must be valid JSON");
        assert_eq!(
            reparsed["choices"][0]["finish_reason"].as_str().unwrap(),
            "tool_calls",
            "finish_reason must survive encode_frame round-trip"
        );
    }

    // ─── encode_text_delta tests ─────────────────────────────────────────────

    #[test]
    fn encode_text_delta_produces_valid_sse_frame() {
        let encoded = parser().encode_text_delta("hello world");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(
            text.starts_with("data: "),
            "must start with SSE data prefix"
        );
        assert!(text.ends_with("\n\n"), "must end with SSE event terminator");
    }

    #[test]
    fn encode_text_delta_content_round_trips() {
        let encoded = parser().encode_text_delta("hello world");
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_done);
        assert!(!frames[0].is_error);
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        let text = v["choices"][0]["delta"]["content"].as_str().unwrap();
        assert_eq!(text, "hello world");
    }

    #[test]
    fn encode_text_delta_empty_string() {
        let encoded = parser().encode_text_delta("");
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(
            text.ends_with("\n\n"),
            "empty delta must still be valid SSE"
        );
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn encode_text_delta_pii_redacted_text_round_trips() {
        let redacted = "contact [REDACTED_EMAIL] for help";
        let encoded = parser().encode_text_delta(redacted);
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        let text = v["choices"][0]["delta"]["content"].as_str().unwrap();
        assert_eq!(text, redacted);
    }

    #[test]
    fn encode_text_delta_finish_reason_is_null() {
        let encoded = parser().encode_text_delta("some text");
        let frames = parser().parse_frame(&encoded);
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        assert!(
            v["choices"][0]["finish_reason"].is_null(),
            "encode_text_delta must produce null finish_reason, got: {:?}",
            v
        );
    }

    #[test]
    fn encode_text_delta_special_chars_json_escaped() {
        let text = r#"say "hello" \ world"#;
        let encoded = parser().encode_text_delta(text);
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        let recovered = v["choices"][0]["delta"]["content"].as_str().unwrap();
        assert_eq!(recovered, text);
    }

    #[test]
    fn parse_frame_finish_reason_split() {
        use crate::streaming::parsers::extract_complete_sse_events;

        // finish_reason: "tool_calls" split across chunks.
        // Before fix: Force received truncated JSON → couldn't see finish_reason
        // and reported finish=stop, causing tool execution guard to silently skip.
        let chunk1 = b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_";
        let chunk2 = b"calls\"}]}\n\n";

        let mut sse_buf: Vec<u8> = Vec::new();
        sse_buf.extend_from_slice(chunk1);
        assert!(extract_complete_sse_events(&mut sse_buf).is_empty());

        sse_buf.extend_from_slice(chunk2);
        let events = extract_complete_sse_events(&mut sse_buf);
        assert_eq!(events.len(), 1);

        let frames = parser().parse_frame(&events[0]);
        assert_eq!(frames.len(), 1);

        let parsed: serde_json::Value = serde_json::from_str(&frames[0].data)
            .expect("finish_reason event must parse cleanly after reassembly");
        assert_eq!(
            parsed["choices"][0]["finish_reason"].as_str().unwrap(),
            "tool_calls",
            "finish_reason must survive chunk split"
        );
    }
}
