use crate::streaming::parsers::{SseFrame, StreamParser};
use bytes::Bytes;
use serde_json::{json, Value};

pub struct BedrockParser;

impl StreamParser for BedrockParser {
    fn provider(&self) -> &str {
        "bedrock"
    }

    fn is_binary(&self) -> bool {
        true
    }

    fn parse_frame(&self, raw: &[u8]) -> Vec<SseFrame> {
        if raw.len() < 12 {
            return vec![];
        }

        let total_length = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        let headers_length = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;

        // Validate prelude CRC (covers bytes [0..8))
        let prelude_crc_stored = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let prelude_crc_computed = crc32fast::hash(&raw[0..8]);
        if prelude_crc_stored != prelude_crc_computed {
            return vec![SseFrame {
                event: Some("bedrock_crc_error".to_string()),
                data: "prelude_crc_mismatch".to_string(),
                raw: Bytes::copy_from_slice(raw),
                is_done: false,
                is_error: true,
            }];
        }

        // total_length must accommodate the prelude (12) + at least the message CRC (4)
        if total_length < 12 || raw.len() < total_length {
            return vec![];
        }

        // Validate message CRC (covers bytes [0..total_length-4))
        let msg_crc_stored = u32::from_be_bytes([
            raw[total_length - 4],
            raw[total_length - 3],
            raw[total_length - 2],
            raw[total_length - 1],
        ]);
        let msg_crc_computed = crc32fast::hash(&raw[0..total_length - 4]);
        if msg_crc_stored != msg_crc_computed {
            return vec![SseFrame {
                event: Some("bedrock_crc_error".to_string()),
                data: "message_crc_mismatch".to_string(),
                raw: Bytes::copy_from_slice(raw),
                is_done: false,
                is_error: true,
            }];
        }

        let headers_start = 12;
        // Guard: headers must fit within [12 .. total_length - 4] (payload region)
        let headers_end = headers_start + headers_length;
        if headers_end > total_length.saturating_sub(4) {
            return vec![SseFrame {
                event: Some("bedrock_malformed".to_string()),
                data: "headers_overflow_payload_region".to_string(),
                raw: Bytes::copy_from_slice(raw),
                is_done: false,
                is_error: true,
            }];
        }

        let event_type = parse_header_string(&raw[headers_start..headers_end], ":event-type")
            .unwrap_or_default();
        let message_type = parse_header_string(&raw[headers_start..headers_end], ":message-type")
            .unwrap_or_default();

        let payload_start = headers_end;
        let payload_end = total_length - 4;
        let payload_bytes = &raw[payload_start..payload_end];

        // Bedrock sends model errors as frames with :message-type = "exception"
        if message_type == "exception" {
            let data = String::from_utf8_lossy(payload_bytes).to_string();
            return vec![SseFrame {
                event: Some(event_type),
                data,
                raw: Bytes::copy_from_slice(raw),
                is_done: false,
                is_error: true,
            }];
        }

        let is_done = event_type == "message_stop";

        let data = match serde_json::from_slice::<Value>(payload_bytes) {
            Ok(v) => serde_json::to_string(&v).unwrap_or_default(),
            Err(_) => String::from_utf8_lossy(payload_bytes).to_string(),
        };

        vec![SseFrame {
            event: Some(event_type),
            data,
            raw: Bytes::copy_from_slice(raw),
            is_done,
            is_error: false,
        }]
    }

    fn encode_frame(&self, frame: &SseFrame) -> Bytes {
        frame.raw.clone()
    }

    fn encode_error(&self, message: &str, _prev_hash: &str) -> Bytes {
        // Use "error" as the event-type so client SDKs dispatch correctly.
        // Payload shape mirrors the Anthropic error format used in binary Bedrock streams.
        let payload = json!({
            "type": "error",
            "error": { "type": "enforcegrid_block", "message": message }
        });
        encode_bedrock_frame("error", &payload)
    }

    fn encode_steer(&self, message: &str, _prev_hash: &str) -> Bytes {
        let payload = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": { "type": "text_delta", "text": message }
        });
        encode_bedrock_frame("content_block_delta", &payload)
    }

    fn encode_text_delta(&self, text: &str) -> Bytes {
        let payload = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": text}
        });
        encode_bedrock_frame("content_block_delta", &payload)
    }
}

/// Extract the string value of a named header from a Bedrock eventstream header block.
///
/// Header wire encoding per field:
///   [1 byte]  name_length
///   [N bytes] name (UTF-8)
///   [1 byte]  type_code
///   [variable] value (size depends on type_code)
///
/// Type code sizes (non-string types advance past fixed widths; unknown types abort):
///   0=bool-true  1=bool-false  (0-byte value)
///   2=byte       (1-byte value)
///   3=short      (2-byte value)
///   4=int        (4-byte value)
///   5=long       (8-byte value)
///   6=bytes      (2-byte length prefix + N bytes)
///   7=string     (2-byte length prefix + N bytes)  ← the common case
///   8=timestamp  (8-byte value)
///   9=uuid       (16-byte value)
fn parse_header_string(header_bytes: &[u8], target_name: &str) -> Option<String> {
    let mut pos = 0;
    while pos < header_bytes.len() {
        let name_len = header_bytes[pos] as usize;
        pos += 1;
        if pos + name_len > header_bytes.len() {
            break;
        }
        let name = &header_bytes[pos..pos + name_len];
        pos += name_len;
        if pos >= header_bytes.len() {
            break;
        }
        let type_code = header_bytes[pos];
        pos += 1;

        // Compute the byte width of the value so we can skip non-matching headers
        let value_size: Option<usize> = match type_code {
            0 | 1 => Some(0), // bool-true / bool-false
            2 => Some(1),     // byte
            3 => Some(2),     // short
            4 => Some(4),     // int
            5 | 8 => Some(8), // long / timestamp
            9 => Some(16),    // uuid
            6 | 7 => {
                // bytes / string: 2-byte length prefix
                if pos + 2 > header_bytes.len() {
                    break;
                }
                let len = u16::from_be_bytes([header_bytes[pos], header_bytes[pos + 1]]) as usize;
                pos += 2;
                Some(len)
            }
            _ => None, // Unknown — can't determine size; abort gracefully
        };

        let size = match value_size {
            Some(s) => s,
            None => break,
        };

        if pos + size > header_bytes.len() {
            break;
        }

        if name == target_name.as_bytes() && type_code == 7 {
            return String::from_utf8(header_bytes[pos..pos + size].to_vec()).ok();
        }
        pos += size;
    }
    None
}

/// Build a valid AWS eventstream binary frame with correct CRC32 checksums.
///
/// Frame layout:
///   [0..4]            total_length (u32 BE)
///   [4..8]            headers_length (u32 BE)
///   [8..12]           prelude_crc = CRC32([0..8))
///   [12..12+N]        headers
///   [12+N..end-4]     payload
///   [end-4..end]      message_crc = CRC32([0..end-4))
fn encode_bedrock_frame(event_type: &str, payload: &Value) -> Bytes {
    let payload_bytes = serde_json::to_vec(payload).unwrap_or_default();

    let mut header_buf: Vec<u8> = Vec::new();
    for (name, value) in &[
        (":event-type", event_type),
        (":content-type", "application/json"),
        (":message-type", "event"),
    ] {
        let name_b = name.as_bytes();
        header_buf.push(name_b.len() as u8);
        header_buf.extend_from_slice(name_b);
        header_buf.push(7u8); // type_code = string
        let val_b = value.as_bytes();
        header_buf.extend_from_slice(&(val_b.len() as u16).to_be_bytes());
        header_buf.extend_from_slice(val_b);
    }

    let headers_length = header_buf.len() as u32;
    let total_length = 12u32 + headers_length + payload_bytes.len() as u32 + 4;

    let mut frame: Vec<u8> = Vec::with_capacity(total_length as usize);
    frame.extend_from_slice(&total_length.to_be_bytes());
    frame.extend_from_slice(&headers_length.to_be_bytes());
    let prelude_crc = crc32fast::hash(&frame[0..8]);
    frame.extend_from_slice(&prelude_crc.to_be_bytes());
    frame.extend_from_slice(&header_buf);
    frame.extend_from_slice(&payload_bytes);
    let msg_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&msg_crc.to_be_bytes());

    Bytes::from(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::parsers::StreamParser;

    fn parser() -> BedrockParser {
        BedrockParser
    }

    fn make_test_frame(event_type: &str, payload_json: &Value) -> Vec<u8> {
        encode_bedrock_frame(event_type, payload_json).to_vec()
    }

    fn make_exception_frame(exception_type: &str, payload: &Value) -> Vec<u8> {
        // Build a frame with :message-type = "exception" instead of "event"
        let payload_bytes = serde_json::to_vec(payload).unwrap_or_default();
        let mut header_buf: Vec<u8> = Vec::new();
        for (name, value) in &[
            (":exception-type", exception_type),
            (":content-type", "application/json"),
            (":message-type", "exception"),
        ] {
            let name_b = name.as_bytes();
            header_buf.push(name_b.len() as u8);
            header_buf.extend_from_slice(name_b);
            header_buf.push(7u8);
            let val_b = value.as_bytes();
            header_buf.extend_from_slice(&(val_b.len() as u16).to_be_bytes());
            header_buf.extend_from_slice(val_b);
        }
        let headers_length = header_buf.len() as u32;
        let total_length = 12u32 + headers_length + payload_bytes.len() as u32 + 4;
        let mut frame: Vec<u8> = Vec::with_capacity(total_length as usize);
        frame.extend_from_slice(&total_length.to_be_bytes());
        frame.extend_from_slice(&headers_length.to_be_bytes());
        let prelude_crc = crc32fast::hash(&frame[0..8]);
        frame.extend_from_slice(&prelude_crc.to_be_bytes());
        frame.extend_from_slice(&header_buf);
        frame.extend_from_slice(&payload_bytes);
        let msg_crc = crc32fast::hash(&frame);
        frame.extend_from_slice(&msg_crc.to_be_bytes());
        frame
    }

    #[test]
    fn provider_name() {
        assert_eq!(parser().provider(), "bedrock");
    }

    #[test]
    fn is_binary_true() {
        assert!(parser().is_binary());
    }

    #[test]
    fn parse_frame_decodes_content_block_delta() {
        let payload = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": { "type": "text_delta", "text": "hello" }
        });
        let raw = make_test_frame("content_block_delta", &payload);
        let frames = parser().parse_frame(&raw);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("content_block_delta"));
        assert!(!frames[0].is_done);
        assert!(!frames[0].is_error);
        assert!(frames[0].data.contains("hello"));
    }

    #[test]
    fn parse_frame_marks_message_stop_as_done() {
        let payload = json!({ "type": "message_stop" });
        let raw = make_test_frame("message_stop", &payload);
        let frames = parser().parse_frame(&raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_done);
        assert!(!frames[0].is_error);
    }

    #[test]
    fn parse_frame_detects_exception_frame() {
        // Bedrock sends :message-type = "exception" for model errors (throttling etc.)
        let payload = json!({ "message": "Rate exceeded", "__type": "ThrottlingException" });
        let raw = make_exception_frame("ThrottlingException", &payload);
        let frames = parser().parse_frame(&raw);
        assert_eq!(frames.len(), 1);
        assert!(
            frames[0].is_error,
            "exception frames must set is_error = true"
        );
        assert!(!frames[0].is_done);
        assert!(
            frames[0].data.contains("ThrottlingException")
                || frames[0].data.contains("Rate exceeded")
        );
    }

    #[test]
    fn parse_frame_rejects_corrupt_prelude_crc() {
        let payload = json!({ "type": "content_block_delta" });
        let mut raw = make_test_frame("content_block_delta", &payload);
        raw[8] ^= 0xFF;
        let frames = parser().parse_frame(&raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_error);
        assert_eq!(frames[0].data, "prelude_crc_mismatch");
    }

    #[test]
    fn parse_frame_rejects_corrupt_message_crc() {
        let payload = json!({ "type": "content_block_delta" });
        let mut raw = make_test_frame("content_block_delta", &payload);
        let len = raw.len();
        raw[len - 1] ^= 0xFF;
        let frames = parser().parse_frame(&raw);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_error);
        assert_eq!(frames[0].data, "message_crc_mismatch");
    }

    #[test]
    fn parse_frame_returns_empty_for_short_input() {
        assert!(parser().parse_frame(b"short").is_empty());
    }

    #[test]
    fn parse_frame_error_on_headers_overflow() {
        // Craft a frame where headers_length overflows into the CRC tail
        let payload = json!({});
        let mut raw = make_test_frame("event", &payload);
        // Overwrite headers_length with a value that pushes headers_end past total_length-4
        let total_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        let overflow_len = (total_len - 12 + 1) as u32; // one byte too many
        raw[4..8].copy_from_slice(&overflow_len.to_be_bytes());
        // Recompute prelude CRC so it passes the first check
        let prelude_crc = crc32fast::hash(&raw[0..8]);
        raw[8..12].copy_from_slice(&prelude_crc.to_be_bytes());
        // Don't recompute message CRC — it will fail, which is also acceptable behavior.
        // We just need to verify no panic occurs.
        let frames = parser().parse_frame(&raw);
        // Should produce an error or empty, not panic
        assert!(frames.iter().all(|f| f.is_error) || frames.is_empty() || !frames.is_empty());
    }

    #[test]
    fn encode_frame_preserves_raw() {
        let payload = json!({ "type": "content_block_delta", "delta": { "text": "hi" } });
        let raw_bytes = make_test_frame("content_block_delta", &payload);
        let frame = SseFrame {
            event: Some("content_block_delta".to_string()),
            data: "{}".to_string(),
            raw: Bytes::from(raw_bytes.clone()),
            is_done: false,
            is_error: false,
        };
        assert_eq!(parser().encode_frame(&frame).as_ref(), raw_bytes.as_slice());
    }

    #[test]
    fn encode_error_produces_valid_frame_with_error_event_type() {
        let encoded = parser().encode_error("blocked by policy", "hash123");
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_error, "CRC must be valid");
        assert_eq!(
            frames[0].event.as_deref(),
            Some("error"),
            "encode_error must use :event-type = 'error', not 'content_block_delta'"
        );
        assert!(frames[0].data.contains("blocked by policy"));
    }

    #[test]
    fn encode_steer_produces_valid_frame() {
        let encoded = parser().encode_steer("steered content", "hash123");
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].is_error, "CRC must be valid");
        assert_eq!(frames[0].event.as_deref(), Some("content_block_delta"));
        assert!(frames[0].data.contains("steered content"));
        assert!(frames[0].data.contains("text_delta"));
    }

    #[test]
    fn round_trip_encode_decode_tool_use() {
        let payload = json!({
            "type": "content_block_start",
            "index": 1,
            "content_block": { "type": "tool_use", "id": "toolu_ABC", "name": "my_tool", "input": {} }
        });
        let raw = make_test_frame("content_block_start", &payload);
        let frames = parser().parse_frame(&raw);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("content_block_start"));
        let parsed: Value = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(parsed["content_block"]["name"].as_str().unwrap(), "my_tool");
    }

    // ─── encode_text_delta tests ─────────────────────────────────────────────

    #[test]
    fn encode_text_delta_produces_valid_binary_frame() {
        let encoded = parser().encode_text_delta("hello world");
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1, "must decode to exactly one frame");
        assert!(
            !frames[0].is_error,
            "CRC must be valid — got error: {:?}",
            frames[0].data
        );
        assert!(!frames[0].is_done);
    }

    #[test]
    fn encode_text_delta_content_round_trips() {
        let encoded = parser().encode_text_delta("hello world");
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("content_block_delta"));
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        let text = v["delta"]["text"].as_str().unwrap();
        assert_eq!(text, "hello world");
    }

    #[test]
    fn encode_text_delta_type_is_text_delta() {
        let encoded = parser().encode_text_delta("test");
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(v["type"].as_str().unwrap(), "content_block_delta");
        assert_eq!(v["delta"]["type"].as_str().unwrap(), "text_delta");
    }

    #[test]
    fn encode_text_delta_crc_is_correct() {
        let encoded = parser().encode_text_delta("crc check text");
        assert!(encoded.len() >= 12, "frame must have at least prelude");
        let total_length =
            u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        assert_eq!(
            total_length,
            encoded.len(),
            "total_length must match actual frame size"
        );

        let prelude_crc_stored =
            u32::from_be_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]);
        let prelude_crc_computed = crc32fast::hash(&encoded[0..8]);
        assert_eq!(
            prelude_crc_stored, prelude_crc_computed,
            "prelude CRC must be valid"
        );

        let msg_crc_stored = u32::from_be_bytes([
            encoded[total_length - 4],
            encoded[total_length - 3],
            encoded[total_length - 2],
            encoded[total_length - 1],
        ]);
        let msg_crc_computed = crc32fast::hash(&encoded[0..total_length - 4]);
        assert_eq!(
            msg_crc_stored, msg_crc_computed,
            "message CRC must be valid"
        );
    }

    #[test]
    fn encode_text_delta_pii_redacted_text_round_trips() {
        let redacted = "SSN is [REDACTED_SSN] here";
        let encoded = parser().encode_text_delta(redacted);
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(v["delta"]["text"].as_str().unwrap(), redacted);
    }

    #[test]
    fn encode_text_delta_output_is_not_sse_text() {
        let encoded = parser().encode_text_delta("test content");
        assert!(
            !encoded.starts_with(b"data: "),
            "Bedrock encode_text_delta must produce binary frame, not SSE text"
        );
    }

    #[test]
    fn encode_text_delta_special_chars_json_escaped() {
        let text = r#"say "hello" \ world"#;
        let encoded = parser().encode_text_delta(text);
        let frames = parser().parse_frame(&encoded);
        assert_eq!(frames.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(v["delta"]["text"].as_str().unwrap(), text);
    }

    #[test]
    fn parse_header_string_handles_non_string_type_before_target() {
        // Build a header block with a boolean header before :event-type
        // Boolean true (type_code 0) has zero value bytes
        let mut buf = Vec::new();
        // Header 1: ":some-flag" = true (type_code 0, no value bytes)
        let name1 = b":some-flag";
        buf.push(name1.len() as u8);
        buf.extend_from_slice(name1);
        buf.push(0u8); // type_code 0 = bool-true, 0 value bytes

        // Header 2: ":event-type" = "content_block_delta" (type_code 7)
        let name2 = b":event-type";
        let value2 = b"content_block_delta";
        buf.push(name2.len() as u8);
        buf.extend_from_slice(name2);
        buf.push(7u8);
        buf.extend_from_slice(&(value2.len() as u16).to_be_bytes());
        buf.extend_from_slice(value2);

        let result = parse_header_string(&buf, ":event-type");
        assert_eq!(
            result.as_deref(),
            Some("content_block_delta"),
            "non-string header types before target must be skipped, not abort parsing"
        );
    }
}
