pub mod openai;
pub mod anthropic;
pub mod gemini;
pub mod bedrock;

use bytes::Bytes;

/// A parsed SSE frame from an upstream provider.
#[derive(Debug, Clone)]
pub struct SseFrame {
    pub event: Option<String>,
    pub data: String,
    pub raw: Bytes,
    pub is_done: bool,
    pub is_error: bool,
}

/// Trait for provider-specific stream parsers.
pub trait StreamParser: Send + Sync {
    fn provider(&self) -> &str;
    /// Whether this parser consumes binary frames (Bedrock eventstream) rather than text SSE.
    fn is_binary(&self) -> bool { false }
    fn parse_frame(&self, raw: &[u8]) -> Vec<SseFrame>;
    fn encode_frame(&self, frame: &SseFrame) -> Bytes;
    fn encode_error(&self, message: &str, prev_hash: &str) -> Bytes;
    fn encode_steer(&self, message: &str, prev_hash: &str) -> Bytes;
    /// Re-encode a (possibly PII-redacted) text string as a valid provider-specific
    /// streaming frame. Called by the enforce path after scan_bytes to replace the
    /// raw-text-bytes emission with properly-framed output.
    fn encode_text_delta(&self, text: &str) -> Bytes;
}

pub fn get_parser(provider: &str) -> Box<dyn StreamParser> {
    match provider {
        "anthropic" => Box::new(anthropic::AnthropicParser),
        "gemini" => Box::new(gemini::GeminiParser),
        "bedrock" => Box::new(bedrock::BedrockParser),
        _ => Box::new(openai::OpenAiParser),
    }
}

/// Detect the upstream provider from an explicit provider name (from config) or
/// from the request path. The explicit name takes precedence over path heuristics.
pub fn detect_provider(provider_name: Option<&str>, path: &str, _content_type: Option<&str>) -> &'static str {
    if let Some(p) = provider_name {
        match p {
            "anthropic" => return "anthropic",
            "gemini" | "google" => return "gemini",
            "bedrock" | "aws-bedrock" => return "bedrock",
            "openai" | "azure" | "azure-openai" => return "openai",
            _ => {} // Unknown explicit name — fall through to path detection
        }
    }
    if path.contains("/v1/messages") {
        return "anthropic";
    }
    if path.contains("/v1beta") || path.contains("generateContent") {
        return "gemini";
    }
    if path.contains("bedrock") {
        return "bedrock";
    }
    "openai"
}

/// Extract complete SSE events from an accumulation buffer.
///
/// SSE events are terminated by `\n\n`. This function drains all complete
/// events from the front of `buf`, leaving any trailing partial event in
/// place.  The pipeline calls this after appending each TCP chunk so that
/// `parse_frame` always receives whole events.
pub fn extract_complete_sse_events(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut events = Vec::new();
    loop {
        // Find the next double-newline delimiter.
        let pos = buf.windows(2).position(|w| w == b"\n\n");
        match pos {
            Some(idx) => {
                // Drain through (and including) the `\n\n`.
                let event: Vec<u8> = buf.drain(..idx + 2).collect();
                events.push(event);
            }
            None => break,
        }
    }
    events
}

/// Extract complete AWS eventstream binary frames from an accumulation buffer.
///
/// A Bedrock frame's total byte length is encoded in the first 4 bytes (big-endian
/// u32).  This function drains all complete frames from the front of `buf`, leaving
/// any trailing partial frame in place.
pub fn extract_complete_bedrock_frames(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    loop {
        if buf.len() < 12 {
            break; // Need at least the prelude (total_length + headers_length + prelude_crc)
        }
        let total_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if total_length < 12 {
            // Corrupt byte — drain 1 byte and retry so subsequent valid frames are preserved.
            buf.drain(..1);
            continue;
        }
        if buf.len() < total_length {
            break; // Incomplete frame — wait for more bytes
        }
        let frame: Vec<u8> = buf.drain(..total_length).collect();
        frames.push(frame);
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_complete_sse_events ──────────────────────────────────────────

    #[test]
    fn extract_single_complete_event() {
        let mut buf = b"data: {\"hello\":true}\n\n".to_vec();
        let events = extract_complete_sse_events(&mut buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], b"data: {\"hello\":true}\n\n");
        assert!(buf.is_empty());
    }

    #[test]
    fn extract_leaves_partial_event_in_buffer() {
        let mut buf = b"data: {\"a\":1}\n\ndata: {\"b\":2".to_vec();
        let events = extract_complete_sse_events(&mut buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], b"data: {\"a\":1}\n\n");
        assert_eq!(buf, b"data: {\"b\":2");
    }

    #[test]
    fn extract_multiple_complete_events() {
        let mut buf = b"data: first\n\ndata: second\n\ndata: third\n\n".to_vec();
        let events = extract_complete_sse_events(&mut buf);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], b"data: first\n\n");
        assert_eq!(events[1], b"data: second\n\n");
        assert_eq!(events[2], b"data: third\n\n");
        assert!(buf.is_empty());
    }

    #[test]
    fn extract_no_complete_events_returns_empty() {
        let mut buf = b"data: partial".to_vec();
        let events = extract_complete_sse_events(&mut buf);
        assert!(events.is_empty());
        assert_eq!(buf, b"data: partial");
    }

    #[test]
    fn extract_empty_buffer_returns_empty() {
        let mut buf = Vec::new();
        let events = extract_complete_sse_events(&mut buf);
        assert!(events.is_empty());
    }

    #[test]
    fn extract_simulates_cross_chunk_accumulation() {
        let mut buf = b"data: {\"content\":\"hel".to_vec();
        let events = extract_complete_sse_events(&mut buf);
        assert!(events.is_empty());

        buf.extend_from_slice(b"lo\"}\n\n");
        let events = extract_complete_sse_events(&mut buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], b"data: {\"content\":\"hello\"}\n\n");
        assert!(buf.is_empty());
    }

    #[test]
    fn extract_done_event() {
        let mut buf = b"data: [DONE]\n\n".to_vec();
        let events = extract_complete_sse_events(&mut buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], b"data: [DONE]\n\n");
    }

    // ── extract_complete_bedrock_frames ──────────────────────────────────────

    fn make_minimal_bedrock_frame(payload: &[u8]) -> Vec<u8> {
        // Build a well-formed frame with zero headers for simplicity.
        // We bypass CRC here to test the length-splitting logic only.
        let headers_length: u32 = 0;
        let total_length: u32 = 12 + payload.len() as u32 + 4;
        let mut frame = Vec::new();
        frame.extend_from_slice(&total_length.to_be_bytes());
        frame.extend_from_slice(&headers_length.to_be_bytes());
        let prelude_crc = crc32fast::hash(&frame[0..8]);
        frame.extend_from_slice(&prelude_crc.to_be_bytes());
        // No headers
        frame.extend_from_slice(payload);
        let msg_crc = crc32fast::hash(&frame);
        frame.extend_from_slice(&msg_crc.to_be_bytes());
        frame
    }

    #[test]
    fn bedrock_extract_single_complete_frame() {
        let payload = b"{}";
        let frame_bytes = make_minimal_bedrock_frame(payload);
        let total_len = frame_bytes.len();
        let mut buf = frame_bytes;
        let frames = extract_complete_bedrock_frames(&mut buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), total_len);
        assert!(buf.is_empty());
    }

    #[test]
    fn bedrock_extract_leaves_partial_frame_in_buffer() {
        let payload = b"{\"type\":\"content_block_delta\"}";
        let mut frame_bytes = make_minimal_bedrock_frame(payload);
        let full_len = frame_bytes.len();
        // Keep only the first half to simulate a partial frame
        frame_bytes.truncate(full_len / 2);
        let mut buf = frame_bytes;
        let frames = extract_complete_bedrock_frames(&mut buf);
        assert!(frames.is_empty());
        assert!(!buf.is_empty());
    }

    #[test]
    fn bedrock_extract_two_complete_frames() {
        let frame1 = make_minimal_bedrock_frame(b"{\"a\":1}");
        let frame2 = make_minimal_bedrock_frame(b"{\"b\":2}");
        let mut buf = [frame1.as_slice(), frame2.as_slice()].concat();
        let frames = extract_complete_bedrock_frames(&mut buf);
        assert_eq!(frames.len(), 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn bedrock_extract_first_complete_second_partial() {
        let frame1 = make_minimal_bedrock_frame(b"first");
        let mut frame2 = make_minimal_bedrock_frame(b"second");
        frame2.truncate(frame2.len() - 2); // truncate to make partial
        let mut buf = [frame1.as_slice(), frame2.as_slice()].concat();
        let frames = extract_complete_bedrock_frames(&mut buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(&frames[0], &make_minimal_bedrock_frame(b"first"));
        assert!(!buf.is_empty()); // partial second frame remains
    }

    #[test]
    fn bedrock_corrupt_byte_drained_valid_frame_recovered() {
        // A single 0x00 prefix byte makes total_length = [0x00, 0x00, 0x00, 0x12] = 18 shift to
        // [0x00, 0x00, 0x00, 0x00] = 0, which is < 12 (corrupt). One drain(..1) re-aligns the
        // buffer so the real total_length field is at position 0, and the frame is recovered.
        let valid_frame = make_minimal_bedrock_frame(b"ok"); // total_length = 18 = 0x00000012
        let mut buf = vec![0x00u8];
        buf.extend_from_slice(&valid_frame);
        let frames = extract_complete_bedrock_frames(&mut buf);
        assert_eq!(frames.len(), 1, "valid frame should be recovered after corrupt byte is drained");
        assert!(buf.is_empty());
    }

    // ── detect_provider ──────────────────────────────────────────────────────

    #[test]
    fn detect_provider_explicit_name_wins() {
        assert_eq!(detect_provider(Some("bedrock"), "/v1/chat/completions", None), "bedrock");
        assert_eq!(detect_provider(Some("anthropic"), "/v1/chat/completions", None), "anthropic");
        assert_eq!(detect_provider(Some("gemini"), "/v1/chat/completions", None), "gemini");
        assert_eq!(detect_provider(Some("openai"), "/v1/messages", None), "openai");
    }

    #[test]
    fn detect_provider_falls_back_to_path() {
        assert_eq!(detect_provider(None, "/v1/messages", None), "anthropic");
        assert_eq!(detect_provider(None, "/v1beta/models/gemini/generateContent", None), "gemini");
        assert_eq!(detect_provider(None, "/bedrock/invoke", None), "bedrock");
        assert_eq!(detect_provider(None, "/v1/chat/completions", None), "openai");
    }

    #[test]
    fn detect_provider_unknown_explicit_falls_back_to_path() {
        // Unknown explicit provider name → use path heuristics
        assert_eq!(detect_provider(Some("unknown_provider"), "/v1/messages", None), "anthropic");
    }
}
