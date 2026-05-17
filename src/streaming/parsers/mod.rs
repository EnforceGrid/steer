pub mod anthropic;
pub mod bedrock;
pub mod gemini;
pub mod openai;

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

/// Trait for provider-specific SSE parsers.
pub trait StreamParser: Send + Sync {
    fn provider(&self) -> &str;
    fn parse_frame(&self, raw: &[u8]) -> Vec<SseFrame>;
    fn encode_frame(&self, frame: &SseFrame) -> Bytes;
    fn encode_error(&self, message: &str, prev_hash: &str) -> Bytes;
    fn encode_steer(&self, message: &str, prev_hash: &str) -> Bytes;
}

pub fn get_parser(provider: &str) -> Box<dyn StreamParser> {
    match provider {
        "anthropic" => Box::new(anthropic::AnthropicParser),
        "gemini" => Box::new(gemini::GeminiParser),
        "bedrock" => Box::new(bedrock::BedrockParser),
        _ => Box::new(openai::OpenAiParser),
    }
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

/// Detect provider from request path.
pub fn detect_provider(path: &str, _content_type: Option<&str>) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // Simulate TCP chunk 1: partial event
        let mut buf = b"data: {\"content\":\"hel".to_vec();
        let events = extract_complete_sse_events(&mut buf);
        assert!(events.is_empty()); // nothing complete yet

        // Simulate TCP chunk 2: rest of event
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
}
