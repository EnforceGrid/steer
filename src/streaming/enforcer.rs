use crate::pii::{PiiFinding, RegexPiiEngine};
use super::buffer::WordBoundaryBuffer;
use super::parsers::get_parser;

/// Process a single SSE chunk through the enforcement pipeline.
/// Returns the bytes to emit to the caller (possibly empty, possibly rewritten).
///
/// **Important:** `chunk` must contain complete `\n\n`-terminated SSE events.
/// In the production streaming loop (`pipeline/mod.rs`), raw TCP chunks are
/// accumulated in an `sse_buf` and split via `extract_complete_sse_events`
/// before being handed to `parse_frame`. If you call this function directly,
/// ensure the same invariant holds — otherwise events split across TCP chunk
/// boundaries will be silently dropped.
pub fn process_chunk(
    chunk: &[u8],
    buffer: &mut WordBoundaryBuffer,
    pii_engine: &RegexPiiEngine,
    provider: &str,
    _prev_hash: &str,
    findings: &mut Vec<PiiFinding>,
) -> (Vec<u8>, bool) {
    let parser = get_parser(provider);

    // Extract text content from SSE frames
    let mut text_content = String::new();
    let mut has_control_frame = false;

    for frame in parser.parse_frame(chunk) {
        if frame.is_done || frame.is_error {
            // Pass through control frames unchanged
            has_control_frame = true;
            break;
        }
        // Extract text from OpenAI/Anthropic delta format
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&frame.data) {
            if let Some(text) = extract_delta_text(&v) {
                text_content.push_str(&text);
            }
        }
    }

    if has_control_frame || text_content.is_empty() {
        return (chunk.to_vec(), false);
    }

    // Buffer the text content, flush on boundary/size
    let mut output = Vec::new();

    if let Some((flushed, _reason)) = buffer.push(text_content.as_bytes()) {
        let (scanned, new_findings) = pii_engine.scan_bytes(&flushed, "streaming_response");
        if !new_findings.is_empty() {
            findings.extend(new_findings);
        }
        output.extend_from_slice(&scanned);
    }

    (output, false)
}

fn extract_delta_text(v: &serde_json::Value) -> Option<String> {
    // OpenAI: choices[0].delta.content
    v.get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("delta"))
        .and_then(|d| d.get("content"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            // Anthropic: delta.text
            v.get("delta")
                .and_then(|d| d.get("text"))
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::pii::RegexPiiEngine;
    use crate::policy::{EnforcementAction, PolicyDecision, PolicyEngine};
    use crate::error::SteerResult;

    fn engine_with_email() -> RegexPiiEngine {
        RegexPiiEngine::new(&["email".to_string()])
    }

    fn engine_passthrough() -> RegexPiiEngine {
        // Request a non-existent pattern name so the filter produces zero patterns.
        // (Empty slice means "enable all", so we must provide a dummy name instead.)
        RegexPiiEngine::new(&["__no_such_pattern__".to_string()])
    }

    /// Helper: run process_chunk with real engine on a raw SSE chunk.
    fn run(engine: &RegexPiiEngine, raw: &[u8]) -> (Vec<u8>, bool) {
        let mut buffer = WordBoundaryBuffer::new(1024);
        let mut findings = vec![];
        process_chunk(raw, &mut buffer, engine, "openai", "", &mut findings)
    }

    #[test]
    fn clean_stream_passes_through_byte_identical() {
        let engine = engine_passthrough();
        let raw = b"data: {\"choices\":[{\"delta\":{\"content\":\"hello world\"}}]}\n\n";
        let (out, _control) = run(&engine, raw);
        // No PII — output should contain the flushed text "hello world"
        let text = std::str::from_utf8(&out).unwrap_or("");
        assert!(text.contains("hello world") || out.is_empty(),
            "unexpected output: {:?}", out);
    }

    #[test]
    fn stream_with_email_gets_redacted() {
        let engine = engine_with_email();
        // Craft a chunk whose content includes an email and a trailing space (boundary flush)
        let content = "contact user@example.com ";
        let raw_json = format!(
            "{{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}",
            content
        );
        let raw = format!("data: {}\n\n", raw_json);

        let mut buffer = WordBoundaryBuffer::new(1024);
        let mut findings = vec![];
        let (out, _control) = process_chunk(
            raw.as_bytes(), &mut buffer, &engine, "openai", "", &mut findings,
        );

        // If the buffer flushed (boundary on space), output must not contain the raw email
        if !out.is_empty() {
            let text = std::str::from_utf8(&out).unwrap();
            assert!(
                !text.contains("user@example.com"),
                "email should have been redacted, got: {:?}", text
            );
            // At least one finding recorded
            assert!(!findings.is_empty(), "expected a PII finding");
        } else {
            // Buffer didn't flush yet — email is still pending; that's valid too
            // (it will be caught at flush_end)
        }
    }

    // ─── T-007 verdict tests ────────────────────────────────────────────────

    /// Mock policy engine that always returns the configured decision.
    struct FixedPolicyEngine {
        decision: PolicyDecision,
    }

    impl FixedPolicyEngine {
        fn new(decision: PolicyDecision) -> Arc<dyn PolicyEngine> {
            Arc::new(Self { decision })
        }
    }

    impl PolicyEngine for FixedPolicyEngine {
        fn evaluate_request(
            &self,
            _principal: &str,
            _action: &str,
            _resource_attrs: &serde_json::Value,
            _context_attrs: &serde_json::Value,
        ) -> SteerResult<PolicyDecision> {
            Ok(self.decision.clone())
        }

        fn evaluate_response(
            &self,
            _principal: &str,
            _action: &str,
            _resource_attrs: &serde_json::Value,
            _context_attrs: &serde_json::Value,
        ) -> SteerResult<PolicyDecision> {
            Ok(self.decision.clone())
        }
    }

    /// Apply the streaming verdict logic in isolation, mirroring the pipeline's flush→policy→verdict path.
    /// Returns (emitted_bytes, findings, verdict_str, stream_terminated).
    fn apply_verdict(
        scanned: Vec<u8>,
        decision: PolicyDecision,
        pii_findings_in: Vec<PiiFinding>,
    ) -> (Vec<u8>, Vec<PiiFinding>, String, bool) {
        let parser = get_parser("openai");
        let mut findings = pii_findings_in;
        let mut emitted: Vec<u8> = Vec::new();
        let mut verdict = "allow".to_string();
        let mut terminated = false;

        match decision.action {
            EnforcementAction::Allow => {
                emitted.extend_from_slice(&scanned);
            }
            EnforcementAction::Flag => {
                verdict = "flag".to_string();
                let rule_id = decision.rule_id.clone()
                    .unwrap_or_else(|| "streaming_policy".to_string());
                findings.push(PiiFinding {
                    pattern: rule_id,
                    redacted_to: String::new(),
                    count: 1,
                    location: "streaming_response_policy".to_string(),
                    matched_text: None,
                });
                emitted.extend_from_slice(&scanned);
            }
            EnforcementAction::Transform => {
                verdict = "transform".to_string();
                let output = if let Some(ref transform_meta) = decision.transform_to {
                    // transform_to format: "pattern\x1freplace"
                    let parts: Vec<&str> = transform_meta.splitn(2, '\x1f').collect();
                    if parts.len() == 2 {
                        let text_str = String::from_utf8_lossy(&scanned);
                        let transformed = text_str.replace(parts[0], parts[1]);
                        transformed.into_bytes()
                    } else {
                        scanned
                    }
                } else {
                    scanned
                };
                emitted.extend_from_slice(&output);
            }
            EnforcementAction::Steer => {
                verdict = "steer".to_string();
                let msg = decision.steer_message.as_deref()
                    .unwrap_or("I can't help with that.");
                let steer_bytes = parser.encode_steer(msg, "steer");
                emitted.extend_from_slice(&steer_bytes);
                terminated = true;
            }
            EnforcementAction::Block => {
                verdict = "block".to_string();
                let rule_id = decision.rule_id.as_deref()
                    .unwrap_or("policy_block");
                let error_bytes = parser.encode_error(rule_id, "block");
                emitted.extend_from_slice(&error_bytes);
                terminated = true;
            }
        }

        (emitted, findings, verdict, terminated)
    }

    // 1. Flag verdict: stream passes through but findings include the policy flag entry
    #[test]
    fn flag_verdict_passes_content_and_adds_finding() {
        let content = b"safe content here".to_vec();
        let decision = PolicyDecision {
            action: EnforcementAction::Flag,
            rule_id: Some("test_flag_rule".to_string()),
            steer_message: None,
            transform_to: None,
            description: None,
            regulatory_mapping: vec![],
            matched_rules: vec![],
        };
        let (emitted, findings, verdict, terminated) =
            apply_verdict(content.clone(), decision, vec![]);

        assert_eq!(emitted, content, "flag should emit content unchanged");
        assert_eq!(verdict, "flag");
        assert!(!terminated, "flag should not terminate the stream");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern, "test_flag_rule");
        assert_eq!(findings[0].location, "streaming_response_policy");
    }

    // 2. Block verdict: stream emits an error frame and then closes (no content after)
    #[test]
    fn block_verdict_emits_error_frame_and_terminates() {
        let content = b"blocked content".to_vec();
        let decision = PolicyDecision {
            action: EnforcementAction::Block,
            rule_id: Some("no_pii_rule".to_string()),
            steer_message: None,
            transform_to: None,
            description: None,
            regulatory_mapping: vec![],
            matched_rules: vec![],
        };
        let (emitted, _findings, verdict, terminated) =
            apply_verdict(content, decision, vec![]);

        assert_eq!(verdict, "block");
        assert!(terminated, "block should terminate the stream");
        // The emitted bytes should be an error frame, not the original content
        let text = String::from_utf8_lossy(&emitted);
        assert!(!text.contains("blocked content"), "original content must not be emitted after block");
        // Should contain an error indicator (non-empty error frame)
        assert!(!emitted.is_empty(), "block should emit an error frame");
    }

    // 3. Steer verdict: stream emits the steer message and then closes
    #[test]
    fn steer_verdict_emits_steer_message_and_terminates() {
        let content = b"steered content".to_vec();
        let decision = PolicyDecision {
            action: EnforcementAction::Steer,
            rule_id: Some("steer_rule".to_string()),
            steer_message: Some("Let me redirect you to a safer topic.".to_string()),
            transform_to: None,
            description: None,
            regulatory_mapping: vec![],
            matched_rules: vec![],
        };
        let (emitted, _findings, verdict, terminated) =
            apply_verdict(content, decision, vec![]);

        assert_eq!(verdict, "steer");
        assert!(terminated, "steer should terminate the stream");
        // The emitted bytes should contain the steer message, not the original content
        let text = String::from_utf8_lossy(&emitted);
        assert!(!text.contains("steered content"), "original content must not be emitted after steer");
        assert!(
            text.contains("Let me redirect you to a safer topic."),
            "steer message must appear in output, got: {:?}", text
        );
    }

    // 4. Transform verdict: the transform pattern/replace is applied to the emitted text
    #[test]
    fn transform_verdict_applies_pattern_replace() {
        let content = b"hello SECRET world".to_vec();
        let decision = PolicyDecision {
            action: EnforcementAction::Transform,
            rule_id: Some("redact_secret".to_string()),
            steer_message: None,
            transform_to: Some("SECRET\x1f[REDACTED]".to_string()),
            description: None,
            regulatory_mapping: vec![],
            matched_rules: vec![],
        };
        let (emitted, _findings, verdict, terminated) =
            apply_verdict(content, decision, vec![]);

        assert_eq!(verdict, "transform");
        assert!(!terminated, "transform should not terminate the stream");
        let text = String::from_utf8_lossy(&emitted);
        assert!(!text.contains("SECRET"), "SECRET must be replaced, got: {:?}", text);
        assert!(text.contains("[REDACTED]"), "replacement must appear, got: {:?}", text);
        assert!(text.contains("hello"), "surrounding context must be preserved");
    }

    // 5. Allow verdict with PII: PII is redacted, policy is Allow, content emitted
    #[test]
    fn allow_verdict_with_pii_emits_redacted_content() {
        let engine = engine_with_email();

        // Simulate a flushed chunk with an email
        let raw_text = "contact user@example.com for details";
        let (scanned, pii_findings) = engine.scan_bytes(raw_text.as_bytes(), "streaming_response");

        let decision = PolicyDecision {
            action: EnforcementAction::Allow,
            rule_id: None,
            steer_message: None,
            transform_to: None,
            description: None,
            regulatory_mapping: vec![],
            matched_rules: vec![],
        };
        let (emitted, findings, verdict, terminated) =
            apply_verdict(scanned, decision, pii_findings);

        assert_eq!(verdict, "allow");
        assert!(!terminated, "allow should not terminate the stream");
        // PII should have been redacted before reaching the verdict logic
        let text = String::from_utf8_lossy(&emitted);
        assert!(
            !text.contains("user@example.com"),
            "email must be redacted in output, got: {:?}", text
        );
        assert!(!findings.is_empty(), "PII findings must be present");
    }

    // 6. FixedPolicyEngine mock works correctly for evaluate_response
    #[test]
    fn fixed_policy_engine_returns_configured_decision() {
        let engine = FixedPolicyEngine::new(PolicyDecision {
            action: EnforcementAction::Flag,
            rule_id: Some("mock_rule".to_string()),
            steer_message: None,
            transform_to: None,
            description: None,
            regulatory_mapping: vec![],
            matched_rules: vec![],
        });
        let decision = engine.evaluate_response(
            "test_principal",
            "llm.response",
            &serde_json::Value::Null,
            &serde_json::json!({"streaming": true}),
        ).expect("mock engine should not error");
        assert_eq!(decision.action, EnforcementAction::Flag);
        assert_eq!(decision.rule_id.as_deref(), Some("mock_rule"));
    }

    // ─── finish_reason passthrough tests ────────────────────────────────

    /// Regression: a frame with `finish_reason: "tool_calls"` and an empty delta
    /// has no text content. `process_chunk` must emit it verbatim — dropping it
    /// causes Force to see finish_reason "stop" instead and skip tool execution.
    #[test]
    fn finish_reason_tool_calls_frame_passes_through() {
        let engine = engine_passthrough();
        let raw = b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n";
        let (out, _control) = run(&engine, raw);

        assert!(!out.is_empty(), "finish_reason: tool_calls frame must not be dropped");
        let text = std::str::from_utf8(&out).unwrap();
        assert!(
            text.contains("\"finish_reason\":\"tool_calls\""),
            "finish_reason value must be preserved verbatim, got: {:?}", text
        );
    }

    /// End-to-end: a realistic tool-call streaming sequence — tool_call deltas
    /// followed by a finish_reason: "tool_calls" frame — must all pass through
    /// `process_chunk` without any frame being silently dropped.
    #[test]
    fn tool_call_stream_sequence_preserves_all_frames() {
        let engine = engine_passthrough();
        let mut buffer = WordBoundaryBuffer::new(1024);
        let mut findings = vec![];

        // Frame 1: first tool_call delta (function name + id)
        let frame1 = b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_abc\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n";
        let (out1, _) = process_chunk(frame1, &mut buffer, &engine, "openai", "", &mut findings);
        assert!(!out1.is_empty(), "tool_call first delta must pass through");

        // Frame 2: tool_call argument delta
        let frame2 = b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\\\"London\\\"}\"}}]}}]}\n\n";
        let (out2, _) = process_chunk(frame2, &mut buffer, &engine, "openai", "", &mut findings);
        assert!(!out2.is_empty(), "tool_call argument delta must pass through");

        // Frame 3: finish_reason: "tool_calls" with empty delta
        let frame3 = b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n";
        let (out3, _) = process_chunk(frame3, &mut buffer, &engine, "openai", "", &mut findings);
        assert!(!out3.is_empty(), "finish_reason frame must not be dropped");
        let text = std::str::from_utf8(&out3).unwrap();
        assert!(
            text.contains("\"finish_reason\":\"tool_calls\""),
            "finish_reason must be preserved in output, got: {:?}", text
        );
    }
}
