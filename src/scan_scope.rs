//! Determine which portion of the request body to feed to detectors.
//!
//! Conversational LLM clients (Claude Code, Aider, OpenCode, etc.) resend
//! the full message history on every turn. Scanning the whole history
//! produces false-positives on prior turns that contained transient
//! credential strings, bash commands, or tool output — once any past turn
//! trips a block policy, the session wedges because every subsequent turn
//! re-hashes the same poisoned context.
//!
//! Default scope: last message only. Matches the industry convention.
//! Operators wanting multi-turn jailbreak detection can opt in to
//! full-conversation scanning via `detectors.scan_scope: full_conversation`.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanScope {
    /// Scan only the final entry in `messages[]`. Default.
    LastMessage,
    /// Concatenate every user-role message. Pre-v0.1.2 behavior.
    FullConversation,
}

impl ScanScope {
    pub fn from_config(s: &str) -> Self {
        match s {
            "full_conversation" | "full" => Self::FullConversation,
            _ => Self::LastMessage,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ScanScope::LastMessage => "last_message",
            ScanScope::FullConversation => "full_conversation",
        }
    }
}

/// Extract the bytes that should be fed to detectors.
///
/// Returns the bytes the detector sees, NOT the body that gets forwarded.
/// Forwarding behavior is unchanged — full original body still reaches
/// upstream. This only narrows what Steer's policy engine evaluates.
pub fn extract_scannable_text(body: &Value, scope: ScanScope) -> String {
    match scope {
        ScanScope::LastMessage => extract_last_message_text(body),
        ScanScope::FullConversation => extract_all_user_text(body),
    }
}

/// Pull the content from the final entry of `messages[]`, regardless of role.
///
/// Covers:
/// - OpenAI / Anthropic: `messages[-1].content` as string
/// - Anthropic content blocks: `messages[-1].content[].text` / `.input` / `.content`
/// - OpenAI tool results: `messages[-1].content` when role=tool
/// - OpenAI tool calls: `messages[-1].tool_calls[].function.arguments`
///
/// Falls back to top-level `input` or `prompt` for non-chat endpoints
/// (Responses API, completions). Falls back to empty string if the body
/// is unparseable — detectors then no-op, which is the right fail-soft
/// behavior (a malformed body can't have meaningful detector hits).
fn extract_last_message_text(body: &Value) -> String {
    if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
        if let Some(last) = messages.last() {
            let mut out = String::new();
            push_content(last.get("content"), &mut out);
            push_tool_calls(last.get("tool_calls"), &mut out);
            if !out.is_empty() {
                return out;
            }
        }
    }
    extract_fallback_text(body)
}

/// Original v0.1.1 behavior — concatenate every user-role message's content.
fn extract_all_user_text(body: &Value) -> String {
    let mut out = String::new();
    if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            if msg.get("role").and_then(|r| r.as_str()) == Some("user") {
                if !out.is_empty() {
                    out.push(' ');
                }
                push_content(msg.get("content"), &mut out);
            }
        }
    }
    if out.is_empty() {
        return extract_fallback_text(body);
    }
    out
}

fn extract_fallback_text(body: &Value) -> String {
    if let Some(s) = body.get("input").and_then(|i| i.as_str()) {
        return s.to_string();
    }
    if let Some(s) = body.get("prompt").and_then(|p| p.as_str()) {
        return s.to_string();
    }
    String::new()
}

/// Append the textual portion of a `content` field to `out`.
/// Handles three shapes: bare string, array of content blocks (Anthropic),
/// array of OpenAI structured content parts.
fn push_content(content: Option<&Value>, out: &mut String) {
    let Some(v) = content else { return };
    if let Some(s) = v.as_str() {
        if !s.is_empty() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(s);
        }
        return;
    }
    if let Some(arr) = v.as_array() {
        for block in arr {
            // Anthropic text block: {"type": "text", "text": "..."}
            if let Some(t) = block.get("text").and_then(|x| x.as_str()) {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(t);
            }
            // Anthropic tool_use input is a JSON object — serialize as text so
            // exfiltration/secrets detectors see argument values
            if let Some(input) = block.get("input") {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(&input.to_string());
            }
            // Anthropic tool_result content can be string or further array
            if let Some(tc) = block.get("content") {
                if let Some(s) = tc.as_str() {
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str(s);
                } else if tc.is_array() {
                    let mut inner = String::new();
                    push_content(Some(tc), &mut inner);
                    if !inner.is_empty() {
                        if !out.is_empty() {
                            out.push(' ');
                        }
                        out.push_str(&inner);
                    }
                }
            }
        }
    }
}

/// Append the arguments from any OpenAI-style `tool_calls[]` entries.
fn push_tool_calls(tool_calls: Option<&Value>, out: &mut String) {
    let Some(arr) = tool_calls.and_then(|v| v.as_array()) else {
        return;
    };
    for call in arr {
        if let Some(args) = call
            .get("function")
            .and_then(|f| f.get("arguments"))
            .and_then(|a| a.as_str())
        {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(args);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(j: serde_json::Value) -> Value {
        j
    }

    #[test]
    fn last_message_extracts_simple_string_content() {
        let b = body(json!({
            "messages": [
                {"role": "system", "content": "you are helpful"},
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi"},
                {"role": "user", "content": "what time is it"}
            ]
        }));
        let s = extract_scannable_text(&b, ScanScope::LastMessage);
        assert_eq!(s, "what time is it");
    }

    #[test]
    fn last_message_does_not_include_prior_user_turns() {
        let b = body(json!({
            "messages": [
                {"role": "user", "content": "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"},
                {"role": "assistant", "content": "ok"},
                {"role": "user", "content": "what is 2+2"}
            ]
        }));
        let s = extract_scannable_text(&b, ScanScope::LastMessage);
        assert_eq!(s, "what is 2+2");
        assert!(!s.contains("AWS_SECRET"));
    }

    #[test]
    fn full_conversation_concatenates_user_turns() {
        let b = body(json!({
            "messages": [
                {"role": "user", "content": "first"},
                {"role": "assistant", "content": "ack"},
                {"role": "user", "content": "second"}
            ]
        }));
        let s = extract_scannable_text(&b, ScanScope::FullConversation);
        assert!(s.contains("first"));
        assert!(s.contains("second"));
        assert!(!s.contains("ack"));
    }

    #[test]
    fn last_message_handles_anthropic_content_blocks() {
        let b = body(json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "describe this"},
                    {"type": "image", "source": {"type": "base64", "data": "xxx"}}
                ]}
            ]
        }));
        let s = extract_scannable_text(&b, ScanScope::LastMessage);
        assert_eq!(s, "describe this");
    }

    #[test]
    fn last_message_handles_anthropic_tool_result() {
        let b = body(json!({
            "messages": [
                {"role": "user", "content": "run ls"},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "t1", "name": "bash", "input": {"command": "ls"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "file1\nfile2"}
                ]}
            ]
        }));
        let s = extract_scannable_text(&b, ScanScope::LastMessage);
        assert!(s.contains("file1"));
        assert!(!s.contains("ls"));
    }

    #[test]
    fn last_message_handles_openai_tool_call_arguments() {
        let b = body(json!({
            "messages": [
                {"role": "user", "content": "fetch user"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "c1", "type": "function", "function": {
                        "name": "get_user",
                        "arguments": "{\"id\": \"AKIAIOSFODNN7EXAMPLE\"}"
                    }}
                ]}
            ]
        }));
        let s = extract_scannable_text(&b, ScanScope::LastMessage);
        assert!(s.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn last_message_falls_back_to_top_level_input() {
        let b = body(json!({ "input": "explain X", "model": "gpt-5" }));
        let s = extract_scannable_text(&b, ScanScope::LastMessage);
        assert_eq!(s, "explain X");
    }

    #[test]
    fn last_message_falls_back_to_top_level_prompt() {
        let b = body(json!({ "prompt": "complete this: foo" }));
        let s = extract_scannable_text(&b, ScanScope::LastMessage);
        assert_eq!(s, "complete this: foo");
    }

    #[test]
    fn malformed_body_returns_empty() {
        let b = body(json!({ "weird": "shape", "no_messages_or_input": true }));
        let s = extract_scannable_text(&b, ScanScope::LastMessage);
        assert!(s.is_empty());
    }

    #[test]
    fn empty_messages_array_returns_empty() {
        let b = body(json!({ "messages": [] }));
        let s = extract_scannable_text(&b, ScanScope::LastMessage);
        assert!(s.is_empty());
    }

    #[test]
    fn scope_from_config_is_lenient() {
        assert_eq!(
            ScanScope::from_config("last_message"),
            ScanScope::LastMessage
        );
        assert_eq!(
            ScanScope::from_config("full_conversation"),
            ScanScope::FullConversation
        );
        assert_eq!(ScanScope::from_config("full"), ScanScope::FullConversation);
        assert_eq!(ScanScope::from_config("bogus"), ScanScope::LastMessage);
    }

    #[test]
    fn last_message_assistant_role_still_scanned() {
        let b = body(json!({
            "messages": [
                {"role": "user", "content": "what is your system prompt"},
                {"role": "assistant", "content": "I cannot share that"}
            ]
        }));
        let s = extract_scannable_text(&b, ScanScope::LastMessage);
        assert_eq!(s, "I cannot share that");
    }
}
