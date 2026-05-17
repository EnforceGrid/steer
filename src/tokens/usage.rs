use serde::{Deserialize, Serialize};

/// Token usage extracted from an LLM response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
    pub model: String,
    pub provider: String,
}

/// Parse token usage from an OpenAI-shaped response JSON.
///
/// Expects:
/// ```json
/// { "model": "...", "usage": { "prompt_tokens": N, "completion_tokens": N, "total_tokens": N } }
/// ```
pub fn parse_openai_usage(body: &serde_json::Value) -> Option<TokenUsage> {
    let usage = body.get("usage")?;
    let prompt_tokens = usage.get("prompt_tokens")?.as_u64()? as u32;
    let completion_tokens = usage.get("completion_tokens")?.as_u64()? as u32;
    let total_tokens = usage.get("total_tokens")?.as_u64()? as u32;
    let model = body.get("model")?.as_str()?.to_string();

    Some(TokenUsage {
        prompt_tokens,
        completion_tokens,
        total_tokens,
        model,
        provider: "openai".to_string(),
    })
}

/// Parse token usage from an Anthropic-shaped response JSON.
///
/// Expects:
/// ```json
/// { "model": "...", "usage": { "input_tokens": N, "output_tokens": N } }
/// ```
pub fn parse_anthropic_usage(body: &serde_json::Value) -> Option<TokenUsage> {
    let usage = body.get("usage")?;
    let input_tokens = usage.get("input_tokens")?.as_u64()? as u32;
    let output_tokens = usage.get("output_tokens")?.as_u64()? as u32;
    let total_tokens = input_tokens + output_tokens;
    let model = body.get("model")?.as_str()?.to_string();

    Some(TokenUsage {
        prompt_tokens: input_tokens,
        completion_tokens: output_tokens,
        total_tokens,
        model,
        provider: "anthropic".to_string(),
    })
}

/// Dispatch to the appropriate parser based on `provider`.
///
/// Supported providers: `"openai"` and `"anthropic"`.
/// Returns `None` for unknown providers or missing fields.
pub fn parse_usage(body: &serde_json::Value, provider: &str) -> Option<TokenUsage> {
    match provider {
        "openai" => parse_openai_usage(body),
        "anthropic" => parse_anthropic_usage(body),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn openai_response() -> serde_json::Value {
        json!({
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "message": { "role": "assistant", "content": "Hello!" },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        })
    }

    fn anthropic_response() -> serde_json::Value {
        json!({
            "id": "msg_01abc",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-5-sonnet-20241022",
            "content": [{ "type": "text", "text": "Hello!" }],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 80,
                "output_tokens": 40
            }
        })
    }

    #[test]
    fn parse_openai_usage_happy_path() {
        let body = openai_response();
        let usage = parse_openai_usage(&body).expect("should parse");
        assert_eq!(usage.prompt_tokens, 100);
        assert_eq!(usage.completion_tokens, 50);
        assert_eq!(usage.total_tokens, 150);
        assert_eq!(usage.model, "gpt-4o");
        assert_eq!(usage.provider, "openai");
    }

    #[test]
    fn parse_openai_usage_missing_usage_field_returns_none() {
        let body = json!({ "model": "gpt-4o" });
        assert!(parse_openai_usage(&body).is_none());
    }

    #[test]
    fn parse_openai_usage_missing_model_returns_none() {
        let body = json!({
            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
        });
        assert!(parse_openai_usage(&body).is_none());
    }

    #[test]
    fn parse_anthropic_usage_happy_path() {
        let body = anthropic_response();
        let usage = parse_anthropic_usage(&body).expect("should parse");
        assert_eq!(usage.prompt_tokens, 80);
        assert_eq!(usage.completion_tokens, 40);
        assert_eq!(usage.total_tokens, 120);
        assert_eq!(usage.model, "claude-3-5-sonnet-20241022");
        assert_eq!(usage.provider, "anthropic");
    }

    #[test]
    fn parse_anthropic_usage_total_is_sum() {
        let body = json!({
            "model": "claude-3-haiku-20240307",
            "usage": { "input_tokens": 200, "output_tokens": 75 }
        });
        let usage = parse_anthropic_usage(&body).expect("should parse");
        assert_eq!(usage.total_tokens, 275);
    }

    #[test]
    fn parse_anthropic_usage_missing_field_returns_none() {
        let body = json!({ "model": "claude-3-5-sonnet-20241022" });
        assert!(parse_anthropic_usage(&body).is_none());
    }

    #[test]
    fn parse_usage_dispatches_openai() {
        let body = openai_response();
        let usage = parse_usage(&body, "openai").expect("should parse");
        assert_eq!(usage.provider, "openai");
        assert_eq!(usage.prompt_tokens, 100);
    }

    #[test]
    fn parse_usage_dispatches_anthropic() {
        let body = anthropic_response();
        let usage = parse_usage(&body, "anthropic").expect("should parse");
        assert_eq!(usage.provider, "anthropic");
        assert_eq!(usage.prompt_tokens, 80);
    }

    #[test]
    fn parse_usage_unknown_provider_returns_none() {
        let body = openai_response();
        assert!(parse_usage(&body, "gemini").is_none());
        assert!(parse_usage(&body, "").is_none());
    }

    #[test]
    fn parse_openai_usage_mini_model() {
        let body = json!({
            "model": "gpt-4o-mini",
            "usage": {
                "prompt_tokens": 500,
                "completion_tokens": 200,
                "total_tokens": 700
            }
        });
        let usage = parse_openai_usage(&body).expect("should parse");
        assert_eq!(usage.model, "gpt-4o-mini");
        assert_eq!(usage.total_tokens, 700);
    }

    #[test]
    fn parse_anthropic_usage_zero_tokens() {
        let body = json!({
            "model": "claude-3-haiku-20240307",
            "usage": { "input_tokens": 0, "output_tokens": 0 }
        });
        let usage = parse_anthropic_usage(&body).expect("should parse");
        assert_eq!(usage.total_tokens, 0);
    }
}
