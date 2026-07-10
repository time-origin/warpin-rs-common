use anyhow::{Result, anyhow};
use serde_json::{Value, json};

/// Trait for adapting between a generic JSON request/response and a
/// vendor-specific API format.
///
/// Implementations convert a unified `serde_json::Value` request into the
/// vendor's expected JSON body and parse the vendor's JSON response back
/// into a unified shape.  Using `serde_json::Value` keeps this crate free
/// from domain-specific type dependencies.
pub trait ApiAdapter: Send + Sync {
    /// Human-readable name of the API format (e.g. `"openai_compatible"`).
    fn api_format(&self) -> &str;

    /// Transform a unified request JSON into the vendor-specific request body.
    fn adapt_request(&self, request: &Value) -> Value;

    /// Parse a vendor-specific response JSON into a unified response shape.
    fn adapt_response(&self, response: &Value) -> Result<Value>;
}

/// Adapter for OpenAI-compatible APIs (OpenAI, Azure OpenAI, DeepSeek,
/// Moonshot, Zhipu GLM, StellarForge, and other compatible providers).
///
/// Handles two request families:
/// - **Chat completion** — detected by the presence of a `messages` field.
/// - **Image generation** — detected by the absence of `messages` and
///   presence of a `prompt` field.
#[derive(Debug, Clone, Default)]
pub struct OpenAICompatibleAdapter;

impl OpenAICompatibleAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Detect whether the input is a chat-completion or image-generation request.
    fn is_chat_request(request: &Value) -> bool {
        request.get("messages").is_some()
    }

    // ── Chat completion helpers ─────────────────────────────────────

    fn adapt_chat_request(&self, request: &Value) -> Value {
        let mut body = json!({});

        // Required
        if let Some(messages) = request.get("messages") {
            body["messages"] = messages.clone();
        }

        // Model (optional — may be overridden by ResolvedEndpoint.model_param)
        if let Some(model) = request.get("model") {
            body["model"] = model.clone();
        }

        // Optional scalar parameters
        for key in &[
            "temperature",
            "max_tokens",
            "top_p",
            "frequency_penalty",
            "presence_penalty",
            "stop",
            "stream",
            "response_format",
        ] {
            if let Some(v) = request.get(*key) {
                body[*key] = v.clone();
            }
        }

        // Tools / function calling
        if let Some(tools) = request.get("tools") {
            body["tools"] = tools.clone();
        }
        if let Some(tc) = request.get("tool_choice") {
            body["tool_choice"] = tc.clone();
        }

        body
    }

    fn adapt_chat_response(&self, response: &Value) -> Result<Value> {
        // Extract content from choices[0].message.content
        let content = response
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();

        let model = response
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();

        let finish_reason = response
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
            .map(String::from);

        let tool_calls = response.pointer("/choices/0/message/tool_calls").cloned();

        let usage = response.get("usage").cloned();

        let mut result = json!({
            "content": content,
            "model": model,
        });

        if let Some(fr) = finish_reason {
            result["finish_reason"] = json!(fr);
        }
        if let Some(tc) = tool_calls {
            result["tool_calls"] = tc;
        }
        if let Some(u) = usage {
            result["usage"] = u;
        }

        Ok(result)
    }

    // ── Image generation helpers ────────────────────────────────────

    fn adapt_image_request(&self, request: &Value) -> Value {
        let mut body = json!({});

        if let Some(model) = request.get("model") {
            body["model"] = model.clone();
        }

        for key in &[
            "prompt",
            "negative_prompt",
            "size",
            "quality",
            "n",
            "response_format",
            "style",
        ] {
            if let Some(v) = request.get(*key) {
                body[*key] = v.clone();
            }
        }

        // Map width/height into "size" if not already present
        if body.get("size").is_none()
            && let (Some(w), Some(h)) = (request.get("width"), request.get("height"))
            && let (Some(w), Some(h)) = (w.as_u64(), h.as_u64())
        {
            body["size"] = json!(format!("{w}x{h}"));
        }

        // Vendor-specific extra params
        if let Some(extra) = request.get("image_params")
            && let Some(obj) = extra.as_object()
        {
            for (k, v) in obj {
                body[k.clone()] = v.clone();
            }
        }

        body
    }

    fn adapt_image_response(&self, response: &Value) -> Result<Value> {
        // Try data[0].url first, then data[0].b64_json
        let image_url = response
            .pointer("/data/0/url")
            .and_then(Value::as_str)
            .map(String::from);

        let image_b64 = response
            .pointer("/data/0/b64_json")
            .and_then(Value::as_str)
            .map(String::from);

        if image_url.is_none() && image_b64.is_none() {
            return Err(anyhow!(
                "image generation response missing both data[0].url and data[0].b64_json"
            ));
        }

        let model = response
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();

        let mut result = json!({
            "model": model,
            "content": "",
        });

        if let Some(url) = image_url {
            result["image_url"] = json!(url);
        }
        if let Some(b64) = image_b64 {
            result["image_b64"] = json!(b64);
        }

        Ok(result)
    }
}

impl ApiAdapter for OpenAICompatibleAdapter {
    fn api_format(&self) -> &str {
        "openai_compatible"
    }

    fn adapt_request(&self, request: &Value) -> Value {
        if Self::is_chat_request(request) {
            self.adapt_chat_request(request)
        } else {
            self.adapt_image_request(request)
        }
    }

    fn adapt_response(&self, response: &Value) -> Result<Value> {
        // Detect whether this is a chat or image response based on structure.
        // Chat responses have "choices", image responses have "data".
        if response.get("choices").is_some() {
            self.adapt_chat_response(response)
        } else if response.get("data").is_some() {
            self.adapt_image_response(response)
        } else {
            Err(anyhow!(
                "unrecognized response format: missing both 'choices' and 'data' keys"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> OpenAICompatibleAdapter {
        OpenAICompatibleAdapter::new()
    }

    // ── Chat completion tests ───────────────────────────────────────

    #[test]
    fn chat_request_adapts_messages_and_params() {
        let input = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello"}
            ],
            "temperature": 0.7,
            "max_tokens": 1024
        });

        let body = adapter().adapt_request(&input);

        assert_eq!(body["model"], "gpt-4o");
        assert!(body["messages"].is_array());
        assert_eq!(body["messages"].as_array().unwrap().len(), 2);
        assert_eq!(body["temperature"], 0.7);
        assert_eq!(body["max_tokens"], 1024);
    }

    #[test]
    fn chat_request_includes_tools() {
        let input = json!({
            "messages": [{"role": "user", "content": "weather?"}],
            "tools": [{"type": "function", "function": {"name": "get_weather"}}],
            "tool_choice": "auto"
        });

        let body = adapter().adapt_request(&input);
        assert!(body["tools"].is_array());
        assert_eq!(body["tool_choice"], "auto");
    }

    #[test]
    fn chat_response_extracts_content() {
        let response = json!({
            "id": "chatcmpl-123",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hello!"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15
            }
        });

        let result = adapter().adapt_response(&response).unwrap();
        assert_eq!(result["content"], "Hello!");
        assert_eq!(result["model"], "gpt-4o");
        assert_eq!(result["finish_reason"], "stop");
        assert_eq!(result["usage"]["total_tokens"], 15);
    }

    #[test]
    fn chat_response_extracts_tool_calls() {
        let response = json!({
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{}"}}]
                },
                "finish_reason": "tool_calls"
            }]
        });

        let result = adapter().adapt_response(&response).unwrap();
        assert!(result["tool_calls"].is_array());
        assert_eq!(result["content"], "");
    }

    // ── Image generation tests ──────────────────────────────────────

    #[test]
    fn image_request_adapts_prompt_and_params() {
        let input = json!({
            "model": "dall-e-3",
            "prompt": "A sunset over mountains",
            "size": "1024x1024",
            "quality": "hd"
        });

        let body = adapter().adapt_request(&input);
        assert_eq!(body["model"], "dall-e-3");
        assert_eq!(body["prompt"], "A sunset over mountains");
        assert_eq!(body["size"], "1024x1024");
        assert_eq!(body["quality"], "hd");
        // No messages key
        assert!(body.get("messages").is_none());
    }

    #[test]
    fn image_request_builds_size_from_width_height() {
        let input = json!({
            "prompt": "A cat",
            "width": 512,
            "height": 768
        });

        let body = adapter().adapt_request(&input);
        assert_eq!(body["size"], "512x768");
    }

    #[test]
    fn image_request_merges_image_params() {
        let input = json!({
            "prompt": "A dog",
            "image_params": {
                "steps": 50,
                "cfg_scale": 7.5
            }
        });

        let body = adapter().adapt_request(&input);
        assert_eq!(body["steps"], 50);
        assert_eq!(body["cfg_scale"], 7.5);
    }

    #[test]
    fn image_response_extracts_url() {
        let response = json!({
            "model": "dall-e-3",
            "data": [{
                "url": "https://images.example.com/abc.png",
                "revised_prompt": "A beautiful sunset"
            }]
        });

        let result = adapter().adapt_response(&response).unwrap();
        assert_eq!(result["image_url"], "https://images.example.com/abc.png");
        assert_eq!(result["model"], "dall-e-3");
    }

    #[test]
    fn image_response_extracts_b64() {
        let response = json!({
            "data": [{
                "b64_json": "iVBORw0KGgo..."
            }]
        });

        let result = adapter().adapt_response(&response).unwrap();
        assert_eq!(result["image_b64"], "iVBORw0KGgo...");
    }

    #[test]
    fn image_response_missing_data_returns_error() {
        let response = json!({
            "data": [{}]
        });

        let result = adapter().adapt_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn unrecognized_response_returns_error() {
        let response = json!({"status": "ok"});
        let result = adapter().adapt_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn api_format_returns_correct_name() {
        assert_eq!(adapter().api_format(), "openai_compatible");
    }
}
