use std::time::Duration;

use anyhow::{Result, anyhow};
use reqwest::Client;
use serde_json::Value;

use crate::endpoint::ResolvedEndpoint;

/// Classifies endpoint errors into retryable (worth falling back) and
/// non-retryable (request itself is broken).
#[derive(Debug, thiserror::Error)]
pub(crate) enum EndpointError {
    /// Network errors, timeouts, 429, 5xx -- try the next endpoint.
    #[error("{0}")]
    Retryable(String),
    /// 400, 401, 403, 404, 422, etc. -- fallback would not help.
    #[error("{0}")]
    NonRetryable(String),
}

/// Maximum number of fallback hops before giving up.
const MAX_FALLBACK_DEPTH: usize = 3;

/// Returns `true` for HTTP status codes that justify retrying on a
/// fallback endpoint (server errors, rate-limiting, timeouts).
/// Client errors (4xx except 408/429) indicate a problem with the
/// request itself, so retrying on a different endpoint would not help.
pub(crate) fn is_retryable_status(code: u16) -> bool {
    matches!(code, 408 | 429 | 500 | 502 | 503 | 504)
}

/// HTTP client that dispatches requests to a [`ResolvedEndpoint`],
/// automatically falling back along the endpoint's degradation chain
/// on failure.
#[derive(Clone, Debug)]
pub struct EndpointClient {
    http: Client,
}

impl Default for EndpointClient {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointClient {
    /// Create a new client backed by a default `reqwest::Client`.
    pub fn new() -> Self {
        Self {
            http: Client::new(),
        }
    }

    /// Create a client wrapping an existing `reqwest::Client` (useful for
    /// connection pooling or custom TLS configuration).
    pub fn with_client(http: Client) -> Self {
        Self { http }
    }

    /// Send `body` as a JSON POST to `endpoint`.
    ///
    /// On failure the client walks the endpoint's fallback chain, retrying
    /// up to [`MAX_FALLBACK_DEPTH`] times.  Each degradation emits a
    /// `tracing::warn`.
    pub async fn call(&self, endpoint: &ResolvedEndpoint, body: Value) -> Result<Value> {
        let mut current = endpoint;
        let mut depth: usize = 0;
        let mut last_error: anyhow::Error = anyhow!("endpoint call failed with no attempts made");

        loop {
            match self.send_once(current, &body).await {
                Ok(value) => return Ok(value),
                Err(err) => {
                    // Non-retryable errors (client 4xx except 408/429)
                    // should not trigger fallback — the request itself
                    // is the problem, not the endpoint.
                    if err
                        .downcast_ref::<EndpointError>()
                        .is_some_and(|e| matches!(e, EndpointError::NonRetryable(_)))
                    {
                        return Err(err);
                    }

                    last_error = err;

                    depth += 1;
                    if depth > MAX_FALLBACK_DEPTH {
                        break;
                    }

                    if let Some(ref fb) = current.fallback {
                        tracing::warn!(
                            from_url = %current.url,
                            to_url = %fb.url,
                            depth,
                            "endpoint call failed, falling back to next endpoint"
                        );
                        current = fb;
                    } else {
                        break;
                    }
                }
            }
        }

        Err(last_error)
    }

    /// Execute a single POST request (no fallback logic).
    ///
    /// Merges `endpoint.model_param` and `endpoint.extra_params` into a
    /// clone of the request body before sending.  Existing keys in `body`
    /// are never overwritten by `extra_params`.
    async fn send_once(&self, endpoint: &ResolvedEndpoint, body: &Value) -> Result<Value> {
        let timeout = Duration::from_millis(endpoint.timeout_ms);

        let merged_body = merge_endpoint_params(endpoint, body);

        let response = self
            .http
            .post(&endpoint.url)
            .headers(endpoint.headers.clone())
            .header("Content-Type", "application/json")
            .timeout(timeout)
            .json(&merged_body)
            .send()
            .await
            .map_err(|e| {
                // Network-level failures (DNS, connect, timeout) are
                // always retryable — the endpoint may be temporarily
                // unreachable while a fallback is healthy.
                let msg = format!("HTTP request to {} failed: {e}", endpoint.url);
                anyhow::Error::new(EndpointError::Retryable(msg))
            })?;

        let status = response.status();
        let response_body: Value = response
            .json()
            .await
            .map_err(|e| anyhow!("failed to parse JSON response from {}: {e}", endpoint.url))?;

        if !status.is_success() {
            let error_message = response_body
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            let msg = format!(
                "endpoint {} returned HTTP {status}: {error_message}",
                endpoint.url
            );
            if is_retryable_status(status.as_u16()) {
                return Err(EndpointError::Retryable(msg).into());
            }
            return Err(EndpointError::NonRetryable(msg).into());
        }

        Ok(response_body)
    }
}

/// Merge endpoint-level `model_param` and `extra_params` into a clone
/// of the request body.  Keys already present in `body` are never
/// overwritten by `extra_params`.
fn merge_endpoint_params(endpoint: &ResolvedEndpoint, body: &Value) -> Value {
    let mut merged = body.clone();

    // Ensure top-level is an object so we can insert keys.
    let obj = match merged.as_object_mut() {
        Some(o) => o,
        None => return merged,
    };

    // Override or inject the `model` field.
    if let Some(ref model) = endpoint.model_param {
        obj.insert("model".to_owned(), Value::String(model.clone()));
    }

    // Merge extra_params (body-existing keys win).
    if let Some(extras) = endpoint.extra_params.as_object() {
        for (k, v) in extras {
            obj.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::ResolvedEndpoint;

    #[test]
    fn client_default_creates_successfully() {
        let client = EndpointClient::new();
        // Smoke test: the client should be constructible.
        let _ = format!("{client:?}");
    }

    #[test]
    fn max_fallback_depth_is_three() {
        assert_eq!(MAX_FALLBACK_DEPTH, 3);
    }

    #[test]
    fn endpoint_fallback_chain_depth() {
        // Build a 4-deep chain: primary -> fb1 -> fb2 -> fb3
        let fb3 = ResolvedEndpoint::new("https://fb3.example.com");
        let fb2 = ResolvedEndpoint::new("https://fb2.example.com").with_fallback(fb3);
        let fb1 = ResolvedEndpoint::new("https://fb1.example.com").with_fallback(fb2);
        let primary = ResolvedEndpoint::new("https://primary.example.com").with_fallback(fb1);

        // Verify the chain is linked correctly
        let first_fb = primary.fallback.as_ref().unwrap();
        assert_eq!(first_fb.url, "https://fb1.example.com");

        let second_fb = first_fb.fallback.as_ref().unwrap();
        assert_eq!(second_fb.url, "https://fb2.example.com");

        let third_fb = second_fb.fallback.as_ref().unwrap();
        assert_eq!(third_fb.url, "https://fb3.example.com");

        assert!(third_fb.fallback.is_none());
    }

    #[tokio::test]
    async fn call_to_unreachable_host_returns_error() {
        let client = EndpointClient::new();
        let endpoint = ResolvedEndpoint::new("http://127.0.0.1:1").with_timeout_ms(500);

        let result = client
            .call(&endpoint, serde_json::json!({"test": true}))
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn call_exhausts_fallback_chain_on_failure() {
        let client = EndpointClient::new();

        let fb = ResolvedEndpoint::new("http://127.0.0.1:1").with_timeout_ms(500);
        let primary = ResolvedEndpoint::new("http://127.0.0.1:1")
            .with_timeout_ms(500)
            .with_fallback(fb);

        let result = client
            .call(&primary, serde_json::json!({"test": true}))
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn with_client_wraps_existing() {
        let reqwest_client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap();
        let client = EndpointClient::with_client(reqwest_client);
        let _ = format!("{client:?}");
    }

    // ── merge_endpoint_params tests ────────────────────────────────

    #[test]
    fn test_model_param_merged_into_body() {
        let endpoint = ResolvedEndpoint::new("https://api.example.com").with_model("gpt-4o");
        let body = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});

        let merged = merge_endpoint_params(&endpoint, &body);

        assert_eq!(merged["model"], "gpt-4o");
        // Original messages preserved.
        assert!(merged["messages"].is_array());
    }

    #[test]
    fn test_extra_params_merged_into_body() {
        let mut endpoint = ResolvedEndpoint::new("https://api.example.com");
        endpoint.extra_params = serde_json::json!({
            "temperature": 0.7,
            "top_p": 0.9
        });

        let body = serde_json::json!({"messages": []});
        let merged = merge_endpoint_params(&endpoint, &body);

        assert_eq!(merged["temperature"], 0.7);
        assert_eq!(merged["top_p"], 0.9);
    }

    #[test]
    fn test_body_keys_not_overridden_by_extra_params() {
        let mut endpoint = ResolvedEndpoint::new("https://api.example.com");
        endpoint.extra_params = serde_json::json!({
            "temperature": 0.7,
            "max_tokens": 100
        });

        // Body already has temperature -- it must not be overwritten.
        let body = serde_json::json!({
            "temperature": 0.3,
            "messages": []
        });
        let merged = merge_endpoint_params(&endpoint, &body);

        assert_eq!(
            merged["temperature"], 0.3,
            "body key must not be overridden"
        );
        assert_eq!(
            merged["max_tokens"], 100,
            "new key from extra_params must appear"
        );
    }

    #[test]
    fn test_fallback_uses_its_own_model_param() {
        let fallback =
            ResolvedEndpoint::new("https://fallback.example.com").with_model("gpt-3.5-turbo");
        let primary = ResolvedEndpoint::new("https://primary.example.com")
            .with_model("gpt-4o")
            .with_fallback(fallback);

        let body = serde_json::json!({"messages": []});

        // Primary endpoint should inject its own model.
        let merged_primary = merge_endpoint_params(&primary, &body);
        assert_eq!(merged_primary["model"], "gpt-4o");

        // Fallback endpoint should inject its own model.
        let fb = primary.fallback.as_ref().unwrap();
        let merged_fallback = merge_endpoint_params(fb, &body);
        assert_eq!(merged_fallback["model"], "gpt-3.5-turbo");
    }

    // ── is_retryable_status tests ─────────────────────────────────

    #[test]
    fn test_400_does_not_trigger_fallback() {
        assert!(
            !is_retryable_status(400),
            "400 Bad Request must not be retryable"
        );
    }

    #[test]
    fn test_401_does_not_trigger_fallback() {
        assert!(
            !is_retryable_status(401),
            "401 Unauthorized must not be retryable"
        );
    }

    #[test]
    fn test_403_does_not_trigger_fallback() {
        assert!(
            !is_retryable_status(403),
            "403 Forbidden must not be retryable"
        );
    }

    #[test]
    fn test_404_does_not_trigger_fallback() {
        assert!(
            !is_retryable_status(404),
            "404 Not Found must not be retryable"
        );
    }

    #[test]
    fn test_422_does_not_trigger_fallback() {
        assert!(
            !is_retryable_status(422),
            "422 Unprocessable Entity must not be retryable"
        );
    }

    #[test]
    fn test_429_triggers_fallback() {
        assert!(
            is_retryable_status(429),
            "429 Too Many Requests must be retryable"
        );
    }

    #[test]
    fn test_500_triggers_fallback() {
        assert!(
            is_retryable_status(500),
            "500 Internal Server Error must be retryable"
        );
    }

    #[test]
    fn test_502_triggers_fallback() {
        assert!(
            is_retryable_status(502),
            "502 Bad Gateway must be retryable"
        );
    }

    #[test]
    fn test_503_triggers_fallback() {
        assert!(
            is_retryable_status(503),
            "503 Service Unavailable must be retryable"
        );
    }

    #[test]
    fn test_504_triggers_fallback() {
        assert!(
            is_retryable_status(504),
            "504 Gateway Timeout must be retryable"
        );
    }

    #[test]
    fn test_408_triggers_fallback() {
        assert!(
            is_retryable_status(408),
            "408 Request Timeout must be retryable"
        );
    }
}
