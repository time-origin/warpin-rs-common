use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

/// A fully-resolved model endpoint ready for HTTP dispatch.
///
/// Contains the target URL, pre-built authentication headers, optional
/// model parameter override, extra vendor-specific parameters, a timeout,
/// and an optional fallback endpoint for degradation.
#[derive(Clone, Debug)]
pub struct ResolvedEndpoint {
    /// The full URL to send the request to (e.g. `https://api.openai.com/v1/chat/completions`).
    pub url: String,
    /// Pre-built headers including authentication.
    pub headers: HeaderMap,
    /// If set, overrides the `model` field in the request body.
    pub model_param: Option<String>,
    /// Vendor-specific extra parameters merged into the request body.
    pub extra_params: serde_json::Value,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Optional fallback endpoint used when this endpoint fails.
    pub fallback: Option<Box<ResolvedEndpoint>>,
}

impl ResolvedEndpoint {
    /// Create a minimal endpoint for the given URL with default settings.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: HeaderMap::new(),
            model_param: None,
            extra_params: serde_json::Value::Null,
            timeout_ms: 30_000,
            fallback: None,
        }
    }

    /// Builder helper: set authentication headers from auth_type and credential.
    pub fn with_auth(mut self, auth_type: &str, credential: Option<&str>) -> Self {
        self.headers = build_auth_headers(auth_type, credential);
        self
    }

    /// Builder helper: set model parameter override.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model_param = Some(model.into());
        self
    }

    /// Builder helper: set timeout in milliseconds.
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Builder helper: set fallback endpoint.
    pub fn with_fallback(mut self, fallback: ResolvedEndpoint) -> Self {
        self.fallback = Some(Box::new(fallback));
        self
    }
}

/// Build HTTP headers for the given authentication type.
///
/// Supported `auth_type` values:
/// - `"api_key"` / `"bearer_token"` — sets `Authorization: Bearer {credential}`
/// - `"none"` / `"vpc_whitelist"` — returns empty headers (no auth needed)
/// - `"mtls"` — returns empty headers (TLS layer handles authentication)
/// - anything else — returns empty headers and emits a `tracing::warn`
pub fn build_auth_headers(auth_type: &str, credential: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();

    match auth_type {
        "api_key" | "bearer_token" => {
            if let Some(cred) = credential {
                let value = format!("Bearer {cred}");
                if let Ok(header_value) = HeaderValue::from_str(&value) {
                    headers.insert(AUTHORIZATION, header_value);
                } else {
                    tracing::warn!(
                        auth_type,
                        "credential contains invalid header characters, skipping Authorization header"
                    );
                }
            } else {
                tracing::warn!(
                    auth_type,
                    "auth_type requires a credential but none was provided"
                );
            }
        }
        "none" | "vpc_whitelist" | "mtls" => {
            // No headers needed — auth is handled externally or not required.
        }
        other => {
            tracing::warn!(auth_type = other, "unsupported auth_type, returning empty headers");
        }
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_sets_bearer_header() {
        let headers = build_auth_headers("api_key", Some("sk-test-123"));
        let auth = headers.get(AUTHORIZATION).expect("Authorization header missing");
        assert_eq!(auth.to_str().unwrap(), "Bearer sk-test-123");
    }

    #[test]
    fn bearer_token_sets_bearer_header() {
        let headers = build_auth_headers("bearer_token", Some("tok-abc"));
        let auth = headers.get(AUTHORIZATION).expect("Authorization header missing");
        assert_eq!(auth.to_str().unwrap(), "Bearer tok-abc");
    }

    #[test]
    fn api_key_without_credential_returns_empty() {
        let headers = build_auth_headers("api_key", None);
        assert!(headers.is_empty());
    }

    #[test]
    fn none_auth_returns_empty_headers() {
        let headers = build_auth_headers("none", None);
        assert!(headers.is_empty());
    }

    #[test]
    fn vpc_whitelist_returns_empty_headers() {
        let headers = build_auth_headers("vpc_whitelist", Some("ignored"));
        assert!(headers.is_empty());
    }

    #[test]
    fn mtls_returns_empty_headers() {
        let headers = build_auth_headers("mtls", None);
        assert!(headers.is_empty());
    }

    #[test]
    fn unsupported_auth_type_returns_empty_headers() {
        let headers = build_auth_headers("kerberos", Some("ticket"));
        assert!(headers.is_empty());
    }

    #[test]
    fn resolved_endpoint_builder() {
        let fallback = ResolvedEndpoint::new("https://fallback.example.com/v1/chat");
        let endpoint = ResolvedEndpoint::new("https://api.example.com/v1/chat")
            .with_auth("api_key", Some("sk-123"))
            .with_model("gpt-4o")
            .with_timeout_ms(60_000)
            .with_fallback(fallback);

        assert_eq!(endpoint.url, "https://api.example.com/v1/chat");
        assert_eq!(endpoint.model_param.as_deref(), Some("gpt-4o"));
        assert_eq!(endpoint.timeout_ms, 60_000);
        assert!(endpoint.fallback.is_some());
        assert!(endpoint.headers.get(AUTHORIZATION).is_some());
    }

    #[test]
    fn resolved_endpoint_defaults() {
        let ep = ResolvedEndpoint::new("https://api.example.com");
        assert_eq!(ep.timeout_ms, 30_000);
        assert!(ep.model_param.is_none());
        assert!(ep.fallback.is_none());
        assert!(ep.headers.is_empty());
        assert_eq!(ep.extra_params, serde_json::Value::Null);
    }
}
