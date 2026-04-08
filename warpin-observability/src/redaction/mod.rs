//! Payload redaction for audit events.
//!
//! Two-phase redaction strategy:
//! - **GlobalRedaction**: Mandatory rules applied at Producer side (before Kafka).
//!   Covers API keys, secrets, and long text truncation.
//! - **TenantRedaction**: Optional per-tenant rules applied at Consumer side.
//!   Implemented downstream in the application layer.

use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

/// Trait for applying redaction policies to JSON payloads.
///
/// Implementations should mutate the payload in-place, replacing
/// sensitive values with masked versions.
pub trait RedactionPolicy: Send + Sync {
    /// Apply redaction rules to the given JSON payload.
    fn redact(&self, payload: &mut Value);
}

/// Global redaction rules that are always applied (cannot be disabled).
///
/// Rules:
/// 1. Regex-match API key patterns (sk-*, AKIA*, ghp_*, etc.)
/// 2. Field name blocklist (password, secret, token, credential, authorization)
/// 3. Long text truncation (>4096 chars -> first 4096 + "[TRUNCATED sha256:...]")
pub struct GlobalRedaction {
    key_patterns: Vec<Regex>,
    field_blocklist: Vec<String>,
    max_text_length: usize,
}

// Pre-compiled regex patterns for common API key formats
static DEFAULT_KEY_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"sk-[a-zA-Z0-9]{20,}").unwrap(),
        Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(),
        Regex::new(r"ghp_[a-zA-Z0-9]{36,}").unwrap(),
        Regex::new(r"gho_[a-zA-Z0-9]{36,}").unwrap(),
        Regex::new(r"glpat-[a-zA-Z0-9\-_]{20,}").unwrap(),
        Regex::new(r"xox[bpors]-[a-zA-Z0-9\-]+").unwrap(),
        Regex::new(r"Bearer\s+[a-zA-Z0-9\-_.~+/]+=*").unwrap(),
    ]
});

static DEFAULT_FIELD_BLOCKLIST: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        "password",
        "secret",
        "token",
        "credential",
        "authorization",
        "api_key",
        "apikey",
        "api-key",
        "private_key",
        "access_token",
        "refresh_token",
        "client_secret",
    ]
    .into_iter()
    .map(String::from)
    .collect()
});

impl GlobalRedaction {
    /// Create a GlobalRedaction with default rules.
    pub fn new() -> Self {
        Self {
            key_patterns: DEFAULT_KEY_PATTERNS.clone(),
            field_blocklist: DEFAULT_FIELD_BLOCKLIST.clone(),
            max_text_length: 4096,
        }
    }

    /// Create with custom max text length.
    pub fn with_max_text_length(mut self, max_length: usize) -> Self {
        self.max_text_length = max_length;
        self
    }

    fn is_blocked_field(&self, field_name: &str) -> bool {
        let lower = field_name.to_lowercase();
        self.field_blocklist
            .iter()
            .any(|b| lower.contains(b.as_str()))
    }

    fn redact_string(&self, s: &str) -> Option<String> {
        // Check for API key patterns
        for pattern in &self.key_patterns {
            if pattern.is_match(s) {
                return Some("[REDACTED]".to_string());
            }
        }

        // Truncate long text (UTF-8 safe: find a valid char boundary)
        if s.len() > self.max_text_length {
            use std::fmt::Write;
            // Simple hash for truncation marker
            let hash = simple_fnv_hex(s);
            // Find a valid UTF-8 character boundary at or before max_text_length
            // to prevent panics on multi-byte characters (e.g. Chinese, emoji).
            let mut boundary = self.max_text_length;
            while boundary > 0 && !s.is_char_boundary(boundary) {
                boundary -= 1;
            }
            let mut truncated = String::with_capacity(boundary + 80);
            truncated.push_str(&s[..boundary]);
            write!(truncated, "\n[TRUNCATED fnv1a:{hash}]").ok();
            return Some(truncated);
        }

        None
    }

    fn redact_value(&self, key: &str, value: &mut Value) {
        match value {
            Value::String(s) => {
                if self.is_blocked_field(key) {
                    *value = Value::String("[REDACTED]".to_string());
                } else if let Some(redacted) = self.redact_string(s) {
                    *value = Value::String(redacted);
                }
            }
            Value::Object(map) => {
                let keys: Vec<String> = map.keys().cloned().collect();
                for k in keys {
                    if let Some(v) = map.get_mut(&k) {
                        self.redact_value(&k, v);
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.redact_value(key, item);
                }
            }
            _ => {}
        }
    }
}

impl Default for GlobalRedaction {
    fn default() -> Self {
        Self::new()
    }
}

impl RedactionPolicy for GlobalRedaction {
    fn redact(&self, payload: &mut Value) {
        self.redact_value("", payload);
    }
}

/// Chains multiple redaction policies in order.
pub struct CompositeRedaction {
    policies: Vec<Box<dyn RedactionPolicy>>,
}

impl CompositeRedaction {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn with(mut self, policy: impl RedactionPolicy + 'static) -> Self {
        self.policies.push(Box::new(policy));
        self
    }
}

impl Default for CompositeRedaction {
    fn default() -> Self {
        Self::new()
    }
}

impl RedactionPolicy for CompositeRedaction {
    fn redact(&self, payload: &mut Value) {
        for policy in &self.policies {
            policy.redact(payload);
        }
    }
}

/// Simple FNV-1a hash for truncation markers.
/// Not cryptographic quality, but sufficient for identifying truncated content.
fn simple_fnv_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_global_redaction_api_keys() {
        let redaction = GlobalRedaction::new();
        let mut payload = json!({
            "prompt": "Use key sk-abcdefghijklmnopqrstuvwxyz to authenticate",
            "normal_field": "hello world"
        });
        redaction.redact(&mut payload);
        assert_eq!(payload["prompt"], "[REDACTED]");
        assert_eq!(payload["normal_field"], "hello world");
    }

    #[test]
    fn test_global_redaction_blocked_fields() {
        let redaction = GlobalRedaction::new();
        let mut payload = json!({
            "password": "my-secret-pass",
            "api_key": "some-key",
            "normal": "visible"
        });
        redaction.redact(&mut payload);
        assert_eq!(payload["password"], "[REDACTED]");
        assert_eq!(payload["api_key"], "[REDACTED]");
        assert_eq!(payload["normal"], "visible");
    }

    #[test]
    fn test_global_redaction_long_text() {
        let redaction = GlobalRedaction::new().with_max_text_length(100);
        let long_text = "Hello world! This is a long text. ".repeat(10);
        let mut payload = json!({
            "content": long_text
        });
        redaction.redact(&mut payload);
        let result = payload["content"].as_str().unwrap();
        assert!(result.starts_with("Hello world!"));
        assert!(result.contains("[TRUNCATED fnv1a:"));
        assert!(result.len() < long_text.len());
    }

    #[test]
    fn test_global_redaction_nested() {
        let redaction = GlobalRedaction::new();
        let mut payload = json!({
            "config": {
                "credentials": {
                    "secret": "should-be-redacted",
                    "name": "visible"
                }
            }
        });
        redaction.redact(&mut payload);
        assert_eq!(payload["config"]["credentials"]["secret"], "[REDACTED]");
        assert_eq!(payload["config"]["credentials"]["name"], "visible");
    }

    #[test]
    fn test_composite_redaction() {
        let composite = CompositeRedaction::new().with(GlobalRedaction::new());
        let mut payload = json!({
            "password": "secret123",
            "data": "normal"
        });
        composite.redact(&mut payload);
        assert_eq!(payload["password"], "[REDACTED]");
        assert_eq!(payload["data"], "normal");
    }

    #[test]
    fn test_aws_key_redaction() {
        let redaction = GlobalRedaction::new();
        let mut payload = json!({
            "key": "AKIAIOSFODNN7EXAMPLE"
        });
        redaction.redact(&mut payload);
        assert_eq!(payload["key"], "[REDACTED]");
    }

    #[test]
    fn test_global_redaction_long_text_multibyte_utf8() {
        // Chinese characters are 3 bytes each.  With max_text_length=5, the byte
        // index 5 falls in the middle of the second character (bytes 3..6).
        // The truncation must find a valid char boundary (byte 3) instead of
        // panicking with a byte-index slice.
        let redaction = GlobalRedaction::new().with_max_text_length(5);
        let chinese_text = "你好世界测试数据很长的中文文本"; // each char = 3 bytes
        let mut payload = json!({
            "content": chinese_text
        });
        redaction.redact(&mut payload);
        let result = payload["content"].as_str().unwrap();
        assert!(result.contains("[TRUNCATED fnv1a:"));
        // Should not panic and should contain valid UTF-8
        assert!(result.starts_with("你")); // at least the first char is preserved
    }

    #[test]
    fn test_github_token_redaction() {
        let redaction = GlobalRedaction::new();
        let mut payload = json!({
            "token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        });
        redaction.redact(&mut payload);
        assert_eq!(payload["token"], "[REDACTED]");
    }
}
