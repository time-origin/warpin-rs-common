//! Capability registry, policy evaluation, and capability descriptor primitives.
//!
//! This crate provides three small, generic building blocks:
//!
//! - [`CapabilityDescriptor`] — a versioned capability description
//! - [`RegistryClient`] — async trait for resolving capabilities by name
//! - [`PolicyClient`] / [`PolicyDecision`] — async trait for policy evaluation

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Capability Descriptor
// ---------------------------------------------------------------------------

/// Versioned capability descriptor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityDescriptor {
    pub name: String,
    pub version: String,
    pub description: String,
}

impl CapabilityDescriptor {
    /// Returns a `"name:version"` key string.
    pub fn key(&self) -> String {
        format!("{}:{}", self.name, self.version)
    }
}

// ---------------------------------------------------------------------------
// Registry Client
// ---------------------------------------------------------------------------

/// A resolved capability record from the registry.
#[derive(Clone, Debug)]
pub struct CapabilityRecord {
    pub name: String,
    pub version: String,
}

/// Async trait for resolving registered capabilities by name.
#[async_trait]
pub trait RegistryClient: Send + Sync {
    async fn resolve_capability(&self, name: &str) -> Result<Option<CapabilityRecord>>;
}

// ---------------------------------------------------------------------------
// Policy Client
// ---------------------------------------------------------------------------

/// Result of a policy evaluation.
#[derive(Clone, Debug)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
}

/// Async trait for evaluating policies.
#[async_trait]
pub trait PolicyClient: Send + Sync {
    async fn evaluate(&self, policy_name: &str, subject: &str) -> Result<PolicyDecision>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_descriptor_key_format() {
        let desc = CapabilityDescriptor {
            name: "chat".into(),
            version: "1.0".into(),
            description: "Chat capability".into(),
        };
        assert_eq!(desc.key(), "chat:1.0");
    }

    #[test]
    fn policy_decision_variants() {
        let allow = PolicyDecision::Allow;
        let deny = PolicyDecision::Deny("forbidden".into());
        assert!(matches!(allow, PolicyDecision::Allow));
        assert!(matches!(deny, PolicyDecision::Deny(msg) if msg == "forbidden"));
    }
}
