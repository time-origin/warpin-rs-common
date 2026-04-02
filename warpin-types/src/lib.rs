use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Multi-dimensional scope for request context.
///
/// - `tenant_id` = Top-level customer / organisation identifier
/// - `scope_id`  = Secondary scope within the tenant (e.g. ground-station,
///   workspace, business-unit — interpretation is project-specific)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantScope {
    pub tenant_id: String,
    pub scope_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestMetadata {
    pub request_id: Uuid,
    pub timestamp: DateTime<Utc>,
}

impl RequestMetadata {
    pub fn new() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            timestamp: Utc::now(),
        }
    }
}

impl Default for RequestMetadata {
    fn default() -> Self {
        Self::new()
    }
}
