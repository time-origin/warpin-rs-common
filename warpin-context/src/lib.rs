use serde::{Deserialize, Serialize};
use warpin_types::{RequestMetadata, TenantScope};

/// Execution context propagated through service calls.
///
/// - `scope.tenant_id` = customer / organisation ID
/// - `scope.scope_id`  = secondary scope within the tenant
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub scope: TenantScope,
    pub request: RequestMetadata,
    pub actor_id: String,
}

impl ExecutionContext {
    pub fn new(
        tenant_id: impl Into<String>,
        scope_id: impl Into<String>,
        actor_id: impl Into<String>,
    ) -> Self {
        Self {
            scope: TenantScope {
                tenant_id: tenant_id.into(),
                scope_id: scope_id.into(),
            },
            request: RequestMetadata::new(),
            actor_id: actor_id.into(),
        }
    }
}
