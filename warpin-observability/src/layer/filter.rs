//! Audit-specific event filter.

use tracing_subscriber::layer::Filter;

/// Filter that only passes events with `target = "audit"`.
pub struct AuditFilter;

impl<S> Filter<S> for AuditFilter {
    fn enabled(
        &self,
        meta: &tracing::Metadata<'_>,
        _cx: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        meta.target() == "audit"
    }
}
