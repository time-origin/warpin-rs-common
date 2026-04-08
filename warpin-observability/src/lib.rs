//! Tracing, observability, and audit infrastructure for the Warpin framework.
//!
//! # Feature Flags
//!
//! - `tracing-init` (default): Basic tracing initialization
//! - `audit-layer`: AuditLayer for capturing audit events from tracing spans
//! - `redaction`: RedactionPolicy trait and GlobalRedaction implementation
//! - `event-bus-sink`: AuditSink trait and EventBusSink for forwarding to event bus
//! - `full`: All features enabled

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[cfg(feature = "audit-layer")]
pub mod layer;

#[cfg(feature = "redaction")]
pub mod redaction;

#[cfg(feature = "event-bus-sink")]
pub mod sink;

/// Initialize tracing with default configuration.
/// Configures an EnvFilter and fmt subscriber.
pub fn init_tracing(service_name: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{service_name}=info,info")));

    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .try_init();
}

/// Initialize tracing with an additional custom layer (e.g., AuditLayer).
///
/// # Example
/// ```ignore
/// use warpin_observability::init_tracing_with_layer;
/// use warpin_observability::layer::AuditLayer;
///
/// let (audit_layer, rx) = AuditLayer::new(1024);
/// init_tracing_with_layer("my-service", audit_layer);
/// ```
#[cfg(feature = "audit-layer")]
pub fn init_tracing_with_layer<L>(service_name: &str, extra_layer: L)
where
    L: tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{service_name}=info,info")));

    let _ = tracing_subscriber::registry()
        .with(extra_layer)
        .with(fmt::layer())
        .with(filter)
        .try_init();
}
