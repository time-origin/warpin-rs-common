//! Audit event capture layer for tracing.
//!
//! `AuditLayer` is a `tracing_subscriber::Layer` that captures events with
//! `target = "audit"` and forwards them through a bounded channel.

pub mod filter;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;

/// A structured audit record extracted from a tracing event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Timestamp in RFC 3339 format
    pub timestamp: String,
    /// The audit event type (e.g., "trace.started", "span.completed", "tool.invoked")
    pub event_type: String,
    /// Extracted key-value fields from the tracing event
    pub fields: HashMap<String, serde_json::Value>,
    /// Span context: tenant_id, scope_id, actor_id, request_id if available
    pub span_context: SpanContext,
}

/// Context extracted from the current tracing span.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpanContext {
    pub tenant_id: Option<String>,
    pub scope_id: Option<String>,
    pub actor_id: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
}

/// Tracing layer that captures `target = "audit"` events and sends them
/// through a bounded MPSC channel.
///
/// When the channel is full, events are dropped and a metric counter is incremented.
pub struct AuditLayer {
    tx: mpsc::Sender<AuditRecord>,
}

impl AuditLayer {
    /// Create a new AuditLayer with the given channel capacity.
    ///
    /// Returns the layer and a receiver for consuming audit records.
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<AuditRecord>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    /// Get a clone of the sender (useful for testing or manual injection).
    pub fn sender(&self) -> mpsc::Sender<AuditRecord> {
        self.tx.clone()
    }
}

/// Visitor that extracts fields from a tracing event into a HashMap.
struct AuditVisitor {
    fields: HashMap<String, serde_json::Value>,
    event_type: Option<String>,
}

impl AuditVisitor {
    fn new() -> Self {
        Self {
            fields: HashMap::new(),
            event_type: None,
        }
    }
}

impl Visit for AuditVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        if name == "event_type" {
            self.event_type = Some(format!("{:?}", value).trim_matches('"').to_string());
        } else if name != "message" {
            self.fields.insert(
                name.to_string(),
                serde_json::Value::String(format!("{:?}", value).trim_matches('"').to_string()),
            );
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let name = field.name();
        if name == "event_type" {
            self.event_type = Some(value.to_string());
        } else {
            self.fields.insert(
                name.to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if let Some(n) = serde_json::Number::from_f64(value) {
            self.fields
                .insert(field.name().to_string(), serde_json::Value::Number(n));
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }
}

/// Storage for span context data, attached via tracing Extensions.
#[derive(Debug, Clone)]
pub struct AuditSpanData {
    pub tenant_id: Option<String>,
    pub scope_id: Option<String>,
    pub actor_id: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
}

impl<S> Layer<S> for AuditLayer
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Only capture events targeted at "audit"
        if event.metadata().target() != "audit" {
            return;
        }

        // Extract fields from the event
        let mut visitor = AuditVisitor::new();
        event.record(&mut visitor);

        // Extract span context from the current span chain (walk up to find context)
        let span_context = {
            let mut context = SpanContext::default();
            let mut current_span = ctx.event_span(event);
            while let Some(span) = current_span {
                let extensions = span.extensions();
                if let Some(data) = extensions.get::<AuditSpanData>() {
                    if context.tenant_id.is_none() {
                        context.tenant_id = data.tenant_id.clone();
                    }
                    if context.scope_id.is_none() {
                        context.scope_id = data.scope_id.clone();
                    }
                    if context.actor_id.is_none() {
                        context.actor_id = data.actor_id.clone();
                    }
                    if context.request_id.is_none() {
                        context.request_id = data.request_id.clone();
                    }
                    if context.trace_id.is_none() {
                        context.trace_id = data.trace_id.clone();
                    }
                    // If all filled, stop
                    if context.tenant_id.is_some()
                        && context.scope_id.is_some()
                        && context.actor_id.is_some()
                        && context.request_id.is_some()
                        && context.trace_id.is_some()
                    {
                        break;
                    }
                }
                drop(extensions);
                current_span = span.parent();
            }
            context
        };

        let record = AuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: visitor.event_type.unwrap_or_else(|| "unknown".to_string()),
            fields: visitor.fields,
            span_context,
        };

        // Try to send; if channel is full, increment drop counter
        if self.tx.try_send(record).is_err() {
            metrics::counter!("audit_events_dropped").increment(1);
        }
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // Auto-inject span context from attributes
        let mut visitor = AuditVisitor::new();
        attrs.record(&mut visitor);

        let mut span_data = AuditSpanData {
            tenant_id: visitor
                .fields
                .get("tenant_id")
                .and_then(|v| v.as_str().map(String::from)),
            scope_id: visitor
                .fields
                .get("scope_id")
                .and_then(|v| v.as_str().map(String::from)),
            actor_id: visitor
                .fields
                .get("actor_id")
                .and_then(|v| v.as_str().map(String::from)),
            request_id: visitor
                .fields
                .get("request_id")
                .and_then(|v| v.as_str().map(String::from)),
            trace_id: visitor
                .fields
                .get("trace_id")
                .and_then(|v| v.as_str().map(String::from)),
        };

        // Inherit missing fields from parent span chain
        if let Some(span) = ctx.span(id) {
            let mut current = span.parent();
            while let Some(parent) = current {
                let extensions = parent.extensions();
                if let Some(parent_data) = extensions.get::<AuditSpanData>() {
                    if span_data.tenant_id.is_none() {
                        span_data.tenant_id = parent_data.tenant_id.clone();
                    }
                    if span_data.scope_id.is_none() {
                        span_data.scope_id = parent_data.scope_id.clone();
                    }
                    if span_data.actor_id.is_none() {
                        span_data.actor_id = parent_data.actor_id.clone();
                    }
                    if span_data.request_id.is_none() {
                        span_data.request_id = parent_data.request_id.clone();
                    }
                    if span_data.trace_id.is_none() {
                        span_data.trace_id = parent_data.trace_id.clone();
                    }
                    // If all fields filled, stop walking
                    if span_data.tenant_id.is_some()
                        && span_data.scope_id.is_some()
                        && span_data.actor_id.is_some()
                        && span_data.request_id.is_some()
                        && span_data.trace_id.is_some()
                    {
                        break;
                    }
                }
                drop(extensions);
                current = parent.parent();
            }
        }

        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();
            extensions.insert(span_data);
        }
    }
}
