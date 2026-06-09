//! Audit event sink abstraction.
//!
//! `AuditSink` is the trait for forwarding audit records to external systems.
//! `EventBusSinkWorker` bridges audit records to an `AuditSink` with batching.
//! `NoOpSink` discards events (useful for testing/local dev).

use crate::layer::AuditRecord;
use crate::redaction::RedactionPolicy;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};

/// Trait for audit event sinks.
///
/// Implementations receive audit records and forward them to storage/transport.
/// The `AuditSink` does NOT depend on any specific event bus implementation;
/// the Kafka/transport binding is injected by the application layer.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Emit a single audit record.
    async fn emit(&self, record: AuditRecord) -> anyhow::Result<()>;

    /// Emit a batch of audit records.
    /// Default implementation calls `emit` for each record.
    async fn emit_batch(&self, records: Vec<AuditRecord>) -> anyhow::Result<()> {
        for record in records {
            self.emit(record).await?;
        }
        Ok(())
    }
}

/// No-op sink that discards all events. Useful for local dev and testing.
pub struct NoOpSink;

#[async_trait]
impl AuditSink for NoOpSink {
    async fn emit(&self, _record: AuditRecord) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Configuration for EventBusSinkWorker batching behavior.
#[derive(Debug, Clone)]
pub struct EventBusSinkConfig {
    /// Maximum number of records per batch (default: 64)
    pub batch_size: usize,
    /// Maximum time to wait before flushing an incomplete batch (default: 200ms)
    pub flush_interval: Duration,
}

impl Default for EventBusSinkConfig {
    fn default() -> Self {
        Self {
            batch_size: 64,
            flush_interval: Duration::from_millis(200),
        }
    }
}

/// Bridges audit records from the AuditLayer channel to an AuditSink,
/// with configurable batching.
///
/// This struct owns a background tokio task that:
/// 1. Receives AuditRecord from the channel
/// 2. Batches them by size or time
/// 3. Forwards batches to the configured AuditSink
///
/// The sink implementation is injected -- this struct does NOT depend on
/// rdkafka or any specific transport.
pub struct EventBusSinkWorker {
    handle: tokio::task::JoinHandle<()>,
}

impl EventBusSinkWorker {
    /// Start a background worker that drains the receiver and batches to the sink.
    ///
    /// If `redaction` is provided, each record's fields are redacted before batching.
    pub fn start(
        mut rx: mpsc::Receiver<AuditRecord>,
        sink: Arc<dyn AuditSink>,
        config: EventBusSinkConfig,
        redaction: Option<Arc<dyn RedactionPolicy>>,
    ) -> Self {
        let handle = tokio::spawn(async move {
            let mut batch: Vec<AuditRecord> = Vec::with_capacity(config.batch_size);
            let mut flush_timer = interval(config.flush_interval);
            flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    record = rx.recv() => {
                        match record {
                            Some(mut r) => {
                                if let Some(ref policy) = redaction {
                                    let mut fields_value = serde_json::to_value(&r.fields)
                                        .unwrap_or_default();
                                    policy.redact(&mut fields_value);
                                    if let Some(map) = fields_value.as_object() {
                                        r.fields = map
                                            .iter()
                                            .map(|(k, v)| (k.clone(), v.clone()))
                                            .collect();
                                    }
                                }
                                batch.push(r);
                                if batch.len() >= config.batch_size {
                                    let to_send = std::mem::replace(
                                        &mut batch,
                                        Vec::with_capacity(config.batch_size),
                                    );
                                    if let Err(e) = sink.emit_batch(to_send).await {
                                        tracing::warn!(error = %e, "Failed to emit audit batch");
                                        metrics::counter!("audit_batch_failures").increment(1);
                                    } else {
                                        metrics::counter!("audit_batches_sent").increment(1);
                                    }
                                    flush_timer.reset();
                                }
                            }
                            None => {
                                // Channel closed, flush remaining and exit
                                if !batch.is_empty()
                                    && let Err(e) = sink.emit_batch(batch).await
                                {
                                    tracing::error!(error = %e, "Failed to flush remaining audit batch during shutdown");
                                }
                                tracing::info!("Audit sink worker shutting down");
                                break;
                            }
                        }
                    }
                    _ = flush_timer.tick() => {
                        if !batch.is_empty() {
                            let to_send = std::mem::replace(
                                &mut batch,
                                Vec::with_capacity(config.batch_size),
                            );
                            if let Err(e) = sink.emit_batch(to_send).await {
                                tracing::warn!(error = %e, "Failed to flush audit batch");
                                metrics::counter!("audit_batch_failures").increment(1);
                            } else {
                                metrics::counter!("audit_batches_sent").increment(1);
                            }
                        }
                    }
                }
            }
        });

        Self { handle }
    }

    /// Wait for the worker to complete (typically after the sender is dropped).
    pub async fn shutdown(self) {
        let _ = self.handle.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{AuditRecord, SpanContext};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingSink {
        count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl AuditSink for CountingSink {
        async fn emit(&self, _record: AuditRecord) -> anyhow::Result<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn make_record(event_type: &str) -> AuditRecord {
        AuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: event_type.to_string(),
            fields: HashMap::new(),
            span_context: SpanContext::default(),
        }
    }

    #[tokio::test]
    async fn test_noop_sink() {
        let sink = NoOpSink;
        assert!(sink.emit(make_record("test")).await.is_ok());
    }

    #[tokio::test]
    async fn test_event_bus_sink_worker_batch_by_size() {
        let count = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(CountingSink {
            count: count.clone(),
        });

        let (tx, rx) = mpsc::channel(256);
        let config = EventBusSinkConfig {
            batch_size: 5,
            flush_interval: Duration::from_secs(60),
        };

        let worker = EventBusSinkWorker::start(rx, sink, config, None);

        // Send exactly batch_size records
        for i in 0..5 {
            tx.send(make_record(&format!("event_{i}"))).await.unwrap();
        }

        // Give worker time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Should have processed 5 records (1 batch)
        assert_eq!(count.load(Ordering::SeqCst), 5);

        drop(tx);
        worker.shutdown().await;
    }

    #[tokio::test]
    async fn test_event_bus_sink_worker_flush_by_time() {
        let count = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(CountingSink {
            count: count.clone(),
        });

        let (tx, rx) = mpsc::channel(256);
        let config = EventBusSinkConfig {
            batch_size: 100,
            flush_interval: Duration::from_millis(50),
        };

        let worker = EventBusSinkWorker::start(rx, sink, config, None);

        // Send 3 records (less than batch_size)
        for i in 0..3 {
            tx.send(make_record(&format!("event_{i}"))).await.unwrap();
        }

        // Wait for flush timer
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should have flushed by time
        assert_eq!(count.load(Ordering::SeqCst), 3);

        drop(tx);
        worker.shutdown().await;
    }

    #[tokio::test]
    async fn test_event_bus_sink_worker_shutdown_flush() {
        let count = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(CountingSink {
            count: count.clone(),
        });

        let (tx, rx) = mpsc::channel(256);
        let config = EventBusSinkConfig {
            batch_size: 100,
            flush_interval: Duration::from_secs(60),
        };

        let worker = EventBusSinkWorker::start(rx, sink, config, None);

        // Send 2 records
        tx.send(make_record("event_1")).await.unwrap();
        tx.send(make_record("event_2")).await.unwrap();

        // Drop sender to trigger shutdown flush
        drop(tx);
        worker.shutdown().await;

        // Should have flushed remaining on shutdown
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    /// Sink that captures emitted records for assertion.
    struct CaptureSink {
        records: Arc<tokio::sync::Mutex<Vec<AuditRecord>>>,
    }

    #[async_trait]
    impl AuditSink for CaptureSink {
        async fn emit(&self, record: AuditRecord) -> anyhow::Result<()> {
            self.records.lock().await.push(record);
            Ok(())
        }
    }

    /// A test redaction policy that replaces any field named "secret" with "[REDACTED]".
    struct TestRedaction;

    impl RedactionPolicy for TestRedaction {
        fn redact(&self, payload: &mut serde_json::Value) {
            if let serde_json::Value::Object(map) = payload
                && let Some(v) = map.get_mut("secret")
            {
                *v = serde_json::Value::String("[REDACTED]".to_string());
            }
        }
    }

    #[tokio::test]
    async fn test_event_bus_sink_worker_applies_redaction() {
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let sink = Arc::new(CaptureSink {
            records: captured.clone(),
        });

        let (tx, rx) = mpsc::channel(256);
        let config = EventBusSinkConfig {
            batch_size: 100,
            flush_interval: Duration::from_secs(60),
        };

        let redaction: Arc<dyn RedactionPolicy> = Arc::new(TestRedaction);
        let worker = EventBusSinkWorker::start(rx, sink, config, Some(redaction));

        // Build a record with a "secret" field
        let mut record = make_record("test_redaction");
        record.fields.insert(
            "secret".to_string(),
            serde_json::Value::String("my-api-key".to_string()),
        );
        record.fields.insert(
            "visible".to_string(),
            serde_json::Value::String("hello".to_string()),
        );
        tx.send(record).await.unwrap();

        // Drop sender to flush
        drop(tx);
        worker.shutdown().await;

        let records = captured.lock().await;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].fields.get("secret").and_then(|v| v.as_str()),
            Some("[REDACTED]"),
        );
        assert_eq!(
            records[0].fields.get("visible").and_then(|v| v.as_str()),
            Some("hello"),
        );
    }
}
