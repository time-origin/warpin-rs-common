//! Generic async event bus abstraction with pluggable backends.
//!
//! Provides a thin `EventBus` trait backed by either a no-op implementation
//! (for local development) or a production Kafka implementation via rdkafka.
//!
//! # Fail-Safe Contract
//!
//! Implementations **must never panic** on publish failure.  Return `Err` so
//! the caller can decide whether to fall back or log and continue.  Callers
//! must redact secrets before populating `payload_json`.
//!
//! # Partition Ordering
//!
//! `KafkaEventBus` uses `trace_id` as the Kafka message key so that all
//! events within a single trace land on the same partition, preserving
//! per-trace ordering without full topic ordering.
//!
//! # Tenant Guard
//!
//! `KafkaEventBus::publish` rejects any event whose `tenant_id` is empty to
//! prevent accidentally delivering un-scoped events.

use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use async_trait::async_trait;
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::client::DefaultClientContext;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// BusEvent envelope
// ---------------------------------------------------------------------------

/// Minimal envelope carried by every event on the bus.
///
/// `payload_json` is the serialized domain-specific event body.
/// **Callers are responsible for redacting secrets** before populating this
/// field -- the bus never inspects or sanitises the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusEvent {
    /// The topic this event targets.
    pub topic: String,
    /// Correlation identifier propagated from the originating request.
    /// Also used as the Kafka message key for partition ordering.
    pub trace_id: String,
    /// Tenant scope; required.  Events without a tenant_id must be rejected
    /// by bus implementations before delivery.
    pub tenant_id: String,
    /// JSON-encoded domain payload.  Must not contain secrets or credentials.
    pub payload_json: String,
    /// RFC 3339 timestamp when the event was produced.
    pub produced_at: String,
}

impl BusEvent {
    pub fn new(
        topic: impl Into<String>,
        trace_id: impl Into<String>,
        tenant_id: impl Into<String>,
        payload_json: impl Into<String>,
    ) -> Self {
        Self {
            topic: topic.into(),
            trace_id: trace_id.into(),
            tenant_id: tenant_id.into(),
            payload_json: payload_json.into(),
            produced_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// EventBus trait
// ---------------------------------------------------------------------------

/// Async publish/subscribe bus.  All implementations are `Send + Sync` to
/// allow Arc-sharing across Tokio tasks.
#[async_trait]
pub trait EventBus: Send + Sync {
    /// Publish an event to the bus.
    ///
    /// Must not panic.  Returns `Err` when the underlying transport is
    /// unavailable; callers are responsible for deciding retry vs. fall-back
    /// strategy.
    async fn publish(&self, event: BusEvent) -> Result<()>;
}

// ---------------------------------------------------------------------------
// No-op implementation
// ---------------------------------------------------------------------------

/// No-op implementation for local development and tests.
///
/// Always succeeds without side effects.
#[derive(Clone, Debug, Default)]
pub struct NoOpEventBus;

impl NoOpEventBus {
    /// Create a new no-op event bus.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EventBus for NoOpEventBus {
    async fn publish(&self, event: BusEvent) -> Result<()> {
        tracing::debug!(
            topic = %event.topic,
            trace_id = %event.trace_id,
            tenant_id = %event.tenant_id,
            "EventBus no-op publish"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// KafkaEventBusConfig
// ---------------------------------------------------------------------------

/// Configuration for `KafkaEventBus`.
///
/// `broker_url` is the only mandatory field; all other fields have production-
/// safe defaults.
#[derive(Debug, Clone)]
pub struct KafkaEventBusConfig {
    pub broker_url: String,
    pub producer_timeout_ms: u64,
    pub message_timeout_ms: u64,
    pub linger_ms: u64,
    pub client_id: String,
    pub extra_config: Vec<(String, String)>,
}

impl Default for KafkaEventBusConfig {
    fn default() -> Self {
        Self {
            broker_url: "localhost:9092".into(),
            producer_timeout_ms: 5_000,
            message_timeout_ms: 10_000,
            linger_ms: 5,
            client_id: "warpin-service".into(),
            extra_config: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// KafkaEventBus
// ---------------------------------------------------------------------------

/// Production Kafka-backed event bus using rdkafka `FutureProducer`.
#[derive(Clone)]
pub struct KafkaEventBus {
    producer: FutureProducer,
    queue_timeout: Duration,
}

impl std::fmt::Debug for KafkaEventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaEventBus")
            .field("queue_timeout", &self.queue_timeout)
            .finish_non_exhaustive()
    }
}

impl KafkaEventBus {
    pub fn new(config: KafkaEventBusConfig) -> Result<Self> {
        let mut client_config = ClientConfig::new();
        client_config
            .set("bootstrap.servers", &config.broker_url)
            .set("client.id", &config.client_id)
            .set("message.timeout.ms", config.message_timeout_ms.to_string())
            .set("queue.buffering.max.ms", config.linger_ms.to_string());

        for (key, value) in &config.extra_config {
            client_config.set(key.as_str(), value.as_str());
        }

        let producer: FutureProducer = client_config
            .create()
            .context("failed to create rdkafka FutureProducer")?;

        Ok(Self {
            producer,
            queue_timeout: Duration::from_millis(config.producer_timeout_ms),
        })
    }

    /// Access the underlying rdkafka `FutureProducer`.
    pub(crate) fn producer(&self) -> &FutureProducer {
        &self.producer
    }

    pub fn with_broker(broker_url: impl Into<String>) -> Result<Self> {
        Self::new(KafkaEventBusConfig {
            broker_url: broker_url.into(),
            ..KafkaEventBusConfig::default()
        })
    }
}

#[async_trait]
impl EventBus for KafkaEventBus {
    async fn publish(&self, event: BusEvent) -> Result<()> {
        if event.tenant_id.is_empty() {
            return Err(anyhow!(
                "EventBus: tenant_id must not be empty (topic={})",
                event.topic
            ));
        }

        let topic = event.topic.clone();
        let trace_id = event.trace_id.clone();
        let tenant_id = event.tenant_id.clone();

        let payload = event.payload_json.as_bytes().to_vec();
        let key = event.trace_id.as_bytes().to_vec();

        let record = FutureRecord::to(topic.as_str())
            .key(key.as_slice())
            .payload(payload.as_slice());

        let delivery_result = self
            .producer
            .send(record, Timeout::After(self.queue_timeout))
            .await;

        match delivery_result {
            Ok(delivery) => {
                tracing::debug!(
                    topic = %topic,
                    trace_id = %trace_id,
                    tenant_id = %tenant_id,
                    partition = delivery.partition,
                    offset = delivery.offset,
                    "EventBus Kafka publish succeeded"
                );
                Ok(())
            }
            Err((kafka_err, _owned_message)) => {
                tracing::error!(
                    topic = %topic,
                    trace_id = %trace_id,
                    tenant_id = %tenant_id,
                    error = %kafka_err,
                    "EventBus Kafka publish failed"
                );
                Err(anyhow!(
                    "EventBus Kafka publish failed (topic={topic}, trace_id={trace_id}): {kafka_err}"
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EventBusImpl -- runtime switchable
// ---------------------------------------------------------------------------

/// Runtime-switchable event bus implementation.
pub enum EventBusImpl {
    NoOp(NoOpEventBus),
    Kafka(KafkaEventBus),
}

#[async_trait]
impl EventBus for EventBusImpl {
    async fn publish(&self, event: BusEvent) -> Result<()> {
        match self {
            EventBusImpl::NoOp(inner) => inner.publish(event).await,
            EventBusImpl::Kafka(inner) => inner.publish(event).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Topic administration
// ---------------------------------------------------------------------------

/// Ensure a set of topics exist on the Kafka cluster.
///
/// Topics that already exist are silently skipped.  Returns the list of
/// topics that were actually created.
pub async fn ensure_topics(
    broker_url: &str,
    topics: &[&str],
    num_partitions: i32,
    replication_factor: i32,
) -> Result<Vec<String>> {
    let admin: AdminClient<DefaultClientContext> = ClientConfig::new()
        .set("bootstrap.servers", broker_url)
        .create()
        .context("failed to create Kafka AdminClient")?;

    let new_topics: Vec<NewTopic<'_>> = topics
        .iter()
        .map(|name| {
            NewTopic::new(
                name,
                num_partitions,
                TopicReplication::Fixed(replication_factor),
            )
        })
        .collect();

    let opts = AdminOptions::new().operation_timeout(Some(Duration::from_secs(10)));
    let results = admin
        .create_topics(&new_topics, &opts)
        .await
        .context("Kafka AdminClient create_topics RPC failed")?;

    let mut created = Vec::new();
    for result in results {
        match result {
            Ok(topic_name) => {
                tracing::info!(topic = %topic_name, "topic created successfully");
                created.push(topic_name);
            }
            Err((topic_name, err)) => {
                let err_str = format!("{err}");
                if err_str.contains("already exists") || err_str.contains("TopicAlreadyExists") {
                    tracing::info!(topic = %topic_name, "topic already exists, skipping");
                } else {
                    tracing::error!(topic = %topic_name, error = %err, "failed to create topic");
                    return Err(anyhow!("failed to create topic {topic_name}: {err}"));
                }
            }
        }
    }

    Ok(created)
}

// ---------------------------------------------------------------------------
// Consumer configuration
// ---------------------------------------------------------------------------

/// Configuration for a Kafka event consumer.
#[derive(Debug, Clone)]
pub struct ConsumerConfig {
    /// Kafka broker addresses (comma-separated).
    pub broker_url: String,
    /// Consumer group ID — consumers in the same group share partition
    /// assignments.
    pub group_id: String,
    /// Client identifier for this consumer instance.
    pub client_id: String,
    /// Where to start reading when no committed offset exists.
    /// `"earliest"` (from beginning) or `"latest"` (new messages only).
    pub auto_offset_reset: String,
    /// Whether to auto-commit offsets.  When `false`, callers must call
    /// [`KafkaEventConsumer::commit`] explicitly.
    pub enable_auto_commit: bool,
    /// Auto-commit interval in milliseconds (only relevant when
    /// `enable_auto_commit` is `true`).
    pub auto_commit_interval_ms: u64,
    /// Extra rdkafka configuration key-value pairs.
    pub extra_config: Vec<(String, String)>,
}

impl Default for ConsumerConfig {
    fn default() -> Self {
        Self {
            broker_url: "localhost:9092".into(),
            group_id: "warpin-consumer-group".into(),
            client_id: "warpin-consumer".into(),
            auto_offset_reset: "earliest".into(),
            enable_auto_commit: true,
            auto_commit_interval_ms: 5_000,
            extra_config: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ConsumedMessage
// ---------------------------------------------------------------------------

/// A message received from the event bus.
///
/// Mirrors the fields available from a raw Kafka consumed record.
/// The `payload` corresponds to whatever the publisher placed in the
/// message value (typically the `BusEvent::payload_json`).
#[derive(Debug, Clone)]
pub struct ConsumedMessage {
    /// The topic this message was consumed from.
    pub topic: String,
    /// Message key (the publisher uses `trace_id` as key).
    pub key: Option<String>,
    /// Message value (typically the JSON payload).
    pub payload: String,
    /// Kafka partition number.
    pub partition: i32,
    /// Message offset within the partition.
    pub offset: i64,
}

// ---------------------------------------------------------------------------
// KafkaEventConsumer
// ---------------------------------------------------------------------------

use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::Message;

/// Kafka-backed event consumer using rdkafka `StreamConsumer`.
///
/// # Usage
///
/// ```ignore
/// let consumer = KafkaEventConsumer::new(config)?;
/// consumer.subscribe(&["ttc.telemetry.raw"])?;
///
/// loop {
///     match consumer.recv().await {
///         Ok(msg) => { /* process msg */ }
///         Err(e) => tracing::warn!(error = %e, "consumer recv error"),
///     }
/// }
/// ```
pub struct KafkaEventConsumer {
    consumer: StreamConsumer,
}

impl std::fmt::Debug for KafkaEventConsumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaEventConsumer").finish_non_exhaustive()
    }
}

impl KafkaEventConsumer {
    /// Create a new Kafka consumer from the given configuration.
    pub fn new(config: ConsumerConfig) -> Result<Self> {
        let mut client_config = ClientConfig::new();
        client_config
            .set("bootstrap.servers", &config.broker_url)
            .set("group.id", &config.group_id)
            .set("client.id", &config.client_id)
            .set("auto.offset.reset", &config.auto_offset_reset)
            .set(
                "enable.auto.commit",
                config.enable_auto_commit.to_string(),
            )
            .set(
                "auto.commit.interval.ms",
                config.auto_commit_interval_ms.to_string(),
            );

        for (key, value) in &config.extra_config {
            client_config.set(key.as_str(), value.as_str());
        }

        let consumer: StreamConsumer = client_config
            .create()
            .context("failed to create rdkafka StreamConsumer")?;

        Ok(Self { consumer })
    }

    /// Subscribe to one or more topics.
    ///
    /// Must be called before [`recv`](Self::recv).  Replaces any previous
    /// subscription.
    pub fn subscribe(&self, topics: &[&str]) -> Result<()> {
        self.consumer
            .subscribe(topics)
            .context("failed to subscribe to Kafka topics")?;
        tracing::info!(?topics, "Kafka consumer subscribed");
        Ok(())
    }

    /// Block until the next message is available and return it.
    ///
    /// Returns `Err` on deserialization or transport errors. The caller
    /// should log and continue rather than terminating.
    pub async fn recv(&self) -> Result<ConsumedMessage> {
        let msg = self
            .consumer
            .recv()
            .await
            .map_err(|e| anyhow!("Kafka consumer recv error: {e}"))?;

        let topic = msg.topic().to_owned();
        let partition = msg.partition();
        let offset = msg.offset();

        let key = msg
            .key()
            .and_then(|k| std::str::from_utf8(k).ok())
            .map(|s| s.to_owned());

        let payload = msg
            .payload()
            .and_then(|p| std::str::from_utf8(p).ok())
            .unwrap_or("")
            .to_owned();

        tracing::trace!(
            topic = %topic,
            partition,
            offset,
            key = key.as_deref().unwrap_or("<none>"),
            payload_len = payload.len(),
            "consumed message"
        );

        Ok(ConsumedMessage {
            topic,
            key,
            payload,
            partition,
            offset,
        })
    }

    /// Manually commit the current consumer offsets (synchronous commit).
    ///
    /// Only needed when `enable_auto_commit` is `false`.
    pub fn commit(&self) -> Result<()> {
        self.consumer
            .commit_consumer_state(rdkafka::consumer::CommitMode::Sync)
            .context("failed to commit consumer offsets")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NoOpConsumer
// ---------------------------------------------------------------------------

/// No-op consumer for local development and tests.
///
/// `recv()` blocks forever (returns `Pending`), matching the behaviour of
/// a consumer with no messages.
#[derive(Clone, Debug, Default)]
pub struct NoOpConsumer;

impl NoOpConsumer {
    /// Subscribe (no-op, always succeeds).
    pub fn subscribe(&self, topics: &[&str]) -> Result<()> {
        tracing::debug!(?topics, "NoOpConsumer subscribe (no-op)");
        Ok(())
    }

    /// Block forever — a no-op consumer never has messages.
    pub async fn recv(&self) -> Result<ConsumedMessage> {
        // Sleep forever; the future will be dropped on shutdown.
        futures::future::pending::<()>().await;
        unreachable!()
    }

    /// Commit (no-op, always succeeds).
    pub fn commit(&self) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EventConsumerImpl -- runtime switchable
// ---------------------------------------------------------------------------

/// Runtime-switchable event consumer implementation.
#[derive(Debug)]
pub enum EventConsumerImpl {
    NoOp(NoOpConsumer),
    Kafka(KafkaEventConsumer),
}

impl EventConsumerImpl {
    /// Subscribe to topics.
    pub fn subscribe(&self, topics: &[&str]) -> Result<()> {
        match self {
            EventConsumerImpl::NoOp(inner) => inner.subscribe(topics),
            EventConsumerImpl::Kafka(inner) => inner.subscribe(topics),
        }
    }

    /// Receive the next message.
    pub async fn recv(&self) -> Result<ConsumedMessage> {
        match self {
            EventConsumerImpl::NoOp(inner) => inner.recv().await,
            EventConsumerImpl::Kafka(inner) => inner.recv().await,
        }
    }

    /// Commit consumer offsets.
    pub fn commit(&self) -> Result<()> {
        match self {
            EventConsumerImpl::NoOp(inner) => inner.commit(),
            EventConsumerImpl::Kafka(inner) => inner.commit(),
        }
    }
}

// ---------------------------------------------------------------------------
// TypedEnvelope — schema-versioned event envelope
// ---------------------------------------------------------------------------

/// A typed, schema-versioned event envelope that wraps a serializable payload.
///
/// `TypedEnvelope` provides schema evolution support by including a `schema_version`
/// field. Consumers can use this to handle backward-compatible changes.
///
/// # Schema Evolution Strategy
/// - Producers increment `schema_version` when adding new fields
/// - Consumers must handle unknown `schema_version` gracefully (log warning, process known fields)
/// - Fields are additive-only (never remove or rename)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedEnvelope<T: Serialize> {
    /// Unique event identifier (UUID v4)
    pub event_id: String,
    /// Kafka partition key (typically trace_id or tenant_id)
    pub partition_key: String,
    /// The event payload
    pub payload: T,
    /// ISO 8601 timestamp when the event was produced
    pub produced_at: String,
    /// Schema version for evolution support (starts at 1)
    pub schema_version: u32,
}

impl<T: Serialize> TypedEnvelope<T> {
    /// Create a new TypedEnvelope with the current timestamp.
    pub fn new(event_id: String, partition_key: String, payload: T, schema_version: u32) -> Self {
        Self {
            event_id,
            partition_key,
            payload,
            produced_at: chrono::Utc::now().to_rfc3339(),
            schema_version,
        }
    }

    /// Convert this typed envelope into a BusEvent for publishing.
    ///
    /// The entire envelope (including metadata) is serialized to JSON and placed
    /// in `payload_json`. The `topic` and `tenant_id` must be provided by the
    /// caller.
    pub fn into_bus_event(self, topic: &str, tenant_id: &str) -> Result<BusEvent> {
        let payload_json = serde_json::to_string(&self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize TypedEnvelope: {e}"))?;

        Ok(BusEvent {
            topic: topic.to_string(),
            trace_id: self.partition_key,
            tenant_id: tenant_id.to_string(),
            payload_json,
            produced_at: self.produced_at,
        })
    }
}

// ---------------------------------------------------------------------------
// BatchPublisher — best-effort batch publishing
// ---------------------------------------------------------------------------

/// Result of a batch publish operation.
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Number of successfully published events
    pub succeeded: usize,
    /// Failed events with their errors
    pub failures: Vec<BatchFailure>,
}

/// A single failure within a batch publish.
#[derive(Debug, Clone)]
pub struct BatchFailure {
    /// Index of the failed event in the original batch
    pub index: usize,
    /// Error description
    pub error: String,
}

impl BatchResult {
    /// Returns true if all events were published successfully.
    pub fn all_succeeded(&self) -> bool {
        self.failures.is_empty()
    }

    /// Total number of events in the batch.
    pub fn total(&self) -> usize {
        self.succeeded + self.failures.len()
    }
}

/// Trait for publishing a batch of events with per-event failure reporting.
///
/// Implementations should attempt to publish all events and report
/// individual failures without aborting the entire batch.
#[async_trait]
pub trait BatchPublisher: Send + Sync {
    /// Publish a batch of events. Returns a result indicating success/failure per event.
    async fn publish_batch(&self, events: Vec<BusEvent>) -> Result<BatchResult>;
}

#[async_trait]
impl BatchPublisher for KafkaEventBus {
    async fn publish_batch(&self, events: Vec<BusEvent>) -> Result<BatchResult> {
        use futures::future::join_all;

        if events.is_empty() {
            return Ok(BatchResult {
                succeeded: 0,
                failures: vec![],
            });
        }

        // Pre-filter: reject events with empty tenant_id
        let mut failures = Vec::new();
        let valid_events: Vec<(usize, &BusEvent)> = events
            .iter()
            .enumerate()
            .filter(|(idx, event)| {
                if event.tenant_id.is_empty() {
                    failures.push(BatchFailure {
                        index: *idx,
                        error: "tenant_id must not be empty".to_string(),
                    });
                    false
                } else {
                    true
                }
            })
            .collect();

        let futures: Vec<_> = valid_events
            .iter()
            .map(|(idx, event)| {
                let idx = *idx;
                let producer = self.producer().clone();
                let topic = event.topic.clone();
                let key = event.trace_id.clone();
                let payload = event.payload_json.clone();
                async move {
                    let record = FutureRecord::to(&topic)
                        .key(&key)
                        .payload(&payload);
                    match producer
                        .send(record, Timeout::After(Duration::from_secs(5)))
                        .await
                    {
                        Ok(_) => Ok(idx),
                        Err((e, _)) => Err((idx, format!("{e}"))),
                    }
                }
            })
            .collect();

        let results = join_all(futures).await;

        let mut succeeded = 0;
        for result in results {
            match result {
                Ok(_) => succeeded += 1,
                Err((index, error)) => failures.push(BatchFailure { index, error }),
            }
        }

        Ok(BatchResult {
            succeeded,
            failures,
        })
    }
}

#[async_trait]
impl BatchPublisher for NoOpEventBus {
    async fn publish_batch(&self, events: Vec<BusEvent>) -> Result<BatchResult> {
        let count = events.len();
        for event in &events {
            tracing::debug!(
                topic = %event.topic,
                trace_id = %event.trace_id,
                "NoOp batch publish"
            );
        }
        Ok(BatchResult {
            succeeded: count,
            failures: vec![],
        })
    }
}

#[async_trait]
impl BatchPublisher for EventBusImpl {
    async fn publish_batch(&self, events: Vec<BusEvent>) -> Result<BatchResult> {
        match self {
            EventBusImpl::NoOp(bus) => bus.publish_batch(events).await,
            EventBusImpl::Kafka(bus) => bus.publish_batch(events).await,
        }
    }
}

// ---------------------------------------------------------------------------
// CommitStrategy — consumer offset commit strategy
// ---------------------------------------------------------------------------

/// Strategy for committing consumer offsets.
#[derive(Debug, Clone, Default)]
pub enum CommitStrategy {
    /// Let rdkafka auto-commit offsets periodically.
    #[default]
    AutoCommit,
    /// Manually commit synchronously after processing.
    ManualSync,
    /// Manually commit asynchronously after processing.
    ManualAsync,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_bus_succeeds() {
        let bus = NoOpEventBus;
        let event = BusEvent::new("test.topic", "t1", "tenant1", "{}");
        assert!(bus.publish(event).await.is_ok());
    }

    #[tokio::test]
    async fn event_bus_impl_noop_succeeds() {
        let bus = EventBusImpl::NoOp(NoOpEventBus);
        let event = BusEvent::new("test.topic", "t2", "tenant2", r#"{"test":true}"#);
        assert!(bus.publish(event).await.is_ok());
    }

    #[test]
    fn kafka_config_defaults_are_sane() {
        let cfg = KafkaEventBusConfig::default();
        assert_eq!(cfg.broker_url, "localhost:9092");
        assert_eq!(cfg.producer_timeout_ms, 5_000);
        assert_eq!(cfg.message_timeout_ms, 10_000);
        assert_eq!(cfg.linger_ms, 5);
        assert_eq!(cfg.client_id, "warpin-service");
        assert!(cfg.extra_config.is_empty());
    }

    #[tokio::test]
    async fn kafka_bus_rejects_empty_tenant_id() {
        let bus = KafkaEventBus::with_broker("localhost:19099")
            .expect("KafkaEventBus::new should succeed");
        let event = BusEvent::new("test.topic", "trace-x", "", "{}");
        let result = bus.publish(event).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tenant_id"));
    }

    #[tokio::test]
    async fn event_bus_impl_kafka_tenant_guard_propagates() {
        let inner = KafkaEventBus::with_broker("localhost:19099")
            .expect("KafkaEventBus::new must not fail");
        let bus = EventBusImpl::Kafka(inner);
        let event = BusEvent::new("test.topic", "trace-y", "", r#"{"k":1}"#);
        assert!(bus.publish(event).await.is_err());
    }

    // ── Consumer tests ────────────────────────────────────────

    #[test]
    fn consumer_config_defaults_are_sane() {
        let cfg = ConsumerConfig::default();
        assert_eq!(cfg.broker_url, "localhost:9092");
        assert_eq!(cfg.group_id, "warpin-consumer-group");
        assert_eq!(cfg.auto_offset_reset, "earliest");
        assert!(cfg.enable_auto_commit);
        assert_eq!(cfg.auto_commit_interval_ms, 5_000);
    }

    #[tokio::test]
    async fn kafka_consumer_can_be_created() {
        let config = ConsumerConfig {
            broker_url: "localhost:19099".into(),
            ..ConsumerConfig::default()
        };
        let consumer = KafkaEventConsumer::new(config);
        assert!(consumer.is_ok());
    }

    #[test]
    fn noop_consumer_subscribe_succeeds() {
        let consumer = NoOpConsumer;
        assert!(consumer.subscribe(&["test.topic"]).is_ok());
    }

    #[test]
    fn noop_consumer_commit_succeeds() {
        let consumer = NoOpConsumer;
        assert!(consumer.commit().is_ok());
    }

    #[test]
    fn event_consumer_impl_noop_subscribe() {
        let consumer = EventConsumerImpl::NoOp(NoOpConsumer);
        assert!(consumer.subscribe(&["test.topic"]).is_ok());
    }

    #[tokio::test]
    async fn event_consumer_impl_kafka_subscribe() {
        let config = ConsumerConfig {
            broker_url: "localhost:19099".into(),
            ..ConsumerConfig::default()
        };
        let kafka = KafkaEventConsumer::new(config).unwrap();
        let consumer = EventConsumerImpl::Kafka(kafka);
        // subscribe to a topic on a non-existent broker should still succeed
        // (rdkafka defers the actual connection)
        assert!(consumer.subscribe(&["test.topic"]).is_ok());
    }

    #[test]
    fn consumed_message_debug_format() {
        let msg = ConsumedMessage {
            topic: "test.topic".into(),
            key: Some("trace-1".into()),
            payload: r#"{"hello":"world"}"#.into(),
            partition: 0,
            offset: 42,
        };
        let debug = format!("{msg:?}");
        assert!(debug.contains("test.topic"));
        assert!(debug.contains("trace-1"));
    }

    // ── TypedEnvelope tests ──────────────────────────────────

    #[test]
    fn test_typed_envelope_serialization() {
        let envelope = TypedEnvelope::new(
            "evt-123".into(),
            "trace-456".into(),
            serde_json::json!({"key": "value"}),
            1,
        );
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("schema_version"));
        assert!(json.contains("evt-123"));
    }

    #[test]
    fn test_typed_envelope_into_bus_event() {
        let envelope = TypedEnvelope::new(
            "evt-123".into(),
            "trace-456".into(),
            serde_json::json!({"key": "value"}),
            1,
        );
        let bus_event = envelope.into_bus_event("test.topic", "tenant-1").unwrap();
        assert_eq!(bus_event.topic, "test.topic");
        assert_eq!(bus_event.tenant_id, "tenant-1");
        assert_eq!(bus_event.trace_id, "trace-456");
    }

    // ── BatchPublisher tests ─────────────────────────────────

    #[test]
    fn test_batch_result_all_succeeded() {
        let result = BatchResult {
            succeeded: 5,
            failures: vec![],
        };
        assert!(result.all_succeeded());
        assert_eq!(result.total(), 5);
    }

    #[test]
    fn test_batch_result_with_failures() {
        let result = BatchResult {
            succeeded: 3,
            failures: vec![
                BatchFailure {
                    index: 1,
                    error: "timeout".into(),
                },
                BatchFailure {
                    index: 3,
                    error: "full".into(),
                },
            ],
        };
        assert!(!result.all_succeeded());
        assert_eq!(result.total(), 5);
    }

    #[tokio::test]
    async fn test_noop_batch_publisher() {
        let bus = NoOpEventBus::new();
        let events = vec![
            BusEvent {
                topic: "test".into(),
                trace_id: "t1".into(),
                tenant_id: "tenant".into(),
                payload_json: "{}".into(),
                produced_at: "2026-01-01T00:00:00Z".into(),
            },
            BusEvent {
                topic: "test".into(),
                trace_id: "t2".into(),
                tenant_id: "tenant".into(),
                payload_json: "{}".into(),
                produced_at: "2026-01-01T00:00:00Z".into(),
            },
        ];
        let result = bus.publish_batch(events).await.unwrap();
        assert!(result.all_succeeded());
        assert_eq!(result.succeeded, 2);
    }

    #[tokio::test]
    async fn test_noop_batch_publisher_empty() {
        let bus = EventBusImpl::NoOp(NoOpEventBus::new());
        let result = bus.publish_batch(vec![]).await.unwrap();
        assert!(result.all_succeeded());
        assert_eq!(result.total(), 0);
    }

    // ── CommitStrategy tests ─────────────────────────────────

    #[test]
    fn test_commit_strategy_default() {
        let strategy: CommitStrategy = Default::default();
        assert!(matches!(strategy, CommitStrategy::AutoCommit));
    }
}
