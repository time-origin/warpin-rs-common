#![doc = include_str!("../README.md")]
//! Caller-driven MQTT 3.1.1 / 5.0 sessions with bounded queues and retries.
//! Enqueue is not delivery. Inspect outgoing packets and incoming ACK reason codes.
//! No worker is spawned. Dropping/cancelling `poll` requires discarding the session.
pub mod config;
mod driver;
pub mod tls;
pub use config::{Config, Credentials, QoS, Security, Version, Will};
use driver::Driver;
pub use rumqttc as protocol;
use std::{sync::Arc, time::Duration};
use warpin_errors::protocol::{Kind, Phase, ProtocolError, Result};
fn error(k: Kind, p: Phase) -> ProtocolError {
    ProtocolError::new(k, p)
}
/// Local lifecycle only: Ready does not assert device/business readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Created,
    Connecting,
    Ready,
    Reconnecting,
    Failed,
    Stopping,
    Stopped,
}
/// Original protocol events retain packet IDs, reason codes, retain, dup and properties.
/// Intentionally no Debug; raw packet payloads may contain secrets.
// Events are streamed one at a time; keeping them inline avoids a heap allocation per packet.
#[allow(clippy::large_enum_variant)]
pub enum Packet {
    V311(rumqttc::Event),
    V5(rumqttc::v5::Event),
}
/// Session-bound event, used to acknowledge a received publish.
pub struct Event {
    packet: Packet,
    owner: Arc<()>,
    generation: u64,
    acked: bool,
}
impl Event {
    /// Borrows the original protocol event without copying its payload.
    pub fn packet(&self) -> &Packet {
        &self.packet
    }
}
/// Single owner drives the event loop and receives every error. No implicit subscriptions.
pub struct Client {
    driver: Option<Driver>,
    config: Config,
    state: State,
    reconnects: u16,
    busy: bool,
    owner: Arc<()>,
    generation: u64,
}
impl Client {
    /// Validates all required configuration before constructing local state.
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let driver = Driver::new(&config);
        Ok(Self {
            driver: Some(driver),
            config,
            state: State::Created,
            reconnects: 0,
            busy: false,
            owner: Arc::new(()),
            generation: 0,
        })
    }
    /// Returns local lifecycle state; a cancelled poll is reported as failed.
    pub fn state(&self) -> State {
        if self.busy { State::Failed } else { self.state }
    }
    fn available(&self) -> Result<&Driver> {
        if self.busy || matches!(self.state, State::Failed | State::Stopping | State::Stopped) {
            return Err(error(Kind::Closed, Phase::Write));
        }
        self.driver
            .as_ref()
            .ok_or(error(Kind::Closed, Phase::Write))
    }
    /// Success means queued locally, not sent or acknowledged. No operation-level retry.
    pub fn publish(&self, topic: &str, qos: QoS, retain: bool, payload: &[u8]) -> Result<()> {
        config::topic(topic, false)?;
        if topic
            .len()
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(16))
            .is_none_or(|n| n > self.config.max_packet_bytes)
        {
            return Err(error(Kind::Capacity, Phase::Write));
        }
        self.available()?.publish(topic, qos, retain, payload)
    }
    /// Enqueues one validated filter; inspect SubAck for the broker result.
    pub fn subscribe(&self, filter: &str, qos: QoS) -> Result<()> {
        config::topic(filter, true)?;
        self.check_topic_size(filter)?;
        self.available()?.subscribe(filter, qos)
    }
    /// Enqueues removal of one filter; inspect UnsubAck for the broker result.
    pub fn unsubscribe(&self, filter: &str) -> Result<()> {
        config::topic(filter, true)?;
        self.check_topic_size(filter)?;
        self.available()?.unsubscribe(filter)
    }
    fn check_topic_size(&self, topic: &str) -> Result<()> {
        if topic.len() + 16 > self.config.max_packet_bytes {
            return Err(error(Kind::Capacity, Phase::Write));
        }
        Ok(())
    }
    /// Acknowledges only a publish emitted by this connection generation, at most once.
    /// QoS 2 PUBREC/PUBREL/PUBCOMP remains a protocol handshake, not durable application commit.
    pub fn acknowledge(&self, event: &mut Event) -> Result<()> {
        if !Arc::ptr_eq(&self.owner, &event.owner)
            || self.generation != event.generation
            || event.acked
        {
            return Err(error(Kind::Configuration, Phase::Write));
        }
        self.available()?.ack(&event.packet)?;
        event.acked = true;
        Ok(())
    }
    /// One event or explicit failure within deadline. Cancellation permanently poisons this owner.
    /// Reconnect errors are returned individually; the next poll applies a bounded backoff.
    pub async fn poll(&mut self, deadline: Duration) -> Result<Event> {
        if deadline.is_zero() || deadline > Duration::from_secs(86400) {
            return Err(error(Kind::Configuration, Phase::Configure));
        }
        self.available()?;
        self.busy = true;
        let reconnecting = self.state == State::Reconnecting;
        if self.state == State::Created {
            self.state = State::Connecting;
        }
        let driver = self
            .driver
            .as_mut()
            .ok_or(error(Kind::Closed, Phase::Read))?;
        let result = tokio::time::timeout(deadline, async {
            if reconnecting {
                tokio::time::sleep(self.config.reconnect_delay).await;
            }
            driver.poll().await
        })
        .await;
        self.busy = false;
        match result {
            Ok(Ok(packet)) => {
                if driver::connected(&packet) {
                    self.state = State::Ready;
                    self.generation += 1;
                }
                Ok(Event {
                    packet,
                    owner: self.owner.clone(),
                    generation: self.generation,
                    acked: false,
                })
            }
            Ok(Err(e)) => {
                if matches!(
                    e.kind,
                    Kind::Authentication | Kind::Protocol | Kind::Rejected
                ) || self.reconnects >= self.config.max_reconnects
                {
                    self.state = State::Failed;
                    self.driver = None;
                } else {
                    self.reconnects += 1;
                    self.state = State::Reconnecting;
                }
                Err(e)
            }
            Err(_) => {
                self.state = State::Failed;
                self.driver = None;
                Err(error(Kind::Timeout, Phase::Read))
            }
        }
    }
    /// Drain until DISCONNECT is written, bounded by caller deadline, then destroy the socket.
    /// Pending publishes may remain unacknowledged; stop never asserts their delivery.
    pub async fn close(mut self, deadline: Duration) -> Result<()> {
        if deadline.is_zero() || deadline > Duration::from_secs(86400) {
            return Err(error(Kind::Configuration, Phase::Configure));
        }
        self.available()?.disconnect()?;
        self.state = State::Stopping;
        let driver = self
            .driver
            .as_mut()
            .ok_or(error(Kind::Closed, Phase::Close))?;
        let result = tokio::time::timeout(deadline, async {
            loop {
                let event = driver.poll().await?;
                if driver::disconnected(&event) {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| error(Kind::OutcomeUnknown, Phase::Close))
        .and_then(|r| r);
        self.driver = None;
        self.state = State::Stopped;
        result
    }
    /// Immediate local shutdown; queued/unacknowledged packets have unknown delivery status.
    pub fn abort(mut self) {
        self.driver = None;
        self.state = State::Stopped;
    }
}
