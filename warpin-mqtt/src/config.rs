//! Explicit session, authentication and resource policy.
use crate::error;
pub use rumqttc::QoS;
use std::time::Duration;
use warpin_errors::protocol::{Kind, Phase, Result};
/// Protocol versions never automatically downgrade.
pub enum Version {
    V311 {
        clean_session: bool,
    },
    V5 {
        clean_start: bool,
        session_expiry_seconds: u32,
    },
}
pub enum Security {
    Plaintext,
    Tls(crate::tls::MqttTls),
}
/// No Debug: credentials must not appear in logs.
pub struct Credentials {
    /// Explicit authentication username; never log the containing configuration.
    pub username: String,
    /// Secret broker password, retained only for connecting this session.
    pub password: String,
}
pub struct Will {
    /// Valid publish topic; subscription wildcards are rejected.
    pub topic: String,
    /// Unmodified protocol bytes; no unit or business decoding is applied.
    pub payload: Vec<u8>,
    /// MQTT delivery level; it does not express business transaction completion.
    pub qos: QoS,
    /// Whether the broker should retain this publication.
    pub retain: bool,
}
pub struct Config {
    /// Explicit broker hostname or IP address; not a URL containing credentials.
    pub host: String,
    /// Nonzero broker port; no implicit TLS/transport detection.
    pub port: u16,
    /// Nonempty UTF-8 MQTT client identifier; stable IDs are required for persistent sessions.
    pub client_id: String,
    /// Explicit MQTT protocol and session settings; never automatically downgraded.
    pub version: Version,
    /// Explicit plaintext or verified TLS transport selection.
    pub security: Security,
    /// Optional broker username/password; no anonymous fallback after authentication failure.
    pub credentials: Option<Credentials>,
    /// Optional broker will configured at connection establishment.
    pub will: Option<Will>,
    /// MQTT keepalive interval, from 5 through 65535 seconds.
    pub keep_alive: Duration,
    /// Connection timeout in whole seconds (1..3600); poll may impose an earlier deadline.
    pub connect_timeout: Duration,
    /// Bounded local request queue; full queues return Capacity immediately.
    pub queue_capacity: usize,
    /// Maximum packet budget, from 128 bytes through 16 MiB.
    pub max_packet_bytes: usize,
    /// Maximum outstanding protocol work; zero is rejected.
    pub max_in_flight: u16,
    /// Lifetime limit, including failures after earlier successful reconnects. Zero disables reconnect.
    pub max_reconnects: u16,
    /// Fixed positive delay applied before a permitted reconnect attempt.
    pub reconnect_delay: Duration,
}
pub(crate) fn text(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 65535
        && !s.chars().any(|c| {
            c == '\0' || c.is_control() || ('﷐'..='﷯').contains(&c) || c as u32 & 0xffff >= 0xfffe
        })
}
pub(crate) fn topic(s: &str, filter: bool) -> Result<()> {
    if !text(s)
        || if filter {
            !rumqttc::valid_filter(s)
        } else {
            !rumqttc::valid_topic(s)
        }
    {
        return Err(error(Kind::Configuration, Phase::Configure));
    }
    Ok(())
}
impl Config {
    pub(crate) fn validate(&self) -> Result<()> {
        if !text(&self.client_id)
            || self.host.is_empty()
            || self.host.len() > 253
            || (self.host.parse::<std::net::IpAddr>().is_err()
                && self.host.contains(['/', ':', '@', '?', '#', ' ']))
            || self.port == 0
            || self.keep_alive.as_secs() < 5
            || self.keep_alive > Duration::from_secs(65535)
            || self.connect_timeout.as_secs() == 0
            || self.connect_timeout > Duration::from_secs(3600)
            || self.queue_capacity == 0
            || self.queue_capacity > 65536
            || self.max_packet_bytes < 128
            || self.max_packet_bytes > 16 * 1024 * 1024
            || self.max_in_flight == 0
            || self.reconnect_delay.is_zero()
            || self.reconnect_delay > Duration::from_secs(3600)
        {
            return Err(error(Kind::Configuration, Phase::Configure));
        }
        let mut connect_size = 32 + self.client_id.len();
        if let Some(c) = &self.credentials {
            if !text(&c.username) || c.password.len() > 65535 {
                return Err(error(Kind::Configuration, Phase::Configure));
            }
            connect_size += c.username.len() + c.password.len() + 4;
        }
        if let Some(w) = &self.will {
            topic(&w.topic, false)?;
            connect_size += w.topic.len() + w.payload.len() + 8;
        }
        if connect_size > self.max_packet_bytes {
            return Err(error(Kind::Capacity, Phase::Configure));
        }
        Ok(())
    }
}
