use crate::{Config, Packet, QoS, Security, Version, error};
use rumqttc::{TlsConfiguration, Transport};
use warpin_errors::protocol::{Kind, Phase, Result};
pub(crate) enum Driver {
    V311(rumqttc::AsyncClient, Box<rumqttc::EventLoop>),
    V5(rumqttc::v5::AsyncClient, Box<rumqttc::v5::EventLoop>),
}
fn transport(s: &Security) -> Transport {
    match s {
        Security::Plaintext => Transport::tcp(),
        Security::Tls(t) => {
            Transport::tls_with_config(TlsConfiguration::NativeConnector(t.connector()))
        }
    }
}
impl Driver {
    pub(crate) fn new(c: &Config) -> Self {
        match c.version {
            Version::V311 { clean_session } => {
                let mut o = rumqttc::MqttOptions::new(&c.client_id, &c.host, c.port);
                o.set_clean_session(clean_session)
                    .set_keep_alive(c.keep_alive)
                    .set_transport(transport(&c.security))
                    .set_max_packet_size(c.max_packet_bytes, c.max_packet_bytes)
                    .set_inflight(c.max_in_flight)
                    .set_manual_acks(true);
                if let Some(auth) = &c.credentials {
                    o.set_credentials(&auth.username, &auth.password);
                }
                if let Some(w) = &c.will {
                    o.set_last_will(rumqttc::LastWill::new(
                        &w.topic,
                        w.payload.clone(),
                        w.qos,
                        w.retain,
                    ));
                }
                let (client, mut driver) = rumqttc::AsyncClient::new(o, c.queue_capacity);
                driver
                    .network_options
                    .set_connection_timeout(c.connect_timeout.as_secs());
                Self::V311(client, Box::new(driver))
            }
            Version::V5 {
                clean_start,
                session_expiry_seconds,
            } => {
                let mut o = rumqttc::v5::MqttOptions::new(&c.client_id, &c.host, c.port);
                o.set_clean_start(clean_start)
                    .set_session_expiry_interval(Some(session_expiry_seconds))
                    .set_keep_alive(c.keep_alive)
                    .set_transport(transport(&c.security))
                    .set_max_packet_size(Some(c.max_packet_bytes as u32))
                    .set_outgoing_inflight_upper_limit(c.max_in_flight)
                    .set_receive_maximum(Some(c.max_in_flight))
                    .set_manual_acks(true)
                    .set_connection_timeout(c.connect_timeout.as_secs());
                if let Some(auth) = &c.credentials {
                    o.set_credentials(&auth.username, &auth.password);
                }
                if let Some(w) = &c.will {
                    o.set_last_will(rumqttc::v5::mqttbytes::v5::LastWill::new(
                        &w.topic,
                        w.payload.clone(),
                        qos5(w.qos),
                        w.retain,
                        None,
                    ));
                }
                let (client, driver) = rumqttc::v5::AsyncClient::new(o, c.queue_capacity);
                Self::V5(client, Box::new(driver))
            }
        }
    }
    pub(crate) fn publish(&self, t: &str, q: QoS, r: bool, b: &[u8]) -> Result<()> {
        match self {
            Self::V311(c, _) => c
                .try_publish(t, q, r, b)
                .map_err(|_| error(Kind::Capacity, Phase::Write)),
            Self::V5(c, _) => c
                .try_publish(t, qos5(q), r, b.to_vec())
                .map_err(|_| error(Kind::Capacity, Phase::Write)),
        }
    }
    pub(crate) fn subscribe(&self, t: &str, q: QoS) -> Result<()> {
        match self {
            Self::V311(c, _) => c
                .try_subscribe(t, q)
                .map_err(|_| error(Kind::Capacity, Phase::Write)),
            Self::V5(c, _) => c
                .try_subscribe(t, qos5(q))
                .map_err(|_| error(Kind::Capacity, Phase::Write)),
        }
    }
    pub(crate) fn unsubscribe(&self, t: &str) -> Result<()> {
        match self {
            Self::V311(c, _) => c
                .try_unsubscribe(t)
                .map_err(|_| error(Kind::Capacity, Phase::Write)),
            Self::V5(c, _) => c
                .try_unsubscribe(t)
                .map_err(|_| error(Kind::Capacity, Phase::Write)),
        }
    }
    pub(crate) fn disconnect(&self) -> Result<()> {
        match self {
            Self::V311(c, _) => c
                .try_disconnect()
                .map_err(|_| error(Kind::Capacity, Phase::Close)),
            Self::V5(c, _) => c
                .try_disconnect()
                .map_err(|_| error(Kind::Capacity, Phase::Close)),
        }
    }
    pub(crate) fn ack(&self, e: &Packet) -> Result<()> {
        match (self, e) {
            (
                Self::V311(c, _),
                Packet::V311(rumqttc::Event::Incoming(rumqttc::Packet::Publish(p))),
            ) if p.qos != QoS::AtMostOnce => c
                .try_ack(p)
                .map_err(|_| error(Kind::Capacity, Phase::Write)),
            (
                Self::V5(c, _),
                Packet::V5(rumqttc::v5::Event::Incoming(
                    rumqttc::v5::mqttbytes::v5::Packet::Publish(p),
                )),
            ) if p.qos != rumqttc::v5::mqttbytes::QoS::AtMostOnce => c
                .try_ack(p)
                .map_err(|_| error(Kind::Capacity, Phase::Write)),
            _ => Err(error(Kind::Configuration, Phase::Write)),
        }
    }
    pub(crate) async fn poll(&mut self) -> Result<Packet> {
        match self {
            Self::V311(_, d) => d.poll().await.map(Packet::V311).map_err(|e| {
                use rumqttc::ConnectionError::*;
                error(
                    match &e {
                        Tls(_) => Kind::Authentication,
                        ConnectionRefused(
                            rumqttc::ConnectReturnCode::BadUserNamePassword
                            | rumqttc::ConnectReturnCode::NotAuthorized,
                        ) => Kind::Authentication,
                        ConnectionRefused(_) => Kind::Rejected,
                        NetworkTimeout | FlushTimeout => Kind::Timeout,
                        Io(_) => Kind::Connection,
                        RequestsDone => Kind::Closed,
                        _ => Kind::Protocol,
                    },
                    Phase::Read,
                )
                .with_source(e)
            }),
            Self::V5(_, d) => d.poll().await.map(Packet::V5).map_err(|e| {
                use rumqttc::v5::ConnectionError::*;
                error(
                    match &e {
                        Tls(_) => Kind::Authentication,
                        ConnectionRefused(
                            rumqttc::v5::mqttbytes::v5::ConnectReturnCode::BadUserNamePassword
                            | rumqttc::v5::mqttbytes::v5::ConnectReturnCode::NotAuthorized,
                        ) => Kind::Authentication,
                        ConnectionRefused(_) => Kind::Rejected,
                        Timeout(_) => Kind::Timeout,
                        Io(_) => Kind::Connection,
                        RequestsDone => Kind::Closed,
                        _ => Kind::Protocol,
                    },
                    Phase::Read,
                )
                .with_source(e)
            }),
        }
    }
}
fn qos5(q: QoS) -> rumqttc::v5::mqttbytes::QoS {
    match q {
        QoS::AtMostOnce => rumqttc::v5::mqttbytes::QoS::AtMostOnce,
        QoS::AtLeastOnce => rumqttc::v5::mqttbytes::QoS::AtLeastOnce,
        QoS::ExactlyOnce => rumqttc::v5::mqttbytes::QoS::ExactlyOnce,
    }
}
pub(crate) fn connected(p: &Packet) -> bool {
    matches!(
        p,
        Packet::V311(rumqttc::Event::Incoming(rumqttc::Packet::ConnAck(_)))
            | Packet::V5(rumqttc::v5::Event::Incoming(
                rumqttc::v5::mqttbytes::v5::Packet::ConnAck(_)
            ))
    )
}
pub(crate) fn disconnected(p: &Packet) -> bool {
    matches!(
        p,
        Packet::V311(rumqttc::Event::Outgoing(rumqttc::Outgoing::Disconnect))
            | Packet::V5(rumqttc::v5::Event::Outgoing(rumqttc::Outgoing::Disconnect))
    )
}
