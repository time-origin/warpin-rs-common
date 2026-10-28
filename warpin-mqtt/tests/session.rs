use std::time::Duration;
use warpin_errors::protocol::Kind;
use warpin_mqtt::{Client, Config, QoS, Security, State, Version};
fn config() -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: 1883,
        client_id: "test".into(),
        version: Version::V311 {
            clean_session: true,
        },
        security: Security::Plaintext,
        credentials: None,
        will: None,
        keep_alive: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(1),
        queue_capacity: 1,
        max_packet_bytes: 1024,
        max_in_flight: 2,
        max_reconnects: 0,
        reconnect_delay: Duration::from_millis(1),
    }
}
#[test]
fn queue_capacity_validation_and_redaction() {
    for v in [
        Version::V311 {
            clean_session: true,
        },
        Version::V5 {
            clean_start: true,
            session_expiry_seconds: 0,
        },
    ] {
        let mut conf = config();
        conf.version = v;
        let c = Client::new(conf).expect("client");
        assert_eq!(
            c.publish("invalid/#", QoS::AtMostOnce, false, b"x")
                .expect_err("invalid")
                .kind,
            Kind::Configuration
        );
        c.publish("a", QoS::AtMostOnce, false, b"password")
            .expect("queued");
        let e = c
            .publish("a", QoS::AtMostOnce, false, b"password")
            .expect_err("full");
        assert_eq!(e.kind, Kind::Capacity);
        assert!(!format!("{e:?}").contains("password"));
    }
    let mut fractional = config();
    fractional.connect_timeout = Duration::from_millis(1500);
    assert!(
        Client::new(fractional).is_err(),
        "wire seconds must not be silently truncated"
    );
    let mut conf = config();
    conf.keep_alive = Duration::from_secs(1);
    assert!(Client::new(conf).is_err());
}
#[tokio::test]
async fn cancellation_poison_and_deadline() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let mut conf = config();
    conf.port = l.local_addr().expect("addr").port();
    let mut c = Client::new(conf).expect("client");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), c.poll(Duration::from_secs(2)))
            .await
            .is_err()
    );
    assert_eq!(c.state(), State::Failed);
    assert_eq!(
        c.publish("a", QoS::AtMostOnce, false, b"x")
            .expect_err("cancelled")
            .kind,
        Kind::Closed
    );
    c.abort();
}
#[tokio::test]
async fn reconnect_budget_exhausts() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let mut conf = config();
    conf.port = l.local_addr().expect("addr").port();
    drop(l);
    conf.max_reconnects = 1;
    let mut c = Client::new(conf).expect("client");
    assert!(c.poll(Duration::from_secs(2)).await.is_err());
    assert_eq!(c.state(), State::Reconnecting);
    assert!(c.poll(Duration::from_secs(2)).await.is_err());
    assert_eq!(c.state(), State::Failed);
}
