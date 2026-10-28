//! Real Mosquitto interoperability. Set MOSQUITTO_BIN; run this ignored test explicitly.
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
use warpin_mqtt::{Client, Config, Packet, QoS, Security, Version, protocol};
struct Broker {
    child: Child,
    path: std::path::PathBuf,
    port: u16,
    tls_dir: Option<tempfile::TempDir>,
}
impl Drop for Broker {
    fn drop(&mut self) {
        self.child.kill().expect("kill broker");
        self.child.wait().expect("reap broker");
        std::fs::remove_file(&self.path).expect("remove config");
    }
}
impl Broker {
    async fn start() -> Self {
        Self::configured(true, false).await
    }
    async fn configured(anonymous: bool, tls: bool) -> Self {
        let bin = std::env::var("MOSQUITTO_BIN").expect("MOSQUITTO_BIN required");
        let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("port");
        let port = socket.local_addr().expect("addr").port();
        drop(socket);
        let path =
            std::env::temp_dir().join(format!("warpin-mqtt-{}-{port}.conf", std::process::id()));
        let tls_dir = tls.then(tls_fixture);
        std::fs::write(
            &path,
            format!(
                "listener {port} 127.0.0.1\nallow_anonymous {anonymous}\npersistence false\n{}",
                if tls {
                    let dir = tls_dir.as_ref().expect("TLS directory").path();
                    format!(
                        "certfile {}\nkeyfile {}\ncafile {}\nrequire_certificate true\n",
                        dir.join("localhost.pem").display(),
                        dir.join("localhost.key").display(),
                        dir.join("ca.pem").display()
                    )
                } else {
                    String::new()
                }
            ),
        )
        .expect("config");
        let child = Command::new(bin)
            .args(["-c"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("broker");
        let mut b = Self {
            child,
            path,
            port,
            tls_dir,
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                assert!(
                    b.child.try_wait().expect("status").is_none(),
                    "broker exited"
                );
                if tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("ready");
        b
    }
}
fn config(port: u16, version: Version) -> Config {
    Config {
        host: "127.0.0.1".into(),
        port,
        client_id: format!(
            "warpin-{}-{port}-{}",
            std::process::id(),
            matches!(version, Version::V5 { .. })
        ),
        version,
        security: Security::Plaintext,
        credentials: None,
        will: None,
        keep_alive: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        queue_capacity: 8,
        max_packet_bytes: 4096,
        max_in_flight: 8,
        max_reconnects: 2,
        reconnect_delay: Duration::from_millis(10),
    }
}
#[tokio::test]
#[ignore = "requires isolated Mosquitto executable via MOSQUITTO_BIN"]
async fn both_versions_all_qos_manual_ack_and_clean_close() {
    let b = Broker::start().await;
    for version in [
        Version::V311 {
            clean_session: true,
        },
        Version::V5 {
            clean_start: true,
            session_expiry_seconds: 0,
        },
    ] {
        let mut c = Client::new(config(b.port, version)).expect("client");
        c.poll(Duration::from_secs(3)).await.expect("connect");
        c.subscribe("warpin/test", QoS::ExactlyOnce)
            .expect("subscribe");
        loop {
            let e = c.poll(Duration::from_secs(3)).await.expect("suback");
            if matches!(
                e.packet(),
                Packet::V311(protocol::Event::Incoming(protocol::Packet::SubAck(_)))
                    | Packet::V5(protocol::v5::Event::Incoming(
                        protocol::v5::mqttbytes::v5::Packet::SubAck(_)
                    ))
            ) {
                break;
            }
        }
        for qos in [QoS::AtMostOnce, QoS::AtLeastOnce, QoS::ExactlyOnce] {
            c.publish("warpin/test", qos, false, b"generic-payload")
                .expect("queued");
            let (mut received, mut confirmed) = (false, qos == QoS::AtMostOnce);
            for _ in 0..40 {
                let mut e = c.poll(Duration::from_secs(3)).await.expect("event");
                match e.packet() {
                    Packet::V311(protocol::Event::Incoming(protocol::Packet::Publish(p))) => {
                        assert_eq!(p.payload.as_ref(), b"generic-payload");
                        received = true;
                        if qos != QoS::AtMostOnce {
                            c.acknowledge(&mut e).expect("ack");
                            assert!(c.acknowledge(&mut e).is_err());
                        }
                    }
                    Packet::V5(protocol::v5::Event::Incoming(
                        protocol::v5::mqttbytes::v5::Packet::Publish(p),
                    )) => {
                        assert_eq!(p.payload.as_ref(), b"generic-payload");
                        received = true;
                        if qos != QoS::AtMostOnce {
                            c.acknowledge(&mut e).expect("ack");
                            assert!(c.acknowledge(&mut e).is_err());
                        }
                    }
                    Packet::V311(protocol::Event::Incoming(
                        protocol::Packet::PubAck(_) | protocol::Packet::PubComp(_),
                    ))
                    | Packet::V5(protocol::v5::Event::Incoming(
                        protocol::v5::mqttbytes::v5::Packet::PubAck(_)
                        | protocol::v5::mqttbytes::v5::Packet::PubComp(_),
                    )) => confirmed = true,
                    _ => {}
                }
                if received && confirmed {
                    break;
                }
            }
            assert!(received && confirmed, "delivery and protocol confirmation");
        }
        c.unsubscribe("warpin/test").expect("unsubscribe");
        c.close(Duration::from_secs(3)).await.expect("close");
    }
}

#[tokio::test]
#[ignore = "requires isolated Mosquitto executable via MOSQUITTO_BIN"]
async fn persistent_sessions_and_v5_expiry() {
    let b = Broker::start().await;
    for v5 in [false, true] {
        let version = || {
            if v5 {
                Version::V5 {
                    clean_start: false,
                    session_expiry_seconds: 1,
                }
            } else {
                Version::V311 {
                    clean_session: false,
                }
            }
        };
        let mut c = Client::new(config(b.port, version())).expect("client");
        let first = c.poll(Duration::from_secs(3)).await.expect("connect");
        assert!(!session_present(&first));
        c.subscribe("persist/#", QoS::AtLeastOnce)
            .expect("subscribe");
        loop {
            let e = c.poll(Duration::from_secs(3)).await.expect("event");
            if matches!(
                e.packet(),
                Packet::V311(protocol::Event::Incoming(protocol::Packet::SubAck(_)))
                    | Packet::V5(protocol::v5::Event::Incoming(
                        protocol::v5::mqttbytes::v5::Packet::SubAck(_)
                    ))
            ) {
                break;
            }
        }
        c.close(Duration::from_secs(3)).await.expect("close");
        let mut c = Client::new(config(b.port, version())).expect("client");
        assert!(session_present(
            &c.poll(Duration::from_secs(3)).await.expect("reconnect")
        ));
        c.publish("persist/test", QoS::AtMostOnce, false, b"restored")
            .expect("publish");
        loop {
            let e = c.poll(Duration::from_secs(3)).await.expect("event");
            if matches!(
                e.packet(),
                Packet::V311(protocol::Event::Incoming(protocol::Packet::Publish(_)))
                    | Packet::V5(protocol::v5::Event::Incoming(
                        protocol::v5::mqttbytes::v5::Packet::Publish(_)
                    ))
            ) {
                break;
            }
        }
        c.close(Duration::from_secs(3)).await.expect("close");
        if v5 {
            // Mosquitto expires sessions on its one-second housekeeping tick.
            // Cover the one-second interval plus both boundary ticks.
            tokio::time::sleep(Duration::from_secs(3)).await;
            let mut c = Client::new(config(b.port, version())).expect("client");
            assert!(!session_present(
                &c.poll(Duration::from_secs(3)).await.expect("expired")
            ));
            c.close(Duration::from_secs(3)).await.expect("close");
        }
    }
}
fn session_present(e: &warpin_mqtt::Event) -> bool {
    match e.packet() {
        Packet::V311(protocol::Event::Incoming(protocol::Packet::ConnAck(a))) => a.session_present,
        Packet::V5(protocol::v5::Event::Incoming(
            protocol::v5::mqttbytes::v5::Packet::ConnAck(a),
        )) => a.session_present,
        _ => panic!("expected connack"),
    }
}

#[tokio::test]
#[ignore = "requires isolated Mosquitto executable via MOSQUITTO_BIN"]
async fn tls_and_authentication_rejection() {
    use warpin_mqtt::tls::MqttTls;
    for v5 in [false, true] {
        let version = || {
            if v5 {
                Version::V5 {
                    clean_start: true,
                    session_expiry_seconds: 0,
                }
            } else {
                Version::V311 {
                    clean_session: true,
                }
            }
        };
        let b = Broker::configured(true, true).await;
        let mut conf = config(b.port, version());
        let dir = b.tls_dir.as_ref().expect("TLS directory").path();
        let identity = warpin_transport::tls::Identity {
            certificate_pem: std::fs::read(dir.join("localhost.pem")).expect("certificate"),
            private_key_pem: std::fs::read(dir.join("localhost.key")).expect("private test key"),
        };
        conf.security = Security::Tls(
            MqttTls::new(
                &std::fs::read(dir.join("ca.pem")).expect("CA"),
                Some(&identity),
            )
            .expect("mTLS config"),
        );
        let mut c = Client::new(conf).expect("client");
        c.poll(Duration::from_secs(3))
            .await
            .unwrap_or_else(|e| panic!("TLS fixture: {:?}", std::error::Error::source(&e)));
        c.close(Duration::from_secs(3)).await.expect("TLS close");
        drop(b);
        let b = Broker::configured(false, false).await;
        let mut c = Client::new(config(b.port, version())).expect("client");
        assert!(
            matches!(c.poll(Duration::from_secs(3)).await,Err(e) if e.kind==warpin_errors::protocol::Kind::Authentication)
        );
        assert_eq!(c.state(), warpin_mqtt::State::Failed);
    }
}

fn tls_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("TLS tempdir");
    let run = |args: &[&str]| {
        let output = Command::new("openssl")
            .current_dir(dir.path())
            .args(args)
            .output()
            .expect("openssl test dependency");
        assert!(
            output.status.success(),
            "test certificate generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "2",
        "-subj",
        "/CN=Warpin temporary test CA",
    ]);
    run(&[
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "localhost.key",
        "-out",
        "server.csr",
        "-subj",
        "/CN=localhost",
    ]);
    std::fs::write(dir.path().join("server.ext"),"subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n").expect("extensions");
    run(&[
        "x509",
        "-req",
        "-in",
        "server.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "localhost.pem",
        "-days",
        "1",
        "-extfile",
        "server.ext",
    ]);
    dir
}

#[tokio::test]
#[ignore = "requires isolated Mosquitto executable via MOSQUITTO_BIN"]
async fn unacknowledged_qos1_is_redelivered_in_persistent_session() {
    let b = Broker::start().await;
    for v5 in [false, true] {
        let version = || {
            if v5 {
                Version::V5 {
                    clean_start: false,
                    session_expiry_seconds: 60,
                }
            } else {
                Version::V311 {
                    clean_session: false,
                }
            }
        };
        let mut c = Client::new(config(b.port, version())).expect("client");
        c.poll(Duration::from_secs(3)).await.expect("connect");
        c.subscribe("redelivery", QoS::AtLeastOnce)
            .expect("subscribe");
        loop {
            let e = c.poll(Duration::from_secs(3)).await.expect("suback");
            if matches!(
                e.packet(),
                Packet::V311(protocol::Event::Incoming(protocol::Packet::SubAck(_)))
                    | Packet::V5(protocol::v5::Event::Incoming(
                        protocol::v5::mqttbytes::v5::Packet::SubAck(_)
                    ))
            ) {
                break;
            }
        }
        c.publish("redelivery", QoS::AtLeastOnce, false, b"pending")
            .expect("publish");
        let mut old = loop {
            let e = c.poll(Duration::from_secs(3)).await.expect("event");
            if matches!(
                e.packet(),
                Packet::V311(protocol::Event::Incoming(protocol::Packet::Publish(_)))
                    | Packet::V5(protocol::v5::Event::Incoming(
                        protocol::v5::mqttbytes::v5::Packet::Publish(_)
                    ))
            ) {
                break e;
            }
        };
        c.abort();
        let mut c = Client::new(config(b.port, version())).expect("new owner");
        assert!(session_present(
            &c.poll(Duration::from_secs(3)).await.expect("restored")
        ));
        assert!(c.acknowledge(&mut old).is_err());
        loop {
            let mut e = c.poll(Duration::from_secs(3)).await.expect("redelivery");
            let dup = match e.packet() {
                Packet::V311(protocol::Event::Incoming(protocol::Packet::Publish(p))) => {
                    Some(p.dup)
                }
                Packet::V5(protocol::v5::Event::Incoming(
                    protocol::v5::mqttbytes::v5::Packet::Publish(p),
                )) => Some(p.dup),
                _ => None,
            };
            if let Some(dup) = dup {
                assert!(dup);
                c.acknowledge(&mut e).expect("new generation ack");
                break;
            }
        }
        c.close(Duration::from_secs(3)).await.expect("close");
    }
}
