//! Explicit plaintext test-broker example: host port topic; exits after one message.
use std::time::Duration;
use warpin_mqtt::{Client, Config, Packet, QoS, Security, Version, protocol};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 4 {
        return Err("provide test broker host port topic (explicit plaintext)".into());
    }
    let mut c = Client::new(Config {
        host: a[1].clone(),
        port: a[2].parse()?,
        client_id: format!("warpin-example-{}", std::process::id()),
        version: Version::V311 {
            clean_session: true,
        },
        security: Security::Plaintext,
        credentials: None,
        will: None,
        keep_alive: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(3),
        queue_capacity: 16,
        max_packet_bytes: 65536,
        max_in_flight: 16,
        max_reconnects: 3,
        reconnect_delay: Duration::from_secs(1),
    })?;
    c.subscribe(&a[3], QoS::AtLeastOnce)?;
    loop {
        let mut e = c.poll(Duration::from_secs(15)).await?;
        if matches!(
            e.packet(),
            Packet::V311(protocol::Event::Incoming(protocol::Packet::Publish(_)))
        ) {
            c.acknowledge(&mut e)?;
            break;
        }
    }
    c.close(Duration::from_secs(3)).await?;
    Ok(())
}
