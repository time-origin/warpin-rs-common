//! Runs without a device. Both protocols carry only generic bytes.
use std::time::Duration;
use warpin_transport::{
    Limits,
    codec::Fixed,
    tcp::{Connection, Listener},
    udp::{Socket, Sources},
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        timeout: Duration::from_secs(2),
        max_frame_bytes: 1024,
    };
    let listener = Listener::bind("127.0.0.1:0".parse()?, 1, limits).await?;
    let mut client = Connection::connect(listener.local_addr()?, limits).await?;
    let (mut server, _) = listener.accept().await?;
    client.write_frame(b"hello").await?;
    assert_eq!(server.read_frame(&mut Fixed(5)).await?, b"hello");
    client.close().await?;
    let a = Socket::bind("127.0.0.1:0".parse()?, limits, Sources::Any).await?;
    let b = Socket::bind(
        "127.0.0.1:0".parse()?,
        limits,
        Sources::Only(vec![a.local_addr()?]),
    )
    .await?;
    a.send(b.local_addr()?, b"hello").await?;
    assert_eq!(b.recv().await?.payload, b"hello");
    Ok(())
}
