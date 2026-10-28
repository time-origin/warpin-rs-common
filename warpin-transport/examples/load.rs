//! Local echo load measurement; no claim about production throughput or physical devices.
use std::time::{Duration, Instant};
use warpin_transport::{
    Limits,
    codec::Fixed,
    tcp::{Connection, Listener},
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let count = 10_000usize;
    let limits = Limits {
        timeout: Duration::from_secs(5),
        max_frame_bytes: 1024,
    };
    let listener = Listener::bind("127.0.0.1:0".parse()?, 1, limits).await?;
    let mut client = Connection::connect(listener.local_addr()?, limits).await?;
    let (mut server, _) = listener.accept().await?;
    let start = Instant::now();
    let producer = async {
        let mut latencies = Vec::with_capacity(count);
        for _ in 0..count {
            let t = Instant::now();
            client.write_frame(&[7; 64]).await?;
            let response = client.read_frame(&mut Fixed(64)).await?;
            assert_eq!(response, [7; 64]);
            latencies.push(t.elapsed().as_micros());
        }
        Ok::<_, warpin_errors::protocol::ProtocolError>(latencies)
    };
    let consumer = async {
        for _ in 0..count {
            let data = server.read_frame(&mut Fixed(64)).await?;
            server.write_frame(&data).await?;
        }
        Ok::<_, warpin_errors::protocol::ProtocolError>(())
    };
    let (mut latencies, _) = tokio::try_join!(producer, consumer)?;
    let elapsed = start.elapsed();
    latencies.sort_unstable();
    println!(
        "frames={count} bytes=64 connections=1 elapsed_ms={} p50_us={} p99_us={} configured_buffer_bytes=1024",
        elapsed.as_millis(),
        latencies[count / 2],
        latencies[count * 99 / 100]
    );
    Ok(())
}
