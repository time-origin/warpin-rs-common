//! Usage: cargo run -p warpin-http --example http_get -- https://host/api/ relative/path
use std::time::Duration;
use warpin_http::transport::{Authentication, HttpLimits, HttpTransport, Security};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("provide HTTPS base URL ending in / and relative path".into());
    }
    let c = HttpTransport::new(
        &args[1],
        Security::Https,
        Authentication::None,
        HttpLimits {
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(10),
            max_request_bytes: 1024,
            max_response_bytes: 1024 * 1024,
            max_in_flight: 4,
        },
    )?;
    let r = c
        .request(
            reqwest::Method::GET,
            &args[2],
            reqwest::header::HeaderMap::new(),
            vec![],
        )
        .await?;
    let status = r.status();
    let bytes = r.bytes().await?;
    println!("HTTP {status}; {} bytes", bytes.len());
    Ok(())
}
