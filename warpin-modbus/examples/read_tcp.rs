//! Explicit read-only example: address:port unit zero-based-register quantity.
use std::time::Duration;
use warpin_modbus::{Client, Request};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 5 {
        return Err("provide address:port unit register quantity (explicit plaintext TCP)".into());
    }
    let mut c =
        Client::connect_tcp_plaintext(a[1].parse()?, a[2].parse()?, Duration::from_secs(2)).await?;
    let response = c
        .call(Request::ReadHoldingRegisters(a[3].parse()?, a[4].parse()?))
        .await?;
    println!("{response:?}");
    c.close().await?;
    Ok(())
}
