use reqwest::{Method, header::HeaderMap};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use warpin_errors::protocol::Kind;
use warpin_http::transport::{Authentication, HttpLimits, HttpTransport, Security};
fn limits() -> HttpLimits {
    HttpLimits {
        connect_timeout: Duration::from_secs(1),
        read_timeout: Duration::from_secs(1),
        total_timeout: Duration::from_secs(2),
        max_request_bytes: 128,
        max_response_bytes: 64,
        max_in_flight: 1,
    }
}
async fn peer(response: &'static [u8]) -> (HttpTransport, tokio::task::JoinHandle<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let url = format!("http://{}/api/", l.local_addr().expect("addr"));
    let handle = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut b = vec![0; 4096];
        let n = s.read(&mut b).await.expect("read");
        assert!(n > 0);
        b.truncate(n);
        s.write_all(response).await.expect("response");
        b
    });
    (
        HttpTransport::new(
            &url,
            Security::PlaintextAllowed,
            Authentication::Bearer("test-only".into()),
            limits(),
        )
        .expect("client"),
        handle,
    )
}
#[tokio::test]
async fn status_json_and_credentials() {
    let(c,h)=peer(b"HTTP/1.1 422 Unprocessable Entity\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"error\":1}").await;
    let r = c
        .request(Method::GET, "item", HeaderMap::new(), vec![])
        .await
        .expect("response");
    assert_eq!(r.status(), 422);
    assert_eq!(
        r.json::<serde_json::Value>().await.expect("json")["error"],
        1
    );
    let sent = String::from_utf8(h.await.expect("join")).expect("utf8");
    assert!(sent.contains("/api/item"));
    assert!(
        sent.to_lowercase()
            .contains("authorization: bearer test-only")
    );
}
#[tokio::test]
async fn advertised_and_chunked_limits() {
    for data in [b"HTTP/1.1 200 OK\r\nContent-Length: 65\r\nConnection: close\r\n\r\n".as_slice(),b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n41\r\n01234567890123456789012345678901234567890123456789012345678901234\r\n0\r\n\r\n"]{
 let(c,h)=peer(data).await;let e=match c.request(Method::GET,"x",HeaderMap::new(),vec![]).await{Err(e)=>e,Ok(r)=>r.bytes().await.expect_err("over limit")};assert_eq!(e.kind,Kind::Capacity);h.await.expect("join");}
}
#[tokio::test]
async fn redirects_capacity_path_and_decode() {
    let(c,h)=peer(b"HTTP/1.1 302 Found\r\nLocation: http://invalid.example/\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx").await;
    for path in [
        "//evil.example/",
        "../secret",
        "%2e%2e/secret",
        "https://evil.example/",
        "x#fragment",
        "/root",
    ] {
        assert!(
            matches!(c.request(Method::GET,path,HeaderMap::new(),vec![]).await,Err(e) if e.kind==Kind::Configuration)
        );
    }
    let r = c
        .request(Method::GET, "x", HeaderMap::new(), vec![])
        .await
        .expect("302");
    assert_eq!(r.status(), 302);
    assert!(
        matches!(c.request(Method::GET,"x",HeaderMap::new(),vec![]).await,Err(e) if e.kind==Kind::Capacity)
    );
    assert_eq!(
        r.json::<serde_json::Value>()
            .await
            .expect_err("invalid JSON")
            .kind,
        Kind::Protocol
    );
    h.await.expect("join");
    assert!(
        HttpTransport::new(
            "http://localhost/",
            Security::Https,
            Authentication::None,
            limits()
        )
        .is_err()
    );
}
#[tokio::test]
async fn write_deadline_is_unknown_and_secrets_redacted() {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let c = HttpTransport::new(
        &format!("http://{}/", l.local_addr().expect("addr")),
        Security::PlaintextAllowed,
        Authentication::None,
        HttpLimits {
            connect_timeout: Duration::from_millis(30),
            read_timeout: Duration::from_millis(30),
            total_timeout: Duration::from_millis(30),
            ..limits()
        },
    )
    .expect("client");
    let h = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut b = [0; 1024];
        assert!(s.read(&mut b).await.expect("read") > 0);
        tokio::time::sleep(Duration::from_millis(100)).await;
    });
    assert!(
        matches!(c.request(Method::POST,"x",HeaderMap::new(),vec![1]).await,Err(e) if e.kind==Kind::OutcomeUnknown)
    );
    h.await.expect("join");
    let e = HttpTransport::new(
        "http://user:password@localhost/",
        Security::PlaintextAllowed,
        Authentication::None,
        limits(),
    )
    .err()
    .expect("invalid");
    assert!(!format!("{e:?} {e}").contains("password"));
}
#[tokio::test]
async fn private_ca_https_and_wrong_name() {
    use warpin_transport::{
        Limits,
        tls::{ClientTls, Identity, ServerTls},
    };
    let id = Identity {
        certificate_pem: include_bytes!("fixtures/localhost.pem").to_vec(),
        private_key_pem: include_bytes!("fixtures/localhost.key").to_vec(),
    };
    let ca = include_bytes!("fixtures/ca.pem");
    let tls = ServerTls::new(&id, None).expect("tls");
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("https://{}/", l.local_addr().expect("addr"));
    let h = tokio::spawn(async move {
        let (s, _) = l.accept().await.expect("accept");
        let mut c = tls
            .accept(
                s,
                Limits {
                    timeout: Duration::from_secs(3),
                    max_frame_bytes: 4096,
                },
            )
            .await
            .expect("handshake");
        c.read_chunk().await.expect("request");
        c.write_frame(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("response");
    });
    let c = HttpTransport::new(
        &url,
        Security::CustomTls(ClientTls::new(ca, None).expect("ca")),
        Authentication::None,
        limits(),
    )
    .expect("client");
    assert_eq!(
        c.request(Method::GET, "x", HeaderMap::new(), vec![])
            .await
            .expect("request")
            .bytes()
            .await
            .expect("body"),
        b"ok"
    );
    h.await.expect("join");
}
