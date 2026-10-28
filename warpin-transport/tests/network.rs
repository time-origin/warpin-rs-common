use std::time::Duration;
use tokio::io::AsyncWriteExt;
use warpin_errors::protocol::Kind;
use warpin_transport::{
    Limits,
    codec::{Delimited, Fixed},
    tcp::{Connection, Listener},
    tls::{ClientTls, Identity, ServerTls},
    udp::{Socket, Sources},
};
fn limits() -> Limits {
    Limits {
        timeout: Duration::from_secs(2),
        max_frame_bytes: 64,
    }
}
fn addr() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("address")
}
#[tokio::test]
async fn split_coalesced_and_truncated_frames() {
    let (a, mut b) = tokio::io::duplex(64);
    let mut c = Connection::new(a, limits()).expect("client");
    b.write_all(b"one\ntwo\nend").await.expect("send");
    b.shutdown().await.expect("close");
    assert_eq!(
        c.read_frame(&mut Delimited(b'\n')).await.expect("one"),
        b"one\n"
    );
    assert_eq!(c.read_frame(&mut Fixed(4)).await.expect("two"), b"two\n");
    assert_eq!(
        c.read_frame(&mut Fixed(4))
            .await
            .expect_err("truncated")
            .kind,
        Kind::Protocol
    );
    assert_eq!(
        c.write_frame(b"x").await.expect_err("poisoned").kind,
        Kind::Closed
    );
}
#[tokio::test]
async fn cancelled_read_poisoned_and_write_outcome_unknown() {
    let (a, _b) = tokio::io::duplex(1);
    let mut c = Connection::new(a, limits()).expect("client");
    assert!(
        tokio::time::timeout(Duration::from_millis(10), c.read_frame(&mut Fixed(1)))
            .await
            .is_err()
    );
    assert_eq!(
        c.write_frame(b"a").await.expect_err("cancelled read").kind,
        Kind::Closed
    );
    let (a, _b) = tokio::io::duplex(1);
    let mut c = Connection::new(
        a,
        Limits {
            timeout: Duration::from_millis(10),
            ..limits()
        },
    )
    .expect("client");
    assert_eq!(
        c.write_frame(b"ab").await.expect_err("partial write").kind,
        Kind::OutcomeUnknown
    );
    assert_eq!(
        c.read_frame(&mut Fixed(1))
            .await
            .expect_err("poisoned")
            .kind,
        Kind::Closed
    );
}
#[tokio::test]
async fn listener_capacity_and_release() {
    let listener = Listener::bind(addr(), 1, limits()).await.expect("listen");
    let _client = Connection::connect(listener.local_addr().expect("addr"), limits())
        .await
        .expect("connect");
    let (server, _) = listener.accept().await.expect("accept");
    assert!(matches!(listener.accept().await,Err(e) if e.kind==Kind::Capacity));
    drop(server);
    let _other = Connection::connect(listener.local_addr().expect("addr"), limits())
        .await
        .expect("connect");
    listener.accept().await.expect("released");
}
#[tokio::test]
async fn udp_whole_datagrams_duplicates_oversize_and_filter() {
    let a = Socket::bind(addr(), limits(), Sources::Any)
        .await
        .expect("a");
    let b = Socket::bind(
        addr(),
        Limits {
            max_frame_bytes: 4,
            ..limits()
        },
        Sources::Only(vec![a.local_addr().expect("addr")]),
    )
    .await
    .expect("b");
    for payload in [b"".as_slice(), b"same", b"same"] {
        a.send(b.local_addr().expect("addr"), payload)
            .await
            .expect("send");
        let d = b.recv().await.expect("recv");
        assert_eq!(d.payload, payload);
        assert_eq!(d.peer, a.local_addr().expect("addr"));
    }
    a.send(b.local_addr().expect("addr"), b"large")
        .await
        .expect("send");
    assert!(matches!(b.recv().await,Err(e) if e.kind==Kind::Capacity));
    let outsider = Socket::bind(addr(), limits(), Sources::Any)
        .await
        .expect("other");
    outsider
        .send(b.local_addr().expect("addr"), b"x")
        .await
        .expect("send");
    assert!(matches!(b.recv().await,Err(e) if e.kind==Kind::Rejected));
}
fn identity() -> Identity {
    Identity {
        certificate_pem: include_bytes!("fixtures/localhost.pem").to_vec(),
        private_key_pem: include_bytes!("fixtures/localhost.key").to_vec(),
    }
}
#[tokio::test]
async fn mutual_tls_and_wrong_hostname() {
    let ca = include_bytes!("fixtures/ca.pem");
    let id = identity();
    let server = ServerTls::new(&id, Some(ca)).expect("server TLS");
    let client = ClientTls::new(ca, Some(&id)).expect("client TLS");
    let (a, b) = tokio::io::duplex(8192);
    let (s, c) = tokio::join!(
        server.accept(a, limits()),
        client.connect(b, "localhost", limits())
    );
    let (mut s, mut c) = (s.expect("server"), c.expect("client"));
    c.write_frame(b"ok").await.expect("write");
    assert_eq!(s.read_frame(&mut Fixed(2)).await.expect("read"), b"ok");
    let (a, b) = tokio::io::duplex(8192);
    let (_, c) = tokio::join!(
        server.accept(a, limits()),
        client.connect(b, "wrong.example", limits())
    );
    assert!(matches!(c,Err(e) if e.kind==Kind::Authentication));
    assert!(ClientTls::new(b"invalid", None).is_err());
}
#[tokio::test]
async fn oversize_frame_and_configuration() {
    let (a, mut b) = tokio::io::duplex(128);
    let mut c = Connection::new(a, limits()).expect("client");
    b.write_all(&[b'a'; 64]).await.expect("write");
    assert_eq!(
        c.read_frame(&mut Delimited(b'\n'))
            .await
            .expect_err("bounded")
            .kind,
        Kind::Capacity
    );
    assert!(
        Limits {
            timeout: Duration::ZERO,
            ..limits()
        }
        .validate()
        .is_err()
    );
}
