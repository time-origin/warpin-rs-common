use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use warpin_errors::protocol::Kind;
use warpin_modbus::{Client, Error, ExceptionCode, Request, Response};
fn deadline() -> Duration {
    Duration::from_secs(1)
}
#[tokio::test]
async fn tcp_read_exception_and_echo_validation() {
    let (a, mut b) = tokio::io::duplex(256);
    let mut c = Client::attach_tcp(a, 1, deadline()).expect("attach");
    let h = tokio::spawn(async move {
        for response in [vec![3, 2, 0x12, 0x34], vec![0x83, 2], vec![6, 0, 2, 0, 9]] {
            let mut q = [0; 12];
            b.read_exact(&mut q).await.expect("query");
            let mut header = q[..7].to_vec();
            header[4..6].copy_from_slice(&((response.len() + 1) as u16).to_be_bytes());
            header.extend(response);
            b.write_all(&header).await.expect("reply");
        }
    });
    assert_eq!(
        c.call(Request::ReadHoldingRegisters(0, 1))
            .await
            .expect("read"),
        Response::ReadHoldingRegisters(vec![0x1234])
    );
    assert!(matches!(
        c.call(Request::ReadHoldingRegisters(0, 1)).await,
        Err(Error::Exception(ExceptionCode::IllegalDataAddress))
    ));
    assert!(!c.is_closed());
    assert!(
        matches!(c.call(Request::WriteSingleRegister(1,9)).await,Err(Error::Transport(e)) if e.kind==Kind::OutcomeUnknown)
    );
    assert!(c.is_closed());
    h.await.expect("join");
}
#[tokio::test]
async fn wrong_transaction_id_and_cancelled_request() {
    let (a, mut b) = tokio::io::duplex(256);
    let mut c = Client::attach_tcp(a, 1, deadline()).expect("attach");
    let h = tokio::spawn(async move {
        let mut q = [0; 12];
        b.read_exact(&mut q).await.expect("query");
        q[0] ^= 1;
        b.write_all(&[q[0], q[1], 0, 0, 0, 5, 1, 3, 2, 0, 1])
            .await
            .expect("reply");
    });
    assert!(
        matches!(c.call(Request::ReadHoldingRegisters(0,1)).await,Err(Error::Transport(e)) if e.kind==Kind::Protocol)
    );
    assert!(c.is_closed());
    h.await.expect("join");
    let (a, _b) = tokio::io::duplex(256);
    let mut c = Client::attach_tcp(a, 1, deadline()).expect("attach");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            c.call(Request::ReadHoldingRegisters(0, 1))
        )
        .await
        .is_err()
    );
    assert!(c.is_closed());
}
fn crc(bytes: &[u8]) -> [u8; 2] {
    let mut c = 0xffffu16;
    for b in bytes {
        c ^= u16::from(*b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xa001
            } else {
                c >> 1
            };
        }
    }
    c.to_le_bytes()
}
#[cfg(unix)]
#[tokio::test]
async fn real_virtual_serial_rtu_and_crc_failure() {
    for corrupt in [false, true] {
        let (a, mut b) = tokio_serial::SerialStream::pair().expect("PTY pair");
        let mut c = Client::attach_rtu(a, 1, deadline()).expect("attach");
        let h = tokio::spawn(async move {
            let mut q = [0; 8];
            b.read_exact(&mut q).await.expect("request");
            assert_eq!(&q[..6], &[1, 3, 0, 0, 0, 1]);
            assert_eq!(&q[6..], &crc(&q[..6]));
            let mut r = vec![1, 3, 2, 0, 42];
            r.extend(crc(&r));
            if corrupt {
                r[6] ^= 1;
            }
            b.write_all(&r).await.expect("reply");
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let r = c.call(Request::ReadHoldingRegisters(0, 1)).await;
        if corrupt {
            assert!(r.is_err());
            assert!(c.is_closed());
        } else {
            assert_eq!(r.expect("RTU"), Response::ReadHoldingRegisters(vec![42]));
        }
        h.await.expect("join");
    }
}

#[tokio::test]
async fn all_supported_function_codes_have_exact_wire_requests_and_validated_responses() {
    let cases = vec![
        (
            Request::ReadCoils(10, 3),
            vec![1, 0, 10, 0, 3],
            vec![1, 1, 5],
            Response::ReadCoils(vec![true, false, true]),
        ),
        (
            Request::ReadDiscreteInputs(10, 3),
            vec![2, 0, 10, 0, 3],
            vec![2, 1, 2],
            Response::ReadDiscreteInputs(vec![false, true, false]),
        ),
        (
            Request::ReadHoldingRegisters(10, 2),
            vec![3, 0, 10, 0, 2],
            vec![3, 4, 0, 42, 0, 43],
            Response::ReadHoldingRegisters(vec![42, 43]),
        ),
        (
            Request::ReadInputRegisters(10, 2),
            vec![4, 0, 10, 0, 2],
            vec![4, 4, 0, 42, 0, 43],
            Response::ReadInputRegisters(vec![42, 43]),
        ),
        (
            Request::WriteSingleCoil(10, true),
            vec![5, 0, 10, 255, 0],
            vec![5, 0, 10, 255, 0],
            Response::WriteSingleCoil(10, true),
        ),
        (
            Request::WriteSingleRegister(10, 42),
            vec![6, 0, 10, 0, 42],
            vec![6, 0, 10, 0, 42],
            Response::WriteSingleRegister(10, 42),
        ),
        (
            Request::WriteMultipleCoils(10, vec![true, false, true].into()),
            vec![15, 0, 10, 0, 3, 1, 5],
            vec![15, 0, 10, 0, 3],
            Response::WriteMultipleCoils(10, 3),
        ),
        (
            Request::WriteMultipleRegisters(10, vec![42, 43].into()),
            vec![16, 0, 10, 0, 2, 4, 0, 42, 0, 43],
            vec![16, 0, 10, 0, 2],
            Response::WriteMultipleRegisters(10, 2),
        ),
        (
            Request::MaskWriteRegister(10, 0xff00, 0x00f0),
            vec![22, 0, 10, 255, 0, 0, 240],
            vec![22, 0, 10, 255, 0, 0, 240],
            Response::MaskWriteRegister(10, 0xff00, 0x00f0),
        ),
        (
            Request::ReadWriteMultipleRegisters(10, 2, 20, vec![42].into()),
            vec![23, 0, 10, 0, 2, 0, 20, 0, 1, 2, 0, 42],
            vec![23, 4, 0, 1, 0, 2],
            Response::ReadWriteMultipleRegisters(vec![1, 2]),
        ),
    ];
    for (request, wire, reply, expected) in cases {
        for rtu in [false, true] {
            let (a, mut b) = tokio::io::duplex(1024);
            let mut c = if rtu {
                Client::attach_rtu(a, 1, deadline())
            } else {
                Client::attach_tcp(a, 1, deadline())
            }
            .expect("client");
            let wire = wire.clone();
            let reply = reply.clone();
            let h = tokio::spawn(async move {
                if rtu {
                    let mut q = vec![0; wire.len() + 3];
                    b.read_exact(&mut q).await.expect("RTU request");
                    assert_eq!(q[0], 1);
                    assert_eq!(&q[1..q.len() - 2], wire);
                    assert_eq!(&q[q.len() - 2..], crc(&q[..q.len() - 2]));
                    let mut r = vec![1];
                    r.extend(reply);
                    r.extend(crc(&r));
                    b.write_all(&r).await.expect("RTU reply");
                } else {
                    let mut header = [0; 7];
                    b.read_exact(&mut header).await.expect("MBAP");
                    assert_eq!(&header[2..4], &[0, 0]);
                    assert_eq!(header[6], 1);
                    let mut pdu =
                        vec![0; usize::from(u16::from_be_bytes([header[4], header[5]])) - 1];
                    b.read_exact(&mut pdu).await.expect("PDU");
                    assert_eq!(pdu, wire);
                    header[4..6].copy_from_slice(&((reply.len() + 1) as u16).to_be_bytes());
                    b.write_all(&header).await.expect("header");
                    b.write_all(&reply).await.expect("reply");
                }
            });
            assert_eq!(
                c.call(request.clone()).await.expect("validated response"),
                expected
            );
            h.await.expect("join");
        }
    }
}
