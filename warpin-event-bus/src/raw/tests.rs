use super::*;
use crate::{
    DurableEventRecord, EventConsumerImpl, NoOpConsumer, ProducerAttestationSigner,
    ProducerAttestationVerifier,
};
use rdkafka::message::{Header, OwnedHeaders, OwnedMessage, Timestamp};

fn message(
    key: Option<Vec<u8>>,
    payload: Option<Vec<u8>>,
    headers: Option<OwnedHeaders>,
) -> OwnedMessage {
    OwnedMessage::new(
        payload,
        key,
        "raw-topic".into(),
        Timestamp::NotAvailable,
        3,
        42,
        headers,
    )
}

#[test]
fn raw_record_preserves_binary_key_payload_and_original_coordinates_after_source_drop() {
    let original = message(Some(vec![0, 255, 128]), Some(vec![254, 0, 129]), None);
    let raw = OwnedRawMessage::from_message(&original);
    drop(original);
    assert_eq!(raw.topic, "raw-topic");
    assert_eq!(raw.partition, 3);
    assert_eq!(raw.offset, 42);
    assert_eq!(raw.key, Some(vec![0, 255, 128]));
    assert_eq!(raw.payload, Some(vec![254, 0, 129]));
    assert!(raw.headers.is_empty());
}

#[test]
fn raw_record_distinguishes_missing_and_empty_key_payload_and_headers() {
    let absent = OwnedRawMessage::from_message(&message(None, None, None));
    let empty = OwnedRawMessage::from_message(&message(
        Some(vec![]),
        Some(vec![]),
        Some(OwnedHeaders::new()),
    ));
    assert_eq!(absent.key, None);
    assert_eq!(absent.payload, None);
    assert_eq!(empty.key, Some(vec![]));
    assert_eq!(empty.payload, Some(vec![]));
    let headers = OwnedHeaders::new()
        .insert(Header {
            key: "duplicate",
            value: Some(&[255u8, 0][..]),
        })
        .insert(Header {
            key: "duplicate",
            value: None::<&[u8]>,
        })
        .insert(Header {
            key: "duplicate",
            value: Some(&[][..]),
        })
        .insert(Header {
            key: "last",
            value: Some(&[128u8][..]),
        });
    let raw = OwnedRawMessage::from_message(&message(None, None, Some(headers)));
    assert_eq!(
        raw.headers,
        vec![
            ("duplicate".into(), Some(vec![255, 0])),
            ("duplicate".into(), None),
            ("duplicate".into(), Some(vec![])),
            ("last".into(), Some(vec![128]))
        ]
    );
}

#[test]
fn raw_record_passes_original_binary_signed_record_to_the_public_verifier() {
    let signer = ProducerAttestationSigner::new(
        "fixture-producer",
        "key-a",
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap(),
    )
    .unwrap();
    let record = DurableEventRecord::new(
        "raw-topic",
        "tenant-a",
        vec![0, 255, 128],
        vec![254, 0, 129],
    )
    .unwrap();
    let record = signer.attest(record, "event-1", 100000, 160000).unwrap();
    let mut headers = OwnedHeaders::new();
    for header in record.headers() {
        headers = headers.insert(Header {
            key: header.name(),
            value: Some(header.value()),
        });
    }
    let original = message(
        Some(record.key().to_vec()),
        Some(record.payload().to_vec()),
        Some(headers),
    );
    let raw = OwnedRawMessage::from_message(&original);
    let mut verifier = ProducerAttestationVerifier::new(60000, 5000).unwrap();
    // RFC 8032 test-vector key pair; no external key or broker is used.
    let public =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    verifier
        .insert_verifying_key("fixture-producer", "key-a", public)
        .unwrap();
    let verify = |key: &[u8], payload: &[u8], headers: &[(String, Option<Vec<u8>>)]| {
        verifier.verify(
            &raw.topic,
            key,
            payload,
            headers.iter().map(|(n, v)| (n.as_str(), v.as_deref())),
            100001,
        )
    };
    let verified = verify(
        raw.key.as_deref().unwrap(),
        raw.payload.as_deref().unwrap(),
        &raw.headers,
    )
    .unwrap();
    assert_eq!(verified.tenant_id, "tenant-a");
    assert_eq!(verified.event_id, "event-1");
    assert!(
        verify(
            &[0, 255, 129],
            raw.payload.as_deref().unwrap(),
            &raw.headers
        )
        .is_err()
    );
    assert!(verify(raw.key.as_deref().unwrap(), &[254, 0, 130], &raw.headers).is_err());
    let mut duplicate = raw.headers.clone();
    duplicate.push(duplicate[0].clone());
    assert!(
        verify(
            raw.key.as_deref().unwrap(),
            raw.payload.as_deref().unwrap(),
            &duplicate
        )
        .is_err()
    );
}

#[tokio::test]
async fn raw_noop_and_switchable_noop_remain_cancelable_pending_receives() {
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(5), NoOpConsumer.recv_raw())
            .await
            .is_err()
    );
    let consumer = EventConsumerImpl::NoOp(NoOpConsumer);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(5), consumer.recv_raw())
            .await
            .is_err()
    );
}
