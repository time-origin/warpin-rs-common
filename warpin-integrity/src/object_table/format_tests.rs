use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Serialize, Serializer};
use serde_json::{Value, json};

use super::{
    Document, ObjectTableFormat, ObjectTableLimits, Work, object_table_decode,
    object_table_decode_with_format, object_table_encode, object_table_encode_with_format,
};
use crate::{canonical_bytes, digest_bytes};

const V2: ObjectTableFormat = ObjectTableFormat::ShortReferencesV2;
fn limits() -> ObjectTableLimits {
    ObjectTableLimits::new(1024 * 1024, 16 * 1024 * 1024).unwrap()
}
fn source() -> Value {
    json!(vec!["neutral complete instruction ".repeat(12); 6])
}
fn document() -> Document {
    serde_json::from_slice(&object_table_encode_with_format(&source(), V2, limits()).unwrap())
        .unwrap()
}
fn reject(doc: &Document) {
    assert!(object_table_decode_with_format(&canonical_bytes(doc).unwrap(), V2, limits()).is_err());
}

#[test]
fn legacy_bytes_and_explicit_format_are_stable() {
    let source = json!(vec!["legacy immutable instruction ".repeat(8); 4]);
    let golden = include_bytes!("fixtures/v1-repeated-golden.json");
    assert_eq!(object_table_encode(&source, limits()).unwrap(), golden);
    assert_eq!(
        object_table_encode_with_format(&source, ObjectTableFormat::IndexedV1, limits()).unwrap(),
        golden
    );
    assert_eq!(object_table_decode(golden, limits()).unwrap(), source);
    assert!(object_table_decode_with_format(golden, V2, limits()).is_err());
    let v2 = object_table_encode_with_format(&source, V2, limits()).unwrap();
    assert!(object_table_decode(&v2, limits()).is_err());
    assert!(object_table_decode_with_format(&v2, ObjectTableFormat::IndexedV1, limits()).is_err());
}

#[test]
fn references_do_not_double_count_expanded_source_nodes() {
    // 66,001 source nodes fit the existing bound. Reference indirections used
    // to count again, rejecting the encoder's own small compressed document.
    let sources = [
        json!(vec![
            vec!["neutral repeated directory reference body"; 10];
            6000
        ]),
        json!(vec!["neutral repeated directory reference body"; 60_000]),
    ];
    for (shape, source) in sources.into_iter().enumerate() {
        for format in [V2, ObjectTableFormat::IndexedV1] {
            // V1's longer reference key makes this flat document exceed 1 MiB.
            let wire_budget = if shape == 1 && format == ObjectTableFormat::IndexedV1 {
                assert!(object_table_encode_with_format(&source, format, limits()).is_err());
                2 * 1024 * 1024
            } else {
                1024 * 1024
            };
            let limits = ObjectTableLimits::new(wire_budget, 16 * 1024 * 1024).unwrap();
            let wire = object_table_encode_with_format(&source, format, limits).unwrap();
            assert!(wire.len() < wire_budget);
            assert_eq!(
                object_table_decode_with_format(&wire, format, limits).unwrap(),
                source
            );
        }
    }
}

#[test]
fn short_references_roundtrip_complete_values_and_capture_once() {
    let value = json!({"rows": (0..95).map(|i| json!({"id":i,"instructions":source(),"parameters":{"required":true,"order":[2,1]}})).collect::<Vec<_>>()});
    let wire = object_table_encode_with_format(&value, V2, limits()).unwrap();
    assert_eq!(
        object_table_decode_with_format(&wire, V2, limits()).unwrap(),
        value
    );
    assert_eq!(
        object_table_encode_with_format(&value, V2, limits()).unwrap(),
        wire
    );
    let parsed: Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(parsed["schemaVersion"], "warpin-indexed-json/v2");
    assert!(!parsed["objects"].as_object().unwrap().is_empty());
    struct Once<'a>(&'a AtomicUsize);
    impl Serialize for Once<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            assert_eq!(self.0.fetch_add(1, Ordering::SeqCst), 0);
            source().serialize(serializer)
        }
    }
    let calls = AtomicUsize::new(0);
    object_table_encode_with_format(&Once(&calls), V2, limits()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn format_reserves_only_its_own_token_and_preserves_nested_v1() {
    let legacy = object_table_encode(&source(), limits()).unwrap();
    let legacy_value: Value = serde_json::from_slice(&legacy).unwrap();
    let retained = json!({"encodedLegacy":legacy_value,"literal":{"$objectRef":"ordinary source"}});
    let wire = object_table_encode_with_format(&retained, V2, limits()).unwrap();
    let decoded = object_table_decode_with_format(&wire, V2, limits()).unwrap();
    assert_eq!(decoded, retained);
    assert_eq!(canonical_bytes(&decoded["encodedLegacy"]).unwrap(), legacy);
    assert!(object_table_encode_with_format(&json!({"$r":"literal"}), V2, limits()).is_err());
    let legacy_literal = json!({"$r":"ordinary v1 source"});
    let wire = object_table_encode(&legacy_literal, limits()).unwrap();
    assert_eq!(
        object_table_decode(&wire, limits()).unwrap(),
        legacy_literal
    );
}

#[test]
fn short_format_rejects_wrong_header_duplicate_unknown_and_digest_drift() {
    let raw = object_table_encode_with_format(&source(), V2, limits()).unwrap();
    let mut doc = document();
    doc.schema_version = "warpin-indexed-json/v1".into();
    reject(&doc);
    let mut doc = document();
    doc.source_digest = digest_bytes(b"foreign source").to_string();
    reject(&doc);
    let mut value: Value = serde_json::from_slice(&raw).unwrap();
    value["unknown"] = json!(true);
    assert!(
        object_table_decode_with_format(&canonical_bytes(&value).unwrap(), V2, limits()).is_err()
    );
    assert!(object_table_decode_with_format(br#"{"schemaVersion":"warpin-indexed-json/v2","schemaVersion":"warpin-indexed-json/v2"}"#, V2, limits()).is_err());
    let mut noncanonical = vec![b' '];
    noncanonical.extend(raw);
    assert!(object_table_decode_with_format(&noncanonical, V2, limits()).is_err());
}

#[test]
fn short_format_rejects_invalid_unknown_unused_and_cyclic_indices() {
    for index in ["01", "-1", "+1", "2", "99999999999999999999999999"] {
        let mut doc = document();
        let body = doc.objects.remove("0").unwrap();
        doc.objects.insert(index.into(), body);
        reject(&doc);
    }
    let mut doc = document();
    doc.objects.insert("1".into(), json!("unused"));
    reject(&doc);
    let mut doc = document();
    doc.objects.insert("0".into(), json!({"$r":"0"}));
    reject(&doc);
    for value in [
        json!({"$r":0}),
        json!({"$r":"0","extra":true}),
        json!({"$r":"2"}),
    ] {
        let mut doc = document();
        doc.root = json!([value]);
        reject(&doc);
    }
}

#[test]
fn short_format_requires_profit_and_expanded_hash_order() {
    let doc = Document {
        schema_version: "warpin-indexed-json/v2".into(),
        source_digest: digest_bytes(b"[0,0]").to_string(),
        root: json!([{"$r":"0"},{"$r":"0"}]),
        objects: [("0".into(), json!(0))].into(),
    };
    reject(&doc);
    let original = json!([
        "a".repeat(200),
        "b".repeat(200),
        "a".repeat(200),
        "b".repeat(200)
    ]);
    let raw = object_table_encode_with_format(&original, V2, limits()).unwrap();
    let mut doc: Document = serde_json::from_slice(&raw).unwrap();
    let zero = doc.objects.remove("0").unwrap();
    let one = doc.objects.remove("1").unwrap();
    doc.objects.insert("0".into(), one);
    doc.objects.insert("1".into(), zero);
    for row in doc.root.as_array_mut().unwrap() {
        let index = row["$r"].as_str().unwrap();
        *row = json!({"$r":if index == "0" {"1"} else {"0"}});
    }
    reject(&doc);
}

#[test]
fn short_format_keeps_wire_expansion_depth_and_node_limits() {
    let raw = object_table_encode_with_format(&source(), V2, limits()).unwrap();
    assert!(
        object_table_decode_with_format(
            &raw,
            V2,
            ObjectTableLimits::new(raw.len() - 1, 16 * 1024 * 1024).unwrap()
        )
        .is_err()
    );
    assert!(
        object_table_decode_with_format(
            &raw,
            V2,
            ObjectTableLimits::new(1024 * 1024, 128).unwrap()
        )
        .is_err()
    );
    let mut doc = document();
    for n in 1..30 {
        doc.objects.insert(
            n.to_string(),
            json!(vec![json!({"$r":(n-1).to_string()}); 8]),
        );
    }
    doc.root = json!([{"$r":"29"},{"$r":"29"}]);
    assert!(
        super::unprofitable(&doc, limits(), &mut Work::with_format(V2))
            .unwrap()
            .is_empty()
    );
    reject(&doc);
    let mut deep = json!(0);
    for _ in 0..130 {
        deep = json!([deep]);
    }
    assert!(object_table_encode_with_format(&deep, V2, limits()).is_err());
    assert!(object_table_encode_with_format(&json!(vec![0; 100_001]), V2, limits()).is_err());
}
