use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Serialize, Serializer};
use serde_json::{Value, json};

use super::{Document, ObjectTableLimits, SCHEMA, object_table_decode, object_table_encode};
use crate::{canonical_bytes, digest_bytes};

fn limits() -> ObjectTableLimits {
    ObjectTableLimits::new(1024 * 1024, 16 * 1024 * 1024).unwrap()
}
fn repeated() -> Value {
    json!(vec!["long retained immutable instruction ".repeat(12); 6])
}
fn document(value: &Value) -> Document {
    serde_json::from_slice(&object_table_encode(value, limits()).unwrap()).unwrap()
}
fn reject(document: &Document) {
    assert!(object_table_decode(&canonical_bytes(document).unwrap(), limits()).is_err());
}

#[test]
fn scalar_container_and_array_order_roundtrip() {
    let value = json!({"steps":(0..95).map(|n| json!({"id":n,"instruction":"retain every applicable constraint ".repeat(20),"policy":{"required":true,"input":["x","y"]}})).collect::<Vec<_>>()});
    let encoded = object_table_encode(&value, limits()).unwrap();
    assert!(encoded.len() < canonical_bytes(&value).unwrap().len());
    assert_eq!(object_table_decode(&encoded, limits()).unwrap(), value);
    assert_eq!(object_table_encode(&value, limits()).unwrap(), encoded);
}

#[test]
fn captures_caller_once_and_keeps_old_api_bounds() {
    struct Stateful<'a>(&'a AtomicUsize);
    impl Serialize for Stateful<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            assert_eq!(self.0.fetch_add(1, Ordering::SeqCst), 0);
            repeated().serialize(serializer)
        }
    }
    let count = AtomicUsize::new(0);
    object_table_encode(&Stateful(&count), limits()).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let large = json!(vec!["neutral complete source ".repeat(10_000); 6]);
    assert!(canonical_bytes(&large).is_err());
    let encoded = object_table_encode(&large, limits()).unwrap();
    assert_eq!(object_table_decode(&encoded, limits()).unwrap(), large);
}

#[test]
fn wire_and_expansion_budgets_are_independent() {
    assert!(ObjectTableLimits::new(0, 1).is_err());
    assert!(ObjectTableLimits::new(1, 16 * 1024 * 1024 + 1).is_err());
    let raw = object_table_encode(&repeated(), limits()).unwrap();
    assert!(
        object_table_decode(
            &raw,
            ObjectTableLimits::new(raw.len() - 1, 16 * 1024 * 1024).unwrap()
        )
        .is_err()
    );
    assert!(object_table_decode(&raw, ObjectTableLimits::new(1024 * 1024, 128).unwrap()).is_err());
}

#[test]
fn strict_document_and_reserved_literal_keys() {
    assert!(object_table_encode(&json!({"$objectRef":"literal"}), limits()).is_err());
    assert!(
        object_table_decode(br#"{"schemaVersion":"x","schemaVersion":"x"}"#, limits()).is_err()
    );
    let mut value: Value =
        serde_json::from_slice(&object_table_encode(&repeated(), limits()).unwrap()).unwrap();
    value["foreign"] = json!(1);
    assert!(object_table_decode(&canonical_bytes(&value).unwrap(), limits()).is_err());
    let mut doc = document(&repeated());
    doc.schema_version = "unknown".into();
    reject(&doc);
    let mut doc = document(&repeated());
    doc.source_digest = digest_bytes(b"other").to_string();
    reject(&doc);
    let raw = object_table_encode(&repeated(), limits()).unwrap();
    let mut spaced = vec![b' '];
    spaced.extend(raw);
    assert!(object_table_decode(&spaced, limits()).is_err());
}

#[test]
fn rejects_index_drift_unused_cycle_and_extra_reference_fields() {
    for key in ["01", "-1", "+1", "9999999999999999999999999999", "2"] {
        let mut doc = document(&repeated());
        let body = doc.objects.remove("0").unwrap();
        doc.objects.insert(key.into(), body);
        reject(&doc);
    }
    let mut doc = document(&repeated());
    doc.objects.insert("1".into(), json!("unused"));
    reject(&doc);
    let mut doc = document(&repeated());
    doc.objects.insert("0".into(), json!({"$objectRef":"0"}));
    reject(&doc);
    let mut doc = document(&repeated());
    doc.root = json!([{"$objectRef":"0","extra":true}]);
    reject(&doc);
    let mut doc = document(&repeated());
    doc.root = json!([{"$objectRef":0}]);
    reject(&doc);
}

#[test]
fn rejects_nonprofitable_and_hash_order_substitution() {
    let doc = Document {
        schema_version: SCHEMA.into(),
        source_digest: digest_bytes(b"[0,0]").to_string(),
        root: json!([{"$objectRef":"0"},{"$objectRef":"0"}]),
        objects: [("0".into(), json!(0))].into(),
    };
    reject(&doc);
    let source = json!([
        "a".repeat(200),
        "b".repeat(200),
        "a".repeat(200),
        "b".repeat(200)
    ]);
    let mut doc = document(&source);
    assert_eq!(doc.objects.len(), 2);
    let zero = doc.objects.remove("0").unwrap();
    let one = doc.objects.remove("1").unwrap();
    doc.objects.insert("0".into(), one);
    doc.objects.insert("1".into(), zero);
    if let Value::Array(items) = &mut doc.root {
        for item in items {
            let key = item["$objectRef"].as_str().unwrap();
            *item = json!({"$objectRef":if key=="0" {"1"} else {"0"}});
        }
    }
    reject(&doc);
}

#[test]
fn expands_references_under_resource_bounds_without_exponential_allocation() {
    let mut doc = document(&repeated());
    for n in 1..30 {
        doc.objects.insert(
            n.to_string(),
            json!(vec![json!({"$objectRef":(n-1).to_string()}); 8]),
        );
    }
    doc.root = json!([{"$objectRef":"29"},{"$objectRef":"29"}]);
    // This must reach the expansion budget, rather than passing merely
    // because the dictionary is rejected by its preceding profitability gate.
    assert!(
        super::unprofitable(&doc, limits(), &mut super::Work::new())
            .unwrap()
            .is_empty()
    );
    reject(&doc);
    let mut deep = json!(0);
    for _ in 0..130 {
        deep = json!([deep]);
    }
    assert!(object_table_encode(&deep, limits()).is_err());
}

#[test]
fn prunes_many_distinct_low_profit_values_without_quadratic_membership() {
    // Every value is repeated, but an indexed reference costs more than its
    // short scalar body. The complete candidate set is retired in one pass.
    let values = (0..10_000).flat_map(|n| [n, n]).collect::<Vec<_>>();
    let source = json!(values);
    let encoded = object_table_encode(&source, limits()).unwrap();
    let document: Document = serde_json::from_slice(&encoded).unwrap();
    assert!(document.objects.is_empty());
    assert_eq!(object_table_decode(&encoded, limits()).unwrap(), source);
}
