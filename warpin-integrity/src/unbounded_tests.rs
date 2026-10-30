use crate::*;
use serde_json::json;

#[test]
fn unbounded_bytes_nodes_depth_and_tokens_use_the_existing_algorithms() {
    let source = json!({"content": "a".repeat(17 * 1024 * 1024)});
    assert!(canonical_bytes(&source).is_err());
    let bytes = canonical_bytes_with_profile_unbounded(&source, CanonicalProfile::Rfc8785).unwrap();
    assert_eq!(
        parse_json_strict_unbounded(std::str::from_utf8(&bytes).unwrap()).unwrap(),
        source
    );
    assert!(parse_json_strict(std::str::from_utf8(&bytes).unwrap()).is_err());

    let many = vec![true; 100_001];
    assert!(canonical_bytes(&many).is_err());
    assert!(canonical_bytes_with_profile_unbounded(&many, CanonicalProfile::Rfc8785).is_ok());
    let nested = format!("{}true{}", "[".repeat(140), "]".repeat(140));
    assert!(parse_json_strict(&nested).is_err());
    let value = parse_json_strict_unbounded(&nested).unwrap();
    assert_eq!(
        canonical_bytes_with_profile_unbounded(&value, CanonicalProfile::Rfc8785).unwrap(),
        nested.as_bytes()
    );
    let token = format!("0.{}1", "0".repeat(2048));
    assert!(parse_json_strict(&token).is_err());
    assert!(parse_json_strict_unbounded(&token).is_ok());
}

#[test]
fn unbounded_keeps_digest_numeric_duplicate_and_format_semantics() {
    let source = json!({"ordered": [3, 1, 2], "repeat": vec!["unchanged repeated value"; 4]});
    let binding = DigestBinding::new("sample-domain", "sample-profile").unwrap();
    for profile in [
        CanonicalProfile::Rfc8785,
        CanonicalProfile::IJsonSafeIntegers,
    ] {
        assert_eq!(
            canonical_bytes_with_profile_unbounded(&source, profile).unwrap(),
            canonical_bytes_with_profile(&source, profile).unwrap()
        );
        assert_eq!(
            digest_bound_with_profile_unbounded(&binding, &source, profile).unwrap(),
            digest_bound_with_profile(&binding, &source, profile).unwrap()
        );
    }
    assert!(canonical_bytes_with_profile_unbounded(&u64::MAX, CanonicalProfile::Rfc8785).is_err());
    assert!(
        canonical_bytes_with_profile_unbounded(
            &9_007_199_254_740_992u64,
            CanonicalProfile::IJsonSafeIntegers
        )
        .is_err()
    );
    assert!(parse_json_strict_unbounded("{\"a\":1,\"\\u0061\":2}").is_err());
    assert!(parse_json_strict_unbounded("1e400").is_err());
    for format in [
        ObjectTableFormat::IndexedV1,
        ObjectTableFormat::ShortReferencesV2,
    ] {
        let limits = ObjectTableLimits::new(4096, 4096).unwrap();
        let wire = object_table_encode_with_format_unbounded(&source, format).unwrap();
        assert_eq!(
            wire,
            object_table_encode_with_format(&source, format, limits).unwrap()
        );
        assert_eq!(
            object_table_decode_with_format_unbounded(&wire, format).unwrap(),
            source
        );
        let other = if format == ObjectTableFormat::IndexedV1 {
            ObjectTableFormat::ShortReferencesV2
        } else {
            ObjectTableFormat::IndexedV1
        };
        assert!(object_table_decode_with_format_unbounded(&wire, other).is_err());
    }
}

#[test]
fn unbounded_object_table_roundtrips_above_single_string_and_depth_quotas() {
    let long = "x".repeat(1024 * 1024 + 1);
    let source = json!({"members": [&long, &long], "numbers": [1, 1.5, true]});
    let format = ObjectTableFormat::ShortReferencesV2;
    assert!(
        object_table_encode_with_format(
            &source,
            format,
            ObjectTableLimits::new(16 * 1024 * 1024, 16 * 1024 * 1024).unwrap()
        )
        .is_err()
    );
    let wire = object_table_encode_with_format_unbounded(&source, format).unwrap();
    assert_eq!(
        object_table_decode_with_format_unbounded(&wire, format).unwrap(),
        source
    );
    let mut corrupted: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    corrupted["sourceDigest"] = json!(digest_bytes(b"different").as_str());
    let bytes =
        canonical_bytes_with_profile_unbounded(&corrupted, CanonicalProfile::Rfc8785).unwrap();
    assert!(object_table_decode_with_format_unbounded(&bytes, format).is_err());

    let nested = format!("{}true{}", "[".repeat(140), "]".repeat(140));
    let source = parse_json_strict_unbounded(&nested).unwrap();
    let wire = object_table_encode_with_format_unbounded(&source, format).unwrap();
    assert_eq!(
        object_table_decode_with_format_unbounded(&wire, format).unwrap(),
        source
    );
}
