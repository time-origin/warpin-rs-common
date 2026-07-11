use std::{cell::Cell, collections::BTreeMap};

use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};

use super::*;

#[test]
fn canonicalizes_key_order_nested_values_and_arrays() {
    let bytes = canonical_bytes_from_json(r#"{"b":1,"a":{"z":true,"x":null},"v":[2,1]}"#)
        .expect("valid JSON canonicalizes");
    assert_eq!(
        String::from_utf8(bytes).expect("JCS is UTF-8"),
        r#"{"a":{"x":null,"z":true},"b":1,"v":[2,1]}"#
    );
}

#[test]
fn canonicalizes_utf16_key_order_escaping_and_rfc_numbers() {
    let unicode = canonical_bytes_from_json(
        "{\"\\uFFFD\":1,\"😀\":2,\"text\":\"line\\nquote\\\"slash\\\\\\u000f\"}",
    )
    .expect("Unicode JSON canonicalizes");
    assert_eq!(
        String::from_utf8(unicode).expect("JCS is UTF-8"),
        "{\"text\":\"line\\nquote\\\"slash\\\\\\u000f\",\"😀\":2,\"�\":1}"
    );
    let numbers = canonical_bytes_from_json(
        "[333333333.33333329,1E-7,4.50,2e-3,0.000000000000000000000000001,-0]",
    )
    .expect("finite numbers canonicalize");
    assert_eq!(
        String::from_utf8(numbers).expect("JCS is UTF-8"),
        "[333333333.3333333,1e-7,4.5,0.002,1e-27,0]"
    );
}

#[test]
fn default_canonicalization_accepts_the_full_rfc8785_number_domain() {
    assert_eq!(
        String::from_utf8(canonical_bytes_from_json("1E30").expect("RFC 8785 number"))
            .expect("UTF-8"),
        "1e+30"
    );
    assert_eq!(
        String::from_utf8(canonical_bytes(&1e30_f64).expect("finite typed float")).expect("UTF-8"),
        "1e+30"
    );
}

#[test]
fn explicit_profiles_have_stable_and_distinct_number_contracts() {
    let full = CanonicalProfile::Rfc8785;
    let safe = CanonicalProfile::IJsonSafeIntegers;

    for (input, expected) in [
        ("1E30", "1e+30"),
        ("9007199254740993", "9007199254740992"),
        ("9007199254740993.0", "9007199254740992"),
        ("9007199254740993e0", "9007199254740992"),
        ("1e-400", "0"),
    ] {
        assert_eq!(
            String::from_utf8(
                canonical_bytes_from_json_with_profile(input, full).expect("full RFC 8785")
            )
            .expect("UTF-8"),
            expected
        );
    }
    for rejected in [
        "1E30",
        "9007199254740992",
        "9007199254740993.0",
        "9007199254740993e0",
        "1e-400",
    ] {
        assert!(matches!(
            canonical_bytes_from_json_with_profile(rejected, safe),
            Err(IntegrityError::Canonicalization)
        ));
    }
    assert_eq!(
        canonical_bytes_from_json_with_profile("1E30", safe)
            .expect_err("safe profile rejects the value")
            .to_string(),
        "value cannot be canonicalized under the selected profile"
    );

    assert_eq!(
        String::from_utf8(
            canonical_bytes_with_profile(&9_007_199_254_740_992_u64, full)
                .expect("exact binary64 integer")
        )
        .expect("UTF-8"),
        "9007199254740992"
    );
    assert!(matches!(
        canonical_bytes_with_profile(&9_007_199_254_740_993_u64, full),
        Err(IntegrityError::Canonicalization)
    ));
    assert!(matches!(
        canonical_bytes_with_profile(&9_007_199_254_740_992_u64, safe),
        Err(IntegrityError::Canonicalization)
    ));
    let exact_i128 = 1_i128 << 100;
    assert!(canonical_bytes_with_profile(&exact_i128, full).is_ok());
    assert!(matches!(
        canonical_bytes_with_profile(&(exact_i128 + 1), full),
        Err(IntegrityError::Canonicalization)
    ));
    assert!(matches!(
        canonical_bytes_with_profile(&exact_i128, safe),
        Err(IntegrityError::Canonicalization)
    ));
    assert_eq!(
        String::from_utf8(
            canonical_bytes_with_profile(&1e30_f64, full).expect("finite full-profile float")
        )
        .expect("UTF-8"),
        "1e+30"
    );
    assert!(matches!(
        canonical_bytes_with_profile(&1e30_f64, safe),
        Err(IntegrityError::Canonicalization)
    ));

    let full_digest = digest_from_json_with_profile("1E30", full).expect("full digest");
    assert_eq!(
        full_digest.as_str(),
        "sha256:7412d94bdf30adfa71080e057185e1a8de86e2e99a8350b011df8ac41ed5a6e3"
    );
    assert_eq!(digest_from_json("1E30").expect("default full"), full_digest);
    assert_eq!(
        digest_typed(&1e30_f64).expect("default typed full"),
        digest_typed_with_profile(&1e30_f64, full).expect("explicit typed full")
    );

    let binding = DigestBinding::new("warpin.integrity", "rfc8785-v1").expect("binding");
    assert_eq!(
        digest_bound(&binding, &1e30_f64).expect("default bound full"),
        digest_bound_with_profile(&binding, &1e30_f64, full).expect("explicit bound full")
    );
}

#[test]
fn integer_map_keys_are_profile_independent_json_strings() {
    let profile = CanonicalProfile::IJsonSafeIntegers;
    let numeric_u64 = BTreeMap::from([(9_007_199_254_740_993_u64, "u64")]);
    let string_u64 = BTreeMap::from([("9007199254740993".to_owned(), "u64")]);
    assert_eq!(
        canonical_bytes_with_profile(&numeric_u64, profile).expect("numeric u64 key"),
        canonical_bytes_with_profile(&string_u64, profile).expect("string u64 key")
    );

    let numeric_u128 = BTreeMap::from([(u128::MAX, "u128")]);
    let string_u128 = BTreeMap::from([(u128::MAX.to_string(), "u128")]);
    assert_eq!(
        canonical_bytes_with_profile(&numeric_u128, profile).expect("numeric u128 key"),
        canonical_bytes_with_profile(&string_u128, profile).expect("string u128 key")
    );

    struct NumericStringCollision;
    impl Serialize for NumericStringCollision {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry(&u128::MAX, &1)?;
            map.serialize_entry(&u128::MAX.to_string(), &2)?;
            map.end()
        }
    }
    assert!(matches!(
        canonical_bytes_with_profile(&NumericStringCollision, profile),
        Err(IntegrityError::Canonicalization)
    ));
}

#[test]
fn zero_mantissas_and_full_profile_extreme_exponents_are_stable() {
    let enormous = "9".repeat(80);
    let safe = CanonicalProfile::IJsonSafeIntegers;
    for input in [
        format!("0e{enormous}"),
        format!("-0e-{enormous}"),
        format!("0.000E+{enormous}"),
    ] {
        assert_eq!(
            String::from_utf8(
                canonical_bytes_from_json_with_profile(&input, safe).expect("mathematical zero")
            )
            .expect("UTF-8"),
            "0"
        );
    }

    let full = CanonicalProfile::Rfc8785;
    assert_eq!(
        String::from_utf8(
            canonical_bytes_from_json_with_profile(&format!("1e-{enormous}"), full)
                .expect("binary64 underflow")
        )
        .expect("UTF-8"),
        "0"
    );
    assert!(matches!(
        canonical_bytes_from_json_with_profile(&format!("1e{enormous}"), full),
        Err(IntegrityError::Canonicalization)
    ));
}

#[test]
fn strict_parser_rejects_nested_and_escaped_duplicate_keys_without_echoing_values() {
    for input in [
        r#"{"secret":"first","secret":"second"}"#,
        r#"{"outer":{"token":"first","token":"second"}}"#,
        r#"[{"credential":"first","\u0063redential":"second"}]"#,
    ] {
        let error = parse_json_strict(input).expect_err("duplicates are ambiguous");
        assert!(matches!(error, IntegrityError::DuplicateKey { .. }));
        let display = error.to_string();
        for sensitive in ["secret", "token", "credential", "first", "second"] {
            assert!(!display.contains(sensitive));
        }
    }
}

#[test]
fn typed_serialization_is_invoked_exactly_once() {
    struct Stateful<'a>(&'a Cell<usize>);
    impl Serialize for Stateful<'_> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let call = self.0.get();
            self.0.set(call + 1);
            if call == 0 {
                serializer.serialize_str("first")
            } else {
                serializer.serialize_f64(f64::NAN)
            }
        }
    }
    let calls = Cell::new(0);
    let canonical = canonical_bytes(&Stateful(&calls)).expect("single capture");
    assert_eq!(calls.get(), 1);
    assert_eq!(String::from_utf8(canonical).expect("UTF-8"), r#""first""#);
}

#[test]
fn typed_duplicate_map_keys_and_nonfinite_values_are_rejected() {
    struct DuplicateMap;
    impl Serialize for DuplicateMap {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry("same", &1)?;
            map.serialize_entry("same", &2)?;
            map.end()
        }
    }
    struct IgnoredDuplicateMap;
    impl Serialize for IgnoredDuplicateMap {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry("same", &1)?;
            let _ignored = map.serialize_entry("same", &2);
            map.end()
        }
    }
    assert!(matches!(
        canonical_bytes(&DuplicateMap),
        Err(IntegrityError::Canonicalization)
    ));
    assert!(matches!(
        canonical_bytes(&IgnoredDuplicateMap),
        Err(IntegrityError::Canonicalization)
    ));
    assert!(matches!(
        canonical_bytes(&f64::NAN),
        Err(IntegrityError::Canonicalization)
    ));
    assert!(matches!(
        canonical_bytes_with_profile(
            &9_007_199_254_740_992_f64,
            CanonicalProfile::IJsonSafeIntegers
        ),
        Err(IntegrityError::Canonicalization)
    ));
}

#[test]
fn typed_map_rejects_an_ignored_second_key_before_the_pending_value() {
    struct IgnoredSecondKey;
    impl Serialize for IgnoredSecondKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_key("first")?;
            let _ignored = map.serialize_key("second");
            let _ignored = map.serialize_value(&1);
            map.end()
        }
    }

    assert!(matches!(
        canonical_bytes(&IgnoredSecondKey),
        Err(IntegrityError::Canonicalization)
    ));
}

#[test]
fn typed_map_keeps_every_ignored_state_and_capture_error_sticky() {
    struct NonFinite;
    impl Serialize for NonFinite {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_f64(f64::NAN)
        }
    }

    struct MissingKey;
    impl Serialize for MissingKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(1))?;
            let _ignored = map.serialize_value(&1);
            let _ignored = map.serialize_entry("recovery", &1);
            map.end()
        }
    }

    struct InvalidKey;
    impl Serialize for InvalidKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(1))?;
            let _ignored = map.serialize_key(&NonFinite);
            let _ignored = map.serialize_entry("recovery", &1);
            map.end()
        }
    }

    struct InvalidValue;
    impl Serialize for InvalidValue {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_key("bad")?;
            let _ignored = map.serialize_value(&NonFinite);
            let _ignored = map.serialize_entry("recovery", &1);
            map.end()
        }
    }

    struct BudgetFailure;
    impl Serialize for BudgetFailure {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let oversized = "x".repeat(1_048_577);
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_key("oversized")?;
            let _ignored = map.serialize_value(&oversized);
            map.end()
        }
    }

    for rejected in [
        canonical_bytes(&MissingKey),
        canonical_bytes(&InvalidKey),
        canonical_bytes(&InvalidValue),
        canonical_bytes(&BudgetFailure),
    ] {
        assert!(matches!(rejected, Err(IntegrityError::Canonicalization)));
    }
}

#[test]
fn typed_sequences_and_structs_keep_ignored_capture_errors_sticky() {
    struct NonFinite;
    impl Serialize for NonFinite {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_f64(f64::NAN)
        }
    }

    struct IgnoredSequenceError;
    impl Serialize for IgnoredSequenceError {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(1))?;
            let _ignored = sequence.serialize_element(&NonFinite);
            let _ignored = sequence.serialize_element(&1);
            sequence.end()
        }
    }

    struct IgnoredStructError;
    impl Serialize for IgnoredStructError {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut object = serializer.serialize_struct("IgnoredStructError", 2)?;
            let _ignored = object.serialize_field("bad", &NonFinite);
            let _ignored = object.serialize_field("recovery", &1);
            object.end()
        }
    }

    assert!(matches!(
        canonical_bytes(&IgnoredSequenceError),
        Err(IntegrityError::Canonicalization)
    ));
    assert!(matches!(
        canonical_bytes(&IgnoredStructError),
        Err(IntegrityError::Canonicalization)
    ));
}

#[test]
fn raw_mathematical_integers_use_i_json_safe_domain() {
    let profile = CanonicalProfile::IJsonSafeIntegers;
    for unsafe_integer in [
        "9007199254740992",
        "9007199254740993",
        "9007199254740993.0",
        "9007199254740993e0",
        "-9007199254740992",
        "-9007199254740993.0",
    ] {
        assert!(matches!(
            canonical_bytes_from_json_with_profile(unsafe_integer, profile),
            Err(IntegrityError::Canonicalization)
        ));
    }
    for (safe, expected) in [
        ("9007199254740991", "9007199254740991"),
        ("9007199254740991.0", "9007199254740991"),
        ("9007199254740991e0", "9007199254740991"),
        ("-9007199254740991", "-9007199254740991"),
        ("15e-1", "1.5"),
        ("9007199254740991.5", "9007199254740992"),
    ] {
        assert_eq!(
            String::from_utf8(canonical_bytes_from_json_with_profile(safe, profile).expect("safe"))
                .expect("UTF-8"),
            expected
        );
    }
}

#[test]
fn raw_overflow_underflow_and_malformed_numbers_fail_closed() {
    for value in ["1e400", "-1e400"] {
        assert!(matches!(
            canonical_bytes_from_json(value),
            Err(IntegrityError::Canonicalization)
        ));
    }
    for value in ["1e-400", "-1e-400"] {
        assert!(matches!(
            canonical_bytes_from_json_with_profile(value, CanonicalProfile::IJsonSafeIntegers),
            Err(IntegrityError::Canonicalization)
        ));
    }
    assert_eq!(
        String::from_utf8(canonical_bytes_from_json("0e-400").expect("zero")).expect("UTF-8"),
        "0"
    );
    for value in ["+1", "01", "--1", "1 trailing", "1.", ".1", "1e"] {
        assert!(matches!(
            canonical_bytes_from_json(value),
            Err(IntegrityError::InvalidJson { .. })
        ));
    }
}

#[test]
fn raw_parser_enforces_depth_input_and_number_resource_bounds() {
    let too_deep = format!("{}0{}", "[".repeat(130), "]".repeat(130));
    assert!(matches!(
        canonical_bytes_from_json(&too_deep),
        Err(IntegrityError::InvalidJson { .. })
    ));

    let oversized_number = "1".repeat(1_025);
    assert!(matches!(
        canonical_bytes_from_json(&oversized_number),
        Err(IntegrityError::Canonicalization)
    ));

    let oversized_input = format!("\"{}\"", "x".repeat(1_048_576));
    assert!(matches!(
        canonical_bytes_from_json(&oversized_input),
        Err(IntegrityError::InvalidJson { .. })
    ));
}

#[test]
fn typed_capture_enforces_shared_resource_budgets_without_panicking() {
    struct HugeHint;
    impl Serialize for HugeHint {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_seq(Some(usize::MAX))?.end()
        }
    }

    struct Nested(usize);
    impl Serialize for Nested {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            if self.0 == 0 {
                return serializer.serialize_unit();
            }
            let mut sequence = serializer.serialize_seq(Some(1))?;
            sequence.serialize_element(&Nested(self.0 - 1))?;
            sequence.end()
        }
    }

    struct RecursiveKey(usize);
    impl Serialize for RecursiveKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            if self.0 == 0 {
                serializer.serialize_str("key")
            } else {
                serializer.serialize_newtype_struct("RecursiveKey", &RecursiveKey(self.0 - 1))
            }
        }
    }
    struct DeepKeyMap;
    impl Serialize for DeepKeyMap {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry(&RecursiveKey(130), &1)?;
            map.end()
        }
    }

    let huge_hint = std::panic::catch_unwind(|| canonical_bytes(&HugeHint));
    assert!(matches!(
        huge_hint,
        Ok(Err(IntegrityError::Canonicalization))
    ));
    assert!(matches!(
        canonical_bytes(&Nested(130)),
        Err(IntegrityError::Canonicalization)
    ));
    assert!(matches!(
        canonical_bytes(&DeepKeyMap),
        Err(IntegrityError::Canonicalization)
    ));
    assert!(matches!(
        canonical_bytes(&"x".repeat(1_048_577)),
        Err(IntegrityError::Canonicalization)
    ));
    assert!(matches!(
        canonical_bytes(&vec![0_u8; 100_001]),
        Err(IntegrityError::Canonicalization)
    ));
}

#[test]
fn typed_capture_does_not_retain_capacity_from_untrusted_empty_hints() {
    struct EmptySequence;
    impl Serialize for EmptySequence {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_seq(Some(1_024))?.end()
        }
    }

    struct EmptyObject;
    impl Serialize for EmptyObject {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_map(Some(1_024))?.end()
        }
    }

    struct ManyEmptyContainers;
    impl Serialize for ManyEmptyContainers {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut outer = serializer.serialize_seq(Some(2_000))?;
            for index in 0..2_000 {
                if index % 2 == 0 {
                    outer.serialize_element(&EmptySequence)?;
                } else {
                    outer.serialize_element(&EmptyObject)?;
                }
            }
            outer.end()
        }
    }

    let captured = crate::capture::capture_typed(&ManyEmptyContainers, CanonicalProfile::Rfc8785)
        .expect("within budget");
    let crate::capture::CapturedValue::Array(children) = captured else {
        panic!("expected outer array");
    };
    assert_eq!(children.len(), 2_000);
    let retained_child_capacity: usize = children
        .iter()
        .map(|child| match child {
            crate::capture::CapturedValue::Array(values) => values.capacity(),
            crate::capture::CapturedValue::Object(entries) => entries.capacity(),
            _ => panic!("expected empty container"),
        })
        .sum();
    assert_eq!(retained_child_capacity, 0);
}

#[test]
fn typed_integer_domain_is_uniform_for_all_widths() {
    let profile = CanonicalProfile::IJsonSafeIntegers;
    for value in [9_007_199_254_740_992_i64, i64::MAX] {
        assert!(matches!(
            canonical_bytes_with_profile(&value, profile),
            Err(IntegrityError::Canonicalization)
        ));
    }
    for value in [9_007_199_254_740_992_u64, u64::MAX] {
        assert!(matches!(
            canonical_bytes_with_profile(&value, profile),
            Err(IntegrityError::Canonicalization)
        ));
    }
    for rejected in [
        canonical_bytes_with_profile(&i128::MIN, profile),
        canonical_bytes_with_profile(&i128::MAX, profile),
        canonical_bytes_with_profile(&u128::MAX, profile),
    ] {
        assert!(matches!(rejected, Err(IntegrityError::Canonicalization)));
    }
    assert!(canonical_bytes_with_profile(&9_007_199_254_740_991_i64, profile).is_ok());
    assert!(canonical_bytes_with_profile(&-9_007_199_254_740_991_i64, profile).is_ok());
}

#[test]
fn semantic_digests_binding_and_protojson_vector_are_stable() {
    let left = digest_from_json(r#"{"alpha":1,"nested":{"x":"same","y":2}}"#).expect("digest");
    let reordered = digest_from_json(r#"{"nested":{"y":2,"x":"same"},"alpha":1}"#).expect("digest");
    let changed =
        digest_from_json(r#"{"alpha":1,"nested":{"x":"changed","y":2}}"#).expect("digest");
    assert_eq!(left, reordered);
    assert_ne!(left, changed);
    assert_eq!(left.as_str().len(), 71);

    let binding = DigestBinding::new("astro.event", "protojson-jcs-v1").expect("binding");
    let order = serde_json::json!({"steps":["second", "first"]});
    assert_ne!(
        digest_bound(&binding, &order).expect("bound"),
        digest_bound(&binding, &serde_json::json!({"steps":["first", "second"]})).expect("bound")
    );

    let protojson = r#"{"status":"COST_SETTLEMENT_STATUS_SETTLED","quantityDecimal":"12.5","microunits":"1250000","metadata":{"tenantId":"tenant_a","occurredAt":"2026-07-11T10:05:01Z","eventId":"evt_1"}}"#;
    assert_eq!(
        digest_from_json(protojson)
            .expect("ProtoJSON digest")
            .as_str(),
        "sha256:9814f428f0a53d8b6d6f5887da362371c4533c51c1535b05f02c6cf7c08b9431"
    );
}

#[test]
fn digest_and_binding_validation_are_strict_and_redacted() {
    let valid = format!("sha256:{}", "a".repeat(64));
    assert_eq!(
        valid.parse::<Sha256Digest>().expect("valid").as_str(),
        valid
    );
    for invalid in [
        "",
        "sha256:abc",
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(matches!(
            invalid.parse::<Sha256Digest>(),
            Err(IntegrityError::InvalidDigest)
        ));
    }
    for label in ["", "line\nbreak", "\u{7f}"] {
        let error = DigestBinding::new(label, "profile").expect_err("invalid");
        if !label.is_empty() {
            assert!(!error.to_string().contains(label));
        }
    }
}

#[test]
fn typed_and_raw_json_share_the_same_tree() {
    #[derive(Serialize)]
    struct Payload<'a> {
        alpha: u64,
        label: &'a str,
    }
    let typed = digest_typed(&Payload {
        alpha: 7,
        label: "stable",
    })
    .expect("typed");
    let raw = digest_from_json(r#"{"label":"stable","alpha":7}"#).expect("raw");
    assert_eq!(typed, raw);
}

#[test]
fn raw_byte_digest_is_stable_and_distinct_from_json_semantics() {
    assert_eq!(
        crate::digest_bytes(b"abc").as_str(),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_ne!(
        crate::digest_bytes(br#"{"a": 1}"#),
        digest_from_json(r#"{"a": 1}"#).expect("semantic JSON digest")
    );
}
