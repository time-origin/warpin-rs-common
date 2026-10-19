use std::cell::Cell;

use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq};

use super::*;

fn limits(bytes: usize) -> CanonicalLimits {
    CanonicalLimits::new(bytes).expect("constructed finite byte budget")
}

fn document(bytes: usize) -> String {
    // Many bounded strings, not a single enlarged string-token allowance.
    let count = bytes / 200_000 + 1;
    let payload = bytes - (3 * count + 1);
    let strings = (0..count)
        .map(|index| {
            let length = payload / count + usize::from(index < payload % count);
            format!("\"{}\"", "x".repeat(length))
        })
        .collect::<Vec<_>>();
    let raw = format!("[{}]", strings.join(","));
    assert_eq!(raw.len(), bytes);
    raw
}

#[test]
fn explicit_budget_is_finite_and_does_not_change_default_input_bounds() {
    assert!(CanonicalLimits::new(0).is_err());
    assert!(CanonicalLimits::new(16 * 1024 * 1024 + 1).is_err());
    assert!(CanonicalLimits::new(usize::MAX).is_err());
    assert_eq!(
        limits(16 * 1024 * 1024).maximum_document_bytes(),
        16 * 1024 * 1024
    );
    let raw = document(2_139_405);
    let value: serde_json::Value = serde_json::from_str(&raw).expect("constructed tree");
    assert!(canonical_bytes(&value).is_err());
    assert!(parse_json_strict(&raw).is_err());
    assert!(canonical_bytes_from_json(&raw).is_err());
    let policy = limits(16 * 1024 * 1024);
    let expected =
        canonical_bytes_with_profile_and_limits(&value, CanonicalProfile::Rfc8785, policy)
            .expect("explicit complete document");
    assert_eq!(expected, raw.as_bytes());
    assert_eq!(
        canonical_bytes_from_json_with_profile_and_limits(&raw, CanonicalProfile::Rfc8785, policy)
            .expect("same raw complete document"),
        expected
    );
    assert_eq!(
        parse_json_strict_with_limits(&raw, policy).expect("strict bounded raw"),
        value
    );
}

#[test]
fn raw_and_canonical_output_enforce_the_exact_explicit_boundary() {
    let policy = limits(16 * 1024 * 1024);
    let exact = document(policy.maximum_document_bytes());
    assert_eq!(
        canonical_bytes_from_json_with_profile_and_limits(
            &exact,
            CanonicalProfile::Rfc8785,
            policy
        )
        .expect("exact maximum"),
        exact.as_bytes()
    );
    let over = document(policy.maximum_document_bytes() + 1);
    assert!(parse_json_strict_with_limits(&over, policy).is_err());
    let captured: serde_json::Value = serde_json::from_str(&over).expect("constructed tree");
    assert!(
        canonical_bytes_with_profile_and_limits(&captured, CanonicalProfile::Rfc8785, policy)
            .is_err()
    );
    // JCS expansion is independently bounded, even if raw input fits.
    assert!(
        canonical_bytes_from_json_with_profile_and_limits(
            "1e20",
            CanonicalProfile::Rfc8785,
            limits(4)
        )
        .is_err()
    );
    assert_eq!(
        canonical_bytes_with_profile_and_limits(&"\0", CanonicalProfile::Rfc8785, limits(8))
            .expect("exact escaped output"),
        br#""\u0000""#
    );
    assert!(
        canonical_bytes_with_profile_and_limits(&"\0", CanonicalProfile::Rfc8785, limits(7))
            .is_err()
    );
}

#[test]
fn individual_strings_and_legacy_output_behavior_are_preserved() {
    let full = limits(16 * 1024 * 1024);
    let typed = "x".repeat(1_048_576);
    // The old typed budget counts captured bytes, not output quote bytes.
    assert_eq!(
        canonical_bytes(&typed)
            .expect("legacy exact typed capture")
            .len(),
        1_048_578
    );
    assert!(
        canonical_bytes_with_profile_and_limits(
            &typed,
            CanonicalProfile::Rfc8785,
            limits(1_048_576)
        )
        .is_err()
    );
    assert!(
        canonical_bytes_with_profile_and_limits(&typed, CanonicalProfile::Rfc8785, full).is_ok()
    );
    assert!(
        canonical_bytes_with_profile_and_limits(
            &"x".repeat(1_048_577),
            CanonicalProfile::Rfc8785,
            full
        )
        .is_err()
    );
    for (raw, accepted) in [
        (format!("\"{}\"", "x".repeat(262_142)), true),
        (format!("\"{}\"", "x".repeat(262_143)), false),
    ] {
        assert_eq!(parse_json_strict_with_limits(&raw, full).is_ok(), accepted);
        assert_eq!(parse_json_strict(&raw).is_ok(), accepted);
    }
    let escaped = format!("\"{}\"", "\\u0061".repeat(43_691));
    assert!(parse_json_strict_with_limits(&escaped, full).is_err());
    // A key cannot bypass the typed single-string ceiling.
    let keyed = std::collections::BTreeMap::from([("k".repeat(1_048_577), 0)]);
    assert!(
        canonical_bytes_with_profile_and_limits(&keyed, CanonicalProfile::Rfc8785, full).is_err()
    );
}

#[test]
fn expanded_raw_keeps_lexical_guards_and_adds_explicit_node_and_item_caps() {
    let full = limits(16 * 1024 * 1024);
    for raw in [
        r#"{"secret":1,"\u0073ecret":2}"#.to_owned(),
        r#"[{"outer":{"token":1,"token":2}}]"#.to_owned(),
        format!("{}0{}", "[".repeat(130), "]".repeat(130)),
        "1".repeat(1025),
        "[true,]".into(),
        "null trailing".into(),
    ] {
        assert!(parse_json_strict_with_limits(&raw, full).is_err());
        assert!(
            canonical_bytes_from_json_with_profile_and_limits(
                &raw,
                CanonicalProfile::Rfc8785,
                full
            )
            .is_err()
        );
    }
    let exact_nodes = format!("[{}]", vec!["0"; 99_999].join(","));
    assert!(parse_json_strict_with_limits(&exact_nodes, full).is_ok());
    let excess_nodes = format!("[{}]", vec!["0"; 100_000].join(","));
    assert!(
        parse_json_strict(&excess_nodes).is_ok(),
        "old raw API has no added node cap"
    );
    assert!(parse_json_strict_with_limits(&excess_nodes, full).is_err());
    assert!(
        canonical_bytes_with_profile_and_limits(
            &vec![0_u8; 100_000],
            CanonicalProfile::Rfc8785,
            full
        )
        .is_err()
    );
}

#[test]
fn explicit_profiles_keep_utf16_order_array_order_and_numeric_contracts() {
    let policy = limits(16 * 1024 * 1024);
    let raw = "{\"\\uFFFD\":1,\"😀\":2,\"array\":[2,1],\"text\":\"line\\nquote\\\"slash\\\\\"}";
    assert_eq!(
        canonical_bytes_from_json(raw).expect("legacy valid"),
        canonical_bytes_from_json_with_profile_and_limits(raw, CanonicalProfile::Rfc8785, policy)
            .expect("explicit valid")
    );
    for profile in [
        CanonicalProfile::Rfc8785,
        CanonicalProfile::IJsonSafeIntegers,
    ] {
        for raw in [
            "1e30",
            "1e-400",
            "1e400",
            "9007199254740993.0",
            "-0",
            "15e-1",
            "[1e-7,4.5]",
        ] {
            assert_eq!(
                canonical_bytes_from_json_with_profile(raw, profile),
                canonical_bytes_from_json_with_profile_and_limits(raw, profile, policy)
            );
        }
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1e30, -0.0, 4.5] {
            assert_eq!(
                canonical_bytes_with_profile(&value, profile),
                canonical_bytes_with_profile_and_limits(&value, profile, policy)
            );
        }
        assert_eq!(
            canonical_bytes_with_profile(&9_007_199_254_740_993_u64, profile),
            canonical_bytes_with_profile_and_limits(&9_007_199_254_740_993_u64, profile, policy)
        );
    }
}

#[test]
fn explicit_capture_is_once_and_sticky_against_adversarial_serializers() {
    struct Once<'a>(&'a Cell<usize>);
    impl Serialize for Once<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.set(self.0.get() + 1);
            serializer.serialize_str("once")
        }
    }
    struct IgnoredDuplicate;
    impl Serialize for IgnoredDuplicate {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry("secret", &1)?;
            let _ = map.serialize_entry("secret", &2);
            map.end()
        }
    }
    struct IgnoredBudget;
    impl Serialize for IgnoredBudget {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut seq = serializer.serialize_seq(None)?;
            let _ = seq.serialize_element(&"x".repeat(1_048_577));
            let _ = seq.serialize_element(&"recovery");
            seq.end()
        }
    }
    struct HugeHint;
    impl Serialize for HugeHint {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_seq(Some(usize::MAX))?.end()
        }
    }
    let policy = limits(16 * 1024 * 1024);
    let calls = Cell::new(0);
    assert_eq!(
        canonical_bytes_with_profile_and_limits(&Once(&calls), CanonicalProfile::Rfc8785, policy)
            .expect("once"),
        br#""once""#
    );
    assert_eq!(calls.get(), 1);
    for rejected in [
        canonical_bytes_with_profile_and_limits(
            &IgnoredDuplicate,
            CanonicalProfile::Rfc8785,
            policy,
        ),
        canonical_bytes_with_profile_and_limits(&IgnoredBudget, CanonicalProfile::Rfc8785, policy),
        canonical_bytes_with_profile_and_limits(&HugeHint, CanonicalProfile::Rfc8785, policy),
    ] {
        let error = rejected.expect_err("invalid capture stays rejected");
        assert_eq!(error, IntegrityError::Canonicalization);
        assert!(!error.to_string().contains("secret"));
    }
}

#[test]
fn explicit_digest_helpers_preserve_original_domain_and_profile_binding() {
    let policy = limits(16 * 1024 * 1024);
    let binding = DigestBinding::new("public.sample", "jcs-v1").expect("binding");
    let value = serde_json::json!({"v":[2,1],"a":7});
    for profile in [
        CanonicalProfile::Rfc8785,
        CanonicalProfile::IJsonSafeIntegers,
    ] {
        assert_eq!(
            digest_typed_with_profile(&value, profile),
            digest_typed_with_profile_and_limits(&value, profile, policy)
        );
        assert_eq!(
            digest_from_json_with_profile(r#"{"v":[2,1],"a":7}"#, profile),
            digest_from_json_with_profile_and_limits(r#"{"v":[2,1],"a":7}"#, profile, policy)
        );
        assert_eq!(
            digest_bound_with_profile(&binding, &value, profile),
            digest_bound_with_profile_and_limits(&binding, &value, profile, policy)
        );
    }
    assert!(
        digest_bound_with_profile_and_limits(
            &binding,
            &value,
            CanonicalProfile::Rfc8785,
            limits(1)
        )
        .is_err()
    );
}
