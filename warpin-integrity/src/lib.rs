//! Strict JSON integrity primitives.
//!
//! This crate combines duplicate-key-safe JSON parsing with RFC 8785 JSON
//! Canonicalization Scheme (JCS) serialization and SHA-256 digests. Arrays are
//! always preserved in caller-provided order.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize, de, ser};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const DUPLICATE_KEY_MARKER: &str = "warpin_integrity_duplicate_key";
const SHA256_PREFIX: &str = "sha256:";
const BINDING_LABEL_MAX_LEN: usize = 128;

/// Errors returned by strict parsing, canonicalization, and digest validation.
///
/// Messages intentionally omit input values and object keys so callers can
/// safely surface them without leaking credentials or provider payloads.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IntegrityError {
    /// Untrusted JSON was syntactically invalid or contained trailing data.
    #[error("invalid JSON at line {line} column {column}")]
    InvalidJson {
        /// One-based source line reported by the JSON parser.
        line: usize,
        /// One-based source column reported by the JSON parser.
        column: usize,
    },
    /// An object contained the same member name more than once.
    #[error("duplicate JSON object member at line {line} column {column}")]
    DuplicateKey {
        /// One-based source line reported by the JSON parser.
        line: usize,
        /// One-based source column reported by the JSON parser.
        column: usize,
    },
    /// A typed value could not be represented as RFC 8785 JSON.
    #[error("value cannot be canonicalized as RFC 8785 JSON")]
    Canonicalization,
    /// A digest did not have the required lowercase SHA-256 representation.
    #[error("digest must use sha256 followed by 64 lowercase hexadecimal characters")]
    InvalidDigest,
    /// A domain or profile binding label was invalid.
    #[error("digest binding labels must be 1 to 128 printable ASCII characters")]
    InvalidBinding,
}

/// A validated `sha256:<64 lowercase hexadecimal characters>` digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Returns the validated textual digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Sha256Digest {
    type Err = IntegrityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hexadecimal = value
            .strip_prefix(SHA256_PREFIX)
            .ok_or(IntegrityError::InvalidDigest)?;
        if hexadecimal.len() != 64
            || !hexadecimal
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(IntegrityError::InvalidDigest);
        }
        Ok(Self(value.to_owned()))
    }
}

/// Explicit domain and profile binding for contexts that need separation.
///
/// The unbound functions remain appropriate for protocols, such as frozen
/// ProtoJSON contracts, whose digest projection already defines the domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestBinding {
    domain: String,
    profile: String,
}

impl DigestBinding {
    /// Constructs a validated binding without retaining invalid input in errors.
    pub fn new(
        domain: impl Into<String>,
        profile: impl Into<String>,
    ) -> Result<Self, IntegrityError> {
        let domain = domain.into();
        let profile = profile.into();
        if !valid_binding_label(&domain) || !valid_binding_label(&profile) {
            return Err(IntegrityError::InvalidBinding);
        }
        Ok(Self { domain, profile })
    }
}

/// Parses untrusted JSON while rejecting duplicate object members at any depth.
pub fn parse_json_strict(input: &str) -> Result<Value, IntegrityError> {
    validate_json_integer_tokens(input)?;
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let parsed = StrictValue::deserialize(&mut deserializer).map_err(map_json_error)?;
    deserializer.end().map_err(map_json_error)?;
    Ok(parsed.0)
}

/// Serializes a typed value to RFC 8785 canonical UTF-8 bytes.
pub fn canonical_bytes<T>(value: &T) -> Result<Vec<u8>, IntegrityError>
where
    T: Serialize + ?Sized,
{
    value
        .serialize(FiniteNumberValidator)
        .map_err(|_| IntegrityError::Canonicalization)?;
    serde_jcs::to_vec(value).map_err(|_| IntegrityError::Canonicalization)
}

/// Strictly parses untrusted JSON and returns its RFC 8785 canonical bytes.
pub fn canonical_bytes_from_json(input: &str) -> Result<Vec<u8>, IntegrityError> {
    canonical_bytes(&parse_json_strict(input)?)
}

/// Returns the SHA-256 digest of a typed value's RFC 8785 representation.
pub fn digest_typed<T>(value: &T) -> Result<Sha256Digest, IntegrityError>
where
    T: Serialize + ?Sized,
{
    canonical_bytes(value).map(|bytes| digest_bytes(&bytes))
}

/// Strictly parses untrusted JSON and digests its RFC 8785 representation.
pub fn digest_from_json(input: &str) -> Result<Sha256Digest, IntegrityError> {
    canonical_bytes_from_json(input).map(|bytes| digest_bytes(&bytes))
}

/// Digests a typed value with explicit domain and profile separation.
///
/// Binding wraps the value as `{"domain":...,"profile":...,"value":...}`.
/// JCS sorts object members only; array order remains unchanged.
pub fn digest_bound<T>(binding: &DigestBinding, value: &T) -> Result<Sha256Digest, IntegrityError>
where
    T: Serialize + ?Sized,
{
    #[derive(Serialize)]
    struct BoundValue<'a, T: ?Sized> {
        domain: &'a str,
        profile: &'a str,
        value: &'a T,
    }

    digest_typed(&BoundValue {
        domain: &binding.domain,
        profile: &binding.profile,
        value,
    })
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(format!(
        "{SHA256_PREFIX}{}",
        hex::encode(Sha256::digest(bytes))
    ))
}

fn valid_binding_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= BINDING_LABEL_MAX_LEN
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn map_json_error(error: serde_json::Error) -> IntegrityError {
    let duplicate = error.to_string().contains(DUPLICATE_KEY_MARKER);
    if duplicate {
        IntegrityError::DuplicateKey {
            line: error.line(),
            column: error.column(),
        }
    } else {
        IntegrityError::InvalidJson {
            line: error.line(),
            column: error.column(),
        }
    }
}

struct StrictValue(Value);

#[derive(Debug)]
struct ValidationError;

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("value is not valid canonical JSON")
    }
}

impl std::error::Error for ValidationError {}

impl ser::Error for ValidationError {
    fn custom<T>(_message: T) -> Self
    where
        T: fmt::Display,
    {
        Self
    }
}

struct FiniteNumberValidator;
struct CompoundValidator;

impl ser::Serializer for FiniteNumberValidator {
    type Ok = ();
    type Error = ValidationError;
    type SerializeSeq = CompoundValidator;
    type SerializeTuple = CompoundValidator;
    type SerializeTupleStruct = CompoundValidator;
    type SerializeTupleVariant = CompoundValidator;
    type SerializeMap = CompoundValidator;
    type SerializeStruct = CompoundValidator;
    type SerializeStructVariant = CompoundValidator;

    fn serialize_bool(self, _value: bool) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_i8(self, _value: i8) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_i16(self, _value: i16) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_i32(self, _value: i32) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_i64(self, value: i64) -> Result<Self::Ok, Self::Error> {
        validate_integer_exact(value.unsigned_abs().into())
    }
    fn serialize_i128(self, value: i128) -> Result<Self::Ok, Self::Error> {
        validate_integer_exact(value.unsigned_abs())
    }
    fn serialize_u8(self, _value: u8) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_u16(self, _value: u16) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_u32(self, _value: u32) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_u64(self, value: u64) -> Result<Self::Ok, Self::Error> {
        validate_integer_exact(value.into())
    }
    fn serialize_u128(self, value: u128) -> Result<Self::Ok, Self::Error> {
        validate_integer_exact(value)
    }

    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(ValidationError)
        }
    }

    fn serialize_f64(self, value: f64) -> Result<Self::Ok, Self::Error> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(ValidationError)
        }
    }

    fn serialize_char(self, _value: char) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_str(self, _value: &str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_bytes(self, _value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(self)
    }

    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(self)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(CompoundValidator)
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(CompoundValidator)
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(CompoundValidator)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(CompoundValidator)
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(CompoundValidator)
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(CompoundValidator)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(CompoundValidator)
    }
}

impl ser::SerializeSeq for CompoundValidator {
    type Ok = ();
    type Error = ValidationError;
    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(FiniteNumberValidator)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeTuple for CompoundValidator {
    type Ok = ();
    type Error = ValidationError;
    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(FiniteNumberValidator)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeTupleStruct for CompoundValidator {
    type Ok = ();
    type Error = ValidationError;
    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(FiniteNumberValidator)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeTupleVariant for CompoundValidator {
    type Ok = ();
    type Error = ValidationError;
    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(FiniteNumberValidator)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeMap for CompoundValidator {
    type Ok = ();
    type Error = ValidationError;
    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        key.serialize(FiniteNumberValidator)
    }
    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(FiniteNumberValidator)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeStruct for CompoundValidator {
    type Ok = ();
    type Error = ValidationError;
    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(FiniteNumberValidator)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl ser::SerializeStructVariant for CompoundValidator {
    type Ok = ();
    type Error = ValidationError;
    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(FiniteNumberValidator)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

fn validate_integer_exact(magnitude: u128) -> Result<(), ValidationError> {
    let significant_bits = u128::BITS - magnitude.leading_zeros();
    let discarded_bits = significant_bits.saturating_sub(53);
    if discarded_bits == 0 || magnitude.trailing_zeros() >= discarded_bits {
        Ok(())
    } else {
        Err(ValidationError)
    }
}

fn validate_json_integer_tokens(input: &str) -> Result<(), IntegrityError> {
    let bytes = input.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && !matches!(
                    bytes[index],
                    b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}'
                )
            {
                index += 1;
            }
            let token = &input[start..index];
            if !token.bytes().any(|part| matches!(part, b'.' | b'e' | b'E')) {
                let magnitude_text = token.strip_prefix('-').unwrap_or(token);
                if !magnitude_text.is_empty()
                    && magnitude_text.bytes().all(|part| part.is_ascii_digit())
                {
                    let magnitude = magnitude_text
                        .parse::<u128>()
                        .map_err(|_| IntegrityError::Canonicalization)?;
                    validate_integer_exact(magnitude)
                        .map_err(|_| IntegrityError::Canonicalization)?;
                }
            }
            continue;
        }
        index += 1;
    }
    Ok(())
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> de::Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_KEY_MARKER));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::{
        DigestBinding, IntegrityError, Sha256Digest, canonical_bytes, canonical_bytes_from_json,
        digest_bound, digest_from_json, digest_typed, parse_json_strict,
    };

    #[test]
    fn canonicalizes_key_order_and_nested_values() {
        let bytes = canonical_bytes_from_json(r#"{"b":1,"a":{"z":true,"x":null}}"#)
            .expect("valid JSON canonicalizes");
        assert_eq!(
            String::from_utf8(bytes).expect("JCS is UTF-8"),
            r#"{"a":{"x":null,"z":true},"b":1}"#
        );
    }

    #[test]
    fn canonicalizes_utf16_key_order_and_required_escaping() {
        let bytes = canonical_bytes_from_json(
            "{\"\\uFFFD\":1,\"😀\":2,\"text\":\"line\\nquote\\\"slash\\\\\\u000f\"}",
        )
        .expect("Unicode JSON canonicalizes");
        assert_eq!(
            String::from_utf8(bytes).expect("JCS is UTF-8"),
            "{\"text\":\"line\\nquote\\\"slash\\\\\\u000f\",\"😀\":2,\"�\":1}"
        );
    }

    #[test]
    fn canonicalizes_rfc8785_numbers_and_negative_zero() {
        let bytes = canonical_bytes_from_json(
            "[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001,-0]",
        )
        .expect("finite JSON numbers canonicalize");
        assert_eq!(
            String::from_utf8(bytes).expect("JCS is UTF-8"),
            "[333333333.3333333,1e+30,4.5,0.002,1e-27,0]"
        );
    }

    #[test]
    fn strict_parser_rejects_duplicate_keys_at_any_depth_without_echoing_values() {
        for input in [
            r#"{"secret":"first","secret":"second"}"#,
            r#"{"outer":{"token":"first","token":"second"}}"#,
            r#"[{"credential":"first","credential":"second"}]"#,
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
    fn strict_parser_rejects_nonfinite_json_numbers() {
        for input in ["NaN", "Infinity", "-Infinity"] {
            assert!(matches!(
                parse_json_strict(input),
                Err(IntegrityError::InvalidJson { .. })
            ));
        }
    }

    #[test]
    fn typed_canonicalization_rejects_nonfinite_floats() {
        #[derive(Serialize)]
        struct Measurement {
            value: f64,
        }

        assert!(matches!(
            canonical_bytes(&Measurement { value: f64::NAN }),
            Err(IntegrityError::Canonicalization)
        ));
    }

    #[test]
    fn integers_that_cannot_round_trip_through_ieee754_are_rejected() {
        for input in ["9007199254740993", "-9007199254740993"] {
            assert!(matches!(
                canonical_bytes_from_json(input),
                Err(IntegrityError::Canonicalization)
            ));
        }
        for value in [9_007_199_254_740_993_u64, u64::MAX] {
            assert!(matches!(
                canonical_bytes(&value),
                Err(IntegrityError::Canonicalization)
            ));
        }
        assert_eq!(
            String::from_utf8(canonical_bytes(&9_007_199_254_740_992_u64).expect("exact boundary"))
                .expect("JCS is UTF-8"),
            "9007199254740992"
        );
        assert_ne!(
            digest_from_json("9007199254740992")
                .expect("exact integer digest")
                .as_str(),
            ""
        );
    }

    #[test]
    fn semantic_key_order_has_the_same_digest_and_changed_field_does_not() {
        let left =
            digest_from_json(r#"{"alpha":1,"nested":{"x":"same","y":2}}"#).expect("left digest");
        let reordered = digest_from_json(r#"{"nested":{"y":2,"x":"same"},"alpha":1}"#)
            .expect("reordered digest");
        let changed = digest_from_json(r#"{"alpha":1,"nested":{"x":"changed","y":2}}"#)
            .expect("changed digest");
        assert_eq!(left, reordered);
        assert_ne!(left, changed);
        assert!(left.as_str().starts_with("sha256:"));
        assert_eq!(left.as_str().len(), 71);
        assert!(
            left.as_str()[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn typed_and_strict_json_digests_share_the_same_canonical_form() {
        #[derive(Serialize)]
        struct Payload<'a> {
            alpha: u64,
            label: &'a str,
        }

        let typed = digest_typed(&Payload {
            alpha: 7,
            label: "stable",
        })
        .expect("typed digest");
        let json = digest_from_json(r#"{"label":"stable","alpha":7}"#).expect("JSON digest");
        assert_eq!(typed, json);
    }

    #[test]
    fn protojson_profile_vector_preserves_int64_strings_enums_and_timestamp() {
        let input = r#"{
            "status":"COST_SETTLEMENT_STATUS_SETTLED",
            "quantityDecimal":"12.5",
            "microunits":"1250000",
            "metadata":{
                "tenantId":"tenant_a",
                "occurredAt":"2026-07-11T10:05:01Z",
                "eventId":"evt_1"
            }
        }"#;
        let canonical = canonical_bytes_from_json(input).expect("ProtoJSON vector canonicalizes");
        assert_eq!(
            String::from_utf8(canonical).expect("JCS is UTF-8"),
            r#"{"metadata":{"eventId":"evt_1","occurredAt":"2026-07-11T10:05:01Z","tenantId":"tenant_a"},"microunits":"1250000","quantityDecimal":"12.5","status":"COST_SETTLEMENT_STATUS_SETTLED"}"#
        );
        assert_eq!(
            digest_from_json(input)
                .expect("ProtoJSON vector digests")
                .as_str(),
            "sha256:9814f428f0a53d8b6d6f5887da362371c4533c51c1535b05f02c6cf7c08b9431"
        );
    }

    #[test]
    fn digest_and_binding_validation_are_strict_and_redacted() {
        let valid = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            valid
                .parse::<Sha256Digest>()
                .expect("valid digest")
                .as_str(),
            valid
        );
        for invalid in [
            "",
            "sha256:abc",
            "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(matches!(
                invalid.parse::<Sha256Digest>(),
                Err(IntegrityError::InvalidDigest)
            ));
        }
        for label in ["", "line\nbreak", "\u{7f}"] {
            let error = DigestBinding::new(label, "profile").expect_err("invalid binding");
            assert_eq!(error, IntegrityError::InvalidBinding);
            if !label.is_empty() {
                assert!(!error.to_string().contains(label));
            }
        }
    }

    #[test]
    fn bound_digest_is_domain_and_profile_specific_without_reordering_arrays() {
        let value = serde_json::json!({"steps":["second", "first"]});
        let binding = DigestBinding::new("astro.event", "protojson-jcs-v1")
            .expect("binding labels are valid");
        let first = digest_bound(&binding, &value).expect("bound digest");
        let same = digest_bound(&binding, &value).expect("same bound digest");
        let other_profile = digest_bound(
            &DigestBinding::new("astro.event", "protojson-jcs-v2").expect("binding"),
            &value,
        )
        .expect("other profile digest");
        let reversed = digest_bound(&binding, &serde_json::json!({"steps":["first", "second"]}))
            .expect("reversed digest");
        assert_eq!(first, same);
        assert_ne!(first, other_profile);
        assert_ne!(first, reversed);
    }
}
