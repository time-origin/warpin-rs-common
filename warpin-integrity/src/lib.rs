//! Strict JSON integrity primitives.
//!
//! This crate captures typed [`serde::Serialize`] values exactly once, parses
//! untrusted JSON with bounded resources and duplicate-key rejection, and then
//! delegates RFC 8785 JSON Canonicalization Scheme output to `serde_jcs`.
//! Arrays are always preserved in caller-provided order.
//!
//! The default APIs implement the complete RFC 8785 binary64 number model.
//! [`CanonicalProfile::IJsonSafeIntegers`] is an explicit stricter profile for
//! protocols that forbid mathematical integers outside `[-(2^53-1), 2^53-1]`
//! and reject nonzero numeric underflow. ProtoJSON `int64`, `uint64`, and other
//! exact decimal values should be projected as JSON strings before hashing.

mod capture;
mod json;
mod number;

use std::{fmt, str::FromStr};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::capture::{CapturedValue, capture_typed};
use crate::json::parse_captured_json;

const SHA256_PREFIX: &str = "sha256:";
const BINDING_LABEL_MAX_LEN: usize = 128;

/// Numeric contract applied before RFC 8785 canonical serialization.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum CanonicalProfile {
    /// Complete RFC 8785 behavior using ECMAScript binary64 number semantics.
    #[default]
    Rfc8785,
    /// RFC 8785 plus a strict interoperable mathematical-integer domain.
    ///
    /// Mathematical integers must be within `[-(2^53-1), 2^53-1]`, including
    /// raw spellings such as `1.0` and `1e0`. Nonzero underflow is rejected.
    IJsonSafeIntegers,
}

/// Errors returned by strict parsing, canonicalization, and digest validation.
///
/// Messages intentionally omit input values and object keys so callers can
/// safely surface them without leaking credentials or provider payloads.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IntegrityError {
    /// Untrusted JSON was syntactically invalid, exceeded a resource bound, or
    /// contained trailing data.
    #[error("invalid JSON at line {line} column {column}")]
    InvalidJson {
        /// One-based source line.
        line: usize,
        /// One-based source column.
        column: usize,
    },
    /// An object contained the same decoded member name more than once.
    #[error("duplicate JSON object member at line {line} column {column}")]
    DuplicateKey {
        /// One-based source line.
        line: usize,
        /// One-based source column.
        column: usize,
    },
    /// A value violated JCS or the selected numeric profile.
    #[error("value cannot be canonicalized under the selected profile")]
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

/// Parses bounded untrusted JSON while rejecting duplicate decoded object keys.
pub fn parse_json_strict(input: &str) -> Result<serde_json::Value, IntegrityError> {
    parse_captured_json(input, CanonicalProfile::Rfc8785)?.into_json()
}

/// Captures a typed value once and returns RFC 8785 canonical UTF-8 bytes.
///
/// This default uses [`CanonicalProfile::Rfc8785`]. Typed integers are accepted
/// only when conversion to binary64 is lossless; non-finite floats are rejected.
pub fn canonical_bytes<T>(value: &T) -> Result<Vec<u8>, IntegrityError>
where
    T: Serialize + ?Sized,
{
    canonical_bytes_with_profile(value, CanonicalProfile::Rfc8785)
}

/// Captures a typed value once using an explicit numeric profile.
pub fn canonical_bytes_with_profile<T>(
    value: &T,
    profile: CanonicalProfile,
) -> Result<Vec<u8>, IntegrityError>
where
    T: Serialize + ?Sized,
{
    canonicalize_captured(&capture_typed(value, profile)?)
}

/// Strictly parses untrusted JSON using the complete RFC 8785 number model.
///
/// Raw numbers are interpreted as ECMAScript binary64 values. Protocols that
/// require exact `int64` or decimal semantics must encode those values as JSON
/// strings before canonicalization.
pub fn canonical_bytes_from_json(input: &str) -> Result<Vec<u8>, IntegrityError> {
    canonical_bytes_from_json_with_profile(input, CanonicalProfile::Rfc8785)
}

/// Strictly parses untrusted JSON using an explicit numeric profile.
pub fn canonical_bytes_from_json_with_profile(
    input: &str,
    profile: CanonicalProfile,
) -> Result<Vec<u8>, IntegrityError> {
    canonicalize_captured(&parse_captured_json(input, profile)?)
}

/// Returns the SHA-256 digest of a typed value's canonical representation.
pub fn digest_typed<T>(value: &T) -> Result<Sha256Digest, IntegrityError>
where
    T: Serialize + ?Sized,
{
    digest_typed_with_profile(value, CanonicalProfile::Rfc8785)
}

/// Digests a typed value using an explicit numeric profile.
pub fn digest_typed_with_profile<T>(
    value: &T,
    profile: CanonicalProfile,
) -> Result<Sha256Digest, IntegrityError>
where
    T: Serialize + ?Sized,
{
    canonical_bytes_with_profile(value, profile).map(|bytes| digest_bytes(&bytes))
}

/// Strictly parses untrusted JSON and digests its canonical representation.
pub fn digest_from_json(input: &str) -> Result<Sha256Digest, IntegrityError> {
    digest_from_json_with_profile(input, CanonicalProfile::Rfc8785)
}

/// Strictly parses and digests JSON using an explicit numeric profile.
pub fn digest_from_json_with_profile(
    input: &str,
    profile: CanonicalProfile,
) -> Result<Sha256Digest, IntegrityError> {
    canonical_bytes_from_json_with_profile(input, profile).map(|bytes| digest_bytes(&bytes))
}

/// Digests a typed value with explicit domain and profile separation.
///
/// Binding wraps the value as `{"domain":...,"profile":...,"value":...}`.
/// JCS sorts object members only; array order remains unchanged.
pub fn digest_bound<T>(binding: &DigestBinding, value: &T) -> Result<Sha256Digest, IntegrityError>
where
    T: Serialize + ?Sized,
{
    digest_bound_with_profile(binding, value, CanonicalProfile::Rfc8785)
}

/// Digests a bound typed value using an explicit numeric profile.
pub fn digest_bound_with_profile<T>(
    binding: &DigestBinding,
    value: &T,
    profile: CanonicalProfile,
) -> Result<Sha256Digest, IntegrityError>
where
    T: Serialize + ?Sized,
{
    #[derive(Serialize)]
    struct BoundValue<'a, T: ?Sized> {
        domain: &'a str,
        profile: &'a str,
        value: &'a T,
    }

    digest_typed_with_profile(
        &BoundValue {
            domain: &binding.domain,
            profile: &binding.profile,
            value,
        },
        profile,
    )
}

fn canonicalize_captured(value: &CapturedValue) -> Result<Vec<u8>, IntegrityError> {
    serde_jcs::to_vec(value).map_err(|_| IntegrityError::Canonicalization)
}

/// Returns the SHA-256 digest of arbitrary bytes without applying JSON
/// canonicalization. Use the typed or JSON helpers when semantic JSON
/// equivalence is required.
pub fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
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

#[cfg(test)]
mod tests;
