//! Explicit aggregate-document budgets. Numeric and structural policies are
//! deliberately not configurable through this API.
use std::io::{self, Write};

use serde::Serialize;

use crate::capture::{CapturedValue, capture_typed_with_limits};
use crate::json::parse_captured_json_with_limits;
use crate::{CanonicalProfile, DigestBinding, IntegrityError, Sha256Digest, digest_bytes};

/// An opt-in aggregate byte budget for one canonical document.
///
/// Existing APIs keep their original 1 MiB capture/input bounds and behavior.
/// These explicit APIs accept a caller-owned budget from 1 byte to 16 MiB,
/// bounding raw input, aggregate captured string/key bytes, and canonical output.
/// They do not authorize network/storage reads or change a protocol's wire cap.
///
/// Typed capture retains 128 depth, 100,000 nodes/items and a 1 MiB individual
/// string/key ceiling (the old aggregate ceiling). Raw parsing retains its
/// original 262,144-byte quoted-string token and 1,024-byte numeric-token limits,
/// and additionally caps nodes/items at 100,000 only in this opt-in API. Numeric
/// profiles, duplicate-key rejection, and single-capture semantics are unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalLimits {
    maximum_document_bytes: usize,
}

impl CanonicalLimits {
    /// Hard ceiling for explicit document budgets: 16 MiB.
    pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

    /// Constructs an explicit finite budget without changing any defaults.
    /// Zero and values above [`Self::MAX_DOCUMENT_BYTES`] are rejected.
    pub fn new(maximum_document_bytes: usize) -> Result<Self, IntegrityError> {
        if maximum_document_bytes == 0 || maximum_document_bytes > Self::MAX_DOCUMENT_BYTES {
            return Err(IntegrityError::Canonicalization);
        }
        Ok(Self {
            maximum_document_bytes,
        })
    }

    /// Returns the caller's exact aggregate byte ceiling.
    pub fn maximum_document_bytes(self) -> usize {
        self.maximum_document_bytes
    }
}

/// Strictly parses raw JSON under an explicit aggregate input budget.
/// All original raw lexical rules remain in force, including decoded duplicates.
pub fn parse_json_strict_with_limits(
    input: &str,
    limits: CanonicalLimits,
) -> Result<serde_json::Value, IntegrityError> {
    parse_captured_json_with_limits(input, CanonicalProfile::Rfc8785, limits)?.into_json()
}

/// Captures a typed value exactly once under explicit numeric and byte policies.
pub fn canonical_bytes_with_profile_and_limits<T>(
    value: &T,
    profile: CanonicalProfile,
    limits: CanonicalLimits,
) -> Result<Vec<u8>, IntegrityError>
where
    T: Serialize + ?Sized,
{
    canonicalize_bounded(&capture_typed_with_limits(value, profile, limits)?, limits)
}

/// Strictly parses and canonicalizes raw JSON under explicit numeric/byte policies.
/// The raw-input and final canonical-output lengths must both fit the budget.
pub fn canonical_bytes_from_json_with_profile_and_limits(
    input: &str,
    profile: CanonicalProfile,
    limits: CanonicalLimits,
) -> Result<Vec<u8>, IntegrityError> {
    canonicalize_bounded(
        &parse_captured_json_with_limits(input, profile, limits)?,
        limits,
    )
}

/// Digests one typed capture with explicit numeric and document-byte policies.
pub fn digest_typed_with_profile_and_limits<T>(
    value: &T,
    profile: CanonicalProfile,
    limits: CanonicalLimits,
) -> Result<Sha256Digest, IntegrityError>
where
    T: Serialize + ?Sized,
{
    canonical_bytes_with_profile_and_limits(value, profile, limits)
        .map(|bytes| digest_bytes(&bytes))
}

/// Strictly parses and digests JSON with explicit numeric/document-byte policies.
pub fn digest_from_json_with_profile_and_limits(
    input: &str,
    profile: CanonicalProfile,
    limits: CanonicalLimits,
) -> Result<Sha256Digest, IntegrityError> {
    canonical_bytes_from_json_with_profile_and_limits(input, profile, limits)
        .map(|bytes| digest_bytes(&bytes))
}

/// Digests the original domain/profile wrapper under an explicit byte budget.
/// The wrapper and its value share the same aggregate/output budget.
pub fn digest_bound_with_profile_and_limits<T>(
    binding: &DigestBinding,
    value: &T,
    profile: CanonicalProfile,
    limits: CanonicalLimits,
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
    digest_typed_with_profile_and_limits(
        &BoundValue {
            domain: &binding.domain,
            profile: &binding.profile,
            value,
        },
        profile,
        limits,
    )
}

fn canonicalize_bounded(
    value: &CapturedValue,
    limits: CanonicalLimits,
) -> Result<Vec<u8>, IntegrityError> {
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        maximum: limits.maximum_document_bytes(),
    };
    serde_jcs::to_writer(&mut output, value).map_err(|_| IntegrityError::Canonicalization)?;
    Ok(output.bytes)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other(
                "canonical output exceeds explicit byte budget",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
