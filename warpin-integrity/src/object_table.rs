//! Lossless, bounded structural sharing. This format carries data integrity,
//! never authorization, storage references, or instructions to fetch resources.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    CanonicalLimits, CanonicalProfile, IntegrityError, canonical_bytes_with_profile_and_limits,
};

mod decode;
mod encode;
#[cfg(test)]
mod tests;

const SCHEMA: &str = "warpin-indexed-json/v1";
const REFERENCE: &str = "$objectRef";
const MAX_DEPTH: usize = 128;
const MAX_NODES: usize = 100_000;
const MAX_WORK_BYTES: usize = 256 * 1024 * 1024;
const MAX_PASSES: usize = 128;

/// Independent finite wire and expanded-document budgets, each 1..=16 MiB.
///
/// The codec also enforces depth 128, 100,000 traversed nodes per pass, at most
/// 128 monotone pruning passes, and 256 MiB aggregate canonicalization work.
/// Strict parsing keeps the public parser's lexical/string/number limits.
/// These bounds select a representation; they confer no application authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectTableLimits {
    encoded: CanonicalLimits,
    expanded: CanonicalLimits,
}
impl ObjectTableLimits {
    /// Rejects zero or budgets above the public 16 MiB hard ceiling.
    pub fn new(
        maximum_encoded_bytes: usize,
        maximum_expanded_bytes: usize,
    ) -> Result<Self, IntegrityError> {
        Ok(Self {
            encoded: CanonicalLimits::new(maximum_encoded_bytes)?,
            expanded: CanonicalLimits::new(maximum_expanded_bytes)?,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document {
    schema_version: String,
    source_digest: String,
    root: Value,
    objects: BTreeMap<String, Value>,
}

struct Work {
    bytes: usize,
    nodes: usize,
}
impl Work {
    fn new() -> Self {
        Self { bytes: 0, nodes: 0 }
    }
    fn node(&mut self, depth: usize) -> Result<(), IntegrityError> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(IntegrityError::Canonicalization)?;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return Err(IntegrityError::Canonicalization);
        }
        Ok(())
    }
    fn canonical(
        &mut self,
        value: &impl Serialize,
        limit: CanonicalLimits,
    ) -> Result<Vec<u8>, IntegrityError> {
        let bytes =
            canonical_bytes_with_profile_and_limits(value, CanonicalProfile::Rfc8785, limit)?;
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(IntegrityError::Canonicalization)?;
        if self.bytes > MAX_WORK_BYTES {
            return Err(IntegrityError::Canonicalization);
        }
        Ok(bytes)
    }
}

/// Captures the typed source once, then losslessly shares profitable repeated
/// scalar/container values. Object members use RFC 8785 order; array order and
/// all decoded values remain unchanged. Literal `$objectRef` keys are rejected.
/// Dictionary indices follow the SHA-256 lexical order of expanded bodies.
/// The complete encoded document and expanded canonical source obey their own
/// budgets. Errors omit source values and keys.
///
/// ```
/// use warpin_integrity::{ObjectTableLimits, object_table_decode, object_table_encode};
/// let source = serde_json::json!({"steps": ["keep order", "retain complete values"]});
/// let limits = ObjectTableLimits::new(1024, 4096)?;
/// let encoded = object_table_encode(&source, limits)?;
/// assert_eq!(object_table_decode(&encoded, limits)?, source);
/// # Ok::<(), warpin_integrity::IntegrityError>(())
/// ```
pub fn object_table_encode<T: Serialize + ?Sized>(
    source: &T,
    limits: ObjectTableLimits,
) -> Result<Vec<u8>, IntegrityError> {
    encode::run(source, limits)
}

/// Strictly validates an exact canonical object table before expanding it.
/// Rejects duplicate/extra keys, unresolved/cyclic/unused references, invalid or
/// sparse decimal indices, hash-order drift, and nonprofitable dictionary rows.
/// The source digest binds the full expanded canonical value. Applications must
/// independently validate their schema, scope, authority and expected digest.
pub fn object_table_decode(
    encoded: &[u8],
    limits: ObjectTableLimits,
) -> Result<Value, IntegrityError> {
    decode::run(encoded, limits)
}

fn reference(index: &str) -> Value {
    serde_json::json!({ (REFERENCE): index })
}

fn reference_index(value: &Value) -> Result<Option<&str>, IntegrityError> {
    if let Value::Object(map) = value
        && let Some(index) = map.get(REFERENCE)
    {
        if map.len() != 1 {
            return Err(IntegrityError::Canonicalization);
        }
        return index
            .as_str()
            .map(Some)
            .ok_or(IntegrityError::Canonicalization);
    }
    Ok(None)
}

fn references(
    value: &Value,
    counts: &mut BTreeMap<String, usize>,
    work: &mut Work,
    depth: usize,
) -> Result<(), IntegrityError> {
    work.node(depth)?;
    if let Some(index) = reference_index(value)? {
        let number = index
            .parse::<usize>()
            .map_err(|_| IntegrityError::Canonicalization)?;
        if number.to_string() != index {
            return Err(IntegrityError::Canonicalization);
        }
        *counts.entry(index.to_owned()).or_default() += 1;
    } else {
        match value {
            Value::Object(map) => {
                for child in map.values() {
                    references(child, counts, work, depth + 1)?;
                }
            }
            Value::Array(items) => {
                for child in items {
                    references(child, counts, work, depth + 1)?;
                }
            }
            _ => (),
        }
    }
    Ok(())
}

fn unprofitable(
    document: &Document,
    limits: ObjectTableLimits,
    work: &mut Work,
) -> Result<BTreeSet<String>, IntegrityError> {
    let mut counts = BTreeMap::new();
    work.nodes = 0;
    references(&document.root, &mut counts, work, 0)?;
    for body in document.objects.values() {
        references(body, &mut counts, work, 0)?;
    }
    if counts.keys().any(|key| !document.objects.contains_key(key)) {
        return Err(IntegrityError::Canonicalization);
    }
    let mut rejected = BTreeSet::new();
    for (index, body) in &document.objects {
        let uses = counts.get(index).copied().unwrap_or_default() as u128;
        let body_bytes = work.canonical(body, limits.expanded)?.len() as u128;
        let ref_bytes = work.canonical(&reference(index), limits.encoded)?.len() as u128;
        let entry_bytes = body_bytes + work.canonical(index, limits.encoded)?.len() as u128 + 2;
        if uses < 2 || uses * body_bytes <= uses * ref_bytes + entry_bytes {
            rejected.insert(index.clone());
        }
    }
    Ok(rejected)
}
