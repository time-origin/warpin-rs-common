use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{Document, ObjectTableFormat, ObjectTableLimits, Work, reference_index, unprofitable};
use crate::{IntegrityError, Sha256Digest, digest_bytes, parse_json_strict_with_limits};

pub(super) fn run(
    raw: &[u8],
    limits: ObjectTableLimits,
    format: ObjectTableFormat,
) -> Result<Value, IntegrityError> {
    if raw.is_empty()
        || limits
            .encoded
            .is_some_and(|limit| raw.len() > limit.maximum_document_bytes())
    {
        return Err(IntegrityError::Canonicalization);
    }
    let text = std::str::from_utf8(raw).map_err(|_| IntegrityError::Canonicalization)?;
    let document: Document = if let Some(limit) = limits.encoded {
        parse_json_strict_with_limits(text, limit.object_table_wire())?;
        serde_json::from_slice(raw).map_err(|_| IntegrityError::Canonicalization)?
    } else {
        crate::parse_json_strict_unbounded(text)?;
        super::deserialize_unbounded(raw)?
    };
    let mut work = Work::with_format(format);
    work.bounded = limits.expanded.is_some();
    let _: Sha256Digest = document.source_digest.parse()?;
    if document.schema_version != format.schema()
        || work.canonical(
            &document,
            limits.encoded.map(|limit| limit.object_table_wire()),
        )? != raw
        || !unprofitable(&document, limits, &mut work)?.is_empty()
    {
        return Err(IntegrityError::Canonicalization);
    }
    for index in 0..document.objects.len() {
        if !document.objects.contains_key(&index.to_string()) {
            return Err(IntegrityError::Canonicalization);
        }
    }
    work.nodes = 0;
    let mut decoder = Decoder {
        document: &document,
        limits,
        work,
        active: BTreeSet::new(),
        used: BTreeSet::new(),
        hashes: BTreeMap::new(),
        remaining: limits.expanded.map(|limit| limit.maximum_document_bytes()),
    };
    let full = decoder.expand(&document.root, 0)?;
    if decoder.used.len() != document.objects.len() {
        return Err(IntegrityError::Canonicalization);
    }
    let mut previous: Option<&str> = None;
    for index in 0..document.objects.len() {
        let hash = decoder
            .hashes
            .get(&index.to_string())
            .ok_or(IntegrityError::Canonicalization)?;
        if previous.is_some_and(|old| old >= hash.as_str()) {
            return Err(IntegrityError::Canonicalization);
        }
        previous = Some(hash);
    }
    if digest_bytes(&decoder.work.canonical(&full, limits.expanded)?).as_str()
        != document.source_digest
    {
        return Err(IntegrityError::Canonicalization);
    }
    Ok(full)
}

struct Decoder<'a> {
    document: &'a Document,
    limits: ObjectTableLimits,
    work: Work,
    active: BTreeSet<String>,
    used: BTreeSet<String>,
    hashes: BTreeMap<String, String>,
    remaining: Option<usize>,
}
impl Decoder<'_> {
    fn charge(&mut self, amount: usize) -> Result<(), IntegrityError> {
        if let Some(remaining) = &mut self.remaining {
            *remaining = remaining
                .checked_sub(amount)
                .ok_or(IntegrityError::Canonicalization)?;
        }
        Ok(())
    }
    fn expand(&mut self, value: &Value, depth: usize) -> Result<Value, IntegrityError> {
        if let Some(index) = reference_index(value, self.work.format)? {
            if self.work.bounded && depth > super::MAX_DEPTH {
                return Err(IntegrityError::Canonicalization);
            }
            let body = self
                .document
                .objects
                .get(index)
                .ok_or(IntegrityError::Canonicalization)?;
            if !self.active.insert(index.into()) {
                return Err(IntegrityError::Canonicalization);
            }
            let full = self.expand(body, depth + 1)?;
            self.active.remove(index);
            self.used.insert(index.into());
            let digest =
                digest_bytes(&self.work.canonical(&full, self.limits.expanded)?).to_string();
            if self
                .hashes
                .insert(index.into(), digest.clone())
                .is_some_and(|old| old != digest)
            {
                return Err(IntegrityError::Canonicalization);
            }
            return Ok(full);
        }
        // References are wire indirections; the expanded body accounts for its
        // own nodes. Counting both rejects valid sources after compression.
        self.work.node(depth)?;
        match value {
            Value::Object(map) => {
                self.charge(2 + map.len().saturating_sub(1))?;
                let mut output = serde_json::Map::new();
                for (key, child) in map {
                    let key_bytes = self.work.canonical(key, self.limits.expanded)?.len();
                    self.charge(key_bytes + 1)?;
                    output.insert(key.clone(), self.expand(child, depth + 1)?);
                }
                Ok(Value::Object(output))
            }
            Value::Array(items) => {
                self.charge(2 + items.len().saturating_sub(1))?;
                Ok(Value::Array(
                    items
                        .iter()
                        .map(|child| self.expand(child, depth + 1))
                        .collect::<Result<_, _>>()?,
                ))
            }
            _ => {
                let scalar_bytes = self.work.canonical(value, self.limits.expanded)?.len();
                self.charge(scalar_bytes)?;
                Ok(value.clone())
            }
        }
    }
}
