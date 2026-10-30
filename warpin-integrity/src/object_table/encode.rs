use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use super::{
    Document, MAX_PASSES, ObjectTableFormat, ObjectTableLimits, Work, reference, unprofitable,
};
use crate::{
    CanonicalProfile, IntegrityError, canonical_bytes_with_profile_and_limits, digest_bytes,
};

pub(super) fn run<T: Serialize + ?Sized>(
    source: &T,
    limits: ObjectTableLimits,
    format: ObjectTableFormat,
) -> Result<Vec<u8>, IntegrityError> {
    // Only this capture can invoke caller Serialize code. All subsequent work
    // reads the captured JSON value rather than serializing caller state again.
    let bytes = match limits.expanded {
        Some(limit) => {
            canonical_bytes_with_profile_and_limits(source, CanonicalProfile::Rfc8785, limit)?
        }
        None => crate::canonical_bytes_with_profile_unbounded(source, CanonicalProfile::Rfc8785)?,
    };
    let value: Value = if limits.expanded.is_some() {
        serde_json::from_slice(&bytes).map_err(|_| IntegrityError::Canonicalization)?
    } else {
        super::deserialize_unbounded(&bytes)?
    };
    let mut work = Work::with_format(format);
    work.bounded = limits.expanded.is_some();
    work.bytes = bytes.len();
    let mut counts = BTreeMap::new();
    count(&value, &mut counts, &mut work, limits, 0)?;
    let mut candidates = counts
        .into_iter()
        .filter(|(_, uses)| *uses > 1)
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    let mut passes = 0;
    loop {
        if work.bounded && passes == MAX_PASSES {
            return Err(IntegrityError::Canonicalization);
        }
        passes += 1;
        let indices = candidates
            .iter()
            .enumerate()
            .map(|(index, key)| (key.clone(), index.to_string()))
            .collect::<BTreeMap<_, _>>();
        let mut objects = BTreeMap::new();
        work.nodes = 0;
        let root = encode(&value, &indices, &mut objects, &mut work, limits, 0)?;
        let document = Document {
            schema_version: format.schema().into(),
            source_digest: digest_bytes(&bytes).to_string(),
            root,
            objects,
        };
        let rejected = unprofitable(&document, limits, &mut work)?;
        if rejected.is_empty() {
            let raw = work.canonical(
                &document,
                limits.encoded.map(|limit| limit.object_table_wire()),
            )?;
            // Producer and strict consumer must agree on the complete value.
            if super::decode::run(&raw, limits, format)? != value {
                return Err(IntegrityError::Canonicalization);
            }
            return Ok(raw);
        }
        candidates.retain(|key| !rejected.contains(&indices[key]));
    }
}

fn count(
    value: &Value,
    counts: &mut BTreeMap<String, usize>,
    work: &mut Work,
    limits: ObjectTableLimits,
    depth: usize,
) -> Result<(), IntegrityError> {
    work.node(depth)?;
    let raw = work.canonical(value, limits.expanded)?;
    *counts.entry(digest_bytes(&raw).to_string()).or_default() += 1;
    match value {
        Value::Object(map) => {
            if map.contains_key(work.format.reference_key()) {
                return Err(IntegrityError::Canonicalization);
            }
            for child in map.values() {
                count(child, counts, work, limits, depth + 1)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                count(child, counts, work, limits, depth + 1)?;
            }
        }
        _ => (),
    }
    Ok(())
}

fn encode(
    value: &Value,
    indices: &BTreeMap<String, String>,
    objects: &mut BTreeMap<String, Value>,
    work: &mut Work,
    limits: ObjectTableLimits,
    depth: usize,
) -> Result<Value, IntegrityError> {
    work.node(depth)?;
    let key = digest_bytes(&work.canonical(value, limits.expanded)?).to_string();
    let index = indices.get(&key);
    if let Some(index) = index
        && objects.contains_key(index)
    {
        return Ok(reference(index, work.format));
    }
    let body = match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, child)| {
                    Ok((
                        key.clone(),
                        encode(child, indices, objects, work, limits, depth + 1)?,
                    ))
                })
                .collect::<Result<_, IntegrityError>>()?,
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|child| encode(child, indices, objects, work, limits, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        _ => value.clone(),
    };
    if let Some(index) = index {
        objects.insert(index.clone(), body);
        Ok(reference(index, work.format))
    } else {
        Ok(body)
    }
}
