use std::{collections::HashSet, fmt};

use serde::ser::{
    self, Impossible, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant,
};
use serde::{Serialize, Serializer};

use crate::number::{CapturedNumber, map_ser_error};
use crate::{CanonicalProfile, IntegrityError};

const MAX_CAPTURE_DEPTH: usize = 128;
const MAX_CAPTURE_NODES: usize = 100_000;
const MAX_CAPTURE_BYTES: usize = 1_048_576;
const MAX_COLLECTION_ITEMS: usize = 100_000;

struct CaptureBudget {
    profile: CanonicalProfile,
    nodes: usize,
    bytes: usize,
    collection_items: usize,
}

impl CaptureBudget {
    fn new(profile: CanonicalProfile) -> Self {
        Self {
            profile,
            nodes: 0,
            bytes: 0,
            collection_items: 0,
        }
    }

    fn ensure_depth(depth: usize) -> Result<(), CaptureError> {
        if depth > MAX_CAPTURE_DEPTH {
            return Err(CaptureError);
        }
        Ok(())
    }

    fn claim_node(&mut self, depth: usize) -> Result<(), CaptureError> {
        Self::ensure_depth(depth)?;
        if self.nodes >= MAX_CAPTURE_NODES {
            return Err(CaptureError);
        }
        self.nodes += 1;
        Ok(())
    }

    fn claim_bytes(&mut self, bytes: usize) -> Result<(), CaptureError> {
        self.ensure_bytes(bytes)?;
        self.bytes += bytes;
        Ok(())
    }

    fn ensure_bytes(&self, bytes: usize) -> Result<(), CaptureError> {
        if bytes > MAX_CAPTURE_BYTES.saturating_sub(self.bytes) {
            return Err(CaptureError);
        }
        Ok(())
    }

    fn claim_collection_item(&mut self) -> Result<(), CaptureError> {
        if self.collection_items >= MAX_COLLECTION_ITEMS {
            return Err(CaptureError);
        }
        self.collection_items += 1;
        Ok(())
    }

    fn validate_size_hint(&self, hint: usize) -> Result<(), CaptureError> {
        if hint > MAX_COLLECTION_ITEMS.saturating_sub(self.collection_items) {
            return Err(CaptureError);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CapturedValue {
    Null,
    Bool(bool),
    Number(CapturedNumber),
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl CapturedValue {
    pub(crate) fn into_json(self) -> Result<serde_json::Value, IntegrityError> {
        Ok(match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(value),
            Self::Number(CapturedNumber::I64(value)) => value.into(),
            Self::Number(CapturedNumber::U64(value)) => value.into(),
            Self::Number(CapturedNumber::F64(value)) => serde_json::Number::from_f64(value)
                .map(serde_json::Value::Number)
                .ok_or(IntegrityError::Canonicalization)?,
            Self::String(value) => serde_json::Value::String(value),
            Self::Array(values) => serde_json::Value::Array(
                values
                    .into_iter()
                    .map(Self::into_json)
                    .collect::<Result<_, _>>()?,
            ),
            Self::Object(entries) => {
                let mut object = serde_json::Map::with_capacity(entries.len());
                for (key, value) in entries {
                    object.insert(key, value.into_json()?);
                }
                serde_json::Value::Object(object)
            }
        })
    }
}

impl Serialize for CapturedValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(value) => value.serialize(serializer),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(values) => values.serialize(serializer),
            Self::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct CaptureError;

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("value cannot be captured as canonical JSON")
    }
}

impl std::error::Error for CaptureError {}

impl ser::Error for CaptureError {
    fn custom<T>(_message: T) -> Self
    where
        T: fmt::Display,
    {
        Self
    }
}

pub(crate) fn capture_typed<T>(
    value: &T,
    profile: CanonicalProfile,
) -> Result<CapturedValue, IntegrityError>
where
    T: Serialize + ?Sized,
{
    let mut budget = CaptureBudget::new(profile);
    value
        .serialize(CaptureSerializer {
            budget: &mut budget,
            depth: 0,
        })
        .map_err(|_| IntegrityError::Canonicalization)
}

struct CaptureSerializer<'a> {
    budget: &'a mut CaptureBudget,
    depth: usize,
}

impl<'a> CaptureSerializer<'a> {
    fn claim_node(&mut self) -> Result<(), CaptureError> {
        self.budget.claim_node(self.depth)
    }

    fn capture_string(mut self, value: &str) -> Result<CapturedValue, CaptureError> {
        self.claim_node()?;
        self.budget.claim_bytes(value.len())?;
        Ok(CapturedValue::String(value.to_owned()))
    }

    fn nested<T>(&mut self, value: &T) -> Result<CapturedValue, CaptureError>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(CaptureSerializer {
            budget: &mut *self.budget,
            depth: self.depth + 1,
        })
    }
}

impl<'a> Serializer for CaptureSerializer<'a> {
    type Ok = CapturedValue;
    type Error = CaptureError;
    type SerializeSeq = SequenceCapture<'a>;
    type SerializeTuple = SequenceCapture<'a>;
    type SerializeTupleStruct = SequenceCapture<'a>;
    type SerializeTupleVariant = SequenceCapture<'a>;
    type SerializeMap = ObjectCapture<'a>;
    type SerializeStruct = ObjectCapture<'a>;
    type SerializeStructVariant = ObjectCapture<'a>;

    fn serialize_bool(mut self, value: bool) -> Result<Self::Ok, Self::Error> {
        self.claim_node()?;
        Ok(CapturedValue::Bool(value))
    }

    fn serialize_i8(self, value: i8) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i16(self, value: i16) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i32(self, value: i32) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i64(mut self, value: i64) -> Result<Self::Ok, Self::Error> {
        self.claim_node()?;
        CapturedNumber::from_i128(i128::from(value), self.budget.profile)
            .map(CapturedValue::Number)
            .map_err(map_ser_error)
    }

    fn serialize_i128(mut self, value: i128) -> Result<Self::Ok, Self::Error> {
        self.claim_node()?;
        CapturedNumber::from_i128(value, self.budget.profile)
            .map(CapturedValue::Number)
            .map_err(map_ser_error)
    }

    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u16(self, value: u16) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u32(self, value: u32) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u64(mut self, value: u64) -> Result<Self::Ok, Self::Error> {
        self.claim_node()?;
        CapturedNumber::from_u128(u128::from(value), self.budget.profile)
            .map(CapturedValue::Number)
            .map_err(map_ser_error)
    }

    fn serialize_u128(mut self, value: u128) -> Result<Self::Ok, Self::Error> {
        self.claim_node()?;
        CapturedNumber::from_u128(value, self.budget.profile)
            .map(CapturedValue::Number)
            .map_err(map_ser_error)
    }

    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
        self.serialize_f64(f64::from(value))
    }

    fn serialize_f64(mut self, value: f64) -> Result<Self::Ok, Self::Error> {
        self.claim_node()?;
        CapturedNumber::from_f64(value, self.budget.profile)
            .map(CapturedValue::Number)
            .map_err(map_ser_error)
    }

    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        self.capture_string(&value.to_string())
    }

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        self.capture_string(value)
    }

    fn serialize_bytes(mut self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.claim_node()?;
        self.budget.validate_size_hint(value.len())?;
        self.budget.claim_bytes(value.len())?;
        for _ in value {
            self.budget.claim_collection_item()?;
            self.budget.claim_node(self.depth + 1)?;
        }
        Ok(CapturedValue::Array(
            value
                .iter()
                .map(|byte| CapturedValue::Number(CapturedNumber::U64(u64::from(*byte))))
                .collect(),
        ))
    }

    fn serialize_none(mut self) -> Result<Self::Ok, Self::Error> {
        self.claim_node()?;
        Ok(CapturedValue::Null)
    }

    fn serialize_some<T>(mut self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.nested(value)
    }

    fn serialize_unit(mut self) -> Result<Self::Ok, Self::Error> {
        self.claim_node()?;
        Ok(CapturedValue::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T>(
        mut self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.nested(value)
    }

    fn serialize_newtype_variant<T>(
        mut self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.claim_node()?;
        self.budget.claim_collection_item()?;
        self.budget.claim_bytes(variant.len())?;
        Ok(wrap_variant(variant, self.nested(value)?))
    }

    fn serialize_seq(mut self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.claim_node()?;
        SequenceCapture::new(self.budget, self.depth + 1, len.unwrap_or(0), None)
    }

    fn serialize_tuple(mut self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.claim_node()?;
        SequenceCapture::new(self.budget, self.depth + 1, len, None)
    }

    fn serialize_tuple_struct(
        mut self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.claim_node()?;
        SequenceCapture::new(self.budget, self.depth + 1, len, None)
    }

    fn serialize_tuple_variant(
        mut self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.claim_node()?;
        self.budget.claim_node(self.depth + 1)?;
        self.budget.claim_collection_item()?;
        self.budget.claim_bytes(variant.len())?;
        SequenceCapture::new(self.budget, self.depth + 2, len, Some(variant))
    }

    fn serialize_map(mut self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.claim_node()?;
        ObjectCapture::new(self.budget, self.depth + 1, len.unwrap_or(0), None)
    }

    fn serialize_struct(
        mut self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.claim_node()?;
        ObjectCapture::new(self.budget, self.depth + 1, len, None)
    }

    fn serialize_struct_variant(
        mut self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.claim_node()?;
        self.budget.claim_node(self.depth + 1)?;
        self.budget.claim_collection_item()?;
        self.budget.claim_bytes(variant.len())?;
        ObjectCapture::new(self.budget, self.depth + 2, len, Some(variant))
    }
}

pub(crate) struct SequenceCapture<'a> {
    budget: &'a mut CaptureBudget,
    child_depth: usize,
    values: Vec<CapturedValue>,
    variant: Option<&'static str>,
    failed: bool,
}

impl<'a> SequenceCapture<'a> {
    fn new(
        budget: &'a mut CaptureBudget,
        child_depth: usize,
        size_hint: usize,
        variant: Option<&'static str>,
    ) -> Result<Self, CaptureError> {
        budget.validate_size_hint(size_hint)?;
        Ok(Self {
            budget,
            child_depth,
            values: Vec::new(),
            variant,
            failed: false,
        })
    }

    fn push<T>(&mut self, value: &T) -> Result<(), CaptureError>
    where
        T: Serialize + ?Sized,
    {
        if self.failed {
            return Err(CaptureError);
        }
        let result = (|| {
            self.budget.claim_collection_item()?;
            self.values.push(value.serialize(CaptureSerializer {
                budget: &mut *self.budget,
                depth: self.child_depth,
            })?);
            Ok(())
        })();
        self.latch(result)
    }

    fn latch<T>(&mut self, result: Result<T, CaptureError>) -> Result<T, CaptureError> {
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn finish(self) -> Result<CapturedValue, CaptureError> {
        if self.failed {
            return Err(CaptureError);
        }
        let value = CapturedValue::Array(self.values);
        Ok(match self.variant {
            Some(variant) => wrap_variant(variant, value),
            None => value,
        })
    }
}

impl SerializeSeq for SequenceCapture<'_> {
    type Ok = CapturedValue;
    type Error = CaptureError;
    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.push(value)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

macro_rules! sequence_trait {
    ($trait:ident, $method:ident) => {
        impl $trait for SequenceCapture<'_> {
            type Ok = CapturedValue;
            type Error = CaptureError;
            fn $method<T>(&mut self, value: &T) -> Result<(), Self::Error>
            where
                T: Serialize + ?Sized,
            {
                self.push(value)
            }
            fn end(self) -> Result<Self::Ok, Self::Error> {
                self.finish()
            }
        }
    };
}

sequence_trait!(SerializeTuple, serialize_element);
sequence_trait!(SerializeTupleStruct, serialize_field);
sequence_trait!(SerializeTupleVariant, serialize_field);

pub(crate) struct ObjectCapture<'a> {
    budget: &'a mut CaptureBudget,
    child_depth: usize,
    entries: Vec<(String, CapturedValue)>,
    seen: HashSet<String>,
    pending_key: Option<String>,
    variant: Option<&'static str>,
    failed: bool,
}

impl<'a> ObjectCapture<'a> {
    fn new(
        budget: &'a mut CaptureBudget,
        child_depth: usize,
        size_hint: usize,
        variant: Option<&'static str>,
    ) -> Result<Self, CaptureError> {
        budget.validate_size_hint(size_hint)?;
        Ok(Self {
            budget,
            child_depth,
            entries: Vec::new(),
            seen: HashSet::new(),
            pending_key: None,
            variant,
            failed: false,
        })
    }

    fn insert<T>(&mut self, key: String, value: &T) -> Result<(), CaptureError>
    where
        T: Serialize + ?Sized,
    {
        if self.failed {
            return Err(CaptureError);
        }
        let result = (|| {
            self.budget.claim_collection_item()?;
            self.budget.claim_bytes(key.len())?;
            if !self.seen.insert(key.clone()) {
                return Err(CaptureError);
            }
            self.entries.push((
                key,
                value.serialize(CaptureSerializer {
                    budget: &mut *self.budget,
                    depth: self.child_depth,
                })?,
            ));
            Ok(())
        })();
        self.latch(result)
    }

    fn latch<T>(&mut self, result: Result<T, CaptureError>) -> Result<T, CaptureError> {
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn reject<T>(&mut self) -> Result<T, CaptureError> {
        self.failed = true;
        Err(CaptureError)
    }

    fn finish(self) -> Result<CapturedValue, CaptureError> {
        if self.failed || self.pending_key.is_some() {
            return Err(CaptureError);
        }
        let value = CapturedValue::Object(self.entries);
        Ok(match self.variant {
            Some(variant) => wrap_variant(variant, value),
            None => value,
        })
    }
}

impl SerializeMap for ObjectCapture<'_> {
    type Ok = CapturedValue;
    type Error = CaptureError;

    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        if self.failed || self.pending_key.is_some() {
            return self.reject();
        }
        let result = key.serialize(MapKeySerializer {
            budget: &mut *self.budget,
            depth: self.child_depth,
        });
        let key = self.latch(result)?;
        self.pending_key = Some(key);
        Ok(())
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        if self.failed {
            return Err(CaptureError);
        }
        let key = match self.pending_key.take() {
            Some(key) => key,
            None => return self.reject(),
        };
        self.insert(key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl SerializeStruct for ObjectCapture<'_> {
    type Ok = CapturedValue;
    type Error = CaptureError;
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.insert(key.to_owned(), value)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl SerializeStructVariant for ObjectCapture<'_> {
    type Ok = CapturedValue;
    type Error = CaptureError;
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.insert(key.to_owned(), value)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

fn wrap_variant(variant: &str, value: CapturedValue) -> CapturedValue {
    CapturedValue::Object(vec![(variant.to_owned(), value)])
}

struct MapKeySerializer<'a> {
    budget: &'a mut CaptureBudget,
    depth: usize,
}

impl MapKeySerializer<'_> {
    fn stringify<T>(self, value: T) -> Result<String, CaptureError>
    where
        T: fmt::Display,
    {
        CaptureBudget::ensure_depth(self.depth)?;
        let value = value.to_string();
        self.budget.ensure_bytes(value.len())?;
        Ok(value)
    }

    fn capture_str(self, value: &str) -> Result<String, CaptureError> {
        CaptureBudget::ensure_depth(self.depth)?;
        self.budget.ensure_bytes(value.len())?;
        Ok(value.to_owned())
    }

    fn nested<T>(self, value: &T) -> Result<String, CaptureError>
    where
        T: Serialize + ?Sized,
    {
        CaptureBudget::ensure_depth(self.depth)?;
        value.serialize(Self {
            budget: self.budget,
            depth: self.depth + 1,
        })
    }
}

impl Serializer for MapKeySerializer<'_> {
    type Ok = String;
    type Error = CaptureError;
    type SerializeSeq = Impossible<String, CaptureError>;
    type SerializeTuple = Impossible<String, CaptureError>;
    type SerializeTupleStruct = Impossible<String, CaptureError>;
    type SerializeTupleVariant = Impossible<String, CaptureError>;
    type SerializeMap = Impossible<String, CaptureError>;
    type SerializeStruct = Impossible<String, CaptureError>;
    type SerializeStructVariant = Impossible<String, CaptureError>;

    fn serialize_bool(self, value: bool) -> Result<Self::Ok, Self::Error> {
        self.stringify(value)
    }
    fn serialize_i8(self, value: i8) -> Result<Self::Ok, Self::Error> {
        self.stringify(value)
    }
    fn serialize_i16(self, value: i16) -> Result<Self::Ok, Self::Error> {
        self.stringify(value)
    }
    fn serialize_i32(self, value: i32) -> Result<Self::Ok, Self::Error> {
        self.stringify(value)
    }
    fn serialize_i64(self, value: i64) -> Result<Self::Ok, Self::Error> {
        CapturedNumber::from_i128(i128::from(value), self.budget.profile).map_err(map_ser_error)?;
        self.stringify(value)
    }
    fn serialize_i128(self, value: i128) -> Result<Self::Ok, Self::Error> {
        CapturedNumber::from_i128(value, self.budget.profile).map_err(map_ser_error)?;
        self.stringify(value)
    }
    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
        self.stringify(value)
    }
    fn serialize_u16(self, value: u16) -> Result<Self::Ok, Self::Error> {
        self.stringify(value)
    }
    fn serialize_u32(self, value: u32) -> Result<Self::Ok, Self::Error> {
        self.stringify(value)
    }
    fn serialize_u64(self, value: u64) -> Result<Self::Ok, Self::Error> {
        CapturedNumber::from_u128(u128::from(value), self.budget.profile).map_err(map_ser_error)?;
        self.stringify(value)
    }
    fn serialize_u128(self, value: u128) -> Result<Self::Ok, Self::Error> {
        CapturedNumber::from_u128(value, self.budget.profile).map_err(map_ser_error)?;
        self.stringify(value)
    }
    fn serialize_f32(self, _value: f32) -> Result<Self::Ok, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_f64(self, _value: f64) -> Result<Self::Ok, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        self.stringify(value)
    }
    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        self.capture_str(value)
    }
    fn serialize_bytes(self, _value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.nested(value)
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.capture_str(variant)
    }
    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.nested(value)
    }
    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        Err(CaptureError)
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Err(CaptureError)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(CaptureError)
    }
}
