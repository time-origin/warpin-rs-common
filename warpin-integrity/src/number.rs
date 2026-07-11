use serde::ser;

use crate::IntegrityError;

pub(crate) const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CapturedNumber {
    I64(i64),
    U64(u64),
    F64(f64),
}

impl CapturedNumber {
    pub(crate) fn from_i128(value: i128) -> Result<Self, IntegrityError> {
        let minimum = -i128::from(MAX_SAFE_INTEGER);
        let maximum = i128::from(MAX_SAFE_INTEGER);
        if !(minimum..=maximum).contains(&value) {
            return Err(IntegrityError::Canonicalization);
        }
        Ok(Self::I64(value as i64))
    }

    pub(crate) fn from_u128(value: u128) -> Result<Self, IntegrityError> {
        if value > u128::from(MAX_SAFE_INTEGER) {
            return Err(IntegrityError::Canonicalization);
        }
        Ok(Self::U64(value as u64))
    }

    pub(crate) fn from_f64(value: f64) -> Result<Self, IntegrityError> {
        if !value.is_finite() || (value.fract() == 0.0 && value.abs() > MAX_SAFE_INTEGER as f64) {
            return Err(IntegrityError::Canonicalization);
        }
        Ok(Self::F64(value))
    }

    pub(crate) fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::I64(value) => serializer.serialize_i64(*value),
            Self::U64(value) => serializer.serialize_u64(*value),
            Self::F64(value) => serializer.serialize_f64(*value),
        }
    }
}

pub(crate) fn parse_json_number(lexeme: &str) -> Result<CapturedNumber, IntegrityError> {
    let (negative, unsigned) = match lexeme.strip_prefix('-') {
        Some(value) => (true, value),
        None => (false, lexeme),
    };
    let (mantissa, exponent) = split_exponent(unsigned)?;
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (mantissa, ""),
    };
    let digits = format!("{integer}{fraction}");
    let nonzero = digits.bytes().any(|byte| byte != b'0');
    let scale = exponent
        .checked_sub(i64::try_from(fraction.len()).map_err(|_| IntegrityError::Canonicalization)?)
        .ok_or(IntegrityError::Canonicalization)?;

    if let Some(magnitude) = normalized_integer(&digits, scale)? {
        if negative {
            return CapturedNumber::from_i128(-i128::from(magnitude));
        }
        return CapturedNumber::from_u128(u128::from(magnitude));
    }

    let value = lexeme
        .parse::<f64>()
        .map_err(|_| IntegrityError::Canonicalization)?;
    if !value.is_finite() || (value == 0.0 && nonzero) {
        return Err(IntegrityError::Canonicalization);
    }
    Ok(CapturedNumber::F64(value))
}

fn split_exponent(value: &str) -> Result<(&str, i64), IntegrityError> {
    let Some(index) = value.find(['e', 'E']) else {
        return Ok((value, 0));
    };
    let (mantissa, exponent_with_marker) = value.split_at(index);
    let exponent = exponent_with_marker[1..]
        .parse::<i64>()
        .map_err(|_| IntegrityError::Canonicalization)?;
    Ok((mantissa, exponent))
}

fn normalized_integer(digits: &str, scale: i64) -> Result<Option<u64>, IntegrityError> {
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return Ok(Some(0));
    }

    let normalized = if scale >= 0 {
        let zeroes = usize::try_from(scale).map_err(|_| IntegrityError::Canonicalization)?;
        let length = significant
            .len()
            .checked_add(zeroes)
            .ok_or(IntegrityError::Canonicalization)?;
        if length > 16 {
            return Err(IntegrityError::Canonicalization);
        }
        let mut normalized = String::with_capacity(length);
        normalized.push_str(significant);
        normalized.extend(std::iter::repeat_n('0', zeroes));
        normalized
    } else {
        let removed =
            usize::try_from(scale.unsigned_abs()).map_err(|_| IntegrityError::Canonicalization)?;
        if removed > digits.len() {
            return Ok(None);
        }
        if !digits[digits.len() - removed..]
            .bytes()
            .all(|byte| byte == b'0')
        {
            return Ok(None);
        }
        digits[..digits.len() - removed]
            .trim_start_matches('0')
            .to_owned()
    };

    let normalized = if normalized.is_empty() {
        "0"
    } else {
        &normalized
    };
    if normalized.len() > 16 || (normalized.len() == 16 && normalized > "9007199254740991") {
        return Err(IntegrityError::Canonicalization);
    }
    normalized
        .parse::<u64>()
        .map(Some)
        .map_err(|_| IntegrityError::Canonicalization)
}

pub(crate) fn map_ser_error<E>(_error: IntegrityError) -> E
where
    E: ser::Error,
{
    E::custom("value cannot be represented in the I-JSON safe number domain")
}
