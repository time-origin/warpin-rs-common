use serde::ser;

use crate::{CanonicalProfile, IntegrityError};

pub(crate) const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CapturedNumber {
    I64(i64),
    U64(u64),
    F64(f64),
}

impl CapturedNumber {
    pub(crate) fn from_i128(
        value: i128,
        profile: CanonicalProfile,
    ) -> Result<Self, IntegrityError> {
        match profile {
            CanonicalProfile::Rfc8785 => {
                if !integer_is_exact_binary64(value.unsigned_abs()) {
                    return Err(IntegrityError::Canonicalization);
                }
                Ok(i64::try_from(value).map_or(Self::F64(value as f64), Self::I64))
            }
            CanonicalProfile::IJsonSafeIntegers => {
                let minimum = -i128::from(MAX_SAFE_INTEGER);
                let maximum = i128::from(MAX_SAFE_INTEGER);
                if !(minimum..=maximum).contains(&value) {
                    return Err(IntegrityError::Canonicalization);
                }
                Ok(Self::I64(value as i64))
            }
        }
    }

    pub(crate) fn from_u128(
        value: u128,
        profile: CanonicalProfile,
    ) -> Result<Self, IntegrityError> {
        match profile {
            CanonicalProfile::Rfc8785 => {
                if !integer_is_exact_binary64(value) {
                    return Err(IntegrityError::Canonicalization);
                }
                Ok(u64::try_from(value).map_or(Self::F64(value as f64), Self::U64))
            }
            CanonicalProfile::IJsonSafeIntegers => {
                if value > u128::from(MAX_SAFE_INTEGER) {
                    return Err(IntegrityError::Canonicalization);
                }
                Ok(Self::U64(value as u64))
            }
        }
    }

    pub(crate) fn from_f64(value: f64, profile: CanonicalProfile) -> Result<Self, IntegrityError> {
        if !value.is_finite()
            || (profile == CanonicalProfile::IJsonSafeIntegers
                && value.fract() == 0.0
                && value.abs() > MAX_SAFE_INTEGER as f64)
        {
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

pub(crate) fn parse_json_number(
    lexeme: &str,
    profile: CanonicalProfile,
) -> Result<CapturedNumber, IntegrityError> {
    if profile == CanonicalProfile::Rfc8785 {
        let value = lexeme
            .parse::<f64>()
            .map_err(|_| IntegrityError::Canonicalization)?;
        return CapturedNumber::from_f64(value, profile);
    }

    let (negative, unsigned) = match lexeme.strip_prefix('-') {
        Some(value) => (true, value),
        None => (false, lexeme),
    };
    let mantissa_end = unsigned.find(['e', 'E']).unwrap_or(unsigned.len());
    if unsigned[..mantissa_end]
        .bytes()
        .all(|byte| matches!(byte, b'0' | b'.'))
    {
        return Ok(CapturedNumber::U64(0));
    }
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
            return CapturedNumber::from_i128(-i128::from(magnitude), profile);
        }
        return CapturedNumber::from_u128(u128::from(magnitude), profile);
    }

    let value = lexeme
        .parse::<f64>()
        .map_err(|_| IntegrityError::Canonicalization)?;
    if !value.is_finite() || (value == 0.0 && nonzero) {
        return Err(IntegrityError::Canonicalization);
    }
    Ok(CapturedNumber::F64(value))
}

fn integer_is_exact_binary64(magnitude: u128) -> bool {
    let significant_bits = u128::BITS - magnitude.leading_zeros();
    let discarded_bits = significant_bits.saturating_sub(53);
    discarded_bits == 0 || magnitude.trailing_zeros() >= discarded_bits
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
    E::custom("value cannot be represented without canonical numeric loss")
}
