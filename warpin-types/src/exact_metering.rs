use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Failure returned by exact integer metering operations.
#[derive(Clone, Copy, Debug, Eq, Error, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ExactMeteringError {
    /// A rational rate cannot have a zero denominator.
    #[error("exact metering denominator must be positive")]
    ZeroDenominator,
    /// The selected policy rejects a settlement that would require rounding.
    #[error("exact metering settlement is inexact")]
    InexactSettlement,
    /// The exact result cannot be represented as an unsigned 64-bit amount.
    #[error("exact metering amount overflow")]
    AmountOverflow,
}

/// An aggregate, non-negative usage quantity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExactUsageQuantity(u64);

impl ExactUsageQuantity {
    /// Creates an exact usage quantity.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying quantity.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Serialize for ExactUsageQuantity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_u64_decimal(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for ExactUsageQuantity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_u64_decimal(deserializer).map(Self)
    }
}

/// A non-negative amount expressed in the caller's microunit currency.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NonNegativeMicrounits(u64);

impl NonNegativeMicrounits {
    /// Creates a non-negative microunit amount.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying amount.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Adds two amounts without permitting integer wraparound.
    pub fn checked_add(self, other: Self) -> Result<Self, ExactMeteringError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(ExactMeteringError::AmountOverflow)
    }
}

impl Serialize for NonNegativeMicrounits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_u64_decimal(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for NonNegativeMicrounits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_u64_decimal(deserializer).map(Self)
    }
}

/// Rounding applied once to an aggregate exact settlement.
///
/// Callers must not round per token or per item unless their own domain contract
/// explicitly defines that behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SettlementRounding {
    /// Discard any fractional microunit remainder.
    Floor,
    /// Add one microunit when a fractional remainder exists.
    Ceiling,
    /// Reject a result with a fractional microunit remainder.
    RejectInexact,
}

/// A canonical non-negative rational microunit rate per usage unit.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactRate {
    #[serde(serialize_with = "serialize_u64_decimal")]
    numerator_microunits: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    denominator_units: u64,
}

impl ExactRate {
    /// Constructs and reduces a canonical rate.
    ///
    /// Every zero rate is represented as `0/1`.
    pub fn new(
        numerator_microunits: u64,
        denominator_units: u64,
    ) -> Result<Self, ExactMeteringError> {
        if denominator_units == 0 {
            return Err(ExactMeteringError::ZeroDenominator);
        }
        if numerator_microunits == 0 {
            return Ok(Self {
                numerator_microunits: 0,
                denominator_units: 1,
            });
        }

        let divisor = greatest_common_divisor(numerator_microunits, denominator_units);
        Ok(Self {
            numerator_microunits: numerator_microunits / divisor,
            denominator_units: denominator_units / divisor,
        })
    }

    /// Returns the canonical numerator in microunits.
    pub const fn numerator_microunits(&self) -> u64 {
        self.numerator_microunits
    }

    /// Returns the canonical denominator in usage units.
    pub const fn denominator_units(&self) -> u64 {
        self.denominator_units
    }

    /// Settles one aggregate quantity with checked wide-integer arithmetic.
    pub fn settle(
        &self,
        quantity: ExactUsageQuantity,
        rounding: SettlementRounding,
    ) -> Result<NonNegativeMicrounits, ExactMeteringError> {
        let product = u128::from(self.numerator_microunits)
            .checked_mul(u128::from(quantity.get()))
            .ok_or(ExactMeteringError::AmountOverflow)?;
        let denominator = u128::from(self.denominator_units);
        let quotient = product / denominator;
        let remainder = product % denominator;

        let rounded = match (rounding, remainder) {
            (_, 0) | (SettlementRounding::Floor, _) => quotient,
            (SettlementRounding::Ceiling, _) => quotient
                .checked_add(1)
                .ok_or(ExactMeteringError::AmountOverflow)?,
            (SettlementRounding::RejectInexact, _) => {
                return Err(ExactMeteringError::InexactSettlement);
            }
        };

        u64::try_from(rounded)
            .map(NonNegativeMicrounits::new)
            .map_err(|_| ExactMeteringError::AmountOverflow)
    }
}

impl<'de> Deserialize<'de> for ExactRate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireRate {
            #[serde(deserialize_with = "deserialize_u64_decimal")]
            numerator_microunits: u64,
            #[serde(deserialize_with = "deserialize_u64_decimal")]
            denominator_units: u64,
        }

        let wire = WireRate::deserialize(deserializer)?;
        let canonical = Self::new(wire.numerator_microunits, wire.denominator_units)
            .map_err(D::Error::custom)?;
        if canonical.numerator_microunits != wire.numerator_microunits
            || canonical.denominator_units != wire.denominator_units
        {
            return Err(D::Error::custom(
                "exact rate must use its canonical reduced form",
            ));
        }
        Ok(canonical)
    }
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn serialize_u64_decimal<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_u64_decimal<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(D::Error::custom(
            "expected a canonical unsigned decimal string",
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| D::Error::custom("unsigned decimal string exceeds u64"))
}

#[cfg(test)]
mod tests {
    use super::{
        ExactMeteringError, ExactRate, ExactUsageQuantity, NonNegativeMicrounits,
        SettlementRounding,
    };

    #[test]
    fn exact_rate_rejects_zero_denominator_and_normalizes_equivalent_values() {
        assert_eq!(
            ExactRate::new(3, 0),
            Err(ExactMeteringError::ZeroDenominator)
        );
        assert_eq!(
            ExactRate::new(0, 99).unwrap(),
            ExactRate::new(0, 1).unwrap()
        );
        assert_eq!(ExactRate::new(6, 8).unwrap(), ExactRate::new(3, 4).unwrap());
    }

    #[test]
    fn settlement_handles_zero_exact_floor_ceiling_and_reject_inexact() {
        let rate = ExactRate::new(3, 2).unwrap();
        assert_eq!(
            rate.settle(ExactUsageQuantity::new(0), SettlementRounding::Ceiling),
            Ok(NonNegativeMicrounits::new(0))
        );
        assert_eq!(
            rate.settle(
                ExactUsageQuantity::new(4),
                SettlementRounding::RejectInexact
            ),
            Ok(NonNegativeMicrounits::new(6))
        );
        assert_eq!(
            rate.settle(ExactUsageQuantity::new(3), SettlementRounding::Floor),
            Ok(NonNegativeMicrounits::new(4))
        );
        assert_eq!(
            rate.settle(ExactUsageQuantity::new(3), SettlementRounding::Ceiling),
            Ok(NonNegativeMicrounits::new(5))
        );
        assert_eq!(
            rate.settle(
                ExactUsageQuantity::new(3),
                SettlementRounding::RejectInexact
            ),
            Err(ExactMeteringError::InexactSettlement)
        );
    }

    #[test]
    fn settlement_uses_wide_intermediate_and_reports_result_overflow() {
        let exact = ExactRate::new(u64::MAX, u64::MAX).unwrap();
        assert_eq!(
            exact.settle(
                ExactUsageQuantity::new(u64::MAX),
                SettlementRounding::RejectInexact,
            ),
            Ok(NonNegativeMicrounits::new(u64::MAX))
        );

        let overflowing = ExactRate::new(u64::MAX, 1).unwrap();
        assert_eq!(
            overflowing.settle(ExactUsageQuantity::new(2), SettlementRounding::Floor),
            Err(ExactMeteringError::AmountOverflow)
        );
    }

    #[test]
    fn amount_addition_is_checked() {
        assert_eq!(
            NonNegativeMicrounits::new(4).checked_add(NonNegativeMicrounits::new(5)),
            Ok(NonNegativeMicrounits::new(9))
        );
        assert_eq!(
            NonNegativeMicrounits::new(u64::MAX).checked_add(NonNegativeMicrounits::new(1)),
            Err(ExactMeteringError::AmountOverflow)
        );
    }

    #[test]
    fn canonical_json_round_trips_as_decimal_strings() {
        assert_eq!(
            serde_json::to_string(&ExactUsageQuantity::new(42)).unwrap(),
            "\"42\""
        );
        assert_eq!(
            serde_json::to_string(&NonNegativeMicrounits::new(9001)).unwrap(),
            "\"9001\""
        );
        assert_eq!(
            serde_json::to_string(&ExactRate::new(6, 8).unwrap()).unwrap(),
            r#"{"numeratorMicrounits":"3","denominatorUnits":"4"}"#
        );
        assert_eq!(
            serde_json::to_string(&ExactRate::new(0, u64::MAX).unwrap()).unwrap(),
            r#"{"numeratorMicrounits":"0","denominatorUnits":"1"}"#
        );
        assert_eq!(
            serde_json::to_string(&SettlementRounding::RejectInexact).unwrap(),
            "\"REJECT_INEXACT\""
        );

        let rate: ExactRate =
            serde_json::from_str(r#"{"numeratorMicrounits":"3","denominatorUnits":"4"}"#).unwrap();
        assert_eq!(rate, ExactRate::new(3, 4).unwrap());
        assert_eq!(
            serde_json::from_value::<ExactUsageQuantity>(serde_json::json!("42")).unwrap(),
            ExactUsageQuantity::new(42)
        );
        assert_eq!(
            serde_json::from_str::<NonNegativeMicrounits>(&format!("\"{}\"", u64::MAX)).unwrap(),
            NonNegativeMicrounits::new(u64::MAX)
        );
    }

    #[test]
    fn decimal_deserialization_rejects_noncanonical_representations() {
        for invalid in [
            "42",
            r#""+1""#,
            r#"" 1""#,
            r#""01""#,
            r#""""#,
            r#""1.0""#,
            r#""1e2""#,
            r#""18446744073709551616""#,
        ] {
            assert!(
                serde_json::from_str::<ExactUsageQuantity>(invalid).is_err(),
                "accepted invalid usage JSON: {invalid}"
            );
        }
    }

    #[test]
    fn exact_rate_deserialization_rejects_aliases_unknown_fields_and_noncanonical_ratio() {
        for invalid in [
            r#"{"numeratorMicrounits":3,"denominatorUnits":"4"}"#,
            r#"{"numerator_microunits":"3","denominatorUnits":"4"}"#,
            r#"{"numeratorMicrounits":"3","denominatorUnits":"4","extra":"x"}"#,
            r#"{"numeratorMicrounits":"3","numeratorMicrounits":"3","denominatorUnits":"4"}"#,
            r#"{"numeratorMicrounits":"3"}"#,
            r#"{"numeratorMicrounits":"6","denominatorUnits":"8"}"#,
            r#"{"numeratorMicrounits":"1","denominatorUnits":"0"}"#,
        ] {
            assert!(
                serde_json::from_str::<ExactRate>(invalid).is_err(),
                "accepted invalid rate JSON: {invalid}"
            );
        }
        assert!(serde_json::from_str::<SettlementRounding>(r#""ROUND_HALF_UP""#).is_err());
        assert!(serde_json::from_str::<SettlementRounding>("1").is_err());
        assert!(serde_json::from_str::<NonNegativeMicrounits>("1").is_err());
    }

    #[test]
    fn bounded_rounding_properties_hold_for_normalized_equivalent_rates() {
        for numerator in 0..=32_u64 {
            for denominator in 1..=16_u64 {
                let rate = ExactRate::new(numerator, denominator).unwrap();
                let equivalent = ExactRate::new(numerator * 7, denominator * 7).unwrap();
                for quantity in 0..=64_u64 {
                    let usage = ExactUsageQuantity::new(quantity);
                    let floor = rate.settle(usage, SettlementRounding::Floor).unwrap().get();
                    let ceiling = rate
                        .settle(usage, SettlementRounding::Ceiling)
                        .unwrap()
                        .get();
                    assert!(floor <= ceiling);
                    assert!(ceiling - floor <= 1);
                    assert_eq!(
                        floor,
                        equivalent
                            .settle(usage, SettlementRounding::Floor)
                            .unwrap()
                            .get()
                    );
                    assert_eq!(
                        ceiling,
                        equivalent
                            .settle(usage, SettlementRounding::Ceiling)
                            .unwrap()
                            .get()
                    );
                }
            }
        }
    }
}
