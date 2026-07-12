# warpin-types

`warpin-types` provides small shared value types for Warpin services. Version
`0.2.4` adds exact, float-free metering primitives for usage and microunit
settlement.

The crate does not define currency conversion, payer policy, tenant policy, or
provider-specific billing behavior. Those decisions remain with the consuming
service.

## Exact metering

```rust
use warpin_types::{ExactRate, ExactUsageQuantity, SettlementRounding};

let rate = ExactRate::new(3, 2)?;
let amount = rate.settle(
    ExactUsageQuantity::new(5),
    SettlementRounding::Ceiling,
)?;

assert_eq!(amount.get(), 8);
# Ok::<(), warpin_types::ExactMeteringError>(())
```

`ExactRate::new` reduces equivalent ratios to a canonical representation. All
zero rates normalize to `0/1`; a zero denominator is rejected.

Settlement multiplies the supplied aggregate quantity with checked `u128`
intermediate arithmetic and then converts the result to `u64`. Rounding is
applied once to the aggregate:

- `FLOOR` discards a fractional microunit remainder.
- `CEILING` adds one microunit when a remainder exists.
- `REJECT_INEXACT` rejects any settlement requiring rounding.

Callers should not settle each token or item separately unless their own domain
contract explicitly requires per-item rounding.

## Canonical JSON

Usage quantities and microunit amounts serialize as unsigned base-10 strings.
Rates use this exact object form:

```json
{
  "numeratorMicrounits": "3",
  "denominatorUnits": "2"
}
```

Deserialization rejects JSON numbers, signs, whitespace, leading zeroes,
decimal points, exponents, aliases, unknown fields, values above `u64::MAX`,
zero denominators, and non-reduced ratios. Rounding values are exactly
`FLOOR`, `CEILING`, or `REJECT_INEXACT`.

## Errors and overflow

The public `ExactMeteringError` variants distinguish a zero denominator, an
inexact settlement, and an amount overflow. Errors contain no usage value,
price, credential, tenant, or other caller data.

Consumers remain responsible for checking narrower persistence limits such as
PostgreSQL `BIGINT` and for binding currency and business charge policy.

## License

MIT. See [LICENSE](LICENSE).
