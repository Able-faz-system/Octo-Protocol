//! Convert Horizon decimal amount strings to integer stroops without floating point.
//!
//! Stellar amounts have exactly 7 decimal places (1 unit = 10_000_000 stroops). Horizon returns
//! them as strings like "10.0000000". We parse digit-by-digit to avoid float rounding.

/// Stroops per whole unit (7 decimal places).
const STROOPS_PER_UNIT: i64 = 10_000_000;
const DECIMALS: usize = 7;

/// Parse a Stellar decimal amount string into stroops. Returns `None` on malformed input or
/// overflow. Rejects negative and non-positive results (caller treats those as invalid).
///
/// More than 7 fractional digits is rejected, never truncated: sub-stroop precision can't be
/// represented, and rounding it away would credit a silently different amount.
pub fn to_stroops(amount: &str) -> Option<i64> {
    let amount = amount.trim();
    if amount.is_empty() || amount.starts_with('-') {
        return None;
    }

    let (int_part, frac_part) = match amount.split_once('.') {
        Some((i, f)) => (i, f),
        None => (amount, ""),
    };

    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
        // Sub-stroop precision: reject rather than truncate.
        || frac_part.len() > DECIMALS
    {
        return None;
    }

    let int_val: i64 = int_part.parse().ok()?;
    // Pad the fractional part to exactly 7 digits.
    let mut frac = String::with_capacity(DECIMALS);
    frac.push_str(frac_part);
    while frac.len() < DECIMALS {
        frac.push('0');
    }
    let frac_val: i64 = frac.parse().ok()?;

    int_val
        .checked_mul(STROOPS_PER_UNIT)
        .and_then(|v| v.checked_add(frac_val))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_and_fractional() {
        assert_eq!(to_stroops("1"), Some(10_000_000));
        assert_eq!(to_stroops("1.0000000"), Some(10_000_000));
        assert_eq!(to_stroops("10.5"), Some(105_000_000));
        assert_eq!(to_stroops("0.0000001"), Some(1));
        assert_eq!(to_stroops("10000.0000000"), Some(100_000_000_000));
    }

    #[test]
    fn rejects_garbage_and_negatives() {
        assert_eq!(to_stroops("-1"), None);
        assert_eq!(to_stroops("abc"), None);
        assert_eq!(to_stroops("1.234567890"), None); // too many decimals
        assert_eq!(to_stroops(""), None);
    }

    #[test]
    fn no_float_rounding() {
        // 0.1 + 0.2 style values are exact in stroops.
        assert_eq!(to_stroops("0.1000000"), Some(1_000_000));
        assert_eq!(to_stroops("0.2000000"), Some(2_000_000));
    }

    #[test]
    fn rejects_thousands_separators() {
        assert_eq!(to_stroops("1,000.0000000"), None);
    }

    #[test]
    fn rejects_scientific_notation() {
        assert_eq!(to_stroops("1e5"), None);
        assert_eq!(to_stroops("1E5"), None);
    }

    #[test]
    fn rejects_multiple_decimal_points() {
        assert_eq!(to_stroops("1.2.3"), None);
        assert_eq!(to_stroops("0.100000000.500000"), None);
    }

    #[test]
    fn overflowing_whole_units_returns_none_not_panic() {
        assert_eq!(to_stroops("214748364700000.123"), None);
    }

    #[test]
    fn leading_plus_sign_behavior_is_locked_in() {
        assert_eq!(to_stroops("+1.0000000"), None);
    }

    #[test]
    fn to_stroops_rejects_more_than_seven_fractional_digits() {
        assert_eq!(to_stroops("1.00000001"), None);
        assert_eq!(to_stroops("0.00000009"), None);
        // Trailing zeros still exceed native precision; the record is malformed, not rounded.
        assert_eq!(to_stroops("1.00000000"), None);
    }

    #[test]
    fn to_stroops_accepts_exactly_seven_fractional_digits() {
        assert_eq!(to_stroops("1.2345678"), Some(12_345_678));
        assert_eq!(to_stroops("0.9999999"), Some(9_999_999));
    }

    #[test]
    fn to_stroops_still_accepts_whole_number_amounts() {
        assert_eq!(to_stroops("0"), Some(0));
        assert_eq!(to_stroops("42"), Some(420_000_000));
    }
}
