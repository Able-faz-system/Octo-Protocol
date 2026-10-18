//! Ethereum address derivation and EIP-55 checksum handling.
//!
//! An Ethereum address is the last 20 bytes of the keccak-256 hash of the
//! *uncompressed* (65-byte, `0x04`-prefixed) secp256k1 public key.
//!
//! The textual representation uses [EIP-55] mixed-case checksums: the case of
//! each hex letter encodes a bit of the keccak-256 hash of the lowercase
//! address. This gives a cheap typo-detection property, but *only* if the
//! checksum is actually verified — lowercasing before comparison silently
//! discards it, so [`validate_address`] deliberately does not do that.
//!
//! [EIP-55]: https://eips.ethereum.org/EIPS/eip-55

use core::fmt;

use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

/// Length of a raw Ethereum address in bytes.
pub const ADDRESS_LENGTH: usize = 20;

/// Length of a checksummed address in hex characters (no `0x` prefix).
pub const ADDRESS_HEX_LENGTH: usize = ADDRESS_LENGTH * 2;

/// A 20-byte Ethereum address.
///
/// Addresses are public data, so this type does not zeroize on drop.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; ADDRESS_LENGTH]);

impl Address {
    /// Constructs an address from its raw 20-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ADDRESS_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 20-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ADDRESS_LENGTH] {
        &self.0
    }

    /// Derives an address from an uncompressed secp256k1 public key.
    ///
    /// The input must be the 65-byte SEC1 uncompressed encoding
    /// (`0x04 || X || Y`). The address is the last 20 bytes of the
    /// keccak-256 hash of those 65 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AddressError::InvalidPublicKeyLength`] if `public_key` is not
    /// exactly 65 bytes, or [`AddressError::InvalidPublicKeyPrefix`] if the
    /// leading byte is not `0x04`.
    pub fn from_uncompressed_public_key(public_key: &[u8]) -> Result<Self, AddressError> {
        if public_key.len() != 65 {
            return Err(AddressError::InvalidPublicKeyLength(public_key.len()));
        }
        if public_key[0] != 0x04 {
            return Err(AddressError::InvalidPublicKeyPrefix(public_key[0]));
        }

        let digest = Keccak256::digest(&public_key[1..]);
        let mut bytes = [0u8; ADDRESS_LENGTH];
        bytes.copy_from_slice(&digest[12..]);
        Ok(Self(bytes))
    }

    /// Returns the lowercase hex representation, without a `0x` prefix.
    #[must_use]
    pub fn to_lowercase_hex(&self) -> String {
        let mut out = String::with_capacity(ADDRESS_HEX_LENGTH);
        for byte in self.0 {
            // `write!` into a `String` cannot fail.
            let _ = fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
        }
        out
    }

    /// Returns the [EIP-55] checksummed representation, without a `0x` prefix.
    ///
    /// [EIP-55]: https://eips.ethereum.org/EIPS/eip-55
    #[must_use]
    pub fn to_checksum_hex(&self) -> String {
        let lowercase = self.to_lowercase_hex();
        let hash = Keccak256::digest(lowercase.as_bytes());

        let mut out = String::with_capacity(ADDRESS_HEX_LENGTH);
        for (i, ch) in lowercase.chars().enumerate() {
            // Each nibble of the hash decides the case of the corresponding
            // hex character: >= 8 means uppercase.
            let nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 0x0f
            };
            if nibble >= 8 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        }
        out
    }

    /// Returns the [EIP-55] checksummed representation with a `0x` prefix.
    ///
    /// [EIP-55]: https://eips.ethereum.org/EIPS/eip-55
    #[must_use]
    pub fn to_checksum_string(&self) -> String {
        let mut out = String::with_capacity(2 + ADDRESS_HEX_LENGTH);
        out.push_str("0x");
        out.push_str(&self.to_checksum_hex());
        out
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug output is checksummed so that it round-trips through
        // `validate_address` and is copy-pasteable.
        write!(f, "Address({})", self.to_checksum_string())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_checksum_string())
    }
}

/// Errors produced while deriving or parsing an Ethereum address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// The public key was not 65 bytes long.
    InvalidPublicKeyLength(usize),
    /// The public key did not start with the `0x04` uncompressed marker.
    InvalidPublicKeyPrefix(u8),
    /// The address string had the wrong length.
    InvalidLength(usize),
    /// The address string contained a non-hexadecimal character.
    InvalidCharacter(char),
    /// The address string had mixed case but an incorrect EIP-55 checksum.
    InvalidChecksum,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKeyLength(len) => {
                write!(f, "uncompressed public key must be 65 bytes, got {len}")
            }
            Self::InvalidPublicKeyPrefix(byte) => {
                write!(f, "uncompressed public key must start with 0x04, got 0x{byte:02x}")
            }
            Self::InvalidLength(len) => {
                write!(f, "address must be 40 hex characters, got {len}")
            }
            Self::InvalidCharacter(ch) => write!(f, "address contains non-hex character {ch:?}"),
            Self::InvalidChecksum => f.write_str("address has an invalid EIP-55 checksum"),
        }
    }
}

impl std::error::Error for AddressError {}

/// Parses an Ethereum address from a hex string.
///
/// Accepts an optional `0x`/`0X` prefix. The checksum rules follow EIP-55:
///
/// * an all-lowercase address is accepted (checksum not encoded),
/// * an all-uppercase address is accepted (checksum not encoded),
/// * a mixed-case address is accepted **only** if its EIP-55 checksum is
///   correct.
///
/// The mixed-case branch is the whole point: an address with a single
/// mistyped character will almost always have a wrong checksum, and rejecting
/// it is what turns the checksum into typo detection. Lowercasing before
/// comparing would silently discard that property.
///
/// # Errors
///
/// Returns an [`AddressError`] describing the first problem found.
pub fn validate_address(input: &str) -> Result<Address, AddressError> {
    let hex = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);

    if hex.len() != ADDRESS_HEX_LENGTH {
        return Err(AddressError::InvalidLength(hex.len()));
    }

    let mut bytes = [0u8; ADDRESS_LENGTH];
    let mut has_upper = false;
    let mut has_lower = false;

    for (i, ch) in hex.chars().enumerate() {
        let value = match ch {
            '0'..='9' => ch as u8 - b'0',
            'a'..='f' => {
                has_lower = true;
                ch as u8 - b'a' + 10
            }
            'A'..='F' => {
                has_upper = true;
                ch as u8 - b'A' + 10
            }
            other => return Err(AddressError::InvalidCharacter(other)),
        };
        if i % 2 == 0 {
            bytes[i / 2] = value << 4;
        } else {
            bytes[i / 2] |= value;
        }
    }

    let address = Address(bytes);

    // Only mixed-case input carries a checksum to verify. All-lowercase and
    // all-uppercase are both accepted as "checksum not encoded".
    if has_upper && has_lower && hex != address.to_checksum_hex() {
        return Err(AddressError::InvalidChecksum);
    }

    Ok(address)
}

/// Derives an address from an uncompressed public key and returns it in
/// EIP-55 checksummed form.
///
/// # Errors
///
/// See [`Address::from_uncompressed_public_key`].
pub fn address_from_public_key(public_key: &[u8]) -> Result<Zeroizing<String>, AddressError> {
    let address = Address::from_uncompressed_public_key(public_key)?;
    Ok(Zeroizing::new(address.to_checksum_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EIP-55 test vectors.
    ///
    /// Source: <https://eips.ethereum.org/EIPS/eip-55> — the "Test Cases"
    /// section of the EIP, reproduced verbatim.
    const EIP55_VECTORS: &[&str] = &[
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];

    #[test]
    fn eip55_vectors_round_trip() {
        for expected in EIP55_VECTORS {
            let address = validate_address(expected).expect("vector must validate");
            assert_eq!(
                &address.to_checksum_string(),
                expected,
                "checksum encoding must reproduce the EIP-55 vector"
            );
        }
    }

    #[test]
    fn eip55_vectors_accept_lowercase_and_uppercase() {
        for expected in EIP55_VECTORS {
            let address = validate_address(expected).expect("vector must validate");

            let lowercase = expected.to_ascii_lowercase();
            assert_eq!(
                validate_address(&lowercase).expect("lowercase must validate"),
                address
            );

            let uppercase = format!("0x{}", expected[2..].to_ascii_uppercase());
            assert_eq!(
                validate_address(&uppercase).expect("uppercase must validate"),
                address
            );
        }
    }

    #[test]
    fn eip55_vectors_accept_without_prefix() {
        for expected in EIP55_VECTORS {
            let address = validate_address(expected).expect("vector must validate");
            let bare = &expected[2..];
            assert_eq!(
                validate_address(bare).expect("bare hex must validate"),
                address
            );
        }
    }

    #[test]
    fn wrong_checksum_mixed_case_is_rejected() {
        // Negative cases: flip the case of a single hex letter in each EIP-55
        // vector. The result is still valid hex of the right length, but the
        // mixed-case checksum no longer matches, so it must be rejected.
        for expected in EIP55_VECTORS {
            let mut chars: Vec<char> = expected.chars().collect();
            let mut flipped = false;
            for ch in chars.iter_mut().skip(2) {
                if ch.is_ascii_hexdigit() && !ch.is_ascii_digit() {
                    *ch = if ch.is_ascii_uppercase() {
                        ch.to_ascii_lowercase()
                    } else {
                        ch.to_ascii_uppercase()
                    };
                    flipped = true;
                    break;
                }
            }
            assert!(flipped, "vector must contain at least one hex letter");

            let corrupted: String = chars.into_iter().collect();
            assert_eq!(
                validate_address(&corrupted),
                Err(AddressError::InvalidChecksum),
                "corrupted checksum {corrupted} must be rejected"
            );
        }
    }

    #[test]
    fn wrong_checksum_single_character_typo_is_rejected() {
        // A realistic typo: change one hex digit of a checksummed address.
        // The mixed case is preserved, so the checksum must catch it.
        let original = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let typo = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe0";
        assert_eq!(
            validate_address(typo),
            Err(AddressError::InvalidChecksum),
            "a single-character typo must be caught by the checksum"
        );
        assert!(validate_address(original).is_ok());
    }

    #[test]
    fn rejects_bad_length() {
        assert_eq!(
            validate_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe"),
            Err(AddressError::InvalidLength(39))
        );
        assert_eq!(
            validate_address(""),
            Err(AddressError::InvalidLength(0))
        );
    }

    #[test]
    fn rejects_non_hex_characters() {
        assert_eq!(
            validate_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeZ"),
            Err(AddressError::InvalidCharacter('Z'))
        );
    }

    #[test]
    fn derives_known_address_from_public_key() {
        // Public key for the well-known private key
        // 0x0000000000000000000000000000000000000000000000000000000000000001.
        // Source: SEC1 encoding of G, the secp256k1 generator point
        // (SEC 2 / https://www.secg.org/sec2-v2.pdf, §2.4.1).
        let public_key = hex_to_bytes(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
             483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        );
        let address = Address::from_uncompressed_public_key(&public_key).expect("valid key");
        // Address for private key 0x...01, cross-checked against
        // `ethers.js` v6 `new ethers.Wallet("0x" + "0".repeat(63) + "1").address`.
        assert_eq!(
            address.to_checksum_string(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
    }

    #[test]
    fn rejects_bad_public_key() {
        assert_eq!(
            Address::from_uncompressed_public_key(&[0x04; 64]),
            Err(AddressError::InvalidPublicKeyLength(64))
        );
        assert_eq!(
            Address::from_uncompressed_public_key(&[0x03; 65]),
            Err(AddressError::InvalidPublicKeyPrefix(0x03))
        );
    }

    #[test]
    fn debug_and_display_are_checksummed() {
        let address = validate_address(EIP55_VECTORS[0]).expect("vector must validate");
        assert_eq!(format!("{address}"), EIP55_VECTORS[0]);
        assert_eq!(
            format!("{address:?}"),
            format!("Address({})", EIP55_VECTORS[0])
        );
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(cleaned.len() % 2 == 0);
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("valid hex"))
            .collect()
    }
}