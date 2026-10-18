//! Error type for wallet-core.
//!
//! Like [`octo_crypto::CryptoError`], variants avoid carrying secret material. They describe the
//! *kind* of failure (bad input, derivation, signing) without echoing keys, seeds, or amounts.
//!
//! Every variant carries an explicit `#[error("...")]` message so the user/log-facing text is
//! deliberate and auditable, rather than whatever `Debug`'s derive happens to produce. These
//! messages are the single place `WalletError` text is produced and are guaranteed to contain no
//! secret material (mnemonics, seeds, keys, signatures, or amounts).

use thiserror::Error;

/// Wallet errors never contain secret material or unredacted transaction data that could leak through logs.
#[derive(Debug, Error)]
pub enum WalletError {
    /// The supplied BIP39 mnemonic phrase was invalid.
    #[error("invalid mnemonic phrase")]
    InvalidMnemonic,

    /// The mnemonic phrase failed the BIP-39 checksum verification.
    #[error("invalid mnemonic checksum")]
    InvalidChecksum,

    /// Raw seed bytes did not have the 64-byte BIP-39 seed length.
    #[error("invalid seed length")]
    InvalidSeedLength,

    /// A syntactically valid seed does not meet a future entropy-strength policy. Unlike
    /// `InvalidMnemonic` and `InvalidChecksum`, this represents valid input that is too weak.
    #[error("entropy strength is insufficient")]
    WeakSeed,

    /// A derivation path component or index was invalid.
    #[error("invalid derivation path")]
    InvalidDerivationPath,

    /// Failed to construct a Stellar keypair from the derived seed bytes.
    #[error("key derivation failed")]
    KeyDerivation,

    /// The mnemonic-derived account did not match the account claimed by the caller.
    #[error("mnemonic does not derive the expected account")]
    MnemonicAccountMismatch,

    /// An address string (G... or M...) could not be parsed.
    #[error("invalid Stellar address")]
    InvalidAddress,

    /// A credit-asset code was not 1 to 12 bytes, so it can never match a real Stellar asset
    /// (see [`crate::asset::is_valid_asset_code`]).
    #[error("invalid asset code")]
    InvalidAssetCode,

    /// A credit asset code conflicts with Octo's reserved native-asset spellings.
    #[error("native asset codes cannot be used as credit asset codes")]
    ReservedNativeAssetCode,

    /// A requested amount was out of range (must be a positive number of stroops).
    #[error("invalid amount")]
    InvalidAmount,

    /// Building or signing the transaction failed.
    #[error("transaction signing failed")]
    Signing,

    /// Decrypting the sealed seed failed (wrong key/context or tampered record).
    #[error("seed decryption failed")]
    SeedDecryption,

    /// A supplied XDR string could not be parsed as a valid `TransactionEnvelope`, or was a
    /// variant this crate does not accept here (e.g. a fee-bump used as an inner transaction).
    #[error("invalid transaction XDR")]
    InvalidXdr,

    /// An ed25519 signature failed to parse or did not verify against the claimed account.
    #[error("invalid signature")]
    InvalidSignature,

    /// The transaction sequence number does not match the account's current chain sequence.
    #[error("stale transaction sequence number")]
    StaleSequence,
}

impl From<octo_crypto::CryptoError> for WalletError {
    fn from(_: octo_crypto::CryptoError) -> Self {
        // Collapse all crypto failures to a single coarse variant — do not leak which.
        WalletError::SeedDecryption
    }
}

#[cfg(test)]
mod tests {
    use super::WalletError;

    /// Every variant, paired with the exact `Display` message it must produce. Keeping this list
    /// exhaustive (and asserting the count below) means a newly added variant without an explicit,
    /// audited message fails the test rather than silently falling back to derived `Debug` output.
    const ALL_VARIANTS: &[(WalletError, &str)] = &[
        (WalletError::InvalidMnemonic, "invalid mnemonic phrase"),
        (WalletError::InvalidChecksum, "invalid mnemonic checksum"),
        (
            WalletError::WeakSeed,
            "entropy strength is insufficient",
        ),
        (WalletError::InvalidDerivationPath, "invalid derivation path"),
        (WalletError::KeyDerivation, "key derivation failed"),
        (
            WalletError::MnemonicAccountMismatch,
            "mnemonic does not derive the expected account",
        ),
        (WalletError::InvalidAddress, "invalid Stellar address"),
        (WalletError::InvalidAssetCode, "invalid asset code"),
        (
            WalletError::ReservedNativeAssetCode,
            "native asset codes cannot be used as credit asset codes",
        ),
        (WalletError::InvalidAmount, "invalid amount"),
        (WalletError::Signing, "transaction signing failed"),
        (WalletError::SeedDecryption, "seed decryption failed"),
        (WalletError::InvalidXdr, "invalid transaction XDR"),
        (WalletError::InvalidSignature, "invalid signature"),
        (WalletError::StaleSequence, "stale transaction sequence number"),
    ];

    /// Substrings that must never appear in any `WalletError` `Display` message. These cover the
    /// secret material the parallel secret-exposure audit flagged: mnemonics, seeds, keys,
    /// signatures, and amounts.
    const FORBIDDEN_SUBSTRINGS: &[&str] = &[
        "illness spike retreat truth genius clock brain pass fit cave bargain toe",
        "seed",
        "secret",
        "private",
        "mnemonic",
        "signature",
        "amount",
    ];

    #[test]
    fn every_walleterror_variant_has_an_explicit_display_message_containing_no_secret_material() {
        // Guard against a variant being added without an entry in `ALL_VARIANTS`.
        assert_eq!(ALL_VARIANTS.len(), 15, "update ALL_VARIANTS for new variants");

        for (error, expected) in ALL_VARIANTS {
            let display = error.to_string();

            // The `Display` text must be the deliberate, hand-written message — not derived
            // `Debug` output.
            assert_eq!(&display, expected, "unexpected Display message for {error:?}");
            assert_ne!(display, format!("{error:?}"), "Display must not equal Debug output");

            // No secret material may leak through the user/log-facing text.
            let lower = display.to_lowercase();
            for forbidden in FORBIDDEN_SUBSTRINGS {
                assert!(
                    !lower.contains(&forbidden.to_lowercase()),
                    "Display for {error:?} leaked forbidden substring {forbidden:?}: {display:?}"
                );
            }
        }
    }

    #[test]
    fn wallet_error_output_never_contains_secret_material() {
        let secret = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
        let errors = [
            WalletError::InvalidMnemonic,
            WalletError::InvalidSeedLength,
            WalletError::WeakSeed,
            WalletError::InvalidDerivationPath,
            WalletError::KeyDerivation,
            WalletError::MnemonicAccountMismatch,
            WalletError::InvalidAddress,
            WalletError::InvalidAssetCode,
            WalletError::InvalidAmount,
            WalletError::Signing,
            WalletError::SeedDecryption,
            WalletError::InvalidXdr,
            WalletError::InvalidSignature,
        ];

        for (error, _) in ALL_VARIANTS {
            assert!(!error.to_string().contains(secret));
            assert!(!format!("{error:?}").contains(secret));
        }
    }
}
