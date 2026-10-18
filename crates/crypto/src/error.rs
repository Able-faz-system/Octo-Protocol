//! Error type for sealing/opening secrets.
//!
//! Variants are intentionally coarse and carry **no** plaintext, key bytes, or cryptographic
//! detail — an attacker must not learn *why* a decryption failed (e.g. wrong key vs. tampered
//! ciphertext vs. wrong context), only that it did. This avoids padding/MAC oracle style leaks.

use thiserror::Error;

/// Errors returned by [`crate::seal`] and [`crate::open`].
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The master key was not exactly 32 bytes (AES-256 requires a 256-bit key).
    #[error("invalid master key length: expected {expected} bytes, got {actual}")]
    InvalidMasterKeyLength { expected: usize, actual: usize },

    /// A stored nonce was not the expected 12 bytes (corrupt record).
    #[error("invalid nonce length: expected 12 bytes")]
    InvalidNonceLength,

    /// Authenticated decryption failed. This is returned for *any* failure to open —
    /// wrong key, tampered ciphertext/nonce/tag, or mismatched AAD/context — on purpose.
    #[error("decryption failed: ciphertext could not be authenticated")]
    DecryptionFailed,

    /// Authenticated encryption failed (should not happen for well-formed inputs).
    #[error("encryption failed")]
    EncryptionFailed,

    /// A V2 record was opened without the account identity bound into its AAD.
    #[error("account identity is required to open this sealed seed")]
    AccountIdentityRequired,

    /// The `scheme` tag stored in a [`crate::SealedSeed`] is not a value this version of the
    /// code knows how to handle. The record must be migrated (re-sealed under the current scheme)
    /// before it can be opened.
    #[error("unknown sealed-seed scheme version: {0}")]
    UnknownScheme(u8),

    /// The boot-time [`crate::self_test`] failed. Names the failing stage, never any bytes.
    #[error("crypto self-test failed: {0}")]
    SelfTestFailed(&'static str),
}
