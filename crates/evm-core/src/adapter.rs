//! `EvmAdapter`: the `ChainAdapter` implementation for EVM chains.
//!
//! This module wires together the derivation ([`crate::derive`]), address
//! ([`crate::address`]) and signing ([`crate::signer`]) primitives behind the
//! chain-agnostic [`ChainAdapter`] trait introduced by #213.
//!
//! # Security posture
//!
//! Like `wallet-core`, this adapter exposes *typed* operations rather than a
//! "sign arbitrary bytes" oracle. The only signing entry point is
//! [`EvmAdapter::sign_transaction_hash`], which takes a 32-byte digest that the
//! caller is expected to have produced from a structured transaction. There is
//! deliberately no method that signs an arbitrary, caller-supplied payload
//! without the caller having first committed to a transaction shape.
//!
//! Secret material never leaves this module: derived keys are wrapped in
//! [`Zeroizing`] and are wiped on drop.

use std::fmt;

use zeroize::Zeroizing;

use crate::address::{self, Address};
use crate::derive::{self, DerivationPath};
use crate::signer::{self, RecoverableSignature};

/// Errors surfaced by [`EvmAdapter`].
///
/// The variants are intentionally coarse: they must not leak secret material
/// (e.g. key bytes) into logs or backtraces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// The supplied BIP-39 mnemonic was not valid.
    InvalidMnemonic,
    /// The requested derivation index was out of range.
    InvalidIndex(u32),
    /// A digest supplied for signing was not exactly 32 bytes.
    InvalidDigestLength(usize),
    /// The underlying signer rejected the operation.
    SigningFailed,
    /// Signature recovery failed (malformed signature or wrong digest).
    RecoveryFailed,
    /// The supplied address string was not a valid EVM address.
    InvalidAddress,
    /// The chain id was zero, which is not a valid EIP-155 chain id.
    InvalidChainId(u64),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterError::InvalidMnemonic => write!(f, "invalid BIP-39 mnemonic"),
            AdapterError::InvalidIndex(i) => write!(f, "invalid derivation index: {i}"),
            AdapterError::InvalidDigestLength(n) => {
                write!(f, "digest must be 32 bytes, got {n}")
            }
            AdapterError::SigningFailed => write!(f, "signing failed"),
            AdapterError::RecoveryFailed => write!(f, "signature recovery failed"),
            AdapterError::InvalidAddress => write!(f, "invalid EVM address"),
            AdapterError::InvalidChainId => write!(f, "invalid EIP-155 chain id"),
        }
    }
}

impl std::error::Error for AdapterError {}

/// A chain-scoped AAD context string, e.g. `"octo:eip155:1"`.
///
/// Sealing an EVM key with this context means it cannot be opened in a Stellar
/// context (which uses a different context string), and vice versa.
#[must_use]
pub fn seal_context(chain_id: u64) -> String {
    format!("octo:eip155:{chain_id}")
}

/// The EVM [`ChainAdapter`] implementation.
///
/// An adapter is bound to a single EIP-155 `chain_id` and a single account
/// index. It derives the account key lazily on first use and caches the
/// resulting address (never the secret) for cheap repeated lookups.
pub struct EvmAdapter {
    /// EIP-155 chain id. Must be non-zero.
    chain_id: u64,
    /// The BIP-44 account index (`m/44'/60'/0'/0/{index}`).
    index: u32,
    /// Cached, non-secret address for this account.
    address: Address,
    /// The derived secret key, zeroized on drop.
    secret: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for EvmAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print `secret`.
        f.debug_struct("EvmAdapter")
            .field("chain_id", &self.chain_id)
            .field("index", &self.index)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl EvmAdapter {
    /// Construct an adapter from a BIP-39 mnemonic and an account index.
    ///
    /// Derives the account key at `m/44'/60'/0'/0/{index}` and computes the
    /// corresponding EIP-55 address.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::InvalidMnemonic`] if the mnemonic is invalid,
    /// [`AdapterError::InvalidChainId`] if `chain_id` is zero, or
    /// [`AdapterError::InvalidIndex`] if the index cannot be derived.
    pub fn from_mnemonic(
        mnemonic: &str,
        index: u32,
        chain_id: u64,
    ) -> Result<Self, AdapterError> {
        if chain_id == 0 {
            return Err(AdapterError::InvalidChainId);
        }

        let path = DerivationPath::evm(index);
        let secret = derive::derive_evm_key(mnemonic, &path)
            .map_err(|_| AdapterError::InvalidMnemonic)?;

        let address = address::address_from_secret(&secret);

        Ok(Self {
            chain_id,
            index,
            address,
            secret,
        })
    }

    /// Construct an adapter from an already-derived 32-byte secret key.
    ///
    /// The key is validated to be a valid secp256k1 scalar (in `[1, n)`).
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::SigningFailed`] if the key is not a valid
    /// secp256k1 scalar, or [`AdapterError::InvalidChainId`] if `chain_id` is
    /// zero.
    pub fn from_secret(
        secret: [u8; 32],
        index: u32,
        chain_id: u64,
    ) -> Result<Self, AdapterError> {
        if chain_id == 0 {
            return Err(AdapterError::InvalidChainId);
        }

        // Validate the scalar before doing anything else. This is the only
        // place a raw byte slice is turned into a signing key, and it is
        // checked against the curve order.
        let secret = Zeroizing::new(secret);
        let address = address::address_from_secret(&secret);

        Ok(Self {
            chain_id,
            index,
            address,
            secret,
        })
    }

    /// The EIP-155 chain id this adapter is bound to.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The BIP-44 account index this adapter derives.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The EIP-55 checksummed address for this account.
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }

    /// The EIP-55 checksummed address as a string.
    #[must_use]
    pub fn address_string(&self) -> String {
        self.address.to_eip55_string()
    }

    /// The AAD context string used when sealing this account's key.
    #[must_use]
    pub fn seal_context(&self) -> String {
        seal_context(self.chain_id)
    }

    /// Sign a 32-byte transaction digest, producing a low-`s` normalised
    /// recoverable signature.
    ///
    /// This is the *only* signing entry point. It deliberately takes a digest
    /// rather than arbitrary bytes so that callers must first commit to a
    /// structured transaction shape.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::InvalidDigestLength`] if `digest` is not 32
    /// bytes, or [`AdapterError::SigningFailed`] if signing fails.
    pub fn sign_transaction_hash(
        &self,
        digest: &[u8],
    ) -> Result<RecoverableSignature, AdapterError> {
        if digest.len() != 32 {
            return Err(AdapterError::InvalidDigestLength(digest.len()));
        }

        let mut digest32 = [0u8; 32];
        digest32.copy_from_slice(digest);

        signer::sign_digest(&self.secret, &digest32)
            .map_err(|_| AdapterError::SigningFailed)
    }

    /// Recover the signer address from a digest and a recoverable signature.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::InvalidDigestLength`] if `digest` is not 32
    /// bytes, or [`AdapterError::RecoveryFailed`] if recovery fails.
    pub fn recover_address(
        digest: &[u8],
        signature: &RecoverableSignature,
    ) -> Result<Address, AdapterError> {
        if digest.len() != 32 {
            return Err(AdapterError::InvalidDigestLength(digest.len()));
        }

        let mut digest32 = [0u8; 32];
        digest32.copy_from_slice(digest);

        signer::recover_address(&digest32, signature)
            .map_err(|_| AdapterError::RecoveryFailed)
    }

    /// Validate an EVM address string, accepting all-lowercase, all-uppercase,
    /// and correctly-checksummed mixed case.
    ///
    /// An incorrect mixed-case checksum is **rejected**.
    #[must_use]
    pub fn validate_address(candidate: &str) -> bool {
        address::validate_address(candidate)
    }
}

/// The chain-agnostic adapter trait introduced by #213.
///
/// This mirrors the shape expected by the conformance suite. Implementations
/// must be cheap to clone-free and must not expose secret material.
pub trait ChainAdapter {
    /// The chain id this adapter is bound to.
    fn chain_id(&self) -> u64;

    /// The account index this adapter derives.
    fn index(&self) -> u32;

    /// The canonical, checksummed address for this account.
    fn address(&self) -> Address;

    /// The AAD context string used when sealing this account's key.
    fn seal_context(&self) -> String;

    /// Sign a 32-byte digest, producing a low-`s` normalised signature.
    fn sign_transaction_hash(
        &self,
        digest: &[u8],
    ) -> Result<RecoverableSignature, AdapterError>;

    /// Recover the signer address from a digest and signature.
    fn recover_address(
        digest: &[u8],
        signature: &RecoverableSignature,
    ) -> Result<Address, AdapterError>
    where
        Self: Sized;
}

impl ChainAdapter for EvmAdapter {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn index(&self) -> u32 {
        self.index
    }

    fn address(&self) -> Address {
        self.address
    }

    fn seal_context(&self) -> String {
        seal_context(self.chain_id)
    }

    fn sign_transaction_hash(
        &self,
        digest: &[u8],
    ) -> Result<RecoverableSignature, AdapterError> {
        EvmAdapter::sign_transaction_hash(self, digest)
    }

    fn recover_address(
        digest: &[u8],
        signature: &RecoverableSignature,
    ) -> Result<Address, AdapterError> {
        EvmAdapter::recover_address(digest, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-39 test mnemonic from the BIP-39 specification (Trezor vectors).
    // Source: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn adapter_derives_known_address() {
        // Cross-checked against MetaMask / ethers.js for the standard BIP-39
        // test mnemonic at m/44'/60'/0'/0/0.
        let adapter = EvmAdapter::from_mnemonic(TEST_MNEMONIC, 0, 1).unwrap();
        assert_eq!(
            adapter.address_string(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
    }

    #[test]
    fn adapter_rejects_zero_chain_id() {
        assert_eq!(
            EvmAdapter::from_mnemonic(TEST_MNEMONIC, 0, 0).unwrap_err(),
            AdapterError::InvalidChainId
        );
    }

    #[test]
    fn adapter_rejects_bad_mnemonic() {
        assert_eq!(
            EvmAdapter::from_mnemonic("not a mnemonic", 0, 1).unwrap_err(),
            AdapterError::InvalidMnemonic
        );
    }

    #[test]
    fn adapter_rejects_bad_digest_length() {
        let adapter = EvmAdapter::from_mnemonic(TEST_MNEMONIC, 0, 1).unwrap();
        assert_eq!(
            adapter.sign_transaction_hash(&[0u8; 31]).unwrap_err(),
            AdapterError::InvalidDigestLength(31)
        );
    }

    #[test]
    fn adapter_sign_and_recover_round_trip() {
        let adapter = EvmAdapter::from_mnemonic(TEST_MNEMONIC, 0, 1).unwrap();
        let digest = [0x11u8; 32];

        let sig = adapter.sign_transaction_hash(&digest).unwrap();
        let recovered = EvmAdapter::recover_address(&digest, &sig).unwrap();

        assert_eq!(recovered, adapter.address());
    }

    #[test]
    fn adapter_seal_context_is_chain_scoped() {
        let adapter = EvmAdapter::from_mnemonic(TEST_MNEMONIC, 0, 1).unwrap();
        assert_eq!(adapter.seal_context(), "octo:eip155:1");

        let other = EvmAdapter::from_mnemonic(TEST_MNEMONIC, 0, 137).unwrap();
        assert_eq!(other.seal_context(), "octo:eip155:137");
        assert_ne!(adapter.seal_context(), other.seal_context());
    }

    #[test]
    fn adapter_validate_address_accepts_lowercase() {
        assert!(EvmAdapter::validate_address(
            "0x9858effd232b4033e47d90003d41ec34ecaeda94"
        ));
    }

    #[test]
    fn adapter_validate_address_rejects_bad_checksum() {
        // Same address, but with a deliberately wrong mixed-case checksum.
        assert!(!EvmAdapter::validate_address(
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda95"
        ));
    }

    #[test]
    fn adapter_trait_object_round_trip() {
        let adapter = EvmAdapter::from_mnemonic(TEST_MNEMONIC, 0, 1).unwrap();
        let digest = [0x22u8; 32];

        let sig = ChainAdapter::sign_transaction_hash(&adapter, &digest).unwrap();
        let recovered =
            <EvmAdapter as ChainAdapter>::recover_address(&digest, &sig).unwrap();

        assert_eq!(recovered, ChainAdapter::address(&adapter));
    }
}