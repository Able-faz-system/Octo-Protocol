//! # octo-evm-core
//!
//! EVM (secp256k1 / BIP-32 / BIP-44) key derivation, address encoding, and signing
//! primitives for Octo Protocol.
//!
//! ## Secret key material
//!
//! **This crate handles secret key material.** It inherits `wallet-core`'s full lint
//! wall and `zeroize`-on-drop discipline. A panic in this crate can surface key bytes
//! in a backtrace, so panicking is forbidden outside of tests.
//!
//! All secret material produced by this crate is wrapped in [`zeroize::Zeroizing`] and
//! is wiped from memory when dropped. Sealing reuses [`octo_crypto`] unchanged; there is
//! deliberately no second encryption scheme. The sealing `context` AAD string is
//! chain-scoped (e.g. `"octo:eip155:1"`) so a sealed EVM key cannot be opened in a
//! Stellar context, and vice versa.
//!
//! ## Derivation path and the non-hardened warning
//!
//! Keys are derived at `m/44'/60'/0'/0/{index}` (BIP-44, coin type 60 for Ethereum).
//! Unlike Stellar's all-hardened SEP-0005 path (`m/44'/148'/index'`), the **last two
//! levels of the EVM path are non-hardened**.
//!
//! This is what allows xpub-based address derivation (a watch-only xpub can enumerate
//! every receive address without holding the seed). It is also the reason for the
//! following consequence, which must be understood by anything built on top of this
//! crate:
//!
//! > **A leaked child private key plus the parent xpub compromises every sibling key.**
//! >
//! > Because the change and index levels are non-hardened, the parent chain code and
//! > public key are sufficient to walk *down* the tree. Given one non-hardened child
//! > private key and the parent extended public key, an attacker can recover the parent
//! > private key, and from there every sibling and every descendant key.
//!
//! Do not export xpubs alongside any child private key. Do not treat the non-hardened
//! levels as equivalent to the hardened account level. Downstream issues (#220, #224)
//! depend on this property being respected.
//!
//! ## Test vectors
//!
//! Per `CONTRIBUTING.md`, crypto and derivation code must include test vectors. This
//! crate is verified against BIP-32 Test Vectors 1 and 2, the full EIP-55 example set,
//! and a known mnemonic-to-address set cross-checked against an independent
//! implementation. Sources are cited in the relevant test modules.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
    )
)]

pub mod address;
pub mod adapter;
pub mod derive;
pub mod error;
pub mod signer;

pub use address::{encode_address, validate_address, Address};
pub use adapter::EvmAdapter;
pub use derive::{derive_key, derive_key_at_path, EvmDerivationPath, EvmSecretKey};
pub use error::EvmError;
pub use signer::{recover_address, sign_digest, EvmSignature, Signer};