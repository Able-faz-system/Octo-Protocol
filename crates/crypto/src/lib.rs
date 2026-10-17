//! AES-256-GCM seal/open of the HD seed at rest.
//!
//! This crate is the at-rest encryption boundary for octo's secret material (the HD seed).
//! It knows nothing about Stellar — it just authenticated-encrypts bytes under a 256-bit master
//! key, with two hardening properties beyond plain AES-GCM:
//!
//! 1. **Per-record subkey derivation (HKDF-SHA256).** Each sealed record gets a fresh random
//!    `salt`; the actual AES key is `HKDF(master_key, salt, info=context)`. This means the master
//!    key is never used directly as the cipher key, every record uses a distinct key, and the
//!    `context` (e.g. `"octo:mainnet"`) is bound into key derivation.
//! 2. **AAD context binding.** The same `context` is also passed as AES-GCM associated data, so a
//!    ciphertext sealed for one context cannot be opened under another even if salts collided.
//! 3. **Scheme version tag.** Each [`SealedSeed`] carries an explicit `scheme` byte so that
//!    future cipher or KDF upgrades can be identified without a flag-day migration. The current
//!    scheme is [`SCHEME_V1`] (`1`). Rows in the database default to `1` via the migration
//!    (`0008_scheme_version.sql`). The legacy `scheme = 0` tag maps to the same algorithm as `1`
//!    and exists only as an internal baseline for migration tooling — it is never produced by
//!    `seal` and [`open`] rejects it with [`CryptoError::UnknownScheme`].
//!
//! Plaintext and derived keys are wrapped in [`Zeroizing`] and wiped on drop. Errors are coarse
//! and leak no cryptographic detail (see [`CryptoError`]).
#![forbid(unsafe_code)]
// Secret-handling crate: a panic could surface key material in a backtrace, and lossy/sign
// conversions on amounts are bugs. Deny them (tests may unwrap freely).
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
// Tests may panic and build fixtures with lossy casts; the production bans above still apply to
// all non-test code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation
    )
)]

mod error;

pub use error::CryptoError;

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Length of the AES-256 master key, in bytes.
pub const MASTER_KEY_LEN: usize = 32;
/// Length of the AES-GCM nonce, in bytes (96 bits, the recommended size).
pub const NONCE_LEN: usize = 12;
/// Length of the per-record HKDF salt, in bytes.
pub const SALT_LEN: usize = 32;

/// The current sealing scheme: AES-256-GCM with per-record HKDF-SHA256 subkey derivation and
/// context-bound AAD. All new seals are produced with this scheme tag.
pub const SCHEME_V1: u8 = 1;
/// AES-256-GCM with the network context and owning account id bound into the AAD.
pub const SCHEME_V2: u8 = 2;

/// A sealed secret: the AES-256-GCM ciphertext (including the authentication tag) plus the
/// public, non-secret `nonce` and `salt` needed to open it, and an explicit `scheme` version tag
/// that identifies the cipher and KDF used to produce the ciphertext.
///
/// None of these fields are secret, so deriving `Debug` is safe — but note that `open` *also*
/// requires the original `context` and master key, neither of which is stored here.
///
/// ## Scheme values
/// | `scheme` | Algorithm |
/// |---|---|
/// | `1` (current) | AES-256-GCM, HKDF-SHA256 per-record subkey, context-bound AAD |
///
/// Scheme `0` is a sentinel for "not yet set" in older DB rows; it is never produced by [`seal`]
/// and is rejected by [`open`] with [`CryptoError::UnknownScheme`]. Rows that carry `scheme = 0`
/// must be migrated with [`reseal`] before they can be opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSeed {
    /// AES-256-GCM ciphertext with the 16-byte GCM tag appended.
    pub ciphertext: Vec<u8>,
    /// Random 96-bit nonce used for this record.
    pub nonce: [u8; NONCE_LEN],
    /// Random salt used to derive this record's subkey via HKDF.
    pub salt: [u8; SALT_LEN],
    /// Scheme version tag. Currently always [`SCHEME_V1`] for records produced by [`seal`].
    pub scheme: u8,
}

impl SealedSeed {
    /// Reconstruct a [`SealedSeed`] from stored byte slices (e.g. read back from the database).
    ///
    /// Fails with [`CryptoError::InvalidNonceLength`] if the nonce or salt have the wrong length.
    pub fn from_parts(
        ciphertext: Vec<u8>,
        nonce: &[u8],
        salt: &[u8],
    ) -> Result<SealedSeed, CryptoError> {
        Self::from_parts_with_scheme(ciphertext, nonce, salt, SCHEME_V1)
    }

    /// Like [`from_parts`] but also accepts the explicit scheme tag stored in the database.
    pub fn from_parts_with_scheme(
        ciphertext: Vec<u8>,
        nonce: &[u8],
        salt: &[u8],
        scheme: u8,
    ) -> Result<SealedSeed, CryptoError> {
        match scheme {
            SCHEME_V1 | SCHEME_V2 => {}
            _ => return Err(CryptoError::UnknownScheme(scheme)),
        }
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength)?;
        let salt: [u8; SALT_LEN] = salt
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength)?;
        Ok(SealedSeed {
            ciphertext,
            nonce,
            salt,
            scheme,
        })
    }
}

/// Derive a fresh per-record AES-256 key from the master key, salt, and context using HKDF-SHA256.
///
/// The returned key is zeroized on drop. Expansion to 32 bytes is always within HKDF-SHA256's
/// output limit, so the only error path is structural and surfaces as [`CryptoError`] rather than
/// a panic.
fn derive_subkey(
    master_key: &[u8; MASTER_KEY_LEN],
    salt: &[u8; SALT_LEN],
    context: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(context, okm.as_mut())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(okm)
}

/// Authenticated-encrypt `plaintext` under `master_key`, binding `context` into both the key
/// derivation and the AEAD associated data.
///
/// `context` is a non-secret domain separator that must be supplied identically to [`open`]
/// (e.g. `b"octo:mainnet"`). A fresh random nonce and salt are generated per call, so sealing the
/// same plaintext twice yields different output. The returned [`SealedSeed`] always has
/// `scheme = `[`SCHEME_V1`].
/// Nonce and salt bytes come from `OsRng`, the operating system's cryptographically secure RNG.
pub fn seal(
    master_key: &[u8; MASTER_KEY_LEN],
    plaintext: &[u8],
    context: &[u8],
) -> Result<SealedSeed, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let subkey = derive_subkey(master_key, &salt, context)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(subkey.as_ref()));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: context,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(SealedSeed {
        ciphertext,
        nonce: nonce_bytes,
        salt,
        scheme: SCHEME_V1,
    })
}

/// Seal a secret while binding its owning Stellar account id into the authenticated context.
pub fn seal_with_account_id(
    master_key: &[u8; MASTER_KEY_LEN],
    plaintext: &[u8],
    context: &[u8],
    account_id: &str,
) -> Result<SealedSeed, CryptoError> {
    if account_id.is_empty() {
        return Err(CryptoError::AccountIdentityRequired);
    }
    let mut bound_context = context.to_vec();
    bound_context.push(0);
    bound_context.extend_from_slice(account_id.as_bytes());
    let mut sealed = seal(master_key, plaintext, &bound_context)?;
    sealed.scheme = SCHEME_V2;
    Ok(sealed)
}

/// Authenticated-decrypt a [`SealedSeed`] produced by [`seal`].
///
/// Returns the plaintext wrapped in [`Zeroizing`] so it is wiped when dropped. Fails with
/// [`CryptoError::DecryptionFailed`] for *any* authentication failure (wrong key, tampered
/// ciphertext/nonce/tag, or a `context` that differs from the one used to seal), and with
/// [`CryptoError::UnknownScheme`] when the `scheme` tag is not a value this code knows how to
/// handle — the variant is deliberately indistinguishable across those cases for security.
pub fn open(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Validate the scheme tag before attempting any cryptographic operation.
    match sealed.scheme {
        SCHEME_V1 => {} // the only supported scheme
        SCHEME_V2 => return Err(CryptoError::AccountIdentityRequired),
        _ => return Err(CryptoError::UnknownScheme(sealed.scheme)),
    }

    if sealed.nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength);
    }

    let subkey = derive_subkey(master_key, &sealed.salt, context)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(subkey.as_ref()));
    let nonce = Nonce::from_slice(&sealed.nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed.ciphertext,
                aad: context,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}

/// Open a V2 secret using the expected owning Stellar account id.
pub fn open_with_account_id(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    context: &[u8],
    account_id: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.scheme != SCHEME_V2 {
        return open(master_key, sealed, context);
    }
    if account_id.is_empty() {
        return Err(CryptoError::AccountIdentityRequired);
    }
    let mut bound_context = context.to_vec();
    bound_context.push(0);
    bound_context.extend_from_slice(account_id.as_bytes());
    let mut v1 = sealed.clone();
    v1.scheme = SCHEME_V1;
    open(master_key, &v1, &bound_context)
}

/// Rotate the master key protecting an already-sealed secret.
///
/// Opens `sealed` under `old_key`/`context`, then seals the recovered plaintext under `new_key`
/// and the same `context`. The intermediate plaintext is wrapped in [`Zeroizing`] (as returned by
/// [`open`]) and wiped on drop. The returned [`SealedSeed`] gets a fresh random nonce and salt, as
/// [`seal`] always generates — it never reuses the original record's.
///
/// `reseal` is the one place a legacy `scheme = 0` record is accepted: `0` names the same
/// algorithm as [`SCHEME_V1`], so it is opened as V1 and re-sealed with an explicit V1 tag.
pub fn reseal(
    old_key: &[u8; MASTER_KEY_LEN],
    new_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    context: &[u8],
) -> Result<SealedSeed, CryptoError> {
    let plaintext = if sealed.scheme == 0 {
        let as_v1 = SealedSeed {
            scheme: SCHEME_V1,
            ..sealed.clone()
        };
        open(old_key, &as_v1, context)?
    } else {
        open(old_key, sealed, context)?
    };
    seal(new_key, plaintext.as_ref(), context)
}

/// Rotate a sealed secret into the account-bound V2 scheme.
pub fn reseal_with_account_id(
    old_key: &[u8; MASTER_KEY_LEN],
    new_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    context: &[u8],
    account_id: &str,
) -> Result<SealedSeed, CryptoError> {
    let plaintext = open_with_account_id(old_key, sealed, context, account_id)?;
    seal_with_account_id(new_key, plaintext.as_ref(), context, account_id)
}

/// Domain separator for the self-test canary, so it can never be confused with a real record.
const SELF_TEST_CONTEXT: &[u8] = b"octo:self-test";
/// Length of the random canary sealed by [`self_test`].
const CANARY_LEN: usize = 32;

/// Boot-time check that the OS entropy source and the seal/open round-trip work under
/// `master_key`, so a broken RNG or degenerate key fails at startup rather than at first use.
///
/// Rejects an all-zero key, draws two random canaries (a stuck RNG would repeat), seals one,
/// opens it, and confirms a foreign context is rejected. Canaries are zeroized on drop.
pub fn self_test(master_key: &[u8; MASTER_KEY_LEN]) -> Result<(), CryptoError> {
    if master_key.iter().all(|b| *b == 0) {
        return Err(CryptoError::SelfTestFailed("master key is all zero bytes"));
    }

    let mut canary = Zeroizing::new([0u8; CANARY_LEN]);
    let mut probe = Zeroizing::new([0u8; CANARY_LEN]);
    OsRng
        .try_fill_bytes(canary.as_mut())
        .and_then(|()| OsRng.try_fill_bytes(probe.as_mut()))
        .map_err(|_| CryptoError::SelfTestFailed("entropy source unavailable"))?;
    // Two independent 256-bit draws are equal or all-zero only if the RNG is broken.
    if *canary == *probe || canary.iter().all(|b| *b == 0) {
        return Err(CryptoError::SelfTestFailed("entropy source returned degenerate output"));
    }

    let sealed = seal(master_key, canary.as_ref(), SELF_TEST_CONTEXT)
        .map_err(|_| CryptoError::SelfTestFailed("seal failed"))?;
    if sealed.ciphertext.get(..CANARY_LEN) == Some(canary.as_slice()) {
        return Err(CryptoError::SelfTestFailed("ciphertext equals plaintext"));
    }

    let opened = open(master_key, &sealed, SELF_TEST_CONTEXT)
        .map_err(|_| CryptoError::SelfTestFailed("open failed"))?;
    if opened.as_slice() != canary.as_slice() {
        return Err(CryptoError::SelfTestFailed("round-trip mismatch"));
    }

    // AEAD must authenticate the context; a foreign one opening would mean AAD is ignored.
    if open(master_key, &sealed, b"octo:self-test:foreign").is_ok() {
        return Err(CryptoError::SelfTestFailed("foreign context was accepted"));
    }
    Ok(())
}

/// Convenience: parse a 32-byte master key from a byte slice (e.g. decoded from a KMS/env value).
pub fn master_key_from_slice(bytes: &[u8]) -> Result<[u8; MASTER_KEY_LEN], CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::InvalidMasterKeyLength {
        expected: MASTER_KEY_LEN,
        actual: bytes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"octo:testnet";

    fn key() -> [u8; MASTER_KEY_LEN] {
        let mut k = [0u8; MASTER_KEY_LEN];
        OsRng.fill_bytes(&mut k);
        k
    }

    #[test]
    fn seal_open_roundtrip() {
        let mk = key();
        let secret = b"a 24-word BIP39 mnemonic seed lives here";
        let sealed = seal(&mk, secret, CTX).unwrap();
        let opened = open(&mk, &sealed, CTX).unwrap();
        assert_eq!(opened.as_slice(), secret);
    }

    #[test]
    fn seal_always_produces_scheme_v1() {
        let mk = key();
        let sealed = seal(&mk, b"seed", CTX).unwrap();
        assert_eq!(
            sealed.scheme, SCHEME_V1,
            "seal must always produce scheme v1"
        );
    }

    #[test]
    fn account_bound_v2_rejects_the_wrong_account_id() {
        let mk = key();
        let sealed = seal_with_account_id(&mk, b"seed", CTX, "GGOOD").unwrap();
        assert!(matches!(
            open_with_account_id(&mk, &sealed, CTX, "GBAD"),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn v1_rows_still_open_with_the_original_context() {
        let mk = key();
        let sealed = seal(&mk, b"seed", CTX).unwrap();
        assert_eq!(open(&mk, &sealed, CTX).unwrap().as_slice(), b"seed");
    }

    #[test]
    fn reseal_migrates_v1_to_account_bound_v2() {
        let old_mk = key();
        let new_mk = key();
        let sealed = seal(&old_mk, b"seed", CTX).unwrap();
        let migrated = reseal_with_account_id(
            &old_mk,
            &new_mk,
            &sealed,
            CTX,
            "GACCOUNT",
        )
        .unwrap();
        assert_eq!(migrated.scheme, SCHEME_V2);
        assert_eq!(
            open_with_account_id(&new_mk, &migrated, CTX, "GACCOUNT")
                .unwrap()
                .as_slice(),
            b"seed"
        );
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let mk = key();
        let secret = b"super secret seed";
        let sealed = seal(&mk, secret, CTX).unwrap();
        assert_ne!(sealed.ciphertext.as_slice(), secret.as_slice());
        // ciphertext carries the 16-byte GCM tag, so it is longer than the plaintext.
        assert_eq!(sealed.ciphertext.len(), secret.len() + 16);
    }

    #[test]
    fn two_seals_differ_nonce_and_ciphertext() {
        let mk = key();
        let secret = b"identical plaintext";
        let a = seal(&mk, secret, CTX).unwrap();
        let b = seal(&mk, secret, CTX).unwrap();
        // Fresh random nonce + salt per call => no reuse, different ciphertext.
        assert_ne!(a.nonce, b.nonce, "nonce must be unique per seal");
        assert_ne!(a.salt, b.salt, "salt must be unique per seal");
        assert_ne!(a.ciphertext, b.ciphertext, "ciphertext must differ");
        // Both still open to the same plaintext.
        assert_eq!(open(&mk, &a, CTX).unwrap().as_slice(), secret);
        assert_eq!(open(&mk, &b, CTX).unwrap().as_slice(), secret);
    }

    #[test]
    fn nonce_is_never_reused_across_many_seals_of_identical_plaintext() {
        let mk = key();
        let secret = b"identical plaintext";
        let mut nonces = std::collections::HashSet::with_capacity(10_000);

        for _ in 0..10_000 {
            let sealed = seal(&mk, secret, CTX).unwrap();
            assert!(nonces.insert(sealed.nonce), "nonce reused across seal calls");
        }
    }
        }
    }

    #[test]
    fn nonce_is_never_reused_across_many_seals_of_identical_plaintext() {
        let mk = key();
        let secret = b"identical plaintext";
        let mut nonces = std::collections::HashSet::with_capacity(10_000);

        for _ in 0..10_000 {
            let sealed = seal(&mk, secret, CTX).unwrap();
            assert!(nonces.insert(sealed.nonce), "nonce reused across seal calls");
        }
    }

    #[test]
    fn nonces_show_no_correlation_with_varying_plaintext_and_key_across_a_large_sample() {
        const SAMPLE_SIZE: usize = 10_000;
        let mut nonces = std::collections::HashSet::with_capacity(SAMPLE_SIZE);
        let mut sum_n: f64 = 0.0;
        let mut sum_k: f64 = 0.0;
        let mut sum_p: f64 = 0.0;
        let mut sum_nk: f64 = 0.0;
        let mut sum_np: f64 = 0.0;
        let mut sum_n_sq: f64 = 0.0;
        let mut sum_k_sq: f64 = 0.0;
        let mut sum_p_sq: f64 = 0.0;

        for _ in 0..SAMPLE_SIZE {
            let mut mk = [0u8; MASTER_KEY_LEN];
            let mut pt = [0u8; 32];
            OsRng.fill_bytes(&mut mk);
            OsRng.fill_bytes(&mut pt);

            let sealed = seal(&mk, &pt, CTX).unwrap();
            assert!(nonces.insert(sealed.nonce), "nonce collision detected in varied sample");

            let n_val = sealed.nonce[0] as f64;
            let k_val = mk[0] as f64;
            let p_val = pt[0] as f64;

            sum_n += n_val;
            sum_k += k_val;
            sum_p += p_val;
            sum_nk += n_val * k_val;
            sum_np += n_val * p_val;
            sum_n_sq += n_val * n_val;
            sum_k_sq += k_val * k_val;
            sum_p_sq += p_val * p_val;
        }

        let n = SAMPLE_SIZE as f64;
        let r_key = (n * sum_nk - sum_n * sum_k)
            / (((n * sum_n_sq - sum_n * sum_n) * (n * sum_k_sq - sum_k * sum_k)).sqrt());
        let r_pt = (n * sum_np - sum_n * sum_p)
            / (((n * sum_n_sq - sum_n * sum_n) * (n * sum_p_sq - sum_p * sum_p)).sqrt());

        // Pearson correlation between nonce and input bytes must be negligible (< 0.05).
        assert!(r_key.abs() < 0.05, "correlation detected between nonce and key: {r_key}");
        assert!(r_pt.abs() < 0.05, "correlation detected between nonce and plaintext: {r_pt}");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mk = key();
        let mut sealed = seal(&mk, b"seed", CTX).unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(matches!(
            open(&mk, &sealed, CTX),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampered_tag_fails() {
        let mk = key();
        let mut sealed = seal(&mk, b"seed", CTX).unwrap();
        // The last byte is part of the GCM tag.
        let last = sealed.ciphertext.len() - 1;
        sealed.ciphertext[last] ^= 0x01;
        assert!(matches!(
            open(&mk, &sealed, CTX),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampered_nonce_fails() {
        let mk = key();
        let mut sealed = seal(&mk, b"seed", CTX).unwrap();
        sealed.nonce[0] ^= 0xff;
        assert!(matches!(
            open(&mk, &sealed, CTX),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_master_key_fails() {
        let mk = key();
        let other = key();
        let sealed = seal(&mk, b"seed", CTX).unwrap();
        assert!(matches!(
            open(&other, &sealed, CTX),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_context_fails() {
        // A record sealed for mainnet must not open under testnet, even with the right key.
        let mk = key();
        let sealed = seal(&mk, b"seed", b"octo:mainnet").unwrap();
        assert!(matches!(
            open(&mk, &sealed, b"octo:testnet"),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let mk = key();
        let sealed = seal(&mk, b"", CTX).unwrap();
        assert_eq!(open(&mk, &sealed, CTX).unwrap().as_slice(), b"");
    }

    #[test]
    fn reseal_produces_a_record_openable_only_under_the_new_key() {
        let old_mk = key();
        let new_mk = key();
        let secret = b"a 24-word BIP39 mnemonic seed lives here";
        let sealed = seal(&old_mk, secret, CTX).unwrap();

        let resealed = reseal(&old_mk, &new_mk, &sealed, CTX).unwrap();

        assert_eq!(open(&new_mk, &resealed, CTX).unwrap().as_slice(), secret);
        assert!(matches!(
            open(&old_mk, &resealed, CTX),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn reseal_result_has_fresh_nonce_and_salt_distinct_from_the_original() {
        let old_mk = key();
        let new_mk = key();
        let sealed = seal(&old_mk, b"seed", CTX).unwrap();

        let resealed = reseal(&old_mk, &new_mk, &sealed, CTX).unwrap();

        assert_ne!(resealed.nonce, sealed.nonce);
        assert_ne!(resealed.salt, sealed.salt);
    }

    #[test]
    fn reseal_upgrades_a_legacy_scheme_0_record_to_v1() {
        let (old_mk, new_mk) = (key(), key());
        let mut legacy = seal(&old_mk, b"legacy seed", CTX).unwrap();
        legacy.scheme = 0;
        assert!(open(&old_mk, &legacy, CTX).is_err());
        let resealed = reseal(&old_mk, &new_mk, &legacy, CTX).unwrap();
        assert_eq!(resealed.scheme, SCHEME_V1);
        assert_eq!(
            open(&new_mk, &resealed, CTX).unwrap().as_slice(),
            b"legacy seed"
        );
    }

    #[test]
    fn reseal_fails_cleanly_if_old_key_or_context_is_wrong() {
        let old_mk = key();
        let new_mk = key();
        let wrong_mk = key();
        let sealed = seal(&old_mk, b"seed", CTX).unwrap();

        assert!(matches!(
            reseal(&wrong_mk, &new_mk, &sealed, CTX),
            Err(CryptoError::DecryptionFailed)
        ));
        assert!(matches!(
            reseal(&old_mk, &new_mk, &sealed, b"octo:mainnet"),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn master_key_from_slice_validates_length() {
        assert!(master_key_from_slice(&[0u8; 32]).is_ok());
        assert!(matches!(
            master_key_from_slice(&[0u8; 31]),
            Err(CryptoError::InvalidMasterKeyLength { .. })
        ));
        assert!(matches!(
            master_key_from_slice(&[0u8; 33]),
            Err(CryptoError::InvalidMasterKeyLength { .. })
        ));
    }

    #[test]
    fn from_parts_with_scheme_rejects_unknown_scheme() {
        let error = SealedSeed::from_parts_with_scheme(
            vec![0u8; 16],
            &[0u8; NONCE_LEN],
            &[0u8; SALT_LEN],
            255,
        )
        .unwrap_err();
        assert!(matches!(error, CryptoError::UnknownScheme(255)));
    }

    // ---------------------------------------------------------------------------
    // Size-boundary tests
    //
    // HKDF-SHA256 can expand up to 255 * 32 = 8 160 bytes of output.  This crate
    // always requests exactly 32 bytes, so the expansion limit is never approached
    // regardless of plaintext size.  The GCM ciphertext-length invariant is:
    //
    //     ciphertext.len() == plaintext.len() + 16   (16-byte authentication tag)
    //
    // The tests below assert that invariant and verify seal/open round-trips for
    // each size class: 0, 1, 64 (HD seed), 1 024, and 1 048 576 bytes (1 MiB).
    // ---------------------------------------------------------------------------

    /// Table-driven seal→open roundtrip across the full range of supported sizes.
    #[test]
    fn seal_open_roundtrips_across_size_range() {
        let mk = key();
        for &size in &[0usize, 1, 64, 1_024, 1_048_576] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
            let sealed = seal(&mk, &plaintext, CTX)
                .unwrap_or_else(|e| panic!("seal failed for size {size}: {e:?}"));
            let opened = open(&mk, &sealed, CTX)
                .unwrap_or_else(|e| panic!("open failed for size {size}: {e:?}"));
            assert_eq!(
                opened.as_slice(),
                plaintext.as_slice(),
                "roundtrip mismatch for size {size}"
            );
        }
    }

    /// Splicing fields from two independently-sealed records always fails authentication.
    ///
    /// We seal two different plaintexts under the same master key but with *different* contexts,
    /// producing records A and B. Every cross-combination of
    ///
    ///   {A.ciphertext, B.ciphertext} × {A.nonce, B.nonce} × {A.salt, B.salt}
    ///
    /// is then tried under both contexts. The only combinations that could possibly succeed are
    /// the two identity combinations (A opened under ctx_a, B opened under ctx_b); those are
    /// excluded from the loop. All remaining 2×2×2×2 − 2 = 14 combinations must return
    /// `Err(CryptoError::DecryptionFailed)`.
    #[test]
    fn spliced_sealed_seed_fields_never_decrypt() {
        let mk = key();
        let ctx_a: &[u8] = b"octo:mainnet";
        let ctx_b: &[u8] = b"octo:testnet";

        let a = seal(&mk, b"plaintext-alpha", ctx_a).unwrap();
        let b = seal(&mk, b"plaintext-beta", ctx_b).unwrap();

        let ciphertexts = [(&a.ciphertext, "A.ct"), (&b.ciphertext, "B.ct")];
        let nonces = [(&a.nonce[..], "A.nonce"), (&b.nonce[..], "B.nonce")];
        let salts = [(&a.salt[..], "A.salt"), (&b.salt[..], "B.salt")];
        let contexts = [(ctx_a, "ctx_a"), (ctx_b, "ctx_b")];

        for (ct, ct_label) in &ciphertexts {
            for (nonce, nonce_label) in &nonces {
                for (salt, salt_label) in &salts {
                    for (ctx, ctx_label) in &contexts {
                        // Skip the two identity combinations that are supposed to succeed.
                        let is_identity_a = std::ptr::eq(*ct, &a.ciphertext)
                            && std::ptr::eq(*nonce, &a.nonce[..])
                            && std::ptr::eq(*salt, &a.salt[..])
                            && std::ptr::eq(*ctx, ctx_a);
                        let is_identity_b = std::ptr::eq(*ct, &b.ciphertext)
                            && std::ptr::eq(*nonce, &b.nonce[..])
                            && std::ptr::eq(*salt, &b.salt[..])
                            && std::ptr::eq(*ctx, ctx_b);
                        if is_identity_a || is_identity_b {
                            continue;
                        }

                        let spliced = SealedSeed::from_parts((*ct).clone(), nonce, salt).unwrap();
                        let result = open(&mk, &spliced, ctx);
                        assert!(
                            matches!(result, Err(CryptoError::DecryptionFailed)),
                            "expected DecryptionFailed for splice \
                             ({ct_label}, {nonce_label}, {salt_label}, {ctx_label}), \
                             got {result:?}"
                        );
                    }
                }
            }
        }
    }

    /// The GCM ciphertext is always exactly plaintext.len() + 16 (the authentication tag).
    #[test]
    fn ciphertext_length_is_plaintext_plus_tag_across_size_range() {
        const GCM_TAG_LEN: usize = 16;
        let mk = key();
        for &size in &[0usize, 1, 64, 1_024, 1_048_576] {
            let plaintext: Vec<u8> = vec![0xab; size];
            let sealed = seal(&mk, &plaintext, CTX)
                .unwrap_or_else(|e| panic!("seal failed for size {size}: {e:?}"));
            assert_eq!(
                sealed.ciphertext.len(),
                size + GCM_TAG_LEN,
                "ciphertext length wrong for plaintext size {size}: \
                 expected {}, got {}",
                size + GCM_TAG_LEN,
                sealed.ciphertext.len()
            );
        }
    }
}
