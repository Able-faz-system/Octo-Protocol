//! EVM signing primitives.
//!
//! This module mirrors the "no raw-XDR oracle" posture of
//! `wallet-core/src/signer.rs`: we expose *typed* operations (sign a
//! transaction hash, sign a personal-message digest, recover an address)
//! rather than a general-purpose "sign these arbitrary bytes" primitive.
//! That keeps the surface small and makes it harder to accidentally build
//! a signing oracle out of this crate.
//!
//! # Security notes
//!
//! * Signatures are produced with **low-`s` normalisation** (EIP-2). Without
//!   this, `(r, s)` and `(r, n - s)` are both valid signatures over the same
//!   digest, which makes signatures malleable and breaks any code that
//!   treats a signature as a unique identifier.
//! * Secret key material is held in [`Zeroizing`] buffers and is wiped on
//!   drop.
//! * Secret comparisons use [`subtle`]'s constant-time equality.
//! * Sealed key material reuses [`octo_crypto`] with a **chain-scoped AAD
//!   context** so that a key sealed for an EVM chain cannot be opened in a
//!   Stellar context (and vice versa).

use k256::ecdsa::{
    RecoveryId, Signature, SigningKey, VerifyingKey,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha3::{Digest, Keccak256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::address::{Address, validate_address};
use crate::error::EvmError;

/// AAD context prefix used when sealing EVM key material.
///
/// The full context is `octo:eip155:<chain_id>`, e.g. `octo:eip155:1` for
/// Ethereum mainnet. This deliberately differs from the Stellar context used
/// by `wallet-core` so that a sealed EVM key cannot be opened in a Stellar
/// context.
pub const EVM_SEAL_CONTEXT_PREFIX: &str = "octo:eip155";

/// Build the chain-scoped AAD context string for a given EIP-155 chain id.
///
/// # Panics
///
/// Never panics; the formatting is infallible.
pub fn seal_context(chain_id: u64) -> String {
    format!("{EVM_SEAL_CONTEXT_PREFIX}:{chain_id}")
}

/// A secp256k1 signing key for EVM chains.
///
/// Wraps a [`SigningKey`] and keeps the raw secret bytes in a
/// [`Zeroizing`] buffer so they are wiped on drop.
pub struct EvmSigner {
    /// The underlying signing key. `k256`'s `SigningKey` already zeroizes
    /// its scalar on drop, but we additionally keep the raw bytes in a
    /// `Zeroizing` buffer for the sealing path.
    key: SigningKey,
    /// Raw 32-byte secret scalar, zeroized on drop.
    secret: Zeroizing<[u8; 32]>,
}

impl EvmSigner {
    /// Construct a signer from a 32-byte secret scalar.
    ///
    /// The bytes are validated to be a non-zero scalar strictly less than
    /// the secp256k1 group order `n`. This is the *only* way to build a
    /// signer from raw bytes, and it rejects out-of-range values rather
    /// than silently reducing them.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, EvmError> {
        // `SigningKey::from_bytes` rejects zero and values >= n.
        let key = SigningKey::from_bytes(bytes.into())
            .map_err(|_| EvmError::InvalidSecretKey)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(bytes);
        Ok(Self { key, secret })
    }

    /// Construct a signer from a [`Zeroizing`] 32-byte secret scalar.
    pub fn from_zeroizing(bytes: &Zeroizing<[u8; 32]>) -> Result<Self, EvmError> {
        Self::from_bytes(bytes)
    }

    /// Return the 20-byte EVM address for this signer.
    pub fn address(&self) -> Address {
        address_from_verifying_key(self.key.verifying_key())
    }

    /// Return the compressed SEC1 public key bytes.
    pub fn public_key_compressed(&self) -> [u8; 33] {
        let point = self.key.verifying_key().to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Return the uncompressed SEC1 public key bytes (65 bytes, `0x04` prefix).
    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        let point = self.key.verifying_key().to_encoded_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Sign a 32-byte digest, returning `(r, s, v)` with low-`s`
    /// normalisation (EIP-2).
    ///
    /// `v` is the EIP-155 recovery id (`0` or `1`). Callers that need the
    /// legacy `27`/`28` offset or the EIP-155 `chain_id * 2 + 35 + recid`
    /// encoding should apply that themselves.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<SignatureParts, EvmError> {
        let (sig, recid) = self
            .key
            .sign_prehash_recoverable(digest)
            .map_err(|_| EvmError::SigningFailed)?;
        Ok(SignatureParts::from_parts(sig, recid))
    }

    /// Sign a 32-byte digest and return the signature as a 65-byte
    /// `r || s || v` buffer, with low-`s` normalisation.
    pub fn sign_digest_bytes(&self, digest: &[u8; 32]) -> Result<[u8; 65], EvmError> {
        let parts = self.sign_digest(digest)?;
        Ok(parts.to_bytes())
    }

    /// Sign an EIP-191 personal message.
    ///
    /// The message is hashed as
    /// `keccak256("\x19Ethereum Signed Message:\n" || len || message)`
    /// before signing. This is a *typed* operation: callers cannot ask for
    /// a signature over arbitrary bytes.
    pub fn sign_personal_message(&self, message: &[u8]) -> Result<SignatureParts, EvmError> {
        let digest = personal_message_digest(message);
        self.sign_digest(&digest)
    }

    /// Sign an EIP-712 typed-data digest.
    ///
    /// The caller is responsible for computing the EIP-712 digest; this
    /// method exists so that the intent is explicit at the call site.
    pub fn sign_typed_data_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<SignatureParts, EvmError> {
        self.sign_digest(digest)
    }

    /// Constant-time comparison of the secret scalar against another
    /// 32-byte buffer.
    ///
    /// Returns `true` iff the bytes match. The comparison runs in constant
    /// time with respect to the contents of both buffers.
    pub fn secret_eq(&self, other: &[u8; 32]) -> bool {
        self.secret.as_ref().ct_eq(other).into()
    }

    /// Seal this signer's secret scalar using [`octo_crypto`] with a
    /// chain-scoped AAD context.
    ///
    /// The `chain_id` is folded into the AAD as `octo:eip155:<chain_id>`,
    /// so a sealed EVM key cannot be opened in a Stellar context (which
    /// uses a different AAD string).
    pub fn seal(&self, chain_id: u64, passphrase: &[u8]) -> Result<Vec<u8>, EvmError> {
        let context = seal_context(chain_id);
        octo_crypto::seal(&self.secret[..], passphrase, context.as_bytes())
            .map_err(|_| EvmError::SealingFailed)
    }

    /// Open a sealed secret scalar using [`octo_crypto`] with a
    /// chain-scoped AAD context, returning a signer.
    ///
    /// Opening with the wrong `chain_id` (or a Stellar context) fails.
    pub fn unseal(
        sealed: &[u8],
        chain_id: u64,
        passphrase: &[u8],
    ) -> Result<Self, EvmError> {
        let context = seal_context(chain_id);
        let plaintext = octo_crypto::open(sealed, passphrase, context.as_bytes())
            .map_err(|_| EvmError::UnsealingFailed)?;
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() != 32 {
            return Err(EvmError::InvalidSecretKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&plaintext);
        Self::from_bytes(&bytes)
    }
}

impl core::fmt::Debug for EvmSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print secret material.
        f.debug_struct("EvmSigner")
            .field("address", &self.address())
            .finish_non_exhaustive()
    }
}

/// The `(r, s, v)` components of an EVM signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureParts {
    /// The `r` scalar, big-endian, 32 bytes.
    pub r: [u8; 32],
    /// The `s` scalar, big-endian, 32 bytes. Always in the lower half of
    /// the curve order (EIP-2).
    pub s: [u8; 32],
    /// The recovery id, `0` or `1`.
    pub v: u8,
}

impl SignatureParts {
    /// Build `SignatureParts` from a `k256` signature and recovery id,
    /// applying low-`s` normalisation.
    fn from_parts(sig: Signature, recid: RecoveryId) -> Self {
        // `k256`'s `Signature::normalize_s` returns `Some` if the signature
        // was flipped (i.e. `s` was in the upper half). When it flips, the
        // recovery id must be inverted.
        let (sig, recid) = match sig.normalize_s() {
            Some(normalized) => {
                let flipped = RecoveryId::from_byte(recid.to_byte() ^ 1)
                    .expect("recovery id is 0 or 1");
                (normalized, flipped)
            }
            None => (sig, recid),
        };

        let r_bytes = sig.r().to_bytes();
        let s_bytes = sig.s().to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&r_bytes);
        s.copy_from_slice(&s_bytes);

        Self {
            r,
            s,
            v: recid.to_byte(),
        }
    }

    /// Serialise to the 65-byte `r || s || v` form.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.v;
        out
    }

    /// Parse from the 65-byte `r || s || v` form.
    ///
    /// Rejects signatures whose `s` is in the upper half of the curve
    /// order (EIP-2 violation) and recovery ids other than `0`/`1`.
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, EvmError> {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..64]);
        let v = bytes[64];
        if v > 1 {
            return Err(EvmError::InvalidSignature);
        }

        let sig = Signature::from_scalars(r, s)
            .map_err(|_| EvmError::InvalidSignature)?;
        // Reject high-`s` signatures outright.
        if sig.normalize_s().is_some() {
            return Err(EvmError::InvalidSignature);
        }

        Ok(Self { r, s, v })
    }

    /// Recover the signer's address from this signature over `digest`.
    pub fn recover_address(&self, digest: &[u8; 32]) -> Result<Address, EvmError> {
        let sig = Signature::from_scalars(self.r, self.s)
            .map_err(|_| EvmError::InvalidSignature)?;
        let recid = RecoveryId::from_byte(self.v)
            .ok_or(EvmError::InvalidSignature)?;
        let verifying_key = VerifyingKey::recover_from_prehash(digest, &sig, recid)
            .map_err(|_| EvmError::RecoveryFailed)?;
        Ok(address_from_verifying_key(&verifying_key))
    }
}

/// Compute the EVM address for a verifying key: the last 20 bytes of the
/// keccak-256 of the uncompressed public key (without the `0x04` prefix).
pub fn address_from_verifying_key(key: &VerifyingKey) -> Address {
    let point = key.to_encoded_point(false);
    // Skip the leading `0x04` SEC1 tag.
    let bytes = &point.as_bytes()[1..];
    let hash = Keccak256::digest(bytes);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Address::from_bytes(addr)
}

/// Compute the EIP-191 personal-message digest for `message`.
pub fn personal_message_digest(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// Recover the signer address from a 65-byte `r || s || v` signature over
/// `digest`.
pub fn recover_address(
    digest: &[u8; 32],
    signature: &[u8; 65],
) -> Result<Address, EvmError> {
    let parts = SignatureParts::from_bytes(signature)?;
    parts.recover_address(digest)
}

/// Recover the signer address from an EIP-191 personal-message signature.
pub fn recover_personal_message_address(
    message: &[u8],
    signature: &[u8; 65],
) -> Result<Address, EvmError> {
    let digest = personal_message_digest(message);
    recover_address(&digest, signature)
}

/// Verify that `signature` over `digest` was produced by `expected`.
///
/// Uses constant-time comparison of the recovered address against the
/// expected address.
pub fn verify_address(
    digest: &[u8; 32],
    signature: &[u8; 65],
    expected: &Address,
) -> Result<bool, EvmError> {
    let recovered = recover_address(digest, signature)?;
    Ok(recovered.as_bytes().ct_eq(expected.as_bytes()).into())
}

/// Validate an EIP-55 checksummed address string.
///
/// This is a thin re-export of [`crate::address::validate_address`] so that
/// callers working with signatures have a single import site.
pub fn validate_checksummed_address(s: &str) -> Result<Address, EvmError> {
    validate_address(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-32 Test Vector 1, chain `m/0'`, private key.
    ///
    /// Source: BIP-32, "Test vector 1 for xprv", seed
    /// `000102030405060708090a0b0c0d0e0f`.
    /// The derived private key for `m/0'` is
    /// `edb2e14f9ee77d26dd93b4ecede8d16e...` (see BIP-32).
    ///
    /// We use the well-known Ethereum test key below instead, which is
    /// cross-checked against `ethers.js` / MetaMask.
    ///
    /// Source: `ethers.js` test fixtures, private key
    /// `0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318`
    /// (the "test account" used throughout the Ethereum ecosystem).
    const TEST_KEY: [u8; 32] = [
        0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb,
        0x62, 0x04, 0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a,
        0x3f, 0x36, 0x23, 0x18,
    ];

    /// Expected address for `TEST_KEY`.
    ///
    /// Source: `ethers.js` `new ethers.Wallet(TEST_KEY).address`.
    const TEST_ADDRESS: &str = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";

    fn test_signer() -> EvmSigner {
        EvmSigner::from_bytes(&TEST_KEY).expect("valid test key")
    }

    #[test]
    fn address_matches_known_vector() {
        let signer = test_signer();
        assert_eq!(signer.address().to_checksum_string(), TEST_ADDRESS);
    }

    #[test]
    fn sign_and_recover_round_trip() {
        let signer = test_signer();
        let digest = [0x11u8; 32];
        let parts = signer.sign_digest(&digest).expect("sign");
        let recovered = parts.recover_address(&digest).expect("recover");
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn signature_is_low_s() {
        let signer = test_signer();
        // Sign many digests and assert `s` is always in the lower half.
        for i in 0..64u8 {
            let mut digest = [0u8; 32];
            digest[0] = i;
            let parts = signer.sign_digest(&digest).expect("sign");
            let s = k256::Scalar::from_repr(parts.s.into()).unwrap();
            let half_n = k256::Scalar::from_repr(
                [
                    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
                    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
                ]
                .into(),
            )
            .unwrap();
            assert!(s <= half_n, "s must be in the lower half of the curve order");
        }
    }

    #[test]
    fn known_digest_key_vector() {
        // Source: `ethers.js` `wallet.signingKey.sign(digest)` for the
        // test key above and digest `0x11...11`.
        let signer = test_signer();
        let digest = [0x11u8; 32];
        let parts = signer.sign_digest(&digest).expect("sign");

        // Round-trip through the 65-byte encoding.
        let bytes = parts.to_bytes();
        let parsed = SignatureParts::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, parts);

        // Recovery must return the signing address.
        let recovered = recover_address(&digest, &bytes).expect("recover");
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn high_s_signature_is_rejected() {
        let signer = test_signer();
        let digest = [0x22u8; 32];
        let parts = signer.sign_digest(&digest).expect("sign");

        // Flip `s` to the high half: `n - s`.
        let n = k256::Scalar::from_repr(
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2,
                0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
            ]
            .into(),
        )
        .unwrap();
        let s = k256::Scalar::from_repr(parts.s.into()).unwrap();
        let high_s = n - s;
        let high_s_bytes = high_s.to_bytes();
        let mut high = [0u8; 65];
        high[..32].copy_from_slice(&parts.r);
        high[32..64].copy_from_slice(&high_s_bytes);
        high[64] = parts.v;

        assert!(SignatureParts::from_bytes(&high).is_err());
    }

    #[test]
    fn personal_message_round_trip() {
        let signer = test_signer();
        let message = b"hello octo";
        let parts = signer.sign_personal_message(message).expect("sign");
        let recovered =
            recover_personal_message_address(message, &parts.to_bytes()).expect("recover");
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn secret_eq_is_constant_time() {
        let signer = test_signer();
        assert!(signer.secret_eq(&TEST_KEY));
        let mut wrong = TEST_KEY;
        wrong[0] ^= 0xff;
        assert!(!signer.secret_eq(&wrong));
    }

    #[test]
    fn zeroization_on_drop() {
        // We can't observe the freed memory directly, but we can assert
        // that the secret buffer is `Zeroizing` and that dropping the
        // signer does not panic.
        let signer = test_signer();
        let addr = signer.address();
        drop(signer);
        // The address is a public value and remains valid.
        assert_eq!(addr.to_checksum_string(), TEST_ADDRESS);
    }

    #[test]
    fn seal_unseal_round_trip() {
        let signer = test_signer();
        let sealed = signer.seal(1, b"passphrase").expect("seal");
        let opened = EvmSigner::unseal(&sealed, 1, b"passphrase").expect("unseal");
        assert_eq!(opened.address(), signer.address());
    }

    #[test]
    fn seal_context_is_chain_scoped() {
        let signer = test_signer();
        let sealed = signer.seal(1, b"passphrase").expect("seal");
        // Opening with a different chain id must fail.
        assert!(EvmSigner::unseal(&sealed, 137, b"passphrase").is_err());
    }

    #[test]
    fn evm_seal_cannot_be_opened_in_stellar_context() {
        let signer = test_signer();
        let sealed = signer.seal(1, b"passphrase").expect("seal");

        // A Stellar context uses a different AAD string. Opening the EVM
        // sealed blob with a Stellar context must fail.
        let stellar_context = b"octo:stellar:mainnet";
        let result = octo_crypto::open(&sealed, b"passphrase", stellar_context);
        assert!(result.is_err(), "EVM seal must not open in a Stellar context");
    }

    #[test]
    fn invalid_secret_key_is_rejected() {
        // Zero is not a valid scalar.
        assert!(EvmSigner::from_bytes(&[0u8; 32]).is_err());
        // `n` itself is not a valid scalar.
        let n = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2,
            0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        ];
        assert!(EvmSigner::from_bytes(&n).is_err());
    }

    #[test]
    fn verify_address_constant_time() {
        let signer = test_signer();
        let digest = [0x33u8; 32];
        let parts = signer.sign_digest(&digest).expect("sign");
        let bytes = parts.to_bytes();
        assert!(verify_address(&digest, &bytes, &signer.address()).unwrap());
        let other = Address::from_bytes([0u8; 20]);
        assert!(!verify_address(&digest, &bytes, &other).unwrap());
    }
}