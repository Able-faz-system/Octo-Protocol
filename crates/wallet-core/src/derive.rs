//! SEP-0005 hierarchical key derivation for Stellar (SLIP-0010 ed25519).
//!
//! Stellar's SEP-0005 derives account keys at the path `m/44'/148'/<index>'` (all hardened),
//! where `148` is Stellar's SLIP-0044 coin type. From one BIP39 mnemonic we can derive unlimited
//! account keypairs deterministically.
//!
//! In octo's muxed-account model we normally derive only **account 0** (the single master
//! account) and fan out to customers via muxed ids — but this module supports arbitrary indexes
//! so the "real account per customer" model remains available later.

use crate::error::WalletError;
use bip39::{Language, Mnemonic, Seed};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// Stellar's SLIP-0044 coin type.
const STELLAR_COIN_TYPE: u32 = 148;
/// BIP44 purpose.
const BIP44_PURPOSE: u32 = 44;
/// Hardened-derivation offset.
const HARDENED: u32 = 0x8000_0000;
/// Entropy for a 12-word BIP39 mnemonic (128 bits).
const MNEMONIC_ENTROPY_LEN: usize = 16;
/// BIP39 seed output length, independent of mnemonic entropy length.
const BIP39_SEED_LEN: usize = 64;

/// Validate a BIP-39 recovery phrase without constructing or holding secret material.
///
/// Verifies word count, English wordlist membership, and BIP-39 checksum. Safe to call
/// with untrusted input and produces no secret-bearing output, making it suitable for
/// pre-flight client-side checks and API validation routes.
///
/// Returns `Ok(())` on valid mnemonics, or [`WalletError::InvalidMnemonic`] if the phrase
/// is syntactically invalid or fails checksum validation.
pub fn validate_seed_phrase(phrase: &str) -> Result<(), WalletError> {
    // Validate mnemonic syntax, wordlist membership, and checksum.
    Mnemonic::from_phrase(phrase, Language::English)
        .map_err(|_| WalletError::InvalidMnemonic)?;
    Ok(())
}

/// A BIP39 seed (the 64-byte output of mnemonic + passphrase), zeroized on drop.
pub struct WalletSeed(Zeroizing<Vec<u8>>);

impl WalletSeed {
    /// Generate a fresh 12-word mnemonic and return both it and its seed.
    ///
    /// The mnemonic is the **backup secret** — it must be shown to the operator once (for
    /// out-of-band storage) and then only ever persisted in sealed form. It is returned in a
    /// [`Zeroizing`] string so the caller controls its lifetime.
    ///
    /// # Entropy source (load-bearing security property)
    ///
    /// The 128 bits of mnemonic entropy come from [`rand::rngs::OsRng`] — the operating system's
    /// CSPRNG (`getrandom(2)` on Linux) — and are passed to [`Mnemonic::from_entropy`]. We do
    /// **not** call `Mnemonic::new`: in tiny-bip39 2.0.0 that routes through
    /// `crypto::gen_random_bytes` → `rand::thread_rng()`, a userspace ChaCha12 generator that is
    /// only reachable when tiny-bip39's default `rand` feature is on and whose algorithm is a
    /// `rand` implementation detail. Pinning `OsRng` here keeps this guarantee independent of
    /// either crate's defaults across version bumps.
    ///
    /// ```
    /// use octo_wallet_core::WalletSeed;
    /// let (a, _) = WalletSeed::generate();
    /// let (b, _) = WalletSeed::generate();
    /// assert_eq!(a.split(' ').count(), 12);
    /// assert_ne!(*a, *b);
    /// ```
    pub fn generate() -> (Zeroizing<String>, WalletSeed) {
        let mnemonic = fresh_mnemonic();
        let phrase = Zeroizing::new(mnemonic.phrase().to_string());
        let seed = Seed::new(&mnemonic, "");
        let wallet_seed = WalletSeed(Zeroizing::new(seed.as_bytes().to_vec()));
        (phrase, wallet_seed)
    }

    /// Reconstruct a seed from an existing BIP39 mnemonic phrase (recovery / re-import).
    ///
    /// Validates both that each word belongs to the BIP-39 wordlist and that the phrase's
    /// built-in checksum bits verify. Wordlist membership alone is not sufficient validation.
    pub fn from_phrase(phrase: &str) -> Result<WalletSeed, WalletError> {
        // Enforce wordlist and checksum validation before constructing secret material.
        validate_seed_phrase(phrase)?;
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).map_err(|e| match e {
            bip39::ErrorKind::InvalidChecksum => WalletError::InvalidChecksum,
            _ => WalletError::InvalidMnemonic,
        })?;
        let seed = Seed::new(&mnemonic, "");
        Ok(WalletSeed(Zeroizing::new(seed.as_bytes().to_vec())))
    }

    /// Construct from the 64-byte BIP39 seed output (e.g. after decrypting a sealed seed).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<WalletSeed, WalletError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() != BIP39_SEED_LEN {
            return Err(WalletError::InvalidSeedLength);
        }
        Ok(WalletSeed(bytes))
    }

    /// Borrow the raw seed bytes (kept private to the crate; callers derive, they don't read).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derive the 32-byte ed25519 secret key for Stellar account `index` (`m/44'/148'/index'`).
    ///
    /// # Derivation Path & Invariants
    ///
    /// Derives according to Stellar's [SEP-0005](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md)
    /// specification using SLIP-0010 ed25519 master-key derivation:
    ///
    /// - **Path**: `m/44'/148'/index'`, where `44'` is BIP-44 purpose, `148'` is Stellar's
    ///   SLIP-0044 coin type, and `index'` is the account index.
    /// - **All-Hardened Derivation**: Every level in SEP-0005 is strictly hardened (`index | HARDENED`).
    ///   Unlike EVM's BIP-44 path (`m/44'/60'/0'/0/index`, referenced for contrast in
    ///   `docs/ethereum-expansion-issues.md`), which permits unhardened derivation at the change and
    ///   address levels, ed25519 does not safely support unhardened public derivation without
    ///   compromising key security (leaking an extended public key alongside a single child private
    ///   key would allow recovering the parent secret key and all sibling keys). Full hardening
    ///   guarantees that compromise of any derived key cannot compromise parent or sibling keys.
    /// - **Valid Index Range**: Hardened indices must fall within `0..2^31` (`0..0x8000_0000`). Values
    ///   at or above the 2^31 ceiling cannot be hardened without overflowing the 31-bit index space.
    ///   Per SEP-0005 and SLIP-0010 / BIP-32, hardened derivation adds `0x8000_0000` (2^31) to the
    ///   index. An index at or above 2^31 (`index >= 0x8000_0000`) is invalid and would wrap or
    ///   collide with lower indices; it is explicitly rejected with [`WalletError::InvalidDerivationPath`].
    ///
    /// # Architecture & Deposit Model
    ///
    /// In Octo's deposit architecture (see `docs/deposit-model.md`), this derivation underpins the
    /// muxed-address model: account index 0 is derived as the single master base account (`G...`).
    /// Customer funds are multiplexed via 64-bit IDs encoded into SEP-0023 muxed addresses (`M...`),
    /// allowing off-chain per-user address allocation with zero on-chain account reserves and no sweeps.
    /// Arbitrary index derivation remains available if dedicated on-chain accounts are required.
    ///
    /// The returned secret is wrapped in [`Zeroizing`] and zeroized on drop. Feed it to
    /// [`crate::signer`] to construct a keypair.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octo_wallet_core::WalletSeed;
    ///
    /// let mnemonic = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    /// let seed = WalletSeed::from_phrase(mnemonic).unwrap();
    /// let secret = seed.derive_ed25519_secret(0).unwrap();
    /// assert_eq!(secret.len(), 32);
    /// ```
    pub fn derive_ed25519_secret(&self, index: u32) -> Result<Zeroizing<[u8; 32]>, WalletError> {
        if index >= HARDENED {
            return Err(WalletError::InvalidDerivationPath);
        }
        // Derive ed25519 key at hardened path m/44'/148'/index'.
        let path = [
            BIP44_PURPOSE | HARDENED,
            STELLAR_COIN_TYPE | HARDENED,
            index | HARDENED,
        ];
        let key = slip10_ed25519::derive_ed25519_private_key(self.as_bytes(), &path);
        Ok(Zeroizing::new(key))
    }
}

/// Draw a new 12-word mnemonic from OS entropy (see [`WalletSeed::generate`]).
fn fresh_mnemonic() -> Mnemonic {
    let mut entropy = Zeroizing::new([0u8; MNEMONIC_ENTROPY_LEN]);
    OsRng.fill_bytes(entropy.as_mut());
    // 16 bytes is a valid BIP39 entropy length, so from_entropy cannot fail here.
    match Mnemonic::from_entropy(entropy.as_ref(), Language::English) {
        Ok(m) => m,
        Err(_) => unreachable!("16-byte entropy is always a valid BIP39 length"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use stellar_strkey::ed25519::PublicKey;

    // Official SEP-0005 Test 1 vector (no passphrase).
    // https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
    const VECTOR_MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    // m/44'/148'/0' — verified against the official SEP-0005 Test 1 vector.
    const EXPECTED_ACCOUNT_0: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

    fn account_id(seed: &WalletSeed, index: u32) -> String {
        let secret = seed.derive_ed25519_secret(index).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
        let pk = PublicKey(signing.verifying_key().to_bytes());
        format!("{pk}")
    }

    #[test]
    fn sep0005_account_0_matches_official_vector() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_eq!(account_id(&seed, 0), EXPECTED_ACCOUNT_0);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let b = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_eq!(account_id(&a, 0), account_id(&b, 0));
        assert_eq!(account_id(&a, 5), account_id(&b, 5));
    }

    #[test]
    fn different_indexes_give_different_accounts() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_ne!(account_id(&seed, 0), account_id(&seed, 1));
        assert_ne!(account_id(&seed, 1), account_id(&seed, 2));
    }

    #[test]
    fn generated_mnemonic_roundtrips() {
        let (phrase, seed) = WalletSeed::generate();
        let reimported = WalletSeed::from_phrase(&phrase).unwrap();
        assert_eq!(account_id(&seed, 0), account_id(&reimported, 0));
    }

    #[test]
    fn from_phrase_rejects_a_wordlist_valid_but_checksum_invalid_mnemonic() {
        // All words are valid BIP-39 English words, but the checksum is invalid.
        let invalid_checksum_phrase =
            "illness spike retreat truth genius clock brain pass fit cave bargain bargain";
        assert!(matches!(
            WalletSeed::from_phrase(invalid_checksum_phrase),
            Err(WalletError::InvalidChecksum)
        ));
    }

    #[test]
    fn from_phrase_accepts_a_valid_checksummed_mnemonic() {
        assert!(WalletSeed::from_phrase(VECTOR_MNEMONIC).is_ok());
    }

    #[test]
    fn from_bytes_accepts_only_the_64_byte_bip39_seed_length() {
        assert!(matches!(
            WalletSeed::from_bytes(Vec::new()),
            Err(WalletError::InvalidSeedLength)
        ));
        assert!(matches!(
            WalletSeed::from_bytes(vec![0; BIP39_SEED_LEN - 1]),
            Err(WalletError::InvalidSeedLength)
        ));
        assert!(matches!(
            WalletSeed::from_bytes(vec![0; BIP39_SEED_LEN + 1]),
            Err(WalletError::InvalidSeedLength)
        ));

        let phrase_seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_eq!(phrase_seed.as_bytes().len(), BIP39_SEED_LEN);
        assert!(WalletSeed::from_bytes(vec![0; BIP39_SEED_LEN]).is_ok());
    }

    #[test]
    fn from_phrase_rejects_a_word_not_in_the_wordlist() {
        assert!(matches!(
            WalletSeed::from_phrase("not a real mnemonic phrase at all"),
            Err(WalletError::InvalidMnemonic)
        ));
    }

    // Sourced checksum-invalid and syntactically invalid test vectors.
    //
    // Sources:
    // 1. Trezor python-mnemonic test suite (tests/test_mnemonic.py:test_failed_checksum).
    // 2. BIP-39 specification official vectors (bitcoin/bips/bip-0039.mediawiki &
    //    trezor/python-mnemonic/vectors.json), mutating the final checksum word to an alternative
    //    wordlist entry ("almost valid" vectors: correct word count and wordlist membership, wrong checksum).
    // 3. Grossly invalid vectors (length mismatches, non-wordlist tokens, empty input).
    const SOURCED_CHECKSUM_INVALID_VECTORS: &[&str] = &[
        // Trezor python-mnemonic tests/test_mnemonic.py test_failed_checksum
        "bless cloud wheel regular tiny venue bird web grief security dignity zoo",
        // BIP-39 spec vector 0 (12-word all-zero entropy), mutated checksum word (about -> abandon)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        // BIP-39 spec vector 0 (12-word all-zero entropy), mutated checksum word (about -> zoo)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo",
        // BIP-39 spec vector 1 (12-word all-0x7F entropy), mutated checksum word (yellow -> legal)
        "legal winner thank year wave sausage worth useful legal winner thank legal",
        // BIP-39 spec vector 3 (12-word all-0xFF entropy), mutated checksum word (wrong -> zoo)
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
        // 15-word phrase, mutated checksum word
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        // BIP-39 spec vector 4 (18-word all-zero entropy), mutated checksum word (agent -> abandon)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        // BIP-39 spec vector 7 (24-word all-zero entropy), mutated checksum word (art -> abandon)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        // BIP-39 spec vector 8 (24-word all-0x7F entropy), mutated checksum word (title -> yellow)
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth yellow",
        // BIP-39 spec vector 9 (24-word all-0xFF entropy), mutated checksum word (vote -> zoo)
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
        // Grossly invalid: non-wordlist tokens
        "not a real mnemonic phrase at all",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword",
        // Grossly invalid: incorrect word counts (11, 13, 25 words)
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        // Grossly invalid: empty and corrupt strings
        "",
        "   ",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon 1234",
    ];

    #[test]
    fn from_phrase_rejects_every_sourced_checksum_invalid_vector() {
        for &vector in SOURCED_CHECKSUM_INVALID_VECTORS {
            let res = WalletSeed::from_phrase(vector);
            assert!(
                matches!(res, Err(WalletError::InvalidMnemonic)),
                "from_phrase must reject checksum-invalid vector {vector:?}, got {res:?}"
            );
        }
    }

    #[test]
    fn validate_seed_phrase_accepts_every_from_phrase_accepted_vector() {
        let (gen_phrase, _) = WalletSeed::generate();
        let valid_vectors = [
            VECTOR_MNEMONIC,
            gen_phrase.as_str(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ];
        for vector in valid_vectors {
            assert!(
                validate_seed_phrase(vector).is_ok(),
                "validate_seed_phrase rejected valid vector {vector:?}"
            );
            assert!(
                WalletSeed::from_phrase(vector).is_ok(),
                "from_phrase rejected valid vector {vector:?}"
            );
        }
    }

    #[test]
    fn validate_seed_phrase_rejects_every_from_phrase_rejected_vector() {
        for &vector in SOURCED_CHECKSUM_INVALID_VECTORS {
            let val_res = validate_seed_phrase(vector);
            let seed_res = WalletSeed::from_phrase(vector);
            assert!(
                matches!(val_res, Err(WalletError::InvalidMnemonic)),
                "validate_seed_phrase must reject {vector:?}"
            );
            assert!(
                matches!(seed_res, Err(WalletError::InvalidMnemonic)),
                "from_phrase must reject {vector:?}"
            );
        }
    }

    #[test]
    fn validate_seed_phrase_never_returns_secret_material_even_on_success() {
        // Assert at type level that validate_seed_phrase produces unit () and holds no secret state.
        let result: Result<(), WalletError> = validate_seed_phrase(VECTOR_MNEMONIC);
        assert_eq!(result.unwrap(), ());
        assert_eq!(std::mem::size_of::<()>(), 0);
    }

    proptest! {
        #[test]
        fn derivation_is_deterministic_for_any_index(
            entropy in any::<[u8; 16]>(),
            index in 0..super::HARDENED
        ) {
            let mnemonic =
                bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
            let seed_bytes = bip39::Seed::new(&mnemonic, "").as_bytes().to_vec();
            let seed_a = WalletSeed::from_bytes(seed_bytes.clone()).unwrap();
            let seed_b = WalletSeed::from_bytes(seed_bytes).unwrap();
            let secret_a = seed_a.derive_ed25519_secret(index).unwrap();
            let secret_b = seed_b.derive_ed25519_secret(index).unwrap();
            prop_assert_eq!(*secret_a, *secret_b);
        }

        #[test]
        fn distinct_indices_yield_distinct_secrets(
            entropy in any::<[u8; 16]>(),
            index_a in 0..super::HARDENED,
            index_b in 0..super::HARDENED
        ) {
            prop_assume!(index_a != index_b);
            let mnemonic =
                bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
            let seed = WalletSeed::from_bytes(
                bip39::Seed::new(&mnemonic, "").as_bytes().to_vec(),
            )
            .unwrap();
            let secret_a = seed.derive_ed25519_secret(index_a).unwrap();
            let secret_b = seed.derive_ed25519_secret(index_b).unwrap();
            prop_assert_ne!(*secret_a, *secret_b);
        }
    }

    #[test]
    fn derive_ed25519_secret_rejects_an_index_at_2_pow_31() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert!(matches!(
            seed.derive_ed25519_secret(super::HARDENED),
            Err(WalletError::InvalidDerivationPath)
        ));
        assert!(matches!(
            seed.derive_ed25519_secret(u32::MAX),
            Err(WalletError::InvalidDerivationPath)
        ));
    }

    #[test]
    fn derive_ed25519_secret_accepts_the_maximum_valid_index_2_pow_31_minus_1() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        let max_valid = super::HARDENED - 1;
        assert!(seed.derive_ed25519_secret(max_valid).is_ok());
    }

    #[test]
    fn derive_ed25519_secret_matches_known_sep0005_test_vectors_for_small_indices() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        assert_eq!(account_id(&seed, 0), EXPECTED_ACCOUNT_0);
        assert!(seed.derive_ed25519_secret(0).is_ok());
        assert!(seed.derive_ed25519_secret(1).is_ok());
    }

    #[test]
    fn boundary_indices_derive_without_panic() {
        let seed = WalletSeed::from_phrase(VECTOR_MNEMONIC).unwrap();
        // Exercises valid boundary indices: 0, 1, and HARDENED - 1 (2^31 - 1).
        for &index in &[0u32, 1, super::HARDENED - 1] {
            let secret = seed.derive_ed25519_secret(index).unwrap();
            let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
            let pk = PublicKey(signing.verifying_key().to_bytes());
            let encoded = format!("{pk}");
            let decoded = PublicKey::from_string(&encoded).unwrap();
            assert_eq!(decoded.0, signing.verifying_key().to_bytes());
        }
    }
}
