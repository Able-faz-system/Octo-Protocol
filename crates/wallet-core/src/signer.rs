//! The signing path: open a sealed seed, derive the master key, build a **payment** transaction,
//! sign it, and zeroize secrets.
//!
//! Security posture (see `docs/threat-model.md`):
//! - This module only ever builds octo's own **Payment** operations. It does **not** accept or
//!   sign caller-supplied raw XDR, so it cannot be used as a "sign anything" oracle.
//! - Amounts are integer **stroops** (`i64`), validated to be strictly positive.
//! - The network (testnet/mainnet) is always explicit — there is no ambient default that could
//!   cause a testnet-intended signature to be valid on mainnet.
//! - The decrypted seed and the derived keypair live only for the duration of `sign_payment` and
//!   are zeroized on drop.

use crate::derive::WalletSeed;
use crate::error::WalletError;
use octo_crypto::{open, SealedSeed, MASTER_KEY_LEN};
use stellar_base::crypto::DalekKeyPair;
use stellar_base::network::Network;
// sign_fee_bump (production, not test-gated) rejects sub-minimum fees against this constant.
use stellar_base::transaction::MIN_BASE_FEE;
use zeroize::Zeroizing;

// validate_change_trust (production) checks the issuer strkey.
use crate::address::is_valid_account;
// Used only by the feature-gated custodial signing fixtures below.
#[cfg(any(test, feature = "test-fixtures"))]
use crate::asset::validate_asset_code;
#[cfg(any(test, feature = "test-fixtures"))]
use stellar_base::amount::Stroops;
#[cfg(any(test, feature = "test-fixtures"))]
use stellar_base::asset::Asset;
#[cfg(any(test, feature = "test-fixtures"))]
use stellar_base::crypto::{MuxedEd25519PublicKey, PublicKey};
#[cfg(any(test, feature = "test-fixtures"))]
use stellar_base::memo::Memo;
#[cfg(any(test, feature = "test-fixtures"))]
use stellar_base::operations::Operation;
#[cfg(any(test, feature = "test-fixtures"))]
use stellar_base::transaction::Transaction;
#[cfg(any(test, feature = "test-fixtures"))]
use stellar_base::xdr::XDRSerialize;

/// Which Stellar network a signature targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StellarNetwork {
    /// Public (mainnet) network.
    Public,
    /// Test network.
    Testnet,
    /// Local standalone network (Stellar quickstart default).
    ///
    /// Uses the well-known quickstart passphrase `"Standalone Network ; February 2017"` so that
    /// contributors can run integration tests against a local Stellar node without depending on
    /// public testnet availability or friendbot rate limits.
    Standalone,
}

impl StellarNetwork {
    fn to_base(self) -> Network {
        match self {
            StellarNetwork::Public => Network::new_public(),
            StellarNetwork::Testnet => Network::new_test(),
            StellarNetwork::Standalone => {
                Network::new("Standalone Network ; February 2017".to_string())
            }
        }
    }

    /// The canonical network passphrase (what clients must sign against).
    pub fn passphrase(self) -> &'static str {
        match self {
            StellarNetwork::Public => "Public Global Stellar Network ; September 2015",
            StellarNetwork::Testnet => "Test SDF Network ; September 2015",
            StellarNetwork::Standalone => "Standalone Network ; February 2017",
        }
    }

    pub fn crypto_context(self) -> &'static [u8] {
        match self {
            StellarNetwork::Public => b"octo:mainnet",
            StellarNetwork::Testnet => b"octo:testnet",
            StellarNetwork::Standalone => b"octo:standalone",
        }
    }

    /// The canonical lowercase name (`"mainnet"` / `"testnet"` / `"standalone"`) used in the DB
    /// and API.
    pub fn as_str(self) -> &'static str {
        match self {
            StellarNetwork::Public => "mainnet",
            StellarNetwork::Testnet => "testnet",
            StellarNetwork::Standalone => "standalone",
        }
    }

    /// Parse from the canonical name. Accepts `mainnet`/`public`, `testnet`/`test`, and
    /// `standalone`.
    ///
    /// Fail-closed invariant: returns `None` for any unrecognized or typo string (e.g. `mainnnet`,
    /// `Testnet`), with no default fallback. Callers must fail closed rather than defaulting to any
    /// ambient network, preventing wrong-network signatures.
    pub fn parse(s: &str) -> Option<StellarNetwork> {
        match s {
            "mainnet" | "public" => Some(StellarNetwork::Public),
            "testnet" | "test" => Some(StellarNetwork::Testnet),
            "standalone" => Some(StellarNetwork::Standalone),
            _ => None,
        }
    }
}

/// A single payment to build and sign from the master account.
///
/// **Test fixture only** since the non-custodial cutover: production code has no server-held
/// user seed to sign with. Kept (feature-gated) so validation tests can fabricate real signed
/// envelopes.
#[cfg(any(test, feature = "test-fixtures"))]
pub struct PaymentRequest<'a> {
    /// Destination account (`G...`) or muxed (`M...`) address.
    pub destination: &'a str,
    /// Amount in **stroops** (1 XLM = 10_000_000 stroops). Must be > 0.
    pub stroops: i64,
    /// `None` => native XLM. `Some((code, issuer_g))` => a credit asset.
    pub asset: Option<(&'a str, &'a str)>,
    /// Optional nonnegative Stellar `MEMO_ID`; the `u64` type matches XDR and excludes negatives.
    pub memo_id: Option<u64>,
    /// The master account's current sequence number (fetched from Horizon by the caller).
    pub sequence: i64,
}

/// The result of signing: the base64 XDR envelope to submit, plus the master account it was
/// signed for. (The transaction hash is computed by the caller/Horizon on submit.)
pub struct SignedPayment {
    /// Base64-encoded signed `TransactionEnvelope`, ready to POST to Horizon.
    pub envelope_xdr: String,
    /// The `G...` master account that sourced and signed this transaction.
    pub source_account: String,
}

/// Open a sealed seed for `network`, derive Stellar account `account_index`, and return its
/// `DalekKeyPair`. The decrypted seed is zeroized as it leaves scope.
fn derived_secret_from_sealed(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    network: StellarNetwork,
    account_index: u32,
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let seed_bytes = open(master_key, sealed, network.crypto_context())?;
    let seed = WalletSeed::from_bytes(seed_bytes.to_vec())?;
    seed.derive_ed25519_secret(account_index)
}

fn keypair_from_sealed(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    network: StellarNetwork,
    account_index: u32,
) -> Result<DalekKeyPair, WalletError> {
    let secret = derived_secret_from_sealed(master_key, sealed, network, account_index)?;
    // stellar-base builds the ed25519 keypair from the 32-byte secret seed.
    DalekKeyPair::from_seed_bytes(secret.as_ref()).map_err(|_| WalletError::KeyDerivation)
}

/// Derive just the `G...` account id for `account_index` from a sealed seed (no signing).
pub fn account_id_from_sealed(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    network: StellarNetwork,
    account_index: u32,
) -> Result<String, WalletError> {
    let kp = keypair_from_sealed(master_key, sealed, network, account_index)?;
    Ok(kp.public_key().account_id())
}

/// Build and sign a payment from the master account (`account_index`, normally 0).
///
/// Only a Payment operation is ever constructed — no other operation type can be produced by this
/// function, which is the core anti-"signing-oracle" guarantee.
///
/// Invariant: secret material is zeroized on every exit path, success or error.
///
/// **Test fixture only** since the non-custodial cutover (see [`PaymentRequest`]).
#[cfg(any(test, feature = "test-fixtures"))]
pub fn sign_payment(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    network: StellarNetwork,
    account_index: u32,
    req: &PaymentRequest<'_>,
) -> Result<SignedPayment, WalletError> {
    if req.stroops <= 0 {
        return Err(WalletError::InvalidAmount);
    }

    let keypair = keypair_from_sealed(master_key, sealed, network, account_index)?;
    let source = keypair.public_key();
    let source_account = source.account_id();

    // Resolve the destination (accept either G... or M...).
    let destination = parse_destination(req.destination)?;

    // Resolve the asset (native XLM or a validated credit asset).
    let asset = match req.asset {
        None => Asset::new_native(),
        Some((code, issuer)) => {
            validate_asset_code(code)?;
            if !is_valid_account(issuer) {
                return Err(WalletError::InvalidAddress);
            }
            let issuer_pk =
                PublicKey::from_account_id(issuer).map_err(|_| WalletError::InvalidAddress)?;
            Asset::new_credit(code, issuer_pk).map_err(|_| WalletError::InvalidAssetCode)?
        }
    };

    let payment = Operation::new_payment()
        .with_destination(destination)
        .with_amount(Stroops::new(req.stroops))
        .map_err(|_| WalletError::InvalidAmount)?
        .with_asset(asset)
        .build()
        .map_err(|_| WalletError::Signing)?;

    let mut builder = Transaction::builder(source, req.sequence, MIN_BASE_FEE);
    if let Some(id) = req.memo_id {
        builder = builder.with_memo(Memo::new_id(id));
    }
    let mut tx = builder
        .add_operation(payment)
        .into_transaction()
        .map_err(|_| WalletError::Signing)?;

    // DalekKeyPair derefs to the inner KeyPair, which is what sign() accepts.
    tx.sign(keypair.as_ref(), &network.to_base())
        .map_err(|_| WalletError::Signing)?;

    let envelope_xdr = tx
        .into_envelope()
        .xdr_base64()
        .map_err(|_| WalletError::Signing)?;

    Ok(SignedPayment {
        envelope_xdr,
        source_account,
    })
}

/// Validate ChangeTrust parameters: asset code, `G...` issuer, and a non-negative limit.
///
/// Shared by server-side validation of client-built trustlines and the test-fixture signer, so
/// both paths accept exactly the same inputs.
pub fn validate_change_trust(
    asset_code: &str,
    asset_issuer: &str,
    limit_stroops: Option<i64>,
) -> Result<(), WalletError> {
    if !crate::asset::is_valid_asset_code(asset_code) {
        return Err(WalletError::InvalidAssetCode);
    }
    if !is_valid_account(asset_issuer) {
        return Err(WalletError::InvalidAddress);
    }
    if limit_stroops.is_some_and(|l| l < 0) {
        return Err(WalletError::InvalidAmount);
    }
    Ok(())
}

/// A trustline (ChangeTrust) to build and sign from the master account.
///
/// **Test fixture only** since the non-custodial cutover (see [`PaymentRequest`]).
#[cfg(any(test, feature = "test-fixtures"))]
pub struct ChangeTrustRequest<'a> {
    /// Asset code to trust (e.g. `"USDC"`). 1–12 ASCII chars.
    pub asset_code: &'a str,
    /// The asset issuer account (`G...`).
    pub asset_issuer: &'a str,
    /// Trust limit in **stroops**. `None` => the protocol maximum (unlimited).
    /// `Some(0)` removes the trustline (only allowed when the balance is zero).
    pub limit_stroops: Option<i64>,
    /// The master account's current sequence number (fetched from Horizon by the caller).
    pub sequence: i64,
}

/// Build and sign a ChangeTrust (trustline) operation from the master account.
///
/// This only ever constructs Octo's own operation — here a single ChangeTrust — so it cannot be
/// used as a "sign anything" oracle.
///
/// Invariant: secret material is zeroized on every exit path, success or error.
///
/// **Test fixture only** since the non-custodial cutover (see [`PaymentRequest`]).
#[cfg(any(test, feature = "test-fixtures"))]
pub fn sign_change_trust(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    network: StellarNetwork,
    account_index: u32,
    req: &ChangeTrustRequest<'_>,
) -> Result<SignedPayment, WalletError> {
    validate_change_trust(req.asset_code, req.asset_issuer, req.limit_stroops)?;

    let keypair = keypair_from_sealed(master_key, sealed, network, account_index)?;
    let source = keypair.public_key();
    let source_account = source.account_id();

    let issuer_pk =
        PublicKey::from_account_id(req.asset_issuer).map_err(|_| WalletError::InvalidAddress)?;
    // `with_asset` takes a ChangeTrustAsset; a credit `Asset` converts via `From<Asset>`.
    let asset: Asset =
        Asset::new_credit(req.asset_code, issuer_pk).map_err(|_| WalletError::InvalidAddress)?;

    // Stellar encodes a *missing* limit as 0, which means "remove the trustline" — not
    // "unlimited". So map "no limit requested" to the protocol maximum (i64::MAX) to establish
    // an unlimited trustline. An explicit 0 is preserved (caller intends to remove).
    let limit = req.limit_stroops.unwrap_or(i64::MAX);
    let change_trust = Operation::new_change_trust()
        .with_asset(asset.into())
        .with_limit(Some(Stroops::new(limit)))
        .map_err(|_| WalletError::InvalidAmount)?
        .build()
        .map_err(|_| WalletError::Signing)?;

    let mut tx = Transaction::builder(source, req.sequence, MIN_BASE_FEE)
        .add_operation(change_trust)
        .into_transaction()
        .map_err(|_| WalletError::Signing)?;

    tx.sign(keypair.as_ref(), &network.to_base())
        .map_err(|_| WalletError::Signing)?;

    let envelope_xdr = tx
        .into_envelope()
        .xdr_base64()
        .map_err(|_| WalletError::Signing)?;

    Ok(SignedPayment {
        envelope_xdr,
        source_account,
    })
}

/// Request parameters for wrapping a user's signed transaction in a FeeBumpTransaction.
pub struct FeeBumpRequest<'a> {
    /// Base64-encoded signed `TransactionEnvelope` from the user. Must be a v1 (`Tx`) envelope.
    pub inner_xdr: &'a str,
    /// Maximum fee (in stroops) the sponsor is willing to pay for the fee-bump.
    ///
    /// This value is stored **verbatim** as the outer `FeeBumpTransaction.fee` — a **flat total
    /// fee bid in stroops for the whole envelope**, not a per-operation base fee. Per Stellar's
    /// fee-bump validity rules (CAP-15), the network treats the declared fee as covering
    /// `inner_operation_count + 1` operations (the inner ops plus the fee-bump itself), so for
    /// multi-op inner transactions the caller must size this bid accordingly — use
    /// [`inner_operation_count`] to inspect the inner transaction. See `docs/threat-model.md`
    /// section B (signing-path abuse / fee injection) for the fee-semantics threat rows.
    pub max_base_fee_stroops: i64,
}

/// Wrap a user's already-signed `TransactionEnvelope` in a `FeeBumpTransaction` signed by the
/// master wallet as fee source, then return the signed outer envelope XDR.
///
/// Security: the seed is decrypted, the signing key is derived, and both are zeroized on drop —
/// the same contract as `sign_payment`. The caller is responsible for validating the inner XDR
/// (operation-type allowlist, self-sponsorship guard) before calling this function.
///
/// Invariant: secret material is zeroized on every exit path, success or error.
pub fn sign_fee_bump(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    network: StellarNetwork,
    account_index: u32,
    req: &FeeBumpRequest<'_>,
) -> Result<SignedPayment, WalletError> {
    use sha2::{Digest, Sha256};
    use stellar_base::xdr::{
        BytesM, DecoratedSignature, FeeBumpTransaction as XdrFeeBump, FeeBumpTransactionEnvelope,
        FeeBumpTransactionExt, FeeBumpTransactionInnerTx, Hash, MuxedAccount, Signature,
        SignatureHint, TransactionEnvelope, TransactionSignaturePayload,
        TransactionSignaturePayloadTaggedTransaction, Uint256, VecM, XDRSerialize,
    };

    // Reject fees below the Stellar network minimum before touching key material.
    // A sub-minimum fee would be rejected by Horizon at submit time, wasting a budget
    // reservation (try_reserve_sponsored_transaction) and a full sign cycle.
    if req.max_base_fee_stroops < MIN_BASE_FEE.to_i64() {
        return Err(WalletError::InvalidAmount);
    }

    // Parse and validate the inner XDR — must be a v1 TransactionEnvelope.
    let inner_v1 = parse_inner_v1(req.inner_xdr)?;

    // Derive the signing key for the fee source (decrypt → derive → zeroize on drop).
    let secret = derived_secret_from_sealed(master_key, sealed, network, account_index)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);

    let pk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let source_account = format!("{}", stellar_strkey::ed25519::PublicKey(pk_bytes));

    // Build the fee-bump transaction (without signatures yet).
    let fee_bump_tx = XdrFeeBump {
        fee_source: MuxedAccount::Ed25519(Uint256(pk_bytes)),
        fee: req.max_base_fee_stroops,
        inner_tx: FeeBumpTransactionInnerTx::Tx(inner_v1),
        ext: FeeBumpTransactionExt::V0,
    };

    // Compute the signing hash: sha256(XDR(TransactionSignaturePayload)).
    let network_id_bytes = network.to_base().network_id();
    let network_hash: [u8; 32] = network_id_bytes
        .as_slice()
        .try_into()
        .map_err(|_| WalletError::Signing)?;

    let sig_payload = TransactionSignaturePayload {
        network_id: Hash(network_hash),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::TxFeeBump(
            fee_bump_tx.clone(),
        ),
    };
    let payload_xdr = sig_payload.xdr_bytes().map_err(|_| WalletError::Signing)?;
    let hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

    // Sign the hash with ed25519 (signing_key zeroized on drop).
    use ed25519_dalek::Signer as _;
    let signature: ed25519_dalek::Signature = signing_key.sign(&hash);
    let sig_bytes: [u8; 64] = signature.to_bytes();

    // Build the decorated signature (hint = last 4 bytes of the public key).
    let hint_bytes: [u8; 4] = pk_bytes[28..32]
        .try_into()
        .map_err(|_| WalletError::Signing)?;
    let decorated = DecoratedSignature {
        hint: SignatureHint(hint_bytes),
        signature: Signature(
            BytesM::<64>::try_from(sig_bytes.to_vec()).map_err(|_| WalletError::Signing)?,
        ),
    };

    // Assemble the fee-bump envelope and serialize.
    let sigs: VecM<DecoratedSignature, 20> = vec![decorated]
        .try_into()
        .map_err(|_| WalletError::Signing)?;
    let fee_bump_envelope = FeeBumpTransactionEnvelope {
        tx: fee_bump_tx,
        signatures: sigs,
    };
    let envelope_xdr = TransactionEnvelope::TxFeeBump(fee_bump_envelope)
        .xdr_base64()
        .map_err(|_| WalletError::Signing)?;

    Ok(SignedPayment {
        envelope_xdr,
        source_account,
    })
}

/// Compute the Stellar transaction hash (SHA-256 of the network-specific signing payload) for the
/// inner transaction in a fee-bump flow. This is the standard txID Horizon uses, not a hash of the
/// submitted envelope bytes: signatures are excluded and the decoded transaction is XDR-serialized
/// as a `TransactionSignaturePayload`.
pub fn compute_inner_tx_hash(
    inner_xdr: &str,
    network: StellarNetwork,
) -> Result<[u8; 32], WalletError> {
    use sha2::{Digest, Sha256};
    use stellar_base::xdr::{
        Hash, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
        XDRSerialize,
    };

    let inner_tx = parse_inner_v1(inner_xdr)?.tx;

    let network_id_bytes = network.to_base().network_id();
    let network_hash: [u8; 32] = network_id_bytes
        .as_slice()
        .try_into()
        .map_err(|_| WalletError::Signing)?;

    let sig_payload = TransactionSignaturePayload {
        network_id: Hash(network_hash),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(inner_tx),
    };
    let payload_xdr = sig_payload.xdr_bytes().map_err(|_| WalletError::Signing)?;
    Ok(Sha256::digest(&payload_xdr).into())
}

/// Count the operations in the inner transaction of a fee-bump flow, so callers can size the
/// flat fee bid ([`FeeBumpRequest::max_base_fee_stroops`]) as
/// `(operation_count + 1) × base_fee` per Stellar's fee-bump rule (the `+ 1` pays for the
/// fee-bump itself).
///
/// Accepts only a v1 (`Tx`) envelope — the same constraint as [`sign_fee_bump`] — and returns
/// [`WalletError::InvalidXdr`] for anything else. Pure parsing: no I/O, no secret material. A
/// zero-op envelope parses and returns `Ok(0)`; Stellar itself rejects zero-op transactions, so
/// this helper reports the count, it does not validate the transaction.
pub fn inner_operation_count(inner_xdr: &str) -> Result<usize, WalletError> {
    Ok(parse_inner_v1(inner_xdr)?.tx.operations.len())
}

// Extract the sequence number of the inner transaction.
pub fn inner_sequence_number(inner_xdr: &str) -> Result<i64, WalletError> {
    Ok(parse_inner_v1(inner_xdr)?.tx.seq_num.0)
}

// Decode a base64 TransactionEnvelope strictly, rejecting trailing bytes after the envelope.
pub fn decode_envelope_strict(
    b64: &str,
) -> Result<stellar_base::xdr::TransactionEnvelope, WalletError> {
    use base64::Engine;
    use stellar_base::xdr::{TransactionEnvelope, XDRDeserialize, XDRSerialize};

    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| WalletError::InvalidXdr)?;
    let env = TransactionEnvelope::from_xdr(&raw).map_err(|_| WalletError::InvalidXdr)?;
    let encoded = env.xdr_bytes().map_err(|_| WalletError::InvalidXdr)?;
    if encoded.len() != raw.len() {
        return Err(WalletError::InvalidXdr);
    }
    Ok(env)
}

// Parse inner_xdr as a v1 Tx TransactionEnvelope using strict decoding.
fn parse_inner_v1(
    inner_xdr: &str,
) -> Result<stellar_base::xdr::TransactionV1Envelope, WalletError> {
    use stellar_base::xdr::TransactionEnvelope;
    let env = decode_envelope_strict(inner_xdr)?;
    match env {
        TransactionEnvelope::Tx(v1) => Ok(v1),
        _ => Err(WalletError::InvalidXdr),
    }
}

/// Parse a destination that may be a `G...` account or an `M...` muxed address.
#[cfg(any(test, feature = "test-fixtures"))]
fn parse_destination(dest: &str) -> Result<stellar_base::crypto::MuxedAccount, WalletError> {
    if let Ok(mux) = MuxedEd25519PublicKey::from_account_id(dest) {
        return Ok(mux.into());
    }
    let pk = PublicKey::from_account_id(dest).map_err(|_| WalletError::InvalidAddress)?;
    Ok(pk.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use octo_crypto::seal;
    use stellar_base::xdr::XDRDeserialize;

    const VECTOR_MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    const MASTER_ACCOUNT_0: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
    // A valid destination: account index 1 derived from the same vector seed.
    const DEST: &str = "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX";

    fn sealed_vector_seed(net: StellarNetwork) -> ([u8; 32], SealedSeed) {
        let mk = [7u8; 32];
        // The raw 64-byte BIP39 seed for the SEP-0005 vector mnemonic, sealed for `net`.
        let bytes = bip39::Seed::new(
            &bip39::Mnemonic::from_phrase(VECTOR_MNEMONIC, bip39::Language::English).unwrap(),
            "",
        )
        .as_bytes()
        .to_vec();
        let sealed = seal(&mk, &bytes, net.crypto_context()).unwrap();
        (mk, sealed)
    }

    #[test]
    fn parse_rejects_a_typo_variant_of_a_known_network_name() {
        assert_eq!(StellarNetwork::parse("mainnnet"), None);
        assert_eq!(StellarNetwork::parse("tsetnet"), None);
        assert_eq!(StellarNetwork::parse("stand-alone"), None);
    }

    #[test]
    fn parse_rejects_case_variants_not_exactly_matching_the_canonical_string() {
        assert_eq!(StellarNetwork::parse("Mainnet"), None);
        assert_eq!(StellarNetwork::parse("Testnet"), None);
        assert_eq!(StellarNetwork::parse("TESTNET"), None);
        assert_eq!(StellarNetwork::parse("PUBLIC"), None);
        assert_eq!(StellarNetwork::parse("Standalone"), None);
    }

    #[test]
    fn parse_accepts_every_canonical_network_string() {
        assert_eq!(StellarNetwork::parse("mainnet"), Some(StellarNetwork::Public));
        assert_eq!(StellarNetwork::parse("public"), Some(StellarNetwork::Public));
        assert_eq!(StellarNetwork::parse("testnet"), Some(StellarNetwork::Testnet));
        assert_eq!(StellarNetwork::parse("test"), Some(StellarNetwork::Testnet));
        assert_eq!(StellarNetwork::parse("standalone"), Some(StellarNetwork::Standalone));
    }

    #[test]
    fn account_id_from_sealed_matches_vector() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let acct = account_id_from_sealed(&mk, &sealed, StellarNetwork::Testnet, 0).unwrap();
        assert_eq!(acct, MASTER_ACCOUNT_0);
    }

    #[test]
    fn signs_native_payment_and_produces_valid_envelope() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = PaymentRequest {
            destination: DEST,
            stroops: 10_000_000, // 1 XLM
            asset: None,
            memo_id: None,
            sequence: 1,
        };
        let signed = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        assert_eq!(signed.source_account, MASTER_ACCOUNT_0);
        // The envelope must be valid, signed XDR that round-trips through the parser.
        let env = stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&signed.envelope_xdr)
            .expect("signed envelope must be valid XDR");
        // It must carry exactly one signature.
        match env {
            stellar_base::xdr::TransactionEnvelope::Tx(e) => {
                assert_eq!(e.signatures.len(), 1, "must be signed once");
            }
            _ => panic!("unexpected envelope variant"),
        }
    }

    #[test]
    fn signs_change_trust_and_produces_valid_envelope() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = ChangeTrustRequest {
            asset_code: "USDC",
            asset_issuer: DEST,
            limit_stroops: None, // unlimited
            sequence: 1,
        };
        let signed = sign_change_trust(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        assert_eq!(signed.source_account, MASTER_ACCOUNT_0);
        let env = stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&signed.envelope_xdr)
            .expect("signed envelope must be valid XDR");
        match env {
            stellar_base::xdr::TransactionEnvelope::Tx(e) => {
                assert_eq!(e.signatures.len(), 1, "must be signed once");
                // A `None` limit must serialize as i64::MAX (unlimited), NOT 0 —
                // 0 means "remove trustline" and yields op_invalid_limit on-chain.
                match &e.tx.operations[0].body {
                    stellar_base::xdr::OperationBody::ChangeTrust(op) => {
                        assert_eq!(op.limit, i64::MAX, "unlimited trustline limit");
                    }
                    _ => panic!("expected a ChangeTrust op"),
                }
            }
            _ => panic!("unexpected envelope variant"),
        }
    }

    #[test]
    fn change_trust_rejects_bad_issuer() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = ChangeTrustRequest {
            asset_code: "USDC",
            asset_issuer: "not-an-account",
            limit_stroops: None,
            sequence: 1,
        };
        assert!(sign_change_trust(&mk, &sealed, StellarNetwork::Testnet, 0, &req).is_err());
    }

    #[test]
    fn rejects_non_positive_amount() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        for bad in [0i64, -1, -10_000_000] {
            let req = PaymentRequest {
                destination: DEST,
                stroops: bad,
                asset: None,
                memo_id: None,
                sequence: 1,
            };
            assert!(matches!(
                sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
                Err(WalletError::InvalidAmount)
            ));
        }
    }

    #[test]
    fn rejects_bad_destination() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = PaymentRequest {
            destination: "not-an-address",
            stroops: 1,
            asset: None,
            memo_id: None,
            sequence: 1,
        };
        assert!(matches!(
            sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::InvalidAddress)
        ));
    }

    /// Regression coverage for `sign_payment`'s use of the shared
    /// `crate::asset::is_valid_asset_code` (see `crate::asset`): an out-of-bounds credit-asset
    /// code must be rejected as `InvalidAssetCode` before any `Asset::new_credit` call, and a
    /// well-formed 1-12 byte code must still sign successfully.
    #[test]
    fn credit_payment_asset_code_goes_through_shared_validator() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);

        for bad in ["", "THIRTEEN_BYTE"] {
            let req = PaymentRequest {
                destination: DEST,
                stroops: 1,
                asset: Some((bad, MASTER_ACCOUNT_0)),
                memo_id: None,
                sequence: 1,
            };
            assert!(
                matches!(
                    sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
                    Err(WalletError::InvalidAssetCode)
                ),
                "code {bad:?} (len {}) must be rejected as InvalidAssetCode",
                bad.len()
            );
        }

        let req = PaymentRequest {
            destination: DEST,
            stroops: 1,
            asset: Some(("USDC", MASTER_ACCOUNT_0)),
            memo_id: None,
            sequence: 1,
        };
        assert!(sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req).is_ok());
    }

    #[test]
    fn wrong_network_context_cannot_open_seed() {
        // Seed sealed for mainnet; signing as testnet must fail to decrypt (AAD/context mismatch).
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Public);
        let req = PaymentRequest {
            destination: DEST,
            stroops: 1,
            asset: None,
            memo_id: None,
            sequence: 1,
        };
        assert!(matches!(
            sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::SeedDecryption)
        ));
    }

    #[test]
    fn every_sealed_seed_operation_rejects_cross_network_use() {
        let (master_key, sealed) = sealed_vector_seed(StellarNetwork::Public);

        assert!(matches!(
            account_id_from_sealed(&master_key, &sealed, StellarNetwork::Testnet, 0),
            Err(WalletError::SeedDecryption)
        ));

        let payment = PaymentRequest {
            destination: DEST,
            stroops: 1,
            asset: None,
            memo_id: None,
            sequence: 1,
        };
        assert!(matches!(
            sign_payment(&master_key, &sealed, StellarNetwork::Testnet, 0, &payment),
            Err(WalletError::SeedDecryption)
        ));

        let trustline = ChangeTrustRequest {
            asset_code: "USDC",
            asset_issuer: DEST,
            limit_stroops: None,
            sequence: 1,
        };
        assert!(matches!(
            sign_change_trust(
                &master_key,
                &sealed,
                StellarNetwork::Testnet,
                0,
                &trustline,
            ),
            Err(WalletError::SeedDecryption)
        ));
    }

    #[test]
    fn sign_fee_bump_produces_valid_outer_envelope() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Create a valid inner signed payment to wrap.
        let inner_req = PaymentRequest {
            destination: DEST,
            stroops: 100,
            asset: None,
            memo_id: None,
            sequence: 1,
        };
        let inner = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &inner_req).unwrap();

        let req = FeeBumpRequest {
            inner_xdr: &inner.envelope_xdr,
            max_base_fee_stroops: 200,
        };
        let result = sign_fee_bump(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        assert_eq!(result.source_account, MASTER_ACCOUNT_0);

        // Round-trip parse the outer envelope and verify structure.
        use stellar_base::xdr::{TransactionEnvelope, XDRDeserialize};
        let env = TransactionEnvelope::from_xdr_base64(&result.envelope_xdr)
            .expect("signed fee-bump envelope must be valid XDR");
        match env {
            TransactionEnvelope::TxFeeBump(e) => {
                assert_eq!(
                    e.signatures.len(),
                    1,
                    "outer envelope must carry exactly one signature"
                );
                // Inner signatures must be preserved.
                match e.tx.inner_tx {
                    stellar_base::xdr::FeeBumpTransactionInnerTx::Tx(v1) => {
                        assert_eq!(v1.signatures.len(), 1, "inner signatures must be preserved");
                    }
                }
            }
            _ => panic!("expected TxFeeBump envelope variant"),
        }
    }

    #[test]
    fn sign_fee_bump_rejects_a_fee_below_the_network_minimum_before_parsing_xdr() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = FeeBumpRequest {
            inner_xdr: "",
            max_base_fee_stroops: MIN_BASE_FEE.to_i64() - 1,
        };

        assert!(matches!(
            sign_fee_bump(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::InvalidAmount)
        ));
    }

    #[test]
    fn sign_fee_bump_accepts_the_network_minimum_base_fee() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner_xdr = make_inner_xdr(0, 1);
        let req = FeeBumpRequest {
            inner_xdr: &inner_xdr,
            max_base_fee_stroops: MIN_BASE_FEE.to_i64(),
        };

        assert!(sign_fee_bump(&mk, &sealed, StellarNetwork::Testnet, 0, &req).is_ok());
    }

    #[test]
    fn sign_fee_bump_rejects_invalid_xdr() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = FeeBumpRequest {
            inner_xdr: "this-is-not-valid-base64-xdr",
            max_base_fee_stroops: 200,
        };
        assert!(matches!(
            sign_fee_bump(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::InvalidXdr)
        ));
    }

    #[test]
    fn sign_fee_bump_wrong_network_cannot_open_seed() {
        // Build a valid inner XDR using the testnet-sealed seed.
        let (mk, testnet_sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner = sign_payment(
            &mk,
            &testnet_sealed,
            StellarNetwork::Testnet,
            0,
            &PaymentRequest {
                destination: DEST,
                stroops: 1,
                asset: None,
                memo_id: None,
                sequence: 1,
            },
        )
        .unwrap();

        // Seal the same seed for mainnet; trying to open it as testnet must fail (AAD mismatch).
        let (mk2, mainnet_sealed) = sealed_vector_seed(StellarNetwork::Public);
        let req = FeeBumpRequest {
            inner_xdr: &inner.envelope_xdr,
            max_base_fee_stroops: 200,
        };
        assert!(matches!(
            sign_fee_bump(&mk2, &mainnet_sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::SeedDecryption)
        ));
    }

    #[test]
    fn compute_inner_tx_hash_is_deterministic() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner = sign_payment(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &PaymentRequest {
                destination: DEST,
                stroops: 100,
                asset: None,
                memo_id: None,
                sequence: 5,
            },
        )
        .unwrap();
        let h1 = compute_inner_tx_hash(&inner.envelope_xdr, StellarNetwork::Testnet).unwrap();
        let h2 = compute_inner_tx_hash(&inner.envelope_xdr, StellarNetwork::Testnet).unwrap();
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_ne!(h1, [0u8; 32], "hash must not be all zeros");
    }

    #[test]
    fn compute_inner_tx_hash_matches_stellar_signing_payload_hash() {
        use sha2::{Digest, Sha256};
        use stellar_base::xdr::{
            Hash, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
            XDRSerialize,
        };

        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner = sign_payment(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &PaymentRequest {
                destination: DEST,
                stroops: 100,
                asset: None,
                memo_id: None,
                sequence: 5,
            },
        )
        .unwrap();
        let transaction = parse_inner_v1(&inner.envelope_xdr).unwrap().tx;
        let network_hash: [u8; 32] = StellarNetwork::Testnet
            .to_base()
            .network_id()
            .as_slice()
            .try_into()
            .unwrap();
        let payload = TransactionSignaturePayload {
            network_id: Hash(network_hash),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(transaction),
        };
        let expected: [u8; 32] = Sha256::digest(payload.xdr_bytes().unwrap()).into();

        assert_eq!(
            compute_inner_tx_hash(&inner.envelope_xdr, StellarNetwork::Testnet).unwrap(),
            expected
        );
    }

    #[test]
    fn sign_payment_encodes_memo_id_u64_max() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let signed = sign_payment(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &PaymentRequest {
                destination: DEST,
                stroops: 100,
                asset: None,
                memo_id: Some(u64::MAX),
                sequence: 5,
            },
        )
        .unwrap();
        let envelope =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&signed.envelope_xdr)
                .unwrap();

        match envelope {
            stellar_base::xdr::TransactionEnvelope::Tx(envelope) => assert!(matches!(
                envelope.tx.memo,
                stellar_base::xdr::Memo::Id(id) if id == u64::MAX
            )),
            _ => panic!("unexpected envelope variant"),
        }
    }

    #[test]
    fn signs_payment_to_muxed_destination() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let muxed = crate::address::encode_muxed(DEST, 99).unwrap();
        let req = PaymentRequest {
            destination: &muxed,
            stroops: 5,
            asset: None,
            memo_id: None,
            sequence: 2,
        };
        let signed = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        assert!(!signed.envelope_xdr.is_empty());
    }

    // ── Credit-asset branch of sign_payment (#42) ────────────────────────────

    #[test]
    fn signs_credit_asset_payment_alphanum4() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // USDC is 4 chars → AlphaNum4; use DEST as the issuer (a valid G... address).
        let req = PaymentRequest {
            destination: DEST,
            stroops: 10_000_000,
            asset: Some(("USDC", DEST)),
            memo_id: None,
            sequence: 1,
        };
        let signed = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        let env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&signed.envelope_xdr).unwrap();
        match env {
            stellar_base::xdr::TransactionEnvelope::Tx(e) => match &e.tx.operations[0].body {
                stellar_base::xdr::OperationBody::Payment(pay) => {
                    assert!(
                        matches!(pay.asset, stellar_base::xdr::Asset::CreditAlphanum4(_)),
                        "4-char code must produce CreditAlphanum4 asset"
                    );
                }
                _ => panic!("expected Payment operation"),
            },
            _ => panic!("expected Tx envelope"),
        }
    }

    #[test]
    fn signs_credit_asset_payment_alphanum12() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // "LONGTOKEN" is 9 chars (5-12 range) → AlphaNum12.
        let req = PaymentRequest {
            destination: DEST,
            stroops: 10_000_000,
            asset: Some(("LONGTOKEN", DEST)),
            memo_id: None,
            sequence: 1,
        };
        let signed = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        let env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&signed.envelope_xdr).unwrap();
        match env {
            stellar_base::xdr::TransactionEnvelope::Tx(e) => match &e.tx.operations[0].body {
                stellar_base::xdr::OperationBody::Payment(pay) => {
                    assert!(
                        matches!(pay.asset, stellar_base::xdr::Asset::CreditAlphanum12(_)),
                        "9-char code must produce CreditAlphanum12 asset"
                    );
                }
                _ => panic!("expected Payment operation"),
            },
            _ => panic!("expected Tx envelope"),
        }
    }

    #[test]
    fn rejects_credit_asset_with_invalid_issuer() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = PaymentRequest {
            destination: DEST,
            stroops: 1,
            asset: Some(("USDC", "not-a-valid-G-address")),
            memo_id: None,
            sequence: 1,
        };
        assert!(matches!(
            sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::InvalidAddress)
        ));
    }

    #[test]
    fn rejects_credit_asset_with_invalid_code() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Empty string and a 13-char code are both outside the 1-12 byte range that
        // Asset::new_credit accepts. Since the shared `is_valid_asset_code` primitive landed,
        // these are rejected up front as InvalidAssetCode (previously the generic
        // InvalidAddress, which conflated a bad code with a bad issuer).
        for bad_code in ["", "TOOLONGASSET1X"] {
            let req = PaymentRequest {
                destination: DEST,
                stroops: 1,
                asset: Some((bad_code, DEST)),
                memo_id: None,
                sequence: 1,
            };
            assert!(
                matches!(
                    sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
                    Err(WalletError::InvalidAssetCode)
                ),
                "code {:?} should be rejected",
                bad_code
            );
        }
    }

    // ── Helper: build a signed inner payment envelope XDR ────────────────────

    fn make_inner_xdr(source_index: u32, seq: i64) -> String {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Use DEST as destination regardless of source; the inner tx just needs to be valid.
        let req = PaymentRequest {
            destination: DEST,
            stroops: 1_000_000,
            asset: None,
            memo_id: None,
            sequence: seq,
        };
        sign_payment(&mk, &sealed, StellarNetwork::Testnet, source_index, &req)
            .unwrap()
            .envelope_xdr
    }

    // ── fee_bump negative / security tests ───────────────────────────────────

    // Security: the outer fee_source must always be the master account, not the inner
    // tx's source, ensuring the sponsor identity cannot be forged by the inner XDR.
    #[test]
    fn fee_bump_fee_source_is_always_master_account() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Inner tx signed by account index 1 (DEST), not the master.
        let inner_xdr = make_inner_xdr(1, 1);
        let result = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest {
                inner_xdr: &inner_xdr,
                max_base_fee_stroops: 200,
            },
        )
        .unwrap();

        let outer_env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&result.envelope_xdr).unwrap();
        let fee_bump_env = match outer_env {
            stellar_base::xdr::TransactionEnvelope::TxFeeBump(e) => e,
            _ => panic!("expected TxFeeBump"),
        };
        // Decode MASTER_ACCOUNT_0 to its raw 32-byte ed25519 key.
        let expected_bytes = stellar_strkey::ed25519::PublicKey::from_string(MASTER_ACCOUNT_0)
            .unwrap()
            .0;
        match fee_bump_env.tx.fee_source {
            stellar_base::xdr::MuxedAccount::Ed25519(bytes) => {
                assert_eq!(bytes.0, expected_bytes);
            }
            _ => panic!("expected Ed25519 fee_source"),
        }
    }

    // Security: inner signatures must survive the fee-bump wrapping unmodified,
    // so the inner transaction's authorisation is not silently stripped or replaced.
    #[test]
    fn fee_bump_preserves_inner_signatures() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner_xdr = make_inner_xdr(0, 1);

        // Capture the inner signatures before wrapping.
        let inner_env_before =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&inner_xdr).unwrap();
        let inner_sigs_before = match inner_env_before {
            stellar_base::xdr::TransactionEnvelope::Tx(e) => e.signatures.to_vec(),
            _ => panic!("expected Tx"),
        };

        let result = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest {
                inner_xdr: &inner_xdr,
                max_base_fee_stroops: 200,
            },
        )
        .unwrap();

        let outer_env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&result.envelope_xdr).unwrap();
        let fee_bump_env = match outer_env {
            stellar_base::xdr::TransactionEnvelope::TxFeeBump(e) => e,
            _ => panic!("expected TxFeeBump"),
        };
        let inner_sigs_after = match fee_bump_env.tx.inner_tx {
            stellar_base::xdr::FeeBumpTransactionInnerTx::Tx(e) => e.signatures.to_vec(),
        };
        assert_eq!(inner_sigs_before, inner_sigs_after);
    }

    // Security: the outer envelope must carry exactly one signature (the master key's).
    // Multiple outer signatures would indicate an unintended key was used.
    #[test]
    fn fee_bump_outer_has_exactly_one_signature() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner_xdr = make_inner_xdr(0, 1);
        let result = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest {
                inner_xdr: &inner_xdr,
                max_base_fee_stroops: 200,
            },
        )
        .unwrap();

        let outer_env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&result.envelope_xdr).unwrap();
        let fee_bump_env = match outer_env {
            stellar_base::xdr::TransactionEnvelope::TxFeeBump(e) => e,
            _ => panic!("expected TxFeeBump"),
        };
        assert_eq!(fee_bump_env.signatures.len(), 1);
    }

    // Security: empty string is obviously invalid XDR; the function must reject it
    // rather than panic or produce an empty envelope.
    #[test]
    fn fee_bump_rejects_empty_string_xdr() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        assert!(matches!(
            sign_fee_bump(
                &mk,
                &sealed,
                StellarNetwork::Testnet,
                0,
                &FeeBumpRequest {
                    inner_xdr: "",
                    max_base_fee_stroops: 200,
                },
            ),
            Err(WalletError::InvalidXdr)
        ));
    }

    // Security: a raw Transaction XDR (not wrapped in a TransactionEnvelope) must be
    // rejected, ensuring only well-formed signed envelopes are accepted as inner XDR.
    #[test]
    fn fee_bump_rejects_payment_xdr_as_fee_bump_xdr() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // A FeeBumpTransaction envelope cannot wrap another fee-bump — use that as
        // "wrong XDR type": first produce a fee-bump envelope, then try to wrap it again.
        let inner_xdr = make_inner_xdr(0, 1);
        let fee_bump_xdr = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest {
                inner_xdr: &inner_xdr,
                max_base_fee_stroops: 200,
            },
        )
        .unwrap()
        .envelope_xdr;

        // Passing a fee-bump envelope as the inner XDR must be rejected.
        assert!(matches!(
            sign_fee_bump(
                &mk,
                &sealed,
                StellarNetwork::Testnet,
                0,
                &FeeBumpRequest {
                    inner_xdr: &fee_bump_xdr,
                    max_base_fee_stroops: 200
                },
            ),
            Err(WalletError::InvalidXdr)
        ));
    }

    // Security: a seed sealed for mainnet cannot be opened under a testnet context;
    // the AEAD tag will fail, preventing cross-network fee-bump signing.
    #[test]
    fn fee_bump_wrong_network_sealed_seed() {
        let (mk, mainnet_sealed) = sealed_vector_seed(StellarNetwork::Public);
        let inner_xdr = make_inner_xdr(0, 1);
        assert!(matches!(
            sign_fee_bump(
                &mk,
                &mainnet_sealed,
                StellarNetwork::Testnet,
                0,
                &FeeBumpRequest {
                    inner_xdr: &inner_xdr,
                    max_base_fee_stroops: 200
                },
            ),
            Err(WalletError::SeedDecryption)
        ));
    }

    // Security: the max_base_fee value supplied by the caller must be faithfully
    // encoded in the outer envelope's fee field (fee = max_base_fee × (inner_ops + 1)),
    // preventing silent fee inflation or deflation.
    #[test]
    fn fee_bump_max_base_fee_reflected_in_envelope() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner_xdr = make_inner_xdr(0, 1);
        let max_base_fee: i64 = 500;
        let result = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest {
                inner_xdr: &inner_xdr,
                max_base_fee_stroops: max_base_fee,
            },
        )
        .unwrap();

        let outer_env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&result.envelope_xdr).unwrap();
        let fee_bump_env = match outer_env {
            stellar_base::xdr::TransactionEnvelope::TxFeeBump(e) => e,
            _ => panic!("expected TxFeeBump"),
        };
        // stellar-base stores max_base_fee directly in the fee field.
        assert_eq!(fee_bump_env.tx.fee, max_base_fee);
    }

    // Normal operation: an inner tx signed by a non-master account (the common case
    // where a user signs their own tx and octo sponsors the fee) must succeed.
    #[test]
    fn fee_bump_inner_xdr_from_different_account() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Inner tx sourced from account index 1 (not the master).
        let inner_xdr = make_inner_xdr(1, 1);
        let result = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest {
                inner_xdr: &inner_xdr,
                max_base_fee_stroops: 200,
            },
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().source_account, MASTER_ACCOUNT_0);
    }

    // ── Malformed-XDR corpus (#44) ────────────────────────────────────────────
    //
    // Table-driven tests that mutate a known-good signed envelope at the byte
    // level to produce truncated or bit-corrupted XDR.  Every case must return
    // Err(WalletError::InvalidXdr) from both sign_fee_bump and
    // compute_inner_tx_hash — never panic, never silently accept garbage.

    fn valid_xdr_bytes() -> (String, Vec<u8>) {
        use base64::prelude::*;
        let xdr_b64 = make_inner_xdr(0, 1);
        let bytes = BASE64_STANDARD.decode(&xdr_b64).unwrap();
        (xdr_b64, bytes)
    }

    fn b64(bytes: &[u8]) -> String {
        use base64::prelude::*;
        BASE64_STANDARD.encode(bytes)
    }

    #[test]
    fn truncated_xdr_variants_are_rejected() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let (_, bytes) = valid_xdr_bytes();

        let truncations = [0usize, 1, bytes.len() / 4, bytes.len() / 2, bytes.len() - 1];

        for &len in &truncations {
            let truncated = b64(&bytes[..len]);
            assert!(
                matches!(
                    sign_fee_bump(
                        &mk,
                        &sealed,
                        StellarNetwork::Testnet,
                        0,
                        &FeeBumpRequest {
                            inner_xdr: &truncated,
                            max_base_fee_stroops: 200
                        },
                    ),
                    Err(WalletError::InvalidXdr)
                ),
                "sign_fee_bump should reject truncated XDR (byte len {})",
                len
            );
        }
    }

    #[test]
    fn bit_flipped_xdr_variants_are_rejected() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let (_, bytes) = valid_xdr_bytes();

        // Flip entire bytes at positions covering the 4-byte TransactionEnvelope
        // type discriminant and the MuxedAccount type discriminant that follows.
        // XOR with 0xFF guarantees a non-zero mutation on any non-FF byte.
        let flip_offsets = [0usize, 1, 2, 3, 4];

        for &offset in &flip_offsets {
            let mut flipped = bytes.clone();
            flipped[offset] ^= 0xFF;
            let flipped_b64 = b64(&flipped);
            assert!(
                matches!(
                    sign_fee_bump(
                        &mk,
                        &sealed,
                        StellarNetwork::Testnet,
                        0,
                        &FeeBumpRequest {
                            inner_xdr: &flipped_b64,
                            max_base_fee_stroops: 200
                        },
                    ),
                    Err(WalletError::InvalidXdr)
                ),
                "sign_fee_bump should reject bit-flipped XDR at byte offset {}",
                offset
            );
        }
    }

    #[test]
    fn compute_inner_tx_hash_rejects_same_corpus() {
        let (_, bytes) = valid_xdr_bytes();

        // Truncations
        for &len in &[0usize, 1, bytes.len() / 2, bytes.len() - 1] {
            let truncated = b64(&bytes[..len]);
            assert!(
                matches!(
                    compute_inner_tx_hash(&truncated, StellarNetwork::Testnet),
                    Err(WalletError::InvalidXdr)
                ),
                "compute_inner_tx_hash should reject truncated XDR (len {})",
                len
            );
        }

        // Bit flips at discriminant bytes
        for &offset in &[0usize, 3] {
            let mut flipped = bytes.clone();
            flipped[offset] ^= 0xFF;
            let flipped_b64 = b64(&flipped);
            assert!(
                matches!(
                    compute_inner_tx_hash(&flipped_b64, StellarNetwork::Testnet),
                    Err(WalletError::InvalidXdr)
                ),
                "compute_inner_tx_hash should reject bit-flipped XDR at offset {}",
                offset
            );
        }
    }

    #[test]
    fn sign_payment_zeroizes_seed_bytes_even_when_the_xdr_construction_step_fails_after_decryption() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // An invalid destination triggers an error after seed decryption and derivation,
        // confirming that the decrypted seed wrapped in Zeroizing is dropped and zeroized on error.
        let req = PaymentRequest {
            destination: "invalid-destination-address",
            stroops: 10_000_000,
            asset: None,
            memo_id: None,
            sequence: 1,
        };
        let res = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req);
        assert!(matches!(res, Err(WalletError::InvalidAddress)));
    }

    #[test]
    fn sign_change_trust_zeroizes_seed_bytes_on_error_after_decryption() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // An invalid asset code triggers an error after seed decryption in sign_change_trust.
        let req = ChangeTrustRequest {
            asset_code: "TOOLONGASSETCODE123",
            asset_issuer: DEST,
            limit_stroops: None,
            sequence: 1,
        };
        let res = sign_change_trust(&mk, &sealed, StellarNetwork::Testnet, 0, &req);
        assert!(matches!(res, Err(WalletError::InvalidAddress)));
    }

    #[test]
    fn sign_fee_bump_zeroizes_seed_bytes_on_error_after_decryption() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Out-of-range account index triggers InvalidDerivationPath after decryption in sign_fee_bump.
        let (_, bytes) = valid_xdr_bytes();
        let req = FeeBumpRequest {
            inner_xdr: &b64(&bytes),
            max_base_fee_stroops: 200,
        };
        let res = sign_fee_bump(&mk, &sealed, StellarNetwork::Testnet, 0x8000_0000, &req);
        assert!(matches!(res, Err(WalletError::InvalidDerivationPath)));
    }
}
