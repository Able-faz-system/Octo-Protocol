//! Validation for client-signed transactions (the non-custodial submit path).
//!
//! The client holds its own key and signs locally; Octo only validates + submits. The rules are
//! the inverse of sponsorship: here the transaction source **must be** the wallet's own account
//! (you can only spend from the wallet you're authenticated for), the envelope must carry at
//! least one signature, and only wallet-scoped operation types are allowed. Validation is pure —
//! no I/O — so it can be unit-tested independently of the database or Horizon.

use crate::error::ApiError;
use stellar_base::xdr::{Asset, MuxedAccount, OperationBody, TransactionEnvelope, XDRDeserialize};
use stellar_strkey::ed25519::PublicKey as StrkeyPK;

/// Operation types a client-signed submission may contain.
const ALLOWED_OP_TYPES: &[&str] = &[
    "Payment",
    "PathPaymentStrictSend",
    "PathPaymentStrictReceive",
    "ChangeTrust",
];

/// A recordable summary of the first Payment operation (used for the history row). `None` when
/// the transaction contains no Payment (e.g. a trustline-only tx).
#[derive(Debug)]
pub struct PaymentSummary {
    pub destination: String,
    pub amount_stroops: i64,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
}

/// Parse and validate a client-signed envelope for `wallet_account_g`.
///
/// On success returns the optional [`PaymentSummary`] for history recording.
pub fn validate_signed_xdr(
    signed_xdr: &str,
    wallet_account_g: &str,
) -> Result<Option<PaymentSummary>, ApiError> {
    let env = TransactionEnvelope::from_xdr_base64(signed_xdr)
        .map_err(|_| ApiError::BadRequest("transaction_xdr is not valid base64 XDR".into()))?;

    let v1 = match env {
        TransactionEnvelope::Tx(v1) => v1,
        _ => {
            return Err(ApiError::BadRequest(
                "transaction_xdr must be a v1 TransactionEnvelope".into(),
            ))
        }
    };

    // The user must have actually signed it — Octo never adds a signature on this path.
    if v1.signatures.is_empty() {
        return Err(ApiError::BadRequest(
            "transaction_xdr carries no signatures; sign it client-side first".into(),
        ));
    }

    // The tx must spend from the wallet it is being submitted for — nothing else.
    if !source_matches(&v1.tx.source_account, wallet_account_g) {
        return Err(ApiError::BadRequest(
            "transaction source must be this wallet's account".into(),
        ));
    }

    let mut summary: Option<PaymentSummary> = None;
    for op in v1.tx.operations.iter() {
        // Per-operation source overrides could spend from another account Octo has no business
        // relaying; require ops to inherit the (already-checked) tx source.
        if let Some(op_source) = &op.source_account {
            if !source_matches(op_source, wallet_account_g) {
                return Err(ApiError::BadRequest(
                    "operation source must be this wallet's account".into(),
                ));
            }
        }
        match &op.body {
            OperationBody::Payment(p) => {
                if summary.is_none() {
                    let (asset_code, asset_issuer) = asset_parts(&p.asset);
                    summary = Some(PaymentSummary {
                        destination: muxed_to_string(&p.destination),
                        amount_stroops: p.amount,
                        asset_code,
                        asset_issuer,
                    });
                }
            }
            OperationBody::PathPaymentStrictSend(_)
            | OperationBody::PathPaymentStrictReceive(_)
            | OperationBody::ChangeTrust(_) => {}
            other => {
                return Err(ApiError::BadRequest(format!(
                    "op_not_allowed: operation type '{}' is not allowed in a client submission; \
                     allowed types: {}",
                    op_name(other),
                    ALLOWED_OP_TYPES.join(", ")
                )));
            }
        }
    }

    Ok(summary)
}

/// True when `source` is the same underlying ed25519 account as `account_g` (muxed or not).
fn source_matches(source: &MuxedAccount, account_g: &str) -> bool {
    let Ok(pk) = StrkeyPK::from_string(account_g) else {
        return false;
    };
    match source {
        MuxedAccount::Ed25519(uint256) => uint256.0 == pk.0,
        MuxedAccount::MuxedEd25519(muxed) => muxed.ed25519.0 == pk.0,
    }
}

/// Render a muxed account as its canonical strkey (`G…` or `M…`).
/// (`stellar_strkey` renders into a no-alloc `heapless::String`; convert to `std::String`.)
pub(crate) fn muxed_to_string(m: &MuxedAccount) -> String {
    match m {
        MuxedAccount::Ed25519(uint256) => StrkeyPK(uint256.0).to_string().as_str().to_owned(),
        MuxedAccount::MuxedEd25519(muxed) => stellar_strkey::ed25519::MuxedAccount {
            ed25519: muxed.ed25519.0,
            id: muxed.id,
        }
        .to_string()
        .as_str()
        .to_owned(),
    }
}

/// Split an XDR asset into (code, issuer) the way the store records them.
pub(crate) fn asset_parts(asset: &Asset) -> (String, Option<String>) {
    match asset {
        Asset::Native => ("native".to_string(), None),
        Asset::CreditAlphanum4(a) => (
            trimmed_code(&a.asset_code.0),
            Some(
                StrkeyPK(account_bytes(&a.issuer))
                    .to_string()
                    .as_str()
                    .to_owned(),
            ),
        ),
        Asset::CreditAlphanum12(a) => (
            trimmed_code(&a.asset_code.0),
            Some(
                StrkeyPK(account_bytes(&a.issuer))
                    .to_string()
                    .as_str()
                    .to_owned(),
            ),
        ),
    }
}

fn trimmed_code(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string()
}

fn account_bytes(id: &stellar_base::xdr::AccountId) -> [u8; 32] {
    let stellar_base::xdr::PublicKey::PublicKeyTypeEd25519(uint256) = &id.0;
    uint256.0
}

fn op_name(body: &OperationBody) -> &'static str {
    crate::sponsor_validation::op_type_name(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use octo_wallet_core::{import_wallet, sign_payment, PaymentRequest, StellarNetwork};
    use stellar_base::xdr::{
        Memo, MuxedAccount, Operation, OperationBody, Preconditions, SequenceNumber, Transaction,
        TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, XDRSerialize,
    };

    const VECTOR_MK: [u8; 32] = [7u8; 32];
    const VECTOR_MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    const WALLET_ACCOUNT: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
    const OTHER_ACCOUNT: &str = "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX";

    /// A valid payment XDR signed by the vector wallet (source == WALLET_ACCOUNT).
    fn signed_payment_xdr() -> String {
        let provisioned =
            import_wallet(
                &VECTOR_MK,
                StellarNetwork::Testnet,
                VECTOR_MNEMONIC,
                WALLET_ACCOUNT,
            )
            .unwrap();
        sign_payment(
            &VECTOR_MK,
            &provisioned.sealed,
            StellarNetwork::Testnet,
            0,
            &PaymentRequest {
                destination: OTHER_ACCOUNT,
                stroops: 250,
                asset: None,
                memo_id: None,
                sequence: 1,
            },
        )
        .unwrap()
        .envelope_xdr
    }

    fn envelope(ops: Vec<OperationBody>, source_g: &str, signed: bool) -> String {
        use stellar_base::xdr::{BytesM, DecoratedSignature, Signature, SignatureHint};
        let pk = StrkeyPK::from_string(source_g).unwrap();
        let operations: Vec<Operation> = ops
            .into_iter()
            .map(|body| Operation {
                source_account: None,
                body,
            })
            .collect();
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(pk.0)),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: operations.try_into().unwrap(),
            ext: TransactionExt::V0,
        };
        // A dummy signature is enough here: the API checks presence, Horizon checks validity.
        let signatures: Vec<DecoratedSignature> = if signed {
            let bytes: BytesM<64> = vec![0u8; 64].try_into().unwrap();
            vec![DecoratedSignature {
                hint: SignatureHint([0u8; 4]),
                signature: Signature(bytes),
            }]
        } else {
            vec![]
        };
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: signatures.try_into().unwrap(),
        })
        .xdr_base64()
        .unwrap()
    }

    #[test]
    fn accepts_signed_payment_from_wallet_and_summarizes() {
        let xdr = signed_payment_xdr();
        let summary = validate_signed_xdr(&xdr, WALLET_ACCOUNT).unwrap();
        let s = summary.expect("payment summary");
        assert_eq!(s.destination, OTHER_ACCOUNT);
        assert_eq!(s.amount_stroops, 250);
        assert_eq!(s.asset_code, "native");
        assert_eq!(s.asset_issuer, None);
    }

    #[test]
    fn rejects_wrong_source() {
        let xdr = signed_payment_xdr(); // source is WALLET_ACCOUNT
        let result = validate_signed_xdr(&xdr, OTHER_ACCOUNT);
        assert!(
            matches!(result, Err(ApiError::BadRequest(ref m)) if m.contains("source")),
            "expected wrong-source rejection, got: {result:?}"
        );
    }

    #[test]
    fn rejects_unsigned_envelope() {
        let xdr = envelope(vec![OperationBody::Inflation], WALLET_ACCOUNT, false);
        let result = validate_signed_xdr(&xdr, WALLET_ACCOUNT);
        assert!(
            matches!(result, Err(ApiError::BadRequest(ref m)) if m.contains("no signatures")),
            "expected unsigned rejection, got: {result:?}"
        );
    }

    #[test]
    fn rejects_disallowed_op() {
        let xdr = envelope(
            vec![OperationBody::AccountMerge(MuxedAccount::Ed25519(Uint256(
                [9u8; 32],
            )))],
            WALLET_ACCOUNT,
            true,
        );
        let result = validate_signed_xdr(&xdr, WALLET_ACCOUNT);
        assert!(
            matches!(result, Err(ApiError::BadRequest(ref m)) if m.contains("AccountMerge")),
            "expected AccountMerge rejection, got: {result:?}"
        );
    }

    #[test]
    fn allows_change_trust() {
        use stellar_base::xdr::{ChangeTrustAsset, ChangeTrustOp};
        let xdr = envelope(
            vec![OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::Native,
                limit: i64::MAX,
            })],
            WALLET_ACCOUNT,
            true,
        );
        let summary = validate_signed_xdr(&xdr, WALLET_ACCOUNT).unwrap();
        assert!(summary.is_none(), "trustline tx has no payment summary");
    }

    #[test]
    fn rejects_malformed_xdr() {
        let result = validate_signed_xdr("not-xdr-at-all!!!", WALLET_ACCOUNT);
        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }
}
