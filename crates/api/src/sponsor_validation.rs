//! XDR validation for sponsored transactions.
//!
//! Enforces the operation-type allowlist (Payment, PathPaymentStrictSend/Receive) and rejects
//! self-sponsorship (inner tx source == master account). Validation is pure — no I/O — so it can
//! be unit-tested independently of the database or Horizon.

use crate::error::ApiError;
use stellar_base::xdr::{MuxedAccount, OperationBody, TransactionEnvelope, XDRDeserialize};
use stellar_strkey::ed25519::PublicKey as StrkeyPK;

/// Operation types that are permitted inside a sponsored fee-bump transaction.
const ALLOWED_OP_TYPES: &[&str] = &[
    "Payment",
    "PathPaymentStrictSend",
    "PathPaymentStrictReceive",
];

/// Parse `inner_xdr` and reject any operation not in [`ALLOWED_OP_TYPES`] or where the inner
/// transaction's source account is the same as `master_account_g`.
///
/// Must be called **before** `sign_fee_bump` so that the signing path never sees forbidden ops.
pub fn validate_inner_xdr(inner_xdr: &str, master_account_g: &str) -> Result<(), ApiError> {
    let env = TransactionEnvelope::from_xdr_base64(inner_xdr)
        .map_err(|_| ApiError::BadRequest("transaction_xdr is not valid base64 XDR".into()))?;

    let inner_v1 = match env {
        TransactionEnvelope::Tx(v1) => v1,
        _ => {
            return Err(ApiError::BadRequest(
                "transaction_xdr must be a v1 TransactionEnvelope".into(),
            ))
        }
    };

    // Reject self-sponsorship: the inner tx source must not be the master wallet.
    if source_matches_master(&inner_v1.tx.source_account, master_account_g) {
        return Err(ApiError::BadRequest(
            "inner transaction source must not be the master account".into(),
        ));
    }

    // Validate every operation against the allowlist.
    for op in inner_v1.tx.operations.iter() {
        if !is_op_allowed(&op.body) {
            let name = op_type_name(&op.body);
            return Err(ApiError::BadRequest(format!(
                "op_not_allowed: operation type '{name}' is not allowed in a sponsored transaction; \
                 allowed types: {}",
                ALLOWED_OP_TYPES.join(", ")
            )));
        }
    }

    Ok(())
}

/// Return `true` when the inner tx source matches the master account's public key.
fn source_matches_master(source: &MuxedAccount, master_g: &str) -> bool {
    let Ok(master_pk) = StrkeyPK::from_string(master_g) else {
        return false;
    };
    match source {
        MuxedAccount::Ed25519(uint256) => uint256.0 == master_pk.0,
        MuxedAccount::MuxedEd25519(muxed) => muxed.ed25519.0 == master_pk.0,
    }
}

fn is_op_allowed(body: &OperationBody) -> bool {
    matches!(
        body,
        OperationBody::Payment(_)
            | OperationBody::PathPaymentStrictReceive(_)
            | OperationBody::PathPaymentStrictSend(_)
    )
}

pub(crate) fn op_type_name(body: &OperationBody) -> &'static str {
    match body {
        OperationBody::CreateAccount(_) => "CreateAccount",
        OperationBody::Payment(_) => "Payment",
        OperationBody::PathPaymentStrictReceive(_) => "PathPaymentStrictReceive",
        OperationBody::ManageSellOffer(_) => "ManageSellOffer",
        OperationBody::CreatePassiveSellOffer(_) => "CreatePassiveSellOffer",
        OperationBody::SetOptions(_) => "SetOptions",
        OperationBody::ChangeTrust(_) => "ChangeTrust",
        OperationBody::AllowTrust(_) => "AllowTrust",
        OperationBody::AccountMerge(_) => "AccountMerge",
        OperationBody::Inflation => "Inflation",
        OperationBody::ManageData(_) => "ManageData",
        OperationBody::BumpSequence(_) => "BumpSequence",
        OperationBody::ManageBuyOffer(_) => "ManageBuyOffer",
        OperationBody::PathPaymentStrictSend(_) => "PathPaymentStrictSend",
        OperationBody::CreateClaimableBalance(_) => "CreateClaimableBalance",
        OperationBody::ClaimClaimableBalance(_) => "ClaimClaimableBalance",
        OperationBody::BeginSponsoringFutureReserves(_) => "BeginSponsoringFutureReserves",
        OperationBody::EndSponsoringFutureReserves => "EndSponsoringFutureReserves",
        OperationBody::RevokeSponsorship(_) => "RevokeSponsorship",
        OperationBody::Clawback(_) => "Clawback",
        OperationBody::ClawbackClaimableBalance(_) => "ClawbackClaimableBalance",
        OperationBody::SetTrustLineFlags(_) => "SetTrustLineFlags",
        OperationBody::LiquidityPoolDeposit(_) => "LiquidityPoolDeposit",
        OperationBody::LiquidityPoolWithdraw(_) => "LiquidityPoolWithdraw",
        OperationBody::InvokeHostFunction(_) => "InvokeHostFunction",
        OperationBody::ExtendFootprintTtl(_) => "ExtendFootprintTtl",
        OperationBody::RestoreFootprint(_) => "RestoreFootprint",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octo_wallet_core::{import_wallet, sign_payment, PaymentRequest, StellarNetwork};
    use stellar_base::xdr::{
        AllowTrustOp, Asset, BeginSponsoringFutureReservesOp, BumpSequenceOp, ChangeTrustOp,
        ClaimClaimableBalanceOp, ClawbackClaimableBalanceOp, ClawbackOp, CreateAccountOp,
        CreateClaimableBalanceOp, CreatePassiveSellOfferOp, ExtendFootprintTtlOp,
        InvokeHostFunctionOp, LiquidityPoolDepositOp, LiquidityPoolWithdrawOp, ManageBuyOfferOp,
        ManageDataOp, ManageSellOfferOp, Memo, MuxedAccount, Operation, OperationBody,
        PathPaymentStrictReceiveOp, PathPaymentStrictSendOp, PaymentOp, Preconditions,
        RestoreFootprintOp, RevokeSponsorshipOp, SequenceNumber, SetOptionsOp, SetTrustLineFlagsOp,
        Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256,
        XDRSerialize,
    };

    const VECTOR_MK: [u8; 32] = [7u8; 32];
    const VECTOR_MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    /// Account 0 of the vector seed — used as inner-tx source in payment_xdr().
    const MASTER_ACCOUNT_0: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
    /// Account 1 of the vector seed — used as destination (different from account 0).
    const DEST: &str = "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX";

    /// A valid payment XDR signed by account 0 of the vector mnemonic.
    fn payment_xdr() -> String {
        let provisioned =
            import_wallet(
                &VECTOR_MK,
                StellarNetwork::Testnet,
                VECTOR_MNEMONIC,
                MASTER_ACCOUNT_0,
            )
            .unwrap();
        sign_payment(
            &VECTOR_MK,
            &provisioned.sealed,
            StellarNetwork::Testnet,
            0,
            &PaymentRequest {
                destination: DEST,
                stroops: 100,
                asset: None,
                memo_id: None,
                sequence: 1,
            },
        )
        .unwrap()
        .envelope_xdr
    }

    /// Build a minimal (unsigned) `TransactionEnvelope::Tx` with the given operations and source.
    fn make_envelope(ops: Vec<OperationBody>, source_bytes: [u8; 32]) -> String {
        let operations: Vec<Operation> = ops
            .into_iter()
            .map(|body| Operation {
                source_account: None,
                body,
            })
            .collect();
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source_bytes)),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: operations.try_into().unwrap(),
            ext: TransactionExt::V0,
        };
        let envelope = TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        };
        TransactionEnvelope::Tx(envelope).xdr_base64().unwrap()
    }

    #[test]
    fn allows_payment_op() {
        // Source is MASTER_ACCOUNT_0; pass a different account as the sponsor master
        // so the self-sponsorship guard does not fire.
        let xdr = payment_xdr();
        assert!(validate_inner_xdr(&xdr, DEST).is_ok());
    }

    #[test]
    fn rejects_account_merge() {
        let xdr = make_envelope(
            vec![OperationBody::AccountMerge(MuxedAccount::Ed25519(Uint256(
                [1u8; 32],
            )))],
            [2u8; 32], // source != master
        );
        let result = validate_inner_xdr(&xdr, MASTER_ACCOUNT_0);
        assert!(
            matches!(result, Err(ApiError::BadRequest(ref m)) if m.contains("AccountMerge")),
            "expected AccountMerge rejection, got: {result:?}"
        );
    }

    #[test]
    fn rejects_set_options() {
        // Use Inflation (no inner data) as a simpler stand-in for any forbidden op.
        let xdr = make_envelope(vec![OperationBody::Inflation], [3u8; 32]);
        let result = validate_inner_xdr(&xdr, MASTER_ACCOUNT_0);
        assert!(
            matches!(result, Err(ApiError::BadRequest(ref m)) if m.contains("Inflation")),
            "expected forbidden-op rejection, got: {result:?}"
        );
    }

    #[test]
    fn rejects_self_sponsorship() {
        // payment_xdr() is signed FROM MASTER_ACCOUNT_0; passing the same address as master
        // triggers the self-sponsorship guard.
        let xdr = payment_xdr();
        let result = validate_inner_xdr(&xdr, MASTER_ACCOUNT_0);
        assert!(
            matches!(result, Err(ApiError::BadRequest(ref m)) if m.contains("master")),
            "expected self-sponsorship rejection, got: {result:?}"
        );
    }

    #[test]
    fn rejects_malformed_xdr() {
        let result = validate_inner_xdr("this-is-not-valid-xdr!!!", DEST);
        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }

    /// Every `OperationBody` variant that is *not* in [`ALLOWED_OP_TYPES`], paired with its
    /// expected `op_type_name`. Field values are minimal/arbitrary (mostly `Default::default()`)
    /// — only the operation *kind* is under test here, never the semantic validity of its
    /// payload, so defaulted inner fields (zeroed amounts, empty vecs, `None` options, etc.) are
    /// intentional and sufficient.
    ///
    /// All 24 non-allowlisted variants are covered; none were awkward enough to skip — every
    /// inner XDR struct in this crate's `stellar-xdr` version derives `Default` when the `alloc`
    /// feature is enabled (it is, via `std`), including deeply-nested ones like
    /// `RevokeSponsorshipOp`'s default `LedgerKey` and `InvokeHostFunctionOp`'s default
    /// `HostFunction`.
    fn forbidden_op_cases() -> Vec<(&'static str, OperationBody)> {
        vec![
            (
                "CreateAccount",
                OperationBody::CreateAccount(CreateAccountOp::default()),
            ),
            (
                "ManageSellOffer",
                OperationBody::ManageSellOffer(ManageSellOfferOp::default()),
            ),
            (
                "CreatePassiveSellOffer",
                OperationBody::CreatePassiveSellOffer(CreatePassiveSellOfferOp::default()),
            ),
            (
                "SetOptions",
                OperationBody::SetOptions(SetOptionsOp::default()),
            ),
            (
                "ChangeTrust",
                OperationBody::ChangeTrust(ChangeTrustOp::default()),
            ),
            (
                "AllowTrust",
                OperationBody::AllowTrust(AllowTrustOp::default()),
            ),
            (
                "AccountMerge",
                OperationBody::AccountMerge(MuxedAccount::default()),
            ),
            ("Inflation", OperationBody::Inflation),
            (
                "ManageData",
                OperationBody::ManageData(ManageDataOp::default()),
            ),
            (
                "BumpSequence",
                OperationBody::BumpSequence(BumpSequenceOp::default()),
            ),
            (
                "ManageBuyOffer",
                OperationBody::ManageBuyOffer(ManageBuyOfferOp::default()),
            ),
            (
                "CreateClaimableBalance",
                OperationBody::CreateClaimableBalance(CreateClaimableBalanceOp::default()),
            ),
            (
                "ClaimClaimableBalance",
                OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp::default()),
            ),
            (
                "BeginSponsoringFutureReserves",
                OperationBody::BeginSponsoringFutureReserves(
                    BeginSponsoringFutureReservesOp::default(),
                ),
            ),
            (
                "EndSponsoringFutureReserves",
                OperationBody::EndSponsoringFutureReserves,
            ),
            (
                "RevokeSponsorship",
                OperationBody::RevokeSponsorship(RevokeSponsorshipOp::default()),
            ),
            ("Clawback", OperationBody::Clawback(ClawbackOp::default())),
            (
                "ClawbackClaimableBalance",
                OperationBody::ClawbackClaimableBalance(ClawbackClaimableBalanceOp::default()),
            ),
            (
                "SetTrustLineFlags",
                OperationBody::SetTrustLineFlags(SetTrustLineFlagsOp::default()),
            ),
            (
                "LiquidityPoolDeposit",
                OperationBody::LiquidityPoolDeposit(LiquidityPoolDepositOp::default()),
            ),
            (
                "LiquidityPoolWithdraw",
                OperationBody::LiquidityPoolWithdraw(LiquidityPoolWithdrawOp::default()),
            ),
            (
                "InvokeHostFunction",
                OperationBody::InvokeHostFunction(InvokeHostFunctionOp::default()),
            ),
            (
                "ExtendFootprintTtl",
                OperationBody::ExtendFootprintTtl(ExtendFootprintTtlOp::default()),
            ),
            (
                "RestoreFootprint",
                OperationBody::RestoreFootprint(RestoreFootprintOp::default()),
            ),
        ]
    }

    #[test]
    fn every_non_allowlisted_operation_kind_is_rejected() {
        for (name, body) in forbidden_op_cases() {
            // Source != master so the self-sponsorship guard never masks the op-type rejection.
            let xdr = make_envelope(vec![body], [4u8; 32]);
            let result = validate_inner_xdr(&xdr, MASTER_ACCOUNT_0);
            assert!(
                matches!(result, Err(ApiError::BadRequest(ref m)) if m.contains(name)),
                "expected '{name}' to be rejected by name, got: {result:?}"
            );
        }
    }

    #[test]
    fn all_three_allowlisted_operation_kinds_are_individually_accepted() {
        let destination = MuxedAccount::Ed25519(Uint256([9u8; 32]));
        let cases: Vec<OperationBody> = vec![
            OperationBody::Payment(PaymentOp {
                destination: destination.clone(),
                asset: Asset::Native,
                amount: 100,
            }),
            OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                send_asset: Asset::Native,
                send_amount: 100,
                destination: destination.clone(),
                dest_asset: Asset::Native,
                dest_min: 1,
                path: vec![].try_into().unwrap(),
            }),
            OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                send_asset: Asset::Native,
                send_max: 100,
                destination,
                dest_asset: Asset::Native,
                dest_amount: 1,
                path: vec![].try_into().unwrap(),
            }),
        ];
        for body in cases {
            let name = op_type_name(&body);
            // Source != master: correctly sourced, not self-sponsoring.
            let xdr = make_envelope(vec![body], [5u8; 32]);
            let result = validate_inner_xdr(&xdr, MASTER_ACCOUNT_0);
            assert!(
                result.is_ok(),
                "expected '{name}' to be accepted, got: {result:?}"
            );
        }
    }
}
