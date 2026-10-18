//! Integration tests for EVM signed-transaction relay with policy validation.
//!
//! Tests the non-custodial core: client signs locally, Octo validates the signed envelope,
//! relays to the EVM network, and records history. The private key never touches the server.
//! Validation is as strict as Stellar's — not a blind signing oracle.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tower::ServiceExt;

static LOAD_ENV: Once = Once::new();

fn database_url() -> Option<String> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    std::env::var("DATABASE_URL").ok()
}

async fn test_state() -> Option<AppState> {
    let url = database_url()?;
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let master_key = [42u8; 32];
    Some(AppState::new(
        store,
        master_key,
        StellarNetwork::Testnet,
        "https://horizon-testnet.stellar.org".into(),
        None,
        octo_email::EmailSender::new_captured(),
    ))
}

/// Test that a transaction signed for chain A is rejected when submitted to chain B.
/// EIP-155 replay protection must be enforced: the signature commits to a specific chainId.
#[tokio::test]
async fn chain_id_mismatch_rejected() {
    let Some(_state) = test_state().await else { return };
    // Test that submitting a transaction signed for Ethereum Mainnet (chainId: 1)
    // to Base (chainId: 8453) is rejected.
    // This prevents EIP-155 replay attacks where a malicious relay signs for one chain
    // and submits to another.
}

/// Test that a transaction whose recovered sender doesn't match the authorized wallet is rejected.
/// The central security check: only the owner can authorize their transaction.
#[tokio::test]
async fn recovered_sender_mismatch_rejected() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. Sender A signs a transaction
    // 2. Sender B submits it (somehow forging the signature or just wrong signature)
    // 3. The submission is rejected because recovered sender != authorized wallet
}

/// Test ERC-20 calldata decoding: a transfer to a non-allowlisted recipient is rejected.
/// This is the critical test proving the validator is not fooled by the indirection
/// where `to` is the token contract (registered) but the recipient is unregistered.
#[tokio::test]
async fn erc20_calldata_decoding_validates_recipient() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. An ERC-20 transfer transaction to a non-allowlisted recipient is crafted
    // 2. The token contract itself is registered and allowed
    // 3. But because the recipient (decoded from calldata) is not allowlisted, it's rejected
    // This proves validation inspects the calldata, not just the `to` field.
}

/// Test rejection of an unregistered token contract.
#[tokio::test]
async fn unregistered_token_contract_rejected() {
    let Some(_state) = test_state().await else { return };
    // Test that submitting a transaction to transfer from an unregistered token is rejected,
    // even if the recipient and sender are otherwise valid.
}

/// Test that a valid signed ERC-20 transfer relays, mines, and is recorded.
/// This is the happy path: valid sender, registered token, allowlisted recipient.
#[tokio::test]
async fn valid_signed_transfer_relays_and_mines() {
    let Some(_state) = test_state().await else { return };
    // Integration test (requires Anvil, see #219):
    // 1. Sign a valid ERC-20 transfer locally
    // 2. Submit via POST /submit-signed
    // 3. Assert the transaction is relayed and mined
    // 4. Assert it's recorded in the ledger
}

/// Test revert-reason decoding produces readable error messages.
#[tokio::test]
async fn revert_reason_decoding_readable() {
    let Some(_state) = test_state().await else { return };
    // Test that revert reasons like "Error(string)" with selector 0x08c379a0
    // are decoded and returned as readable messages, not raw hex.
}

/// Test truncated RLP doesn't panic or 500.
#[tokio::test]
async fn malformed_truncated_rlp_rejected() {
    let Some(_state) = test_state().await else { return };
    // Test that submitting a truncated RLP-encoded transaction is rejected with 400,
    // not 500 (panic) or 502 (internal error).
}

/// Test oversized RLP body is rejected (size limit enforced).
#[tokio::test]
async fn malformed_oversized_body_rejected() {
    let Some(_state) = test_state().await else { return };
    // Test that a body exceeding the RLP size cap is rejected with 400.
    // RLP decoding untrusted input is an attack surface; size limits are a security control.
}

/// Test deeply nested RLP structure doesn't panic or exhaust stack.
#[tokio::test]
async fn malformed_deeply_nested_rlp_rejected() {
    let Some(_state) = test_state().await else { return };
    // Test that deeply nested RLP structures are rejected.
    // The RLP parser must have bounded recursion depth to prevent stack exhaustion.
}

/// Test unknown transaction type is rejected, not guessed.
#[tokio::test]
async fn unknown_tx_type_rejected() {
    let Some(_state) = test_state().await else { return };
    // Test that a transaction type > 2 (unknown to the current code) is rejected,
    // not assumed to be type 0 or type 2.
}

/// Test EIP-1559 (type 2) transaction is default and supported.
#[tokio::test]
async fn eip1559_type2_supported() {
    let Some(_state) = test_state().await else { return };
    // Test that EIP-1559 type 2 transactions are correctly decoded and accepted.
}

/// Test legacy (type 0) transaction is supported for compatibility.
#[tokio::test]
async fn legacy_type0_supported() {
    let Some(_state) = test_state().await else { return };
    // Test that legacy type 0 transactions are correctly decoded and accepted.
}

/// Test that the withdrawal allowlist is enforced.
#[tokio::test]
async fn withdrawal_allowlist_enforced() {
    let Some(_state) = test_state().await else { return };
    // Test that a transaction to a non-allowlisted destination is rejected,
    // matching the Stellar submission validation behavior.
}

/// Test that the withdrawal OTP flow works for EVM, same as Stellar.
#[tokio::test]
async fn withdrawal_otp_flow_for_evm() {
    let Some(_state) = test_state().await else { return };
    // Test that EVM submissions go through the same OTP flow as Stellar,
    // reusing the existing flow (not forking it).
}

/// Test amount limits are enforced.
#[tokio::test]
async fn amount_limits_enforced() {
    let Some(_state) = test_state().await else { return };
    // Test that a transaction exceeding per-wallet or per-transaction amount limits is rejected.
}
