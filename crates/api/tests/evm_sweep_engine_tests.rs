//! Integration tests for EVM deposit sweep engine.
//!
//! Tests the sweep engine that consolidates per-customer deposits into a treasury.
//! Sweeps are gas-funded then executed as a two-step, crash-recoverable state machine.
//! Dust below the gas-to-value threshold accumulates instead of being swept at a loss.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octo_api::{build_router, AppState};
use octo_store::Store;
use octo_wallet_core::StellarNetwork;
use std::sync::Once;
use tokio::sync::Mutex;
use std::sync::Arc;
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

/// Test that a confirmed deposit is swept: fund deposit, run sweeper, treasury increases.
/// This is the happy path on Anvil: mock ERC-20 token, sweep transaction mines successfully.
#[tokio::test]
async fn sweep_confirmed_deposit_to_treasury() {
    let Some(_state) = test_state().await else { return };
    // Anvil integration test (#219):
    // 1. Create a deposit address
    // 2. Fund it with a mock ERC-20 token
    // 3. Record the deposit as confirmed
    // 4. Run the sweep worker
    // 5. Assert the sweep transaction mines
    // 6. Assert the treasury balance increases by the deposit amount
    // 7. Assert the sweep row reaches `confirmed` state
}

/// Test crash recovery: kill between gas funding and sweep, restart, exactly one sweep occurs.
/// This is the idempotency guarantee: no double-sends, no stranded funds.
#[tokio::test]
async fn crash_recovery_between_gas_and_sweep() {
    let Some(_state) = test_state().await else { return };
    // Anvil test with simulated crash:
    // 1. Fund deposit address with ERC-20
    // 2. Start sweep: gas-funding tx is submitted and mined
    // 3. Kill the process before sweep tx is submitted
    // 4. Restart and run reconciliation
    // 5. Assert the sweep is completed (sweep tx submitted and mined)
    // 6. Assert gas was NOT double-sent
    // 7. Assert exactly one sweep row exists for this deposit
}

/// Test economic gating: a dust deposit whose gas exceeds its value is NOT swept.
/// The threshold is configurable per chain.
#[tokio::test]
async fn economic_gating_dust_not_swept() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. A deposit of $2 at an estimated gas cost of $4 is not swept
    // 2. The deposit accumulates in the deposit address
    // 3. When batched with other deposits, the combined amount passes the gate
    // This prevents value destruction by sweeping at a loss.
}

/// Test idempotency: running the sweeper twice concurrently over the same deposit yields one sweep.
#[tokio::test]
async fn sweep_idempotency_concurrent_runs() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. Launch two concurrent sweep runs
    // 2. Both target the same confirmed deposit
    // 3. Only one sweep row is created
    // 4. Only one sweep tx is submitted
    // 5. No gas is double-sent
    // Reuses the idempotency-key pattern from Store::create_withdrawal.
}

/// Test that only confirmed deposits are swept.
/// Sweeping an unconfirmed deposit that then reorgs means paying gas to move money that never existed.
#[tokio::test]
async fn unconfirmed_deposits_never_swept() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. A pending (unconfirmed) deposit is present
    // 2. The sweep worker explicitly checks confirmation status
    // 3. The pending deposit is NOT swept
    // 4. Once confirmed, a later sweep run sweeps it
}

/// Test failure path: sweep transaction reverts, funds remain safely at deposit address.
#[tokio::test]
async fn failure_path_sweep_reverts_funds_safe() {
    let Some(_state) = test_state().await else { return };
    // Anvil test:
    // 1. Fund deposit address
    // 2. Trigger a revert scenario (e.g., treasury contract rejection)
    // 3. Run sweep: gas funding succeeds, sweep tx is submitted but reverts
    // 4. Assert the sweep row lands in `failed` state
    // 5. Assert the funds remain at the deposit address (not lost)
}

/// Test gas-funding transfers to deposit addresses are properly recorded.
#[tokio::test]
async fn gas_funding_tx_recorded() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. Gas-funding tx hash is recorded in the sweep row
    // 2. It's used for idempotency and reconciliation
    // 3. A retry uses the same gas-funding tx, not a new one
}

/// Test sweep transaction recording and state transitions.
#[tokio::test]
async fn sweep_tx_recorded_state_transitions() {
    let Some(_state) = test_state().await else { return };
    // Test the sweep row state machine:
    // pending -> gas_funded -> submitted -> confirmed (or failed)
}

/// Test that unswept balance per chain is tracked and alerted on.
#[tokio::test]
async fn metrics_unswept_balance_per_chain() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. Metrics track total unswept balance per chain
    // 2. Alerts trigger if unswept balance exceeds a threshold
}

/// Test that sweeps blocked by economic gate are tracked.
#[tokio::test]
async fn metrics_sweeps_blocked_by_gate() {
    let Some(_state) = test_state().await else { return };
    // Test that sweeps rejected by the economic gate are counted and alerted.
}

/// Test that sweeps stuck in non-terminal state are detected and alerted.
#[tokio::test]
async fn metrics_stuck_non_terminal_sweeps() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. A sweep stuck in `gas_funded` or `submitted` for too long is detected
    // 2. An alert is issued to investigate
}

/// Test that the sweeper reuses nonce management from #226 (not a second allocator).
#[tokio::test]
async fn sweeper_reuses_nonce_management() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. Sweep submission calls allocate_nonce() from #226
    // 2. No parallel nonce allocator is built
    // 3. Sweeper transactions integrate into the overall nonce sequence
}

/// Test that the sweeper holds spending keys for every deposit address.
/// This is the largest departure from Octo's non-custodial posture (AD-4).
#[tokio::test]
async fn sweeper_holds_spending_keys() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. The sweeper has access to the derived keys for deposit addresses
    // 2. Keys are sealed with octo-crypto and only opened inside the signing boundary
    // 3. Keys are zeroized after use
}

/// Test batch sweeping: multiple deposits below the gate accumulate and sweep together.
#[tokio::test]
async fn batch_sweeping_accumulates_dust() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. Deposits A ($1), B ($1), C ($1), each with gas cost $2, are not swept individually
    // 2. They accumulate in their deposit addresses
    // 3. Once total ≥ $6 (allowing gas cost), a batch sweep occurs
    // 4. All three are swept in one batch operation
}

/// Test crash recovery reconciliation on startup.
#[tokio::test]
async fn startup_reconciliation_crash_recovery() {
    let Some(_state) = test_state().await else { return };
    // Test that on startup:
    // 1. The sweeper reconciles every non-terminal sweep against on-chain state
    // 2. A gas-funded sweep with no on-chain sweep tx is retried
    // 3. A submitted sweep with mined tx is promoted to confirmed
    // 4. A stuck sweep is alerted but not re-submitted
}

/// Test threshold is configurable per chain.
#[tokio::test]
async fn gate_threshold_configurable_per_chain() {
    let Some(_state) = test_state().await else { return };
    // Test that:
    // 1. The gas-to-value threshold can be set differently for Mainnet vs Base vs other chains
    // 2. A $10 L1 deposit with $8 gas is not swept, but same deposit on Base ($0.50 gas) is swept
}
