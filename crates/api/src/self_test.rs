//! Boot-time crypto self-test (issue #441).
//!
//! A misconfigured master key or a broken entropy source must stop the server at startup, not
//! surface at the first sponsored transaction. Errors name the failing stage only, never bytes.

use crate::state::AppState;
use octo_crypto::{open_with_account_id, self_test, SealedSeed};

/// Run every startup check; `Err` carries an operator-facing reason and must abort boot.
pub async fn run(state: &AppState) -> Result<(), String> {
    // Canary round-trip + RNG sanity under each configured key.
    self_test(state.master_key()).map_err(|e| format!("MASTER_KEY: {e}"))?;
    if let Some(next) = state.master_key_next() {
        self_test(next).map_err(|e| format!("MASTER_KEY_NEXT: {e}"))?;
    }
    open_latest_sealed_row(state).await
}

/// Prove the configured key(s) open real data: a canary always opens under the key that sealed
/// it, so only a stored row can catch a key that is well-formed but simply wrong.
async fn open_latest_sealed_row(state: &AppState) -> Result<(), String> {
    let network = state.network();
    let Some(wallet) = state
        .store()
        .latest_sealed_wallet(network.as_str())
        .await
        .map_err(|e| format!("load a sealed wallet for the key check: {e}"))?
    else {
        tracing::info!("no sealed rows yet; stored-key check skipped");
        return Ok(());
    };

    let (Some(ciphertext), Some(nonce), Some(salt), Some(scheme)) = (
        wallet.sealed_ciphertext,
        wallet.sealed_nonce,
        wallet.sealed_salt,
        wallet.sealed_scheme,
    ) else {
        return Err(format!("wallet {} has incomplete sealed columns", wallet.id));
    };
    let scheme = u8::try_from(scheme)
        .map_err(|_| format!("wallet {} has out-of-range sealed_scheme", wallet.id))?;
    let sealed = SealedSeed::from_parts_with_scheme(ciphertext, &nonce, &salt, scheme)
        .map_err(|e| format!("wallet {} sealed seed is malformed: {e}", wallet.id))?;
    // Same account binding as bin/migrate-keys uses for V2 rows; ignored for V1.
    let account_id = wallet
        .gas_tank_account_g
        .as_deref()
        .unwrap_or(&wallet.stellar_account_g);

    // The plaintext is Zeroizing and dropped immediately; only success matters here.
    let opens = state.opening_keys().any(|key| {
        open_with_account_id(key, &sealed, network.crypto_context(), account_id).is_ok()
    });
    if !opens {
        return Err(format!(
            "configured master key(s) cannot open sealed wallet {} — wrong MASTER_KEY?",
            wallet.id
        ));
    }
    Ok(())
}
