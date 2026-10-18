//! Core of `octo-migrate-keys`: re-seal every sealed wallet seed from `old_key` to `new_key`.
//!
//! Split from `main.rs` so the interruption-safety tests can drive the exact production loop.
//!
//! ## Which rows need work
//!
//! Every record is tagged `SCHEME_V1` whichever key sealed it, so the scheme tag cannot say
//! whether a row is already rotated. AES-GCM authentication can: a row that opens under
//! `new_key` is done and is skipped; anything else is opened under `old_key` and re-sealed.
//! A row that opens under neither aborts the run — it needs an operator, not a silent skip.
//!
//! ## Interruption safety
//!
//! Each row is written by one `UPDATE` of all four sealed fields (`Store::reseal_wallet`), so an
//! interrupted run leaves every row wholly old or wholly new. Re-running resumes: rotated rows
//! open under `new_key` and are skipped.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use octo_crypto::{open, reseal, SealedSeed, MASTER_KEY_LEN, SCHEME_V1};
use octo_store::Store;
use uuid::Uuid;

/// Totals from one run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Rows re-sealed under the new key by this run.
    pub migrated: usize,
    /// Rows already on the new key (or changed concurrently) and left untouched.
    pub skipped: usize,
}

/// Re-seal every sealed wallet from `old_key` to `new_key`, `batch_size` rows per page.
///
/// `before_write` runs after a row is re-sealed in memory and before it is persisted — the
/// window a crash would hit. Production passes a no-op; tests use it to inject a failure there.
pub async fn migrate(
    store: &Store,
    old_key: &[u8; MASTER_KEY_LEN],
    new_key: &[u8; MASTER_KEY_LEN],
    batch_size: i64,
    mut before_write: impl FnMut(Uuid) -> Result<()>,
) -> Result<Summary> {
    let mut summary = Summary::default();
    let mut after_id: Option<Uuid> = None;

    loop {
        let batch = store
            .list_sealed_wallets(batch_size, after_id)
            .await
            .context("list_sealed_wallets")?;
        let Some(last) = batch.last() else { break };
        after_id = Some(last.id);
        tracing::info!(batch_len = batch.len(), "processing batch");

        for wallet in &batch {
            // Client-custody wallets hold no server-side seed; only sealed rows are rotated.
            let (Some(ciphertext), Some(nonce), Some(salt)) = (
                wallet.sealed_ciphertext.as_ref(),
                wallet.sealed_nonce.as_ref(),
                wallet.sealed_salt.as_ref(),
            ) else {
                continue;
            };
            let scheme = wallet.sealed_scheme.unwrap_or(SCHEME_V1 as i16);
            let sealed = SealedSeed::from_parts_with_scheme(
                ciphertext.clone(),
                nonce,
                salt,
                u8::try_from(scheme).context("sealed_scheme out of range")?,
            )
            .with_context(|| format!("from_parts wallet {}", wallet.id))?;
            // Context is the network string bound into the AEAD AAD (e.g. "octo:mainnet").
            let context = format!("octo:{}", wallet.network);

            // Already rotated (or old == new on a current-scheme row): nothing to do.
            if open(new_key, &sealed, context.as_bytes()).is_ok() {
                summary.skipped += 1;
                continue;
            }

            let new_sealed = reseal(old_key, new_key, &sealed, context.as_bytes())
                .with_context(|| format!("wallet {} opens under neither key", wallet.id))?;

            before_write(wallet.id)?;

            let updated = store
                .reseal_wallet(
                    wallet.id,
                    &new_sealed.ciphertext,
                    &new_sealed.nonce,
                    &new_sealed.salt,
                    i16::from(new_sealed.scheme),
                    ciphertext,
                )
                .await
                .with_context(|| format!("reseal_wallet DB update for {}", wallet.id))?;
            if updated {
                summary.migrated += 1;
            } else {
                summary.skipped += 1;
            }
        }
    }
    Ok(summary)
}
