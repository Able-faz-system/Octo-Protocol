//! `octo-migrate-keys` — offline, resumable master-key rotation tool.
//!
//! ## Purpose
//!
//! Re-seals every wallet's HD seed under a new master key (and/or cipher scheme) without
//! requiring a maintenance window. The tool operates in batches so it can be safely interrupted
//! and re-run; already-migrated wallets are skipped automatically.
//!
//! ## Dual-key rotation window
//!
//! During a rotation, **both** the old and the new master key must be available to the running
//! `octo-server` process so it can open seeds that have not yet been migrated. Once this tool
//! reports 0 wallets remaining, the old key can be removed from the environment.
//!
//! Configure the two keys via environment variables:
//!
//! ```text
//! MASTER_KEY      = <base64-encoded current/old key>   # the key octo-server currently uses
//! MASTER_KEY_NEXT = <base64-encoded new key>           # the key to rotate to
//! ```
//!
//! When `MASTER_KEY_NEXT` is absent the tool defaults to `MASTER_KEY` for both old and new,
//! which is still useful as a cipher-upgrade path (re-seal all rows under the latest scheme
//! even if the key itself doesn't change).
//!
//! ## Idempotency
//!
//! A row that already opens under the new key is skipped, and `reseal_wallet` only writes when
//! the row still holds the ciphertext that was read (compare-and-swap). Re-running the tool
//! against a fully-migrated database is safe and produces 0 updates. See `lib.rs`.
//!
//! ## Rollback
//!
//! Old-key and new-key records can coexist indefinitely: during the rotation window the server
//! tries `MASTER_KEY_NEXT` first and falls back to `MASTER_KEY` (AES-GCM authentication tells
//! them apart). To abort, stop the tool. Rolling back a completed rotation means running the tool
//! again with the old and new keys swapped.
//!
//! ## Usage
//!
//! ```bash
//! # Rotate from MASTER_KEY to MASTER_KEY_NEXT, batch of 100 at a time:
//! MASTER_KEY=<old_b64> MASTER_KEY_NEXT=<new_b64> \
//!   cargo run -p octo-migrate-keys -- --batch-size 100
//!
//! # Re-seal all rows under the current key/scheme (cipher upgrade only):
//! MASTER_KEY=<b64> \
//!   cargo run -p octo-migrate-keys -- --batch-size 100
//! ```
//!
//! ## Checkpoint (resuming an interrupted run)
//!
//! After every fully-processed batch the tool writes the last wallet id it handled to a
//! checkpoint file, so a crash or Ctrl-C resumes from the last completed batch instead of
//! re-scanning the whole table.
//!
//! - **Location:** `migrate-keys.checkpoint` in the working directory, or the path in
//!   `MIGRATE_KEYS_CHECKPOINT`.
//! - **Contents:** a fingerprint of the `(MASTER_KEY, MASTER_KEY_NEXT)` pair (a SHA-256 over
//!   the keys — no key material) and the `after_id` cursor. A checkpoint written for a
//!   different key pair is refused rather than silently skipping rows.
//! - **Lifecycle:** removed automatically on clean completion.
//! - **Forcing a full re-run:** stop the tool, then delete the file (`rm migrate-keys.checkpoint`).
//!   This is always safe — the idempotency guard below makes re-scanned rows no-ops. Do not
//!   hand-edit the cursor: moving it forward skips rows that were never migrated.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use base64::Engine;
use octo_crypto::{master_key_from_slice, reseal_with_account_id, MASTER_KEY_LEN, SCHEME_V2};
use octo_store::Store;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Maximum rows per batch (hard cap, configurable via CLI).
const DEFAULT_BATCH_SIZE: i64 = 100;

/// Checkpoint file used when `MIGRATE_KEYS_CHECKPOINT` is unset.
const DEFAULT_CHECKPOINT_PATH: &str = "migrate-keys.checkpoint";

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    init_tracing();

    let cfg = Config::from_env()?;

    tracing::info!(
        batch_size = cfg.batch_size,
        same_key = (cfg.old_key == cfg.new_key),
        "octo-migrate-keys starting"
    );

    let store = Store::connect(&cfg.database_url)
        .await
        .context("connect to database")?;
    store.migrate().await.context("run migrations")?;

    let fingerprint = key_pair_fingerprint(&cfg.old_key, &cfg.new_key);
    let mut after_id = read_checkpoint(&cfg.checkpoint_path, &fingerprint)?;
    match after_id {
        Some(id) => tracing::info!(
            checkpoint = %cfg.checkpoint_path.display(),
            after_id = %id,
            "resuming from checkpoint"
        ),
        None => tracing::info!(
            checkpoint = %cfg.checkpoint_path.display(),
            "no checkpoint found; starting from the beginning"
        ),
    }
    let mut batches_completed = 0usize;
    let mut total_migrated = 0usize;
    let mut total_skipped = 0usize;

    loop {
        let batch = store
            .list_wallets_needing_reseal(SCHEME_V2 as i16, cfg.batch_size, after_id)
            .await
            .context("list_wallets_needing_reseal")?;

        if batch.is_empty() {
            break;
        }

        tracing::info!(
            batch_len  = batch.len(),
            after_id   = ?after_id,
            "processing batch"
        );

        for wallet in &batch {
            // Client-custody wallets hold no server-side seed (the user's key never reaches us),
            // so there is nothing to reseal. Only rows that actually carry sealed material —
            // legacy server-custody wallets and gas-tank fee accounts — are rotated.
            let (Some(ciphertext), Some(nonce), Some(salt), Some(scheme)) = (
                wallet.sealed_ciphertext.as_ref(),
                wallet.sealed_nonce.as_ref(),
                wallet.sealed_salt.as_ref(),
                wallet.sealed_scheme,
            ) else {
                tracing::debug!(wallet_id = %wallet.id, "skipping wallet with no sealed seed");
                continue;
            };

            // Build the SealedSeed from the current DB values.
            let sealed = octo_crypto::SealedSeed::from_parts_with_scheme(
                ciphertext.clone(),
                nonce,
                salt,
                u8::try_from(scheme).context("sealed scheme must fit in an unsigned byte")?,
            )
            .with_context(|| format!("from_parts wallet {}", wallet.id))?;

            // Context is the network string bound into the AEAD AAD (e.g. "octo:mainnet").
            let context = format!("octo:{}", wallet.network);
            let account_id = wallet
                .gas_tank_account_g
                .as_deref()
                .unwrap_or(&wallet.stellar_account_g);

            // Reseal into the account-bound scheme (Zeroizing throughout).
            let new_sealed = reseal_with_account_id(
                &cfg.old_key,
                &cfg.new_key,
                &sealed,
                context.as_bytes(),
                account_id,
            )
                .with_context(|| format!("reseal wallet {}", wallet.id))?;

            // Atomically swap the DB record. The idempotency guard (expected_old_scheme)
            // means a concurrent run that already migrated this wallet is a safe no-op.
            let updated = store
                .reseal_wallet(
                    wallet.id,
                    &new_sealed.ciphertext,
                    &new_sealed.nonce,
                    &new_sealed.salt,
                    SCHEME_V2 as i16,
                    scheme,
                )
                .await
                .with_context(|| format!("reseal_wallet DB update for {}", wallet.id))?;

            if updated {
                total_migrated += 1;
                tracing::debug!(wallet_id = %wallet.id, "migrated");
            } else {
                total_skipped += 1;
                tracing::debug!(wallet_id = %wallet.id, "skipped (already migrated by concurrent runner)");
            }
        }

        // Advance the cursor to the last wallet in this batch (ids are ordered ASC), and persist
        // it only now that every row in the batch is done, so a resume never skips a row.
        after_id = batch.last().map(|w| w.id);
        if let Some(id) = after_id {
            write_checkpoint(&cfg.checkpoint_path, &fingerprint, id)?;
        }
        batches_completed += 1;
        tracing::info!(
            batches_completed,
            total_migrated,
            total_skipped,
            after_id = ?after_id,
            "batch complete"
        );
    }

    remove_checkpoint(&cfg.checkpoint_path)?;
    tracing::info!(
        batches_completed,
        total_migrated,
        total_skipped,
        "migration complete — 0 wallets remaining on old scheme; checkpoint removed"
    );
    Ok(())
}

/// Identify the key pair a checkpoint belongs to without writing any key material to disk.
fn key_pair_fingerprint(old_key: &[u8; MASTER_KEY_LEN], new_key: &[u8; MASTER_KEY_LEN]) -> String {
    let mut h = Sha256::new();
    h.update(b"octo-migrate-keys/checkpoint/v1");
    h.update(old_key);
    h.update(new_key);
    hex::encode(h.finalize())
}

/// Read the resume cursor, refusing a malformed checkpoint or one from a different key pair.
fn read_checkpoint(path: &Path, fingerprint: &str) -> Result<Option<Uuid>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("read checkpoint {}", path.display()));
        }
    };
    let mut stored_fingerprint = None;
    let mut stored_after_id = None;
    for line in contents.lines() {
        match line.split_once('=') {
            Some(("fingerprint", v)) => stored_fingerprint = Some(v.trim()),
            Some(("after_id", v)) => stored_after_id = Some(v.trim()),
            _ => {}
        }
    }
    let (Some(stored_fingerprint), Some(stored_after_id)) = (stored_fingerprint, stored_after_id)
    else {
        anyhow::bail!(
            "checkpoint {} is malformed; delete it to restart from the beginning",
            path.display()
        );
    };
    if stored_fingerprint != fingerprint {
        anyhow::bail!(
            "checkpoint {} was written for a different MASTER_KEY/MASTER_KEY_NEXT pair; \
             delete it to restart from the beginning",
            path.display()
        );
    }
    let id = Uuid::parse_str(stored_after_id).with_context(|| {
        format!(
            "checkpoint {} has an invalid after_id; delete it to restart from the beginning",
            path.display()
        )
    })?;
    Ok(Some(id))
}

/// Persist the cursor via write-then-rename so a crash mid-write never leaves a torn file.
fn write_checkpoint(path: &Path, fingerprint: &str, after_id: Uuid) -> Result<()> {
    let tmp = path.with_extension("checkpoint.tmp");
    std::fs::write(&tmp, format!("fingerprint={fingerprint}\nafter_id={after_id}\n"))
        .with_context(|| format!("write checkpoint {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replace checkpoint {}", path.display()))
}

/// Delete the checkpoint after a clean run; a missing file is fine.
fn remove_checkpoint(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("remove checkpoint {}", path.display()))
        }
        _ => Ok(()),
    }
}

struct Config {
    database_url: String,
    old_key: [u8; MASTER_KEY_LEN],
    new_key: [u8; MASTER_KEY_LEN],
    batch_size: i64,
    checkpoint_path: PathBuf,
}

impl Config {
    fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;

        let old_key = decode_key("MASTER_KEY")?;

        // MASTER_KEY_NEXT is optional: if absent, re-seal under the same key (cipher upgrade only).
        let new_key = if std::env::var("MASTER_KEY_NEXT").is_ok() {
            decode_key("MASTER_KEY_NEXT")?
        } else {
            tracing::info!(
                "MASTER_KEY_NEXT not set; re-sealing under MASTER_KEY (cipher/scheme upgrade only)"
            );
            old_key
        };

        // --batch-size N from argv, or DEFAULT_BATCH_SIZE.
        let batch_size = std::env::args()
            .skip_while(|a| a != "--batch-size")
            .nth(1)
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(DEFAULT_BATCH_SIZE);
        // LIMIT 0 returns an empty page, which the loop would misread as "migration complete".
        if batch_size <= 0 {
            anyhow::bail!("--batch-size must be a positive integer");
        }

        let checkpoint_path = std::env::var("MIGRATE_KEYS_CHECKPOINT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CHECKPOINT_PATH));

        Ok(Config {
            database_url,
            old_key,
            new_key,
            batch_size,
            checkpoint_path,
        })
    }
}

fn decode_key(env_var: &str) -> Result<[u8; MASTER_KEY_LEN]> {
    let b64 = std::env::var(env_var).with_context(|| format!("{env_var} is required"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .with_context(|| format!("{env_var} is not valid base64"))?;
    master_key_from_slice(&raw).map_err(|_| anyhow::anyhow!("{env_var} must be exactly 32 bytes"))
}

fn init_tracing() {
    let filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "info,octo_migrate_keys=debug".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .init();
}
