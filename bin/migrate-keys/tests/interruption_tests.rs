//! Interruption-safety tests for the key-rotation reseal path (`octo_migrate_keys::migrate`).
//!
//! Requires Postgres via `DATABASE_URL` (loaded from `.env`); skipped with a message otherwise.
//! Each test runs in its own throwaway database so the whole wallets table is under its control.

use octo_crypto::{open, seal, SealedSeed, MASTER_KEY_LEN};
use octo_migrate_keys::{migrate, Summary};
use octo_store::{NewWallet, Store};
use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;

const OLD_KEY: [u8; MASTER_KEY_LEN] = [1u8; MASTER_KEY_LEN];
const NEW_KEY: [u8; MASTER_KEY_LEN] = [2u8; MASTER_KEY_LEN];
const CONTEXT: &[u8] = b"octo:testnet";
const WALLETS: usize = 12;
/// The injected crash hits the write of the Nth wallet (0-based), so N rows are already rotated.
const CRASH_AT: usize = 5;

/// A fresh, migrated database; returns its store and name (for dropping).
async fn fresh_store() -> Option<(Store, String, String)> {
    let _ = dotenvy::dotenv();
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("SKIPPED: DATABASE_URL is not set");
        return None;
    };
    let name = format!("octo_mk_{}", Uuid::new_v4().simple());
    let mut admin = PgConnection::connect(&url).await.expect("connect admin");
    admin
        .execute(format!(r#"CREATE DATABASE "{name}""#).as_str())
        .await
        .expect("create db");
    let base = url.split('?').next().unwrap();
    let db_url = format!("{}/{name}", base.rsplit_once('/').unwrap().0);
    let store = Store::connect(&db_url).await.expect("connect test db");
    store.migrate().await.expect("migrate");
    Some((store, url, name))
}

async fn drop_db(store: Store, admin_url: &str, name: &str) {
    drop(store);
    let mut admin = PgConnection::connect(admin_url)
        .await
        .expect("connect admin");
    let _ = admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#).as_str())
        .await;
}

/// Seed `WALLETS` wallets whose seeds are sealed under `OLD_KEY`; returns (id, plaintext).
async fn seed_wallets(store: &Store) -> Vec<(Uuid, Vec<u8>)> {
    let mut out = Vec::new();
    for i in 0..WALLETS {
        let secret = format!("seed-{i}-{}", Uuid::new_v4()).into_bytes();
        let sealed = seal(&OLD_KEY, &secret, CONTEXT).unwrap();
        let account = format!("G{}", Uuid::new_v4().simple());
        let w = store
            .create_wallet(NewWallet {
                network: "testnet",
                stellar_account_g: &account,
                sealed_ciphertext: &sealed.ciphertext,
                sealed_nonce: &sealed.nonce,
                sealed_salt: &sealed.salt,
                sealed_scheme: i16::from(sealed.scheme),
                label: None,
                user_id: None,
                description: None,
            })
            .await
            .unwrap();
        out.push((w.id, secret));
    }
    out
}

/// Which key a row's four sealed fields open under, asserting it is exactly one and that the
/// plaintext is intact — i.e. the row is wholly pre- or post-migration, never a mix.
async fn row_key(store: &Store, id: Uuid, secret: &[u8]) -> &'static str {
    let w = store.get_wallet(id).await.unwrap();
    let sealed = SealedSeed::from_parts_with_scheme(
        w.sealed_ciphertext.unwrap(),
        &w.sealed_nonce.unwrap(),
        &w.sealed_salt.unwrap(),
        u8::try_from(w.sealed_scheme.unwrap()).unwrap(),
    )
    .unwrap();
    let old = open(&OLD_KEY, &sealed, CONTEXT).ok();
    let new = open(&NEW_KEY, &sealed, CONTEXT).ok();
    match (old, new) {
        (Some(p), None) if p.as_slice() == secret => "old",
        (None, Some(p)) if p.as_slice() == secret => "new",
        _ => panic!("wallet {id} has mismatched sealed fields (opens under neither/both keys)"),
    }
}

/// Run `migrate` in its own task with a hook that panics on the `CRASH_AT`-th write — the moment
/// between re-sealing in memory and persisting, i.e. a process killed mid-batch.
async fn run_and_crash(store: &Store) {
    let store = store.clone();
    let handle = tokio::spawn(async move {
        let mut writes = 0;
        // Small batches so the crash lands mid-run, across batch boundaries.
        migrate(&store, &OLD_KEY, &NEW_KEY, 4, |_| {
            if writes == CRASH_AT {
                panic!("simulated crash mid-batch");
            }
            writes += 1;
            Ok(())
        })
        .await
    });
    assert!(handle.await.unwrap_err().is_panic(), "the run must crash");
}

#[tokio::test]
async fn interrupting_migrate_keys_mid_batch_never_leaves_a_wallet_row_with_mismatched_scheme_and_ciphertext(
) {
    let Some((store, admin_url, name)) = fresh_store().await else {
        return;
    };
    let wallets = seed_wallets(&store).await;

    run_and_crash(&store).await;

    let mut new = 0;
    for (id, secret) in &wallets {
        if row_key(&store, *id, secret).await == "new" {
            new += 1;
        }
    }
    assert_eq!(
        new, CRASH_AT,
        "exactly the rows written before the crash are rotated"
    );
    drop_db(store, &admin_url, &name).await;
}

#[tokio::test]
async fn a_second_clean_run_after_interruption_completes_the_remaining_wallets_correctly() {
    let Some((store, admin_url, name)) = fresh_store().await else {
        return;
    };
    let wallets = seed_wallets(&store).await;
    run_and_crash(&store).await;

    let summary = migrate(&store, &OLD_KEY, &NEW_KEY, 4, |_| Ok(()))
        .await
        .unwrap();
    assert_eq!(
        summary,
        Summary {
            migrated: WALLETS - CRASH_AT,
            skipped: CRASH_AT
        }
    );
    for (id, secret) in &wallets {
        assert_eq!(row_key(&store, *id, secret).await, "new");
    }

    // A third run is a no-op.
    let summary = migrate(&store, &OLD_KEY, &NEW_KEY, 4, |_| Ok(()))
        .await
        .unwrap();
    assert_eq!(summary.migrated, 0);
    drop_db(store, &admin_url, &name).await;
}
