# Operational Runbook: Master Key Rotation (`bin/migrate-keys`)

## Overview

The `octo-migrate-keys` binary is an offline, resumable operator tool designed to re-seal HD master seeds under a new master key or cipher scheme without service downtime.

### When to Run
- Routine cryptographic key rotation (e.g. quarterly or annual key roll).
- Secret incident mitigation (when the existing `MASTER_KEY` may have been exposed).
- Cipher upgrade (re-encrypting stored seeds under updated cipher parameters or schemes, such as `SCHEME_V1`).

## Architecture & Dual-Key Window

During rotation, `octo-server` supports a dual-key configuration:
- `MASTER_KEY`: The current/old 32-byte base64-encoded key used to decrypt existing seeds.
- `MASTER_KEY_NEXT`: The target/new 32-byte base64-encoded key.

While `octo-migrate-keys` is executing, both keys must remain available to running API instances. Each row records its `sealed_scheme`, allowing decryption routines to identify the applicable key. Once `octo-migrate-keys` finishes with 0 remaining rows, `MASTER_KEY_NEXT` can be promoted to `MASTER_KEY` and the old key decommissioned.

## Pre-flight Checks

1. **Database Connectivity and Backup**:
   Verify access to the production PostgreSQL cluster and take a snapshot:
   ```bash
   pg_dump -Fc "$DATABASE_URL" > "octo_backup_$(date +%Y%m%d_%H%M%S).dump"
   ```
2. **Key Material Validation**:
   Ensure keys are valid 32-byte base64 strings:
   ```bash
   [ "$(echo -n "$MASTER_KEY" | base64 -d | wc -c)" -eq 32 ] || echo "Invalid MASTER_KEY length"
   [ "$(echo -n "$MASTER_KEY_NEXT" | base64 -d | wc -c)" -eq 32 ] || echo "Invalid MASTER_KEY_NEXT length"
   ```
3. **Database Migration Status**:
   Ensure the database schema is up-to-date (`Store::migrate` is also executed at binary startup).
4. **Current Unmigrated Row Count**:
   Query rows currently requiring migration:
   ```sql
   SELECT sealed_scheme, count(*) 
   FROM wallets 
   WHERE sealed_ciphertext IS NOT NULL 
   GROUP BY sealed_scheme;
   ```

## Invocations

### Full Key Rotation
```bash
MASTER_KEY="<old_base64_32_bytes>" \
MASTER_KEY_NEXT="<new_base64_32_bytes>" \
DATABASE_URL="postgres://user:pass@localhost:5432/octo" \
cargo run --release -p octo-migrate-keys -- --batch-size 100
```

### Cipher Upgrade Only (Same Key)
If `MASTER_KEY_NEXT` is omitted, the tool defaults to re-sealing under `MASTER_KEY`:
```bash
MASTER_KEY="<base64_32_bytes>" \
DATABASE_URL="postgres://user:pass@localhost:5432/octo" \
cargo run --release -p octo-migrate-keys -- --batch-size 100
```

## Expected Healthy Log Output

```text
2026-09-26T22:00:00.000Z  INFO octo_migrate_keys: batch_size=100 same_key=false octo-migrate-keys starting
2026-09-26T22:00:00.150Z  INFO octo_migrate_keys: batch_len=100 after_id=None processing batch
2026-09-26T22:00:00.420Z DEBUG octo_migrate_keys: wallet_id=9d14... migrated
...
2026-09-26T22:00:01.200Z  INFO octo_migrate_keys: batch_len=42 after_id=Some(a4f1...) processing batch
2026-09-26T22:00:01.350Z  INFO octo_migrate_keys: total_migrated=142 total_skipped=0 migration complete — 0 wallets remaining on old scheme
```

## Store Method Implementation Reference

The migration tool is backed by two primary methods in [`crates/store`](file:///c:/Users/DELL/OneDrive/Desktop/drip/Octo-Protocol-6/crates/store):
- [`Store::list_wallets_needing_reseal`](file:///c:/Users/DELL/OneDrive/Desktop/drip/Octo-Protocol-6/crates/store/src/wallets.rs):
  Fetches batches of wallets where `sealed_scheme != target_scheme` ordered by `id ASC`, paginating via `after_id`.
- [`Store::reseal_wallet`](file:///c:/Users/DELL/OneDrive/Desktop/drip/Octo-Protocol-6/crates/store/src/wallets.rs):
  Atomically updates `sealed_ciphertext`, `sealed_nonce`, `sealed_salt`, and `sealed_scheme` with an optimistic concurrency guard (`WHERE id = $1 AND sealed_scheme = $expected_old_scheme`).
- Cryptographic re-encryption is executed via `octo_crypto::reseal` in [`crates/crypto`](file:///c:/Users/DELL/OneDrive/Desktop/drip/Octo-Protocol-6/crates/crypto).

## Monitoring Progress

Operators can monitor ongoing execution in another terminal:
```sql
SELECT 
    count(*) FILTER (WHERE sealed_scheme = 1) AS migrated_v1,
    count(*) FILTER (WHERE sealed_scheme != 1) AS remaining_old
FROM wallets 
WHERE sealed_ciphertext IS NOT NULL;
```

## Interruption Recovery & Rollback

### Resuming an Interrupted Run
- **Safe Interruption**: The tool operates using atomic per-wallet updates and paginated batches.
- If stopped (SIGINT, network timeout, process termination), simply re-run the same command.
- Wallets already migrated will have `sealed_scheme == target_scheme` and will not be re-processed by `Store::list_wallets_needing_reseal`.

### Rollback Procedure
- If rotation needs to be reverted before decommissioning the old key:
  Swap the values of `MASTER_KEY` and `MASTER_KEY_NEXT`:
  ```bash
  MASTER_KEY="<new_base64_32_bytes>" \
  MASTER_KEY_NEXT="<old_base64_32_bytes>" \
  DATABASE_URL="postgres://user:pass@localhost:5432/octo" \
  cargo run --release -p octo-migrate-keys -- --batch-size 100
  ```
