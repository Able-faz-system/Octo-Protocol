# Operational Runbook: Operation Index Backfill (`bin/backfill-operation-index`)

## Overview

The `octo-backfill-operation-index` binary is an operator tool designed to backfill historical deposit records in the `transactions` table. Early versions of deposit ingestion defaulted `operation_index` to `0` rather than extracting the true index from the Horizon Transaction Operation ID (`horizon_op_id` / TOID).

Correcting `operation_index` ensures that multi-operation transactions satisfy the `uq_tx_onchain` partial unique index on `(stellar_tx_hash, operation_index)`. For a full theoretical and database constraint safety analysis, see [docs/backfill-constraint-analysis.md](file:///c:/Users/DELL/OneDrive/Desktop/drip/Octo-Protocol-6/docs/backfill-constraint-analysis.md).

### When to Run
- Post-migration execution to update existing legacy deposits with accurate operation indices.
- Before enforcing strict schema constraints or auditing multi-operation deposit uniqueness.

## Pre-flight Checks

1. **Verify Database Connectivity & Snapshot**:
   ```bash
   pg_dump -Fc "$DATABASE_URL" -t transactions > "transactions_backup_$(date +%Y%m%d_%H%M%S).dump"
   ```
2. **Estimate Candidate Rows**:
   Identify transactions requiring updates (where TOID indicates index > 0 but stored index is 0):
   ```sql
   SELECT count(*) 
   FROM transactions 
   WHERE direction = 'deposit' 
     AND horizon_op_id IS NOT NULL 
     AND operation_index = 0 
     AND split_part(horizon_op_id, '-', 3) <> '0';
   ```
3. **Execute a Dry Run**:
   Run with `--dry-run` to preview planned updates without modifying any data.

## Invocations

### Dry Run (Non-destructive Preview)
```bash
DATABASE_URL="postgres://user:pass@localhost:5432/octo" \
  cargo run --release -p octo-backfill-operation-index -- --dry-run --batch-size 1000
```

### Canary Run (Limited Sample)
Process a small batch (e.g. 50 records) to verify live database behavior:
```bash
DATABASE_URL="postgres://user:pass@localhost:5432/octo" \
  cargo run --release -p octo-backfill-operation-index -- --limit 50 --batch-size 50
```

### Full Live Execution
```bash
DATABASE_URL="postgres://user:pass@localhost:5432/octo" \
  cargo run --release -p octo-backfill-operation-index -- --batch-size 1000
```

## Expected Healthy Log Output

```text
2026-09-26T22:05:00.000Z  INFO backfill_operation_index: Starting operation_index backfill
2026-09-26T22:05:00.010Z  INFO backfill_operation_index: Database URL: postgres://user:***...
2026-09-26T22:05:00.010Z  INFO backfill_operation_index: Batch size: 1000
2026-09-26T22:05:00.010Z  INFO backfill_operation_index: Dry run: false
2026-09-26T22:05:00.010Z  INFO backfill_operation_index: Limit: unlimited
2026-09-26T22:05:00.250Z  INFO backfill_operation_index: Updated transaction 3fa85f64-...: 0 -> 1 (tx_hash: 7d2b4f...)
2026-09-26T22:05:00.255Z  INFO backfill_operation_index: Updated transaction 8ce219a1-...: 0 -> 2 (tx_hash: 7d2b4f...)
...
2026-09-26T22:05:05.100Z  INFO backfill_operation_index: Backfill Summary:
2026-09-26T22:05:05.100Z  INFO backfill_operation_index:   Total examined: 4500
2026-09-26T22:05:05.100Z  INFO backfill_operation_index:   Needs update: 120
2026-09-26T22:05:05.100Z  INFO backfill_operation_index:   Updated: 120
2026-09-26T22:05:05.100Z  INFO backfill_operation_index:   Skipped (already correct): 4380
2026-09-26T22:05:05.100Z  INFO backfill_operation_index:   Skipped (invalid TOID): 0
2026-09-26T22:05:05.100Z  INFO backfill_operation_index:   Errors: 0
```

## Implementation & Code Reference

The backfill tool relies on:
- [`octo_ingest::operation_index_from_toid`](file:///c:/Users/DELL/OneDrive/Desktop/drip/Octo-Protocol-6/crates/ingest/src/lib.rs):
  Extracts the 0-based operation index from TOID strings formatted as `{ledger}-{tx_index}-{op_index}`.
- Atomic SQL Transaction Updates:
  Each candidate batch is updated inside an isolated SQL transaction with an optimistic guard:
  ```sql
  UPDATE transactions 
  SET operation_index = $1, updated_at = now()
  WHERE id = $2 AND operation_index = $3 AND horizon_op_id = $4;
  ```
- Any rows modified concurrently will log a warning without aborting the batch.

## Monitoring Progress

Operators can monitor the remaining backfill volume during execution:
```sql
SELECT 
    count(*) FILTER (WHERE operation_index = 0 AND split_part(horizon_op_id, '-', 3) <> '0') AS pending_backfill,
    count(*) FILTER (WHERE operation_index = split_part(horizon_op_id, '-', 3)::int) AS verified_correct
FROM transactions
WHERE direction = 'deposit' AND horizon_op_id IS NOT NULL;
```

## Interruption Recovery

- **Idempotent**: Rows with matching `operation_index` and TOID component are identified as `already correct` and skipped on subsequent runs.
- **Transactional Batches**: Each batch commits atomically. If the process is terminated mid-execution, previously committed batches remain intact.
- **Recovery Action**: Simply re-execute the binary. It will query from offset or filter candidates and continue until all rows match their TOID index.
