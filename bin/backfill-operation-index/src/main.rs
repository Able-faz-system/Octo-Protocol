//! Backfill tool for fixing operation_index values in existing deposit rows.
//!
//! This tool safely backfills the correct operation_index for deposits that were recorded
//! with a hardcoded operation_index = 0. It extracts the real operation index from the
//! already-stored horizon_op_id (TOID) field and updates the rows in batches to avoid
//! long-held table locks.
//!
//! The tool is designed to be:
//! - Idempotent: can be run multiple times safely
//! - Resumable: can be interrupted and restarted
//! - Safe for production: uses small batches and transactions
//! - Non-blocking: doesn't hold long locks on the transactions table

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use octo_ingest::operation_index_from_toid;
use octo_store::Store;
use sqlx::Row;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "backfill-operation-index")]
#[command(about = "Backfill operation_index values from horizon_op_id for existing deposits")]
struct Args {
    /// Database URL (or set DATABASE_URL env var)
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Batch size for processing records (default: 1000)
    #[arg(long, default_value = "1000")]
    batch_size: usize,

    /// Dry run mode - shows what would be updated without making changes
    #[arg(long)]
    dry_run: bool,

    /// Maximum number of records to process (0 = unlimited)
    #[arg(long, default_value = "0")]
    limit: usize,
}

/// Represents a row that needs to be updated
#[derive(Debug)]
struct UpdateCandidate {
    id: uuid::Uuid,
    horizon_op_id: String,
    current_operation_index: i32,
    new_operation_index: i32,
    stellar_tx_hash: String,
}

/// Statistics about the backfill process
#[derive(Debug, Default)]
struct BackfillStats {
    total_examined: usize,
    needs_update: usize,
    updated: usize,
    skipped_invalid_toid: usize,
    skipped_already_correct: usize,
    errors: usize,
}

impl BackfillStats {
    fn print_summary(&self) {
        info!("Backfill Summary:");
        info!("  Total examined: {}", self.total_examined);
        info!("  Needs update: {}", self.needs_update);
        info!("  Updated: {}", self.updated);
        info!(
            "  Skipped (already correct): {}",
            self.skipped_already_correct
        );
        info!("  Skipped (invalid TOID): {}", self.skipped_invalid_toid);
        info!("  Errors: {}", self.errors);
    }
}

async fn find_candidates_batch(
    store: &Store,
    limit: usize,
    offset: usize,
) -> Result<Vec<UpdateCandidate>> {
    let query = r#"
        SELECT id, horizon_op_id, operation_index, stellar_tx_hash
        FROM transactions 
        WHERE direction = 'deposit' 
        AND horizon_op_id IS NOT NULL
        ORDER BY created_at ASC
        LIMIT $1 OFFSET $2
    "#;

    let pool = store.pool();
    let rows = sqlx::query(query)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool)
        .await
        .context("Failed to fetch candidate rows")?;

    let mut candidates = Vec::new();

    for row in rows {
        let id: uuid::Uuid = row.get("id");
        let horizon_op_id: String = row.get("horizon_op_id");
        let current_operation_index: i32 = row.get("operation_index");
        let stellar_tx_hash: Option<String> = row.get("stellar_tx_hash");

        if let Some(new_operation_index) = operation_index_from_toid(&horizon_op_id) {
            if new_operation_index != current_operation_index {
                candidates.push(UpdateCandidate {
                    id,
                    horizon_op_id,
                    current_operation_index,
                    new_operation_index,
                    stellar_tx_hash: stellar_tx_hash.unwrap_or_default(),
                });
            }
        }
    }

    Ok(candidates)
}

async fn update_batch(
    store: &Store,
    candidates: &[UpdateCandidate],
    dry_run: bool,
) -> Result<usize> {
    if candidates.is_empty() {
        return Ok(0);
    }

    if dry_run {
        for candidate in candidates {
            info!(
                "Would update transaction {}: {} -> {} (tx_hash: {}, toid: {})",
                candidate.id,
                candidate.current_operation_index,
                candidate.new_operation_index,
                candidate.stellar_tx_hash,
                candidate.horizon_op_id
            );
        }
        return Ok(candidates.len());
    }

    let mut updated = 0;

    // Use a transaction to ensure consistency
    let pool = store.pool();
    let mut tx = pool
        .begin()
        .await
        .context("Failed to begin database transaction")?;

    for candidate in candidates {
        // Double-check the current value hasn't changed since we selected it
        // and update atomically
        let result = sqlx::query(
            "UPDATE transactions 
             SET operation_index = $1, updated_at = now()
             WHERE id = $2 AND operation_index = $3 AND horizon_op_id = $4",
        )
        .bind(candidate.new_operation_index)
        .bind(candidate.id)
        .bind(candidate.current_operation_index)
        .bind(&candidate.horizon_op_id)
        .execute(&mut *tx)
        .await
        .context("Failed to update transaction")?;

        if result.rows_affected() == 1 {
            updated += 1;
            info!(
                "Updated transaction {}: {} -> {} (tx_hash: {})",
                candidate.id,
                candidate.current_operation_index,
                candidate.new_operation_index,
                candidate.stellar_tx_hash
            );
        } else {
            warn!(
                "Transaction {} was not updated (may have been modified by another process)",
                candidate.id
            );
        }
    }

    tx.commit()
        .await
        .context("Failed to commit database transaction")?;

    Ok(updated)
}

async fn run_backfill(args: Args) -> Result<()> {
    info!("Starting operation_index backfill");
    info!(
        "Database URL: {}",
        args.database_url.chars().take(20).collect::<String>() + "..."
    );
    info!("Batch size: {}", args.batch_size);
    info!("Dry run: {}", args.dry_run);
    info!(
        "Limit: {}",
        if args.limit == 0 {
            "unlimited".to_string()
        } else {
            args.limit.to_string()
        }
    );

    let store = Store::connect(&args.database_url)
        .await
        .context("Failed to connect to database")?;

    let mut stats = BackfillStats::default();
    let mut offset = 0;
    let mut total_processed = 0;

    loop {
        // Determine how many records to fetch in this batch
        let current_batch_size = if args.limit > 0 {
            std::cmp::min(args.batch_size, args.limit - total_processed)
        } else {
            args.batch_size
        };

        if current_batch_size == 0 {
            info!("Reached the specified limit of {} records", args.limit);
            break;
        }

        info!(
            "Processing batch starting at offset {} (batch size: {})",
            offset, current_batch_size
        );

        let candidates = find_candidates_batch(&store, current_batch_size, offset)
            .await
            .context("Failed to find candidate records")?;

        if candidates.is_empty() {
            info!("No more records to process");
            break;
        }

        stats.total_examined += current_batch_size;
        stats.needs_update += candidates.len();

        // Log some examples of what we're about to update
        if !candidates.is_empty() {
            info!(
                "Found {} records needing updates in this batch:",
                candidates.len()
            );
            for (i, candidate) in candidates.iter().take(3).enumerate() {
                info!(
                    "  {}: {} -> {} (tx_hash: {}, toid: {})",
                    i + 1,
                    candidate.current_operation_index,
                    candidate.new_operation_index,
                    candidate.stellar_tx_hash,
                    candidate.horizon_op_id
                );
            }
            if candidates.len() > 3 {
                info!("  ... and {} more", candidates.len() - 3);
            }
        }

        match update_batch(&store, &candidates, args.dry_run).await {
            Ok(updated_count) => {
                stats.updated += updated_count;
                info!(
                    "Successfully processed {} records in this batch",
                    updated_count
                );
            }
            Err(e) => {
                error!("Error updating batch: {}", e);
                stats.errors += 1;
                // Continue with next batch rather than failing completely
            }
        }

        offset += current_batch_size;
        total_processed += current_batch_size;

        // Check if we've reached the limit
        if args.limit > 0 && total_processed >= args.limit {
            info!("Reached the specified limit of {} records", args.limit);
            break;
        }

        // Small delay between batches to be nice to the database
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    stats.print_summary();

    if args.dry_run {
        info!("Dry run completed - no changes were made to the database");
    } else if stats.errors > 0 {
        warn!("Backfill completed with {} errors", stats.errors);
    } else {
        info!("Backfill completed successfully");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("backfill_operation_index=info,warn")
        .init();

    // Load .env file if present
    if let Err(e) = dotenvy::dotenv() {
        // It's OK if .env doesn't exist
        if !e.to_string().contains("No such file") {
            return Err(anyhow!("Failed to load .env file: {}", e));
        }
    }

    let args = Args::parse();

    run_backfill(args).await
}

#[cfg(test)]
mod tests {
    use octo_ingest::operation_index_from_toid;

    #[test]
    fn operation_index_from_toid_parses_correctly() {
        assert_eq!(operation_index_from_toid("12884905985"), Some(0));
        assert_eq!(operation_index_from_toid("12884905986"), Some(1));
        assert_eq!(operation_index_from_toid("53021371310086"), Some(5));
        assert_eq!(operation_index_from_toid("4294963001036900"), Some(99));
    }

    #[test]
    fn operation_index_from_toid_handles_invalid_format() {
        assert_eq!(operation_index_from_toid(""), None);
        assert_eq!(operation_index_from_toid("12345-1-0"), None);
        assert_eq!(operation_index_from_toid("abc"), None);
        assert_eq!(operation_index_from_toid("12884905984"), None);
    }
}
