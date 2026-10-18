//! Deposit detection for octo.
//!
//! Polls a master account's Horizon `/payments` (oldest-first, from a saved cursor), attributes
//! each incoming payment to a customer by **muxed id** or **transaction memo id**, and records it
//! idempotently via [`octo_store`]. Unattributable deposits are still recorded but with no
//! `address_id` (quarantine) — they are never guessed onto a customer.
//!
//! Security (see `docs/threat-model.md`):
//! - Only `transaction_successful` payments are credited (no failed/reorged double-credit).
//! - Dedup on the Horizon operation id (TOID) → replays/re-deliveries are no-ops.
//! - Amounts are integer stroops (no floats); only whitelisted incoming directions are credited.
//! - The cursor is advanced and persisted only after a record is processed, so a crash resumes
//!   without missing or double-processing.
#![forbid(unsafe_code)]

pub mod amount;
pub mod horizon;

#[cfg(test)]
mod backfill_tests;

use horizon::{HorizonPayments, PaymentRecord};
use octo_store::{NewDeposit, Store, Wallet};
use octo_wallet_core::decode_muxed;
use octo_webhooks::{Event, WebhookSender};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// The widely-used testnet USDC issuer — must match `crates/api/src/routes/payment_links.rs`'s
/// constant of the same name (kept separate rather than shared since this crate has no
/// dependency on `octo-api`).
const USDC_TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// Shared thread-safe tracker for the last successful poll times of ingestion.
#[derive(Debug, Clone, Default)]
pub struct LastPollTracker {
    last_polls: Arc<Mutex<HashMap<Uuid, i64>>>,
}

impl LastPollTracker {
    /// Create a new empty `LastPollTracker`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful poll for a wallet.
    pub fn record_success(&self, wallet_id: Uuid, timestamp: i64) {
        if let Ok(mut map) = self.last_polls.lock() {
            map.insert(wallet_id, timestamp);
        }
    }

    /// Get the last successful poll timestamp (unix-seconds) for a wallet.
    pub fn last_poll(&self, wallet_id: Uuid) -> Option<i64> {
        self.last_polls
            .lock()
            .ok()
            .and_then(|map| map.get(&wallet_id).copied())
    }

    /// Get a copy of all tracked poll times.
    pub fn all_last_polls(&self) -> HashMap<Uuid, i64> {
        self.last_polls
            .lock()
            .map(|map| map.clone())
            .unwrap_or_default()
    }
}

/// Outcome of processing a single payment record.
#[derive(Debug, PartialEq, Eq)]
pub enum Processed {
    /// A new deposit was recorded (attributed to a customer address, or quarantined if `None`).
    Recorded { attributed: bool },
    /// Already recorded (idempotent no-op).
    Duplicate,
    /// Skipped (not a credit to us, failed tx, unknown asset shape, etc.).
    Skipped,
}

/// The ingest worker for one master wallet.
pub struct Ingestor {
    store: Store,
    horizon: HorizonPayments,
    wallet_id: Uuid,
    account_g: String,
    webhooks: Option<WebhookSender>,
    tracker: Option<LastPollTracker>,
}

impl Ingestor {
    pub fn new(store: Store, horizon_url: &str, wallet_id: Uuid, account_g: String) -> Self {
        Self {
            store,
            horizon: HorizonPayments::new(horizon_url),
            wallet_id,
            account_g,
            webhooks: None,
            tracker: None,
        }
    }

    /// Create an Ingestor with explicit resilience configuration (used by `Supervisor::tick`
    /// when `bin/server` wires env-var resilience config through).
    pub fn new_with_resilience(
        store: Store,
        horizon_url: &str,
        wallet_id: Uuid,
        account_g: String,
        retry: octo_resilience::RetryPolicy,
        circuit: octo_resilience::CircuitBreaker,
    ) -> Self {
        Self {
            store,
            horizon: HorizonPayments::with_resilience(horizon_url, retry, circuit),
            wallet_id,
            account_g,
            webhooks: None,
            tracker: None,
        }
    }

    /// Attach a webhook sender so new deposits fire a `deposit.created` event.
    pub fn with_webhooks(mut self, sender: WebhookSender) -> Self {
        self.webhooks = Some(sender);
        self
    }

    /// Attach a tracker to record successful poll times.
    pub fn with_tracker(mut self, tracker: LastPollTracker) -> Self {
        self.tracker = Some(tracker);
        self
    }

    /// Poll once: fetch the next page of payments after the saved cursor, process each, and persist
    /// the cursor. Returns the number of records processed.
    pub async fn poll_once(&self, limit: u32) -> Result<usize, IngestError> {
        let cursor = self.store.get_cursor(self.wallet_id).await?;
        let records = self
            .horizon
            .payments_after(&self.account_g, cursor.as_deref(), limit)
            .await
            .map_err(|_| IngestError::Horizon)?;

        let mut count = 0;
        for rec in &records {
            self.process(rec).await?;
            // Advance the cursor after each record so a crash resumes cleanly.
            self.store
                .set_cursor(self.wallet_id, &rec.paging_token)
                .await?;
            count += 1;
        }

        if let Some(ref tracker) = self.tracker {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            tracker.record_success(self.wallet_id, now);
        }

        Ok(count)
    }

    /// Run forever, polling every `interval`. Errors are logged and retried (the cursor makes this
    /// safe). Intended to run as its own task/process.
    pub async fn run(self, interval: Duration, page_limit: u32) {
        loop {
            // Drain a backlog within one interval, bounded like `Supervisor::tick`.
            for _ in 0..Supervisor::MAX_PAGES_PER_TICK {
                match self.poll_once(page_limit).await {
                    Ok(n) => {
                        if n > 0 {
                            tracing::debug!(processed = n, "ingest poll");
                        }
                        if !page_was_full(n, page_limit) {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = ?e, "ingest poll failed; will retry");
                        break;
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Process one payment record into a deposit (or skip it).
    pub async fn process(&self, rec: &PaymentRecord) -> Result<Processed, IngestError> {
        // 1. Only successful credits to us.
        if !rec.transaction_successful {
            return Ok(Processed::Skipped);
        }
        if rec.kind != "payment" && rec.kind != "create_account" {
            return Ok(Processed::Skipped);
        }
        // The destination base account must be our master account.
        match rec.to.as_deref() {
            Some(to) if to == self.account_g => {}
            _ => return Ok(Processed::Skipped),
        }

        // 2. Amount → stroops (payment uses `amount`, create_account uses `starting_balance`).
        let amount_str = rec
            .amount
            .as_deref()
            .or(rec.starting_balance.as_deref())
            .unwrap_or("");
        let Some(stroops) = amount::to_stroops(amount_str) else {
            // Never credit an approximation: surface the unparseable amount (no customer data).
            tracing::warn!(
                op_id = %rec.id,
                amount = ?amount_str,
                "skipping payment: amount is not a valid Stellar amount (≤ 7 decimals)"
            );
            return Ok(Processed::Skipped);
        };
        if stroops <= 0 {
            return Ok(Processed::Skipped);
        }

        // 3. Attribute to a customer: muxed id first, then memo id.
        let customer_id = self.attribute(rec);
        let address_id = match customer_id {
            Some(id) => self
                .store
                .address_by_muxed_id(self.wallet_id, id)
                .await?
                .map(|a| a.id),
            None => None,
        };
        let attributed = address_id.is_some();

        // 4. Asset.
        let (asset_code, asset_issuer) = match rec.asset_type.as_deref() {
            Some("native") | None => ("native".to_string(), None),
            _ => (
                rec.asset_code.clone().unwrap_or_else(|| "unknown".into()),
                rec.asset_issuer.clone(),
            ),
        };

        let memo_id = self.memo_id(rec);
        let ledger = rec.transaction.as_ref().and_then(|t| t.ledger);
        let tx_hash = rec.transaction_hash.clone().unwrap_or_default();

        // A bad TOID would corrupt the (tx_hash, operation_index) dedup key — skip, never guess.
        let toid = decode_toid(&rec.id, plausible_max_ledger())
            .filter(|t| ledger.is_none_or(|l| i64::from(t.ledger) == l));
        let Some(toid) = toid else {
            tracing::warn!(
                op_id = %rec.id,
                tx_hash = %tx_hash,
                ?ledger,
                "implausible Horizon TOID; skipping record"
            );
            return Ok(Processed::Skipped);
        };

        let dep = NewDeposit {
            wallet_id: self.wallet_id,
            address_id,
            asset_code,
            asset_issuer,
            amount_stroops: stroops,
            source_account: rec.from.clone(),
            destination_account: rec.to_muxed.clone().or_else(|| rec.to.clone()),
            stellar_tx_hash: tx_hash,
            operation_index: toid.operation_index,
            horizon_op_id: rec.id.clone(),
            ledger,
            memo_id,
        };

        match self.store.record_deposit(&dep).await? {
            Some(tx) => {
                self.fire_deposit_webhook(&tx).await;
                self.confirm_payment_link(&tx).await;
                Ok(Processed::Recorded { attributed })
            }
            None => Ok(Processed::Duplicate),
        }
    }

    /// If this deposit landed on a payment link's dedicated address, confirm its oldest pending
    /// payment and fire `payment_link.paid`. Best-effort: a lookup miss just means it wasn't one.
    async fn confirm_payment_link(&self, tx: &octo_store::Transaction) {
        // v1 payment links are USDC-only — a deposit in any other asset (e.g. native XLM sent to
        // the address by mistake) must not be mistaken for the USDC payment the link is waiting
        // on, or the merchant's dashboard would report a payment they never actually received.
        if tx.asset_code != "USDC" || tx.asset_issuer.as_deref() != Some(USDC_TESTNET_ISSUER) {
            return;
        }
        let Some(address_id) = tx.address_id else {
            return;
        };

        // Preferred path: the deposit landed on an intent's OWN address, so it maps to exactly
        // one payment even with several payers on the same link concurrently.
        let exact = self.store.pending_payment_by_address(address_id).await;
        let (link, payment) = match exact {
            Ok(Some(payment)) => {
                let Ok(link) = self
                    .store
                    .get_payment_link(self.wallet_id, payment.payment_link_id)
                    .await
                else {
                    return;
                };
                (link, payment)
            }
            _ => {
                // Fallback for intents created before per-intent addresses (migration 0015):
                // the deposit landed on the link's shared address.
                let Ok(Some(link)) = self.store.get_payment_link_by_address(address_id).await
                else {
                    return;
                };
                let Ok(Some(payment)) = self
                    .store
                    .oldest_pending_payment_link_payment(link.id)
                    .await
                else {
                    return;
                };
                (link, payment)
            }
        };

        // Exact match confirms; anything else is a mismatch the merchant/payer must be told
        // about — never silently absorbed as if it were correct, and never confirmed either.
        if tx.amount_stroops != payment.amount_usdc_stroops {
            let status = if tx.amount_stroops < payment.amount_usdc_stroops {
                "underpaid"
            } else {
                "overpaid"
            };
            tracing::warn!(
                payment_id = %payment.id,
                expected = payment.amount_usdc_stroops,
                received = tx.amount_stroops,
                status,
                "payment-link deposit does not match the intended amount"
            );
            // Only the call that actually flipped the row notifies; a no-op means already settled.
            let flipped = self
                .store
                .mark_payment_link_payment_mismatched(payment.id, tx.id, status)
                .await;
            if !matches!(flipped, Ok(true)) {
                return;
            }
            if let Some(sender) = &self.webhooks {
                let event = Event {
                    event_type: "payment_link.mismatched".to_string(),
                    data: serde_json::json!({
                        "payment_link_id": link.id,
                        "payment_id": payment.id,
                        "slug": link.slug,
                        "payer_name": payment.payer_name,
                        "payer_email": payment.payer_email,
                        "status": status,
                        "expected_usdc_stroops": payment.amount_usdc_stroops,
                        "received_usdc_stroops": tx.amount_stroops,
                        "stellar_tx_hash": tx.stellar_tx_hash,
                    }),
                };
                sender.dispatch(self.wallet_id, &event).await;
            }
            return;
        }

        // Only the call that actually flipped the row notifies; a no-op means already settled.
        let flipped = self
            .store
            .confirm_payment_link_payment(payment.id, tx.id)
            .await;
        if !matches!(flipped, Ok(true)) {
            return;
        }

        let Some(sender) = &self.webhooks else { return };
        let event = Event {
            event_type: "payment_link.paid".to_string(),
            data: serde_json::json!({
                "payment_link_id": link.id,
                "payment_id": payment.id,
                "slug": link.slug,
                "payer_name": payment.payer_name,
                "payer_email": payment.payer_email,
                "amount_usdc_stroops": payment.amount_usdc_stroops,
                "stellar_tx_hash": tx.stellar_tx_hash,
            }),
        };
        sender.dispatch(self.wallet_id, &event).await;
    }

    /// Fire a `deposit.created` webhook for a newly-recorded deposit. The event echoes the
    /// customer's address `metadata` (if attributed) so the consumer can reconcile to their user.
    async fn fire_deposit_webhook(&self, tx: &octo_store::Transaction) {
        let Some(sender) = &self.webhooks else {
            return;
        };

        // Echo the customer address's metadata (Blockradar-parity reconciliation), best-effort.
        let metadata = match tx.address_id {
            Some(addr_id) => match self.store.get_address(addr_id).await {
                Ok(Some(a)) => a.metadata,
                _ => serde_json::Value::Null,
            },
            None => serde_json::Value::Null,
        };

        let event = Event {
            event_type: "deposit.created".to_string(),
            data: serde_json::json!({
                "id": tx.id,
                "wallet_id": tx.wallet_id,
                "address_id": tx.address_id,
                "asset_code": tx.asset_code,
                "asset_issuer": tx.asset_issuer,
                "amount_stroops": tx.amount_stroops,
                "source_account": tx.source_account,
                "destination_account": tx.destination_account,
                "stellar_tx_hash": tx.stellar_tx_hash,
                "memo_id": tx.memo_id,
                "status": tx.status,
                "attributed": tx.address_id.is_some(),
                "metadata": metadata,
            }),
        };
        sender.dispatch(self.wallet_id, &event).await;
    }

    /// The customer id for a record: the muxed id if the payment was sent to `M...`, else a numeric
    /// memo id, else `None` (unattributed).
    fn attribute(&self, rec: &PaymentRecord) -> Option<i64> {
        if let Some(id) = self.muxed_id(rec) {
            return Some(id);
        }
        self.memo_id(rec)
    }

    /// Extract the muxed id from a record, validating the muxed address decodes to our base account.
    fn muxed_id(&self, rec: &PaymentRecord) -> Option<i64> {
        let muxed = rec.to_muxed.as_deref()?;
        let decoded = decode_muxed(muxed).ok()?;
        if decoded.base_account() != self.account_g {
            return None;
        }
        i64::try_from(decoded.id).ok()
    }

    /// Extract a numeric memo id from the joined transaction (`memo_type == "id"`).
    fn memo_id(&self, rec: &PaymentRecord) -> Option<i64> {
        let tx = rec.transaction.as_ref()?;
        if tx.memo_type.as_deref() != Some("id") {
            return None;
        }
        tx.memo.as_deref()?.parse::<i64>().ok()
    }
}

/// Whether a page came back full, meaning more records may be waiting behind it.
fn page_was_full(records: usize, page_limit: u32) -> bool {
    page_limit > 0 && records >= page_limit as usize
}

/// Unix time of pubnet genesis (2015-09-30T00:00:00Z, rounded down so the bound stays generous).
const STELLAR_GENESIS_UNIX: u64 = 1_443_571_200;
/// Ledger ceiling that holds regardless of the host clock: seconds from genesis to 2026-01-01.
const LEDGER_CEILING_FLOOR: u32 = 323_654_400;
/// stellar-core's `MAX_OPS_PER_TX`: an operation index is always in `0..100`.
const MAX_OPS_PER_TX: u64 = 100;

/// A decoded Horizon operation TOID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toid {
    pub ledger: u32,
    /// 1-based application order of the transaction within its ledger.
    pub tx_order: u32,
    /// 0-based index of the operation within its transaction.
    pub operation_index: i32,
}

/// The highest ledger sequence that could plausibly exist now.
///
/// Assumes at most one ledger per second (5× faster than the ~5 s close target), and never drops
/// below [`LEDGER_CEILING_FLOOR`] so a host clock set in the past cannot reject real deposits.
pub fn plausible_max_ledger() -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let by_clock = u32::try_from(now.saturating_sub(STELLAR_GENESIS_UNIX)).unwrap_or(u32::MAX);
    by_clock.max(LEDGER_CEILING_FLOOR)
}

/// Decode a Horizon operation TOID, rejecting any field outside its real-world range.
///
/// A TOID is a positive `int64` written as a decimal string (e.g. `"12884905985"`), laid out as
/// in stellar/go `toid/main.go` (`LedgerShift = 32`, `TransactionShift = 12`):
///
/// ```text
///  bit 63       32 31               12 11          0
///  ┌──────────────┬───────────────────┬─────────────┐
///  │ ledger (32)  │ tx order (20)     │ op order(12)│
///  └──────────────┴───────────────────┴─────────────┘
/// ```
///
/// Horizon's operations processor builds it as `toid.New(ledger, tx.Index, opIndex + 1)`, so for
/// an operation: `ledger` is in `1..=max_ledger`, `tx order` starts at 1, and `op order` is
/// `1..=MAX_OPS_PER_TX` (0 would be the transaction's own TOID, not an operation's).
pub fn decode_toid(toid: &str, max_ledger: u32) -> Option<Toid> {
    // Canonical digits only — `parse` alone would accept "+1" and leading signs.
    if toid.is_empty() || !toid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let packed = u64::try_from(toid.parse::<i64>().ok()?).ok()?;
    let ledger = (packed >> 32) as u32;
    let tx_order = ((packed >> 12) & 0xF_FFFF) as u32;
    let op_order = packed & 0xFFF;
    if ledger == 0 || ledger > max_ledger || tx_order == 0 {
        return None;
    }
    if op_order == 0 || op_order > MAX_OPS_PER_TX {
        return None;
    }
    Some(Toid {
        ledger,
        tx_order,
        operation_index: (op_order - 1) as i32,
    })
}

/// Extract the 0-based operation index from a Horizon operation TOID.
///
/// Returns `None` for anything that does not decode to a plausible operation (see
/// [`decode_toid`]) — never a guessed or out-of-range index.
pub fn operation_index_from_toid(toid: &str) -> Option<i32> {
    decode_toid(toid, plausible_max_ledger()).map(|t| t.operation_index)
}

/// Errors from the ingest worker.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("store error")]
    Store(#[from] octo_store::StoreError),
    #[error("horizon error")]
    Horizon,
}

/// Supervises deposit ingestion across all wallets.
///
/// On each tick it pages through the due wallets and polls each one once (resuming from its
/// cursor). This is a simple, restart-safe fan-out for the MVP; it can later be split into
/// per-wallet workers or separate processes for scale without changing the cursor-based contract.
pub struct Supervisor {
    store: Store,
    horizon_url: String,
    webhooks: WebhookSender,
    network: &'static str,
    tracker: LastPollTracker,
    /// Retry/circuit config handed to each per-wallet `Ingestor` built in `tick`.
    retry: octo_resilience::RetryPolicy,
    circuit: octo_resilience::CircuitBreaker,
}

impl Supervisor {
    pub fn new(
        store: Store,
        horizon_url: String,
        webhooks: WebhookSender,
        network: &'static str,
    ) -> Self {
        // Same defaults the rest of the workspace uses for Horizon clients: open after 5
        // consecutive failures, probe again after 30s.
        Self::new_with_resilience(
            store,
            horizon_url,
            webhooks,
            network,
            octo_resilience::RetryPolicy::default(),
            octo_resilience::CircuitBreaker::new(5, Duration::from_secs(30)),
        )
    }

    /// Like [`Supervisor::new`] but with explicit resilience configuration (used by
    /// `bin/server`, which reads retry/circuit settings from env vars).
    pub fn new_with_resilience(
        store: Store,
        horizon_url: String,
        webhooks: WebhookSender,
        network: &'static str,
        retry: octo_resilience::RetryPolicy,
        circuit: octo_resilience::CircuitBreaker,
    ) -> Self {
        Self {
            store,
            horizon_url,
            webhooks,
            network,
            tracker: LastPollTracker::new(),
            retry,
            circuit,
        }
    }

    /// Mark stale pending payment-link intents as `expired` and fire one `payment_link.expired`
    /// webhook per row. Runs every tick — a single indexed `UPDATE ... WHERE` is cheap even when
    /// it matches nothing, so no separate timer is needed. Best-effort: a DB error here must
    /// never abort the poll loop.
    async fn expire_stale_payment_link_payments(&self) {
        let expired = match self.store.expire_stale_payment_link_payments().await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = ?e, "failed to sweep stale payment-link payments");
                return;
            }
        };
        for payment in expired {
            let Ok(Some(link)) = self
                .store
                .get_payment_link_by_id(payment.payment_link_id)
                .await
            else {
                continue;
            };
            let event = Event {
                event_type: "payment_link.expired".to_string(),
                data: serde_json::json!({
                    "payment_link_id": link.id,
                    "payment_id": payment.id,
                    "slug": link.slug,
                    "payer_name": payment.payer_name,
                    "payer_email": payment.payer_email,
                    "amount_usdc_stroops": payment.amount_usdc_stroops,
                }),
            };
            self.webhooks.dispatch(link.wallet_id, &event).await;
        }
    }

    /// Run forever: every `interval`, poll all wallets on this network once.
    pub async fn run(self, interval: Duration, page_limit: u32) {
        self.run_until_cancelled(interval, page_limit, CancellationToken::new()).await;
    }

    /// Like [`Supervisor::run`], but returns once `shutdown` is cancelled.
    ///
    /// Cancellation is only observed *between* ticks: an in-progress tick always finishes its
    /// current page (deposit rows + cursor), so a rolling deploy never aborts a page halfway.
    /// Bounding how long that may take is the caller's job (see `bin/server`'s drain timeout).
    pub async fn run_until_cancelled(
        self,
        interval: Duration,
        page_limit: u32,
        shutdown: CancellationToken,
    ) {
        while !shutdown.is_cancelled() {
            if let Err(e) = self.tick(page_limit).await {
                tracing::warn!(error = ?e, "ingest supervisor tick failed; will retry");
            }
            // Wake early on shutdown instead of sleeping out the full interval.
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                () = shutdown.cancelled() => {}
            }
        }
        tracing::info!("ingest supervisor stopped after finishing its current tick");
    }

    /// One supervision pass: poll every wallet on this network, draining each wallet's backlog
    /// page by page up to [`Self::MAX_PAGES_PER_TICK`].
    ///
    /// Wallets are polled CONCURRENTLY (bounded by [`Self::MAX_CONCURRENT_POLLS`]), not one at a
    /// time. Sequential polling meant a single slow/unfunded wallet's Horizon round-trip (or
    /// retry-with-backoff) blocked every wallet behind it in the list — with hundreds of wallets,
    /// a deposit on a late one could sit unprocessed for minutes despite the nominal poll
    /// interval. Bounding concurrency (rather than firing all requests at once) keeps Horizon
    /// request volume sane regardless of how many wallets exist.
    pub async fn tick(&self, page_limit: u32) -> Result<usize, IngestError> {
        self.expire_stale_payment_link_payments().await;

        // Only wallets actually due under the backoff tiers — a dev/production DB accumulates
        // wallets that never transact again, and polling them every cycle starves the active ones
        // of the shared concurrency budget. Paged by id so memory doesn't scale with wallet count.
        let semaphore = Arc::new(tokio::sync::Semaphore::new(Self::MAX_CONCURRENT_POLLS));
        let mut tasks = tokio::task::JoinSet::new();
        let mut task_wallets = HashMap::new();

        for w in wallets {
            let wallet_id = w.id;
            let store = self.store.clone();
            let store_for_mark = self.store.clone();
            let horizon_url = self.horizon_url.clone();
            let webhooks = self.webhooks.clone();
            let tracker = self.tracker.clone();
            let retry = self.retry.clone();
            let circuit = self.circuit.clone();
            let semaphore = semaphore.clone();
            let task_id = tasks.spawn(async move {
                // Held for the duration of this wallet's poll; bounds how many Horizon requests
                // are in flight at once without limiting how many wallets we *queue*.
                let _permit = semaphore.acquire_owned().await;
                let ingestor = Ingestor::new_with_resilience(
                    store,
                    &horizon_url,
                    w.id,
                    w.stellar_account_g.clone(),
                    retry,
                    circuit,
                )
                .with_webhooks(webhooks)
                .with_tracker(tracker);
                // Drain a backlog page by page; each page persists its own cursor (crash-safe).
                let mut total = 0;
                let mut result = Ok(0);
                for _ in 0..Self::MAX_PAGES_PER_TICK {
                    let page = ingestor.poll_once(page_limit).await;
                    // Record the attempt regardless of outcome, so a wallet whose polls keep
                    // failing still backs off instead of being retried at full rate forever.
                    let _ = store_for_mark.mark_polled(w.id).await;
                    match page {
                        Ok(n) => {
                            total += n;
                            result = Ok(total);
                            if !page_was_full(n, page_limit) {
                                break;
                            }
                        }
                        Err(e) => {
                            result = Err(e);
                            break;
                        }
                    }
                }
                (w.id, result)
            });
            task_wallets.insert(task_id.id(), wallet_id);
        }

        let mut total = 0;
        let mut after_id = None;
        let mut fetch_error = None;

        loop {
            let page = match self
                .store
                .wallets_due_for_poll_page(
                    self.network,
                    Self::ACTIVE_AFTER_SECS,
                    Self::IDLE_INTERVAL_SECS,
                    Self::DORMANT_AFTER_SECS,
                    Self::DORMANT_INTERVAL_SECS,
                    Some(Self::FANOUT_PAGE_SIZE),
                    after_id,
                )
                .await
            {
                Ok(page) => page,
                // Don't return yet: dropping the JoinSet would abort polls already in flight.
                Err(e) => {
                    fetch_error = Some(e);
                    break;
                }
            };
            let is_last_page = (page.len() as i64) < Self::FANOUT_PAGE_SIZE;
            after_id = page.last().map(|w| w.id);

            for w in page {
                self.spawn_poll(&mut tasks, &semaphore, w, page_limit);
            }
            if is_last_page {
                break;
            }
            // Backpressure: keep at most about one page of queued tasks before loading the next.
            while tasks.len() > Self::FANOUT_PAGE_SIZE as usize {
                if let Some(joined) = tasks.join_next().await {
                    total += Self::tally(joined);
                }
            }
        }

        while let Some(joined) = tasks.join_next().await {
            total += Self::tally(joined);
        }
        match fetch_error {
            Some(e) => Err(e.into()),
            None => Ok(total),
        }
    }

    /// Queue one wallet's poll on `tasks`, gated by the shared concurrency `semaphore`.
    fn spawn_poll(
        &self,
        tasks: &mut tokio::task::JoinSet<(Uuid, Result<usize, IngestError>)>,
        semaphore: &Arc<tokio::sync::Semaphore>,
            }
        }

        while let Some(joined) = tasks.join_next().await {
            total += Self::tally(joined);
        }
        match fetch_error {
            Some(e) => Err(e.into()),
            None => Ok(total),
        }
    }

    /// Queue one wallet's poll on `tasks`, gated by the shared concurrency `semaphore`.
    fn spawn_poll(
        &self,
        tasks: &mut tokio::task::JoinSet<(Uuid, Result<usize, IngestError>)>,
        semaphore: &Arc<tokio::sync::Semaphore>,
        w: Wallet,
        page_limit: u32,
    ) {
        let store = self.store.clone();
        let horizon_url = self.horizon_url.clone();
        let webhooks = self.webhooks.clone();
        let tracker = self.tracker.clone();
        let retry = self.retry.clone();
        let circuit = self.circuit.clone();
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            // Held for the duration of this wallet's poll; bounds how many Horizon requests
            // are in flight at once without limiting how many wallets we *queue*.
            let _permit = semaphore.acquire_owned().await;
            let ingestor = Ingestor::new_with_resilience(
                store.clone(),
                &horizon_url,
                w.id,
                w.stellar_account_g.clone(),
                retry,
                circuit,
            )
            .with_webhooks(webhooks)
            .with_tracker(tracker);
            let result = ingestor.poll_once(page_limit).await;
            // Record the attempt regardless of outcome, so a wallet whose polls keep failing
            // still backs off instead of being retried at full rate forever.
            let _ = store.mark_polled(w.id).await;
            (w.id, result)
        });
    }

    /// Count records from one finished poll task, logging failures.
    fn tally(joined: Result<(Uuid, Result<usize, IngestError>), tokio::task::JoinError>) -> usize {
        match joined {
            Ok((_wallet_id, Ok(n))) => n,
            Ok((wallet_id, Err(e))) => {
                tracing::warn!(wallet = %wallet_id, error = ?e, "wallet poll failed");
                0
            }
            Err(e) => {
                tracing::warn!(error = ?e, "wallet poll task panicked");
                0
            }
        }
    }

    /// Wallets fetched per page during the fan-out. Bounds both the query size and the number of
    /// queued poll tasks (roughly two pages at most) regardless of total wallet count.
    const FANOUT_PAGE_SIZE: i64 = 500;

    /// How many wallets to poll concurrently in one [`Supervisor::tick`] pass.
    const MAX_CONCURRENT_POLLS: usize = 20;

    /// Upper bound on pages one wallet may fetch in a single [`Supervisor::tick`].
    ///
    /// Fairness tradeoff: a wallet keeps its concurrency permit while it drains, so an unbounded
    /// drain would let one recovering wallet pin a permit for its whole backlog. At the default
    /// `INGEST_PAGE_LIMIT` of 50 this drains up to 500 records per wallet per tick — enough to
    /// clear a typical outage backlog in one or two ticks — while costing at most 10 Horizon
    /// round-trips on one of 20 permits, so the other permits keep serving every other wallet.
    const MAX_PAGES_PER_TICK: usize = 10;

    /// Activity-based backoff tiers. A wallet that saw a deposit within `ACTIVE_AFTER_SECS` is
    /// polled every tick; quieter wallets are polled progressively less often. Deposit latency for
    /// an actively-used wallet is unchanged — only dead accounts are slowed down.
    const ACTIVE_AFTER_SECS: i64 = 60 * 60; // active if activity in the last hour
    const IDLE_INTERVAL_SECS: i64 = 120; // idle wallets: at most every 2 minutes
    const DORMANT_AFTER_SECS: i64 = 24 * 60 * 60; // dormant after a day of silence
    const DORMANT_INTERVAL_SECS: i64 = 600; // dormant wallets: at most every 10 minutes

    /// Get a clone of the `LastPollTracker` to inspect poll lag.
    ///
    /// # Example
    /// ```
    /// # use octo_ingest::{Supervisor, LastPollTracker};
    /// # // How a caller (like AppState or a health router) reads poll timestamps:
    /// # // let supervisor: Supervisor = ...;
    /// # // let tracker: LastPollTracker = supervisor.last_poll_tracker();
    /// # // if let Some(ts) = tracker.last_poll(wallet_id) { ... }
    /// ```
    pub fn last_poll_tracker(&self) -> LastPollTracker {
        self.tracker.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use horizon::{PaymentRecord, TransactionRecord};

    const BASE: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

    // The attribution logic is pure; mirror it as free functions so these unit tests need no DB.
    // The DB-backed process()/poll_once() path is covered by the integration test.
    fn muxed_id_of(account_g: &str, rec: &PaymentRecord) -> Option<i64> {
        let muxed = rec.to_muxed.as_deref()?;
        let decoded = decode_muxed(muxed).ok()?;
        if decoded.base_account() != account_g {
            return None;
        }
        i64::try_from(decoded.id).ok()
    }

    fn memo_id_of(rec: &PaymentRecord) -> Option<i64> {
        let tx = rec.transaction.as_ref()?;
        if tx.memo_type.as_deref() != Some("id") {
            return None;
        }
        tx.memo.as_deref()?.parse::<i64>().ok()
    }

    fn rec() -> PaymentRecord {
        PaymentRecord {
            id: "op1".into(),
            paging_token: "op1".into(),
            kind: "payment".into(),
            transaction_hash: Some("hash".into()),
            transaction_successful: true,
            from: Some("Gfrom".into()),
            to: Some(BASE.into()),
            to_muxed: None,
            to_muxed_id: None,
            asset_type: Some("native".into()),
            asset_code: None,
            asset_issuer: None,
            amount: Some("5.0000000".into()),
            starting_balance: None,
            transaction: None,
        }
    }

    #[test]
    fn attributes_by_muxed_id() {
        let muxed = octo_wallet_core::encode_muxed(BASE, 77).unwrap();
        let mut r = rec();
        r.to_muxed = Some(muxed);
        assert_eq!(muxed_id_of(BASE, &r), Some(77));
    }

    #[test]
    fn muxed_for_other_base_is_ignored() {
        // A different (valid) base account — its muxed form must not attribute to ours.
        let other = "GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR";
        let muxed = octo_wallet_core::encode_muxed(other, 5).unwrap();
        let mut r = rec();
        r.to_muxed = Some(muxed);
        assert_eq!(muxed_id_of(BASE, &r), None);
    }

    #[test]
    fn attributes_by_memo_id() {
        let mut r = rec();
        r.transaction = Some(TransactionRecord {
            memo_type: Some("id".into()),
            memo: Some("42".into()),
            ledger: Some(10),
        });
        assert_eq!(memo_id_of(&r), Some(42));
    }

    #[test]
    fn non_id_memo_is_ignored() {
        let mut r = rec();
        r.transaction = Some(TransactionRecord {
            memo_type: Some("text".into()),
            memo: Some("hello".into()),
            ledger: None,
        });
        assert_eq!(memo_id_of(&r), None);
    }

    // --- i64/u64 boundary tests -------------------------------------------
    //
    // muxed_id uses i64::try_from(decoded.id).ok() where decoded.id is u64.
    // Any id above i64::MAX causes try_from to fail and the deposit becomes
    // unattributed (None) rather than erroring. These tests lock that
    // documented behavior in as an explicit regression guard.
    //
    // NOTE: if this silent-truncation behavior should change, do NOT fix it
    // here — this file is test-only per issue #60. Raise the concern in the
    // PR so a maintainer can decide (see the related backend tracking issue).

    #[test]
    fn muxed_id_at_i64_max_is_attributed() {
        // i64::MAX fits in u64 and must round-trip through i64::try_from cleanly.
        let muxed = octo_wallet_core::encode_muxed(BASE, i64::MAX as u64).unwrap();
        let mut r = rec();
        r.to_muxed = Some(muxed);
        assert_eq!(
            muxed_id_of(BASE, &r),
            Some(i64::MAX),
            "a muxed id of exactly i64::MAX must be attributed correctly"
        );
    }

    #[test]
    fn muxed_id_above_i64_max_is_unattributed_not_error() {
        // i64::MAX + 1 overflows i64::try_from → must return None, not panic.
        let above_max: u64 = i64::MAX as u64 + 1;
        let muxed = octo_wallet_core::encode_muxed(BASE, above_max).unwrap();
        let mut r = rec();
        r.to_muxed = Some(muxed);
        assert_eq!(
            muxed_id_of(BASE, &r),
            None,
            "a muxed id above i64::MAX must be silently unattributed (current documented behavior)"
        );
    }

    #[test]
    fn memo_id_at_i64_max_is_attributed() {
        // "9223372036854775807" is i64::MAX as a decimal string — must parse cleanly.
        let mut r = rec();
        r.transaction = Some(TransactionRecord {
            memo_type: Some("id".into()),
            memo: Some("9223372036854775807".into()), // i64::MAX
            ledger: Some(1),
        });
        assert_eq!(
            memo_id_of(&r),
            Some(i64::MAX),
            "memo string equal to i64::MAX must be attributed correctly"
        );
    }

    #[test]
    fn memo_id_above_i64_max_is_unattributed_not_error() {
        // "9223372036854775808" is i64::MAX + 1 — parse::<i64>() fails → must return None.
        let mut r = rec();
        r.transaction = Some(TransactionRecord {
            memo_type: Some("id".into()),
            memo: Some("9223372036854775808".into()), // i64::MAX + 1
            ledger: Some(1),
        });
        assert_eq!(
            memo_id_of(&r),
            None,
            "memo string one above i64::MAX must be silently unattributed (current documented behavior)"
        );
    }

    #[test]
    fn operation_index_from_toid_parses_correctly() {
        // Packed Horizon TOIDs: (ledger << 32) | (tx_order << 12) | (op_index + 1).
        assert_eq!(operation_index_from_toid("12884905985"), Some(0)); // ledger 3, tx 1, op 1
        assert_eq!(operation_index_from_toid("12884905986"), Some(1));
        assert_eq!(operation_index_from_toid("53021371310086"), Some(5));
        assert_eq!(operation_index_from_toid("4294963001036900"), Some(99));
    }

    #[test]
    fn operation_index_from_toid_handles_invalid_format() {
        for bad in [
            "",
            "abc",
            "12345-1-0",
            "+12884905985",
            "-12884905985",
            "9223372036854775808",
        ] {
            assert_eq!(operation_index_from_toid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn operation_index_from_toid_handles_edge_cases() {
        // op order 0 is the transaction's own TOID; op order 101 exceeds MAX_OPS_PER_TX.
        assert_eq!(operation_index_from_toid("12884905984"), None);
        assert_eq!(operation_index_from_toid("12884906085"), None);
        // tx order 0 and ledger 0 are never produced by Horizon.
        assert_eq!(operation_index_from_toid("12884901889"), None);
        assert_eq!(operation_index_from_toid("4097"), None);
        // Ledger i32::MAX is representable but implausible.
        assert_eq!(operation_index_from_toid("9223372032559812609"), None);
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        // Fuzz test asserting that operation_index_from_toid never panics on arbitrary string inputs.
        #[test]
        fn operation_index_from_toid_never_panics_on_arbitrary_input(
            input in ".*"
        ) {
            let _ = operation_index_from_toid(&input);
        }

        // Fuzz test asserting any successfully extracted operation index is non-negative and within valid bounds.
        #[test]
        fn operation_index_from_toid_extracted_value_is_always_within_the_documented_valid_range_when_some(
            input in prop_oneof![
                ".*",
                "[0-9]{1,19}-[0-9]{1,10}-[0-9]{1,10}",
                "[ \t]*[0-9]+-[0-9]+-[0-9]+[ \t]*",
                "-?[0-9]+--?[0-9]+--?[0-9]+",
                "\\PC*",
            ]
        ) {
            if let Some(idx) = operation_index_from_toid(&input) {
                prop_assert!(idx >= 0 && idx <= i32::MAX);
            }
        }
    }
}
