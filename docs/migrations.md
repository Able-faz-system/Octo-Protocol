# Database Migrations Decision Index & Audit Trail

`crates/store/migrations/` is strictly append-only and forward-only. Migrations must never be edited or reordered once merged.

This document serves as the single changelog-style decision index tracking every migration's structural changes, constraint choices, foreign key `ON DELETE` rules, and the reasoning behind non-obvious design decisions.

---

## Foreign Key `ON DELETE` Audit & Invariants

| Parent Table | Child Table | Foreign Key Column | `ON DELETE` Action | Security & Integrity Rationale |
|---|---|---|---|---|
| `wallets` | `addresses` | `wallet_id` | `CASCADE` | Ephemeral customer addresses derived from base wallet; safe to cascade on dev cleanup. |
| `wallets` | `transactions` | `wallet_id` | `RESTRICT` | Financial ledger integrity: a wallet with confirmed on-chain activity must never be hard-deleted. |
| `addresses` | `transactions` | `address_id` | `RESTRICT` | Ensures attribution history remains immutable. |
| `wallets` | `withdrawals` | `wallet_id` | `RESTRICT` | Outbound payment records and client idempotency keys must be preserved. |
| `wallets` | `webhook_endpoints` | `wallet_id` | `CASCADE` | Outbound endpoints belong strictly to their parent wallet. |
| `webhook_endpoints` | `webhook_deliveries` | `endpoint_id` | `CASCADE` (historical) | **Audit Note (Issue #338)**: Hard deletion of an endpoint cascaded and erased delivery history. Migration 0021 introduced `deleted_at` soft-deletion so endpoints can be retired while keeping historical deliveries intact and queryable. |
| `wallets` | `ingest_cursor` | `wallet_id` | `CASCADE` | Horizon sync cursor has a 1:1 lifecycle with the wallet. |
| `users` | `wallets` | `user_id` | `SET NULL` | Preserves non-custodial wallets if an admin or dashboard user account is deleted. |
| `wallets` | `api_keys` | `wallet_id` | `CASCADE` | API keys derive their permissions solely from the parent wallet. |
| `users` | `audit_logs` | `user_id` | `CASCADE` | User-scoped audit events; system-level logs are archived independently. Since `0026` the cascade is the only non-retention path that may delete audit rows. |
| `wallets` | `gas_sponsorship_configs` | `wallet_id` | `CASCADE` | Sponsorship configuration is a 1:1 extension of the sponsoring wallet. |
| `wallets` | `sponsored_transactions` | `wallet_id` | `RESTRICT` | Fee-bump ledger must be preserved for audit and daily budget calculations. |
| `wallets` | `withdrawal_allowlist_configs` | `wallet_id` | `CASCADE` | Anti-fraud toggle tied directly to wallet lifecycle. |
| `wallets` | `whitelisted_addresses` | `wallet_id` | `CASCADE` | Destination address list tied to the parent wallet's allowlist configuration. |
| `wallets` | `payment_links` | `wallet_id` | `CASCADE` | Public checkout links belong to the merchant wallet. |
| `addresses` | `payment_links` | `address_id` | `CASCADE` | Initial shared fallback address for checkout link. |
| `payment_links` | `payment_link_payments` | `link_id` | `CASCADE` | Intents are bound to checkout link lifecycle. |
| `addresses` | `payment_link_payments` | `address_id` | `SET NULL` | Per-intent address mapping (Issue #338/0015): nullified rather than cascading payment records if address record is pruned. |
| `transactions` | `payment_link_payments` | `transaction_id` | `RESTRICT` | Payment settlement records cannot orphan confirmed transactions. |
| `users` | `email_otps` | `user_id` | `CASCADE` | Short-lived authentication codes expire or purge with user deletion. |

---

## Migration Decision Index

| Version | File | Target Tables / Objects | Key Decisions, Constraints & `ON DELETE` Rules | Rationale / Why |
|---|---|---|---|---|
| `0001` | `0001_init.sql` | `wallets`, `addresses`, `transactions`, `withdrawals`, `webhook_endpoints`, `webhook_deliveries`, `ingest_cursor` | `pgcrypto` extension; BIGINT stroops; `RESTRICT` on financial records (`transactions`, `withdrawals`); `CASCADE` on `webhook_deliveries`; partial unique on `(stellar_tx_hash, operation_index)`. | Baseline schema establishing financial integrity invariants, immutable ledger records, and AES-256-GCM ciphertext storage. |
| `0002` | `0002_horizon_op_id.sql` | `transactions`, `addresses` | Added `transactions.horizon_op_id` with partial unique index `uq_tx_horizon_op_id`; dropped redundant `uq_addresses_muxed`. | Robust idempotent deposit dedup using Horizon TOIDs (ledger+tx+op) regardless of operation index availability. |
| `0003` | `0003_users.sql` | `users` | Argon2id password hash, case-insensitive unique lowercase email constraint. | Core dashboard user authentication without reversible password storage. |
| `0004` | `0004_wallet_owner.sql` | `wallets` | Added `user_id UUID REFERENCES users(id) ON DELETE SET NULL`, `description TEXT`, index `idx_wallets_user`. | Links wallets to dashboard owners while preserving wallets if a user account is deleted. |
| `0005` | `0005_api_keys.sql` | `api_keys` | SHA-256 hash storage (`key_hash`), non-secret prefix, unique index on `wallet_id` for active keys, `ON DELETE CASCADE`. | Developer API keys stored securely as one-way hashes; replaces key upon regeneration. |
| `0006` | `0006_audit_logs.sql` | `audit_logs` | Append-only table referencing `users(id) ON DELETE CASCADE`, tracking action, category, target, and IP. | Persistent audit trail for compliance and user visibility across dashboard operations. |
| `0007` | `0007_gas_sponsorship.sql` | `gas_sponsorship_configs`, `sponsored_transactions` | Config `ON DELETE CASCADE`; `sponsored_transactions` `ON DELETE RESTRICT`, `UNIQUE (inner_tx_hash)`. | Enables fee-bump sponsorship with daily budget tracking and prevents duplicate inner transaction sponsorships. |
| `0008` | `0008_scheme_version.sql` | `wallets` | Added `sealed_scheme SMALLINT NOT NULL DEFAULT 1`. | Explicit cipher/KDF version tag enabling zero-downtime key rotation via `bin/migrate-keys`. |
| `0027` | `0027_api_key_lifecycle.sql` | `api_keys` | Added scopes, last-used timestamps, and optional expiry with supporting constraints/index. | Enables least-privilege keys and lifecycle enforcement without storing raw credentials. |
| `0009` | `0009_token_denylist.sql` | `token_denylist` | SHA-256 hash of revoked JWTs with `expires_at` timestamp. | Stateless JWT revocation on logout without storing raw token strings in database. |
| `0010` | `0010_sponsored_tx_status_index.sql` | `sponsored_transactions` | Replaced `(wallet_id, created_at)` with composite `(wallet_id, status, created_at DESC)`. | Aligns indexing with actual query filters (`wallet_id` + `status`) in hot fee-budget checks. |
| `0011` | `0011_sponsored_and_audit_indexing.sql` | `sponsored_transactions`, `audit_logs` | Partial index for pending fee reservations; `pg_trgm` extension and GIN trigram index on audit logs. | Accelerates rolling daily budget CTEs and enables fast ILIKE search over audit actions/targets. |
| `0012` | `0012_client_custody.sql` | `wallets` | Added `custody TEXT CHECK (custody IN ('server', 'client'))`; made `sealed_*` nullable. | Accommodates non-custodial wallets where server never holds the user's private key or seed. |
| `0013` | `0013_withdrawal_allowlist.sql` | `withdrawal_allowlist_configs`, `whitelisted_addresses` | Config toggle default false; `whitelisted_addresses` unique `(wallet_id, address)` with `ON DELETE CASCADE`. | Anti-fraud defense-in-depth allowing wallets to restrict destination accounts prior to submission. |
| `0014` | `0014_payment_links.sql` | `payment_links`, `payment_link_payments` | Public slug unique; `payment_link_payments` unique `transaction_id`; CASCADE on link deletion. | Supports public merchant checkout URLs and tracks payment intent state transitions. |
| `0015` | `0015_payment_intent_address.sql` | `payment_link_payments` | Added `address_id UUID REFERENCES addresses(id) ON DELETE SET NULL`; unique pending index. | Binds distinct deposit address per payment intent to prevent cross-matching concurrent payments. |
| `0016` | `0016_ingest_last_polled.sql` | `ingest_cursor` | Added `last_polled_at TIMESTAMPTZ` and index on `(wallet_id, last_polled_at)`. | Decouples polling tick checks from activity updates so supervisor backoff functions correctly on dormant wallets. |
| `0017` | `0017_payment_link_redirect_url.sql` | `payment_links` | Added `redirect_url TEXT`. | Merchant post-payment browser redirection; developer-provided passthrough with no SSRF exposure. |
| `0018` | `0018_payment_status_expansion.sql` | `payment_link_payments` | Expanded status CHECK constraint to include `'expired'`, `'underpaid'`, `'overpaid'`. | Prevents miscrediting mismatched deposits while preserving auditability of unexpected amounts. |
| `0019` | `0019_email_otp.sql` | `email_otps` | Table referencing `users(id) ON DELETE CASCADE`; code hash; purpose CHECK; optional `tx_hash_bound`. | Rate-limited email OTP verification for registration and high-risk withdrawal authorizations. |
| `0020` | `0020_username.sql` | `users` | Added `username TEXT` with unique partial index on `lower(username)`. | Case-insensitive unique display handles distinct from email addresses. |
| `0021` | `0021_soft_delete_webhook_endpoints.sql` | `webhook_endpoints` | Added `deleted_at TIMESTAMPTZ` and filtered indices on `(wallet_id)` where `deleted_at IS NULL`. | Soft-delete endpoint path (Issue #338) preventing accidental cascade-purges of `webhook_deliveries` logs. |
| `0026` | `0026_audit_logs_append_only.sql` | `audit_logs`; functions `audit_logs_retention_allowed`, `audit_logs_block_mutation`, `audit_logs_block_truncate` | `BEFORE UPDATE OR DELETE` row trigger and `BEFORE TRUNCATE` statement trigger raise `insufficient_privilege`. Bypass only for members of `octo_audit_retention` (created out-of-band) or a `DELETE` whose owning `users` row is already gone (FK cascade). Functions pin `search_path = pg_catalog, pg_temp` and schema-qualify `users` via `TG_TABLE_SCHEMA`. | Issue #438: append-only was a convention. A temp table can't spoof the checks; signup rollback still cascades. See `docs/postgres-roles.md`. |
| `0028` | `0028_rate_limit_buckets.sql` | `rate_limit_buckets` | `UNLOGGED`; PK `(key, class)`; index on `expires_at`; no foreign keys. | Shared fixed-window counters so API rate limits hold across replicas and restarts (Issue #445). Unlogged because losing counters on a Postgres crash only resets windows early. |
| `0032` | `0032_wallet_ingest_paused.sql` | `wallets` | Added `ingest_paused BOOLEAN NOT NULL DEFAULT false` and `ingest_paused_at TIMESTAMPTZ`; partial index `idx_wallets_ingest_active (network, id) WHERE ingest_paused = false`. No FK changes. | Issue #450: operators can stop polling a misbehaving wallet without deleting it. `ingest_cursor` is never touched by a pause, so resume continues from the saved paging token without gaps. |
| `0033` | `0033_transaction_history_filters.sql` | `transactions` | Added `idx_tx_wallet_created (wallet_id, created_at DESC, id DESC)` and `idx_tx_wallet_asset_created (wallet_id, asset_code, created_at DESC, id DESC)`; dropped the now-redundant `idx_tx_wallet`. No FK changes (the `RESTRICT` check on `wallet_id` is still served by the composite's leading column). | Issue #451: filtered history (`from`/`to`/`asset`/`status`) with keyset pagination on `(created_at, id)` is answered by one ordered index scan instead of a sort over every wallet row. |
| `0034` | `0034_idempotency_keys.sql` | `idempotency_keys` | PK `(wallet_id, scope, key)`; `wallet_id` → `wallets(id) ON DELETE CASCADE`; `key` length CHECK 1-255; SHA-256 `request_hash`; nullable `status_code`/`response` (NULL = in progress); index on `expires_at`. | Issue #453: a retried payment-link create replays the stored response instead of creating a duplicate, and reusing a key with a different body is a conflict. Rows expire after 24h and are purged hourly. They cascade with the wallet because they only cache its own responses. |

---

## Maintenance Convention

> **Mandatory Rule for PRs:**
> Any PR that adds a new migration file under `crates/store/migrations/` **must** append a new entry to the decision index table above within the same PR.
> The entry must document the migration version, filename, target schema objects, foreign key `ON DELETE` rules, constraints, and the design rationale.
