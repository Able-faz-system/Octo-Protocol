-- Migration 0021: make ON DELETE RESTRICT explicit on all wallet foreign keys
-- Wallets are permanent records and cannot be deleted while dependent records exist.

ALTER TABLE addresses
    DROP CONSTRAINT addresses_wallet_id_fkey,
    ADD CONSTRAINT addresses_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;

ALTER TABLE transactions
    DROP CONSTRAINT transactions_wallet_id_fkey,
    ADD CONSTRAINT transactions_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;

ALTER TABLE withdrawals
    DROP CONSTRAINT withdrawals_wallet_id_fkey,
    ADD CONSTRAINT withdrawals_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;

ALTER TABLE webhook_endpoints
    DROP CONSTRAINT webhook_endpoints_wallet_id_fkey,
    ADD CONSTRAINT webhook_endpoints_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;

ALTER TABLE ingest_cursor
    DROP CONSTRAINT ingest_cursor_wallet_id_fkey,
    ADD CONSTRAINT ingest_cursor_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_wallet_id_fkey,
    ADD CONSTRAINT api_keys_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;

ALTER TABLE gas_sponsorship_configs
    DROP CONSTRAINT gas_sponsorship_configs_wallet_id_fkey,
    ADD CONSTRAINT gas_sponsorship_configs_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;

ALTER TABLE sponsored_transactions
    DROP CONSTRAINT sponsored_transactions_wallet_id_fkey,
    ADD CONSTRAINT sponsored_transactions_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;

ALTER TABLE withdrawal_allowlist_configs
    DROP CONSTRAINT withdrawal_allowlist_configs_wallet_id_fkey,
    ADD CONSTRAINT withdrawal_allowlist_configs_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;

ALTER TABLE whitelisted_addresses
    DROP CONSTRAINT whitelisted_addresses_wallet_id_fkey,
    ADD CONSTRAINT whitelisted_addresses_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;

ALTER TABLE payment_links
    DROP CONSTRAINT payment_links_wallet_id_fkey,
    ADD CONSTRAINT payment_links_wallet_id_fkey FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT;
