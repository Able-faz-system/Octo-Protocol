-- Migration 0021: add a CHECK constraint on wallets.sealed_scheme to ensure valid scheme versions.
--
-- Supported scheme versions:
--   1 = AES-256-GCM + HKDF-SHA256 (current)
--
-- This constraint also enables testing statement-level atomicity: an invalid scheme value
-- violates the check constraint, causing Postgres to reject the single UPDATE statement in
-- `Store::reseal_wallet` and leave the row completely unchanged (zero partial updates).

ALTER TABLE wallets ADD CONSTRAINT wallets_sealed_scheme_check CHECK (
    sealed_scheme IS NULL OR sealed_scheme >= 1
);