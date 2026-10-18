# Sealed-seed versioning

Every persisted sealed seed carries an explicit `sealed_scheme` value. The value is part of the
storage contract: readers must select a supported decoder from it and must never guess, downgrade,
or silently fall back when a scheme is unknown.

## Compatibility contract

| Scheme | Status | Construction | Required open operation |
|---|---|---|---|
| `0` | invalid sentinel | Never emitted | Reject and migrate the row |
| `1` | supported legacy | AES-256-GCM with HKDF-SHA256 and network AAD | `open` |
| `2` | supported current | Scheme 1 plus the owning account ID in AAD | `open_with_account_id` |
| other | unsupported | Reserved for future versions | Reject as `UnknownScheme` |

Network context is authenticated data. A seed sealed for mainnet, testnet, or standalone cannot be
opened by any operation under another network. Scheme 2 also prevents a ciphertext copied between
accounts from being opened under the recipient row.

## Adding a scheme

1. Add a new constant and an explicit decoder; do not change an existing scheme's meaning.
2. Keep old readers until every row has been resealed and rollback is no longer required.
3. Extend cross-network, cross-account, tamper, and unknown-version regression coverage.
4. Update the database constraint and `docs/migrations.md` in the same change.
5. Roll out readers before writers, migrate in bounded batches, then retire the old writer.

Key rotation does not by itself require a new scheme. Use the migration flow in
[`runbook-migrate-keys.md`](runbook-migrate-keys.md) when the construction and AAD remain unchanged.
