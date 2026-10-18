# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Security: `octo-server` exits non-zero on mainnet when secrets are placeholders or low-entropy,
  or when `HORIZON_URL` / `PUBLIC_APP_URL` / `PUBLIC_API_URL` are not HTTPS (#433).
- CI: CycloneDX SBOM (full transitive tree) uploaded on every `main` build and attached to
  releases (#432); every GitHub Action pinned to a commit SHA, enforced by a lint job (#431);
  weekly grouped Dependabot for cargo and Actions, with crypto-crate breaking bumps held for
  manual review and manifests routed to maintainers + security via CODEOWNERS (#430).
- Workspace scaffold: `crypto`, `wallet-core`, `store`, `webhooks`, `ingest`, `api` crates and
  the `server` binary.
- Repository tooling: CI (fmt, clippy, test, cargo-deny), `justfile`, `docker-compose` for local
  Postgres, contribution/security docs, MIT license.
- Pinned dependency set verified against the official SEP-0005 test vectors and Stellar muxed
  (`M...`) address round-trips.
- `octo-crypto`: AES-256-GCM seal/open of the HD seed at rest, with HKDF-SHA256 per-record
  subkeys, AAD context binding (records are bound to e.g. `octo:mainnet`), and zeroized
  plaintext/keys. Covered by 10 tests including tamper, wrong-key, and wrong-context negatives.
- Security: `docs/threat-model.md`; deny `unwrap`/`expect`/`panic` and lossy casts in
  secret-handling crates; CI adds cargo-audit and gitleaks.
- `octo-wallet-core`: SEP-0005 ed25519 derivation (`m/44'/148'/index'`, matches the official
  vector), muxed (`M...`) + `G...`+memo deposit addresses, and a payment signing path that opens
  the sealed seed, derives the key, builds **only** a Payment op (no raw-XDR signing oracle),
  signs, and zeroizes. 17 tests including non-positive-amount, bad-destination, and
  wrong-network-decryption negatives.
- `octo-store`: Postgres schema (wallets, addresses, transactions, withdrawals, webhook
  endpoints/deliveries, ingest cursor) and a sqlx `Store` API. Idempotent deposit recording
  (unique `(tx_hash, operation_index)` → anti double-credit), idempotency-keyed withdrawals,
  atomic row-locked muxed-id allocation, and a durable ingest cursor. Amounts are integer
  stroops. 6 integration tests against Postgres.
- `octo-wallet-core`: `provision_wallet`/`import_wallet` tie mnemonic generation, account
  derivation, and sealing into one call; `StellarNetwork::{as_str,parse}`.
- `octo-api`: axum REST service with `POST /v1/wallets` (generate → seal → store, returns the
  `G...` address + one-time recovery mnemonic), `GET /v1/wallets/:id`, and
  `POST|GET /v1/wallets/:id/addresses` (returns both the muxed `M...` and the `G...`+memo_id
  fallback). Standard `{statusCode,message,data}` envelope; errors never leak internals. 4
  integration tests drive the real router (incl. a check that the stored seed is ciphertext, not
  the plaintext mnemonic).
- `octo-api`: friendbot funding of new testnet accounts on wallet creation (`funded` flag), a
  `GET /v1/wallets/:id/balances` endpoint backed by a thin Horizon client, and a live testnet
  integration test (gated by `OCTO_LIVE_TESTS=1`) proving real on-chain funding + balance reads.
- `octo-ingest`: deposit detection. Polls a master account's Horizon `/payments` (oldest-first,
  from a persisted cursor), attributes each payment by **muxed id** or **transaction memo id**,
  and records it idempotently. Only `successful` txs are credited; dedup is on the Horizon
  operation id (TOID); unattributed deposits are quarantined (no `address_id`); amounts converted
  to integer stroops without floats. Migration `0002` adds `transactions.horizon_op_id` (unique).
  7 unit tests (amount + attribution) and 6 DB-backed `process()` tests.
- `octo-webhooks`: HMAC-SHA256 signed outbound delivery (`X-Octo-Signature`) with retry/backoff
  and a `webhook_deliveries` audit log; SSRF guard (`is_safe_url`) blocks loopback/private targets.
  Wired into `octo-ingest`: a newly-recorded deposit fires a `deposit.created` event that echoes
  the customer address `metadata` for reconciliation. New `POST /v1/wallets/:id/webhooks` endpoint
  registers an endpoint (generates a secret if omitted). Store gains webhook endpoint/delivery
  methods. Tests: signature roundtrip + tamper/wrong-secret rejection, SSRF blocking, and an
  end-to-end test delivering a signed webhook to a local sink and verifying the signature.
- `octo-api`: `POST /v1/wallets/:id/withdraw` — builds + signs a payment from the master wallet
  (decrypt → derive → sign → zeroize inside `wallet-core`), submits it to Horizon, and records the
  outcome. Idempotency-keyed (header or body): a retried key conflicts (409) **before** any signing
  or network call, so no double-spend. Horizon client gains `account_sequence` and
  `submit_transaction`; `octo-crypto::SealedSeed::from_parts` reconstructs a sealed seed from DB
  bytes; store gains `update_withdrawal_status`. Tests: hermetic validation + idempotency-conflict,
  and a **live testnet** test that withdraws 1 XLM between two funded wallets and confirms on-chain.
- `octo-server`: the deployable binary. Loads config from env (`.env` supported), connects +
  migrates Postgres, then runs the REST API (axum) and a deposit **ingest supervisor** (polls
  Horizon for all wallets on an interval, restart-safe via cursors) in one process. New
  `octo_ingest::Supervisor` fans out per-wallet polling; store gains `list_wallets`. Verified by
  booting the server and creating + friendbot-funding a wallet over real HTTP.
- Dashboard auth: `POST /v1/auth/signup`, `POST /v1/auth/login`, `GET /v1/auth/me`. Passwords
  hashed with **argon2id**; sessions are HS256 JWTs (hand-rolled with hmac/sha2 to avoid a heavy
  dependency). Login uses a single error for unknown-email vs. wrong-password (no enumeration).
  `users` migration (0003), store user methods, `JWT_SECRET` config, and permissive CORS for the
  browser dashboard. 5 auth integration tests.
- **Frontend** (`frontend/`): Next.js 16 + TypeScript + Tailwind v4 (App Router, pnpm). Burgundy
  landing page mirroring the Blockradar layout (sticky nav, hero, feature cards, developer code
  block, use cases, CTA, footer), plus split-screen **signup/login** pages wired to the auth API
  and a placeholder authed dashboard. API client + token storage in `src/lib`.
- Wallets are now owned by users: migration 0004 adds `wallets.user_id` + `description`;
  `POST /v1/wallets` requires auth and records the owner; new `GET /v1/wallets` lists the
  authenticated user's wallets. Dashboard: a sidebar/topbar shell, a home page showing "Your
  Master Wallets at a glance" with wallet cards, and a "New master wallet" form (network, name,
  description) that creates a wallet and reveals the 12-word recovery phrase once. Verified
  end-to-end against the running backend (signup → create → list, with 401 when unauthenticated).
- Wallet detail / Overview: new `GET /v1/wallets/:id/transactions` endpoint; the wallet card's
  **Manage** dropdown ("Go to dashboard" / "API settings"); a wallet-scoped sidebar
  (Overview/Assets/Transactions/Addresses) and an Overview page showing the wallet header, balance
  stat cards, an action row (New address / Refresh balances wired; Deposit/Withdraw stubbed),
  Assets, Addresses, and recent transactions — all fed by the real balances/addresses/transactions
  endpoints. "New address" creates a muxed address live. Verified via integration tests + curl.
- Per-wallet API keys for developer integration: migration 0005 `api_keys` (stores only a SHA-256
  hash + a non-secret display prefix). `POST /v1/wallets/:id/api-key` generates/regenerates and
  returns the full `octo_sk_test_…` key **once**; `GET` returns prefix + configured status, never
  the secret. Ownership-enforced (another user's wallet → 404). Frontend **Developers** page
  (reachable from the wallet sidebar and the card's Manage → "API settings"): Wallet ID, API Key
  (reveal/copy after generation), webhook/IP rows, status, and a curl quickstart. 2 integration
  tests (generate/get round-trip + ownership).
- API keys now authenticate requests: `authorize_wallet` accepts **either** a dashboard login JWT
  (whose user owns the wallet) **or** an `octo_sk_…` API key (which implies its wallet). Applied to
  all per-wallet address operations, reads (wallet/balances/transactions), and webhook registration
  — so a developer can integrate server-to-server with just their Wallet ID + API key. Withdrawals
  are **dashboard-only** (`require_login` rejects API keys). A key is scoped to its wallet
  (another wallet → 404) and unauthenticated requests now 401. 4 new integration tests
  (key-creates-address, key-scope-404, key-blocked-on-withdraw, unauthenticated-401).
- **Developer docs** at `/docs` (in the Next.js app, burgundy-styled, Blockradar-style structure):
  a sidebar nav + content shell with reusable doc primitives (Callout, Code, Step, ParamTable,
  Endpoint). Pages: Introduction (why Octo + muxed model), Getting Started (0-to-integration
  numbered walkthrough: wallet → API key → address → deposit webhook → withdraw), API Reference
  (Overview/envelope, Authentication, Addresses, Balances & Transactions, Withdrawals), Webhooks
  (event payload + HMAC signature verification with a Node snippet), and Security. Honest to what
  Octo actually is (Stellar/muxed, key vs login auth). Linked from the landing navbar.
- **Audit logs**: migration 0006 `audit_logs`; events recorded for signup, login, wallet creation,
  address generation, API-key generation, and withdrawals (with best-effort client IP from proxy
  headers). New `GET /v1/audit-logs` lists the user's activity, filterable by `category` and a
  case-insensitive `search`. A functional dashboard **Audit Logs** page (search box, category
  dropdown, table of Activity / User / Category / IP / Time with relative timestamps). Auditing is
  best-effort and never blocks the primary operation. Integration-tested.
