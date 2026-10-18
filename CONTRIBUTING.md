# Contributing to octo

Thanks for your interest! This project is built incrementally and values correctness and
security over speed (it handles crypto keys).

## Development setup

- **Rust 1.84.1** — pinned via `rust-toolchain.toml`; `rustup` will install it automatically.
- **Docker** — for the local Postgres (`docker compose up -d db`).
- **just** — task runner (`cargo install just`), optional but recommended.

```bash
cp .env.example .env
just build && just test
```

## Before opening a PR

Run the same checks CI runs:

```bash
just fmt        # cargo fmt
just lint       # cargo clippy -- -D warnings
just test       # cargo test
cargo deny check   # licenses + advisories (cargo install cargo-deny)
```

All of `fmt --check`, `clippy -D warnings`, and the test suite must pass.

## Integration & Load Testing

### Bruno API Collection Tests
The HTTP API routes and challenge-signing scripts can be executed end-to-end non-interactively:

```bash
just test-integration
```

Or manually:
```bash
cd api-tests/scripts && npm install
npx @usebruno/cli run api-tests --env Local
```

**Environment Variables (`api-tests/environments/Local.bru`):**
- `base_url`: The target API server URL (defaults to `http://localhost:8080`).
- Ensure `octo-server` has valid environment variables configured in `.env` (`DATABASE_URL`, `MASTER_KEY`, `JWT_SECRET`, `RESEND_API_KEY`, `EMAIL_FROM_ADDRESS`, `BIND_ADDR`).

### Concurrency Load Tests
High-concurrency stress tests (such as budget reservation under 100-way concurrency) are marked `#[ignore]` so they do not slow down default test runs. To run explicitly:

```bash
cargo test -p octo-store --test store_tests sponsorship_budget_reservation_under_100_way_concurrency_never_exceeds_budget -- --ignored --nocapture
```

> **Troubleshooting `E0514: found crate X compiled by an incompatible version of rustc`.**
> This appears when `target/` holds artifacts from two different `rustc` builds that share a
> version string but not their internal metadata format — e.g. a system `/usr/bin/rustc` vs. a
> rustup-managed toolchain, or after running `cargo clippy` (whose `clippy-driver` writes rmeta a
> plain `rustc` build then rejects). **Fix: `cargo clean && cargo test --workspace`** — a single
> clean rebuild makes all artifacts come from one toolchain. To avoid it: use one `cargo`
> consistently, and don't run `cargo clippy` locally on source-tarball toolchains (clippy is
> enforced in CI on an official toolchain). `cargo build`/`test`/`fmt` are otherwise unaffected.

## Conventions

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
  `docs:`, `refactor:`, `test:`, `chore:`).
- **Secrets:** never log seeds, private keys, or decrypted material. Secret-bearing types live in
  `wallet-core` and must `zeroize` on drop.
- **Tests:** crypto and derivation code must include test vectors (e.g. SEP-0005).
- **Migrations:** `crates/store/migrations/` is forward-only and append-only. Every PR adding a migration must also update the decision index in `docs/migrations.md` in the same PR.

## Branching

Work on a feature branch; open a PR against `main`. CI must be green before merge.
