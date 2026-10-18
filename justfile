# octo dev tasks — run `just <task>`. Install: cargo install just
set dotenv-load := true

# List available tasks.
default:
    @just --list

# Build the whole workspace.
build:
    cargo build --workspace

# Run all tests.
test:
    cargo test --workspace

# Run live Stellar testnet tests (friendbot funding, balances) — hits the network.
test-live:
    OCTO_LIVE_TESTS=1 cargo test --workspace

# Format the code.
fmt:
    cargo fmt --all

# Check formatting (CI mode).
fmt-check:
    cargo fmt --all -- --check

# Lint with clippy, warnings as errors.
# NOTE: on toolchains built from a source tarball, clippy-driver rejects pre-compiled dependency
# rmeta with E0514 ("compiled by an incompatible version of rustc") even though its version matches
# rustc. If you hit that, it's the toolchain, not the code — clippy is enforced in CI instead.
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Dependency/license/advisory audit.
deny:
    cargo deny check

# Local pre-push checks that work on every toolchain (clippy + deny run in CI).
check: fmt-check test

# Everything CI runs (may fail locally on source-tarball toolchains due to the clippy E0514 bug).
ci: fmt-check lint test deny

# Start local Postgres.
db-up:
    docker compose up -d db

# Stop local services.
db-down:
    docker compose down

# Run database migrations.
migrate:
    sqlx migrate run --source crates/store/migrations

# Drop & recreate the dev database schema (destructive — local only).
db-reset:
    docker exec -i octo-db psql -U octo -d octo -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# Run the server.
run:
    cargo run -p octo-server

# Run the Bruno API-tests integration suite non-interactively against a local server.
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p octo-server
    cargo run -p octo-server &
    SERVER_PID=$!
    trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
    echo "Waiting for octo-server to be ready..."
    for i in $(seq 1 30); do
        if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
            echo "octo-server is ready."
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo "octo-server failed to start"
            exit 1
        fi
        sleep 1
    done
    npx -y @usebruno/cli run api-tests --env Local
