# Architecture

## Database access

The server talks to Postgres through `octo-store`. In production it should connect as a
least-privilege runtime role (`octo_app`, `RUN_MIGRATIONS=false`) while a separate migrator role
applies migrations with `octo-server --migrate-only`. Roles, exact grants and the runbook:
[postgres-roles.md](postgres-roles.md).
