CREATE TABLE auth_lockouts (
    email           TEXT PRIMARY KEY,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    window_started  TIMESTAMPTZ NOT NULL DEFAULT now(),
    lockout_count   INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX auth_lockouts_locked_until_idx ON auth_lockouts (locked_until)
WHERE locked_until IS NOT NULL;
