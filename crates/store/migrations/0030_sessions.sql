-- Server-side login sessions (issue #435).
--
-- Every dashboard JWT carries the id of its session row (`sid` claim). A token is accepted only
-- while that row is unrevoked, so a user can list their sessions and kill any one of them
-- immediately. Refresh rotates the token but keeps the session id.
--
-- `user_agent_hash` is SHA-256 hex of the User-Agent header — enough to tell devices apart
-- without storing the raw header. Tokens issued before this migration carry no `sid`; they stay
-- valid until expiry, and "revoke all other sessions" kills them by bumping `session_epoch`.

CREATE TABLE sessions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_agent_hash TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ
);

-- GET /v1/auth/sessions: a user's live sessions, most recently used first.
CREATE INDEX idx_sessions_user_active ON sessions (user_id, last_seen_at DESC)
    WHERE revoked_at IS NULL;

-- Pruning: DELETE FROM sessions WHERE expires_at < ...
CREATE INDEX idx_sessions_expires ON sessions (expires_at);
