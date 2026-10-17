ALTER TABLE api_keys
    ADD COLUMN scopes TEXT[] NOT NULL DEFAULT ARRAY['read', 'write', 'sponsor']::TEXT[],
    ADD COLUMN last_used_at TIMESTAMPTZ,
    ADD COLUMN expires_at TIMESTAMPTZ;

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_scopes_nonempty CHECK (cardinality(scopes) > 0),
    ADD CONSTRAINT api_keys_expiry_after_creation CHECK (expires_at IS NULL OR expires_at > created_at);

CREATE INDEX idx_api_keys_expires_at ON api_keys(expires_at) WHERE expires_at IS NOT NULL;
