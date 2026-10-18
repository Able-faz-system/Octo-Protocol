-- Truncated response body from the endpoint's last attempt, so a merchant can diagnose a failed
-- delivery without reproducing the call. `response_code` (0001) already holds the HTTP status.
-- The CHECK caps growth even if a caller forgets to truncate (the sender stores at most 1 KiB).
ALTER TABLE webhook_deliveries
    ADD COLUMN response_body_snippet TEXT
        CHECK (response_body_snippet IS NULL OR octet_length(response_body_snippet) <= 1024);
