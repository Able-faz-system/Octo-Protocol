-- Forgot-password flow: a new OTP purpose, plus a per-user session epoch.
--
-- JWTs are stateless, so "sign out everywhere" needs a server-side counter: every token carries the
-- epoch it was issued under, and bumping it (on password reset) invalidates all older tokens at once.
ALTER TABLE email_otps DROP CONSTRAINT email_otps_purpose_check;
ALTER TABLE email_otps ADD CONSTRAINT email_otps_purpose_check
    CHECK (purpose IN ('signup', 'withdrawal', 'password_reset'));

ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;
