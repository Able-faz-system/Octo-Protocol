-- Email-change flow: a new OTP purpose. The OTP is bound (tx_hash_bound) to the new address.
ALTER TABLE email_otps DROP CONSTRAINT email_otps_purpose_check;
ALTER TABLE email_otps ADD CONSTRAINT email_otps_purpose_check
    CHECK (purpose IN ('signup', 'withdrawal', 'password_reset', 'email_change'));
