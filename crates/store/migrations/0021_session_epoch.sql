-- Per-user session epoch, embedded in every JWT. Bumping it (on password change) invalidates
-- every token issued before, without enumerating tokens into the deny-list.
ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;
