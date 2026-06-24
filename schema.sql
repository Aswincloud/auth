-- @aswincloud/auth — canonical auth schema for a site's OWN D1 database.
--
-- Run this once per site, against THAT site's database:
--   wrangler d1 execute <your-db> --remote --file=node_modules/@aswincloud/auth/schema.sql
--
-- Every table is IF NOT EXISTS, so re-running is safe. This file defines only
-- the auth tables; your site adds its own app tables in its own migrations.
-- Nothing here references another site — each database is fully self-contained.

-- One row per user of THIS site.
CREATE TABLE IF NOT EXISTS users (
  id             TEXT PRIMARY KEY,                       -- ULID/uuid (your choice)
  email          TEXT NOT NULL UNIQUE COLLATE NOCASE,    -- case-insensitive unique
  password_hash  TEXT NOT NULL,                          -- pbkdf2$... from hashPassword()
  email_verified INTEGER NOT NULL DEFAULT 0,             -- 0/1
  name           TEXT,                                   -- display name, nullable
  is_admin       INTEGER NOT NULL DEFAULT 0,             -- 0/1
  created_at     INTEGER NOT NULL                        -- epoch seconds
);

-- Existing DBs created before 0.2.0 (no name/is_admin columns): run once —
--   ALTER TABLE users ADD COLUMN name TEXT;
--   ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;

-- Linked social logins (Google / GitHub / Microsoft). A user can have several.
-- PK is (provider, provider_user_id) so the same provider account maps to one row.
CREATE TABLE IF NOT EXISTS oauth_identities (
  provider         TEXT NOT NULL,                        -- 'google' | 'github' | 'microsoft'
  provider_user_id TEXT NOT NULL,                        -- the id the provider returns
  user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email            TEXT,
  created_at       INTEGER NOT NULL,
  PRIMARY KEY (provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_identities_user ON oauth_identities(user_id);

-- One-time codes for passwordless / email verification (optional; only needed
-- if you use the OTP flow). Keyed by email so a new code overwrites the old.
CREATE TABLE IF NOT EXISTS otp_codes (
  email      TEXT PRIMARY KEY COLLATE NOCASE,
  code_hash  TEXT NOT NULL,                              -- sha256(code|pepper)
  expires_at INTEGER NOT NULL,                           -- epoch ms
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
