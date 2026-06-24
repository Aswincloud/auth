// D1 data layer for the canonical users / oauth_identities / otp_codes tables
// (see schema.sql). Lifted and generalized from shiptrack's lib/db.ts — same
// parameterized-SQL discipline, with watch/* and resend_api_key dropped.
//
// Every function takes the D1Database as its first arg; the site owns the
// binding (env.DB). All timestamps are epoch SECONDS.

import type { D1Database } from "@cloudflare/workers-types";
import type { UserRow, ListedUser, OtpRow } from "./types.js";

const nowSec = () => Math.floor(Date.now() / 1000);

// ---- users -----------------------------------------------------------------

export async function getUserByEmail(db: D1Database, email: string): Promise<UserRow | null> {
  const row = await db.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first<UserRow>();
  return row ?? null;
}

export async function getUserById(db: D1Database, id: string): Promise<UserRow | null> {
  const row = await db.prepare(`SELECT * FROM users WHERE id = ?`).bind(id).first<UserRow>();
  return row ?? null;
}

export async function createUser(
  db: D1Database,
  u: { id: string; email: string; passwordHash: string; name?: string | null; isAdmin?: boolean; emailVerified?: boolean },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO users (id, email, password_hash, email_verified, is_admin, name, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      u.id,
      u.email,
      u.passwordHash,
      u.emailVerified ? 1 : 0,
      u.isAdmin ? 1 : 0,
      u.name ? u.name.trim().slice(0, 80) || null : null,
      nowSec(),
    )
    .run();
}

export async function markEmailVerified(db: D1Database, userId: string): Promise<void> {
  await db.prepare(`UPDATE users SET email_verified = 1 WHERE id = ?`).bind(userId).run();
}

export async function updateUserName(db: D1Database, userId: string, name: string | null): Promise<void> {
  const cleaned = name ? name.trim().slice(0, 80) : "";
  await db.prepare(`UPDATE users SET name = ? WHERE id = ?`).bind(cleaned || null, userId).run();
}

export async function updateUserPasswordHash(db: D1Database, userId: string, passwordHash: string): Promise<void> {
  await db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).bind(passwordHash, userId).run();
}

/** Change email, with a friendly conflict result instead of a raw UNIQUE error. */
export async function updateUserEmail(
  db: D1Database,
  userId: string,
  newEmail: string,
): Promise<{ ok: boolean; conflict?: boolean }> {
  const existing = await db
    .prepare(`SELECT id FROM users WHERE email = ? AND id != ?`)
    .bind(newEmail, userId)
    .first<{ id: string }>();
  if (existing) return { ok: false, conflict: true };
  await db.prepare(`UPDATE users SET email = ? WHERE id = ?`).bind(newEmail, userId).run();
  return { ok: true };
}

export async function setUserAdmin(db: D1Database, userId: string, isAdmin: boolean): Promise<void> {
  await db.prepare(`UPDATE users SET is_admin = ? WHERE id = ?`).bind(isAdmin ? 1 : 0, userId).run();
}

export async function deleteUser(db: D1Database, userId: string): Promise<void> {
  // D1 doesn't guarantee PRAGMA foreign_keys per connection, so clean up the
  // dependent rows explicitly rather than relying on ON DELETE CASCADE.
  await db.prepare(`DELETE FROM oauth_identities WHERE user_id = ?`).bind(userId).run();
  await db.prepare(`DELETE FROM users WHERE id = ?`).bind(userId).run();
}

export async function listUsers(db: D1Database): Promise<ListedUser[]> {
  const res = await db
    .prepare(
      `SELECT id, email, email_verified, is_admin, name, created_at
       FROM users ORDER BY created_at DESC`,
    )
    .all<ListedUser>();
  return res.results ?? [];
}

export async function countAdmins(db: D1Database): Promise<number> {
  const row = await db.prepare(`SELECT COUNT(*) AS n FROM users WHERE is_admin = 1`).first<{ n: number }>();
  return row?.n ?? 0;
}

export async function listAdminEmails(db: D1Database): Promise<string[]> {
  const res = await db
    .prepare(`SELECT email FROM users WHERE is_admin = 1 AND email_verified = 1`)
    .all<{ email: string }>();
  return (res.results ?? []).map((r) => r.email);
}

// ---- oauth identities ------------------------------------------------------

export async function getUserByOAuthIdentity(
  db: D1Database,
  provider: string,
  providerUserId: string,
): Promise<UserRow | null> {
  const row = await db
    .prepare(
      `SELECT u.* FROM users u
       JOIN oauth_identities oi ON oi.user_id = u.id
       WHERE oi.provider = ? AND oi.provider_user_id = ?`,
    )
    .bind(provider, providerUserId)
    .first<UserRow>();
  return row ?? null;
}

export async function linkOAuthIdentity(
  db: D1Database,
  args: { provider: string; providerUserId: string; userId: string; email?: string | null },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO oauth_identities (provider, provider_user_id, user_id, email, created_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(provider, provider_user_id) DO UPDATE SET user_id = excluded.user_id, email = excluded.email`,
    )
    .bind(args.provider, args.providerUserId, args.userId, args.email ?? null, nowSec())
    .run();
}

// ---- otp codes -------------------------------------------------------------

export async function upsertOtp(db: D1Database, email: string, codeHash: string, expiresAt: number): Promise<void> {
  await db
    .prepare(
      `INSERT INTO otp_codes (email, code_hash, expires_at, attempts, created_at)
       VALUES (?, ?, ?, 0, ?)
       ON CONFLICT(email) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at, attempts = 0, created_at = excluded.created_at`,
    )
    .bind(email, codeHash, expiresAt, nowSec())
    .run();
}

export async function getOtp(db: D1Database, email: string): Promise<OtpRow | null> {
  const row = await db.prepare(`SELECT * FROM otp_codes WHERE email = ?`).bind(email).first<OtpRow>();
  return row ?? null;
}

export async function incrementOtpAttempts(db: D1Database, email: string): Promise<void> {
  await db.prepare(`UPDATE otp_codes SET attempts = attempts + 1 WHERE email = ?`).bind(email).run();
}

export async function deleteOtp(db: D1Database, email: string): Promise<void> {
  await db.prepare(`DELETE FROM otp_codes WHERE email = ?`).bind(email).run();
}
