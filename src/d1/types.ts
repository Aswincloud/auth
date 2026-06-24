// Shared types for the D1-backed user-management layer.
//
// import type ensures @cloudflare/workers-types is erased at compile time
// (verbatimModuleSyntax) — it stays a devDep, never a runtime dependency.
import type { D1Database } from "@cloudflare/workers-types";

export type { D1Database };

/** A user row in the package's canonical `users` table (see schema.sql). */
export interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  email_verified: number; // 0/1
  is_admin: number; // 0/1
  name: string | null;
  created_at: number; // epoch SECONDS
}

/** A lighter projection for listing users (no password hash). */
export interface ListedUser {
  id: string;
  email: string;
  email_verified: number;
  is_admin: number;
  name: string | null;
  created_at: number;
}

export interface OtpRow {
  email: string;
  code_hash: string;
  expires_at: number; // epoch seconds
  attempts: number;
  created_at: number; // epoch seconds
}

/**
 * Sentinel stored in password_hash for OAuth-only accounts (created via social
 * login, never set a password). Shaped like a real pbkdf2$ hash so
 * verifyPassword() returns false for any input, but recognizable so the
 * change-password flow knows not to demand a "current password".
 */
export const OAUTH_ONLY_HASH = "pbkdf2$100000$oauth_only$oauth_only";

/** True if the user has set a real password (vs. being OAuth-only). */
export function hasRealPassword(u: Pick<UserRow, "password_hash">): boolean {
  return u.password_hash !== OAUTH_ONLY_HASH;
}

/**
 * Pluggable email sender. The package NEVER hardcodes a provider — each site
 * injects this (Resend, MailChannels, SES, …). Throw on failure; flows that
 * must not leak (e.g. requestPasswordReset) swallow it internally.
 */
export type EmailSender = (args: {
  to: string;
  subject: string;
  html: string;
  text?: string;
}) => Promise<void>;
