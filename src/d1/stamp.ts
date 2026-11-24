// Security stamp and constant-cost password checks.
//
// The stamp is a short fingerprint of the user's current password hash. It
// changes whenever the password changes (set, reset, or wiped to OAuth-only),
// so anything that embeds it — a password-reset link, an email-change link, a
// site's session token — stops working the moment the password changes. That
// makes reset links single-use and lets a site sign out every other session on
// a password change, with no extra column or revocation list.

import { sha256Hex } from "../random.js";
import { verifyPassword } from "../passwords.js";
import type { UserRow } from "./types.js";

/** 16 hex chars of sha256(password_hash). Not secret; just changes with the password. */
export async function securityStamp(user: Pick<UserRow, "password_hash">): Promise<string> {
  return (await sha256Hex(`stamp|${user.password_hash}`)).slice(0, 16);
}

// A real pbkdf2 hash of a random value nobody knows. Verifying against it costs
// the same as a real check, so a login for a non-existent account takes as long
// as one with a wrong password (no account-existence timing oracle).
const DUMMY_HASH =
  "pbkdf2$100000$ZHVtbXlzYWx0ZHVtbXlzYWx0$7O8mJz3QbF8hYw2q0kq6mF6u3nqf7m4G3b6g0pXkZ2Q";

/**
 * Check a password against a user's stored hash, or against a dummy hash when
 * there is no user, so both paths cost one PBKDF2. Always false for a missing
 * user.
 */
export async function verifyPasswordOrDummy(password: string, storedHash: string | null | undefined): Promise<boolean> {
  if (!storedHash) {
    await verifyPassword(password, DUMMY_HASH).catch(() => false);
    return false;
  }
  return verifyPassword(password, storedHash);
}
