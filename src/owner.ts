/**
 * Owner allowlist parsing. console/auth.ts and status/auth.ts both parsed a
 * comma-separated OWNER_EMAILS env var the same way; here once.
 *
 * Semantics match the originals: an EMPTY allowlist means "allow any
 * authenticated user" (callers decide whether that's acceptable).
 */

export function parseAllowlist(raw: string | undefined): Set<string> {
  return new Set(
    (raw ?? "")
      .split(",")
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean),
  );
}

export function isOwner(raw: string | undefined, email: string): boolean {
  const allow = parseAllowlist(raw);
  const e = email.trim().toLowerCase();
  if (!e) return false;
  // Empty allowlist => any authenticated email is the owner.
  if (allow.size === 0) return true;
  return allow.has(e);
}
