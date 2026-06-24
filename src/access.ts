/**
 * Per-site access policy: decide WHO may sign in to a site once a provider has
 * verified their email. Three modes, chosen per site (e.g. via an ACCESS_MODE
 * env the provisioner sets):
 *
 *   "public"  — any authenticated, non-empty email.
 *   "domain"  — only emails whose domain is in an allowlist (e.g. aswincloud.com).
 *   "owners"  — only emails in an explicit owner allowlist (the strict "only me").
 *
 * Pure + zero-dep; reuses the owner allowlist parsing. Never throws — a missing
 * or malformed email is simply not allowed. The provider still vouches for the
 * email's authenticity; this only decides whether that email is permitted here.
 */

import { isOwner, parseAllowlist } from "./owner.js";

export type AccessMode = "public" | "domain" | "owners";

/** Parse a comma-separated domain list. A leading "@" is tolerated and stripped. */
export function parseDomains(raw: string | undefined): Set<string> {
  return new Set(
    (raw ?? "")
      .split(",")
      .map((d) => d.trim().toLowerCase().replace(/^@/, ""))
      .filter(Boolean),
  );
}

/** Normalize an AccessMode from an env string; unknown/empty falls back to "owners" (safe default). */
export function parseAccessMode(raw: string | undefined): AccessMode {
  const m = (raw ?? "").trim().toLowerCase();
  return m === "public" || m === "domain" || m === "owners" ? m : "owners";
}

function domainOf(email: string): string | null {
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return null;
  return email.slice(at + 1).toLowerCase();
}

/**
 * Is this email allowed to sign in under the given policy?
 *
 * - public: any non-empty email.
 * - owners: email ∈ owners allowlist. (An EMPTY owners list means "anyone" per
 *   isOwner's semantics — callers wanting strict "only me" must supply owners.)
 * - domain: email's domain ∈ domains; owners (if any) are ALSO always allowed,
 *   so you can permit a whole domain plus a few outside guests.
 *
 * Never throws; a malformed/empty email returns false (except note the public
 * mode still requires a non-empty email).
 */
export function emailAllowed(args: {
  mode: AccessMode;
  email: string;
  owners?: string;
  domains?: string;
}): boolean {
  const email = (args.email ?? "").trim().toLowerCase();
  if (!email) return false;

  switch (args.mode) {
    case "public":
      return true;
    case "owners":
      return isOwner(args.owners, email);
    case "domain": {
      const dom = domainOf(email);
      if (dom && parseDomains(args.domains).has(dom)) return true;
      // Owners listed explicitly are allowed even if off-domain. Guard against
      // isOwner's empty-list="anyone" rule: only consult it when owners is non-empty.
      return parseAllowlist(args.owners).size > 0 && isOwner(args.owners, email);
    }
  }
}
