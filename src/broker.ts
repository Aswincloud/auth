/**
 * Relay hand-off between a central OAuth broker and a registered site.
 *
 * A broker authenticates the user with a provider (Google/GitHub/Microsoft)
 * against ONE OAuth client, then must tell the originating site "this verified
 * email signed in". The relay is an HMAC token signed with a PER-SITE shared
 * secret (RELAY_SECRET): the broker holds every site's secret in its registry;
 * each site holds only its own and verifies with it. So a relay forged for one
 * site can't be replayed against another.
 *
 * Short TTL + a per-request `nonce` (echoed from the site's start request) stop
 * replay. Reuses signToken/verifyToken — no new crypto. Pure, zero-dep.
 */

import { signToken, verifyToken } from "./tokens.js";

const RELAY_PURPOSE = "relay";
const DEFAULT_TTL_SECONDS = 120; // 2 min — a relay is redeemed immediately

export interface RelayClaims {
  /** The provider-verified email being asserted to the site. */
  email: string;
  /** Which provider vouched for it ("google" | "github" | "microsoft"). */
  provider: string;
  /** Opaque value the site generated and passed through ?nonce, echoed back to bind the round-trip. */
  nonce: string;
  /**
   * The provider's STABLE user id (e.g. Google `sub`, GitHub numeric id).
   * Optional: owner-only sites that match purely on email can ignore it, but
   * multi-user sites should link accounts on (provider, providerUserId) so a
   * provider email change doesn't orphan the account. Packed into the token only
   * when present, so tokens for sites that don't send it stay byte-identical to
   * before this field existed.
   */
  providerUserId?: string;
}

/**
 * Sign a relay token for a site. `relaySecret` is THAT site's shared secret.
 * The claims are JSON-packed into the token subject; the TTL defaults to 2 min.
 */
export function signRelay(
  relaySecret: string,
  claims: RelayClaims,
  ttlSeconds: number = DEFAULT_TTL_SECONDS,
): Promise<string> {
  const payload: { e: string; p: string; n: string; u?: string } = {
    e: claims.email,
    p: claims.provider,
    n: claims.nonce,
  };
  // Include the provider user id only when given, so single-key sites (status)
  // produce the same token shape as before this field existed.
  if (claims.providerUserId) payload.u = claims.providerUserId;
  return signToken(relaySecret, JSON.stringify(payload), RELAY_PURPOSE, ttlSeconds);
}

/**
 * Verify a relay token with the site's shared secret. Returns the claims, or
 * null if the signature/purpose/expiry is invalid or the payload is malformed.
 * Never throws (verifyToken already swallows malformed-token decode errors).
 */
export async function verifyRelay(relaySecret: string, token: string): Promise<RelayClaims | null> {
  const subject = await verifyToken(relaySecret, token, RELAY_PURPOSE);
  if (!subject) return null;
  try {
    const o = JSON.parse(subject) as { e?: unknown; p?: unknown; n?: unknown; u?: unknown };
    if (typeof o.e !== "string" || typeof o.p !== "string" || typeof o.n !== "string") return null;
    if (!o.e || !o.p) return null;
    const claims: RelayClaims = { email: o.e, provider: o.p, nonce: o.n };
    if (typeof o.u === "string" && o.u) claims.providerUserId = o.u; // optional
    return claims;
  } catch {
    return null;
  }
}
