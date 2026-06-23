/**
 * HMAC-SHA256 signed tokens:  <base64url(payload)>.<base64url(sig)>
 *
 * Extracted from shiptrack/tokens.ts and generalized. Used for sessions,
 * email-confirm links, password-reset links, OAuth state, etc. The `purpose`
 * is bound into the signature so a confirm token can't be replayed as a
 * session token.
 *
 * NOTE: purpose is a free-form string here (shiptrack hardcoded a union). Each
 * site picks its own purposes; keep them stable since they're part of the
 * signed payload.
 */

import { b64urlEncode, b64urlDecode } from "./encoding.js";
import { constantTimeEqual } from "./compare.js";

interface Payload {
  /** subject — the userId / email / watchId this token is about */
  s: string;
  /** purpose — bound into the signature */
  p: string;
  /** expiry, epoch seconds (optional = never expires) */
  e?: number;
}

async function hmac(secret: string, data: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return new Uint8Array(sig);
}

export async function signToken(
  secret: string,
  subject: string,
  purpose: string,
  expSeconds?: number,
): Promise<string> {
  const payload: Payload = { s: subject, p: purpose };
  if (expSeconds) payload.e = Math.floor(Date.now() / 1000) + expSeconds;
  const body = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = b64urlEncode(await hmac(secret, body));
  return `${body}.${sig}`;
}

/** Returns the subject if the token is valid for `purpose` and unexpired, else null. */
export async function verifyToken(
  secret: string,
  token: string,
  purpose: string,
): Promise<string | null> {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts as [string, string];
  const expected = await hmac(secret, body);
  const actual = b64urlDecode(sig);
  if (!constantTimeEqual(expected, actual)) return null;
  let payload: Payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body))) as Payload;
  } catch {
    return null;
  }
  if (payload.p !== purpose) return null;
  if (payload.e && payload.e < Math.floor(Date.now() / 1000)) return null;
  return payload.s ?? null;
}
