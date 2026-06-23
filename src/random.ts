/**
 * Random id / secret helpers, all Web Crypto. Lifted from console/crypto.ts.
 */

import { b64urlEncode } from "./encoding.js";

/** URL-safe random string. Default 32 bytes -> 43 base64url chars. */
export function randomSecret(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return b64urlEncode(buf);
}

const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32

/**
 * ULID: 48-bit ms timestamp + 80 bits randomness, Crockford base32, 26 chars.
 * Time-prefixed so ids sort by creation order — handy for D1 primary keys.
 */
export function newUlid(nowMs: number = Date.now()): string {
  let ts = nowMs;
  const time: string[] = [];
  for (let i = 9; i >= 0; i--) {
    time[i] = ULID_ALPHABET[ts % 32] as string;
    ts = Math.floor(ts / 32);
  }
  const rand = new Uint8Array(16);
  crypto.getRandomValues(rand);
  let r = "";
  for (let i = 0; i < 16; i++) r += ULID_ALPHABET[(rand[i] as number) % 32];
  return time.join("") + r;
}

/** sha256 -> lowercase hex. For hashing tokens/secrets before they touch D1. */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
