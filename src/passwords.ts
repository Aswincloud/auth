/**
 * PBKDF2-SHA256 password hashing. Extracted verbatim from shiptrack.
 *
 * Stored format:  pbkdf2$<iterations>$<salt_b64url>$<hash_b64url>
 * 100k iterations (Cloudflare Workers caps PBKDF2 at 100k), 16-byte salt,
 * 32-byte hash. Verify is constant-time over the derived hash.
 */

import { b64urlEncode, b64urlDecode } from "./encoding.js";
import { constantTimeEqual } from "./compare.js";

const ITERATIONS = 100_000;
const SALT_BYTES = 16;
const HASH_BYTES = 32;

async function derive(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    key,
    HASH_BYTES * 8,
  );
  return new Uint8Array(bits);
}

export async function hashPassword(plain: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await derive(plain, salt, ITERATIONS);
  return `pbkdf2$${ITERATIONS}$${b64urlEncode(salt)}$${b64urlEncode(hash)}`;
}

export async function verifyPassword(plain: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 1000) return false;
  const salt = b64urlDecode(parts[2] as string);
  const expected = b64urlDecode(parts[3] as string);
  const actual = await derive(plain, salt, iterations);
  return constantTimeEqual(expected, actual);
}
