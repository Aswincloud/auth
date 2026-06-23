/**
 * base64url encode/decode (no padding).
 *
 * This exact pair was copy-pasted into 4 places across the sites
 * (console/crypto.ts, shiptrack/passwords.ts, shiptrack/tokens.ts,
 * status/auth.ts). It lives here once now.
 */

export function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Convenience: base64url a UTF-8 string. */
export function b64urlEncodeString(s: string): string {
  return b64urlEncode(new TextEncoder().encode(s));
}

/** Convenience: decode base64url back to a UTF-8 string. */
export function b64urlDecodeString(s: string): string {
  return new TextDecoder().decode(b64urlDecode(s));
}
