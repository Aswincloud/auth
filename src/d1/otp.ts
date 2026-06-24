// One-time-code helpers for email verification / passwordless. Reuses the core
// constant-time string compare instead of duplicating it (shiptrack had a copy).

import { constantTimeEqualString } from "../compare.js";

export const OTP_TTL_SECONDS = 10 * 60;
export const OTP_MAX_ATTEMPTS = 5;
export const OTP_RESEND_COOLDOWN_SECONDS = 60;

/** 6 digits, leading zeros preserved, crypto-random (no Math.random bias). */
export function generateOtp(): string {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return ((buf[0] as number) % 1_000_000).toString().padStart(6, "0");
}

/** sha256(code|pepper) hex. Pepper is the site's TOKEN_SECRET (not stored with the hash). */
export async function hashOtp(code: string, pepper: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${code}|${pepper}`));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Constant-time compare of two OTP hashes. */
export function otpHashEquals(a: string, b: string): boolean {
  return constantTimeEqualString(a, b);
}
