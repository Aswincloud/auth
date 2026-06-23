/**
 * A small session helper built on signToken/verifyToken + cookies. This is the
 * "owner-only site" sweet spot (status/console style): sign an email/userId into
 * an HMAC cookie, read it back, gate requests.
 *
 * Each site supplies its own secret + cookie name; nothing here links sites.
 */

import { signToken, verifyToken } from "./tokens.js";
import { serializeCookie, readCookie } from "./cookies.js";

export interface SessionConfig {
  /** HMAC secret, per-site. Keep it in a Worker secret, never commit it. */
  secret: string;
  /** Cookie name, e.g. "sess" or "myapp_session". */
  cookieName: string;
  /** Lifetime in seconds. Default 30 days. */
  ttlSeconds?: number;
}

const SESSION_PURPOSE = "session";
const DEFAULT_TTL = 30 * 24 * 60 * 60;

/** Create the Set-Cookie header value for a logged-in subject (email or userId). */
export async function createSessionCookie(cfg: SessionConfig, subject: string): Promise<string> {
  const ttl = cfg.ttlSeconds ?? DEFAULT_TTL;
  const token = await signToken(cfg.secret, subject, SESSION_PURPOSE, ttl);
  return serializeCookie(cfg.cookieName, token, { maxAgeSeconds: ttl });
}

/** Set-Cookie value that clears the session. */
export function clearSessionCookie(cfg: SessionConfig): string {
  return serializeCookie(cfg.cookieName, "", { maxAgeSeconds: 0 });
}

/** Returns the subject (email/userId) from a valid session cookie, else null. */
export async function readSession(cfg: SessionConfig, req: Request): Promise<string | null> {
  const token = readCookie(req, cfg.cookieName);
  if (!token) return null;
  return verifyToken(cfg.secret, token, SESSION_PURPOSE);
}
