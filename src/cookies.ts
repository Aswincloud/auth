/**
 * Cookie helpers. Unifies the secure-cookie builders duplicated in
 * status/auth.ts and shiptrack/auth.ts.
 */

export interface CookieOptions {
  maxAgeSeconds?: number;
  path?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "Lax" | "Strict" | "None";
}

/** Build a Set-Cookie header value with safe defaults (HttpOnly; Secure; SameSite=Lax; Path=/). */
export function serializeCookie(name: string, value: string, opts: CookieOptions = {}): string {
  const {
    maxAgeSeconds,
    path = "/",
    httpOnly = true,
    secure = true,
    sameSite = "Lax",
  } = opts;
  const parts = [`${name}=${value}`, `Path=${path}`];
  if (httpOnly) parts.push("HttpOnly");
  if (secure) parts.push("Secure");
  parts.push(`SameSite=${sameSite}`);
  if (maxAgeSeconds !== undefined) parts.push(`Max-Age=${maxAgeSeconds}`);
  return parts.join("; ");
}

/** Read a single cookie value out of a Request's Cookie header. */
export function readCookie(req: Request, name: string): string | null {
  const cookie = req.headers.get("Cookie") ?? "";
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${escaped}=([^;]+)`));
  return m && m[1] !== undefined ? decodeURIComponent(m[1]) : null;
}
