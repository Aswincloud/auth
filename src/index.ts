/**
 * @aswincloud/auth — core entry point.
 *
 * Pure Web Crypto. Zero runtime dependencies. Runs on any Cloudflare Worker
 * (and Node >=18). Each consuming site supplies its own secrets and binds its
 * own D1 database; this package never links sites together.
 *
 * The React login UI is a separate entry point: `@aswincloud/auth/react`.
 */

// encoding / compare / random
export {
  b64urlEncode,
  b64urlDecode,
  b64urlEncodeString,
  b64urlDecodeString,
} from "./encoding.js";
export { constantTimeEqual, constantTimeEqualString } from "./compare.js";
export { randomSecret, newUlid, sha256Hex } from "./random.js";

// passwords
export { hashPassword, verifyPassword } from "./passwords.js";

// signed tokens
export { signToken, verifyToken } from "./tokens.js";

// cookies + sessions + owner allowlist
export { serializeCookie, readCookie } from "./cookies.js";
export type { CookieOptions } from "./cookies.js";
export {
  createSessionCookie,
  clearSessionCookie,
  readSession,
} from "./session.js";
export type { SessionConfig } from "./session.js";
export { parseAllowlist, isOwner } from "./owner.js";

// OAuth (Google) — currently stubbed; see source TODOs
export {
  startGoogleLogin,
  handleGoogleCallback,
} from "./oauth-google.js";
export type { GoogleOAuthConfig, GoogleIdentity } from "./oauth-google.js";
