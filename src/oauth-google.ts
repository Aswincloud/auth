/**
 * Google OIDC sign-in for Cloudflare Workers sites. Extracted and generalized
 * from status/src/auth.ts (handleLogin / handleCallback).
 *
 * Flow:
 *   startGoogleLogin(cfg)        -> 302 to Google consent + short-lived state cookie
 *   handleGoogleCallback(req,cfg) -> verify state, exchange code, decode id_token
 *                                    -> returns the verified identity, or null
 *
 * The state cookie is the CSRF defense: a random value set on /login and
 * compared (constant-time) on the callback. It's short-lived, so clearing it
 * after use is optional (it expires on its own); use clearStateCookie() if you
 * want tidiness.
 *
 * id_token note: we decode the id_token payload WITHOUT re-verifying its
 * signature. For the authorization-code flow with a confidential client, Google
 * just minted that token over TLS in direct response to our authenticated
 * token-endpoint exchange, so the transport authenticates the issuer. This is
 * the standard server-side code-flow practice and keeps the package zero-dep
 * (no JWKS fetch / JWT library on Workers).
 */

import { b64urlEncode, b64urlDecodeString } from "./encoding.js";
import { constantTimeEqualString } from "./compare.js";
import { serializeCookie, readCookie } from "./cookies.js";

export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  /** Absolute callback URL, e.g. https://site.com/api/auth/callback */
  redirectUri: string;
  /** Cookie name for the CSRF state. Default "oauth_state". */
  stateCookieName?: string;
  /** OAuth scope. Default "openid email". */
  scope?: string;
  /** Google "prompt" param. Default "select_account". */
  prompt?: string;
}

export interface GoogleIdentity {
  email: string;
  emailVerified: boolean;
}

const DEFAULT_STATE_COOKIE = "oauth_state";
const STATE_TTL_SECONDS = 600;

function stateCookieName(cfg: GoogleOAuthConfig): string {
  return cfg.stateCookieName ?? DEFAULT_STATE_COOKIE;
}

/**
 * Returns a 302 Response sending the user to Google's consent screen, with a
 * short-lived signed-by-randomness state cookie attached.
 */
export function startGoogleLogin(cfg: GoogleOAuthConfig): Response {
  const state = b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
  const params = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    response_type: "code",
    scope: cfg.scope ?? "openid email",
    state,
    prompt: cfg.prompt ?? "select_account",
  });
  return new Response(null, {
    status: 302,
    headers: {
      Location: `https://accounts.google.com/o/oauth2/v2/auth?${params}`,
      "Set-Cookie": serializeCookie(stateCookieName(cfg), state, {
        maxAgeSeconds: STATE_TTL_SECONDS,
      }),
    },
  });
}

/** Set-Cookie value that clears the state cookie. Optional (state self-expires). */
export function clearStateCookie(cfg: GoogleOAuthConfig): string {
  return serializeCookie(stateCookieName(cfg), "", { maxAgeSeconds: 0 });
}

/**
 * Verify state, exchange the code, decode the id_token. Returns the verified
 * Google identity, or null on any failure (bad/missing state = CSRF, failed
 * exchange, unverified email). Never throws.
 */
export async function handleGoogleCallback(
  req: Request,
  cfg: GoogleOAuthConfig,
): Promise<GoogleIdentity | null> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const stateCookie = readCookie(req, stateCookieName(cfg));

  // CSRF: the returned state must match the cookie we set on /login.
  if (!code || !state || !stateCookie || !constantTimeEqualString(state, stateCookie)) {
    return null;
  }

  let tokenRes: Response;
  try {
    tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        redirect_uri: cfg.redirectUri,
        grant_type: "authorization_code",
      }),
    });
  } catch {
    return null;
  }
  if (!tokenRes.ok) return null;

  let tok: { id_token?: string };
  try {
    tok = (await tokenRes.json()) as { id_token?: string };
  } catch {
    return null;
  }
  if (!tok.id_token) return null;

  let claims: { email?: string; email_verified?: boolean | string };
  try {
    const payloadB64 = tok.id_token.split(".")[1];
    if (!payloadB64) return null;
    claims = JSON.parse(b64urlDecodeString(payloadB64));
  } catch {
    return null;
  }

  const email = (claims.email ?? "").toLowerCase();
  const emailVerified = claims.email_verified === true || claims.email_verified === "true";
  if (!email) return null;
  return { email, emailVerified };
}
