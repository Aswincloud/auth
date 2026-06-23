/**
 * Google OIDC sign-in for owner-only sites.
 *
 * STATUS: stub. The working implementation lives in status/src/auth.ts
 * (handleLogin / handleCallback / handleLogout, with state-cookie CSRF and the
 * "bounce home with ?auth=<code>" UX). This module will lift that logic,
 * dropping the status-specific banner choice and taking the redirect targets
 * as config so any site can use it.
 *
 * shiptrack/src/lib/oauth.ts is the second reference (multi-provider).
 */

export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  /** Absolute callback URL, e.g. https://site.com/api/auth/callback */
  redirectUri: string;
  /** HMAC secret for the short-lived state cookie. */
  stateSecret: string;
}

export interface GoogleIdentity {
  email: string;
  emailVerified: boolean;
}

/** 302 to Google's consent screen; returns a Response that also sets the state cookie. */
export function startGoogleLogin(_cfg: GoogleOAuthConfig): Response {
  throw new Error("TODO: extract from status/src/auth.ts handleLogin");
}

/**
 * Handle the OAuth callback: verify state, exchange code, decode id_token.
 * Returns the verified identity, or null on any failure (caller decides UX).
 */
export async function handleGoogleCallback(
  _req: Request,
  _cfg: GoogleOAuthConfig,
): Promise<GoogleIdentity | null> {
  throw new Error("TODO: extract from status/src/auth.ts handleCallback");
}
