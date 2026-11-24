/**
 * Multi-provider OAuth 2 / OIDC client: Google, GitHub, Microsoft.
 *
 * Generalized from shiptrack/src/lib/oauth.ts and decoupled from that app's
 * AppEnv. Same authorization-code flow for every provider:
 *   1. startOAuth()          -> HMAC-signed state cookie + 302 to provider
 *   2. handleOAuthCallback() -> verify state, exchange code, fetch userinfo
 *                               -> returns a verified { providerUserId, email,
 *                                  emailVerified }, or null.
 *
 * No PKCE: the state cookie (HttpOnly, short-lived, HMAC-signed via signToken)
 * is sufficient CSRF protection for a confidential server-side flow.
 *
 * IMPORTANT: this module authenticates the user with the provider. It does NOT
 * touch any database. Linking the returned identity to a user row — and which
 * D1 it lives in — is the consuming site's job, which keeps every site's data
 * isolated (no cross-site linking).
 */

import { signToken, verifyToken } from "./tokens.js";
import { serializeCookie, readCookie } from "./cookies.js";
import { b64urlDecodeString } from "./encoding.js";

export type ProviderId = "google" | "github" | "microsoft";

export const ALL_PROVIDERS: readonly ProviderId[] = ["google", "github", "microsoft"];

export interface OAuthUser {
  providerUserId: string;
  email: string;
  emailVerified: boolean;
}

/** Per-provider client credentials. Omit a provider to leave it unconfigured. */
export interface OAuthClients {
  google?: { clientId: string; clientSecret: string };
  github?: { clientId: string; clientSecret: string };
  microsoft?: { clientId: string; clientSecret: string; tenantId?: string };
}

export interface OAuthConfig {
  clients: OAuthClients;
  /**
   * HMAC secret for the state cookie. Per-site; keep it in a Worker secret.
   */
  stateSecret: string;
  /**
   * Builds the callback URL for a provider. Most sites use a single pattern,
   * e.g. (p) => `${origin}/api/auth/oauth/${p}/callback`.
   */
  redirectUri: (provider: ProviderId) => string;
  /** State cookie name. Default "oauth_state". */
  stateCookieName?: string;
  /**
   * Reject identities whose email the provider hasn't verified (default true).
   * Set false to receive them with `emailVerified: false` and decide yourself —
   * e.g. sign them in as a separate account that is never linked to an
   * existing user by email. Never link an unverified email to an existing
   * account: for Microsoft that email is a free-text field any tenant admin
   * can set to anyone's address.
   */
  requireVerifiedEmail?: boolean;
}

const STATE_PURPOSE = "oauth_state";
const STATE_TTL_SECONDS = 10 * 60;
const DEFAULT_STATE_COOKIE = "oauth_state";

const PROVIDER_NAME: Record<ProviderId, string> = {
  google: "Google",
  github: "GitHub",
  microsoft: "Microsoft",
};

export function providerName(p: ProviderId): string {
  return PROVIDER_NAME[p];
}

function clientFor(cfg: OAuthConfig, provider: ProviderId) {
  return cfg.clients[provider] ?? null;
}

export function isProviderConfigured(cfg: OAuthConfig, provider: ProviderId): boolean {
  const c = clientFor(cfg, provider);
  return !!c && !!c.clientId && !!c.clientSecret;
}

/** The providers that actually have credentials — for rendering SSO buttons. */
export function configuredProviders(cfg: OAuthConfig): ProviderId[] {
  return ALL_PROVIDERS.filter((p) => isProviderConfigured(cfg, p));
}

function stateCookieName(cfg: OAuthConfig): string {
  return cfg.stateCookieName ?? DEFAULT_STATE_COOKIE;
}

// ---- authorize URL ---------------------------------------------------------

const SCOPES: Record<ProviderId, string> = {
  google: "openid email profile",
  github: "read:user user:email",
  microsoft: "openid email profile User.Read",
};

function microsoftTenant(cfg: OAuthConfig): string {
  return cfg.clients.microsoft?.tenantId || "common";
}

function buildAuthorizeUrl(cfg: OAuthConfig, provider: ProviderId, state: string): string {
  const client = clientFor(cfg, provider);
  if (!client) throw new Error(`provider not configured: ${provider}`);

  const params = new URLSearchParams({
    client_id: client.clientId,
    redirect_uri: cfg.redirectUri(provider),
    state,
    scope: SCOPES[provider],
    response_type: "code",
  });

  switch (provider) {
    case "google":
      params.set("access_type", "online");
      params.set("prompt", "select_account");
      return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
    case "github":
      return `https://github.com/login/oauth/authorize?${params}`;
    case "microsoft":
      params.set("response_mode", "query");
      return `https://login.microsoftonline.com/${microsoftTenant(cfg)}/oauth2/v2.0/authorize?${params}`;
  }
}

// ---- token exchange --------------------------------------------------------

function tokenUrl(cfg: OAuthConfig, provider: ProviderId): string {
  switch (provider) {
    case "google":
      return "https://oauth2.googleapis.com/token";
    case "github":
      return "https://github.com/login/oauth/access_token";
    case "microsoft":
      return `https://login.microsoftonline.com/${microsoftTenant(cfg)}/oauth2/v2.0/token`;
  }
}

interface TokenResponse {
  accessToken: string;
  /** OIDC ID token, when the provider returns one (Google, Microsoft). */
  idToken?: string;
}

async function exchangeCode(cfg: OAuthConfig, provider: ProviderId, code: string): Promise<TokenResponse> {
  const client = clientFor(cfg, provider);
  if (!client) throw new Error(`provider not configured: ${provider}`);

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: cfg.redirectUri(provider),
    client_id: client.clientId,
    client_secret: client.clientSecret,
  });

  const res = await fetch(tokenUrl(cfg, provider), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`token exchange ${res.status} ${txt.slice(0, 200)}`);
  }
  const json = (await res.json()) as { access_token?: string; id_token?: string; error?: string };
  if (!json.access_token) {
    throw new Error(`token exchange: no access_token (${json.error ?? "unknown"})`);
  }
  return { accessToken: json.access_token, idToken: json.id_token };
}

// ---- Microsoft ID token ----------------------------------------------------

interface MicrosoftIdClaims {
  aud?: string;
  iss?: string;
  tid?: string;
  exp?: number;
  email?: string;
  xms_edov?: boolean | string;
}

/**
 * Read the claims from a Microsoft ID token.
 *
 * The signature is not checked: the token came straight from Microsoft's token
 * endpoint over TLS in the back-channel code exchange, which OIDC Core §3.1.3.7
 * accepts in place of signature validation. The audience, expiry and issuer
 * are still checked so a token minted for another app can't be replayed here.
 * Throws on anything malformed or mismatched (the caller maps it to
 * "userinfo_failed").
 */
function readMicrosoftIdToken(idToken: string, clientId: string): MicrosoftIdClaims {
  const [, payload, , extra] = idToken.split(".");
  if (!payload || extra !== undefined) throw new Error("Microsoft id_token is not a JWT");
  let claims: MicrosoftIdClaims;
  try {
    claims = JSON.parse(b64urlDecodeString(payload)) as MicrosoftIdClaims;
  } catch {
    throw new Error("Microsoft id_token payload is unreadable");
  }
  if (claims.aud !== clientId) throw new Error("Microsoft id_token audience mismatch");
  if (typeof claims.exp !== "number" || claims.exp * 1000 <= Date.now()) {
    throw new Error("Microsoft id_token expired");
  }
  // With tenant "common" the issuer varies per tenant, but it must name the
  // same tenant as the token's own tid claim.
  if (!claims.tid || claims.iss !== `https://login.microsoftonline.com/${claims.tid}/v2.0`) {
    throw new Error("Microsoft id_token issuer mismatch");
  }
  return claims;
}

// ---- userinfo (per provider) ----------------------------------------------

async function fetchUser(cfg: OAuthConfig, provider: ProviderId, tokens: TokenResponse): Promise<OAuthUser> {
  const { accessToken } = tokens;
  switch (provider) {
    case "google": {
      const r = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!r.ok) throw new Error(`Google userinfo ${r.status}`);
      const j = (await r.json()) as { sub: string; email: string; email_verified?: boolean };
      // Only an explicit true counts; a missing claim is not a verification.
      return { providerUserId: j.sub, email: j.email, emailVerified: j.email_verified === true };
    }
    case "github": {
      const headers = {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "aswincloud-auth",
      };
      const ur = await fetch("https://api.github.com/user", { headers });
      if (!ur.ok) throw new Error(`GitHub /user ${ur.status}`);
      const u = (await ur.json()) as { id: number; email: string | null };

      let email = u.email ?? "";
      let verified = false;
      if (email) {
        // GitHub only surfaces a verified primary email on /user.
        verified = true;
      } else {
        const er = await fetch("https://api.github.com/user/emails", { headers });
        if (er.ok) {
          const emails = (await er.json()) as Array<{ email: string; primary: boolean; verified: boolean }>;
          const primary = emails.find((e) => e.primary) ?? emails[0];
          if (primary) {
            email = primary.email;
            verified = primary.verified;
          }
        }
      }
      if (!email) throw new Error("GitHub returned no email");
      return { providerUserId: String(u.id), email, emailVerified: verified };
    }
    case "microsoft": {
      const r = await fetch("https://graph.microsoft.com/v1.0/me", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!r.ok) throw new Error(`Microsoft Graph /me ${r.status}`);
      const j = (await r.json()) as { id: string; mail?: string; userPrincipalName?: string };

      // Graph's mail / userPrincipalName are free text that any tenant admin can
      // set to anyone's address, so on their own they prove nothing ("nOAuth").
      // Microsoft's signal is the xms_edov ID-token claim: true only when the
      // tenant has verified it owns the email's domain (personal Microsoft
      // accounts included). It is an optional claim — the app registration must
      // add `email` and `xms_edov` to the ID token, or every Microsoft login is
      // treated as unverified. When verified, use the ID token's email: that is
      // the address xms_edov vouches for.
      let verifiedEmail = "";
      if (tokens.idToken) {
        const claims = readMicrosoftIdToken(tokens.idToken, cfg.clients.microsoft?.clientId ?? "");
        const edov = claims.xms_edov === true || claims.xms_edov === "true";
        if (edov && claims.email) verifiedEmail = claims.email;
      }
      if (verifiedEmail) return { providerUserId: j.id, email: verifiedEmail, emailVerified: true };

      const email = j.mail ?? j.userPrincipalName ?? "";
      if (!email) throw new Error("Microsoft returned no email");
      return { providerUserId: j.id, email, emailVerified: false };
    }
  }
}

// ---- public flow -----------------------------------------------------------

/**
 * Start the OAuth dance for a provider: returns a 302 Response to the
 * provider's consent screen, with the signed state cookie attached.
 * Returns a 503 Response if the provider isn't configured.
 */
export async function startOAuth(cfg: OAuthConfig, provider: ProviderId): Promise<Response> {
  if (!isProviderConfigured(cfg, provider)) {
    return new Response(JSON.stringify({ error: "provider_not_configured" }), {
      status: 503,
      headers: { "Content-Type": "application/json" },
    });
  }
  // State is a signed nonce; we verify the signature on callback (so a forged
  // cookie can't pass) AND that it matches the returned state param.
  const state = await signToken(cfg.stateSecret, crypto.randomUUID(), STATE_PURPOSE, STATE_TTL_SECONDS);
  const url = buildAuthorizeUrl(cfg, provider, state);
  return new Response(null, {
    status: 302,
    headers: {
      Location: url,
      "Set-Cookie": serializeCookie(stateCookieName(cfg), state, { maxAgeSeconds: STATE_TTL_SECONDS }),
    },
  });
}

/** Set-Cookie value that clears the state cookie. */
export function clearStateCookie(cfg: OAuthConfig): string {
  return serializeCookie(stateCookieName(cfg), "", { maxAgeSeconds: 0 });
}

export type OAuthCallbackResult =
  | { ok: true; user: OAuthUser }
  | { ok: false; error: string };

/**
 * Handle the provider callback. Verifies state (cookie matches param AND is a
 * valid signed nonce), exchanges the code, fetches the user. Never throws.
 *
 * Returns { ok:true, user } on success, or { ok:false, error } with a stable
 * code ("bad_state" | "missing_code" | "token_exchange_failed" |
 * "userinfo_failed" | "email_not_verified" | "provider_error:<x>"). The caller
 * decides the redirect/UX and does any DB work.
 */
export async function handleOAuthCallback(
  cfg: OAuthConfig,
  provider: ProviderId,
  req: Request,
): Promise<OAuthCallbackResult> {
  if (!isProviderConfigured(cfg, provider)) return { ok: false, error: "provider_not_configured" };

  const url = new URL(req.url);
  const providerError = url.searchParams.get("error");
  if (providerError) return { ok: false, error: `provider_error:${providerError}` };

  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");
  if (!code || !stateParam) return { ok: false, error: "missing_code" };

  // CSRF: returned state must equal the cookie, and the cookie must be a valid
  // signed nonce (so neither a forged cookie nor a replayed param passes alone).
  const cookieState = readCookie(req, stateCookieName(cfg));
  if (!cookieState || cookieState !== stateParam) return { ok: false, error: "bad_state" };
  const stateValid = (await verifyToken(cfg.stateSecret, stateParam, STATE_PURPOSE)) !== null;
  if (!stateValid) return { ok: false, error: "bad_state" };

  let tokens: TokenResponse;
  try {
    tokens = await exchangeCode(cfg, provider, code);
  } catch {
    return { ok: false, error: "token_exchange_failed" };
  }

  let user: OAuthUser;
  try {
    user = await fetchUser(cfg, provider, tokens);
  } catch {
    return { ok: false, error: "userinfo_failed" };
  }

  if (!user.emailVerified && cfg.requireVerifiedEmail !== false) {
    return { ok: false, error: "email_not_verified" };
  }
  user.email = user.email.toLowerCase();
  return { ok: true, user };
}
