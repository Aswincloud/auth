// Runs against the built dist/. `npm test` builds first.
// Uses Node's built-in test runner — no test framework dependency.
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement as h } from "react";

import {
  hashPassword,
  verifyPassword,
  signToken,
  verifyToken,
  isOwner,
  parseAllowlist,
  newUlid,
  randomSecret,
  sha256Hex,
  createSessionCookie,
  readSession,
  clearSessionCookie,
  serializeCookie,
  readCookie,
  constantTimeEqual,
  b64urlEncode,
  b64urlDecode,
  emailAllowed,
  parseDomains,
  parseAccessMode,
  signRelay,
  verifyRelay,
} from "../dist/index.js";

import {
  startOAuth,
  handleOAuthCallback,
  configuredProviders,
  isProviderConfigured,
  providerName,
  clearStateCookie,
} from "../dist/oauth.js";

import { LoginPage, SsoButtons } from "../dist/react/index.js";

// ---------------------------------------------------------------- encoding
test("b64url round-trips arbitrary bytes", () => {
  const bytes = new Uint8Array([0, 1, 250, 255, 64, 63]);
  assert.deepEqual(b64urlDecode(b64urlEncode(bytes)), bytes);
});

test("constantTimeEqual", () => {
  assert.ok(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])));
  assert.ok(!constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])));
  assert.ok(!constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])));
});

// ---------------------------------------------------------------- passwords
test("password hash verifies and rejects", async () => {
  const h1 = await hashPassword("hunter2");
  assert.ok(h1.startsWith("pbkdf2$100000$"));
  assert.ok(await verifyPassword("hunter2", h1));
  assert.ok(!(await verifyPassword("wrong", h1)));
});

test("verifyPassword rejects malformed stored hash", async () => {
  assert.ok(!(await verifyPassword("x", "not-a-hash")));
  assert.ok(!(await verifyPassword("x", "pbkdf2$5$a$b"))); // iterations too low
});

// ---------------------------------------------------------------- tokens
test("signToken / verifyToken round-trip and purpose binding", async () => {
  const t = await signToken("secret", "user-1", "session", 3600);
  assert.equal(await verifyToken("secret", t, "session"), "user-1");
  assert.equal(await verifyToken("secret", t, "confirm"), null); // wrong purpose
  assert.equal(await verifyToken("wrong-secret", t, "session"), null);
  assert.equal(await verifyToken("secret", t + "x", "session"), null); // tampered
});

test("verifyToken rejects expired", async () => {
  const t = await signToken("secret", "u", "session", -1);
  assert.equal(await verifyToken("secret", t, "session"), null);
});

test("verifyToken returns null (not throws) on malformed/garbage tokens", async () => {
  // atob() throws a DOMException on non-base64 input; a bad token is "invalid",
  // not an error — these must all resolve to null, never reject.
  for (const bad of ["garbage.token", "...", "a.b.c", "!!!.???", ".", "x."]) {
    assert.equal(await verifyToken("secret", bad, "session"), null, `for ${JSON.stringify(bad)}`);
  }
});

// ---------------------------------------------------------------- random
test("newUlid is 26 chars and time-sortable", () => {
  const a = newUlid(1000);
  const b = newUlid(2000);
  assert.equal(a.length, 26);
  assert.ok(a < b);
});

test("randomSecret + sha256Hex", async () => {
  assert.notEqual(randomSecret(), randomSecret());
  assert.match(await sha256Hex("abc"), /^[0-9a-f]{64}$/);
});

// ---------------------------------------------------------------- owner allowlist
test("isOwner allowlist semantics", () => {
  assert.ok(isOwner("a@x.com, b@x.com", "B@X.COM")); // case-insensitive
  assert.ok(!isOwner("a@x.com", "c@x.com"));
  assert.ok(isOwner("", "anyone@x.com")); // empty allowlist => any
  assert.ok(!isOwner("a@x.com", "")); // empty email never owner
  assert.equal(parseAllowlist("a@x.com, ,b@x.com").size, 2);
});

// ---------------------------------------------------------------- cookies + session
test("serializeCookie defaults are hardened", () => {
  const c = serializeCookie("sess", "v", { maxAgeSeconds: 60 });
  assert.ok(c.includes("HttpOnly") && c.includes("Secure") && c.includes("SameSite=Lax"));
  assert.ok(c.includes("Max-Age=60"));
});

test("readCookie extracts a value", () => {
  const req = new Request("https://x.com", { headers: { Cookie: "a=1; sess=hello; b=2" } });
  assert.equal(readCookie(req, "sess"), "hello");
  assert.equal(readCookie(req, "missing"), null);
});

test("session cookie round-trips", async () => {
  const cfg = { secret: "s", cookieName: "sess" };
  const setCookie = await createSessionCookie(cfg, "owner@x.com");
  const value = setCookie.split(";")[0].split("=").slice(1).join("=");
  const req = new Request("https://x.com", { headers: { Cookie: `sess=${value}` } });
  assert.equal(await readSession(cfg, req), "owner@x.com");
  assert.ok(clearSessionCookie(cfg).includes("Max-Age=0"));
});

// ---------------------------------------------------------------- oauth: config
test("configuredProviders filters by credentials", () => {
  const cfg = {
    clients: {
      google: { clientId: "a", clientSecret: "b" },
      github: { clientId: "c", clientSecret: "d" },
      microsoft: { clientId: "e", clientSecret: "f" },
    },
    stateSecret: "x",
    redirectUri: (p) => `https://s.com/${p}`,
  };
  assert.deepEqual(configuredProviders(cfg), ["google", "github", "microsoft"]);

  const partial = { ...cfg, clients: { google: cfg.clients.google } };
  assert.deepEqual(configuredProviders(partial), ["google"]);
  assert.ok(!isProviderConfigured(partial, "github"));
  assert.equal(providerName("microsoft"), "Microsoft");
});

const OAUTH = {
  clients: {
    google: { clientId: "g-id", clientSecret: "g-sec" },
    github: { clientId: "gh-id", clientSecret: "gh-sec" },
    microsoft: { clientId: "ms-id", clientSecret: "ms-sec", tenantId: "my-tenant" },
  },
  stateSecret: "state-secret",
  redirectUri: (p) => `https://site.com/api/auth/oauth/${p}/callback`,
};

// ---------------------------------------------------------------- oauth: authorize URLs
test("google authorize url", async () => {
  const res = await startOAuth(OAUTH, "google");
  assert.equal(res.status, 302);
  const u = new URL(res.headers.get("Location"));
  assert.equal(u.origin + u.pathname, "https://accounts.google.com/o/oauth2/v2/auth");
  assert.equal(u.searchParams.get("scope"), "openid email profile");
  assert.equal(u.searchParams.get("access_type"), "online");
  assert.equal(u.searchParams.get("prompt"), "select_account");
  assert.equal(u.searchParams.get("redirect_uri"), "https://site.com/api/auth/oauth/google/callback");
  // state cookie matches the state param + is hardened
  const state = u.searchParams.get("state");
  const setCookie = res.headers.get("Set-Cookie");
  assert.ok(setCookie.includes(`oauth_state=${state}`));
  assert.ok(setCookie.includes("HttpOnly") && setCookie.includes("Secure"));
});

test("github authorize url", async () => {
  const u = new URL((await startOAuth(OAUTH, "github")).headers.get("Location"));
  assert.equal(u.origin + u.pathname, "https://github.com/login/oauth/authorize");
  assert.equal(u.searchParams.get("scope"), "read:user user:email");
  assert.equal(u.searchParams.get("access_type"), null); // no google-only params
});

test("microsoft authorize url uses tenant + response_mode", async () => {
  const u = new URL((await startOAuth(OAUTH, "microsoft")).headers.get("Location"));
  assert.equal(u.pathname, "/my-tenant/oauth2/v2.0/authorize");
  assert.equal(u.searchParams.get("response_mode"), "query");
  assert.ok(u.searchParams.get("scope").includes("User.Read"));
});

test("microsoft defaults to common tenant", async () => {
  const cfg = { ...OAUTH, clients: { microsoft: { clientId: "x", clientSecret: "y" } } };
  const u = new URL((await startOAuth(cfg, "microsoft")).headers.get("Location"));
  assert.ok(u.pathname.startsWith("/common/oauth2"));
});

test("startOAuth on unconfigured provider returns 503", async () => {
  const cfg = { ...OAUTH, clients: { google: OAUTH.clients.google } };
  assert.equal((await startOAuth(cfg, "github")).status, 503);
});

// ---------------------------------------------------------------- oauth: callback rejections (no network)
test("callback rejects missing state cookie (CSRF)", async () => {
  const r = await handleOAuthCallback(OAUTH, "google", new Request("https://site.com/cb?code=x&state=abc"));
  assert.deepEqual(r, { ok: false, error: "bad_state" });
});

test("callback rejects state mismatch (CSRF)", async () => {
  const req = new Request("https://site.com/cb?code=x&state=abc", { headers: { Cookie: "oauth_state=other" } });
  assert.equal((await handleOAuthCallback(OAUTH, "google", req)).error, "bad_state");
});

test("callback rejects forged (unsigned) state even if cookie matches param", async () => {
  const req = new Request("https://site.com/cb?code=x&state=forged", { headers: { Cookie: "oauth_state=forged" } });
  assert.equal((await handleOAuthCallback(OAUTH, "google", req)).error, "bad_state");
});

test("callback rejects missing code", async () => {
  const req = new Request("https://site.com/cb?state=abc", { headers: { Cookie: "oauth_state=abc" } });
  assert.equal((await handleOAuthCallback(OAUTH, "google", req)).error, "missing_code");
});

test("callback surfaces provider error param", async () => {
  const r = await handleOAuthCallback(OAUTH, "google", new Request("https://site.com/cb?error=access_denied"));
  assert.equal(r.error, "provider_error:access_denied");
});

test("clearStateCookie expires the cookie", () => {
  assert.ok(clearStateCookie(OAUTH).includes("Max-Age=0"));
});

// ---------------------------------------------------------------- react UI
test("LoginPage renders form with defaults", () => {
  const html = renderToStaticMarkup(h(LoginPage, {}));
  assert.ok(html.includes('type="email"'));
  assert.ok(html.includes('type="password"'));
  assert.ok(html.includes("Welcome back"));
  assert.ok(!html.includes("Create account")); // no links unless hrefs given
});

test("LoginPage renders links + sso slot when provided", () => {
  const html = renderToStaticMarkup(
    h(LoginPage, {
      signupHref: "/signup",
      forgotHref: "/forgot",
      ssoSlot: h(SsoButtons, { providers: ["google"] }),
    }),
  );
  assert.ok(html.includes("Create account"));
  assert.ok(html.includes("/forgot"));
  assert.ok(html.includes("/api/auth/oauth/google/start"));
});

test("SsoButtons renders all three providers", () => {
  const html = renderToStaticMarkup(h(SsoButtons, { providers: ["google", "github", "microsoft"] }));
  assert.equal((html.match(/\/start/g) || []).length, 3);
  assert.ok(html.includes("/api/auth/oauth/google/start"));
  assert.ok(html.includes("/api/auth/oauth/github/start"));
  assert.ok(html.includes("/api/auth/oauth/microsoft/start"));
});

test("SsoButtons renders nothing for empty list", () => {
  assert.equal(renderToStaticMarkup(h(SsoButtons, { providers: [] })), "");
});

// ---------------------------------------------------------------- access policy
test("parseDomains normalizes + strips @", () => {
  const d = parseDomains(" Aswincloud.com, @Example.COM ,, ");
  assert.deepEqual([...d].sort(), ["aswincloud.com", "example.com"]);
  assert.equal(parseDomains(undefined).size, 0);
});

test("parseAccessMode falls back to owners on unknown/empty", () => {
  assert.equal(parseAccessMode("public"), "public");
  assert.equal(parseAccessMode("DOMAIN"), "domain");
  assert.equal(parseAccessMode("owners"), "owners");
  assert.equal(parseAccessMode("nonsense"), "owners");
  assert.equal(parseAccessMode(undefined), "owners");
});

test("emailAllowed: public mode lets any non-empty email in", () => {
  assert.equal(emailAllowed({ mode: "public", email: "anyone@x.com" }), true);
  assert.equal(emailAllowed({ mode: "public", email: "" }), false);
  assert.equal(emailAllowed({ mode: "public", email: "   " }), false);
});

test("emailAllowed: owners mode is the strict allowlist", () => {
  const owners = "me@x.com, you@y.com";
  assert.equal(emailAllowed({ mode: "owners", email: "ME@X.com", owners }), true);
  assert.equal(emailAllowed({ mode: "owners", email: "stranger@z.com", owners }), false);
  // empty owners ⇒ isOwner treats as "anyone" — document that callers must supply owners.
  assert.equal(emailAllowed({ mode: "owners", email: "any@x.com", owners: "" }), true);
  assert.equal(emailAllowed({ mode: "owners", email: "", owners }), false);
});

test("emailAllowed: domain mode allows in-domain + explicit owners, rejects others", () => {
  const domains = "aswincloud.com";
  const owners = "guest@gmail.com";
  assert.equal(emailAllowed({ mode: "domain", email: "a@aswincloud.com", domains }), true);
  assert.equal(emailAllowed({ mode: "domain", email: "a@OTHER.com", domains }), false);
  // off-domain owner still allowed (union)
  assert.equal(emailAllowed({ mode: "domain", email: "guest@gmail.com", domains, owners }), true);
  // no owners list ⇒ off-domain rejected (must NOT inherit isOwner empty="anyone")
  assert.equal(emailAllowed({ mode: "domain", email: "x@other.com", domains, owners: "" }), false);
  // malformed email ⇒ false
  assert.equal(emailAllowed({ mode: "domain", email: "no-at-sign", domains }), false);
  assert.equal(emailAllowed({ mode: "domain", email: "trailing@", domains }), false);
});

// ---------------------------------------------------------------- broker relay
test("signRelay / verifyRelay round-trips claims", async () => {
  const tok = await signRelay("site-secret", { email: "u@x.com", provider: "google", nonce: "n1" });
  const claims = await verifyRelay("site-secret", tok);
  assert.deepEqual(claims, { email: "u@x.com", provider: "google", nonce: "n1" });
});

test("relay carries providerUserId when present, omits it otherwise", async () => {
  // Present: round-trips and is returned.
  const withId = await signRelay("s", { email: "u@x.com", provider: "github", nonce: "n", providerUserId: "12345" });
  assert.deepEqual(await verifyRelay("s", withId), {
    email: "u@x.com",
    provider: "github",
    nonce: "n",
    providerUserId: "12345",
  });
  // Absent: claims have no providerUserId key (back-compat with single-key sites).
  const without = await signRelay("s", { email: "u@x.com", provider: "google", nonce: "n" });
  const claims = await verifyRelay("s", without);
  assert.equal("providerUserId" in claims, false);
  // Empty string is treated as absent (not packed).
  const empty = await signRelay("s", { email: "u@x.com", provider: "google", nonce: "n", providerUserId: "" });
  assert.equal("providerUserId" in (await verifyRelay("s", empty)), false);
});

test("verifyRelay rejects wrong secret, tamper, expiry, malformed", async () => {
  const tok = await signRelay("site-a-secret", { email: "u@x.com", provider: "github", nonce: "n" });
  assert.equal(await verifyRelay("site-b-secret", tok), null); // different site's secret
  assert.equal(await verifyRelay("site-a-secret", tok + "x"), null); // tampered
  assert.equal(await verifyRelay("site-a-secret", "garbage.token"), null); // malformed (0.3.1 fix)
  const expired = await signRelay("site-a-secret", { email: "u@x.com", provider: "google", nonce: "n" }, -1);
  assert.equal(await verifyRelay("site-a-secret", expired), null); // expired
});

test("verifyRelay rejects a token signed for a different purpose", async () => {
  // A session token must not pass as a relay (purpose binding).
  const sess = await signToken("site-secret", "u@x.com", "session", 3600);
  assert.equal(await verifyRelay("site-secret", sess), null);
});
