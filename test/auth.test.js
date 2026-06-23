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
