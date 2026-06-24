# @aswincloud/auth

[![npm](https://img.shields.io/npm/v/@aswincloud/auth?color=cb3837&logo=npm)](https://www.npmjs.com/package/@aswincloud/auth)
[![CI](https://github.com/Aswincloud/auth/actions/workflows/ci.yml/badge.svg)](https://github.com/Aswincloud/auth/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![zero deps](https://img.shields.io/badge/dependencies-0-brightgreen)](#)

> Drop-in auth for Cloudflare Workers sites. Write the login plumbing **once**,
> reuse it across every site — each keeping its **own** database, fully isolated.

Shared, framework-agnostic auth primitives for Cloudflare Workers sites — signed
sessions, HMAC tokens, PBKDF2 password hashing, owner allowlists, and OAuth
(Google / GitHub / Microsoft) — plus an optional React login UI.

**Each consuming site brings its own D1 database and its own secrets. Nothing in
this package links sites together.** Security rests on your per-site
`SESSION_SECRET`, not on this code being private (it's public on purpose).

## Install

```sh
npm install @aswincloud/auth
```

## New site? Each gets its OWN database

This package never shares a database between sites — every site you build gets
its own isolated D1, so nothing is linked. Setting one up is one command:

```sh
# creates the D1, prints the binding to paste into wrangler.jsonc, applies the schema
npx aswincloud-auth-setup-db mysite-db
```

Or do it by hand:

```sh
npx wrangler d1 create mysite-db          # → copy the database_id it prints
# paste into wrangler.jsonc:
#   "d1_databases": [{ "binding": "DB", "database_name": "mysite-db",
#                      "database_id": "<id>" }]
npx wrangler d1 execute mysite-db --remote \
  --file=node_modules/@aswincloud/auth/schema.sql
```

`schema.sql` creates `users`, `oauth_identities`, and `otp_codes` — all
`IF NOT EXISTS`, so re-running is safe, and you add your own app tables
alongside them in your own migrations. Then set per-site secrets
(`SESSION_SECRET`, OAuth client ids).

## Two entry points

```ts
// Core — pure Web Crypto, zero deps, runs on any Worker.
import {
  hashPassword, verifyPassword,
  signToken, verifyToken,
  createSessionCookie, readSession, clearSessionCookie,
  isOwner,
} from "@aswincloud/auth";

// Optional React login UI — only multi-user sites need this.
import { LoginPage } from "@aswincloud/auth/react";
```

Owner-only Worker sites import only the core and never pull React in.

## Owner-only site (status / console style)

```ts
const session = { secret: env.SESSION_SECRET, cookieName: "sess" };

// after verifying the user (e.g. Google OAuth) and checking the allowlist:
if (!isOwner(env.OWNER_EMAILS, email)) return new Response("forbidden", { status: 403 });
const setCookie = await createSessionCookie(session, email);

// gate a request:
const who = await readSession(session, req);
if (!who) return Response.redirect(new URL("/api/auth/login", req.url), 302);
```

## Multi-user site (shiptrack style)

```ts
const hash = await hashPassword(plainPassword);          // on signup -> store in your D1
const ok = await verifyPassword(plainPassword, hash);    // on login
const setCookie = await createSessionCookie(session, userId);
```

## OAuth — Google, GitHub, Microsoft

One config drives all three providers. Configure only the ones you have
credentials for; `configuredProviders()` tells the UI which buttons to show.

```ts
import {
  startOAuth, handleOAuthCallback, configuredProviders, isOwner,
  createSessionCookie,
} from "@aswincloud/auth";

const origin = new URL(req.url).origin;
const oauth = {
  clients: {
    google:    { clientId: env.GOOGLE_CLIENT_ID,    clientSecret: env.GOOGLE_CLIENT_SECRET },
    github:    { clientId: env.GITHUB_CLIENT_ID,    clientSecret: env.GITHUB_CLIENT_SECRET },
    microsoft: { clientId: env.MICROSOFT_CLIENT_ID, clientSecret: env.MICROSOFT_CLIENT_SECRET,
                 tenantId: env.MICROSOFT_TENANT_ID }, // optional, defaults to "common"
  },
  stateSecret: env.STATE_SECRET,
  redirectUri: (p) => `${origin}/api/auth/oauth/${p}/callback`,
};

// GET /api/auth/oauth/:provider/start
return startOAuth(oauth, provider);   // 302 to provider + signed CSRF state cookie

// GET /api/auth/oauth/:provider/callback
const r = await handleOAuthCallback(oauth, provider, req);
if (!r.ok) return Response.redirect(`${origin}/login?oauth_error=${r.error}`, 302);
// r.user = { providerUserId, email, emailVerified } — verified by the provider.

// Owner-only site: gate on the allowlist.
if (!isOwner(env.OWNER_EMAILS, r.user.email)) return new Response("forbidden", { status: 403 });
const setCookie = await createSessionCookie(session, r.user.email);

// Multi-user site: look up / create the user in YOUR D1, then issue the session.
// The package never touches a database — each site keeps its own, fully isolated.
```

Provider notes: Google & Microsoft return verified emails; GitHub falls back to
`/user/emails` for the primary verified address. Microsoft uses your tenant in
the URL. CSRF is the HMAC-signed state cookie (checked against the returned
`state` param). Zero-dependency, pure `fetch` + Web Crypto.

## SSO buttons (React)

```tsx
import { SsoButtons } from "@aswincloud/auth/react";

// providers usually comes from configuredProviders(oauth) on the server
<SsoButtons providers={["google", "github", "microsoft"]} />
```

Renders `<a href="/api/auth/oauth/{provider}/start">` buttons with real
provider logos. Drop it into `<LoginPage ssoSlot={...} />` to get SSO + password
on one screen.

## React login UI

```tsx
import { LoginPage } from "@aswincloud/auth/react";

<LoginPage
  action="/api/auth/login"
  onSuccess={() => location.assign("/dashboard")}
  signupHref="/signup"
  forgotHref="/forgot"
/>;
```

Framework-agnostic — no `next/*` imports, so it runs on Next, Vite, or plain
React. Self-contained default styling; every element overridable via `styles`.
Navigation is yours via `onSuccess`. Drop SSO buttons in through `ssoSlot`.

## User-management flows — `@aswincloud/auth/d1`

A separate, opt-in entry point with DB-backed flows for multi-user sites:
signup + OTP verify, password reset, change password/username, self-service
email change, and account removal. The core stays zero-dep — only import `/d1`
where you need it.

Flows are **functions, not HTTP handlers**: each takes your D1 binding + plain
values and returns `{ ok: true, … } | { ok: false, error: "<code>" }` — never
throws. You own the routing, the session cookie, and the email provider.

```ts
import {
  signup, verifyOtp, requestPasswordReset, resetPassword,
  changePassword, requestEmailChange, confirmEmailChange, removeUser,
  type EmailSender,
} from "@aswincloud/auth/d1";
import { createSessionCookie } from "@aswincloud/auth";

// You inject the email provider — the package never hardcodes one:
const sendEmail: EmailSender = async ({ to, subject, html, text }) => {
  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.MAIL_FROM, to, subject, html, text }),
  });
};

// POST /api/auth/forgot
await requestPasswordReset(env.DB, {
  email, secret: env.TOKEN_SECRET, sendEmail, appUrl: origin,
}); // always { ok: true } — no account enumeration

// POST /api/auth/reset
const r = await resetPassword(env.DB, { token, newPassword, secret: env.TOKEN_SECRET });
if (!r.ok) return json({ error: r.error }, 400);

// POST /api/auth/verify  → issue the session yourself on success
const v = await verifyOtp(env.DB, { email, code, secret: env.TOKEN_SECRET });
if (v.ok) setCookie(await createSessionCookie(session, v.userId));
```

Pure email templates ship too (`passwordResetEmail`, `verifyEmail`, `otpEmail`,
`emailChangeEmail`, `accountDeletedEmail`) returning `{ subject, html, text }` —
use them or write your own. Matching React pages: `ForgotPasswordPage`,
`ResetPasswordPage`, `VerifyEmailPage` from `@aswincloud/auth/react`.

**Branded emails** — to keep your own look instead of the built-in template,
pass a `render*` override to the sending flows; it gets the dynamic bits and
returns `{ subject, html, text }`:

```ts
await signup(env.DB, { email, password, secret, sendEmail,
  renderOtp: ({ code, ttlMinutes }) => myOtpEmail({ code, ttlMinutes }) });
// likewise: requestPasswordReset → renderReset({ resetUrl, ttlHours }),
//           requestEmailChange   → renderEmailChange({ confirmUrl, newEmail, ttlHours }).
```

When omitted, the built-in template is used (app name via `appName`).

**Schema (0.2.0):** the `users` table gained `name` + `is_admin`. New sites get
them from `schema.sql`. **Existing DBs** (created before 0.2.0) — run once:

```sql
ALTER TABLE users ADD COLUMN name TEXT;
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
```

Sites using only the core primitives (no `/d1`) need no migration.

## License

MIT
