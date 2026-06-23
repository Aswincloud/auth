# @aswincloud/auth

Shared, framework-agnostic auth primitives for Cloudflare Workers sites — signed
sessions, HMAC tokens, PBKDF2 password hashing, owner allowlists, and OAuth —
plus an optional React login UI.

**Each consuming site brings its own D1 database and its own secrets. Nothing in
this package links sites together.** Security rests on your per-site
`SESSION_SECRET`, not on this code being private (it's public on purpose).

## Install

```sh
npm install @aswincloud/auth
```

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

## Google OAuth (owner-only sites)

```ts
const oauth = {
  clientId: env.GOOGLE_CLIENT_ID,
  clientSecret: env.GOOGLE_CLIENT_SECRET,
  redirectUri: new URL("/api/auth/callback", req.url).origin + "/api/auth/callback",
};

// /api/auth/login
return startGoogleLogin(oauth); // 302 to Google + CSRF state cookie

// /api/auth/callback
const id = await handleGoogleCallback(req, oauth); // {email, emailVerified} | null
if (!id?.emailVerified || !isOwner(env.OWNER_EMAILS, id.email)) return forbidden();
const setCookie = await createSessionCookie(session, id.email);
```

The id_token is decoded but not signature-verified: in the confidential-client
code flow, Google mints it over TLS in direct response to our authenticated
exchange, so the transport authenticates the issuer (standard server-side
practice, keeps this package zero-dep on Workers).

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

## License

MIT
