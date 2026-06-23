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

## Status

Core primitives (encoding, compare, random, passwords, tokens, cookies,
sessions, owner allowlist) are implemented. Google OAuth helpers and the React
`<LoginPage>` are stubbed and being extracted from the reference sites.

## License

MIT
