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

## License

MIT
