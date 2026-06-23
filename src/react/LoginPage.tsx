/**
 * Framework-agnostic email + password login UI.
 *
 * Extracted from shiptrack/src/app/login/page.tsx but DELIBERATELY decoupled
 * from Next.js: no next/router, next/link, or next/navigation. It runs on any
 * React 18+ setup (Next, Vite, plain CRA). Navigation is the caller's job via
 * onSuccess; the component only owns the form, the fetch, and the error UX.
 *
 * Styling: self-contained inline styles with sensible defaults so it looks
 * right out of the box on a bare site, every piece overridable via `styles`.
 * It does NOT depend on any host CSS variables (shiptrack's version did).
 */

import { useState, type FormEvent, type CSSProperties, type ReactNode } from "react";

export interface LoginResult {
  /** Raw fetch Response, in case the caller wants status/headers. */
  response: Response;
  /** Parsed JSON body if any (best-effort). */
  body: unknown;
}

export interface LoginPageStyles {
  wrap?: CSSProperties;
  title?: CSSProperties;
  subtitle?: CSSProperties;
  form?: CSSProperties;
  label?: CSSProperties;
  input?: CSSProperties;
  button?: CSSProperties;
  error?: CSSProperties;
  footer?: CSSProperties;
  link?: CSSProperties;
}

export interface LoginPageProps {
  /** Endpoint the form POSTs {email, password} to as JSON. Default "/api/auth/login". */
  action?: string;
  title?: string;
  subtitle?: string;
  /** Called on a 2xx response. Caller navigates (e.g. router.push or location.assign). */
  onSuccess?: (result: LoginResult) => void;
  /** Called on a non-2xx response or network error, after the built-in message is set. */
  onError?: (message: string, result?: LoginResult) => void;
  /** Map a server error body to a user-facing message. Default handles "invalid_credentials". */
  mapError?: (body: unknown, status: number) => string;
  /** href for the "Create account" link. Omit to hide. */
  signupHref?: string;
  /** href for the "Forgot password?" link. Omit to hide. */
  forgotHref?: string;
  /** Slot above the form, e.g. SSO buttons + an "or" divider. */
  ssoSlot?: ReactNode;
  /** Per-element style overrides merged over the defaults. */
  styles?: LoginPageStyles;
}

function defaultMapError(body: unknown, status: number): string {
  const err = (body as { error?: string } | null)?.error;
  if (err === "invalid_credentials") return "Wrong email or password.";
  if (err) return err;
  return status >= 500 ? "Something went wrong. Try again." : "Login failed.";
}

export function LoginPage({
  action = "/api/auth/login",
  title = "Welcome back",
  subtitle,
  onSuccess,
  onError,
  mapError = defaultMapError,
  signupHref,
  forgotHref,
  ssoSlot,
  styles,
}: LoginPageProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handle(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const response = await fetch(action, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const body = await response.json().catch(() => null);
      if (response.ok) {
        onSuccess?.({ response, body });
        return;
      }
      const msg = mapError(body, response.status);
      setError(msg);
      onError?.(msg, { response, body });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Network error";
      setError(msg);
      onError?.(msg);
    } finally {
      setSubmitting(false);
    }
  }

  const s = { ...DEFAULTS, ...(styles ?? {}) } as Required<LoginPageStyles>;

  return (
    <main style={s.wrap}>
      <h1 style={s.title}>{title}</h1>
      {subtitle && <p style={s.subtitle}>{subtitle}</p>}
      {ssoSlot}
      <form onSubmit={handle} style={s.form}>
        <label style={s.label}>
          Email
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={s.input}
            autoComplete="email"
          />
        </label>
        <label style={s.label}>
          Password
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={s.input}
            autoComplete="current-password"
          />
        </label>
        <button type="submit" disabled={submitting} style={s.button}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>
        {error && <div style={s.error}>{error}</div>}
      </form>
      {(signupHref || forgotHref) && (
        <p style={s.footer}>
          {signupHref ? <a href={signupHref} style={s.link}>Create account</a> : <span />}
          {forgotHref ? <a href={forgotHref} style={s.link}>Forgot password?</a> : <span />}
        </p>
      )}
    </main>
  );
}

// Defaults: a clean, neutral card. No external CSS needed.
const DEFAULTS: Required<LoginPageStyles> = {
  wrap: {
    maxWidth: 360,
    margin: "0 auto",
    padding: "48px 20px",
    fontFamily:
      "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
    color: "#111827",
  },
  title: { fontSize: 28, fontWeight: 700, marginBottom: 6, letterSpacing: "-0.02em" },
  subtitle: { color: "#6b7280", margin: "0 0 28px", fontSize: 15 },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: 12,
    border: "1px solid #e5e7eb",
    borderRadius: 12,
    padding: 20,
    background: "#fff",
  },
  label: { display: "flex", flexDirection: "column", gap: 6, fontSize: 13, color: "#6b7280" },
  input: {
    padding: "10px 12px",
    border: "1px solid #d1d5db",
    borderRadius: 8,
    fontSize: 15,
    color: "#111827",
    background: "#fff",
  },
  button: {
    padding: "11px 16px",
    border: "none",
    borderRadius: 8,
    background: "#111827",
    color: "#fff",
    fontWeight: 600,
    fontSize: 15,
    cursor: "pointer",
  },
  error: { color: "#dc2626", fontSize: 13 },
  footer: {
    marginTop: 16,
    color: "#6b7280",
    fontSize: 14,
    display: "flex",
    justifyContent: "space-between",
  },
  link: { color: "#2563eb", textDecoration: "none" },
};
