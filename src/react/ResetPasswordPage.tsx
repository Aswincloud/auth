// Framework-agnostic "set a new password" page. Reads the reset token from
// ?token (or a prop), POSTs { token, password } to your endpoint (→ resetPassword
// flow). No next/* — token comes from window.location, not useSearchParams.

import { useState, type FormEvent } from "react";
import { defaultAuthStyles, type AuthPageStyles } from "./styles.js";

export interface ResetPasswordPageProps {
  /** Endpoint the form POSTs { token, password } to. Default "/api/auth/reset". */
  action?: string;
  /** The reset token. Defaults to reading ?token from the URL. */
  token?: string;
  title?: string;
  /** Where to go after a successful reset (e.g. "/login"). If set, we redirect. */
  loginHref?: string;
  /** href to request a fresh link when the token is missing/invalid. */
  forgotHref?: string;
  onSuccess?: () => void;
  onError?: (message: string) => void;
  mapError?: (error: string | undefined, status: number) => string;
  styles?: AuthPageStyles;
}

function readTokenFromUrl(): string {
  if (typeof window === "undefined") return "";
  return new URLSearchParams(window.location.search).get("token") ?? "";
}

function defaultMapError(error: string | undefined): string {
  if (error === "invalid_token") return "This reset link is invalid or has expired.";
  if (error === "weak_password") return "Password must be at least 8 characters.";
  return "Couldn't reset your password. Try again.";
}

export function ResetPasswordPage({
  action = "/api/auth/reset",
  token,
  title = "Choose a new password",
  loginHref,
  forgotHref,
  onSuccess,
  onError,
  mapError = defaultMapError,
  styles,
}: ResetPasswordPageProps) {
  const tok = token ?? readTokenFromUrl();
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const s = { ...defaultAuthStyles, ...(styles ?? {}) } as Required<AuthPageStyles>;

  if (!tok) {
    return (
      <main style={s.wrap}>
        <h1 style={s.title}>{title}</h1>
        <p style={s.error}>This reset link is missing its token.</p>
        {forgotHref && (
          <p style={s.footer}><a href={forgotHref} style={s.link}>Request a new link</a></p>
        )}
      </main>
    );
  }

  async function handle(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch(action, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: tok, password }),
      });
      if (res.ok) {
        onSuccess?.();
        if (loginHref) {
          window.location.assign(loginHref);
          return;
        }
        setDone(true);
        return;
      }
      const body = (await res.json().catch(() => null)) as { error?: string } | null;
      const msg = mapError(body?.error, res.status);
      setError(msg);
      onError?.(msg);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Network error";
      setError(msg);
      onError?.(msg);
    } finally {
      setSubmitting(false);
    }
  }

  if (done) {
    return (
      <main style={s.wrap}>
        <h1 style={s.title}>Password updated</h1>
        <p style={s.success}>Your password has been changed. You can sign in now.</p>
        {loginHref && <p style={s.footer}><a href={loginHref} style={s.link}>Go to sign in</a></p>}
      </main>
    );
  }

  return (
    <main style={s.wrap}>
      <h1 style={s.title}>{title}</h1>
      <form onSubmit={handle} style={s.form}>
        <label style={s.label}>
          New password
          <input type="password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} style={s.input} autoComplete="new-password" />
        </label>
        <button type="submit" disabled={submitting} style={s.button}>
          {submitting ? "Updating…" : "Update password"}
        </button>
        {error && <div style={s.error}>{error}{forgotHref && <> · <a href={forgotHref} style={s.link}>request a new link</a></>}</div>}
      </form>
    </main>
  );
}
