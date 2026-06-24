// Framework-agnostic "forgot password" page. POSTs { email } to your endpoint,
// which calls the package's requestPasswordReset flow. Always shows the same
// "if registered, a link is on its way" message (anti-enumeration). No next/*.

import { useState, type FormEvent, type ReactNode } from "react";
import { defaultAuthStyles, type AuthPageStyles } from "./styles.js";

export interface ForgotPasswordPageProps {
  /** Endpoint the form POSTs { email } to. Default "/api/auth/forgot". */
  action?: string;
  title?: string;
  subtitle?: string;
  /** href back to sign-in. Omit to hide. */
  loginHref?: string;
  /** Called after a 2xx (the message is shown regardless). */
  onSuccess?: () => void;
  styles?: AuthPageStyles;
}

export function ForgotPasswordPage({
  action = "/api/auth/forgot",
  title = "Reset your password",
  subtitle = "Enter your email and we'll send a reset link.",
  loginHref,
  onSuccess,
  styles,
}: ForgotPasswordPageProps) {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [sent, setSent] = useState(false);
  const s = { ...defaultAuthStyles, ...(styles ?? {}) } as Required<AuthPageStyles>;

  async function handle(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await fetch(action, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
    } catch {
      // Anti-enumeration: succeed regardless.
    } finally {
      setSubmitting(false);
      setSent(true);
      onSuccess?.();
    }
  }

  const footer: ReactNode = loginHref ? (
    <p style={s.footer}>
      <a href={loginHref} style={s.link}>Back to sign in</a>
    </p>
  ) : null;

  if (sent) {
    return (
      <main style={s.wrap}>
        <h1 style={s.title}>Check your email</h1>
        <p style={s.success}>If an account exists for {email || "that address"}, a reset link is on its way.</p>
        {footer}
      </main>
    );
  }

  return (
    <main style={s.wrap}>
      <h1 style={s.title}>{title}</h1>
      {subtitle && <p style={s.subtitle}>{subtitle}</p>}
      <form onSubmit={handle} style={s.form}>
        <label style={s.label}>
          Email
          <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} style={s.input} autoComplete="email" />
        </label>
        <button type="submit" disabled={submitting} style={s.button}>
          {submitting ? "Sending…" : "Send reset link"}
        </button>
      </form>
      {footer}
    </main>
  );
}
