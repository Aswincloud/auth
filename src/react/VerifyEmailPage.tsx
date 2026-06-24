// Framework-agnostic email-verification page. User enters the 6-digit code sent
// to their email; POSTs { email, code } to your endpoint (→ verifyOtp flow), and
// can resend via a second endpoint (→ resendOtp). Email prefills from ?email.

import { useState, type FormEvent } from "react";
import { defaultAuthStyles, type AuthPageStyles } from "./styles.js";

export interface VerifyEmailPageProps {
  /** Endpoint the form POSTs { email, code } to. Default "/api/auth/verify". */
  action?: string;
  /** Endpoint to POST { email } to for a resend. Default "/api/auth/resend-otp". */
  resendAction?: string;
  /** Prefill the email. Defaults to reading ?email from the URL. */
  email?: string;
  title?: string;
  /** Where to go after successful verification (e.g. "/dashboard"). */
  nextHref?: string;
  onSuccess?: () => void;
  onError?: (message: string) => void;
  mapError?: (error: string | undefined, status: number) => string;
  styles?: AuthPageStyles;
}

function readEmailFromUrl(): string {
  if (typeof window === "undefined") return "";
  return new URLSearchParams(window.location.search).get("email") ?? "";
}

function defaultMapError(error: string | undefined): string {
  switch (error) {
    case "invalid_code": return "That code isn't right. Check and try again.";
    case "too_many_attempts": return "Too many attempts. Request a new code.";
    case "expired": return "That code has expired. Request a new one.";
    case "no_account": return "No account found for that email.";
    default: return "Couldn't verify. Try again.";
  }
}

export function VerifyEmailPage({
  action = "/api/auth/verify",
  resendAction = "/api/auth/resend-otp",
  email: emailProp,
  title = "Verify your email",
  nextHref,
  onSuccess,
  onError,
  mapError = defaultMapError,
  styles,
}: VerifyEmailPageProps) {
  const [email, setEmail] = useState(emailProp ?? readEmailFromUrl());
  const [code, setCode] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resendMsg, setResendMsg] = useState<string | null>(null);
  const s = { ...defaultAuthStyles, ...(styles ?? {}) } as Required<AuthPageStyles>;

  async function handle(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch(action, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code }),
      });
      if (res.ok) {
        onSuccess?.();
        if (nextHref) window.location.assign(nextHref);
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

  async function resend() {
    setResendMsg(null);
    try {
      const res = await fetch(resendAction, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      setResendMsg(res.ok ? "A new code is on its way." : "Couldn't resend just yet — wait a moment.");
    } catch {
      setResendMsg("Couldn't resend — try again.");
    }
  }

  return (
    <main style={s.wrap}>
      <h1 style={s.title}>{title}</h1>
      <p style={s.subtitle}>Enter the 6-digit code we emailed you.</p>
      <form onSubmit={handle} style={s.form}>
        <label style={s.label}>
          Email
          <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} style={s.input} autoComplete="email" />
        </label>
        <label style={s.label}>
          Code
          <input
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={6}
            required
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            style={{ ...s.input, letterSpacing: "0.3em", textAlign: "center", fontSize: 20 }}
            autoComplete="one-time-code"
          />
        </label>
        <button type="submit" disabled={submitting} style={s.button}>
          {submitting ? "Verifying…" : "Verify"}
        </button>
        {error && <div style={s.error}>{error}</div>}
      </form>
      <p style={s.footer}>
        <button type="button" onClick={resend} style={{ ...s.link, background: "none", border: "none", cursor: "pointer", padding: 0 }}>
          Resend code
        </button>
        {resendMsg && <span style={s.success}>{resendMsg}</span>}
      </p>
    </main>
  );
}
