// Shared style shape + defaults for the auth pages (Forgot/Reset/Verify).
// Mirrors LoginPage's inline-style approach so the pages look right on a bare
// site with no external CSS, and every piece is overridable. Self-contained —
// no dependency on host CSS variables.

import type { CSSProperties } from "react";

export interface AuthPageStyles {
  wrap?: CSSProperties;
  title?: CSSProperties;
  subtitle?: CSSProperties;
  form?: CSSProperties;
  label?: CSSProperties;
  input?: CSSProperties;
  button?: CSSProperties;
  error?: CSSProperties;
  success?: CSSProperties;
  footer?: CSSProperties;
  link?: CSSProperties;
}

export const defaultAuthStyles: Required<AuthPageStyles> = {
  wrap: {
    maxWidth: 360,
    margin: "0 auto",
    padding: "48px 20px",
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
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
  success: { color: "#059669", fontSize: 14 },
  footer: { marginTop: 16, color: "#6b7280", fontSize: 14, display: "flex", justifyContent: "space-between" },
  link: { color: "#2563eb", textDecoration: "none" },
};
