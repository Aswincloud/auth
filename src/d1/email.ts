// Pure, de-branded email templates → { subject, html, text }. No provider here;
// the site injects an EmailSender (see types.ts). Table-based, inline-styled
// HTML so it renders across Gmail/Apple Mail/Outlook (no flexbox/CSS vars).

export interface EmailTemplate {
  subject: string;
  html: string;
  text: string;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function button(url: string, label: string, accent: string): string {
  return `<a href="${escapeHtml(url)}" style="display:inline-block;background:${accent};color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-weight:600;">${escapeHtml(label)}</a>`;
}

function shell(args: { appName: string; heading: string; bodyHtml: string; preheader?: string; accentHex?: string }): string {
  const accent = args.accentHex ?? "#2563eb";
  const pre = args.preheader
    ? `<span style="display:none;max-height:0;overflow:hidden;">${escapeHtml(args.preheader)}</span>`
    : "";
  return `<!doctype html><html><body style="margin:0;background:#f3f4f6;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;">${pre}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:32px 0;"><tr><td align="center">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;padding:32px;text-align:left;">
<tr><td style="font-size:13px;color:#9ca3af;padding-bottom:18px;">${escapeHtml(args.appName)}</td></tr>
<tr><td style="font-size:22px;font-weight:700;color:#111827;padding-bottom:16px;">${escapeHtml(args.heading)}</td></tr>
<tr><td style="font-size:15px;color:#374151;line-height:1.55;">${args.bodyHtml}</td></tr>
</table></td></tr></table></body></html>`;
}

export function passwordResetEmail(args: { resetUrl: string; ttlHours: number; appName?: string }): EmailTemplate {
  const appName = args.appName ?? "Your account";
  const accent = "#2563eb";
  return {
    subject: `Reset your ${appName} password`,
    html: shell({
      appName,
      heading: "Reset your password",
      preheader: "Use the button below to choose a new password.",
      bodyHtml: `<p style="margin:0 0 18px;">Click below to choose a new password.</p>${button(args.resetUrl, "Reset password", accent)}<p style="margin:18px 0 0;color:#9ca3af;font-size:13px;">This link expires in ${args.ttlHours} hour${args.ttlHours === 1 ? "" : "s"}. Didn't request this? Ignore this email — your password won't change.</p>`,
    }),
    text: `Reset your ${appName} password: ${args.resetUrl} (expires in ${args.ttlHours}h)`,
  };
}

export function verifyEmail(args: { verifyUrl: string; ttlHours: number; appName?: string }): EmailTemplate {
  const appName = args.appName ?? "Your account";
  const accent = "#2563eb";
  return {
    subject: `Verify your email for ${appName}`,
    html: shell({
      appName,
      heading: "Verify your email",
      preheader: "Confirm your email address to finish signing up.",
      bodyHtml: `<p style="margin:0 0 18px;">Confirm your email address to activate your account.</p>${button(args.verifyUrl, "Verify email", accent)}<p style="margin:18px 0 0;color:#9ca3af;font-size:13px;">This link expires in ${args.ttlHours} hour${args.ttlHours === 1 ? "" : "s"}.</p>`,
    }),
    text: `Verify your email for ${appName}: ${args.verifyUrl} (expires in ${args.ttlHours}h)`,
  };
}

export function otpEmail(args: { code: string; ttlMinutes: number; appName?: string }): EmailTemplate {
  const appName = args.appName ?? "Your account";
  return {
    subject: `Your ${appName} verification code`,
    html: shell({
      appName,
      heading: "Your verification code",
      preheader: `Code: ${args.code}`,
      bodyHtml: `<p style="margin:0 0 18px;">Enter this code to verify your email:</p><p style="font-size:30px;font-weight:700;letter-spacing:6px;color:#111827;margin:0 0 18px;">${escapeHtml(args.code)}</p><p style="margin:0;color:#9ca3af;font-size:13px;">Expires in ${args.ttlMinutes} minutes. Didn't request it? Ignore this email.</p>`,
    }),
    text: `Your ${appName} verification code is ${args.code} (expires in ${args.ttlMinutes} min)`,
  };
}

export function emailChangeEmail(args: { confirmUrl: string; newEmail: string; ttlHours: number; appName?: string }): EmailTemplate {
  const appName = args.appName ?? "Your account";
  const accent = "#2563eb";
  return {
    subject: `Confirm your new email for ${appName}`,
    html: shell({
      appName,
      heading: "Confirm your new email",
      preheader: "Confirm this address to complete your email change.",
      bodyHtml: `<p style="margin:0 0 18px;">Confirm <strong>${escapeHtml(args.newEmail)}</strong> as the new email for your ${escapeHtml(appName)} account.</p>${button(args.confirmUrl, "Confirm new email", accent)}<p style="margin:18px 0 0;color:#9ca3af;font-size:13px;">This link expires in ${args.ttlHours} hour${args.ttlHours === 1 ? "" : "s"}. Didn't request this? Ignore it — nothing changes.</p>`,
    }),
    text: `Confirm ${args.newEmail} as your new ${appName} email: ${args.confirmUrl} (expires in ${args.ttlHours}h)`,
  };
}

export function accountDeletedEmail(args: { appName?: string }): EmailTemplate {
  const appName = args.appName ?? "Your account";
  return {
    subject: `Your ${appName} account was deleted`,
    html: shell({
      appName,
      heading: "Account deleted",
      bodyHtml: `<p style="margin:0;">Your ${escapeHtml(appName)} account and its data have been deleted. If this wasn't you, contact support immediately.</p>`,
    }),
    text: `Your ${appName} account has been deleted.`,
  };
}
