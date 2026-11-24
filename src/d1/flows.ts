// Framework-agnostic user-management flows. Each returns a discriminated result
// and NEVER throws (mirrors the core handleOAuthCallback style). They take the
// D1 db + plain values the site already has (e.g. userId from its own session) —
// NOT a Request. The site owns: HTTP routing, status mapping, session cookie
// issuance, the EmailSender it injects, the D1 binding, and TOKEN_SECRET.

import { hashPassword, verifyPassword } from "../passwords.js";
import { signToken, verifyToken } from "../tokens.js";
import { newUlid } from "../random.js";
import {
  getUserByEmail,
  getUserById,
  createUser,
  updateUserPasswordHash,
  updateUserName,
  updateUserEmail,
  markEmailVerified,
  deleteUser,
  countAdmins,
  upsertOtp,
  getOtp,
  claimOtpAttempt,
  deleteOtp,
} from "./users.js";
import { securityStamp } from "./stamp.js";
import { generateOtp, hashOtp, otpHashEquals, OTP_TTL_SECONDS, OTP_MAX_ATTEMPTS, OTP_RESEND_COOLDOWN_SECONDS } from "./otp.js";
import { OAUTH_ONLY_HASH, hasRealPassword, type D1Database, type EmailSender } from "./types.js";
import { passwordResetEmail, verifyEmail as verifyEmailTpl, otpEmail, emailChangeEmail, type EmailTemplate } from "./email.js";

export type Result<E extends string, T = Record<never, never>> = ({ ok: true } & T) | { ok: false; error: E };

// Optional template-render overrides. A consumer passes one of these to emit
// its own branded HTML; when omitted, the flow uses the built-in template. The
// flow still owns when/whether to send and what URL/code goes in — the override
// only controls the {subject,html,text}.
export type RenderOtp = (args: { code: string; ttlMinutes: number }) => EmailTemplate;
export type RenderReset = (args: { resetUrl: string; ttlHours: number }) => EmailTemplate;
export type RenderEmailChange = (args: { confirmUrl: string; newEmail: string; ttlHours: number }) => EmailTemplate;

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const MIN_PASSWORD = 8;
const nowSec = () => Math.floor(Date.now() / 1000);
const normEmail = (e: string) => e.trim().toLowerCase();

// ---- signup + OTP verification --------------------------------------------

export async function signup(
  db: D1Database,
  args: { email: string; password: string; secret: string; sendEmail: EmailSender; appName?: string; otpTtlSeconds?: number; newUserId?: () => string; renderOtp?: RenderOtp },
): Promise<Result<"invalid_email" | "weak_password" | "send_failed", { status: "pending_verification" }>> {
  const email = normEmail(args.email);
  if (!EMAIL_RE.test(email)) return { ok: false, error: "invalid_email" };
  if (args.password.length < MIN_PASSWORD) return { ok: false, error: "weak_password" };

  const existing = await getUserByEmail(db, email);
  const hash = await hashPassword(args.password);
  let pending: string | null = null;
  if (existing) {
    // Never overwrite an existing account's password here: anyone can call
    // signup with someone else's email. For a still-unverified account the new
    // password is held with the code and applied only when the code is
    // verified, which proves the caller controls the inbox. Re-sends respect
    // the resend cooldown so this can't flood the inbox. Same 202 either way,
    // so it doesn't reveal whether the account exists.
    const current = await getOtp(db, email);
    const cooldown = OTP_RESEND_COOLDOWN_SECONDS;
    if (current && nowSec() - current.created_at < cooldown) return { ok: true, status: "pending_verification" };
    if (existing.email_verified !== 1) pending = hash;
  } else {
    const id = (args.newUserId ?? newUlid)();
    await createUser(db, { id, email, passwordHash: hash });
  }

  const code = generateOtp();
  const ttl = args.otpTtlSeconds ?? OTP_TTL_SECONDS;
  await upsertOtp(db, email, await hashOtp(code, args.secret), nowSec() + ttl, pending);
  const ttlMinutes = Math.round(ttl / 60);
  const tpl = args.renderOtp?.({ code, ttlMinutes }) ?? otpEmail({ code, ttlMinutes, appName: args.appName });
  try {
    await args.sendEmail({ to: email, ...tpl });
  } catch {
    return { ok: false, error: "send_failed" };
  }
  return { ok: true, status: "pending_verification" };
}

export async function verifyOtp(
  db: D1Database,
  args: { email: string; code: string; secret: string },
): Promise<Result<"too_many_attempts" | "invalid_code", { userId: string; email: string }>> {
  // One error for "no such account", "no code", "expired" and "wrong code", so
  // the response doesn't reveal whether an account exists.
  const email = normEmail(args.email);
  const user = await getUserByEmail(db, email);
  if (!user) return { ok: false, error: "invalid_code" };
  const otp = await getOtp(db, email);
  if (!otp || otp.expires_at < nowSec()) return { ok: false, error: "invalid_code" };

  // Spend the guess before comparing, atomically, so parallel requests can't
  // all pass a "fewer than N attempts" check.
  if (!(await claimOtpAttempt(db, email, OTP_MAX_ATTEMPTS))) return { ok: false, error: "too_many_attempts" };

  const candidate = await hashOtp(args.code, args.secret);
  if (!otpHashEquals(candidate, otp.code_hash)) return { ok: false, error: "invalid_code" };

  // The password chosen at a re-signup of an unverified account takes effect
  // only now that the caller has proved they control the inbox.
  if (otp.pending_password_hash && user.email_verified !== 1) {
    await updateUserPasswordHash(db, user.id, otp.pending_password_hash);
  }
  await markEmailVerified(db, user.id);
  await deleteOtp(db, email);
  return { ok: true, userId: user.id, email: user.email };
}

export async function resendOtp(
  db: D1Database,
  args: { email: string; secret: string; sendEmail: EmailSender; appName?: string; otpTtlSeconds?: number; cooldownSeconds?: number; renderOtp?: RenderOtp },
): Promise<Result<"no_account" | "cooldown" | "send_failed", { status: "sent" }>> {
  const email = normEmail(args.email);
  const user = await getUserByEmail(db, email);
  if (!user) return { ok: false, error: "no_account" };
  const existing = await getOtp(db, email);
  const cooldown = args.cooldownSeconds ?? OTP_RESEND_COOLDOWN_SECONDS;
  if (existing && nowSec() - existing.created_at < cooldown) return { ok: false, error: "cooldown" };

  const code = generateOtp();
  const ttl = args.otpTtlSeconds ?? OTP_TTL_SECONDS;
  await upsertOtp(db, email, await hashOtp(code, args.secret), nowSec() + ttl);
  const ttlMinutes = Math.round(ttl / 60);
  const tpl = args.renderOtp?.({ code, ttlMinutes }) ?? otpEmail({ code, ttlMinutes, appName: args.appName });
  try {
    await args.sendEmail({ to: email, ...tpl });
  } catch {
    return { ok: false, error: "send_failed" };
  }
  return { ok: true, status: "sent" };
}

// ---- password reset --------------------------------------------------------

/**
 * Always returns { ok: true } regardless of whether the email exists, to avoid
 * account enumeration, and swallows send errors for the same reason.
 */
export async function requestPasswordReset(
  db: D1Database,
  args: { email: string; secret: string; sendEmail: EmailSender; appUrl: string; resetPath?: string; ttlSeconds?: number; appName?: string; renderReset?: RenderReset },
): Promise<{ ok: true }> {
  const email = normEmail(args.email);
  const user = await getUserByEmail(db, email);
  if (user) {
    const ttl = args.ttlSeconds ?? 60 * 60; // 1h
    // Binding the security stamp makes the link single-use: once the password
    // changes (by this link or any other way) the stamp changes and the link dies.
    const token = await signToken(args.secret, `${user.id}:${await securityStamp(user)}`, "password_reset", ttl);
    const path = args.resetPath ?? "/reset";
    const resetUrl = `${args.appUrl.replace(/\/$/, "")}${path}?token=${encodeURIComponent(token)}`;
    const ttlHours = Math.max(1, Math.round(ttl / 3600));
    const tpl = args.renderReset?.({ resetUrl, ttlHours }) ?? passwordResetEmail({ resetUrl, ttlHours, appName: args.appName });
    try {
      await args.sendEmail({ to: email, ...tpl });
    } catch {
      // swallow — never reveal send success/failure
    }
  }
  return { ok: true };
}

export async function resetPassword(
  db: D1Database,
  args: { token: string; newPassword: string; secret: string },
): Promise<Result<"invalid_token" | "weak_password", { userId: string }>> {
  if (args.newPassword.length < MIN_PASSWORD) return { ok: false, error: "weak_password" };
  const subject = await verifyToken(args.secret, args.token, "password_reset");
  if (!subject) return { ok: false, error: "invalid_token" };
  const idx = subject.lastIndexOf(":");
  if (idx < 0) return { ok: false, error: "invalid_token" };
  const userId = subject.slice(0, idx);
  const user = await getUserById(db, userId);
  if (!user || (await securityStamp(user)) !== subject.slice(idx + 1)) return { ok: false, error: "invalid_token" };
  await updateUserPasswordHash(db, userId, await hashPassword(args.newPassword));
  return { ok: true, userId };
}

// ---- logged-in account changes --------------------------------------------

export async function changePassword(
  db: D1Database,
  args: { userId: string; currentPassword?: string; newPassword: string },
): Promise<Result<"not_found" | "current_password_required" | "invalid_credentials" | "weak_password">> {
  if (args.newPassword.length < MIN_PASSWORD) return { ok: false, error: "weak_password" };
  const user = await getUserById(db, args.userId);
  if (!user) return { ok: false, error: "not_found" };

  if (hasRealPassword(user)) {
    if (!args.currentPassword) return { ok: false, error: "current_password_required" };
    if (!(await verifyPassword(args.currentPassword, user.password_hash))) {
      return { ok: false, error: "invalid_credentials" };
    }
  }
  // OAuth-only accounts set their first password without a current one (they're
  // already authenticated via the session the site issued at OAuth login).
  await updateUserPasswordHash(db, user.id, await hashPassword(args.newPassword));
  return { ok: true };
}

export async function changeUsername(
  db: D1Database,
  args: { userId: string; name: string | null },
): Promise<Result<"not_found">> {
  const user = await getUserById(db, args.userId);
  if (!user) return { ok: false, error: "not_found" };
  await updateUserName(db, user.id, args.name);
  return { ok: true };
}

// ---- self-service email change (token-verified, no admin) ------------------

export async function requestEmailChange(
  db: D1Database,
  args: { userId: string; newEmail: string; secret: string; sendEmail: EmailSender; appUrl: string; confirmPath?: string; ttlSeconds?: number; appName?: string; renderEmailChange?: RenderEmailChange },
): Promise<Result<"not_found" | "invalid_email" | "same_as_current" | "email_taken" | "send_failed", { status: "sent" }>> {
  const newEmail = normEmail(args.newEmail);
  if (!EMAIL_RE.test(newEmail)) return { ok: false, error: "invalid_email" };
  const user = await getUserById(db, args.userId);
  if (!user) return { ok: false, error: "not_found" };
  if (normEmail(user.email) === newEmail) return { ok: false, error: "same_as_current" };
  const taken = await getUserByEmail(db, newEmail);
  if (taken) return { ok: false, error: "email_taken" };

  const ttl = args.ttlSeconds ?? 60 * 60;
  // Subject binds BOTH the userId and the target email so the confirm link
  // can't be retargeted to a different address.
  // Also bind the security stamp, so the link dies if the password changes.
  const token = await signToken(args.secret, `${user.id}:${await securityStamp(user)}:${newEmail}`, "email_change", ttl);
  const path = args.confirmPath ?? "/confirm-email";
  const confirmUrl = `${args.appUrl.replace(/\/$/, "")}${path}?token=${encodeURIComponent(token)}`;
  const ttlHours = Math.max(1, Math.round(ttl / 3600));
  const tpl = args.renderEmailChange?.({ confirmUrl, newEmail, ttlHours }) ?? emailChangeEmail({ confirmUrl, newEmail, ttlHours, appName: args.appName });
  try {
    await args.sendEmail({ to: newEmail, ...tpl }); // sent to the NEW address — proves control
  } catch {
    return { ok: false, error: "send_failed" };
  }
  return { ok: true, status: "sent" };
}

export async function confirmEmailChange(
  db: D1Database,
  args: { token: string; secret: string },
): Promise<Result<"invalid_token" | "email_taken", { userId: string; email: string }>> {
  const subject = await verifyToken(args.secret, args.token, "email_change");
  if (!subject) return { ok: false, error: "invalid_token" };
  const [userId, stamp, ...rest] = subject.split(":");
  const newEmail = rest.join(":");
  if (!userId || !stamp || !newEmail) return { ok: false, error: "invalid_token" };
  const user = await getUserById(db, userId);
  if (!user || (await securityStamp(user)) !== stamp) return { ok: false, error: "invalid_token" };
  const res = await updateUserEmail(db, userId, newEmail);
  if (!res.ok) return { ok: false, error: "email_taken" };
  // A newly confirmed email is verified by definition.
  await markEmailVerified(db, userId);
  return { ok: true, userId, email: newEmail };
}

// ---- account removal -------------------------------------------------------

export async function removeUser(
  db: D1Database,
  args: { userId: string; currentPassword?: string; confirmPhrase?: string; protectLastAdmin?: boolean; sendEmail?: EmailSender; appName?: string },
): Promise<Result<"not_found" | "last_admin" | "password_required" | "invalid_credentials" | "confirm_required", { status: "deleted" }>> {
  const user = await getUserById(db, args.userId);
  if (!user) return { ok: false, error: "not_found" };

  // Require an explicit confirm phrase as a deliberate guard. An account with
  // no password (OAuth-only) has nothing else to prove intent, so for those
  // the phrase is mandatory, not merely checked when supplied.
  const phraseOk = args.confirmPhrase?.trim().toLowerCase() === "delete my account";
  if (args.confirmPhrase !== undefined && !phraseOk) return { ok: false, error: "confirm_required" };
  if (!hasRealPassword(user) && !phraseOk) return { ok: false, error: "confirm_required" };

  if (hasRealPassword(user)) {
    if (!args.currentPassword) return { ok: false, error: "password_required" };
    if (!(await verifyPassword(args.currentPassword, user.password_hash))) {
      return { ok: false, error: "invalid_credentials" };
    }
  }

  const protect = args.protectLastAdmin ?? true;
  if (protect && user.is_admin === 1 && (await countAdmins(db)) <= 1) {
    return { ok: false, error: "last_admin" };
  }

  await deleteUser(db, user.id);
  if (args.sendEmail) {
    const { accountDeletedEmail } = await import("./email.js");
    const tpl = accountDeletedEmail({ appName: args.appName });
    try {
      await args.sendEmail({ to: user.email, ...tpl });
    } catch {
      // best-effort
    }
  }
  return { ok: true, status: "deleted" };
}

export { OAUTH_ONLY_HASH, hasRealPassword };
