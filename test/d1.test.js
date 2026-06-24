// Tests for @aswincloud/auth/d1 — runs against built dist/. Uses the in-memory
// fake D1 stub (no DB dependency).
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement as h } from "react";

import {
  createUser,
  getUserByEmail,
  getUserById,
  updateUserEmail,
  listUsers,
  countAdmins,
  deleteUser,
  linkOAuthIdentity,
  getUserByOAuthIdentity,
  signup,
  verifyOtp,
  resendOtp,
  requestPasswordReset,
  resetPassword,
  changePassword,
  changeUsername,
  requestEmailChange,
  confirmEmailChange,
  removeUser,
  passwordResetEmail,
  verifyEmail,
  otpEmail,
  emailChangeEmail,
  accountDeletedEmail,
  OAUTH_ONLY_HASH,
  hasRealPassword,
} from "../dist/d1/index.js";
import { hashPassword } from "../dist/index.js";
import {
  ForgotPasswordPage,
  ResetPasswordPage,
  VerifyEmailPage,
} from "../dist/react/index.js";
import { makeFakeDb } from "./fake-d1.js";

const SECRET = "test-token-secret";
// captures outgoing email so flows can be asserted
function collector() {
  const sent = [];
  const sendEmail = async (a) => { sent.push(a); };
  return { sent, sendEmail };
}

// ---------------------------------------------------------------- data layer
test("users data layer: create / get / list / conflict / delete", async () => {
  const db = makeFakeDb();
  await createUser(db, { id: "u1", email: "A@X.com", passwordHash: "h1", name: "Al" });
  await createUser(db, { id: "u2", email: "b@x.com", passwordHash: "h2", isAdmin: true, emailVerified: true });

  assert.equal((await getUserByEmail(db, "a@x.com"))?.id, "u1"); // case-insensitive
  assert.equal((await getUserById(db, "u2"))?.is_admin, 1);
  assert.equal((await listUsers(db)).length, 2);
  assert.equal(await countAdmins(db), 1);

  // email conflict
  const conflict = await updateUserEmail(db, "u1", "b@x.com");
  assert.deepEqual(conflict, { ok: false, conflict: true });
  const okChange = await updateUserEmail(db, "u1", "new@x.com");
  assert.equal(okChange.ok, true);

  // oauth identity link + lookup, then cascade on delete
  await linkOAuthIdentity(db, { provider: "google", providerUserId: "g1", userId: "u1" });
  assert.equal((await getUserByOAuthIdentity(db, "google", "g1"))?.id, "u1");
  await deleteUser(db, "u1");
  assert.equal(await getUserById(db, "u1"), null);
  assert.equal(await getUserByOAuthIdentity(db, "google", "g1"), null); // cascaded
});

// ---------------------------------------------------------------- signup + otp
test("signup → verifyOtp happy path, and code is emailed", async () => {
  const db = makeFakeDb();
  const { sent, sendEmail } = collector();
  const r = await signup(db, { email: "New@X.com", password: "hunter2pw", secret: SECRET, sendEmail, newUserId: () => "u-new" });
  assert.deepEqual(r, { ok: true, status: "pending_verification" });
  assert.equal(sent.length, 1);
  const code = sent[0].text.match(/\b(\d{6})\b/)[1]; // otp email contains the code

  const bad = await verifyOtp(db, { email: "new@x.com", code: "000000", secret: SECRET });
  // (unless we got unlucky and 000000 == code) — treat a match as fine
  if (code !== "000000") assert.deepEqual(bad, { ok: false, error: "invalid_code" });

  const good = await verifyOtp(db, { email: "new@x.com", code, secret: SECRET });
  assert.equal(good.ok, true);
  assert.equal(good.userId, "u-new");
  assert.equal((await getUserById(db, "u-new")).email_verified, 1);
});

test("signup rejects bad email + weak password", async () => {
  const db = makeFakeDb();
  const { sendEmail } = collector();
  assert.equal((await signup(db, { email: "nope", password: "longenough", secret: SECRET, sendEmail })).error, "invalid_email");
  assert.equal((await signup(db, { email: "a@b.com", password: "short", secret: SECRET, sendEmail })).error, "weak_password");
});

test("verifyOtp: too_many_attempts after max", async () => {
  const db = makeFakeDb();
  const { sendEmail } = collector();
  await signup(db, { email: "z@x.com", password: "hunter2pw", secret: SECRET, sendEmail, newUserId: () => "uz" });
  for (let i = 0; i < 5; i++) await verifyOtp(db, { email: "z@x.com", code: "999999", secret: SECRET });
  const r = await verifyOtp(db, { email: "z@x.com", code: "999999", secret: SECRET });
  assert.equal(r.error, "too_many_attempts");
});

// ---------------------------------------------------------------- password reset
test("requestPasswordReset always ok + emails only when user exists", async () => {
  const db = makeFakeDb();
  await createUser(db, { id: "u1", email: "a@x.com", passwordHash: await hashPassword("oldpassw") });

  const c1 = collector();
  assert.deepEqual(await requestPasswordReset(db, { email: "a@x.com", secret: SECRET, sendEmail: c1.sendEmail, appUrl: "https://s.com" }), { ok: true });
  assert.equal(c1.sent.length, 1); // existing → emailed

  const c2 = collector();
  assert.deepEqual(await requestPasswordReset(db, { email: "ghost@x.com", secret: SECRET, sendEmail: c2.sendEmail, appUrl: "https://s.com" }), { ok: true });
  assert.equal(c2.sent.length, 0); // unknown → no email, but still ok (anti-enumeration)
});

test("resetPassword: valid token sets new password; bad token rejected", async () => {
  const db = makeFakeDb();
  await createUser(db, { id: "u1", email: "a@x.com", passwordHash: await hashPassword("oldpassw") });
  const c = collector();
  await requestPasswordReset(db, { email: "a@x.com", secret: SECRET, sendEmail: c.sendEmail, appUrl: "https://s.com" });
  const token = new URL(c.sent[0].text.match(/https?:\S+/)[0]).searchParams.get("token");

  assert.equal((await resetPassword(db, { token: "garbage", newPassword: "brandnewpw", secret: SECRET })).error, "invalid_token");
  assert.equal((await resetPassword(db, { token, newPassword: "short", secret: SECRET })).error, "weak_password");
  const ok = await resetPassword(db, { token, newPassword: "brandnewpw", secret: SECRET });
  assert.equal(ok.ok, true);
  // new password verifies
  const { verifyPassword } = await import("../dist/index.js");
  assert.ok(await verifyPassword("brandnewpw", (await getUserById(db, "u1")).password_hash));
});

// ---------------------------------------------------------------- change password
test("changePassword: real-pw requires correct current; OAuth-only skips it", async () => {
  const db = makeFakeDb();
  await createUser(db, { id: "real", email: "r@x.com", passwordHash: await hashPassword("currentpw") });
  await createUser(db, { id: "oauth", email: "o@x.com", passwordHash: OAUTH_ONLY_HASH });

  assert.equal((await changePassword(db, { userId: "real", newPassword: "newpassw" })).error, "current_password_required");
  assert.equal((await changePassword(db, { userId: "real", currentPassword: "wrong", newPassword: "newpassw" })).error, "invalid_credentials");
  assert.equal((await changePassword(db, { userId: "real", currentPassword: "currentpw", newPassword: "newpassw" })).ok, true);

  // OAuth-only sets first password with no current
  assert.equal(hasRealPassword({ password_hash: OAUTH_ONLY_HASH }), false);
  assert.equal((await changePassword(db, { userId: "oauth", newPassword: "firstpass" })).ok, true);
});

test("changeUsername updates name", async () => {
  const db = makeFakeDb();
  await createUser(db, { id: "u1", email: "a@x.com", passwordHash: "h" });
  assert.equal((await changeUsername(db, { userId: "u1", name: "  Alice  " })).ok, true);
  assert.equal((await getUserById(db, "u1")).name, "Alice");
  assert.equal((await changeUsername(db, { userId: "missing", name: "x" })).error, "not_found");
});

// ---------------------------------------------------------------- email change
test("requestEmailChange → confirmEmailChange (self-service, token-bound)", async () => {
  const db = makeFakeDb();
  await createUser(db, { id: "u1", email: "old@x.com", passwordHash: "h" });
  const c = collector();

  assert.equal((await requestEmailChange(db, { userId: "u1", newEmail: "bad", secret: SECRET, sendEmail: c.sendEmail, appUrl: "https://s.com" })).error, "invalid_email");
  assert.equal((await requestEmailChange(db, { userId: "u1", newEmail: "old@x.com", secret: SECRET, sendEmail: c.sendEmail, appUrl: "https://s.com" })).error, "same_as_current");

  const r = await requestEmailChange(db, { userId: "u1", newEmail: "New@X.com", secret: SECRET, sendEmail: c.sendEmail, appUrl: "https://s.com" });
  assert.equal(r.ok, true);
  assert.equal(c.sent[0].to, "new@x.com"); // sent to the NEW address
  // not changed until confirmed
  assert.equal((await getUserById(db, "u1")).email, "old@x.com");

  const token = new URL(c.sent[0].text.match(/https?:\S+/)[0]).searchParams.get("token");
  const conf = await confirmEmailChange(db, { token, secret: SECRET });
  assert.equal(conf.ok, true);
  assert.equal((await getUserById(db, "u1")).email, "new@x.com");

  // tampered/invalid token
  assert.equal((await confirmEmailChange(db, { token: "garbage", secret: SECRET })).error, "invalid_token");
});

// ---------------------------------------------------------------- remove user
test("removeUser: last-admin guard + confirm phrase + password", async () => {
  const db = makeFakeDb();
  await createUser(db, { id: "admin", email: "a@x.com", passwordHash: await hashPassword("adminpw1"), isAdmin: true });

  // last admin protected
  assert.equal((await removeUser(db, { userId: "admin", currentPassword: "adminpw1" })).error, "last_admin");

  // a normal user with wrong confirm phrase
  await createUser(db, { id: "u1", email: "u@x.com", passwordHash: await hashPassword("userpw12") });
  assert.equal((await removeUser(db, { userId: "u1", currentPassword: "userpw12", confirmPhrase: "nope" })).error, "confirm_required");
  assert.equal((await removeUser(db, { userId: "u1", currentPassword: "wrong" })).error, "invalid_credentials");

  const ok = await removeUser(db, { userId: "u1", currentPassword: "userpw12", confirmPhrase: "delete my account" });
  assert.deepEqual(ok, { ok: true, status: "deleted" });
  assert.equal(await getUserById(db, "u1"), null);
});

// ---------------------------------------------------------------- email templates
test("email templates return non-empty subject/html/text with the data", () => {
  const r = passwordResetEmail({ resetUrl: "https://s.com/reset?token=abc", ttlHours: 1, appName: "Acme" });
  assert.ok(r.subject && r.html && r.text);
  assert.ok(r.html.includes("https://s.com/reset?token=abc"));
  assert.ok(verifyEmail({ verifyUrl: "https://s.com/v", ttlHours: 2 }).html.includes("https://s.com/v"));
  assert.ok(otpEmail({ code: "123456", ttlMinutes: 10 }).html.includes("123456"));
  assert.ok(emailChangeEmail({ confirmUrl: "https://s.com/c", newEmail: "n@x.com", ttlHours: 1 }).html.includes("n@x.com"));
  assert.ok(accountDeletedEmail({ appName: "Acme" }).subject.includes("Acme"));
});

// ---------------------------------------------------------------- react pages
test("auth pages render and contain no next/* import in output", async () => {
  const forgot = renderToStaticMarkup(h(ForgotPasswordPage, { loginHref: "/login" }));
  assert.ok(forgot.includes('type="email"') && forgot.includes("Send reset link"));

  // ResetPasswordPage with no token shows the missing-token branch
  const resetNoTok = renderToStaticMarkup(h(ResetPasswordPage, { token: "", forgotHref: "/forgot" }));
  assert.ok(resetNoTok.includes("missing its token"));
  const resetTok = renderToStaticMarkup(h(ResetPasswordPage, { token: "abc" }));
  assert.ok(resetTok.includes('type="password"'));

  const verify = renderToStaticMarkup(h(VerifyEmailPage, { email: "a@x.com" }));
  assert.ok(verify.includes("Verify"));
  assert.ok(verify.includes('pattern="[0-9]*"')); // 6-digit code field rendered
  assert.ok(verify.includes("Resend code"));
  assert.ok(verify.includes('value="a@x.com"')); // email prefilled from prop

  const { readFileSync } = await import("node:fs");
  for (const f of ["ForgotPasswordPage", "ResetPasswordPage", "VerifyEmailPage"]) {
    assert.ok(!/from\s+["']next/.test(readFileSync(`./dist/react/${f}.js`, "utf8")), `${f} leaked next/*`);
  }
});
