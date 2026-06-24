// @aswincloud/auth/d1 — D1-backed user-management layer.
//
// Drop-in flows (signup, OTP verify, password reset, change password/username,
// self-service email change, account removal) + the users data layer + pure
// email templates. The site brings its own D1 binding, its own EmailSender, and
// does the HTTP routing / session-cookie issuance. Nothing here links sites.
//
// Import from "@aswincloud/auth/d1" (separate from the zero-dep core).

// data layer
export {
  getUserByEmail,
  getUserById,
  createUser,
  markEmailVerified,
  updateUserName,
  updateUserPasswordHash,
  updateUserEmail,
  setUserAdmin,
  deleteUser,
  listUsers,
  countAdmins,
  listAdminEmails,
  getUserByOAuthIdentity,
  linkOAuthIdentity,
  upsertOtp,
  getOtp,
  incrementOtpAttempts,
  deleteOtp,
} from "./users.js";

// otp helpers
export {
  generateOtp,
  hashOtp,
  otpHashEquals,
  OTP_TTL_SECONDS,
  OTP_MAX_ATTEMPTS,
  OTP_RESEND_COOLDOWN_SECONDS,
} from "./otp.js";

// email templates (pure; provider is injected by the site)
export {
  passwordResetEmail,
  verifyEmail,
  otpEmail,
  emailChangeEmail,
  accountDeletedEmail,
} from "./email.js";
export type { EmailTemplate } from "./email.js";

// flows
export {
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
} from "./flows.js";
export type { Result } from "./flows.js";

// types + sentinels
export { OAUTH_ONLY_HASH, hasRealPassword } from "./types.js";
export type { UserRow, ListedUser, OtpRow, EmailSender, D1Database } from "./types.js";
