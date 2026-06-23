/**
 * @aswincloud/auth/react — optional React UI (login form + SSO buttons).
 *
 * Imports React (a peer dependency). Owner-only Worker sites should NOT import
 * this entry point; use the core `@aswincloud/auth` instead. Framework-agnostic:
 * works on Next, Vite, or plain React (no next/* imports).
 */

export { LoginPage } from "./LoginPage.js";
export type {
  LoginPageProps,
  LoginPageStyles,
  LoginResult,
} from "./LoginPage.js";

export { SsoButtons } from "./SsoButtons.js";
export type { SsoButtonsProps } from "./SsoButtons.js";
