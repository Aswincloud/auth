/**
 * Shared email+password login UI.
 *
 * STATUS: stub. The working reference is shiptrack/src/app/login + signup +
 * forgot + reset + the PasswordStrength component. This will become a
 * headless-ish, styleable <LoginPage> that POSTs to caller-provided endpoints,
 * so multi-user sites stop hand-rolling the form each time.
 *
 * Only multi-user sites import this. Owner-only sites (status/console) use the
 * core entry point and never pull React in.
 */

import type { FormEvent } from "react";

export interface LoginPageProps {
  /** Where the form POSTs credentials. Defaults to "/api/auth/login". */
  action?: string;
  /** Optional heading text. */
  title?: string;
  /** Show the "Sign in with Google" button (requires the site to wire OAuth). */
  showGoogle?: boolean;
  /** Called after a successful submit if you want to intercept (else native POST). */
  onSubmit?: (e: FormEvent<HTMLFormElement>) => void;
}

export function LoginPage(_props: LoginPageProps) {
  throw new Error(
    "TODO: extract UI from shiptrack/src/app/login/page.tsx and friends",
  );
}
