// Minimal in-memory D1 stub for tests — implements only the statement shapes
// used by src/d1/users.ts. NOT shipped (test-only). Matches on stable
// substrings of each query rather than parsing SQL.

export function makeFakeDb() {
  const users = new Map(); // id -> row
  const otps = new Map(); // email -> row
  const oauth = new Map(); // `${provider}:${puid}` -> { user_id, email }

  const byEmail = (email) => {
    const e = String(email).toLowerCase();
    for (const u of users.values()) if (String(u.email).toLowerCase() === e) return u;
    return null;
  };

  function run(sql, args) {
    const q = sql.replace(/\s+/g, " ").trim();

    // ---- users ----
    if (q.startsWith("INSERT INTO users")) {
      const [id, email, password_hash, email_verified, is_admin, name, created_at] = args;
      users.set(id, { id, email, password_hash, email_verified, is_admin, name, created_at });
      return { first: null, all: [] };
    }
    if (q.includes("UPDATE users SET email_verified = 1")) {
      const u = users.get(args[0]); if (u) u.email_verified = 1;
      return {};
    }
    if (q.includes("UPDATE users SET name =")) {
      const u = users.get(args[1]); if (u) u.name = args[0];
      return {};
    }
    if (q.includes("UPDATE users SET password_hash =")) {
      const u = users.get(args[1]); if (u) u.password_hash = args[0];
      return {};
    }
    if (q.includes("UPDATE users SET email =")) {
      const u = users.get(args[1]); if (u) u.email = args[0];
      return {};
    }
    if (q.includes("UPDATE users SET is_admin =")) {
      const u = users.get(args[1]); if (u) u.is_admin = args[0];
      return {};
    }
    if (q.includes("SELECT id FROM users WHERE email = ? AND id != ?")) {
      const e = String(args[0]).toLowerCase();
      for (const u of users.values()) if (String(u.email).toLowerCase() === e && u.id !== args[1]) return { first: { id: u.id } };
      return { first: null };
    }
    if (q.startsWith("SELECT * FROM users WHERE email")) return { first: byEmail(args[0]) };
    if (q.startsWith("SELECT * FROM users WHERE id")) return { first: users.get(args[0]) ?? null };
    if (q.includes("COUNT(*) AS n FROM users WHERE is_admin = 1")) {
      let n = 0; for (const u of users.values()) if (u.is_admin === 1) n++;
      return { first: { n } };
    }
    if (q.includes("SELECT email FROM users WHERE is_admin = 1")) {
      const r = [...users.values()].filter((u) => u.is_admin === 1 && u.email_verified === 1).map((u) => ({ email: u.email }));
      return { all: r };
    }
    if (q.includes("SELECT id, email, email_verified, is_admin, name, created_at")) {
      return { all: [...users.values()].sort((a, b) => b.created_at - a.created_at) };
    }
    if (q.startsWith("DELETE FROM users WHERE id")) { users.delete(args[0]); return {}; }

    // ---- oauth_identities ----
    if (q.startsWith("DELETE FROM oauth_identities WHERE user_id")) {
      for (const [k, v] of oauth) if (v.user_id === args[0]) oauth.delete(k);
      return {};
    }
    if (q.startsWith("INSERT INTO oauth_identities")) {
      const [provider, puid, user_id, email] = args;
      oauth.set(`${provider}:${puid}`, { user_id, email });
      return {};
    }
    if (q.includes("FROM users u JOIN oauth_identities")) {
      const hit = oauth.get(`${args[0]}:${args[1]}`);
      return { first: hit ? users.get(hit.user_id) ?? null : null };
    }

    // ---- otp_codes ----
    if (q.startsWith("INSERT INTO otp_codes")) {
      const [email, code_hash, expires_at, created_at] = args;
      otps.set(String(email).toLowerCase(), { email, code_hash, expires_at, attempts: 0, created_at });
      return {};
    }
    if (q.startsWith("SELECT * FROM otp_codes WHERE email")) return { first: otps.get(String(args[0]).toLowerCase()) ?? null };
    if (q.includes("UPDATE otp_codes SET attempts = attempts + 1")) {
      const o = otps.get(String(args[0]).toLowerCase()); if (o) o.attempts++;
      return {};
    }
    if (q.startsWith("DELETE FROM otp_codes WHERE email")) { otps.delete(String(args[0]).toLowerCase()); return {}; }

    throw new Error(`fake-d1: unhandled SQL: ${q}`);
  }

  function prepare(sql) {
    let bound = [];
    const stmt = {
      bind: (...a) => { bound = a; return stmt; },
      first: async () => run(sql, bound).first ?? null,
      all: async () => ({ results: run(sql, bound).all ?? [] }),
      run: async () => { run(sql, bound); return { success: true }; },
    };
    return stmt;
  }

  return { prepare, _users: users, _otps: otps, _oauth: oauth };
}
