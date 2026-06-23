#!/usr/bin/env node
// @aswincloud/auth — one-shot D1 setup for a NEW site.
//
//   npx @aswincloud/auth setup-db <db-name> [--local]
//
// Does the whole dance:
//   1. wrangler d1 create <db-name>      (skips if it already exists)
//   2. prints the d1_databases binding block to paste into wrangler.jsonc
//   3. applies schema.sql to the new database
//
// Each site gets its OWN database — this script never touches another site's.
// Requires wrangler to be installed and logged in (npx wrangler login).

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA = join(__dirname, "..", "schema.sql");

const args = process.argv.slice(2);
const local = args.includes("--local");
const name = args.find((a) => !a.startsWith("--"));

if (!name) {
  console.error("usage: npx @aswincloud/auth setup-db <db-name> [--local]");
  process.exit(1);
}

function wrangler(cmdArgs) {
  return execFileSync("npx", ["wrangler", ...cmdArgs], { encoding: "utf8" });
}

console.log(`\n→ Creating D1 database "${name}" (its own, isolated DB)…`);
let createOut = "";
try {
  createOut = wrangler(["d1", "create", name]);
  console.log(createOut);
} catch (e) {
  const out = (e.stdout || "") + (e.stderr || "");
  if (/already exists/i.test(out)) {
    console.log(`  (database "${name}" already exists — reusing it)`);
  } else {
    console.error(out || e.message);
    process.exit(1);
  }
}

// Surface the binding block. wrangler prints database_id on create; if it
// already existed, the user can read it from `wrangler d1 list`.
const idMatch = createOut.match(/database_id\s*=\s*"([0-9a-f-]+)"/i);
console.log("\n→ Add this to your wrangler.jsonc:");
console.log(
  JSON.stringify(
    { d1_databases: [{ binding: "DB", database_name: name, database_id: idMatch ? idMatch[1] : "<run: npx wrangler d1 list>" }] },
    null,
    2,
  ),
);

console.log(`\n→ Applying auth schema to "${name}"…`);
wrangler(["d1", "execute", name, local ? "--local" : "--remote", `--file=${SCHEMA}`]);
console.log("\n✅ Done. This site now has its own users/oauth_identities/otp_codes tables.");
console.log("   Set per-site secrets next: SESSION_SECRET, and any OAuth client ids.");
