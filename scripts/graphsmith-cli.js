#!/usr/bin/env node
/* graphsmith — CLI dispatcher shipped from the graphsmith-skill npm package (scripts/graphsmith-cli.js).
 * Subcommand `verify` runs the normative GSA §9 verification (scripts/gsa-verify.js) over an attestation
 * bundle and exits non-zero on any violation — a fail-closed trust tool for CI / enterprise verifiers.
 * A PASS asserts only that the bundle is a complete, hash-valid, signature-valid, UNALTERED record —
 * NOT that the workflow is safe/correct/compliant. Zero-dep CJS, Node >= 18.
 */
"use strict";
const fs = require("fs");
const { verifyBundle } = require("./gsa-verify.js");

function readJson(p, label) {
  try { return JSON.parse(fs.readFileSync(p, "utf8")); }
  catch (e) { console.error("graphsmith: cannot read " + label + " '" + p + "': " + e.message); process.exit(2); }
}

function cmdVerify(args) {
  const positional = args.filter((a) => !a.startsWith("--"));
  const bundlePath = positional[0];
  if (!bundlePath) {
    console.error("usage: graphsmith verify <bundle.json> [--keys <trusted-keys.json>] [--revoked <hashes.json>] [--json]\n" +
      "  bundle.json     { manifest, contents:{ <path>: <string> } }\n" +
      "  --keys          { \"<signer>\": \"<public-key-pem>\" }  (authenticity is UNAVAILABLE without it)\n" +
      "  --revoked       [\"<implementation_hash>\", ...]\n" +
      "  --json          emit the full machine-readable result");
    process.exit(2);
  }
  const bundle = readJson(bundlePath, "bundle");
  const opts = {};
  const keysAt = args.indexOf("--keys");
  if (keysAt !== -1) opts.trustedKeys = readJson(args[keysAt + 1], "keys");
  const revAt = args.indexOf("--revoked");
  if (revAt !== -1) { const r = readJson(args[revAt + 1], "revoked"); opts.revoked = new Set(Array.isArray(r) ? r : []); }

  const res = verifyBundle(bundle, opts);
  if (args.includes("--json")) {
    console.log(JSON.stringify(res, null, 2));
  } else {
    for (const s of res.steps) console.log("  [" + s.status + "] " + s.step + (s.detail ? " — " + s.detail : ""));
    console.log("");
    console.log(res.status === "PASS"
      ? "PASS — bundle is a complete, hash-valid, signature-valid, unaltered record."
      : "FAIL — verification failed (see steps above).");
    if (res.confirmed_profiles && res.confirmed_profiles.length) console.log("confirmed profiles: " + res.confirmed_profiles.join(", "));
    if (res.downgraded_profiles && res.downgraded_profiles.length) console.log("downgraded to unavailable: " + res.downgraded_profiles.join(", "));
    console.log("note: " + res.note);
  }
  process.exit(res.status === "PASS" ? 0 : 1);
}

function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === "verify") return cmdVerify(rest);
  if (cmd === "--version" || cmd === "-v") { console.log(require("../package.json").version); return process.exit(0); }
  console.error("graphsmith <command>\n\n  verify <bundle.json>   verify a GSA attestation bundle (fail-closed)\n  --version              print the package version\n");
  process.exit(cmd ? 1 : 1);
}

if (require.main === module) main(process.argv.slice(2));
module.exports = { main };
