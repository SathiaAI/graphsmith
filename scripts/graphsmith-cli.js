#!/usr/bin/env node
/* graphsmith — CLI dispatcher shipped from the graphsmith-skill npm package (scripts/graphsmith-cli.js).
 * Subcommand `verify` runs the normative GSA §9 verification (scripts/gsa-verify.js) over an attestation
 * bundle and exits non-zero on any violation — a fail-closed trust tool for CI / enterprise verifiers.
 * A PASS asserts only that the bundle is a complete, hash-valid, signature-valid, UNALTERED record —
 * NOT that the workflow is safe/correct/compliant. Zero-dep CJS, Node >= 18.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const { verifyBundle } = require("./gsa-verify.js");
const { runPostmortem } = require("./postmortem.js");
const { writeReport } = require("./write-report.js");

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

const POSTMORTEM_USAGE =
  "usage: graphsmith postmortem <session.jsonl> [--harness claude-code|codex] [--out report.md]\n" +
  "  session.jsonl   a raw Claude Code (~/.claude/projects/**/*.jsonl) or\n" +
  "                  Codex (~/.codex/sessions/**/*.jsonl) session log\n" +
  "  --harness       force the adapter instead of auto-detecting\n" +
  "  --out           write the Markdown report to this path instead of stdout\n\n" +
  "NOT graphsmith audit replay (Lane E) -- that consumes GraphSmith's own GSA\n" +
  "execution_trace, not an upstream coding CLI's session log.";

/* CodeRabbit review, PR #23, 2026-08-06 (CLI arg parsing): `positional`
 * used to be computed by filtering OUT any token starting with "--",
 * without excluding the VALUE tokens that follow --harness/--out -- so
 * `--harness codex session.jsonl` set sessionPath to the literal string
 * "codex" (--harness's own value token), not the real positional path,
 * since positional was simply ["codex", "session.jsonl"] and [0] picked
 * the wrong one. Separately, `args[harnessAt + 1]` / `args[outAt + 1]`
 * silently returned `undefined` when --harness/--out was the LAST
 * argument (no value token follows) -- --harness silently fell back to
 * auto-detection instead of erroring, --out silently wrote to stdout
 * instead of the intended file, both exiting 0 as if nothing were wrong.
 *
 * Fix: a single left-to-right scan that parses --harness/--out and their
 * values together, consuming (and excluding from the positional list) the
 * value token in the same step -- so option order/position can no longer
 * corrupt sessionPath. --harness or --out with no following value, and
 * any unrecognized --xxx flag, are now a usage error (exit 2, matching
 * this function's existing missing-sessionPath convention) instead of a
 * silent wrong guess. */
function cmdPostmortem(args) {
  function usageError(message) {
    if (message) console.error(message);
    console.error(POSTMORTEM_USAGE);
    process.exit(2);
  }

  const opts = {};
  let outPath = null;
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--harness" || a === "--out") {
      const value = args[i + 1];
      if (value === undefined) {
        usageError(`graphsmith postmortem: ${a} requires a value`);
        return;
      }
      if (a === "--harness") {
        opts.harness = value;
      } else {
        /* CodeRabbit review, PR #23, 2026-08-06 (ast-grep detect-non-literal-
         * fs-filename, CWE-22 note nested inside the "durable workflow
         * manager" comment): --out is a CLI flag the SAME operator running
         * this command supplies on their own command line -- there is no
         * attacker distinct from the invoking user here, the same trust
         * boundary as `cp`/`tar -C`/any other CLI tool that writes to a
         * caller-chosen path. path.resolve() is applied anyway, deliberately
         * (CR-18, follow-up discussion 2026-08-06): (a) it's the canonical
         * mitigation static analyzers look for on this CWE, so a GraphSmith
         * POC running through a regulated org's own security scanner
         * doesn't re-trip this finding on every review, and (b) it makes the
         * write destination unambiguous regardless of the caller's cwd, a
         * real usability improvement independent of the security argument.
         * It intentionally does NOT constrain outPath to some fixed root --
         * restricting where a user-supplied --out may point would break the
         * flag's actual purpose (write the report wherever the operator
         * says) to guard against a caller (an untrusted/automated process
         * supplying --out on this user's behalf) that does not exist today.
         * If GraphSmith's postmortem command ever gets wired into automation
         * where --out is assembled from something other than a human typing
         * it, that assumption should be revisited. */
        outPath = path.resolve(value);
      }
      i++; // consume the value token -- it must never be swept into positional
      continue;
    }
    if (a.startsWith("--")) {
      usageError(`graphsmith postmortem: unknown option '${a}'`);
      return;
    }
    positional.push(a);
  }

  const sessionPath = positional[0];
  if (!sessionPath) {
    usageError();
    return;
  }

  let result;
  try {
    result = runPostmortem(sessionPath, opts);
  } catch (e) {
    console.error(e.message);
    process.exit(1);
    return;
  }

  if (outPath) {
    /* Adversarial review (Grok-4.5 + Qwen3-Coder-Plus via OpenRouter,
     * CR-18 follow-up, 2026-08-07): writeFileSync had no try/catch here,
     * unlike runPostmortem's call above -- an --out that resolves to an
     * existing directory (including --out "" , which path.resolve()s to
     * the CLI's own cwd) threw an uncaught EISDIR with a raw Node stack
     * trace instead of the clean, single-line error this command uses
     * everywhere else. Reproduced directly before this fix landed. */
    try {
      fs.writeFileSync(outPath, result.markdown, "utf8");
    } catch (e) {
      console.error(e.message);
      process.exit(1);
      return;
    }
    console.error(`graphsmith postmortem: wrote ${outPath} (${result.harness}, ${result.trace.events.length} events)`);
  } else {
    writeReport(result.markdown);
  }
  process.exit(0);
}

function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === "verify") return cmdVerify(rest);
  if (cmd === "postmortem") return cmdPostmortem(rest);
  if (cmd === "--version" || cmd === "-v") { console.log(require("../package.json").version); return process.exit(0); }
  console.error("graphsmith <command>\n\n  verify <bundle.json>             verify a GSA attestation bundle (fail-closed)\n  postmortem <session.jsonl>       mechanical plain-English post-mortem of a raw\n                                    Claude Code / Codex coding-session log\n  --version                        print the package version\n");
  process.exit(cmd ? 1 : 1);
}

if (require.main === module) main(process.argv.slice(2));
module.exports = { main };
