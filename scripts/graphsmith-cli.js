#!/usr/bin/env node
/* graphsmith — CLI dispatcher shipped from the graphsmith-skill npm package (scripts/graphsmith-cli.js).
 * Subcommand `verify` runs the normative GSA §9 verification (scripts/gsa-verify.js) over an attestation
 * bundle and exits non-zero on any violation — a fail-closed trust tool for CI / enterprise verifiers.
 * A PASS asserts only that the bundle is a complete, hash-valid, signature-valid, UNALTERED record —
 * NOT that the workflow is safe/correct/compliant. Zero-dep CJS, Node >= 18.
 *
 * Merge note (2026-08-07): this file reconciles two branches that both touched it independently
 * after diverging from the same base (v0.5.0 Wave 1 / Lane B, commit 42579ad) --
 * `gsa-followup/lane-f-coderabbit-fixes` (merged to main as #23/#24, added `postmortem`) and
 * `gsa-followup/lane-e-audit-replay` (this branch, adds `audit replay`). Rebased Lane E onto
 * current main (f3fb973) and combined both subcommands here; neither command's own logic changed
 * in this merge -- cmdPostmortem is byte-for-byte main's version (including the CR-18 EISDIR
 * try/catch), cmdAuditReplay/cmdAudit/auditReplayUsage/renderAuditReplayHuman are byte-for-byte
 * Lane E's version. Only shared scaffolding (requires, main()'s dispatch table, the top-level
 * usage string) was hand-merged to carry both.
 */
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const readline = require("readline/promises");
const { verifyBundle } = require("./gsa-verify.js");
const { runPostmortem } = require("./postmortem.js");
const { writeReport } = require("./write-report.js");
const { composeReport, validateVerifyResultShape } = require("./gsa-audit-replay.js");
const modeSelection = require("./mode-selection.js");

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

/* `graphsmith audit replay <bundle.json> [options]` — Lane E (GSA follow-up track).
 * A NARRATION layer over verifyBundle() (gsa-verify.js) and replayBundle()/planDrift()
 * (gsa-plan.js) — see scripts/gsa-audit-replay.js for the report composer and
 * .plans/gsa-followup/LANE-E-AUDIT-REPLAY-DESIGN.md for the frozen design. This
 * subcommand and gsa-audit-replay.js never import Node's built-in crypto module and never re-derive
 * any of verifyBundle's §9 comparison logic (enforced by tests/audit-replay/run-tests.js
 * GROUP 0, a real executable lint check, not just this comment).
 */
function auditReplayUsage() {
  console.error(
    "usage: graphsmith audit replay <bundle.json> [options]\n" +
    "  --keys <trusted-keys.json>   Same shape as `verify`. Without it, provenance_signing\n" +
    "                                renders unavailable for authenticity, same as `verify` does.\n" +
    "  --revoked <hashes.json>      Same shape as `verify`.\n" +
    "  --diff <prior-bundle.json>   Enables the drift section (planDrift). Optional.\n" +
    "  --lens <skill_id>            Filter skills_lens to one skill_id. Optional.\n" +
    "  --json                       Emit the full machine-readable report\n" +
    "                                (schemas/audit-replay-report.schema.json). Default is a\n" +
    "                                human-readable rendering in the existing §9.x step/status/note house style.\n" +
    "  --no-verify                  Accept a precomputed verify_result as JSON on stdin instead of\n" +
    "                                running verifyBundle() live. Sets verification_provenance to\n" +
    "                                \"external\" — every dimension renders unavailable regardless of\n" +
    "                                the supplied result's content. For CI pipelines that already ran\n" +
    "                                `verify` and don't want to pay for it twice; NOT a way to get a\n" +
    "                                \"verified\" report without a real verify."
  );
}

function renderAuditReplayHuman(report) {
  console.log("graphsmith audit replay — " + report.bundle_id);
  console.log("mode=" + report.mode + "  asserted-profiles=[" + report.asserted_profiles.join(",") + "]  tool=" + report.tool.name + "@" + report.tool.version);
  console.log("verification_provenance=" + report.verification_provenance + "  verify_result.status=" + report.verify_result.status);
  console.log("");
  for (const s of report.verify_result.steps) console.log("  [" + s.status + "] " + s.step + (s.detail ? " — " + s.detail : ""));
  console.log("");
  console.log("  replay: reproducible=" + report.replay_result.reproducible + " deterministic_confirmed=" + report.replay_result.deterministic_confirmed +
    " mismatches=" + report.replay_result.mismatches.length + " non_replayable=" + report.replay_result.non_replayable.length);
  console.log("");
  console.log("  dimension                     status        reason");
  console.log("  --------------------------------------------------------------------------");
  for (const d of report.dimensions) console.log("  " + d.id.padEnd(28) + " [" + d.status + "]" + (d.reason ? " — " + d.reason : ""));
  console.log("  --------------------------------------------------------------------------");
  console.log("");
  console.log("  marks: " + report.marks.length + " occurrence(s)   skills_lens: " + report.skills_lens.length + " skill(s)");
  if (report.drift) {
    console.log("  drift: " + (report.drift.safe ? "no destructive changes" : report.drift.destructive.length + " destructive change(s)") +
      " (added=" + report.drift.added.length + " removed=" + report.drift.removed.length + " changed=" + report.drift.changed.length + ")");
  }
  console.log("");
  console.log(report.narrative);
}

function cmdAuditReplay(args) {
  const positional = args.filter((a) => !a.startsWith("--"));
  const bundlePath = positional[0];
  if (!bundlePath) { auditReplayUsage(); process.exit(2); }
  const bundle = readJson(bundlePath, "bundle");

  const opts = {};
  const keysAt = args.indexOf("--keys");
  if (keysAt !== -1) opts.trustedKeys = readJson(args[keysAt + 1], "keys");
  const revAt = args.indexOf("--revoked");
  if (revAt !== -1) { const r = readJson(args[revAt + 1], "revoked"); opts.revoked = new Set(Array.isArray(r) ? r : []); }
  const diffAt = args.indexOf("--diff");
  const prevBundle = diffAt !== -1 ? readJson(args[diffAt + 1], "prior bundle") : undefined;
  const lensAt = args.indexOf("--lens");
  const lens = lensAt !== -1 ? args[lensAt + 1] : undefined;
  const noVerify = args.includes("--no-verify");

  let verificationProvenance, verifyResult;
  if (noVerify) {
    verificationProvenance = "external";
    let raw;
    try { raw = fs.readFileSync(0, "utf8"); }
    catch (e) { console.error("graphsmith: --no-verify requires a verify_result JSON document on stdin: " + e.message); process.exit(2); }
    let parsed;
    try { parsed = JSON.parse(raw); }
    catch (e) { console.error("graphsmith: --no-verify stdin is not valid JSON: " + e.message); process.exit(2); }
    const shapeErr = validateVerifyResultShape(parsed);
    if (shapeErr) { console.error("graphsmith: malformed verify_result on stdin: " + shapeErr); process.exit(2); }
    verifyResult = parsed;
  } else {
    verificationProvenance = "live";
    verifyResult = verifyBundle(bundle, opts);
  }

  let report;
  try {
    report = composeReport({
      bundle,
      verificationProvenance,
      verifyResult,
      prevBundle,
      lens,
      generated: "unavailable", // no clock read in the decision path; the CLI has no data-supplied timestamp flag
      toolVersion: require("../package.json").version,
    });
  } catch (e) {
    console.error("graphsmith: audit replay failed — " + (e && e.message ? e.message : String(e)));
    process.exit(2);
  }

  if (args.includes("--json")) console.log(JSON.stringify(report, null, 2));
  else renderAuditReplayHuman(report);

  process.exit(verificationProvenance === "live" && verifyResult.status === "PASS" ? 0 : 1);
}

function cmdAudit(args) {
  const [sub, ...rest] = args;
  if (sub === "replay") return cmdAuditReplay(rest);
  console.error("usage: graphsmith audit replay <bundle.json> [options]");
  process.exit(sub ? 1 : 2);
}

/* `graphsmith gateway mode set|status` -- Track 1.1's mode-selection
 * contract CLI (TRD S4/MS-FR-2..MS-FR-4). All logic lives in
 * scripts/mode-selection.js; this is thin argv parsing + the interactive
 * prompt only. `--root <dir>` is a test/automation seam (defaults to
 * process.cwd()), not part of the TRD's own operator-facing surface. */
const GATEWAY_MODE_SET_USAGE =
  "usage: graphsmith gateway mode set <standalone|attach> [options]\n" +
  "  (interactive, default)          shows current -> target mode, requires typing\n" +
  "                                   the target mode name back on a live TTY\n" +
  "  --pre-authorize [--expires-in-hours N] [--out <file>]\n" +
  "                                   interactive; ALSO writes a reusable,\n" +
  "                                   time-boxed pre-authorization artifact\n" +
  "                                   (default 24h, default path\n" +
  "                                   .graphsmith/state/gateway-mode.pre-auth.json)\n" +
  "  --use-pre-authorization <file>   non-interactive (GitOps/IaC): consumes an\n" +
  "                                   artifact produced by an earlier --pre-authorize\n" +
  "                                   run; refuses on any HMAC/expiry/mode mismatch\n" +
  "  --confirmed-by <identity>        override the operator identity string recorded\n" +
  "                                   in the confirmation (default: OS user@host)\n" +
  "  --root <dir>                     deployment root (default: cwd)\n";

function defaultConfirmedBy() {
  try { return `${os.userInfo().username}@${os.hostname()}`; }
  catch { return os.hostname() || "unknown-operator"; }
}

function usageError(usage, message) {
  if (message) console.error(`graphsmith: ${message}`);
  console.error(usage);
  process.exit(2);
}

async function cmdGatewayModeSet(args) {
  const positional = [];
  const opts = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--pre-authorize") { opts.preAuthorize = true; continue; }
    if (a === "--use-pre-authorization" || a === "--expires-in-hours" || a === "--out" || a === "--confirmed-by" || a === "--root") {
      const value = args[i + 1];
      if (value === undefined) return usageError(GATEWAY_MODE_SET_USAGE, `${a} requires a value`);
      if (a === "--use-pre-authorization") opts.usePreAuthorization = value;
      if (a === "--expires-in-hours") opts.expiresInHours = value;
      if (a === "--out") opts.out = value;
      if (a === "--confirmed-by") opts.confirmedBy = value;
      if (a === "--root") opts.root = value;
      i++;
      continue;
    }
    if (a.startsWith("--")) return usageError(GATEWAY_MODE_SET_USAGE, `unknown option '${a}'`);
    positional.push(a);
  }

  const mode = positional[0];
  if (!modeSelection.MODES.includes(mode)) return usageError(GATEWAY_MODE_SET_USAGE);
  if (opts.preAuthorize && opts.usePreAuthorization) return usageError(GATEWAY_MODE_SET_USAGE, "--pre-authorize and --use-pre-authorization are mutually exclusive");

  const rootDir = path.resolve(opts.root || process.cwd());
  const confirmedBy = opts.confirmedBy || defaultConfirmedBy();

  if (opts.usePreAuthorization) {
    let artifact;
    try { artifact = JSON.parse(fs.readFileSync(path.resolve(opts.usePreAuthorization), "utf8")); }
    catch (e) { console.error(`graphsmith: cannot read pre-authorization artifact: ${e.message}`); return process.exit(2); }

    let verified;
    try { verified = modeSelection.verifyPreAuthorizationArtifact(rootDir, artifact, { mode, now: Date.now() }); }
    catch (e) { console.error(`graphsmith: ${e.message}`); return process.exit(1); }

    const record = modeSelection.writeGatewayMode(rootDir, {
      mode,
      confirmedBy: verified.authorized_by,
      confirmedAt: Date.now(),
      preAuthorized: true,
    });
    console.log(`graphsmith: mode confirmed via pre-authorization -> ${record.mode} (confirmed_by=${record.confirmation.confirmed_by})`);
    return process.exit(0);
  }

  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.error(
      "graphsmith: gateway mode set requires an interactive terminal -- no file written. " +
      "For automation, use --use-pre-authorization <file> with an artifact produced by an " +
      "earlier, interactive --pre-authorize run."
    );
    return process.exit(2);
  }

  console.log(`Current mode: ${modeSelection.describeCurrentMode(rootDir)}`);
  console.log(`Target mode:  ${mode}`);
  console.log("");

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const typed = await rl.question(`Type "${mode}" to confirm this change: `);
    if (typed.trim() !== mode) {
      console.error("graphsmith: confirmation did not match -- aborting, no file written.");
      return process.exit(2);
    }

    const confirmedAt = Date.now();

    if (opts.preAuthorize) {
      const hours = opts.expiresInHours !== undefined ? Number(opts.expiresInHours) : null;
      if (opts.expiresInHours !== undefined && (!Number.isFinite(hours) || hours <= 0)) {
        return usageError(GATEWAY_MODE_SET_USAGE, "--expires-in-hours must be a positive number");
      }
      const ttlMs = hours !== null ? Math.round(hours * 3600 * 1000) : undefined;
      const artifact = modeSelection.createPreAuthorizationArtifact(rootDir, {
        mode,
        authorizedBy: confirmedBy,
        authorizedAt: confirmedAt,
        ...(ttlMs !== undefined ? { ttlMs } : {}),
      });
      const outPath = path.resolve(opts.out || path.join(modeSelection.gatewayStateDir(rootDir), "gateway-mode.pre-auth.json"));
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, `${JSON.stringify(artifact, null, 2)}\n`, "utf8");
      console.log(`graphsmith: pre-authorization artifact written to ${outPath} (expires ${new Date(artifact.expires_at).toISOString()})`);
    }

    const record = modeSelection.writeGatewayMode(rootDir, { mode, confirmedBy, confirmedAt });
    console.log(`graphsmith: mode confirmed -> ${record.mode}`);
    return process.exit(0);
  } finally {
    rl.close();
  }
}

function cmdGatewayModeStatus(args) {
  const rootAt = args.indexOf("--root");
  const rootDir = path.resolve(rootAt !== -1 && args[rootAt + 1] ? args[rootAt + 1] : process.cwd());
  const status = modeSelection.statusReport(rootDir);
  console.log(JSON.stringify(status, null, 2));
  process.exit(status.ok ? 0 : 1);
}

function cmdGatewayMode(args) {
  const [sub, ...rest] = args;
  if (sub === "set") return cmdGatewayModeSet(rest);
  if (sub === "status") return cmdGatewayModeStatus(rest);
  console.error(GATEWAY_MODE_SET_USAGE);
  process.exit(sub ? 1 : 2);
}

function cmdGateway(args) {
  const [sub, ...rest] = args;
  if (sub === "mode") return cmdGatewayMode(rest);
  console.error("usage: graphsmith gateway mode set|status ...");
  process.exit(sub ? 1 : 2);
}

function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === "verify") return cmdVerify(rest);
  if (cmd === "postmortem") return cmdPostmortem(rest);
  if (cmd === "audit") return cmdAudit(rest);
  if (cmd === "gateway") {
    const result = cmdGateway(rest);
    if (result && typeof result.catch === "function") {
      result.catch((error) => {
        console.error(error && error.stack ? error.stack : String(error));
        process.exit(1);
      });
    }
    return result;
  }
  if (cmd === "--version" || cmd === "-v") { console.log(require("../package.json").version); return process.exit(0); }
  console.error("graphsmith <command>\n\n  verify <bundle.json>             verify a GSA attestation bundle (fail-closed)\n  postmortem <session.jsonl>       mechanical plain-English post-mortem of a raw\n                                    Claude Code / Codex coding-session log\n  audit replay <bundle.json>       narrate an already-produced GSA bundle (verify +\n                                    replay + drift), never re-derives trust\n  gateway mode set|status          declare/confirm/inspect standalone vs. attach\n                                    mode (Track 1.1 mode-selection contract)\n  --version                        print the package version\n");
  process.exit(cmd ? 1 : 1);
}

if (require.main === module) main(process.argv.slice(2));
module.exports = { main };
