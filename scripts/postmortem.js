#!/usr/bin/env node
"use strict";

/**
 * scripts/postmortem.js -- top-level orchestrator for `graphsmith
 * postmortem` (Lane F). Wires the two adapters (postmortem-claude-code.js,
 * postmortem-codex.js) and the mechanical Markdown renderer
 * (postmortem-render.js) together: reads a session JSONL file from disk,
 * picks (or is told) which harness parsed it, produces a session-trace
 * object, and renders it to Markdown.
 *
 * This is the one place in Lane F that touches the filesystem for its own
 * sake (reading the input file, optionally writing --out); the adapters and
 * renderer themselves stay pure (text/object in, object/string out).
 *
 * Harness detection (--harness omitted): runs BOTH adapters (isClaudeLine /
 * the codex line-type switch) over the input and looks at how many report
 * the file as recognized. RESOLVED, 2026-08-06 (CodeRabbit review, PR #23)
 * -- this used to be an open judgment call, disclosed as such right here:
 * the original two-adapter-RACE approach returned on the FIRST adapter to
 * report recognized, without ever checking whether the OTHER adapter would
 * also recognize the same input, flagged at the time as "unlikely in
 * practice... not proven impossible." The user asked for it hardened
 * regardless of how unlikely, so it now is: if exactly one adapter
 * recognizes the file, that one is used (the common case, unchanged
 * behavior); if neither recognizes it, the existing "could not recognize"
 * error is unchanged; if MORE THAN ONE adapter recognizes the same input,
 * that is now an explicit, named error requiring --harness be passed
 * rather than a silent pick of whichever adapter happened to run first.
 * --harness remains the fully reliable path either way.
 */

const fs = require("fs");

const { parseClaudeCodeSession } = require("./postmortem-claude-code.js");
const { parseCodexSession } = require("./postmortem-codex.js");
const { renderMarkdown } = require("./postmortem-render.js");

const HARNESSES = ["claude-code", "codex"];

/* reliability-2 (adversarial review run-20260807-222752): buildPostmortem
 * used to call fs.readFileSync on an arbitrary session-log path with no
 * size check at all, and the raw text is then further multiplied in memory
 * (split into a line array, then a parsed-event array) before rendering.
 * An independent rebuttal reproduction reported a 512 MiB input pushing
 * process RSS past 2.2 GiB and OOM-killing a 4 GiB CI runner. 200 MiB is
 * generous for a legitimate single session transcript (JSONL text; even a
 * multi-day continuous session is normally well under this) while keeping
 * peak memory for the read+split+parse chain bounded to a level that fits
 * inside a constrained CI runner rather than an unbounded multiple of
 * whatever the file happens to be. */
const MAX_SESSION_FILE_BYTES = 200 * 1024 * 1024; // 200 MiB

function parseWithHarness(harness, text, opts) {
  if (harness === "claude-code") return parseClaudeCodeSession(text, opts);
  if (harness === "codex") return parseCodexSession(text, opts);
  throw new Error(`postmortem: unknown harness '${harness}' (expected one of: ${HARNESSES.join(", ")})`);
}

/**
 * @param {string} sessionPath path to a session .jsonl file on disk
 * @param {{harness?: string}} [opts]
 * @returns {{trace: object, diagnostics: object, harness: string}}
 */
function buildPostmortem(sessionPath, opts) {
  opts = opts || {};
  // Finding 4 (adversarial review, fresh Grok pass, 2026-08-06, downgraded
  // to MEDIUM: display-only, does not affect classification): this used to
  // resolve sessionPath to an absolute path via path.resolve(), which
  // implicitly depends on process.cwd() -- the SAME relative sessionPath
  // invoked from two different directories produced a different
  // session.sourcePath string in the report, a real (if narrow) violation
  // of this repo's no-environment-dependent-report-output rule. Node's own
  // fs.readFileSync already resolves a relative path against process.cwd()
  // internally without needing an explicit path.resolve() at this layer,
  // so sourcePath now records exactly the string the caller passed in --
  // deterministic with respect to the input, not the invocation directory.
  let stat;
  try {
    stat = fs.statSync(sessionPath);
  } catch (e) {
    throw new Error(`postmortem: cannot read '${sessionPath}': ${e.message}`);
  }
  // FAIL-CLOSED: reject oversized input before it is ever read into memory
  // (see MAX_SESSION_FILE_BYTES above) rather than attempting the read and
  // relying on the process to survive it.
  if (stat.size > MAX_SESSION_FILE_BYTES) {
    throw new Error(
      `postmortem: '${sessionPath}' is ${stat.size} bytes, which exceeds the ` +
        `${MAX_SESSION_FILE_BYTES}-byte (${Math.round(MAX_SESSION_FILE_BYTES / (1024 * 1024))} MiB) limit on ` +
        `session-log input. This limit exists to avoid an out-of-memory crash on large ` +
        `files (readFileSync + line-split + event-parse each hold a further copy in memory). ` +
        `If this is a legitimate session that has genuinely grown this large, split it before ` +
        `running postmortem on it.`
    );
  }

  let text;
  try {
    text = fs.readFileSync(sessionPath, "utf8");
  } catch (e) {
    throw new Error(`postmortem: cannot read '${sessionPath}': ${e.message}`);
  }

  const parseOpts = { sourcePath: sessionPath };

  if (opts.harness) {
    if (!HARNESSES.includes(opts.harness)) {
      throw new Error(`postmortem: --harness must be one of: ${HARNESSES.join(", ")} (got '${opts.harness}')`);
    }
    const { trace, diagnostics } = parseWithHarness(opts.harness, text, parseOpts);
    if (!diagnostics.recognized) {
      throw new Error(
        `postmortem: '${sessionPath}' was not recognized as a ${opts.harness} session log ` +
          `(no line matched that harness's structural shape). Double-check --harness.`
      );
    }
    return { trace, diagnostics, harness: opts.harness };
  }

  // CodeRabbit review, PR #23, 2026-08-06 (ambiguous harness auto-
  // detection): both adapters are now run UNCONDITIONALLY (not stopping at
  // the first recognized result), so a file that happens to satisfy both
  // recognizers' loose heuristics can be detected as ambiguous instead of
  // silently resolved to whichever adapter's HARNESSES-array position came
  // first. See the file header for the full history of this decision.
  const attempts = [];
  for (const harness of HARNESSES) {
    const result = parseWithHarness(harness, text, parseOpts);
    attempts.push({ harness, result });
  }
  const recognizedAttempts = attempts.filter((a) => a.result.diagnostics.recognized);
  if (recognizedAttempts.length === 1) {
    const only = recognizedAttempts[0];
    return { trace: only.result.trace, diagnostics: only.result.diagnostics, harness: only.harness };
  }
  if (recognizedAttempts.length > 1) {
    throw new Error(
      `postmortem: '${sessionPath}' was ambiguously recognized by more than one harness adapter ` +
        `(${recognizedAttempts.map((a) => a.harness).join(", ")}). Auto-detection cannot pick a single ` +
        `answer safely -- pass --harness explicitly to say which one this session log actually is.`
    );
  }
  throw new Error(
    `postmortem: could not recognize '${sessionPath}' as a Claude Code or Codex session log. ` +
      `Tried: ${attempts.map((a) => a.harness).join(", ")}. Pass --harness explicitly if this is a valid ` +
      `session log in an unrecognized shape.`
  );
}

/**
 * @param {string} sessionPath
 * @param {{harness?: string}} [opts]
 * @returns {{markdown: string, trace: object, harness: string}}
 */
function runPostmortem(sessionPath, opts) {
  const { trace, diagnostics, harness } = buildPostmortem(sessionPath, opts);
  const markdown = renderMarkdown(trace, diagnostics);
  return { markdown, trace, diagnostics, harness };
}

module.exports = { buildPostmortem, runPostmortem, HARNESSES, MAX_SESSION_FILE_BYTES };
