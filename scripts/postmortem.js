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
 * Harness detection (--harness omitted): tries the Claude Code adapter
 * first, then Codex, and uses whichever adapter's own recognizer
 * (isClaudeLine / the codex line-type switch) reports the file as
 * recognized. JUDGMENT CALL, not specified by the design doc (which only
 * documents the `--harness claude-code|codex` flag, not what happens when
 * it is omitted): this two-adapter-race approach can misclassify a file
 * that happens to satisfy both recognizers' loose heuristics (unlikely in
 * practice -- the two vocabularies barely overlap -- but not proven
 * impossible). --harness is the reliable path; auto-detection is a
 * convenience with a documented failure mode (an explicit error naming both
 * attempts, never a silent guess presented as certain).
 */

const fs = require("fs");

const { parseClaudeCodeSession } = require("./postmortem-claude-code.js");
const { parseCodexSession } = require("./postmortem-codex.js");
const { renderMarkdown } = require("./postmortem-render.js");

const HARNESSES = ["claude-code", "codex"];

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

  const attempts = [];
  for (const harness of HARNESSES) {
    const result = parseWithHarness(harness, text, parseOpts);
    attempts.push({ harness, result });
    if (result.diagnostics.recognized) {
      return { trace: result.trace, diagnostics: result.diagnostics, harness };
    }
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

module.exports = { buildPostmortem, runPostmortem, HARNESSES };
