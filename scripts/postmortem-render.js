#!/usr/bin/env node
"use strict";

/**
 * scripts/postmortem-render.js -- mechanical Markdown renderer for
 * `graphsmith postmortem` (design doc Part 3c). Zero-LLM, deterministic:
 * a pure function from a session-trace object (+ small render-time-only
 * diagnostics not part of the persisted schema, see the header note in
 * postmortem-claude-code.js/postmortem-codex.js about totalLines/
 * unparseableLines) to a Markdown string.
 *
 * Explicitly NOT an interpretive/LLM judge layer -- the design doc's Part
 * 3c and 3d are unambiguous that the mechanical report is all that ships in
 * v1; Option A (sealed judge subprocess) and Option B (in-context judge) are
 * both left as an open, later decision, not built here.
 *
 * No clock, no randomness: every timestamp shown is copied verbatim from
 * the trace's own session.startedAt/endedAt.
 */

const ACTION_ORDER = ["search", "read", "edit", "exec", "verify", "other"];

const MARK_GLYPH = {
  "user-message": "›", // ›
  subagent: "○", // ○
  compaction: "◇", // ◇
};

const MARK_LABEL = {
  "user-message": "user turn",
  subagent: "subagent launched",
  compaction: "context compaction",
};

function fmtPct(n) {
  return (n * 100).toFixed(1) + "%";
}

function fmtRange(startedAt, endedAt) {
  if (startedAt && endedAt) return `${startedAt}–${endedAt}`;
  if (startedAt) return startedAt;
  if (endedAt) return endedAt;
  return "(no timestamps in log)";
}

function churnList(events) {
  const editVersion = new Map();
  for (const e of events) {
    for (const t of e.targets || []) {
      if (t.touch === "edit") editVersion.set(t.path, (editVersion.get(t.path) || 0) + 1);
    }
  }
  return Array.from(editVersion.entries())
    .filter(([, count]) => count >= 3)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([p]) => p);
}

/**
 * F8 (adversarial review finding, 2026-08-06): a mark's `note` (e.g. a
 * user-message excerpt) is untrusted, arbitrary text -- userMessageNote()
 * in postmortem-classify.js only trims and truncates it, deliberately: the
 * trace's own marks[].note field is meant to carry raw text for any
 * consumer of the JSON trace, not markdown-escaped text, so escaping does
 * NOT belong there. This is the place a note gets embedded into a
 * Markdown document (the render loop below, `${glyph} ${label} (seq
 * ${m.seq})${note}`), so this is where escaping belongs. Handles:
 * backslash (must go first, so it doesn't double-escape the characters
 * escaped below), double-quote (the note sits inside a `"..."` span --
 * an unescaped quote would visually break out of it), backtick (an odd
 * count, especially a run of 3, can open an inline or fenced code span
 * that swallows the rest of the document), and newlines/carriage returns
 * (collapsed to a single space -- each mark renders as one bullet line;
 * an embedded newline would inject what looks like an unrelated new line
 * into the timeline).
 *
 * Finding 6 (adversarial review, fresh Grok pass, 2026-08-06) broadened
 * this same helper to other log-content session fields (cwd, gitBranch,
 * model, the startedAt/endedAt-derived range label) interpolated further
 * down in renderMarkdown -- same untrusted-text-into-Markdown concern,
 * same fix, name kept as-is to minimize diff.
 */
function escapeMarkNote(text) {
  return String(text || "")
    .replace(/\\/g, "\\\\")
    .replace(/`/g, "\\`")
    .replace(/"/g, '\\"')
    .replace(/[\r\n]+/g, " ");
}

function outsideTouches(events) {
  const out = [];
  const seen = new Set();
  for (const e of events) {
    for (const o of e.outside || []) {
      const key = o.scope + "|" + o.path;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(o);
    }
  }
  return out;
}

/**
 * @param {object} trace a session-trace v1.0 object
 * @param {{unparseableLines?: number}} [diagnostics] render-time-only extra
 *   info NOT part of the persisted schema (see adapter file headers for why)
 */
function renderMarkdown(trace, diagnostics) {
  diagnostics = diagnostics || {};
  const { session, events, marks, stats } = trace;
  const lines = [];

  // Finding 6 (adversarial review, fresh Grok pass, 2026-08-06): session-
  // level fields sourced from the log ITSELF (cwd, gitBranch, model,
  // timestamps -- unlike session.harness, a literal set by the adapter, and
  // session.sourcePath, a CLI-invocation-controlled filesystem path, not
  // log content) used to be interpolated into this Markdown document
  // unescaped -- only a mark's `note` got escapeMarkNote() treatment (see
  // that function's own comment for why escaping belongs at render sites,
  // not at parse time). A crafted cwd/gitBranch/model/timestamp containing
  // an embedded newline or a triple-backtick fence could inject a spurious
  // line or swallow the rest of the document the same way an unescaped
  // mark note could. Escaped at every log-content render site below.
  const rangeLabel = fmtRange(session.startedAt, session.endedAt);
  lines.push(`# Session post-mortem — ${session.harness}, ${escapeMarkNote(rangeLabel)}`);
  lines.push("");

  const sourceBits = [`${stats && session.sourceLines !== undefined ? session.sourceLines : "?"} lines`];
  if (diagnostics.unparseableLines) {
    sourceBits.push(`${diagnostics.unparseableLines} unparseable — skipped, not dropped silently`);
  }
  lines.push(`Source: ${session.sourcePath || "(no source path recorded)"} (${sourceBits.join(", ")})`);

  // Finding 7 (adversarial review, fresh Grok pass, 2026-08-06, cosmetic):
  // the old one-liner (`repoBits.join(" (") + (session.gitBranch ? ")" : "")`)
  // appended a closing ")" whenever gitBranch was set, even when cwd was
  // NOT set -- with only one repoBits entry, `.join(" (")` has no second
  // element to insert the separator before, so no "(" was ever opened, yet
  // the trailing ")" still got appended: `Repo: branch: main)`, a stray
  // unmatched paren. Spelled out explicitly per combination instead.
  let repoLine;
  if (session.cwd && session.gitBranch) {
    repoLine = `Repo: ${escapeMarkNote(session.cwd)} (branch: ${escapeMarkNote(session.gitBranch)})`;
  } else if (session.cwd) {
    repoLine = `Repo: ${escapeMarkNote(session.cwd)}`;
  } else if (session.gitBranch) {
    repoLine = `Repo: branch: ${escapeMarkNote(session.gitBranch)}`;
  } else {
    repoLine = "Repo: (not recorded in log)";
  }
  lines.push(repoLine + ` — observability: repoSize ${stats.observability.repoSize}`);
  if (session.model) lines.push(`Model: ${escapeMarkNote(session.model)}`);
  lines.push("");

  lines.push("## What happened (mechanical, zero-LLM)");
  lines.push("");

  const total = ACTION_ORDER.reduce((sum, k) => sum + (stats.actions[k] || 0), 0);
  const actionBits = ACTION_ORDER.filter((k) => stats.actions[k] > 0).map((k) => `${stats.actions[k]} ${k}`);
  lines.push(`${total} tool call${total === 1 ? "" : "s"}: ${actionBits.length ? actionBits.join(", ") : "none"}`);

  const churn = churnList(events);
  const churnSuffix = churn.length ? ` (churn: ${churn.join(", ")})` : "";
  lines.push(`${stats.touched} file${stats.touched === 1 ? "" : "s"} touched, ${stats.edited} edited` +
    (stats.churnFiles ? ` (${stats.churnFiles} edited 3+ times${churnSuffix})` : ""));

  lines.push(`${stats.eventsBeforeFirstEdit} events before the first edit`);
  lines.push(`Error rate: ${fmtPct(stats.errorRate)} (${errorCount(stats)} of ${events.length} calls returned an error)`);

  if (stats.editsAfterLastVerify > 0) {
    lines.push(`${stats.editsAfterLastVerify} edit${stats.editsAfterLastVerify === 1 ? "" : "s"} after the last verify-shaped command — the session did not re-verify after its last ${stats.editsAfterLastVerify} edit${stats.editsAfterLastVerify === 1 ? "" : "s"}`);
  } else if (stats.actions.verify > 0) {
    lines.push("No edits after the last verify-shaped command.");
  }

  const outside = outsideTouches(events);
  if (outside.length) {
    // NOTE: unlike targets, an `outside` item carries no `weak` flag in the
    // schema (schemas/session-trace.schema.json's outside items are only
    // {scope, path}) -- a structured tool argument (e.g. Read on an
    // absolute path outside the repo) can resolve to an outside touch just
    // as easily as a free-text-extracted one, so this line deliberately
    // does not claim "weak" the way the design doc's illustrative §3c
    // example did; that claim is not something the data actually carries
    // for every case, and asserting it unconditionally would be exactly
    // the kind of unproven claim a mechanical/zero-LLM report must avoid.
    lines.push(`${outside.length} touch${outside.length === 1 ? "" : "es"} outside the repo: ` +
      outside.map((o) => `${o.path} (scope: ${o.scope})`).join("; "));
  }
  lines.push("");

  lines.push("## Timeline marks");
  lines.push("");
  if (!marks.length) {
    lines.push("(no marks recorded)");
  } else {
    for (const m of marks) {
      const glyph = MARK_GLYPH[m.type] || "•";
      const label = MARK_LABEL[m.type] || m.type;
      const note = m.note ? `: "${escapeMarkNote(m.note)}"` : "";
      lines.push(`${glyph} ${label} (seq ${m.seq})${note}`);
    }
  }
  lines.push("");

  lines.push('Note: "verify" means a command shaped like a test/build runner ran, not that it passed.');
  lines.push('Note: "edited"/"touched" counts distinct files by final touch level; targets marked weak were inferred from free text, not a structured tool argument.');

  return lines.join("\n") + "\n";
}

function errorCount(stats) {
  return ACTION_ORDER.reduce((sum, k) => sum + (stats.errors[k] || 0), 0);
}

module.exports = { renderMarkdown };
