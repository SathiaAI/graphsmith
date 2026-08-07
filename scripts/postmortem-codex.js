#!/usr/bin/env node
"use strict";

/**
 * scripts/postmortem-codex.js -- Codex adapter for `graphsmith postmortem`
 * (session-trace v1.0). Reads the JSONL Codex writes to
 * ~/.codex/sessions/**\/*.jsonl.
 *
 * Pure function: JSONL text in, one session-trace object out. Same purity
 * constraints as the Claude Code adapter (postmortem-claude-code.js).
 *
 * ADAPTED from mindwalk's internal/adapter/codex/adapter.go (MIT,
 * cosmtrek/mindwalk) per the design doc's ADAPT decision (Part 2).
 *
 * Codex's event vocabulary is more heterogeneous than Claude Code's:
 *   - session_meta   -- session identity, cwd, git branch/commit
 *   - turn_context   -- per-turn cwd/model (first non-empty wins)
 *   - response_item  -- decoded into: user/assistant "message" items,
 *                        function_call / custom_tool_call (a tool
 *                        invocation), function_call_output /
 *                        custom_tool_call_output (its result)
 *   - event_msg      -- "context_compacted" -> compaction mark;
 *                        "patch_apply_end" -> resolves an apply_patch call's
 *                        outcome (only for a DIRECT custom_tool_call
 *                        apply_patch, never for one embedded in a JS "exec"
 *                        wrapper snippet -- directPatches tracks that)
 *   - message        -- a legacy bare top-level shape some older Codex
 *                        session files use instead of response_item-wrapped
 *                        messages
 *
 * spawn_agent calls become "subagent" marks.
 *
 * isError-equivalent handling: Codex's raw JSONL carries NO structural
 * error flag on a function_call_output (unlike Claude Code's tool_result
 * is_error). commandOutputFailed() below infers failure from the output
 * text shape Codex's own exec_command/apply_patch tools are known to print
 * (an {"exit_code": N, ...} JSON envelope, a "Process exited with code N" /
 * "Exit code: N" trailer, an "apply_patch verification failed" prefix, a
 * "script failed"/"aborted by user" status line). FLAGGED PER THE DESIGN
 * DOC: this inference is ported from mindwalk's source-confirmed
 * commandOutputFailed(), but neither this build nor the design doc's
 * research verified it against a REAL Codex session log -- it is carried
 * over from reading Go source, not confirmed against live output shapes.
 * Treat stats.observability.errors == "estimated" (always set for Codex,
 * never "exact") as the honest signal of that uncertainty; a reviewer
 * with access to a real ~/.codex/sessions/*.jsonl file should spot-check
 * this against real function_call_output text before this ships.
 */

const {
  contentToString,
  injectedUserMessage,
  userMessageNote,
  buildEvent,
  computeStats,
} = require("./postmortem-classify.js");

const EXIT_CODE_RE = /^(?:Process exited with code|Exit code:)\s*([0-9]+)\s*$/im;

/** Mirrors codex.commandOutputFailed. */
function commandOutputFailed(output) {
  const trimmed = String(output || "").trim();
  try {
    const envelope = JSON.parse(trimmed);
    if (envelope && typeof envelope === "object") {
      if (typeof envelope.exit_code === "number") return envelope.exit_code !== 0;
      if (envelope.metadata && typeof envelope.metadata.exit_code === "number") return envelope.metadata.exit_code !== 0;
      if (envelope.timed_out === true) return true;
    }
  } catch (_) {
    /* not a JSON envelope -- fall through to text-shape checks */
  }
  if (trimmed.toLowerCase().startsWith("apply_patch verification failed")) return true;
  let firstLine = trimmed;
  const nl = firstLine.indexOf("\n");
  if (nl >= 0) firstLine = firstLine.slice(0, nl);
  const status = firstLine.trim().toLowerCase();
  if (status.startsWith("script completed") || status.startsWith("script running")) return false;
  if (status.startsWith("script failed")) return true;

  let header = trimmed;
  for (const marker of ["\nOutput:\n", "\nFinal output:\n"]) {
    const idx = header.indexOf(marker);
    if (idx >= 0) header = header.slice(0, idx);
  }
  for (const line of header.split("\n")) {
    if (line.trim().toLowerCase() === "aborted by user") return true;
  }
  const m = EXIT_CODE_RE.exec(header);
  return !!m && m[1] !== "0";
}

function canonicalCallID(callType, id, callID, name) {
  if (callType !== "function_call" && callType !== "custom_tool_call") return { ok: false };
  const cid = callID || id;
  return { ok: !!cid && !!name, callID: cid };
}

function parseInputText(text) {
  const trimmed = String(text || "").trim();
  if (trimmed === "") return {};
  try {
    const v = JSON.parse(trimmed);
    if (v && typeof v === "object" && !Array.isArray(v)) return v;
    if (typeof v === "string" && v !== text) return parseInputText(v);
  } catch (_) {
    /* fall through */
  }
  return { _raw: text };
}

function parseInput(raw) {
  if (raw === undefined || raw === null) return {};
  let value;
  if (typeof raw === "string") {
    try {
      value = JSON.parse(raw);
    } catch (_) {
      return { _raw: raw };
    }
  } else {
    value = raw;
  }
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  if (typeof value === "string") return parseInputText(value);
  return { _raw: JSON.stringify(value) };
}

function decodeCall(payload, timestamp) {
  const c = canonicalCallID(payload.type, payload.id, payload.call_id, payload.name);
  if (!c.ok) return null;
  let raw;
  if (payload.type === "function_call") raw = payload.arguments;
  else if (payload.type === "custom_tool_call") raw = payload.input;
  return {
    call: { id: c.callID, name: payload.name, input: parseInput(raw), timestamp },
    source: payload.type,
  };
}

function decodeOutput(payload) {
  if (payload.type !== "function_call_output" && payload.type !== "custom_tool_call_output") return null;
  if (!payload.call_id) return null;
  const output = contentToString(payload.output);
  return { callID: payload.call_id, result: { content: output, isError: commandOutputFailed(output) } };
}

function applyPatchChanges(input, changes) {
  if (!changes || Object.keys(changes).length === 0) return input;
  const merged = Object.assign({}, input);
  let patch = "";
  for (const key of ["patch", "input", "_raw"]) {
    if (typeof input[key] === "string") {
      patch = input[key];
      break;
    }
  }
  if (patch && !patch.endsWith("\n")) patch += "\n";
  const paths = Object.keys(changes).sort();
  for (const p of paths) {
    let operation = "Update";
    const t = String((changes[p] && changes[p].type) || "").toLowerCase();
    if (t === "add") operation = "Add";
    else if (t === "delete") operation = "Delete";
    patch += `*** ${operation} File: ${p}\n`;
  }
  merged.patch = patch;
  return merged;
}

function codexContentText(content) {
  const items = Array.isArray(content) ? content : [];
  const parts = [];
  for (const item of items) {
    if (item && typeof item.text === "string" && item.text.trim() !== "") parts.push(item.text.trim());
  }
  return parts.join("\n");
}

function codexContentHasText(content) {
  const items = Array.isArray(content) ? content : [];
  return items.some((item) => item && typeof item.text === "string" && item.text.trim() !== "");
}

/**
 * @param {string} text raw JSONL file contents
 * @param {{sourcePath?: string}} [opts]
 * @returns {{trace: object, diagnostics: {totalLines:number, unparseableLines:number, recognized:boolean}}}
 */
function parseCodexSession(text, opts) {
  opts = opts || {};
  const marks = [];
  let recognized = false;
  let totalLines = 0;
  let unparseableLines = 0;

  let sessionId = "";
  let cwd = "";
  let commit = "";
  let gitBranch = "";
  let model = "";
  let startedAt = "";
  let endedAt = "";
  let sawSessionMeta = false;

  const calls = new Map();
  const callOrder = [];
  const results = new Map();
  const directPatches = new Map();
  const patchResults = new Map();
  let dupCallCounter = 0; // Finding 2 -- see the response_item/decodeCall branch below

  // CodeRabbit review, PR #23, 2026-08-06 (session metadata copied without
  // type checks): `ts` used to be accepted on a bare truthy check --
  // a malformed/adversarial log line with e.g. a NUMERIC `timestamp` would
  // pass and get copied verbatim into session.startedAt/endedAt (both
  // schema'd as string date-time fields). Requiring typeof === "string"
  // here mirrors the same guard added to every other session-metadata
  // capture site in this file and in postmortem-claude-code.js.
  const applyLineTime = (ts) => {
    if (typeof ts !== "string" || !ts) return;
    if (!startedAt) startedAt = ts;
    endedAt = ts;
  };

  const rawLines = String(text).split("\n");
  for (let idx = 0; idx < rawLines.length; idx++) {
    let raw = rawLines[idx];
    if (raw.endsWith("\r")) raw = raw.slice(0, -1);
    if (raw.length === 0) continue;
    totalLines++;

    let line;
    try {
      line = JSON.parse(raw);
    } catch (_) {
      unparseableLines++;
      continue;
    }
    if (!line || typeof line !== "object" || Array.isArray(line)) {
      unparseableLines++;
      continue;
    }

    applyLineTime(line.timestamp);
    const payload = line.payload;

    switch (line.type) {
      case "session_meta": {
        recognized = true;
        if (payload && typeof payload === "object") {
          const firstSessionMeta = !sawSessionMeta;
          sawSessionMeta = true;
          // CodeRabbit review, PR #23, 2026-08-06 (session metadata copied
          // without type checks): every field below used to be copied on a
          // bare truthy guard -- a malformed/adversarial log with e.g. a
          // NUMERIC or OBJECT payload.cwd would pass and reach session.cwd,
          // then flow into buildEvent/the path classifier for every later
          // event (normalizePath assumes a string), potentially
          // misclassifying every target in the session. Every capture here
          // now also requires typeof === "string". sessionId was already
          // first-wins here (gated on firstSessionMeta); that direction is
          // unchanged, just now type-checked -- see
          // postmortem-claude-code.js's matching metadata-capture block for
          // the same fix applied to the Claude Code adapter, including
          // that file's own sessionId direction note.
          if (firstSessionMeta) {
            const idCandidate =
              (typeof payload.id === "string" && payload.id) ||
              (typeof payload.session_id === "string" && payload.session_id) ||
              "";
            if (idCandidate) sessionId = idCandidate;
          }
          if (typeof payload.cwd === "string" && payload.cwd && !cwd) cwd = payload.cwd;
          if (payload.git && typeof payload.git.commit_hash === "string" && payload.git.commit_hash && !commit) commit = payload.git.commit_hash;
          if (payload.git && typeof payload.git.branch === "string" && payload.git.branch && !gitBranch) gitBranch = payload.git.branch;
          if (typeof payload.timestamp === "string" && payload.timestamp && !startedAt) startedAt = payload.timestamp;
        }
        break;
      }
      case "turn_context": {
        recognized = true;
        if (payload && typeof payload === "object") {
          // CodeRabbit review, PR #23, 2026-08-06 -- same type-check fix as
          // session_meta above.
          if (typeof payload.cwd === "string" && payload.cwd && !cwd) cwd = payload.cwd;
          if (typeof payload.model === "string" && payload.model && !model) model = payload.model;
        }
        break;
      }
      case "response_item": {
        recognized = true;
        if (!payload || typeof payload !== "object") break;
        const decoded = decodeCall(payload, line.timestamp);
        if (decoded) {
          // Finding 2 (adversarial review, fresh Grok pass, 2026-08-06): a
          // reused call_id used to be silently dropped here forever
          // (`break`, never added to callOrder) -- even a legitimate reuse
          // AFTER the first occurrence had already resolved vanished from
          // the report with no trace, the same failure mode Finding 1 (and
          // the original F1 finding) fixed for the Claude Code adapter's
          // duplicate-id handling. Register the call under a synthetic key
          // when its call_id collides with one already registered, so it
          // still gets its own event instead of disappearing. Its result
          // can't be reliably disambiguated from the original occurrence
          // (a function_call_output only carries the shared call_id, not
          // which occurrence it belongs to), so a duplicate-key call is
          // left unresolved (empty result, same as any other call pending
          // at EOF) rather than guessed -- an honest "we can't tell" rather
          // than a silent drop or a risky guess.
          const callKey = calls.has(decoded.call.id) ? `${decoded.call.id} dup#${dupCallCounter++}` : decoded.call.id;
          if (decoded.call.name === "spawn_agent") {
            // seq: callOrder.length here (before this call is pushed to
            // callOrder just below) = count of distinct calls issued so
            // far -- stream position, not completed-result count. The
            // Claude Code adapter's marks (postmortem-claude-code.js) were
            // fixed to use the same "calls issued so far" semantic (an
            // adversarial review finding, 2026-08-06, flagged the two
            // adapters as inconsistent); this comment documents that this
            // file's existing behavior is the one both now share, not that
            // this line changed.
            marks.push({ seq: callOrder.length, type: "subagent", note: decoded.call.name });
          }
          calls.set(callKey, decoded.call);
          callOrder.push(callKey);
          directPatches.set(callKey, decoded.source === "custom_tool_call" && decoded.call.name === "apply_patch");
          break;
        }
        const out = decodeOutput(payload);
        if (out) {
          if (!calls.has(out.callID)) break;
          if (results.has(out.callID)) break;
          results.set(out.callID, out.result);
          break;
        }
        if (payload.type === "message" && payload.role === "user" && codexContentHasText(payload.content)) {
          const t = codexContentText(payload.content);
          if (!injectedUserMessage(t)) {
            marks.push({ seq: callOrder.length, type: "user-message", note: userMessageNote(t) });
          }
        }
        break;
      }
      case "message": {
        recognized = true;
        if (line.role === "user" && codexContentHasText(line.content)) {
          const t = codexContentText(line.content);
          if (!injectedUserMessage(t)) {
            marks.push({ seq: callOrder.length, type: "user-message", note: userMessageNote(t) });
          }
        }
        break;
      }
      case "event_msg": {
        recognized = true;
        if (!payload || typeof payload !== "object") break;
        if (payload.type === "context_compacted") {
          marks.push({ seq: callOrder.length, type: "compaction" });
          break;
        }
        if (payload.type !== "patch_apply_end" || !payload.call_id) break;
        if (!directPatches.get(payload.call_id)) break;
        if (!patchResults.has(payload.call_id)) patchResults.set(payload.call_id, payload);
        break;
      }
      case "":
      case undefined: {
        // CodeRabbit review, PR #23, 2026-08-06 (Codex bare-id over-
        // recognition): mirrors an already-fixed Claude Code issue
        // (Finding 12 in postmortem-claude-code.js's isClaudeLine: a bare
        // sessionId alone was too weak a signal on its own). A type-less
        // line with only `{"id": "foreign-1"}` used to set recognized =
        // true with ZERO other validation -- any unrelated JSONL file that
        // happens to have a top-level `id` string field on some line (many
        // do) risked being auto-detected as a Codex session log. Since
        // postmortem.js's harness auto-detection races both adapters and
        // returns on the FIRST one to report recognized, a false positive
        // here means a non-Codex file gets silently parsed by the wrong
        // adapter instead of surfacing a clear "could not recognize" error.
        // Require the line to ALSO carry a `payload` object -- every real
        // Codex line type this adapter understands (session_meta,
        // turn_context, response_item, event_msg) nests its actual content
        // under `payload`, so requiring one here is a real structural
        // signal, not an arbitrary extra hurdle. `sessionId` is still
        // captured from a type-less line that otherwise looks legitimate.
        if (typeof line.id === "string" && line.id && line.payload && typeof line.payload === "object" && !Array.isArray(line.payload)) {
          recognized = true;
          sessionId = line.id;
        }
        break;
      }
      default:
        break;
    }
  }

  const events = [];
  for (const id of callOrder) {
    const call = Object.assign({}, calls.get(id));
    let result = results.get(id) || { content: "", isError: false };
    const patchResult = patchResults.get(id);
    if (patchResult) {
      call.input = applyPatchChanges(call.input, patchResult.changes);
      if (typeof patchResult.success === "boolean") {
        result = Object.assign({}, result, { isError: !patchResult.success });
      }
    }
    events.push(buildEvent(events.length, cwd, call, result));
  }

  const session = {
    harness: "codex",
    eventCount: events.length,
    sourcePath: opts.sourcePath || "",
  };
  if (sessionId) session.id = sessionId;
  if (model) session.model = model;
  if (cwd) session.cwd = cwd;
  if (gitBranch) session.gitBranch = gitBranch;
  if (startedAt) session.startedAt = startedAt;
  if (endedAt) session.endedAt = endedAt;
  session.sourceLines = totalLines;
  void commit; // session-trace v1.0 has no commit field (dropped: mindwalk's TraceSession.Commit has no equivalent in schemas/session-trace.schema.json -- not one of the design doc's disclosed deltas either way, since the schema simply never included it; noted here so a reviewer can see the value was read but had nowhere schema-conformant to go)

  // Codex logs carry no structural error flag; failures are inferred from
  // output text (commandOutputFailed) -- error observability is always
  // "estimated", never "exact".
  const stats = computeStats(events, marks, null, "estimated");

  const trace = {
    schema_version: "1.0",
    session,
    events,
    marks,
    stats,
  };

  return { trace, diagnostics: { totalLines, unparseableLines, recognized } };
}

module.exports = { parseCodexSession, commandOutputFailed };
