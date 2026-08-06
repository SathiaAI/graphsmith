#!/usr/bin/env node
"use strict";

/**
 * scripts/postmortem-claude-code.js -- Claude Code adapter for
 * `graphsmith postmortem` (session-trace v1.0). Reads the JSONL a Claude
 * Code session writes to ~/.claude/projects/**\/*.jsonl.
 *
 * Pure function: JSONL text in, one session-trace object out. No shared
 * mutable state across calls, no network, no clock in any classification
 * decision (the ts/startedAt/endedAt fields on the output are copied
 * verbatim from the log's own timestamps, never generated).
 *
 * ADAPTED from mindwalk's internal/adapter/claudecode/adapter.go (MIT,
 * cosmtrek/mindwalk) per the design doc's ADAPT decision (Part 2), not
 * vendored or shelled out to.
 *
 * Correlation: tool_use / tool_result content items are matched across
 * separate JSONL lines by id, via an in-order pending map (assistant lines
 * carry tool_use items, the following user line carries the matching
 * tool_result). Anything still pending at EOF (a session that ends mid-tool
 * -call) is still emitted as an event, with an empty/absent result rather
 * than silently dropped.
 *
 * Task/Agent tool_use calls become "subagent" marks.
 *
 * isSidechain:true lines (inline subagent-transcript lines occasionally
 * interleaved in a root session file) are skipped when parsing the root
 * file -- this file's contribution to marks/events is dropped, but the line
 * still counts toward session.sourceLines since it *was* valid JSON, just
 * policy-excluded, not malformed. JUDGMENT CALL, flagged for review: the
 * design doc's Part 3b says this "match[es] mindwalk's own ListSessions
 * behavior" -- but mindwalk's actual Parse() (as read from source) does not
 * itself filter isSidechain lines; only ListSessions filters whole
 * `agent-*.jsonl` FILES out of the top-level session listing. Parse() (the
 * function this file's Parse-equivalent actually mirrors) processes
 * isSidechain lines inline exactly like any other line when it encounters
 * them. This implementation instead follows the design doc's stated
 * behavior (skip isSidechain lines within Parse) rather than mindwalk's
 * literal Parse() code, because that is what the design doc explicitly
 * calls for as this build's contract -- but it is a real divergence from
 * the cited prior art, not merely a restatement of it, and a reviewer
 * should treat this as an open question rather than a settled port.
 */

const {
  contentToString,
  injectedUserMessage,
  userMessageNote,
  buildEvent,
  computeStats,
} = require("./postmortem-classify.js");

function isCompaction(line) {
  return line.type === "system" && typeof line.subtype === "string" && line.subtype.toLowerCase().includes("compact");
}

/** Mirrors claudecode.isClaudeLine -- the recognizer used to decide whether
 * this file looks like a Claude Code session log at all.
 *
 * Finding 12 (adversarial review, fresh Grok pass, 2026-08-06): a bare
 * top-level `sessionId` field used to be an unconditional recognizer on its
 * own, regardless of harness -- a line from an unrelated/foreign log shape
 * that happens to carry a top-level `sessionId` (Codex's own session
 * identity lives at `payload.session_id`, nested, so this wasn't meant to
 * catch Codex specifically, but nothing stopped it from catching some other
 * incidental shape) could false-positive the whole file as Claude Code.
 * Since postmortem.js's harness auto-detection races the two adapters and
 * returns on the FIRST one to report `recognized`, a false positive here
 * means a non-Claude-Code file gets silently parsed by the wrong adapter
 * instead of surfacing a clear "could not recognize" error. `sessionId`
 * alone is now only a signal when the line also looks otherwise session-log-
 * shaped (carries a `message` or `timestamp`), narrowing but not entirely
 * removing that lone-field shortcut. */
function isClaudeLine(line) {
  switch (line.type) {
    case "user":
    case "assistant":
    case "system":
    case "ai-title":
      return !!line.timestamp || line.message !== undefined;
    default:
      return typeof line.sessionId === "string" && line.sessionId.length > 0 &&
        (line.message !== undefined || !!line.timestamp);
  }
}

/** Normalizes message.content into a flat item list. Claude Code writes
 * either a bare string (a plain single text turn) or an array of typed
 * content items (text / tool_use / tool_result / ...). */
function contentItems(content) {
  if (content === undefined || content === null) return [];
  if (typeof content === "string") return [{ type: "text", text: content }];
  if (Array.isArray(content)) return content;
  return [];
}

/** Mirrors claudecode.hasUserMessage: false as soon as any tool_result item
 * is present (that shape means this "user" line is the harness relaying a
 * tool result, not something the user typed); true as soon as a non-empty
 * text item is found; otherwise (non-empty content, no tool_result, no
 * non-empty text -- e.g. an image-only turn) defaults true. */
function hasUserMessage(items) {
  if (items.length === 0) return false;
  for (const item of items) {
    if (item.type === "tool_result") return false;
    if (item.type === "text" && typeof item.text === "string" && item.text.trim() !== "") return true;
  }
  return true;
}

function userMessageText(items) {
  const parts = [];
  for (const item of items) {
    if (item.type === "text" && typeof item.text === "string" && item.text.trim() !== "") {
      parts.push(item.text.trim());
    }
  }
  return parts.join("\n");
}

/**
 * @param {string} text raw JSONL file contents
 * @param {{sourcePath?: string}} [opts]
 * @returns {{trace: object, diagnostics: {totalLines:number, unparseableLines:number, recognized:boolean}}}
 */
function parseClaudeCodeSession(text, opts) {
  opts = opts || {};
  const session = {
    harness: "claude-code",
    eventCount: 0,
    sourcePath: opts.sourcePath || "",
  };
  const events = [];
  const marks = [];

  let recognized = false;
  let totalLines = 0;
  let unparseableLines = 0;
  let cwd = "";
  let sessionId = "";
  let model = "";
  let title = "";
  let gitBranch = "";
  let startedAt = "";
  let endedAt = "";

  const pending = new Map(); // id -> {id, name, input, timestamp}
  const pendingOrder = [];
  let noIdCounter = 0; // Finding 8 -- see the tool_use branch below

  const rawLines = String(text).split("\n");
  for (let rawIdx = 0; rawIdx < rawLines.length; rawIdx++) {
    let raw = rawLines[rawIdx];
    if (raw.endsWith("\r")) raw = raw.slice(0, -1);
    if (raw.length === 0) continue; // matches mindwalk's ReadJSONLines: blank lines are not visited at all
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

    if (isClaudeLine(line)) recognized = true;

    // Finding 3 (adversarial review, fresh Grok pass, 2026-08-06): session-
    // level metadata (sessionId/cwd/gitBranch/timestamps) used to be
    // captured from EVERY line, including isSidechain:true lines, BEFORE
    // the skip check below ran -- a nested subagent transcript line can
    // carry its own (different) cwd/timestamps, and capturing those into
    // the ROOT session's fields let a subagent's metadata silently poison
    // the root session's own values (reproduced: a sidechain line with a
    // different cwd caused a real in-repo Read target in the root session
    // to be misclassified as outside the repo, because `cwd` had already
    // been locked in by the sidechain line's value via the `!cwd` guard
    // before the real root cwd line was ever seen). Metadata capture now
    // happens strictly after the sidechain skip, so only root-session lines
    // can set these fields -- the same "sidechain lines don't affect root
    // session state" principle already applied to marks/events below.
    if (line.isSidechain === true) continue; // see file header note

    if (line.sessionId) sessionId = line.sessionId;
    if (line.cwd && !cwd) cwd = line.cwd;
    if (line.gitBranch && !gitBranch) gitBranch = line.gitBranch;
    if (line.timestamp) {
      if (!startedAt) startedAt = line.timestamp;
      endedAt = line.timestamp;
    }

    if (line.type === "ai-title" && line.aiTitle) {
      title = line.aiTitle;
      continue;
    }
    if (isCompaction(line)) {
      // seq: pendingOrder.length -- count of distinct tool_use calls SEEN so
      // far (stream position), not events.length (count already RESOLVED).
      // See the tool_use branch below for the full rationale; kept
      // consistent across all three mark types in this file.
      marks.push({ seq: pendingOrder.length, type: "compaction" });
    }
    if (line.message === undefined || line.message === null) continue;

    const msg = line.message;
    if (!msg || typeof msg !== "object") continue;

    const items = contentItems(msg.content);
    if (line.type === "user" && hasUserMessage(items)) {
      const text2 = userMessageText(items);
      if (!injectedUserMessage(text2)) {
        marks.push({ seq: pendingOrder.length, type: "user-message", note: userMessageNote(text2) });
      }
    }
    if (msg.model && !model) model = msg.model;

    for (const item of items) {
      if (!item || typeof item !== "object") continue;
      if (item.type === "tool_use") {
        // F1 (adversarial review finding, 2026-08-06): a second tool_use
        // reusing an id already pending (no matching tool_result yet) used
        // to silently overwrite the pending-map entry, permanently losing
        // the first call -- it would never be paired with a tool_result
        // (its own result, if one ever arrived, would instead resolve
        // against the second call's data) and never flushed at EOF either
        // (pending.has(call.id) was already true, so it wasn't re-added to
        // pendingOrder). A malformed or adversarial log with a repeated id
        // made a real tool call vanish from the report with no trace.
        // Mirror the Codex adapter's handling of a repeated call id
        // (decodeCall's `if (calls.has(decoded.call.id)) break;`): keep the
        // first call, drop the duplicate tool_use entirely -- including not
        // emitting a second "subagent" mark for it below.
        // Finding 8 (adversarial review, fresh Grok pass, 2026-08-06): a
        // tool_use with no `id` at all (missing/malformed) used to collide
        // with every OTHER id-less tool_use on the literal Map key
        // `undefined` -- the dedup check just above (`pending.has(item.id)`)
        // would then treat every id-less call after the first as a
        // "duplicate" of an unrelated call and silently drop it, the exact
        // "vanishes with no trace" failure mode F1 fixed for real reused
        // ids. Give each id-less call its own synthetic key so id-less
        // calls never collide with each other. Such a call still cannot be
        // reliably paired with a tool_result (which would itself carry no
        // tool_use_id to match against a real key), so it will surface in
        // the report unresolved (flushed at EOF) rather than silently
        // disappearing OR being guess-matched to an unrelated result.
        const callKey = item.id || `__no-id-${noIdCounter++}`;
        if (pending.has(callKey)) continue;
        const call = {
          id: item.id,
          name: item.name,
          input: item.input && typeof item.input === "object" ? item.input : {},
          timestamp: line.timestamp,
        };
        if (call.name === "Task" || call.name === "Agent") {
          // F2 (adversarial review finding, 2026-08-06): seq must reflect
          // stream position (how many calls have been ISSUED so far),
          // matching the Codex adapter's `seq: callOrder.length` -- not
          // events.length (how many calls have already RESOLVED), which
          // undercounts while sibling calls from the same or an earlier
          // turn are still in flight and makes a mark that actually
          // happened after N calls were issued look like it happened
          // after fewer. pendingOrder.length here is the count of distinct
          // calls seen before this one (this call is pushed to
          // pendingOrder just below), the same "before this call" instant
          // Codex's callOrder.length is read at.
          marks.push({ seq: pendingOrder.length, type: "subagent", note: call.name });
        }
        pendingOrder.push(callKey);
        pending.set(callKey, call);
      } else if (item.type === "tool_result") {
        const call = pending.get(item.tool_use_id);
        if (!call) continue;
        pending.delete(item.tool_use_id);
        // Finding 9 (adversarial review, fresh Grok pass, 2026-08-06): loose
        // truthy coercion (`!!item.is_error`) turns the STRING "false" into
        // `true` (a non-empty string is truthy), incorrectly flagging a
        // successful tool result as an error -- reproduced directly.
        // is_error is a structural boolean flag set by the harness (the
        // basis for this adapter's stats.observability.errors === "exact"
        // claim); only a real `true` should count as an error, so any other
        // value (a stray string, a number, undefined, null) is treated as
        // not-an-error rather than guessed at via coercion.
        const result = { content: contentToString(item.content), isError: item.is_error === true };
        events.push(buildEvent(events.length, cwd, call, result));
      }
    }
  }

  // Anything still pending at EOF is still emitted -- a session ending
  // mid-tool-call must not silently lose the last action.
  //
  // Finding 1 (adversarial review, fresh Grok pass, 2026-08-06, CRITICAL): a
  // key can appear in pendingOrder more than once -- specifically, a real
  // tool_use id reused AFTER its first occurrence already resolved (which
  // is legitimate; the dedup check in the tool_use branch above only blocks
  // reuse WHILE pending, by design) pushes that same id into pendingOrder a
  // second time. `pending` (a Map) only ever holds the latest call for a
  // given key, but this loop used to iterate pendingOrder without removing
  // resolved/emitted entries from `pending`, so if that second occurrence
  // was itself still pending at EOF, `pending.has(id)` was true on BOTH
  // pendingOrder occurrences of that id and the SAME call object got pushed
  // to `events` twice. Reproduced: 2 real calls (one resolved, one pending-
  // at-EOF reusing the resolved one's id) produced 3 events instead of 2.
  // Fix: delete from `pending` immediately after emitting, so a repeated
  // key's second occurrence in pendingOrder finds nothing left to emit.
  for (const id of pendingOrder) {
    if (pending.has(id)) {
      const call = pending.get(id);
      pending.delete(id);
      events.push(buildEvent(events.length, cwd, call, { content: "", isError: false }));
    }
  }

  for (let i = 0; i < events.length; i++) events[i].seq = i;

  session.id = sessionId || undefined;
  session.model = model || undefined;
  session.title = title || undefined;
  session.cwd = cwd || undefined;
  session.gitBranch = gitBranch || undefined;
  session.startedAt = startedAt || undefined;
  session.endedAt = endedAt || undefined;
  session.eventCount = events.length;
  session.sourceLines = totalLines;
  for (const k of Object.keys(session)) if (session[k] === undefined) delete session[k];

  // Claude Code tool results carry a structural is_error flag set by the
  // harness -- error observability is "exact", not inferred.
  const stats = computeStats(events, marks, null, "exact");

  const trace = {
    schema_version: "1.0",
    session,
    events,
    marks,
    stats,
  };

  return { trace, diagnostics: { totalLines, unparseableLines, recognized } };
}

module.exports = { parseClaudeCodeSession };
