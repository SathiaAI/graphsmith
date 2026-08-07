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
 * cosmtrek/mindwalk) -- reimplemented natively per the design doc's ADAPT
 * decision (Part 2), not vendored or shelled out to.
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

  // CodeRabbit review, PR #23, 2026-08-06 (P1, event ordering): `pending`
  // now maps a call key to the OCCURRENCE object for that call (not the bare
  // call data) and `pendingOrder` holds those occurrence objects themselves,
  // in call-ISSUANCE order -- not just their keys. Before this fix, a
  // resolved call was pushed straight into `events[]` the instant its
  // tool_result arrived, so the final events[] order reflected RESOLUTION
  // order, not issuance order: a call issued first (A) that happened to
  // resolve after a call issued second (B) that resolved sooner ended up
  // positioned AFTER B in events[]. Since eventsBeforeFirstEdit and
  // editsAfterLastVerify (postmortem-classify.js's computeStats) both trust
  // events[] order via each event's own seq, this could invert the report's
  // core "did you verify after your last edit" narrative. Fix: never push
  // to events[] at resolution time; instead record the result onto the
  // occurrence object, and build events[] in one pass over `pendingOrder`
  // (issuance order) after the main parse loop, mirroring how
  // postmortem-codex.js's parseCodexSession already builds its own events[]
  // from callOrder/calls/results. Each occurrence object is a distinct
  // reference even when a real id is legitimately reused after its first
  // occurrence resolved (a NEW occurrence object is pushed for the reuse,
  // per the tool_use branch below) -- so this also structurally subsumes
  // the old by-key EOF-flush loop (formerly "Finding 1", adversarial
  // review, fresh Grok pass, 2026-08-06) that had to guard against a
  // reused key appearing twice in pendingOrder: that guard is no longer
  // needed because pendingOrder no longer holds bare keys that could repeat
  // and require de-duplication, it holds unique occurrence objects.
  const pending = new Map(); // key -> occurrence {key, call, result}, only while unresolved
  const pendingOrder = []; // occurrence objects, in call-issuance order
  // CodeRabbit review, PR #23, 2026-08-06 (id-less-call key collision
  // risk): Finding 8's fix (below, in the tool_use branch) gave each
  // id-less call its own synthetic STRING key (`__no-id-${noIdCounter++}`)
  // so id-less calls wouldn't collide with each other. But a real
  // harness-provided tool_use.id could theoretically BE that literal
  // string ("__no-id-0", etc.) -- an adversarial or coincidentally-shaped
  // log could then collide a real id with a synthetic one on the Map key,
  // wrongly treating the real call as a "duplicate" of an unrelated
  // id-less call. `pending`/`openByKey` here is a Map, which supports
  // non-string keys natively, so id-less calls now key off a fresh
  // Symbol() per call instead (see the tool_use branch below) -- a Symbol
  // is guaranteed unique and a real string id can provably never equal
  // one, closing the collision class entirely rather than just narrowing
  // it. noIdCounter is no longer needed (Symbol() is unique on its own,
  // no counter required to make it so).

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

    // CodeRabbit review, PR #23, 2026-08-06 (session metadata copied
    // without type checks): these four fields used to be copied on a bare
    // truthy guard only (`if (line.cwd && !cwd) cwd = line.cwd;`) -- a
    // malformed/adversarial log line with e.g. a NUMERIC or OBJECT `cwd`
    // would pass the truthy check and reach session.cwd, then flow into
    // buildEvent/the path classifier for every later event, potentially
    // misclassifying every target in the session (normalizePath assumes a
    // string). Every capture below now also requires typeof === "string".
    //
    // sessionId specifically also changes from LAST-value-wins to
    // FIRST-value-wins here: `if (line.sessionId) sessionId = line.sessionId;`
    // (no `!sessionId` guard) meant every later line with a truthy
    // sessionId overwrote the one before it. A session's true id should
    // not change mid-log -- Codex's session_meta handling already treats
    // its own id fields as first-wins (see postmortem-codex.js's
    // `firstSessionMeta` gate) -- so this now matches that: first
    // valid-string sessionId seen wins, later ones are ignored. No fixture
    // in this repo actually varies sessionId within one file, so this is a
    // pure correctness fix, not a behavior change any existing case relied
    // on the old direction for.
    if (typeof line.sessionId === "string" && line.sessionId && !sessionId) sessionId = line.sessionId;
    if (typeof line.cwd === "string" && line.cwd && !cwd) cwd = line.cwd;
    if (typeof line.gitBranch === "string" && line.gitBranch && !gitBranch) gitBranch = line.gitBranch;
    if (typeof line.timestamp === "string" && line.timestamp) {
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
        //
        // CodeRabbit review, PR #23, 2026-08-06 (id-less-call key collision
        // risk): Finding 8's synthetic key used to be a STRING
        // (`__no-id-${noIdCounter++}`) -- a real harness-provided
        // tool_use.id could theoretically literally equal that format
        // ("__no-id-0"), colliding with a synthetic key on the Map and
        // wrongly triggering the dedup check above as if it were a
        // duplicate of an unrelated call. A Symbol() is a value no string
        // (however adversarially chosen) can ever equal, so it closes this
        // collision class entirely rather than just making it unlikely.
        // Only `pending`/`pendingOrder`/the occurrence's own `.key` field
        // ever see this key -- it is never concatenated into a string or
        // JSON.stringify-ed itself (only the call OBJECT is, via
        // buildEvent), so a non-string Map key is safe here.
        const callKey = item.id || Symbol("no-id");
        if (pending.has(callKey)) continue;
        // CodeRabbit review, PR #23, 2026-08-06 (missing/non-string
        // tool_use name): if `item.name` were passed through as-is when
        // missing or non-string, buildEvent would end up emitting
        // `tool: undefined` -- violating the schema's required-string
        // events[].tool field, and, worse, JSON.stringify silently DROPS
        // an object property whose value is undefined, so a JSON consumer
        // of the trace would see an event object missing its `tool` key
        // entirely rather than an explicit null/placeholder. Skipping or
        // dropping the call outright would reintroduce the exact "vanishes
        // with no trace" failure mode this file explicitly avoids
        // elsewhere (F1/Finding 1/Finding 8 above) -- a malformed name is
        // not a reason to hide that a tool call happened at all. A fixed
        // placeholder string keeps the call visible in the report (still
        // resolvable/pairable by id, still counted in stats) while making
        // it obvious in the rendered output that the harness didn't supply
        // a usable name, which is more consistent with this file's
        // "surface it, don't hide it" philosophy than silent omission.
        const call = {
          id: item.id,
          name: typeof item.name === "string" && item.name ? item.name : "unknown",
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
        // CodeRabbit review, PR #23, 2026-08-06 (P1, event ordering): push
        // an OCCURRENCE object (key + call + a result slot, initially
        // unresolved), not the bare call -- see the `pending`/`pendingOrder`
        // declaration comment above for why. `pending` still only holds
        // occurrences that are CURRENTLY unresolved (same dedup-while-
        // pending semantics as before: `pending.has(callKey)` above still
        // only blocks a reissue of a real id while the previous occurrence
        // of that id has no result yet).
        const occ = { key: callKey, call, result: null };
        pendingOrder.push(occ);
        pending.set(callKey, occ);
      } else if (item.type === "tool_result") {
        const occ = pending.get(item.tool_use_id);
        if (!occ) continue;
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
        //
        // CodeRabbit review, PR #23, 2026-08-06 (P1, event ordering): this
        // used to be `events.push(buildEvent(...))` right here -- i.e. the
        // instant a result arrived, not when its call was originally
        // issued. Record the result onto the occurrence object instead;
        // events[] is built in one pass over `pendingOrder` (issuance
        // order) after the main loop, below.
        occ.result = { content: contentToString(item.content), isError: item.is_error === true };
      }
    }
  }

  // CodeRabbit review, PR #23, 2026-08-06 (P1, event ordering): build
  // events[] by walking `pendingOrder` -- call-ISSUANCE order -- exactly
  // once, pairing each occurrence with whatever result it collected (or an
  // empty/pending result if the session ended before one arrived; see
  // buildEvent's `unresolved` handling below, added for the "unresolved
  // calls counted as exact success" CodeRabbit finding). A session ending
  // mid-tool-call must not silently lose the last action, so a still-
  // pending occurrence (occ.result === null) is still emitted here, same as
  // the old by-key EOF-flush loop this replaces (formerly "Finding 1",
  // adversarial review, fresh Grok pass, 2026-08-06) -- but since
  // `pendingOrder` now holds unique occurrence objects rather than
  // (possibly repeated) keys, there is no double-emission risk to guard
  // against here: every occurrence is visited exactly once, by construction.
  for (const occ of pendingOrder) {
    const result = occ.result || { content: "", isError: false, unresolved: true };
    events.push(buildEvent(events.length, cwd, occ.call, result));
  }

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
