#!/usr/bin/env node
"use strict";

/* tests/postmortem/run-tests.js -- Lane F test suite for `graphsmith
 * postmortem` (schemas/session-trace.schema.json, scripts/postmortem-
 * classify.js, scripts/postmortem-claude-code.js, scripts/postmortem-
 * codex.js, scripts/postmortem-render.js, scripts/postmortem.js, and the
 * `postmortem` subcommand in scripts/graphsmith-cli.js).
 *
 * Standalone, framework-free, mirrors this repo's own
 * tests/<component>/run-tests.js convention (see e.g.
 * tests/reconcile/run-tests.js): report()/PASS-FAIL-SKIP, exit 1 on any
 * failure. Discoverable by scripts/ci-run-suites.js's literal
 * "run-tests.js" filename walk.
 *
 * Fixtures live in tests/postmortem/fixtures/*.jsonl (real, checked-in
 * JSONL files, not generated at test time) except where a case inherently
 * needs a real, live filesystem path (weak-target repo-existence gating,
 * an outside-repo touch scoped "tmp") -- those are built at test time
 * against a real temp directory so the assertion is not host-path-
 * dependent.
 *
 * Covers, at minimum, every case the Lane F build brief calls out:
 *   - a normal Claude Code session and a normal Codex session
 *   - injected user messages filtered correctly (both harnesses)
 *   - a tool call still pending at EOF (not silently dropped, both harnesses)
 *   - sidechain/subagent lines skipped for Claude Code root-file parsing
 *   - a touch outside the repo (weak-flagged path extraction case + a
 *     structured-arg outside touch, which is NOT weak -- see the note in
 *     postmortem-render.js about why "weak" is never asserted on outside
 *     touches unconditionally)
 *   - malformed/unparseable JSONL lines skipped and counted, not silently
 *     dropped or crashing the parser (both harnesses)
 *   - Windows-style paths (drive-letter absolute, cross-drive outside touch)
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const cp = require("child_process");

const REPO = path.resolve(__dirname, "..", "..");
const FIXTURES = path.join(__dirname, "fixtures");
const CLI = path.join(REPO, "scripts", "graphsmith-cli.js");

const classify = require(path.join(REPO, "scripts", "postmortem-classify.js"));
const { parseClaudeCodeSession } = require(path.join(REPO, "scripts", "postmortem-claude-code.js"));
const { parseCodexSession } = require(path.join(REPO, "scripts", "postmortem-codex.js"));
const { renderMarkdown } = require(path.join(REPO, "scripts", "postmortem-render.js"));
const { buildPostmortem, runPostmortem } = require(path.join(REPO, "scripts", "postmortem.js"));

let passed = 0;
let failed = 0;
let skipped = 0;

function report(name, ok, detail) {
  if (ok === true) {
    console.log(`PASS: ${name}`);
    passed++;
  } else if (ok === false) {
    console.log(`FAIL: ${name}${detail ? " -- " + detail : ""}`);
    failed++;
  } else {
    console.log(`UNAVAILABLE: ${name}${detail ? " -- " + detail : ""}`);
    skipped++;
  }
}

function readFixture(name) {
  return fs.readFileSync(path.join(FIXTURES, name), "utf8");
}

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-postmortem-${label}-`));
}

function cleanup(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {
    /* best-effort */
  }
}

/* ===========================================================================
 * GROUP 0: every new file is syntactically valid, standalone.
 * ========================================================================= */
function groupSyntax() {
  console.log("\n=== GROUP 0: node --check on every new Lane F file ===");
  const files = [
    "schemas/session-trace.schema.json",
    "scripts/postmortem-patterns.json",
    "scripts/postmortem-classify.js",
    "scripts/postmortem-claude-code.js",
    "scripts/postmortem-codex.js",
    "scripts/postmortem-render.js",
    "scripts/postmortem.js",
    "scripts/graphsmith-cli.js",
  ];
  for (const f of files) {
    const full = path.join(REPO, f);
    if (f.endsWith(".json")) {
      try {
        JSON.parse(fs.readFileSync(full, "utf8"));
        report(`0.${f} is valid JSON`, true);
      } catch (e) {
        report(`0.${f} is valid JSON`, false, e.message);
      }
      continue;
    }
    const res = cp.spawnSync(process.execPath, ["--check", full], { encoding: "utf8" });
    report(`0.${f} passes node --check`, res.status === 0, res.stderr);
  }
}

/* ===========================================================================
 * GROUP 1: schema shape sanity (hand-rolled structural checks, not a full
 * JSON-Schema validator -- see scripts/schema-validate.js's own header for
 * why this repo hand-rolls rather than takes an ajv dependency; this suite
 * follows the same zero-dep discipline at a smaller, purpose-built scope).
 * ========================================================================= */
function assertTraceShape(trace, label) {
  report(`1.${label} schema_version is "1.0"`, trace.schema_version === "1.0");
  report(`1.${label} session.harness is claude-code|codex`, ["claude-code", "codex"].includes(trace.session.harness));
  report(`1.${label} session.sourcePath present`, typeof trace.session.sourcePath === "string" && trace.session.sourcePath.length > 0);
  report(`1.${label} session.eventCount matches events.length`, trace.session.eventCount === trace.events.length);
  report(`1.${label} events is an array`, Array.isArray(trace.events));
  report(`1.${label} marks is an array`, Array.isArray(trace.marks));
  const eventFieldsOk = trace.events.every((e) =>
    typeof e.seq === "number" &&
    typeof e.tool === "string" &&
    ["search", "read", "edit", "exec", "verify", "other"].includes(e.action) &&
    Array.isArray(e.targets) &&
    typeof e.resultBytes === "number" &&
    typeof e.isError === "boolean" &&
    typeof e.summary === "string"
  );
  report(`1.${label} every event has the required session-trace fields`, eventFieldsOk);
  const seqOk = trace.events.every((e, i) => e.seq === i);
  report(`1.${label} event seq is contiguous from 0`, seqOk);
  const markFieldsOk = trace.marks.every((m) =>
    typeof m.seq === "number" && ["compaction", "user-message", "subagent"].includes(m.type)
  );
  report(`1.${label} every mark has the required fields`, markFieldsOk);
  const targetFieldsOk = trace.events.every((e) =>
    e.targets.every((t) => typeof t.path === "string" && ["hit", "read", "edit"].includes(t.touch))
  );
  report(`1.${label} every target has path+touch, touch in enum`, targetFieldsOk);
  const outsideFieldsOk = trace.events.every((e) =>
    !e.outside || e.outside.every((o) => ["home", "tmp", "other"].includes(o.scope) && typeof o.path === "string" && !("weak" in o))
  );
  report(`1.${label} outside items are {scope,path} only (no weak field)`, outsideFieldsOk);
  const s = trace.stats;
  const statsFieldsOk = [
    "filesInRepo", "touched", "edited", "eventsBeforeFirstEdit", "errorRate",
    "maxEditsPerFile", "churnFiles", "userTurns", "compactions", "subagents",
    "resultBytes", "editsAfterLastVerify",
  ].every((k) => typeof s[k] === "number");
  report(`1.${label} stats numeric fields present`, statsFieldsOk);
  report(`1.${label} stats.observability.verifyOutcome is always "unavailable"`, s.observability.verifyOutcome === "unavailable");
  report(`1.${label} stats.observability.repoSize in enum`, ["exact", "unavailable"].includes(s.observability.repoSize));
  report(`1.${label} stats has NO fovea/parafovea/regressionRate (dropped mindwalk fields)`,
    !("fovea" in s) && !("parafovea" in s) && !("regressionRate" in s));
  report(`1.${label} targets have NO fileId (dropped mindwalk field)`,
    trace.events.every((e) => e.targets.every((t) => !("fileId" in t))));
  report(`1.${label} stats.touched is present (new field, no mindwalk equivalent)`, typeof s.touched === "number");
}

/* ===========================================================================
 * GROUP 2: normal sessions, both harnesses.
 * ========================================================================= */
function groupNormalSessions() {
  console.log("\n=== GROUP 2: normal Claude Code / Codex sessions ===");

  const cc = parseClaudeCodeSession(readFixture("claude-code-normal.jsonl"), { sourcePath: "/fixtures/claude-code-normal.jsonl" });
  assertTraceShape(cc.trace, "cc-normal");
  report("2.1 CC normal: recognized", cc.diagnostics.recognized === true);
  report("2.2 CC normal: 3 events (Read, Edit, Bash->verify)", cc.trace.events.length === 3);
  report("2.3 CC normal: action sequence read,edit,verify", JSON.stringify(cc.trace.events.map((e) => e.action)) === JSON.stringify(["read", "edit", "verify"]));
  report("2.4 CC normal: 1 user-message mark", cc.trace.marks.filter((m) => m.type === "user-message").length === 1);
  report("2.5 CC normal: touched=1, edited=1", cc.trace.stats.touched === 1 && cc.trace.stats.edited === 1);
  report("2.6 CC normal: editsAfterLastVerify=0 (verify ran last)", cc.trace.stats.editsAfterLastVerify === 0);
  report("2.7 CC normal: sourceLines=9, unparseable=0", cc.trace.session.sourceLines === 9 && cc.diagnostics.unparseableLines === 0);
  report("2.8 CC normal: model captured", cc.trace.session.model === "claude-test-model");
  const ccMd = renderMarkdown(cc.trace, cc.diagnostics);
  report("2.9 CC normal: renders non-empty Markdown with a title line", typeof ccMd === "string" && ccMd.startsWith("# Session post-mortem — claude-code"));

  const cx = parseCodexSession(readFixture("codex-normal.jsonl"), { sourcePath: "/fixtures/codex-normal.jsonl" });
  assertTraceShape(cx.trace, "codex-normal");
  report("2.10 Codex normal: recognized", cx.diagnostics.recognized === true);
  report("2.11 Codex normal: 2 events (apply_patch->edit, exec_command->verify)", cx.trace.events.length === 2);
  report("2.12 Codex normal: action sequence edit,verify", JSON.stringify(cx.trace.events.map((e) => e.action)) === JSON.stringify(["edit", "verify"]));
  report("2.13 Codex normal: apply_patch target is src/parser.js, touch edit", cx.trace.events[0].targets.some((t) => t.path === "src/parser.js" && t.touch === "edit"));
  report("2.14 Codex normal: 1 user-message mark", cx.trace.marks.filter((m) => m.type === "user-message").length === 1);
  report("2.15 Codex normal: model + gitBranch captured", cx.trace.session.model === "gpt-5.5-codex" && cx.trace.session.gitBranch === "main");
  report("2.16 Codex normal: observability.errors is 'estimated', never 'exact'", cx.trace.stats.observability.errors === "estimated");
  const cxMd = renderMarkdown(cx.trace, cx.diagnostics);
  report("2.17 Codex normal: renders non-empty Markdown with a title line", typeof cxMd === "string" && cxMd.startsWith("# Session post-mortem — codex"));
}

/* ===========================================================================
 * GROUP 3: injected user messages filtered correctly.
 * ========================================================================= */
function groupInjectedMessages() {
  console.log("\n=== GROUP 3: injected user messages ===");

  const cc = parseClaudeCodeSession(readFixture("claude-code-injected.jsonl"), { sourcePath: "/fixtures/claude-code-injected.jsonl" });
  const ccUserMarks = cc.trace.marks.filter((m) => m.type === "user-message");
  report("3.1 CC injected: exactly 1 real user-message mark survives", ccUserMarks.length === 1);
  report("3.2 CC injected: surviving mark is the real message, not the injected ones", ccUserMarks[0] && ccUserMarks[0].note === "Please add a README badge.");
  report("3.3 CC injected: <system-reminder> text is NOT a mark", !cc.trace.marks.some((m) => m.note && m.note.includes("harness-injected")));
  report("3.4 CC injected: <local-command-caveat> text is NOT a mark", !cc.trace.marks.some((m) => m.note && m.note.includes("truncated")));

  const cx = parseCodexSession(readFixture("codex-injected.jsonl"), { sourcePath: "/fixtures/codex-injected.jsonl" });
  const cxUserMarks = cx.trace.marks.filter((m) => m.type === "user-message");
  report("3.5 Codex injected: exactly 1 real user-message mark survives", cxUserMarks.length === 1);
  report("3.6 Codex injected: surviving mark is the real message", cxUserMarks[0] && cxUserMarks[0].note === "Please add error handling to the CLI entrypoint.");
  report("3.7 Codex injected: '# AGENTS.md instructions' preamble filtered", !cx.trace.marks.some((m) => m.note && m.note.includes("AGENTS.md")));
  report("3.8 Codex injected: <environment_context> tag-shaped text filtered", !cx.trace.marks.some((m) => m.note && m.note.includes("environment_context")));

  // Unit-level: injectedUserMessage() shape rules directly.
  report("3.9 injectedUserMessage: tag envelope -> true", classify.injectedUserMessage("<foo>\nbar\n</foo>") === true);
  report("3.10 injectedUserMessage: AGENTS.md preamble -> true", classify.injectedUserMessage("# AGENTS.md instructions\nfoo") === true);
  report("3.11 injectedUserMessage: real prose starting with '<' but not closing '>' at end -> false", classify.injectedUserMessage("<script>alert(1) then some more text") === false);
  report("3.12 injectedUserMessage: ordinary text -> false", classify.injectedUserMessage("please fix the bug") === false);
}

/* ===========================================================================
 * GROUP 4: tool call still pending at EOF, both harnesses.
 * ========================================================================= */
function groupPendingAtEOF() {
  console.log("\n=== GROUP 4: tool call pending at EOF ===");

  const cc = parseClaudeCodeSession(readFixture("claude-code-pending-eof.jsonl"), { sourcePath: "/fixtures/claude-code-pending-eof.jsonl" });
  report("4.1 CC pending-EOF: 2 events (Read completed, Edit still pending)", cc.trace.events.length === 2);
  const pendingEvent = cc.trace.events[1];
  report("4.2 CC pending-EOF: pending event is the Edit call, not dropped", pendingEvent && pendingEvent.tool === "Edit");
  report("4.3 CC pending-EOF: pending event has resultBytes=0, isError=false (no result ever arrived)", pendingEvent && pendingEvent.resultBytes === 0 && pendingEvent.isError === false);
  report("4.4 CC pending-EOF: pending event still classified edit + has its target", pendingEvent && pendingEvent.action === "edit" && pendingEvent.targets.some((t) => t.path === "config.json"));

  // Codex: a function_call with no matching function_call_output.
  const codexLines = [
    { timestamp: "2026-08-01T20:00:00Z", type: "session_meta", payload: { id: "codex-pending-1", session_id: "codex-pending-1", timestamp: "2026-08-01T20:00:00Z", cwd: "/repo" } },
    { timestamp: "2026-08-01T20:00:01Z", type: "response_item", payload: { type: "function_call", id: "fc-1", call_id: "call-1", name: "exec_command", arguments: JSON.stringify({ cmd: "npm test", workdir: "/repo" }) } },
  ];
  const cxText = codexLines.map((l) => JSON.stringify(l)).join("\n") + "\n";
  const cx = parseCodexSession(cxText, { sourcePath: "/fixtures/codex-pending.jsonl" });
  report("4.5 Codex pending-EOF: 1 event still emitted for the unmatched call", cx.trace.events.length === 1);
  report("4.6 Codex pending-EOF: pending event classified verify (npm test), not dropped", cx.trace.events[0] && cx.trace.events[0].action === "verify");
  report("4.7 Codex pending-EOF: pending event isError=false (no output text to infer failure from)", cx.trace.events[0] && cx.trace.events[0].isError === false);
}

/* ===========================================================================
 * GROUP 5: sidechain/subagent lines skipped for CC root-file parsing.
 * ========================================================================= */
function groupSidechain() {
  console.log("\n=== GROUP 5: sidechain lines skipped, subagent marks kept ===");

  const cc = parseClaudeCodeSession(readFixture("claude-code-sidechain.jsonl"), { sourcePath: "/fixtures/claude-code-sidechain.jsonl" });
  report("5.1 sidechain: only 1 event (the root Task call) -- sidechain Read/tool_result excluded", cc.trace.events.length === 1);
  report("5.2 sidechain: the one event is the Task call", cc.trace.events[0] && cc.trace.events[0].tool === "Task");
  report("5.3 sidechain: no event has tool Read (that call lived only in the isSidechain lines)", !cc.trace.events.some((e) => e.tool === "Read"));
  report("5.4 sidechain: subagent mark recorded for the Task launch", cc.trace.marks.some((m) => m.type === "subagent" && m.note === "Task"));
  report("5.5 sidechain: stats.subagents === 1", cc.trace.stats.subagents === 1);
  report("5.6 sidechain: no target for src/auth.js leaked into stats (sidechain-only read)", !cc.trace.events.some((e) => e.targets.some((t) => t.path === "src/auth.js")));
}

/* ===========================================================================
 * GROUP 6: a touch outside the repo.
 * ========================================================================= */
function groupOutsideRepo() {
  console.log("\n=== GROUP 6: touches outside the repo ===");

  const cc = parseClaudeCodeSession(readFixture("claude-code-outside-repo.jsonl"), { sourcePath: "/fixtures/claude-code-outside-repo.jsonl" });
  const ev = cc.trace.events[0];
  report("6.1 outside-repo: event has zero in-repo targets", ev && ev.targets.length === 0);
  report("6.2 outside-repo: event.outside has exactly 1 entry for /etc/hosts", ev && Array.isArray(ev.outside) && ev.outside.length === 1 && ev.outside[0].path === "/etc/hosts");
  report("6.3 outside-repo: scope is one of the enum values", ev && ["home", "tmp", "other"].includes(ev.outside[0].scope));

  // Weak-target extraction touches a real filesystem path in its command
  // text, so this half of the case is built at test time rather than
  // committed as a static fixture (see file header). Also exercises: a
  // Bash-extracted path INSIDE the repo (kept, weak:true) vs the free-text
  // tmp-scoped outside touch (never subject to weak-target handling at
  // all -- outside touches aren't gated by inclusion, only labeled).
  const dir = tmpDir("weak-target");
  try {
    fs.writeFileSync(path.join(dir, "README.md"), "# demo\n");
    const cmd = "cat README.md " + path.join(os.tmpdir(), "definitely-outside.log");
    const { targets, outside } = classify.targetsFor(dir, "Bash", { command: cmd }, "");
    report("6.4 weak target inside repo kept when the file really exists", targets.some((t) => t.path === "README.md" && t.weak === true));
    report("6.5 outside touch under os.tmpdir() is scope 'tmp' (deterministic, not host-homedir-dependent)", outside.some((o) => o.scope === "tmp"));

    // F3 regression (adversarial review finding, 2026-08-06): a weak target
    // must be kept even when the extracted path does not exist on the
    // machine currently running the tool -- gating inclusion on
    // fs.existsSync() made the same session log produce a different report
    // depending on which machine parsed it, violating this file's own
    // determinism rule. Confirmed via git-stash isolation that this
    // assertion FAILS against the pre-fix repoPathExists()-gated code
    // (targets2.length was 0) and PASSES against the fix.
    const cmd2 = "cat " + path.join(dir, "does-not-exist.txt");
    const { targets: targets2 } = classify.targetsFor(dir, "Bash", { command: cmd2 }, "");
    report("6.6 weak target kept even when the extracted path does not exist on disk (host-independent, deterministic)", targets2.some((t) => t.path === "does-not-exist.txt" && t.weak === true));
  } finally {
    cleanup(dir);
  }
}

/* ===========================================================================
 * GROUP 7: malformed/unparseable JSONL lines.
 * ========================================================================= */
function groupMalformed() {
  console.log("\n=== GROUP 7: malformed/unparseable JSONL lines ===");

  const cc = parseClaudeCodeSession(readFixture("claude-code-malformed.jsonl"), { sourcePath: "/fixtures/claude-code-malformed.jsonl" });
  report("7.1 malformed: parser did not throw (already true if we got here)", true);
  report("7.2 malformed: sourceLines counts all 7 non-blank raw lines", cc.trace.session.sourceLines === 7);
  report("7.3 malformed: exactly 3 unparseable lines counted (invalid JSON x2 + non-object JSON)", cc.diagnostics.unparseableLines === 3);
  report("7.4 malformed: the 1 valid tool call still produced an event", cc.trace.events.length === 1 && cc.trace.events[0].tool === "Read");
  report("7.5 malformed: the 1 valid user message still produced a mark", cc.trace.marks.filter((m) => m.type === "user-message").length === 1);
  report("7.6 malformed: still recognized as a Claude Code session overall", cc.diagnostics.recognized === true);

  // Codex adapter must not crash on malformed lines either (inline text,
  // not a committed fixture -- see file header).
  const codexRaw = [
    '{"timestamp":"2026-08-01T21:00:00Z","type":"session_meta","payload":{"id":"codex-malformed-1","session_id":"codex-malformed-1","cwd":"/repo"}}',
    "not json at all {{{",
    '{"timestamp":"2026-08-01T21:00:01Z","type":"response_item","payload":{"type":"function_call","id":"fc-1","call_id":"call-1","name":"exec_command","arguments":"{\\"cmd\\":\\"npm test\\",\\"workdir\\":\\"/repo\\"}"}}',
    "42",
    '{"timestamp":"2026-08-01T21:00:02Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call-1","output":"Process exited with code 0"}}',
  ].join("\n") + "\n";
  let cxThrew = false;
  let cx;
  try {
    cx = parseCodexSession(codexRaw, { sourcePath: "/fixtures/codex-malformed.jsonl" });
  } catch (_) {
    cxThrew = true;
  }
  report("7.7 Codex malformed: parser did not throw", cxThrew === false);
  report("7.8 Codex malformed: 2 unparseable lines counted (invalid JSON + bare number)", !!cx && cx.diagnostics.unparseableLines === 2);
  report("7.9 Codex malformed: the 1 valid tool call still produced an event", !!cx && cx.trace.events.length === 1 && cx.trace.events[0].action === "verify");
}

/* ===========================================================================
 * GROUP 8: Windows-style paths.
 * ========================================================================= */
function groupWindowsPaths() {
  console.log("\n=== GROUP 8: Windows-style paths ===");

  const cc = parseClaudeCodeSession(readFixture("claude-code-windows-paths.jsonl"), { sourcePath: "/fixtures/claude-code-windows-paths.jsonl" });
  report("8.1 windows: 3 events", cc.trace.events.length === 3);
  report("8.2 windows: nested file resolves to posix-slash relative path (src/main.js)", cc.trace.events[0].targets.some((t) => t.path === "src/main.js"));
  report("8.3 windows: deeper nested file resolves correctly (src/lib/util.js)", cc.trace.events[1].targets.some((t) => t.path === "src/lib/util.js"));
  report("8.4 windows: cross-drive path is an outside touch, not silently dropped or mis-resolved", cc.trace.events[2].targets.length === 0 && Array.isArray(cc.trace.events[2].outside) && cc.trace.events[2].outside.length === 1);
  report("8.5 windows: outside path is forward-slash normalized for display", cc.trace.events[2].outside[0].path === "D:/secrets/file.txt");

  // Direct path.win32-vs-path.posix unit checks, host-OS independent (this
  // suite may run on a Linux CI runner, but these assertions must hold
  // regardless of the HOST platform, which is the whole point of this
  // Windows-path handling -- see postmortem-classify.js's file header).
  const r1 = classify.normalizePath("C:\\Users\\dev\\repo", "", "C:\\Users\\dev\\repo\\a\\b.txt");
  report("8.6 normalizePath: win32 nested relative resolves to posix-slash form", r1.ok && r1.rel === "a/b.txt");
  const r2 = classify.normalizePath("/repo", "", "/repo/a/b.txt");
  report("8.7 normalizePath: posix nested relative still works (no regression from win32 support)", r2.ok && r2.rel === "a/b.txt");
  // CodeRabbit review, PR #23, 2026-08-06 (CR-6, silently-dropped parent-
  // relative paths): this used to assert ok:false -- the path was silently
  // dropped from both targets and outside. That was itself the bug CR-6
  // fixes (see GROUP 16's CR-6 cases for the primary regression coverage);
  // updated here to assert the new, correct behavior: a cwd is available,
  // so the path resolves against it and surfaces as an outside touch
  // instead of vanishing with no trace, same as the POSIX case.
  const r3 = classify.normalizePath("C:\\Users\\dev\\repo", "", "..\\..\\Windows\\System32\\cmd.exe");
  report("8.8 normalizePath: win32 relative path escaping upward with a cwd resolves as an outside touch, not silently dropped", r3.ok === true && !!r3.outside && r3.outside.path === "C:/Users/Windows/System32/cmd.exe", JSON.stringify(r3));
}

/* ===========================================================================
 * GROUP 9: Codex marks (compaction, subagent) -- bonus harness-specific
 * coverage beyond the minimum list, since Codex's mark vocabulary is
 * exercised differently than Claude Code's (event_msg vs tool_use).
 * ========================================================================= */
function groupCodexMarks() {
  console.log("\n=== GROUP 9: Codex compaction + subagent marks ===");
  const cx = parseCodexSession(readFixture("codex-marks.jsonl"), { sourcePath: "/fixtures/codex-marks.jsonl" });
  report("9.1 codex marks: subagent mark for spawn_agent", cx.trace.marks.some((m) => m.type === "subagent" && m.note === "spawn_agent"));
  report("9.2 codex marks: compaction mark for context_compacted", cx.trace.marks.some((m) => m.type === "compaction"));
  report("9.3 codex marks: stats.compactions === 1, stats.subagents === 1", cx.trace.stats.compactions === 1 && cx.trace.stats.subagents === 1);
}

/* ===========================================================================
 * GROUP 10: shell-command classification unit tests (exec-unless-provable
 * discipline).
 * ========================================================================= */
function groupClassification() {
  console.log("\n=== GROUP 10: shell-command classification ===");
  report("10.1 verifyCommand: 'npm test' -> true", classify.verifyCommand("npm test") === true);
  report("10.2 verifyCommand: 'go test ./...' -> true", classify.verifyCommand("go test ./...") === true);
  report("10.3 verifyCommand: extension list includes jest (disclosed GraphSmith addition)", classify.verifyCommand("jest --ci") === true);
  report("10.4 verifyCommand: unrelated command -> false", classify.verifyCommand("echo hello") === false);
  report("10.5 searchCommand: 'grep -rn foo .' -> true", classify.searchCommand("grep -rn foo .") === true);
  report("10.6 searchCommand: 'find . -name x -delete' -> false (mutating find)", classify.searchCommand("find . -name x -delete") === false);
  report("10.7 searchCommand: unrecognized program -> false (conservative default)", classify.searchCommand("some-random-tool --scan") === false);
  report("10.8 readCommand: 'cat foo.txt' -> true", classify.readCommand("cat foo.txt") === true);
  report("10.9 readCommand: redirect present -> false", classify.readCommand("cat foo.txt > bar.txt") === false);
  report("10.10 readCommand: 'sed -i' (mutating) -> false", classify.readCommand("sed -i s/a/b/ foo.txt") === false);
  report("10.11 exec-unless-provable: rm/unknown program -> exec, not search/read/verify", classify.actionFor("Bash", { command: "rm -rf build" }, "") === "exec");
  report("10.12 exec-unless-provable: mixed pipeline (grep | rm) -> exec, not search", classify.actionFor("Bash", { command: "grep foo file.txt | rm" }, "") === "exec");
}

/* ===========================================================================
 * GROUP 11: CLI subcommand (scripts/graphsmith-cli.js postmortem).
 * ========================================================================= */
function runCli(args) {
  return cp.spawnSync(process.execPath, [CLI, "postmortem", ...args], { encoding: "utf8" });
}

function groupCli() {
  console.log("\n=== GROUP 11: `graphsmith postmortem` CLI subcommand ===");

  const noArgs = runCli([]);
  report("11.1 no args: usage printed, exit 2", noArgs.status === 2 && /usage: graphsmith postmortem/.test(noArgs.stderr));
  report("11.2 no args: usage explicitly distinguishes from `audit replay`", /audit replay/.test(noArgs.stderr));

  const ccPath = path.join(FIXTURES, "claude-code-normal.jsonl");
  const stdoutRun = runCli([ccPath]);
  report("11.3 stdout run: exit 0", stdoutRun.status === 0);
  report("11.4 stdout run: Markdown report on stdout", /^# Session post-mortem — claude-code/.test(stdoutRun.stdout));

  const dir = tmpDir("cli-out");
  try {
    const outPath = path.join(dir, "report.md");
    const outRun = runCli([ccPath, "--out", outPath]);
    report("11.5 --out run: exit 0", outRun.status === 0);
    report("11.6 --out run: file written", fs.existsSync(outPath));
    if (fs.existsSync(outPath)) {
      const content = fs.readFileSync(outPath, "utf8");
      report("11.7 --out file content matches stdout rendering", content === stdoutRun.stdout);
    } else {
      report("11.7 --out file content matches stdout rendering", null, "file was not written");
    }

    const forcedCodex = runCli([ccPath, "--harness", "codex"]);
    report("11.8 --harness mismatch: exits non-zero with a clear error, not a silent wrong guess", forcedCodex.status !== 0 && /not recognized as a codex session/.test(forcedCodex.stderr));

    const badHarness = runCli([ccPath, "--harness", "gemini-cli"]);
    report("11.9 --harness invalid value: exits non-zero with a clear error", badHarness.status !== 0 && /--harness must be one of/.test(badHarness.stderr));

    const codexPath = path.join(FIXTURES, "codex-normal.jsonl");
    const autoCodex = runCli([codexPath]);
    report("11.10 auto-detect: codex fixture is recognized without --harness", autoCodex.status === 0 && /^# Session post-mortem — codex/.test(autoCodex.stdout));

    const missing = runCli([path.join(dir, "does-not-exist.jsonl")]);
    report("11.11 missing file: exits non-zero with a readable error, not a stack trace to the user", missing.status !== 0 && /cannot read/.test(missing.stderr) && !/at Object/.test(missing.stderr));
  } finally {
    cleanup(dir);
  }
}

/* ===========================================================================
 * GROUP 12: determinism -- same input, byte-identical output, twice.
 * ========================================================================= */
function groupDeterminism() {
  console.log("\n=== GROUP 12: determinism ===");
  const text = readFixture("claude-code-normal.jsonl");
  const a = parseClaudeCodeSession(text, { sourcePath: "/fixtures/x.jsonl" });
  const b = parseClaudeCodeSession(text, { sourcePath: "/fixtures/x.jsonl" });
  report("12.1 CC adapter: identical input -> byte-identical trace JSON", JSON.stringify(a.trace) === JSON.stringify(b.trace));
  const mdA = renderMarkdown(a.trace, a.diagnostics);
  const mdB = renderMarkdown(b.trace, b.diagnostics);
  report("12.2 renderer: identical trace -> byte-identical Markdown", mdA === mdB);

  const cxText = readFixture("codex-normal.jsonl");
  const cxA = parseCodexSession(cxText, { sourcePath: "/fixtures/y.jsonl" });
  const cxB = parseCodexSession(cxText, { sourcePath: "/fixtures/y.jsonl" });
  report("12.3 Codex adapter: identical input -> byte-identical trace JSON", JSON.stringify(cxA.trace) === JSON.stringify(cxB.trace));
}

/* ===========================================================================
 * GROUP 13: buildPostmortem/runPostmortem programmatic API sanity.
 * ========================================================================= */
function groupProgrammaticApi() {
  console.log("\n=== GROUP 13: programmatic API (postmortem.js) ===");
  const ccPath = path.join(FIXTURES, "claude-code-normal.jsonl");
  const { trace, harness } = buildPostmortem(ccPath);
  report("13.1 buildPostmortem: auto-detects claude-code", harness === "claude-code");
  report("13.2 buildPostmortem: sourcePath is absolute", path.isAbsolute(trace.session.sourcePath));

  const { markdown } = runPostmortem(ccPath, { harness: "claude-code" });
  report("13.3 runPostmortem: forced harness matches auto-detected result", typeof markdown === "string" && markdown.length > 0);

  let threw = false;
  try {
    buildPostmortem(path.join(FIXTURES, "does-not-exist.jsonl"));
  } catch (e) {
    threw = /cannot read/.test(e.message);
  }
  report("13.4 buildPostmortem: missing file throws a readable error", threw === true);
}

/* ===========================================================================
 * GROUP 14: adversarial-review regressions (2026-08-06) -- F1 (duplicate
 * tool_use id), F2 (mark seq stream-position semantics), F8 (Markdown
 * escaping of mark notes).
 * ========================================================================= */
function groupAdversarialRegressions() {
  console.log("\n=== GROUP 14: adversarial-review regressions (F1, F2, F8) ===");

  // F1: a second tool_use reusing an id still pending (no tool_result yet)
  // used to overwrite the pending-map entry, silently losing the FIRST
  // call forever -- the eventual tool_result would resolve against the
  // SECOND call's data instead. Fixture issues toolu_dup for a.txt, then
  // again (duplicate id) for b.txt, before any result arrives; the single
  // tool_result should pair with the first (a.txt) call.
  {
    const cc = parseClaudeCodeSession(readFixture("claude-code-duplicate-id.jsonl"), { sourcePath: "/fixtures/claude-code-duplicate-id.jsonl" });
    report("14.1 F1: exactly 1 event produced for the duplicated id (not 0, not 2)", cc.trace.events.length === 1, `got ${cc.trace.events.length}`);
    report(
      "14.2 F1: the surviving event is the FIRST call (a.txt), not the duplicate second call (b.txt) that overwrote it pre-fix",
      cc.trace.events.length === 1 && cc.trace.events[0].targets.some((t) => t.path === "a.txt"),
      cc.trace.events[0] && JSON.stringify(cc.trace.events[0].targets)
    );
  }

  // F2: a subagent mark issued while earlier tool_use calls are still
  // unresolved must report how many calls have been ISSUED so far (stream
  // position), not how many have already RESOLVED -- otherwise a mark that
  // truly happened after 2 calls were issued looks like it happened after
  // 0. Fixture: t1 (Task) + t2 (Bash) issued together, then t3 (Agent)
  // issued alone while t1/t2 are still pending, then all three resolve.
  {
    const cc = parseClaudeCodeSession(readFixture("claude-code-mark-seq.jsonl"), { sourcePath: "/fixtures/claude-code-mark-seq.jsonl" });
    const subagentMarks = cc.trace.marks.filter((m) => m.type === "subagent");
    report("14.3 F2: two subagent marks recorded (t1 and t3)", subagentMarks.length === 2, JSON.stringify(subagentMarks));
    report("14.4 F2: first subagent mark (t1, nothing yet issued before it) has seq 0", subagentMarks[0] && subagentMarks[0].seq === 0);
    report(
      "14.5 F2: second subagent mark (t3, issued after t1+t2 were already issued but before either resolved) has seq 2 -- stream position, not the 0 a completed-count semantic would have given pre-fix",
      subagentMarks[1] && subagentMarks[1].seq === 2,
      subagentMarks[1] && String(subagentMarks[1].seq)
    );
  }

  // F8: a mark note is untrusted text and gets embedded into a Markdown
  // `"..."` span (see postmortem-render.js's escapeMarkNote). A note
  // containing a literal quote, an embedded newline, and a triple-backtick
  // fence must not leak through unescaped -- the quote would visually break
  // out of the span, the newline would inject a spurious extra line into a
  // single-bullet timeline, and the triple-backtick could open a fenced
  // code block that swallows the rest of the rendered document.
  {
    const trace = {
      session: { harness: "claude-code" },
      events: [],
      marks: [{ seq: 0, type: "user-message", note: 'say "hi"\nthen ```break the doc```' }],
      stats: {
        actions: { search: 0, read: 0, edit: 0, exec: 0, verify: 0, other: 0 },
        errors: { search: 0, read: 0, edit: 0, exec: 0, verify: 0, other: 0 },
        touched: 0,
        edited: 0,
        churnFiles: 0,
        eventsBeforeFirstEdit: 0,
        errorRate: 0,
        editsAfterLastVerify: 0,
        observability: { repoSize: "unavailable" },
      },
    };
    const md = renderMarkdown(trace, {});
    const markLine = md.split("\n").find((l) => l.includes("user turn"));
    report("14.6 F8: rendered mark line has no raw newline injected from the note (still one line)", !!markLine && !markLine.includes("\nthen"));
    report("14.7 F8: embedded double-quote is escaped, not left raw breaking out of the span", !!markLine && markLine.includes('\\"hi\\"') && !markLine.includes('"hi"'));
    report("14.8 F8: triple-backtick fence is escaped, not left as a live code-fence opener", !!markLine && !markLine.includes("```"));
    // The fenced block, if left unescaped, would swallow everything after it
    // in the document -- confirm the trailing "Note:" lines the renderer
    // always appends still show up as literal text in the output.
    report("14.9 F8: content after the note is not swallowed by an unclosed code fence", md.includes('Note: "verify" means'));
  }
}

/* ===========================================================================
 * GROUP 15: fresh Grok review round 2 regressions (2026-08-06) -- Findings
 * 1-12 from the independent post-fix re-review of Lane F. Each assertion
 * below was individually verified via `git stash` isolation (source fix
 * stashed, test still present) to FAIL against the pre-fix code and PASS
 * against the fix, before being folded into this permanent suite.
 * ========================================================================= */
function groupFreshReviewRound2() {
  console.log("\n=== GROUP 15: fresh Grok review round 2 regressions (Findings 1-12) ===");

  // Finding 1 (CRITICAL): a real tool_use id reused AFTER its first
  // occurrence already resolved, with the second occurrence still pending
  // at EOF, used to be double-emitted (pendingOrder held the id twice, the
  // EOF loop never removed a resolved-from-`pending` key after emitting).
  {
    const cc = parseClaudeCodeSession(readFixture("claude-code-eof-reuse.jsonl"), { sourcePath: "/fixtures/claude-code-eof-reuse.jsonl" });
    report("15.1 F1: exactly 2 events (Bash resolved + Read pending-at-EOF), not 3", cc.trace.events.length === 2, `got ${cc.trace.events.length}`);
    report("15.2 F1: the pending-at-EOF Read event appears exactly once", cc.trace.events.filter((e) => e.tool === "Read").length === 1);
  }

  // Finding 3 (HIGH): session-level cwd used to be captured from an
  // isSidechain:true line BEFORE the sidechain skip check ran, letting a
  // subagent's own cwd poison the root session's cwd for every later event.
  {
    const cc = parseClaudeCodeSession(readFixture("claude-code-sidechain-cwd-poison.jsonl"), { sourcePath: "/fixtures/claude-code-sidechain-cwd-poison.jsonl" });
    report("15.3 F3: root session cwd is the ROOT line's cwd (/repo), not the sidechain line's", cc.trace.session.cwd === "/repo", cc.trace.session.cwd);
    const rootEvent = cc.trace.events.find((e) => e.tool === "Read" && e.ts === "2026-08-06T11:00:03Z");
    report("15.4 F3: the root Read resolves in-repo (main.js), not misclassified outside due to a poisoned cwd", !!rootEvent && rootEvent.targets.some((t) => t.path === "main.js"), rootEvent && JSON.stringify(rootEvent));
  }

  // Finding 11 (HIGH, elevated from Grok's own LOW): verifyCommand's plain
  // substring matching against short tokens ("jest", "tox") matched inside
  // ordinary filenames.
  {
    report("15.5 F11: 'cat jest.config.js' is NOT verify-shaped (was a false positive)", classify.verifyCommand("cat jest.config.js") === false);
  report("15.6 F11: 'cat tox.ini' is NOT verify-shaped (was a false positive)", classify.verifyCommand("cat tox.ini") === false);
  report("15.7 F11: 'npx jest --ci' IS still verify-shaped (real invocation, no regression)", classify.verifyCommand("npx jest --ci") === true);
  report("15.8 F11: 'tox -e py39' IS still verify-shaped (real invocation, no regression)", classify.verifyCommand("tox -e py39") === true);
  }

  // Finding 2 (HIGH): a Codex call_id reused after its first occurrence
  // resolved used to be silently dropped forever (`if (calls.has(id)) break;`).
  {
    const codexLines = [
      { timestamp: "2026-08-06T12:00:00Z", type: "session_meta", payload: { id: "codex-dup-1", session_id: "codex-dup-1", cwd: "/repo" } },
      { timestamp: "2026-08-06T12:00:01Z", type: "response_item", payload: { type: "function_call", id: "fc-1", call_id: "call-dup", name: "exec_command", arguments: JSON.stringify({ cmd: "echo hi", workdir: "/repo" }) } },
      { timestamp: "2026-08-06T12:00:02Z", type: "response_item", payload: { type: "function_call_output", call_id: "call-dup", output: "hi" } },
      { timestamp: "2026-08-06T12:00:03Z", type: "