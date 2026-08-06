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
  report("7.5 malformed: the 1 valid user message still produced a mark", cc.trace.marks.filt