#!/usr/bin/env node
"use strict";

/**
 * scripts/postmortem-classify.js -- Lane F shared classification/parsing
 * logic for `graphsmith postmortem` (session-trace v1.0, see
 * .plans/gsa-followup/LANE-F-CODING-SESSION-POSTMORTEM-DESIGN.md Part 3b).
 *
 * This is the harness-agnostic core both adapters (postmortem-claude-code.js,
 * postmortem-codex.js) build on: the action taxonomy, the shell-command
 * classification discipline (default to "exec" unless positively provable,
 * segment-by-segment across pipelines, refuse on unrecognized program or a
 * `>` redirect), targetsFor's path extraction with weak/outside flags,
 * InjectedUserMessage's shape-based filtering, and the stats/observability
 * rollup.
 *
 * ADAPTED (not ported verbatim) from mindwalk's internal/adapter/adapter.go
 * and internal/model/stats.go (MIT, cosmtrek/mindwalk) -- reimplemented
 * natively in zero-dependency CommonJS per the design doc's ADAPT decision
 * (Part 2). Every function below that mirrors a mindwalk function names it
 * in a comment so a reviewer can diff behavior directly against the real
 * source if they have it checked out.
 *
 * Every function here is PURE: no network, no clock, no Math.random, no
 * mutation of shared state across calls. The one exception, disclosed
 * explicitly: outsideScope() below calls os.homedir()/os.tmpdir() to label
 * an out-of-repo touch as "home" vs "tmp" vs "other" -- this makes that one
 * cosmetic label host-environment-dependent (matching mindwalk's own
 * behavior, which does the same via Go's os.UserHomeDir()/os.TempDir()).
 * It does NOT affect which paths are classified as targets/outside, only
 * how an already-outside path's scope is labeled, so it does not reach any
 * classification DECISION -- but a reviewer should know it is there.
 * Windows path handling deliberately does NOT use the bare `path` module
 * (whose behavior depends on the host OS the CLI itself runs on) -- it uses
 * path.win32 / path.posix explicitly, selected by the STYLE of the path
 * string found in the session log, so a Windows-recorded session log parses
 * identically whether `graphsmith postmortem` itself runs on Linux, macOS,
 * or Windows. This directly follows the design doc's Part 3d instruction
 * ("Windows path handling needs explicit fixture tests... use
 * path.posix/path.win32 or equivalent, don't assume POSIX paths").
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const PATTERNS_PATH = path.join(__dirname, "postmortem-patterns.json");

let _patterns = null;
function loadPatterns() {
  if (_patterns) return _patterns;
  const raw = JSON.parse(fs.readFileSync(PATTERNS_PATH, "utf8"));
  const verify = [].concat(
    raw.verify_command_patterns.mindwalk_confirmed,
    raw.verify_command_patterns.graphsmith_extension
  ).map((s) => s.toLowerCase());
  _patterns = {
    verifyPatterns: verify,
    searchPrograms: new Set(raw.search_programs.programs),
    readOnlyPrograms: new Set(raw.read_only_programs.programs),
    readPrograms: new Set(raw.read_programs.programs),
  };
  return _patterns;
}

/* ---------------------------------------------------------------------------
 * Small value helpers (mirrors adapter.go's ContentToString / IntFromAny /
 * firstString).
 * ------------------------------------------------------------------------- */

function contentToString(v) {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (Array.isArray(v)) {
    const parts = [];
    for (const item of v) {
      if (item && typeof item === "object") {
        if (typeof item.text === "string") parts.push(item.text);
        else if (typeof item.content === "string") parts.push(item.content);
      }
    }
    return parts.join("\n");
  }
  try {
    return JSON.stringify(v);
  } catch (_) {
    return String(v);
  }
}

function intFromAny(v) {
  if (typeof v === "number" && Number.isFinite(v)) return Math.trunc(v);
  return 0;
}

function firstString(input, ...keys) {
  if (!input || typeof input !== "object") return "";
  for (const key of keys) {
    if (typeof input[key] === "string") return input[key];
  }
  return "";
}

/** Truncate to a fixed Unicode-code-point budget, ellipsis included, never
 * exceeding it (mirrors textutil.TruncateRunes). */
function truncateRunes(text, limit, ellipsis) {
  const runes = Array.from(text);
  if (runes.length <= limit) return text;
  const keep = Math.max(0, limit - Array.from(ellipsis).length);
  return runes.slice(0, keep).join("") + ellipsis;
}

/** CodeRabbit review, PR #23, 2026-08-06 (multiline summaries): collapses
 * any run of \r/\n into a single space -- the same collapsing approach
 * postmortem-render.js's escapeMarkNote() already uses for a mark's note
 * at RENDER time, but a trace event's `summary` field is built here, at
 * TRACE-BUILD time (summarizeTool/summarizeExecWrapper below), so it needs
 * its own copy of the same collapse rather than depending on a render-time
 * fix elsewhere. A multiline Bash command or multiline Task `description`
 * copied into `summary` unchanged would produce a multiline value,
 * violating the schema's "one-line, mechanically generated" summary
 * contract (schemas/session-trace.schema.json) and potentially breaking a
 * line-oriented consumer of the raw trace JSON (not just the Markdown
 * report). Applied to source text BEFORE truncation, so the truncation
 * budget is spent on the collapsed (shorter) text, not the original
 * newline-bearing one. */
function collapseNewlines(text) {
  return String(text || "").replace(/[\r\n]+/g, " ");
}

const USER_MESSAGE_NOTE_LIMIT = 2000;

/** Mirrors adapter.UserMessageNote. */
function userMessageNote(text) {
  return truncateRunes(String(text || "").trim(), USER_MESSAGE_NOTE_LIMIT, "\u2026");
}

/**
 * Mirrors adapter.InjectedUserMessage. Shape-based (not a tag whitelist): a
 * message that is a complete markup envelope (starts with `<`, ends with
 * `>`) is treated as harness-injected text riding on a "user" role line
 * (<system-reminder>, <command-name>, <local-command-caveat>,
 * <environment_context>, ...), not something the user actually typed.
 * Codex's "# AGENTS.md instructions" preamble is the one non-markup
 * injection, matched by literal prefix.
 */
function injectedUserMessage(text) {
  const t = String(text || "").trim();
  if (t.startsWith("# AGENTS.md instructions")) return true;
  return t.startsWith("<") && t.endsWith(">");
}

/* ---------------------------------------------------------------------------
 * Path normalization -- explicitly platform-aware (path.win32 / path.posix),
 * never the bare `path` module, so parsing is stable across host OSes.
 * ------------------------------------------------------------------------- */

const WIN_ABS_RE = /^[A-Za-z]:[\\/]/;
const UNC_RE = /^\\\\/;

function pathStyleOf(p) {
  if (!p) return null;
  if (WIN_ABS_RE.test(p) || UNC_RE.test(p)) return "win32";
  if (p.startsWith("/")) return "posix";
  return null;
}

function styleModule(style) {
  return style === "win32" ? path.win32 : path.posix;
}

function toSlash(p) {
  return String(p).split("\\").join("/");
}

/** Mirrors adapter.normalizePath -- returns {rel, outside, ok}. `rel` is set
 * (posix-slash form) when the path resolves inside `cwd`; `outside` is set
 * (scope + absolute path) when it resolves but escapes the repo root; ok is
 * false when the raw string could not be interpreted as a path at all. */
function normalizePath(cwd, base, rawPath) {
  let p = String(rawPath || "").trim();
  p = p.replace(/^['"]+|['"]+$/g, "").trim();
  if (!p || p.includes("\n")) return { ok: false };
  if (/^https?:\/\//i.test(p)) return { ok: false };

  // CodeRabbit review, PR #23, 2026-08-06 (home-relative path
  // misclassification): "~" is shell shorthand for the invoking user's home
  // directory -- it is NOT an ordinary relative path segment. Falling
  // through to the ordinary relative-path branch below (as this used to)
  // resolved e.g. "~/.bashrc" AS IF it were a path inside the session's
  // repo cwd, silently mis-locating it. Recognized here, BEFORE ordinary
  // relative-path normalization runs, and routed straight to `outside`
  // with scope "home" -- the schema's existing "home" enum value, not a
  // new one. Deliberately does NOT expand "~" against the actual
  // os.homedir() of whatever machine happens to be running `graphsmith
  // postmortem`: doing so would make the reported outside PATH itself
  // host-dependent, not just its scope LABEL (the one disclosed exception
  // to this file's determinism rule -- see outsideScope()'s own comment).
  // The path is kept exactly as written in the log; only the scope is
  // set, directly from the "~" shape itself, never from a real lookup.
  if (p === "~" || p.startsWith("~/") || p.startsWith("~\\")) {
    return { ok: true, outside: { scope: "home", path: toSlash(p) } };
  }

  const cwdStyle = pathStyleOf(cwd) || (cwd && cwd.includes("\\") ? "win32" : "posix");
  const rawStyle = pathStyleOf(p);
  const baseStyle = pathStyleOf(base);
  const isAbs = rawStyle !== null;

  if (!isAbs) {
    const style = baseStyle || cwdStyle || "posix";
    const mod = styleModule(style);
    const clean = mod.normalize(p);
    const cleanSlash = toSlash(clean);
    if (cleanSlash === ".") return { ok: false };
    if (cleanSlash === ".." || cleanSlash.startsWith("../")) {
      // CodeRabbit review, PR #23, 2026-08-06 (silently-dropped parent-
      // relative paths): a path like "../secret.txt" used to return
      // { ok: false } here unconditionally, dropping it from BOTH targets
      // AND outside -- worse than misclassifying, it vanished with no
      // trace at all, directly conflicting with this file's own
      // "never silently drop, never silently guess" ethos (see e.g. F3's
      // comment on the weak-target keep-don't-drop fix above). A
      // "../"-prefixed path is not unresolvable, it is merely resolvable to
      // somewhere OUTSIDE the anchor directory -- exactly what the
      // `outside` array exists to record. Resolve it against the same
      // anchor an ordinary relative path would use (the explicit `base` if
      // the caller supplied one, else the session's own `cwd`) and report
      // it as an outside touch when it does escape; if the anchor is
      // itself a subdirectory such that "../secret.txt" actually resolves
      // BACK inside the repo root, it is a normal in-repo target instead
      // (relSameStyle already tells these two cases apart). Only genuinely
      // un-anchorable input (no base AND no cwd recorded for the session)
      // falls back to ok:false -- there is no path string to compute
      // ANY location, in or out of the repo, without an anchor.
      const anchor = base || cwd;
      if (!anchor) return { ok: false };
      const abs = mod.normalize(mod.join(anchor, p));
      if (cwd) {
        const rel = relSameStyle(mod, cwd, abs, style);
        if (rel !== null) return { ok: true, rel: toSlash(rel) };
      }
      return { ok: true, outside: { scope: outsideScope(abs), path: toSlash(abs) } };
    }
    if (base) {
      const abs = mod.normalize(mod.join(base, p));
      if (cwd) {
        const rel = relSameStyle(mod, cwd, abs, style);
        if (rel !== null) return { ok: true, rel: toSlash(rel) };
      }
      return { ok: true, outside: { scope: outsideScope(abs), path: toSlash(abs) } };
    }
    return { ok: true, rel: toSlash(clean) };
  }

  const style = rawStyle;
  const mod = styleModule(style);
  const abs = mod.normalize(p);
  if (cwd) {
    const rel = relSameStyle(mod, cwd, abs, style);
    if (rel !== null) return { ok: true, rel: toSlash(rel) };
  }
  return { ok: true, outside: { scope: outsideScope(abs), path: toSlash(abs) } };
}

/* Finding 10 (adversarial review, fresh Grok pass, 2026-08-06, cosmetic):
 * this file used to route every path string through a `toWin(p, style)`
 * helper before handing it to path.win32/path.posix, but the helper's own
 * body (`return style === "win32" ? p : p;`) returned its input unchanged
 * on both branches -- dead code, doing nothing. Removed; callers now pass
 * `p`/`base` directly to mod.normalize/mod.join. (path.win32 already
 * accepts forward slashes as well as backslashes, so no conversion was
 * ever needed here -- callers pass strings that already came from
 * win32-shaped session data, selected via pathStyleOf() above.)
 *
 * Computes a relative path only when `target` resolves inside `cwd`,
 * matching mindwalk's normalizePath: same-style relative, refuses ".."
 * escapes and the "." (same-dir) case (session cwd itself is not a target). */
function relSameStyle(mod, cwd, target, style) {
  if (pathStyleOf(cwd) !== null && pathStyleOf(cwd) !== style) {
    // cwd and target belong to different path "worlds" (e.g. a Windows
    // session log cwd against a POSIX-looking outside reference, or vice
    // versa) -- cannot be resolved as "inside", so caller falls back to an
    // outside touch rather than guessing.
    return null;
  }
  const cwdClean = mod.normalize(cwd);
  const rel = mod.relative(cwdClean, target);
  if (rel === "" || rel === ".") return null;
  const relSlash = toSlash(rel);
  // Finding 5 (adversarial review, fresh Grok pass, 2026-08-06):
  // relSlash.startsWith("..") was too broad -- it also matches a real
  // in-repo file whose NAME happens to start with two dots (e.g.
  // "/repo/..foo" relative to cwd "/repo" produces rel === "..foo", a file
  // INSIDE the repo, not an upward escape). Only "../"-prefixed (escaping
  // through a parent segment) or the bare ".." (the parent dir itself)
  // actually mean "outside" -- this matches the equivalent, already-correct
  // check in normalizePath's own non-absolute branch just above
  // (`cleanSlash === "." || cleanSlash.startsWith("../") || cleanSlash === ".."`).
  if (rel === ".." || relSlash.startsWith("../")) return null;
  if (mod.isAbsolute(rel)) return null;
  return rel;
}

/** Mirrors adapter.outsideScope. The one function in this file that reads
 * host environment (os.homedir/os.tmpdir) -- see file header. */
function outsideScope(absPath) {
  const home = safeHomedir();
  const p = toSlash(absPath).toLowerCase();
  if (home) {
    const homeSlash = toSlash(home).toLowerCase();
    if (p === homeSlash || p.startsWith(homeSlash + "/")) return "home";
  }
  const tmp = toSlash(os.tmpdir()).toLowerCase();
  if (p === tmp || p.startsWith(tmp + "/") || p.startsWith("/tmp/") || p === "/tmp") return "tmp";
  return "other";
}

function safeHomedir() {
  try {
    return os.homedir();
  } catch (_) {
    return "";
  }
}

/* ---------------------------------------------------------------------------
 * Path-extraction regexes -- ported 1:1 from adapter.go's package-level
 * regexps (RE2 syntax used there is a compatible subset of JS regex syntax
 * for these patterns).
 * ------------------------------------------------------------------------- */

const pathLineRe = /(?:^|[\s"'([])([A-Za-z0-9_./@+-]*[A-Za-z0-9_/@+-]\.[A-Za-z0-9][A-Za-z0-9._-]*):([0-9]+)/g;
// CodeRabbit review, PR #23, 2026-08-06 (Windows path extraction from tool
// output): pathLineRe's path character class has no backslash and no colon
// (colon is the literal separator before the line number), so a Windows
// drive-letter absolute path in a Grep/Glob/LS hit line -- e.g.
// "C:\repo\src\a.js:12:hit" -- never matched: the drive letter's own ":"
// breaks the "path:LINE" shape the base regex expects, and "\repo\src"
// contains characters outside the allowed set even before that. Such hits
// were silently dropped from touched-file stats even though this file's
// own path-normalization code (pathStyleOf/normalizePath, see the file
// header) explicitly supports Windows paths elsewhere. A second,
// Windows-specific regex handles the drive-letter shape (accepting either
// "\" or "/" as the separator, since a Windows path recorded with forward
// slashes is also valid); parsePathHits below runs both and merges results.
const pathLineWinRe = /(?:^|[\s"'([])([A-Za-z]:[\\/][^\s"'()[\]:]*\.[A-Za-z0-9][A-Za-z0-9._-]*):([0-9]+)/g;
const pathOnlyRe = /(?:^|[\s"'([])([./~A-Za-z0-9_@+-]*[/][A-Za-z0-9_./~@+-]*\.[A-Za-z0-9][A-Za-z0-9._-]*)(?:$|[\s"',)\]:;])/g;
const commandPathRe = /(?:^|[\s"'=])([./~A-Za-z0-9_@+-]+\.[A-Za-z0-9][A-Za-z0-9._-]*)(?:$|[\s"',)\]:;])/g;
const patchFileRe = /^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$/gm;

function cleanExtractedPath(rawPath, allowTopLevel) {
  let p = rawPath.trim().replace(/^["', ;:()[\]{}]+|["', ;:()[\]{}]+$/g, "");
  if (p.startsWith("a/")) p = p.slice(2);
  else if (p.startsWith("b/")) p = p.slice(2);
  if (p.startsWith("./")) p = p.slice(2);
  if (!p || p.includes("://") || /[\n\r\t]/.test(p)) return { ok: false };
  if (p.startsWith("--") || p.startsWith("++")) return { ok: false };
  if (!allowTopLevel && !p.includes("/")) return { ok: false };
  return { ok: true, path: p };
}

function extractPaths(text) {
  const seen = new Set();
  const out = [];
  pathOnlyRe.lastIndex = 0;
  let m;
  while ((m = pathOnlyRe.exec(text))) {
    const cleaned = cleanExtractedPath(m[1], false);
    if (!cleaned.ok) continue;
    if (!cleaned.path || seen.has(cleaned.path) || cleaned.path.includes("://")) continue;
    seen.add(cleaned.path);
    out.push(cleaned.path);
  }
  return out.sort();
}

function extractCommandPaths(command) {
  const seen = new Set();
  const out = [];
  commandPathRe.lastIndex = 0;
  let m;
  while ((m = commandPathRe.exec(command))) {
    const cleaned = cleanExtractedPath(m[1], true);
    if (!cleaned.ok || seen.has(cleaned.path)) continue;
    seen.add(cleaned.path);
    out.push(cleaned.path);
  }
  return out.sort();
}

function parsePathHits(text) {
  const byPath = new Map();
  pathLineRe.lastIndex = 0;
  let m;
  while ((m = pathLineRe.exec(text))) {
    const line = parseInt(m[2], 10);
    if (line > 0) {
      const cleaned = cleanExtractedPath(m[1], true);
      if (cleaned.ok) {
        if (!byPath.has(cleaned.path)) byPath.set(cleaned.path, []);
        byPath.get(cleaned.path).push([line, line]);
      }
    }
  }
  // CodeRabbit review, PR #23, 2026-08-06 (Windows path extraction) -- see
  // pathLineWinRe's own comment above for why this second pass exists.
  pathLineWinRe.lastIndex = 0;
  while ((m = pathLineWinRe.exec(text))) {
    const line = parseInt(m[2], 10);
    if (line > 0) {
      const cleaned = cleanExtractedPath(m[1], true);
      if (cleaned.ok) {
        if (!byPath.has(cleaned.path)) byPath.set(cleaned.path, []);
        byPath.get(cleaned.path).push([line, line]);
      }
    }
  }
  for (const p of extractPaths(text)) {
    if (!byPath.has(p)) byPath.set(p, []);
  }
  return Array.from(byPath.entries())
    .map(([p, lines]) => ({ path: p, lines }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

function parsePatchPaths(patch) {
  const seen = new Set();
  const out = [];
  patchFileRe.lastIndex = 0;
  let m;
  while ((m = patchFileRe.exec(patch))) {
    const raw = m[1] !== undefined ? m[1] : m[2];
    if (raw === undefined) continue;
    const cleaned = cleanExtractedPath(raw, true);
    if (!cleaned.ok || seen.has(cleaned.path)) continue;
    seen.add(cleaned.path);
    out.push(cleaned.path);
  }
  return out.sort();
}

/* ---------------------------------------------------------------------------
 * Shell-command classification -- default to "exec" unless positively
 * provable, segment-by-segment across pipelines, refuse on an unrecognized
 * program or a `>` redirect. Conservative by design (mirrors adapter.go's
 * comments verbatim on this point).
 * ------------------------------------------------------------------------- */

const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/* strings.FieldsFunc semantics: split on runs of the separator runes,
 * discard empty segments produced between adjacent separators. */
function fieldsFuncSplit(s) {
  return s.split(/[|;&\n]+/).map((x) => x).filter((x) => x.length > 0);
}

function stripRedirectNoise(command) {
  return String(command || "")
    .split("2>&1").join(" ")
    .split("2>/dev/null").join(" ")
    .split(">/dev/null").join(" ")
    .split("> /dev/null").join(" ");
}

function programOf(fields) {
  let f = fields.slice();
  while (f.length > 0 && ENV_ASSIGN_RE.test(f[0])) f = f.slice(1);
  if (f.length === 0) return { program: "", rest: [] };
  const base = f[0].split("/").pop().split("\\").pop().toLowerCase();
  return { program: base, rest: f.slice(1) };
}

/* Shell-token boundary characters -- deliberately NOT regex \b semantics
 * (which treats any non-word character, including "." and "/", as a
 * boundary). Finding 11 (adversarial review, fresh Grok pass, 2026-08-06,
 * elevated to HIGH from Grok's own LOW rating): plain substring matching
 * against short verify-pattern tokens ("jest", "tox", "mocha", "ctest")
 * matched INSIDE ordinary filenames -- verifyCommand("cat jest.config.js")
 * and verifyCommand("cat tox.ini") both returned true, misclassifying an
 * everyday read as "verify", and \b-style boundaries would not have fixed
 * this ("jest." already has a \b at the "."). Only whitespace and shell
 * segment separators count as a real token boundary here. */
const SHELL_TOKEN_BOUNDARY_RE = /[\s|;&]/;

/* CodeRabbit review, PR #23, 2026-08-06 (verify-pattern boundary regex): the
 * single SHELL_TOKEN_BOUNDARY_RE above (whitespace/|/;/&) is the correct,
 * strict boundary for the character AFTER a match -- see Finding 11's own
 * comment for why that strictness matters (a trailing "." must NOT count as
 * a boundary, or "jest.config.js" would misclassify as verify). But used as
 * the BEFORE-match boundary too, it was too strict in the other direction:
 * a verify pattern preceded by a path separator -- "./gradlew test" (before
 * "gradlew" is "/"), or "node_modules/.bin/jest" (before "jest" is "/") --
 * failed beforeOk and fell through to "exec" even though these are real,
 * unambiguous verify-runner invocations, not a token embedded inside an
 * unrelated filename the way "jest.config.js" is. A leading path separator
 * is exactly the shape a real relative-executable or node_modules/.bin
 * invocation takes; it is never how a token gets embedded INSIDE a
 * filename (that would need to be a suffix, like "jest.config.js", which
 * afterOk already refuses). This asymmetry is intentional: only the BEFORE
 * check gains "/" and "\\" as additional valid boundary characters; the
 * AFTER check keeps the original strict set unchanged. */
const SHELL_TOKEN_LEADING_BOUNDARY_RE = /[\s|;&/\\]/;

/* CodeRabbit review, PR #23, 2026-08-06 (verify-detection false positive
 * via echo): verifyCommand used to scan the WHOLE lowercased command string
 * for a pattern occurrence, with only character-boundary checks -- it never
 * asked whether the matched text was actually being INVOKED as a program,
 * versus merely appearing as literal argument text to some other command.
 * `echo npm test` matched the "npm test" pattern (real, boundary-clean
 * whitespace on both sides) even though `echo` never invokes anything; it
 * just prints its arguments. Because actionFor() checks verify before other
 * classifications, this became a false "verify" classification that could
 * reset editsAfterLastVerify, producing a false "the session re-verified"
 * signal. Fix: scan per SHELL SEGMENT (the same fieldsFuncSplit/programOf
 * split searchCommand/readCommand already use), and skip any segment whose
 * own invoked program is "echo" -- echo's arguments are text being printed,
 * never a program name being run, so no pattern occurring only within an
 * echo segment can be a real verify invocation. Segments whose program is
 * anything else (including the verify runner itself, e.g. "npm"/"npx"/
 * "gradlew") are scanned exactly as before -- this does not require the
 * match to BE the segment's first token (that would break "npx jest --ci",
 * where "npx" is the program and "jest" is its argument, a real invocation
 * this file's own existing regression tests require to stay classified as
 * verify). */
function verifyCommand(command) {
  const patterns = loadPatterns().verifyPatterns;
  const c = String(command || "").toLowerCase();
  for (const segment of fieldsFuncSplit(c)) {
    const fields = segment.trim().split(/\s+/).filter(Boolean);
    const { program } = programOf(fields);
    if (program === "echo") continue;
    for (const p of patterns) {
      let idx = segment.indexOf(p);
      while (idx !== -1) {
        const before = idx === 0 ? "" : segment[idx - 1];
        const after = idx + p.length >= segment.length ? "" : segment[idx + p.length];
        const beforeOk = before === "" || SHELL_TOKEN_LEADING_BOUNDARY_RE.test(before);
        const afterOk = after === "" || SHELL_TOKEN_BOUNDARY_RE.test(after);
        if (beforeOk && afterOk) return true;
        idx = segment.indexOf(p, idx + 1);
      }
    }
  }
  return false;
}

/** Mirrors adapter.searchCommand. */
function searchCommand(command) {
  const { searchPrograms, readOnlyPrograms } = loadPatterns();
  const cleaned = stripRedirectNoise(command);
  let searched = false;
  for (const segment of fieldsFuncSplit(cleaned)) {
    if (segment.includes(">")) return false;
    const fields = segment.trim().split(/\s+/).filter(Boolean);
    const { program, rest } = programOf(fields);
    if (!program) continue;
    if (program === "git" && rest.length > 0 && (rest[0] === "grep" || rest[0] === "ls-files")) {
      searched = true;
      continue;
    }
    if (searchPrograms.has(program)) {
      if (segment.includes("-exec") || segment.includes("-delete")) return false;
      searched = true;
      continue;
    }
    if (!readOnlyPrograms.has(program)) return false;
  }
  return searched;
}

function sedReadsOnly(args) {
  let hasN = false;
  for (const a of args) {
    if (a === "-n") hasN = true;
    if (a.startsWith("-i")) return false;
  }
  return hasN;
}

function flagTakesValue(program, flag) {
  if (program === "head" || program === "tail") return flag === "-n" || flag === "-c";
  if (program === "sed") return flag === "-e" || flag === "-f";
  return false;
}

/** Mirrors adapter.commandReadPaths. */
function commandReadPaths(command) {
  const { readPrograms } = loadPatterns();
  const seen = new Set();
  const out = [];
  for (const segment of fieldsFuncSplit(String(command || ""))) {
    if (segment.includes(">")) continue;
    const fields = segment.trim().split(/\s+/).filter(Boolean);
    const { program, rest: args0 } = programOf(fields);
    if (!program || !readPrograms.has(program)) continue;
    let args = args0;
    let scriptArgs = 0;
    if (program === "sed") {
      if (!sedReadsOnly(args)) continue;
      scriptArgs = 1;
    }
    let expectValue = false;
    for (const arg of args) {
      if (expectValue) {
        expectValue = false;
        continue;
      }
      if (arg.startsWith("-")) {
        expectValue = flagTakesValue(program, arg);
        continue;
      }
      if (scriptArgs > 0) {
        scriptArgs--;
        continue;
      }
      if (/[<>*?$`]/.test(arg)) continue;
      const cleaned = cleanExtractedPath(arg, true);
      if (!cleaned.ok || seen.has(cleaned.path)) continue;
      seen.add(cleaned.path);
      out.push(cleaned.path);
    }
  }
  return out.sort();
}

/** Mirrors adapter.readCommand. */
function readCommand(command) {
  const { readOnlyPrograms, readPrograms } = loadPatterns();
  if (commandReadPaths(command).length === 0) return false;
  const cleaned = stripRedirectNoise(command);
  for (const segment of fieldsFuncSplit(cleaned)) {
    if (segment.includes(">")) return false;
    const fields = segment.trim().split(/\s+/).filter(Boolean);
    const { program, rest } = programOf(fields);
    if (!program) continue;
    if (program === "sed" && !sedReadsOnly(rest)) return false;
    if (!readOnlyPrograms.has(program) && !readPrograms.has(program)) return false;
  }
  return true;
}

/* ---------------------------------------------------------------------------
 * Codex "exec" JS-wrapper support: some Codex tool calls are a small JS
 * snippet that itself invokes tools.exec_command({cmd, workdir}) one or more
 * times, or tools.apply_patch({patch}). This is a best-effort static parse
 * of that snippet -- never evaluated -- mirroring adapter.go's
 * execCommands/execToolArguments/execToolNames/matchingJSParen family.
 * ------------------------------------------------------------------------- */

const EXEC_STRING_FIELD_RE = /(?:^|[\s,{])(?:"(cmd|workdir)"|(cmd|workdir))\s*:\s*("(?:\\.|[^"\\])*")/g;
const EXEC_PATCH_ASSIGN_RE = /^[\t ]*(?:const|let|var)[\t ]+patch[\t ]*=[\t ]*("(?:\\.|[^"\\])*")[\t ]*;/gm;

function execSource(input) {
  for (const key of ["_raw", "code", "script"]) {
    const v = input && input[key];
    if (typeof v === "string" && v !== "") return v;
  }
  return "";
}

function isJSSpace(ch) {
  return ch === " " || ch === "\t" || ch === "\r" || ch === "\n";
}
function isJSIdentifierByte(ch) {
  return /[A-Za-z0-9_$]/.test(ch);
}

function skipJSIgnored(source, start) {
  if (start >= source.length) return { next: start, skipped: false };
  const quote = source[start];
  if (quote === "'" || quote === '"' || quote === "`") {
    for (let i = start + 1; i < source.length; i++) {
      if (source[i] === "\\") {
        i++;
        continue;
      }
      if (source[i] === quote) return { next: i + 1, skipped: true };
    }
    return { next: source.length, skipped: true };
  }
  if (source[start] !== "/" || start + 1 >= source.length) return { next: start, skipped: false };
  if (source[start + 1] === "/") {
    const end = source.indexOf("\n", start + 2);
    return end >= 0 ? { next: end + 1, skipped: true } : { next: source.length, skipped: true };
  }
  if (source[start + 1] === "*") {
    const end = source.indexOf("*/", start + 2);
    return end >= 0 ? { next: end + 2, skipped: true } : { next: source.length, skipped: true };
  }
  return { next: start, skipped: false };
}

function matchingJSParen(source, open) {
  let depth = 1;
  let i = open + 1;
  while (i < source.length) {
    const s = skipJSIgnored(source, i);
    if (s.skipped) {
      i = s.next;
      continue;
    }
    if (source[i] === "(") depth++;
    else if (source[i] === ")") {
      depth--;
      if (depth === 0) return { close: i, ok: true };
    }
    i++;
  }
  return { close: 0, ok: false };
}

function execToolArguments(source, tool) {
  const call = "tools." + tool;
  const args = [];
  let i = 0;
  while (i < source.length) {
    const skip = skipJSIgnored(source, i);
    if (skip.skipped) {
      i = skip.next;
      continue;
    }
    if (!source.startsWith(call, i) || (i > 0 && isJSIdentifierByte(source[i - 1]))) {
      i++;
      continue;
    }
    let open = i + call.length;
    while (open < source.length && isJSSpace(source[open])) open++;
    if (open >= source.length || source[open] !== "(") {
      i++;
      continue;
    }
    const m = matchingJSParen(source, open);
    if (!m.ok) break;
    args.push(source.slice(open + 1, m.close));
    i = m.close + 1;
  }
  return args;
}

function execToolNames(source) {
  const prefix = "tools.";
  const names = [];
  let i = 0;
  while (i < source.length) {
    const skip = skipJSIgnored(source, i);
    if (skip.skipped) {
      i = skip.next;
      continue;
    }
    if (!source.startsWith(prefix, i) || (i > 0 && isJSIdentifierByte(source[i - 1]))) {
      i++;
      continue;
    }
    const nameStart = i + prefix.length;
    let nameEnd = nameStart;
    while (nameEnd < source.length && isJSIdentifierByte(source[nameEnd])) nameEnd++;
    let open = nameEnd;
    while (open < source.length && isJSSpace(source[open])) open++;
    if (nameEnd === nameStart || open >= source.length || source[open] !== "(") {
      i++;
      continue;
    }
    names.push(source.slice(nameStart, nameEnd));
    i = open + 1;
  }
  return names;
}

function parseStaticExecCommand(argument) {
  let command = "";
  let workdir = "";
  let ambiguousWorkdir = false;
  EXEC_STRING_FIELD_RE.lastIndex = 0;
  let m;
  while ((m = EXEC_STRING_FIELD_RE.exec(argument))) {
    const key = m[1] !== undefined ? m[1] : m[2];
    let value;
    try {
      value = JSON.parse(m[3]);
    } catch (_) {
      continue;
    }
    if (key === "cmd") {
      if (command !== "") return { ok: false };
      command = value;
      continue;
    }
    if (workdir !== "") {
      ambiguousWorkdir = true;
      workdir = "";
      continue;
    }
    if (!ambiguousWorkdir) workdir = value;
  }
  return { ok: command !== "", command, workdir };
}

function execCommandArguments(source) {
  return execToolArguments(source, "exec_command");
}

function execHasOnlyStaticCommands(input, commandCount) {
  const source = execSource(input);
  if (source === "") return firstString(input, "cmd", "command") !== "";
  const tools = execToolNames(source);
  if (tools.length !== commandCount) return false;
  return tools.every((t) => t === "exec_command");
}

function execCommands(input) {
  const source = execSource(input);
  if (source === "") {
    const command = firstString(input, "cmd", "command");
    if (command !== "") return [{ command, workdir: firstString(input, "workdir") }];
    return [];
  }
  const args = execCommandArguments(source);
  const commands = [];
  for (const argument of args) {
    const parsed = parseStaticExecCommand(argument);
    if (parsed.ok) commands.push({ command: parsed.command, workdir: parsed.workdir });
  }
  return commands;
}

function execPatchPaths(input) {
  const source = execSource(input);
  if (source === "") return [];
  EXEC_PATCH_ASSIGN_RE.lastIndex = 0;
  const match = EXEC_PATCH_ASSIGN_RE.exec(source);
  if (!match) return [];
  let patch;
  try {
    patch = JSON.parse(match[1]);
  } catch (_) {
    return [];
  }
  for (const argument of execToolArguments(source, "apply_patch")) {
    if (argument.trim() === "patch") return parsePatchPaths(patch);
  }
  return [];
}

/* ---------------------------------------------------------------------------
 * actionFor / targetsFor -- the harness-agnostic taxonomy core.
 * ------------------------------------------------------------------------- */

const READ_LINES_TOOLS = new Set(["Read"]);

function actionFor(tool, input, result) {
  switch (tool) {
    case "Read":
      return "read";
    case "Write":
    case "Edit":
    case "MultiEdit":
    case "NotebookEdit":
    case "apply_patch":
      return "edit";
    case "Grep":
    case "Glob":
    case "LS":
    case "view_image":
      return "search";
    case "Bash":
    case "exec_command":
    case "write_stdin":
    case "js":
    case "js_repl": {
      const command = firstString(input, "command", "cmd", "code", "chars", "script", "_raw");
      if (verifyCommand(command)) return "verify";
      if (searchCommand(command)) return "search";
      if (readCommand(command)) return "read";
      return "exec";
    }
    case "exec": {
      if (execPatchPaths(input).length > 0) return "edit";
      const commands = execCommands(input);
      if (commands.length === 0 || !execHasOnlyStaticCommands(input, commands.length)) return "exec";
      let allVerify = true;
      let allSearch = true;
      let allRead = true;
      for (const c of commands) {
        if (!verifyCommand(c.command)) allVerify = false;
        if (!searchCommand(c.command)) allSearch = false;
        if (!readCommand(c.command)) allRead = false;
      }
      if (allVerify) return "verify";
      if (allSearch) return "search";
      if (allRead) return "read";
      return "exec";
    }
    default:
      return "other";
  }
}

function readLines(input) {
  const offset = intFromAny(input && input.offset);
  const limit = intFromAny(input && input.limit);
  if (offset <= 0) return null;
  if (limit <= 0) return [[offset, offset]];
  return [[offset, offset + limit - 1]];
}

function touchRank(touch) {
  if (touch === "edit") return 3;
  if (touch === "read") return 2;
  if (touch === "hit") return 1;
  return 0;
}

/** Mirrors adapter.targetsFor. Returns {targets, outside}. */
function targetsFor(cwd, tool, input, result) {
  const targets = [];
  const outside = [];
  const seenOutside = new Set(); // CodeRabbit review, PR #23, 2026-08-06 -- see the dedup note just below

  const add = (rawPath, touch, weak, lines, base) => {
    const norm = normalizePath(cwd, base, rawPath);
    if (!norm.ok) return;
    if (norm.outside) {
      // CodeRabbit review, PR #23, 2026-08-06 (duplicate outside-path
      // entries per event): several tool cases below call `add()` more
      // than once over the SAME command/result text via different
      // extraction passes (e.g. Bash's commandReadPaths + extractCommandPaths
      // + extractPaths all independently scan the same command string) --
      // when the same outside path is found by more than one pass, each
      // pass used to append its own identical {scope, path} entry here, so
      // a single event's `outside` array (part of the public session-trace
      // JSON, not just the rendered report -- postmortem-render.js's
      // outsideTouches() already dedupes at the whole-REPORT level, a
      // separate, unrelated dedup this does not replace) could contain
      // exact duplicates. Dedupe within this one event's outside array the
      // same way `targets` already dedupes just below (a `find()` by path),
      // scoped per-event via this function-local `seenOutside` Set, keyed
      // by scope+path the same way postmortem-render.js's own
      // outsideTouches() key its report-level dedup.
      const key = norm.outside.scope + "|" + norm.outside.path;
      if (seenOutside.has(key)) return;
      seenOutside.add(key);
      outside.push(norm.outside);
      return;
    }
    // F3 (adversarial review finding, 2026-08-06): a "weak" (free-text-
    // inferred, not structured-argument) target used to be silently
    // dropped here via repoPathExists()'s fs.existsSync() check against
    // whatever machine happens to be running `graphsmith postmortem` --
    // the same session log parsed on two different machines (or the same
    // machine at two different times, as the repo changes) could produce
    // different reports. That's a direct violation of this file's own
    // determinism rule (file header): the only disclosed host-dependent
    // exception is outsideScope()'s home/tmp LABELING, never an
    // inclusion/exclusion decision. Fix: keep every weak target (already
    // flagged `weak: true` below so a report reader can see it was
    // inferred, not structurally certain) regardless of host filesystem
    // state, and removed the now-dead repoPathExists() helper.
    const existing = targets.find((t) => t.path === norm.rel);
    if (existing) {
      if (touchRank(touch) > touchRank(existing.touch)) existing.touch = touch;
      // CodeRabbit review, PR #23, 2026-08-06 (weak flag not cleared on
      // structured confirmation): a free-text-inferred target (weak: true)
      // that is later confirmed by a structured, non-weak argument for the
      // SAME path used to keep its weak flag forever -- add() upgraded
      // `touch` above but never cleared `weak`, so a structurally-certain
      // edit could still be reported as weak:true (an inferred guess) when
      // it is actually confirmed.
      // A structured (non-weak) argument confirms a path previously inferred
      // from free text -- the target is no longer a guess.
      if (!weak && existing.weak) delete existing.weak;
      if (lines) existing.lines = (existing.lines || []).concat(lines);
      return;
    }
    const t = { path: norm.rel, touch };
    if (weak) t.weak = true;
    if (lines && lines.length) t.lines = lines.slice();
    targets.push(t);
  };

  switch (tool) {
    case "Read": {
      if (typeof input.file_path === "string") add(input.file_path, "read", false, readLines(input), "");
      break;
    }
    case "Write":
    case "Edit":
    case "MultiEdit":
    case "NotebookEdit": {
      if (typeof input.file_path === "string") add(input.file_path, "edit", false, null, "");
      if (typeof input.notebook_path === "string") add(input.notebook_path, "edit", false, null, "");
      break;
    }
    case "Grep": {
      const hits = parsePathHits(result);
      for (const h of hits) add(h.path, "hit", false, h.lines, "");
      if (targets.length === 0 && typeof input.path === "string") add(input.path, "hit", true, null, "");
      break;
    }
    case "Glob":
    case "LS": {
      const hits = parsePathHits(result);
      for (const h of hits) add(h.path, "hit", false, null, "");
      if (typeof input.path === "string" && targets.length === 0) add(input.path, "hit", true, null, "");
      break;
    }
    case "Bash": {
      const command = firstString(input, "command");
      for (const p of commandReadPaths(command)) add(p, "read", true, null, "");
      for (const p of extractCommandPaths(command)) add(p, "hit", true, null, "");
      for (const p of extractPaths(command + "\n" + result)) add(p, "hit", true, null, "");
      break;
    }
    case "exec_command": {
      const command = firstString(input, "cmd", "command");
      const base = firstString(input, "workdir");
      for (const p of commandReadPaths(command)) add(p, "read", true, null, base);
      for (const p of extractCommandPaths(command)) add(p, "hit", true, null, base);
      for (const p of extractPaths(command + "\n" + result)) add(p, "hit", true, null, base);
      for (const h of parsePathHits(result)) add(h.path, "hit", true, h.lines, base);
      break;
    }
    case "exec": {
      for (const c of execCommands(input)) {
        for (const p of commandReadPaths(c.command)) add(p, "read", true, null, c.workdir);
        for (const p of extractCommandPaths(c.command)) add(p, "hit", true, null, c.workdir);
        for (const p of extractPaths(c.command)) add(p, "hit", true, null, c.workdir);
      }
      for (const p of extractPaths(result)) add(p, "hit", true, null, "");
      for (const h of parsePathHits(result)) add(h.path, "hit", true, h.lines, "");
      for (const p of execPatchPaths(input)) add(p, "edit", false, null, "");
      break;
    }
    case "apply_patch": {
      const patch = firstString(input, "patch", "input", "_raw");
      for (const p of parsePatchPaths(patch)) add(p, "edit", false, null, "");
      break;
    }
    case "view_image": {
      const p = firstString(input, "path");
      if (p) add(p, "read", false, null, "");
      break;
    }
    case "js":
    case "js_repl": {
      const code = firstString(input, "code", "script", "_raw");
      for (const p of extractPaths(code + "\n" + result)) add(p, "hit", true, null, "");
      break;
    }
    default:
      break;
  }
  return { targets, outside };
}

const TOOL_SUMMARY_VERB_LIMIT = 96;

function summarizeExecWrapper(input) {
  const commands = execCommands(input);
  const source = execSource(input);
  const nestedTools = execToolNames(source);
  if (commands.length === 0 && nestedTools.length === 0) return "";
  let primary = commands.length > 0 ? commands[0].command : nestedTools[0];
  let additionalCalls = commands.length - 1;
  if (nestedTools.length > 0) additionalCalls = nestedTools.length - 1;
  let suffix = "";
  if (additionalCalls === 1) suffix = " (+1 more tool call)";
  else if (additionalCalls > 1) suffix = ` (+${additionalCalls} more tool calls)`;
  const commandLimit = TOOL_SUMMARY_VERB_LIMIT - Array.from(suffix).length;
  return truncateRunes(collapseNewlines(primary), commandLimit, "...") + suffix;
}

/** Mirrors adapter.SummarizeTool. */
function summarizeTool(tool, input, targets, outside, isError) {
  let verb = tool;
  if (typeof input.description === "string" && input.description) verb = collapseNewlines(input.description);
  const command = firstString(input, "command", "cmd");
  if (command) {
    verb = truncateRunes(collapseNewlines(command), TOOL_SUMMARY_VERB_LIMIT, "...");
  } else if (tool === "exec") {
    const summary = summarizeExecWrapper(input);
    if (summary) verb = summary;
  }
  const status = isError ? " error" : "";
  return `${verb} -> ${targets.length} targets, ${outside.length} outside${status}`;
}

/** Mirrors adapter.BuildEvent -- builds one session-trace event object.
 *
 * CodeRabbit review, PR #23, 2026-08-06 (P1, unresolved calls treated as
 * exact success): a call still pending at EOF (never confirmed successful
 * by a real tool_result/function_call_output) used to be built with
 * isError: false, structurally indistinguishable from a real confirmed
 * success -- while the Claude Code adapter unconditionally claimed "exact"
 * error observability for the whole trace. Callers now pass
 * `result.unresolved: true` for a call that was still pending when the
 * session log ended (see postmortem-claude-code.js's final pendingOrder
 * walk); that flows through to `event.unresolved`, a distinguishable
 * marker a report reader (or computeStats below) can use to NOT treat the
 * call's isError:false as a confirmed non-error. Omitted (not written as
 * `false`) for a normally-resolved event, matching this file's existing
 * convention of only writing optional fields when they have something to
 * say (see `ts`/`outside` just below). */
function buildEvent(seq, cwd, call, result) {
  const action = actionFor(call.name, call.input || {}, result.content);
  const { targets, outside } = targetsFor(cwd, call.name, call.input || {}, result.content);
  const event = {
    seq,
    tool: call.name,
    action,
    targets,
    resultBytes: Buffer.byteLength(result.content || "", "utf8"),
    isError: !!result.isError,
    summary: summarizeTool(call.name, call.input || {}, targets, outside, !!result.isError),
  };
  if (call.timestamp) event.ts = call.timestamp;
  if (outside.length) event.outside = outside;
  if (result.unresolved) event.unresolved = true;
  return event;
}

/* ---------------------------------------------------------------------------
 * Stats rollup -- mirrors model.ComputeStats, adapted per the design doc's
 * disclosed deltas: fovea/parafovea and regressionRate dropped, `touched`
 * added, observability gains repoSize/verifyOutcome (always "unavailable").
 * ------------------------------------------------------------------------- */

function emptyActionCounts() {
  return { search: 0, read: 0, edit: 0, exec: 0, verify: 0, other: 0 };
}

function countAction(counts, action) {
  if (Object.prototype.hasOwnProperty.call(counts, action)) counts[action]++;
  else counts.other++;
}

/**
 * @param {object[]} events
 * @param {object[]} marks
 * @param {number|null} filesInRepo null when the repo was not available at
 *   parse time (observability.repoSize becomes "unavailable").
 * @param {"exact"|"estimated"} errorSignal
 */
function computeStats(events, marks, filesInRepo, errorSignal) {
  const state = new Map();
  const lastReadVersion = new Map();
  const editVersion = new Map();
  let readEvents = 0;
  let weakReads = 0;
  let errors = 0;
  let firstEdit = -1;
  let anyUnresolved = false; // CodeRabbit review, PR #23, 2026-08-06 -- see the errorSignal downgrade below

  const stats = {
    filesInRepo: filesInRepo == null ? 0 : filesInRepo,
    touched: 0,
    edited: 0,
    eventsBeforeFirstEdit: 0,
    errorRate: 0,
    actions: emptyActionCounts(),
    errors: emptyActionCounts(),
    maxEditsPerFile: 0,
    churnFiles: 0,
    userTurns: 0,
    compactions: 0,
    subagents: 0,
    resultBytes: 0,
    editsAfterLastVerify: 0,
    observability: {
      reads: "unavailable",
      errors: "estimated",
      repoSize: filesInRepo == null ? "unavailable" : "exact",
      verifyOutcome: "unavailable",
    },
  };

  for (const event of events) {
    countAction(stats.actions, event.action);
    if (event.unresolved) anyUnresolved = true;
    if (event.isError) {
      errors++;
      countAction(stats.errors, event.action);
    }
    stats.resultBytes += event.resultBytes || 0;
    if (event.action === "verify") stats.editsAfterLastVerify = 0;
    else if (event.action === "edit") stats.editsAfterLastVerify++;

    for (const target of event.targets || []) {
      if (!target.path) continue;
      const prev = state.get(target.path) || "";
      if (touchRank(target.touch) > touchRank(prev)) state.set(target.path, target.touch);
      if (target.touch === "edit") {
        editVersion.set(target.path, (editVersion.get(target.path) || 0) + 1);
      }
      if (target.touch === "read") {
        readEvents++;
        if (target.weak) weakReads++;
        const version = lastReadVersion.get(target.path);
        lastReadVersion.set(target.path, editVersion.get(target.path) || 0);
        void version; // (repeated-read rate itself is a dropped mindwalk field -- see regressionRate deletion note in the schema; version bookkeeping is kept only because it feeds observability.reads' weak/exact distinction below, matching mindwalk's own bookkeeping shape)
      }
      if (target.touch === "edit" && firstEdit === -1) firstEdit = event.seq;
    }
  }

  stats.eventsBeforeFirstEdit = firstEdit >= 0 ? firstEdit : events.length;

  for (const touch of state.values()) {
    stats.touched++;
    if (touch === "edit") stats.edited++;
  }
  for (const count of editVersion.values()) {
    if (count > stats.maxEditsPerFile) stats.maxEditsPerFile = count;
    if (count >= 3) stats.churnFiles++;
  }
  for (const mark of marks) {
    if (mark.type === "user-message") stats.userTurns++;
    else if (mark.type === "compaction") stats.compactions++;
    else if (mark.type === "subagent") stats.subagents++;
  }
  if (events.length > 0) stats.errorRate = errors / events.length;

  if (readEvents === 0) stats.observability.reads = "unavailable";
  else if (weakReads === 0) stats.observability.reads = "exact";
  else stats.observability.reads = "estimated";

  // CodeRabbit review, PR #23, 2026-08-06 (P1, unresolved calls treated as
  // exact success): a call still pending at EOF is emitted with
  // isError:false (see buildEvent's `unresolved` handling above) but that
  // is NOT a confirmed non-error -- it's simply a call the session never
  // got a result for before the log ended. Claiming stats.observability
  // .errors === "exact" for a trace that contains even one such
  // unconfirmed call would be dishonest: an unresolved call silently counts
  // toward the error-rate denominator as if it were a verified success.
  // Downgrade "exact" to "estimated" whenever any event is unresolved,
  // regardless of what errorSignal the caller passed in (only "exact" needs
  // downgrading -- "estimated" stays "estimated" either way, so this is a
  // one-directional honesty check, never an upgrade).
  stats.observability.errors = errorSignal || "estimated";
  if (anyUnresolved && stats.observability.errors === "exact") {
    stats.observability.errors = "estimated";
  }

  return stats;
}

module.exports = {
  loadPatterns,
  contentToString,
  intFromAny,
  firstString,
  truncateRunes,
  userMessageNote,
  injectedUserMessage,
  normalizePath,
  outsideScope,
  pathStyleOf,
  extractPaths,
  extractCommandPaths,
  parsePathHits,
  parsePatchPaths,
  cleanExtractedPath,
  verifyCommand,
  searchCommand,
  readCommand,
  commandReadPaths,
  execCommands,
  execPatchPaths,
  execHasOnlyStaticCommands,
  actionFor,
  targetsFor,
  readLines,
  summarizeTool,
  summarizeExecWrapper,
  buildEvent,
  computeStats,
  touchRank,
};
