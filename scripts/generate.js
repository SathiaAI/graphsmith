#!/usr/bin/env node
/* GraphSmith canonical-to-surfaces generator (scripts/generate.js) — Lane D,
 * v0.5.0 Wave 1.
 *
 * Deterministic, zero-LLM, zero-dependency CommonJS, Node >= 18. NO network
 * calls, NO clocks/randomness in any DECISION path (the only exception,
 * matching scripts/reconcile.js's own posture, is crypto.randomBytes used
 * purely to name a scratch temp file for the atomic-write helper -- never
 * read back into a pass/fail branch).
 *
 * WHAT THIS IS. Reads root SKILL.md (read-only input, never written to --
 * see .plans/v0.5.0/WAVE-0-CANONICAL-SOURCE.md) plus every adapter
 * definition under generators/adapters/*.json, validates each definition
 * against schemas/host-adapter.schema.json (scripts/schema-validate.js --
 * see that file's header for why this is hand-rolled instead of `ajv`), and
 * renders one output per adapter:
 *
 *   placementMode "standalone"  -> this script owns the target file
 *                                  outright and writes it directly
 *                                  (atomically -- temp file + rename, and
 *                                  the same symlink-refusal policy as
 *                                  scripts/reconcile.js, since the same
 *                                  "resolve-once-trust-forever" bug class
 *                                  applies to a file this script writes
 *                                  directly, not only to reconciled ones).
 *   placementMode "reconciled"  -> this script NEVER touches the target
 *                                  file with fs.writeFileSync or any other
 *                                  direct write call. The rendered body is
 *                                  handed to scripts/reconcile.js's
 *                                  `reconcile()` and that is the only
 *                                  function ever allowed to write a
 *                                  reconciled-mode target. This is the
 *                                  data-loss-critical guarantee
 *                                  host-adapter.schema.json's own
 *                                  `placementMode` doc calls out.
 *
 * Template: ponytail's build-openclaw-skills.js pattern (read canonical
 * source once, render per-adapter, write deterministically) per the Lane D
 * brief in .plans/v0.5.0/CLAUDE-CODE-KICKOFF.md -- applied to every launch
 * surface from day one, not one surface hand-copied-and-diff-checked the
 * way ponytail actually shipped it.
 *
 * DETERMINISM. Every byte of every rendered output is a pure function of
 * (SKILL.md content, the adapter definition JSON). No Date.now(), no
 * Math.random(), no environment-dependent formatting anywhere in the render
 * path -- see tests/generate/run-tests.js's "byte-identical across runs"
 * group, which diffs two consecutive generation outputs and fails on any
 * difference.
 *
 * CLI:
 *   node scripts/generate.js [--check] [--root <dir>] [--skill <path>]
 *     [--adapters-dir <dir>] [--schema <path>] [--adapters id1,id2,...]
 *
 *   (no flags)  generate and write every adapter's output.
 *   --check     dry run: compute what generation WOULD produce and compare
 *               against what is currently on disk. Exits non-zero and
 *               prints every drifted/missing surface if anything differs --
 *               this is the mechanism the "hand-edit a generated file, run
 *               CI, confirm it actually fails" adversarial test exercises.
 *               Never writes anything, standalone or reconciled.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const schemaValidate = require("./schema-validate.js");
const reconcileLib = require("./reconcile.js");

// The schema_version Lane D's OWN rendered-block contract conforms to when
// handing a reconciled-mode body to scripts/reconcile.js's `reconcile()`.
// This is deliberately distinct from host-adapter.schema.json's own
// versioning and from any adapter definition field: it versions the shape
// of what THIS generator puts inside the markers (currently: SKILL.md's
// body, copied verbatim, nothing else). Bump it, and document why, only if
// that shape itself changes in a way an older reconcile.js could not safely
// splice over -- see reconcile.js's own "SCHEMA-VERSION COMPATIBILITY" note.
const BLOCK_SCHEMA_VERSION = "1";

class GenerationError extends Error {}

// ---------------------------------------------------------------------------
// SKILL.md parsing
// ---------------------------------------------------------------------------

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;
const SIMPLE_SCALAR_LINE_RE = /^([a-zA-Z][a-zA-Z0-9_-]*):[ \t]?(.*)$/;
// Any of these appearing as the *value* of a recognized key signals a YAML
// construct this parser deliberately does not support (block scalars,
// flow collections, anchors, ...). SKILL.md's frontmatter is documented
// (WAVE-0-CANONICAL-SOURCE.md) as exactly two single-line string scalars
// (`name`, `description`) -- anything else is refused loudly rather than
// silently mis-parsed (e.g. truncated at the first line of a multi-line
// block scalar, which would silently drop real canonical content).
const UNSUPPORTED_SCALAR_VALUE_RE = /^([|>]|\[|\{|&|\*|!)/;

/**
 * Parses root SKILL.md into { name, description, body }. Throws
 * GenerationError (loud failure, never a best-effort guess) if the
 * frontmatter isn't the exact shape WAVE-0-CANONICAL-SOURCE.md documents:
 * a `---` delimited block containing single-line `name:` and
 * `description:` scalars, nothing more exotic.
 */
function parseSkill(skillPath) {
  let raw;
  try {
    raw = fs.readFileSync(skillPath, "utf8");
  } catch (e) {
    throw new GenerationError(`parseSkill: cannot read ${skillPath}: ${e.message}`);
  }
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1); // tolerate a BOM, same posture as reconcile.js

  const m = FRONTMATTER_RE.exec(raw);
  if (!m) {
    throw new GenerationError(
      `parseSkill: ${skillPath} does not start with a well-formed "---"-delimited frontmatter block`
    );
  }
  const fmBlock = m[1];
  const body = m[2];

  const fields = {};
  const fmLines = fmBlock.split(/\r?\n/);
  for (let i = 0; i < fmLines.length; i++) {
    const line = fmLines[i];
    if (line.trim() === "") continue;
    const lm = SIMPLE_SCALAR_LINE_RE.exec(line);
    if (!lm) {
      throw new GenerationError(
        `parseSkill: ${skillPath} frontmatter line ${i + 1} is not a supported "key: value" single-line scalar: ${JSON.stringify(line)}`
      );
    }
    const key = lm[1];
    const value = lm[2];
    if (UNSUPPORTED_SCALAR_VALUE_RE.test(value)) {
      throw new GenerationError(
        `parseSkill: ${skillPath} frontmatter field "${key}" uses an unsupported YAML construct (block scalar / flow collection / anchor) -- this generator only supports single-line plain or quoted string scalars for canonical SKILL.md frontmatter`
      );
    }
    // Strip one layer of matching quotes if present; otherwise take the
    // value verbatim. SKILL.md's real frontmatter (confirmed 2026-07-31,
    // WAVE-0-CANONICAL-SOURCE.md) uses bare unquoted scalars for both
    // fields, so this is a courtesy for hand-authored variants, not the
    // load-bearing path.
    let v = value;
    if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
      v = v.slice(1, -1);
    }
    fields[key] = v;
  }

  if (typeof fields.name !== "string" || fields.name.length === 0) {
    throw new GenerationError(`parseSkill: ${skillPath} frontmatter is missing a non-empty "name" field`);
  }
  if (typeof fields.description !== "string" || fields.description.length === 0) {
    throw new GenerationError(`parseSkill: ${skillPath} frontmatter is missing a non-empty "description" field`);
  }

  return { name: fields.name, description: fields.description, body };
}

// ---------------------------------------------------------------------------
// Adapter definition loading + schema validation
// ---------------------------------------------------------------------------

/** Loads every *.json under adaptersDir, sorted by filename for determinism. */
function loadAdapterDefs(adaptersDir) {
  let names;
  try {
    names = fs.readdirSync(adaptersDir).filter((n) => n.endsWith(".json"));
  } catch (e) {
    throw new GenerationError(`loadAdapterDefs: cannot read adapters dir ${adaptersDir}: ${e.message}`);
  }
  names.sort();
  return names.map((name) => {
    const p = path.join(adaptersDir, name);
    let def;
    try {
      def = JSON.parse(fs.readFileSync(p, "utf8"));
    } catch (e) {
      throw new GenerationError(`loadAdapterDefs: ${p} is not valid JSON: ${e.message}`);
    }
    return { file: p, def };
  });
}

/**
 * Validates one adapter definition against host-adapter.schema.json.
 * Returns an array of error strings (empty = valid).
 */
function validateAdapterDef(def, schema) {
  return schemaValidate.validate(def, schema, "$");
}

// ---------------------------------------------------------------------------
// YAML scalar rendering for the "markdown-frontmatter" outputFormat
// ---------------------------------------------------------------------------

// Characters that are unsafe to start a YAML plain scalar with, per the YAML
// 1.1/1.2 spec's "indicator" set. Anything on this list forces quoting.
const YAML_LEADING_INDICATOR_RE = /^[-?:,\[\]{}#&*!|>'"%@`]/;

// Additional YAML 1.2 "core schema" scalars that a plain string can
// accidentally collide with -- none of these start with a character
// YAML_LEADING_INDICATOR_RE catches, and none are covered by the
// true/false/null/decimal-number checks below. Confirmed via a real
// parser (js-yaml) round-trip during the Lane D non-Anthropic adversarial
// review (2026-08-04): unquoted, a real YAML reader silently resolves
// each of these to null/a number/a float instead of the original string,
// with zero error signal. See that review's findings for the exact
// empirical evidence.
const YAML_NULL_ALIAS_RE = /^~$/;
const YAML_HEX_INT_RE = /^[-+]?0x[0-9a-fA-F]+$/;
const YAML_OCTAL_INT_RE = /^[-+]?0o[0-7]+$/;
const YAML_INF_NAN_RE = /^[-+]?\.(inf|Inf|INF|nan|NaN|NAN)$/;

/**
 * Renders `value` as a YAML frontmatter scalar for one field. Prefers a
 * plain (unquoted) scalar when safe; falls back to a double-quoted, escaped
 * scalar for values that need it (colon-space, leading indicator char,
 * trailing/leading whitespace, the literal words true/false/null, or a
 * value that looks like a JSON number). THROWS (GenerationError) rather
 * than emitting anything for a value this simple emitter cannot safely
 * represent as a single-line frontmatter scalar at all -- concretely, a
 * value containing a raw newline or carriage return. That construct is
 * perfectly valid prose for a "markdown-plain" body (reconcile.js copies it
 * byte-for-byte, newlines and all) but is NOT valid as a single physical
 * frontmatter line without YAML block-scalar syntax (`|`/`>`), which this
 * generator deliberately does not implement (see parseSkill's matching
 * refusal for the same reason, in the read direction). This is the "valid
 * in one host's syntax, invalid in another's" case the Lane D adversarial
 * test list calls for: fed the same value, a markdown-plain adapter
 * (agents-generic, copilot) succeeds; a markdown-frontmatter adapter
 * (cursor) fails loudly right here instead of emitting truncated or
 * corrupted YAML.
 */
function toYamlScalar(fieldName, value) {
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  if (typeof value !== "string") {
    throw new GenerationError(`toYamlScalar: field "${fieldName}" has unsupported value type ${typeof value}`);
  }
  if (/[\r\n]/.test(value)) {
    throw new GenerationError(
      `toYamlScalar: field "${fieldName}" value contains a raw newline/carriage-return -- this generator cannot safely represent that as a single-line frontmatter scalar (would require YAML block-scalar syntax, not implemented). Fix the source value or route this field through a "static" single-line value.`
    );
  }
  const needsQuoting =
    value.length === 0 ||
    YAML_LEADING_INDICATOR_RE.test(value) ||
    /: /.test(value) ||
    / #/.test(value) ||
    /\s$/.test(value) ||
    /^\s/.test(value) ||
    value === "true" ||
    value === "false" ||
    value === "null" ||
    /^-?\d+(\.\d+)?$/.test(value) ||
    YAML_NULL_ALIAS_RE.test(value) ||
    YAML_HEX_INT_RE.test(value) ||
    YAML_OCTAL_INT_RE.test(value) ||
    YAML_INF_NAN_RE.test(value);
  if (!needsQuoting) return value;
  const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return `"${escaped}"`;
}

/**
 * Renders the full `---\n...\n---\n` frontmatter block for one adapter,
 * enforcing `required` and `maxLength` per host-adapter.schema.json's own
 * documented semantics: a maxLength violation is a BUILD-TIME VALIDATION
 * ERROR (throws), never silent truncation -- the schema's own field
 * description spells this out explicitly and this function is the one
 * place that contract is enforced.
 */
function renderFrontmatter(adapterId, fields, skill) {
  const lines = [];
  for (const field of fields) {
    let value;
    if (field.source === "name") value = skill.name;
    else if (field.source === "description") value = skill.description;
    else if (field.source === "static") value = field.staticValue;
    else throw new GenerationError(`renderFrontmatter[${adapterId}]: unknown frontmatterFields[].source "${field.source}"`);

    if (field.required && (value === undefined || value === null || value === "")) {
      throw new GenerationError(`renderFrontmatter[${adapterId}]: required field "${field.name}" resolved to an empty value`);
    }

    if (typeof field.maxLength === "number" && typeof value === "string" && value.length > field.maxLength) {
      throw new GenerationError(
        `renderFrontmatter[${adapterId}]: field "${field.name}" (source: ${field.source}) is ${value.length} chars, exceeds this host's maxLength of ${field.maxLength}. ` +
          `Per host-adapter.schema.json this is a build-time error, not silent truncation -- if source is "description", either shorten canonical SKILL.md's description or change this field's source to "static" with a hand-written value that fits.`
      );
    }

    lines.push(`${field.name}: ${toYamlScalar(field.name, value)}`);
  }
  return `---\n${lines.join("\n")}\n---\n`;
}

// ---------------------------------------------------------------------------
// generatedFileHeader placement (format-dependent, load-bearing -- see
// host-adapter.schema.json's own doc comment on this field)
// ---------------------------------------------------------------------------

function insertGeneratedFileHeader(outputFormat, frontmatterBlock, body, header) {
  if (!header) return frontmatterBlock + body;
  const headerLine = `<!-- ${stripComment(header)} -->\n`;
  if (outputFormat === "markdown-frontmatter") {
    // MUST be the line immediately after the closing "---", MUST NEVER
    // precede the opening "---" (Cursor's .mdc parser silently fails to
    // load the file if anything precedes frontmatter).
    return frontmatterBlock + headerLine + body;
  }
  // markdown-plain: first line(s) of the file.
  return headerLine + body;
}

function stripComment(header) {
  // Adapter authors may write the header with or without its own
  // "<!-- ... -->" wrapper; normalize to the bare text so this function is
  // the single place that decides the actual comment delimiters, rather
  // than trusting each adapter JSON to get double-wrapping right.
  const m = /^<!--\s*([\s\S]*?)\s*-->$/.exec(header.trim());
  return m ? m[1] : header.trim();
}

// ---------------------------------------------------------------------------
// Per-adapter rendering
// ---------------------------------------------------------------------------

/**
 * Renders the full content for a "standalone" adapter: frontmatter (if
 * any) + generatedFileHeader (placed per format rule) + SKILL.md body,
 * verbatim (bodyTransform is required to be "verbatim" by the schema; this
 * generator does not implement any other transform, matching v0.5.0's
 * frozen scope).
 */
function renderStandaloneContent(skill, def) {
  if (def.bodyTransform !== "verbatim") {
    throw new GenerationError(`renderStandaloneContent[${def.id}]: unsupported bodyTransform "${def.bodyTransform}" (only "verbatim" is implemented)`);
  }
  const body = skill.body;
  let frontmatterBlock = "";
  if (def.outputFormat === "markdown-frontmatter") {
    frontmatterBlock = renderFrontmatter(def.id, def.frontmatterFields || [], skill);
  }
  return insertGeneratedFileHeader(def.outputFormat, frontmatterBlock, body, def.generatedFileHeader);
}

/**
 * Renders the block body handed to reconcile() for a "reconciled" adapter.
 * Reconciled-mode + markdown-frontmatter is forbidden by the schema's own
 * allOf constraint (frontmatter must sit at the document's absolute top,
 * which a reconciler splicing a mid-file block cannot own) -- re-asserted
 * here defensively even though schema validation already rejects that
 * combination before rendering is ever reached.
 */
function renderReconciledBody(skill, def) {
  if (def.outputFormat !== "markdown-plain") {
    throw new GenerationError(`renderReconciledBody[${def.id}]: reconciled placementMode requires outputFormat "markdown-plain", got "${def.outputFormat}"`);
  }
  if (def.bodyTransform !== "verbatim") {
    throw new GenerationError(`renderReconciledBody[${def.id}]: unsupported bodyTransform "${def.bodyTransform}" (only "verbatim" is implemented)`);
  }
  return skill.body;
}

// ---------------------------------------------------------------------------
// Standalone-mode direct write (with the same symlink-refusal + atomic-write
// discipline as scripts/reconcile.js -- see that file's SYMLINK POLICY /
// ATOMICITY notes, reused here via its exported atomicWriteFileSync rather
// than a second copy of the same logic).
// ---------------------------------------------------------------------------

function writeStandaloneAtomic(targetPath, content) {
  let lst = null;
  try {
    lst = fs.lstatSync(targetPath);
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  if (lst && lst.isSymbolicLink()) {
    return { status: "refused", reason: "symlink-refused", path: targetPath };
  }
  if (lst && !lst.isFile()) {
    return { status: "refused", reason: "target-not-a-file", path: targetPath };
  }
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  const bytesWritten = reconcileLib.atomicWriteFileSync(targetPath, content);
  return { status: lst ? "overwritten" : "created", path: targetPath, bytesWritten };
}

// ---------------------------------------------------------------------------
// --check mode: compute drift without writing anything
// ---------------------------------------------------------------------------

function checkStandalone(targetPath, expectedContent) {
  let actual = null;
  try {
    actual = fs.readFileSync(targetPath, "utf8");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  if (actual === null) return { drift: true, reason: "missing", path: targetPath };
  if (actual !== expectedContent) return { drift: true, reason: "content-mismatch", path: targetPath };
  return { drift: false, path: targetPath };
}

function checkReconciled(targetPath, blockId, expectedBody) {
  let raw;
  try {
    raw = fs.readFileSync(targetPath, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") return { drift: true, reason: "missing", path: targetPath };
    throw e;
  }
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
  const found = reconcileLib.findBlock(raw, blockId);
  if (!found) return { drift: true, reason: "no-block-found", path: targetPath };
  const desiredBody = reconcileLib.normalizeBody(expectedBody);
  const desiredVersion = Number(BLOCK_SCHEMA_VERSION);
  const foundVersion = Number(found.schemaVersion);
  if (foundVersion > desiredVersion) return { drift: true, reason: "future-schema-version", path: targetPath };
  if (foundVersion === desiredVersion && found.body === desiredBody) return { drift: false, path: targetPath };
  return { drift: true, reason: "block-drifted", path: targetPath };
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

function defaultOptions(overrides) {
  const root = (overrides && overrides.root) || process.cwd();
  return Object.assign(
    {
      root,
      skillPath: path.join(root, "SKILL.md"),
      adaptersDir: path.join(root, "generators", "adapters"),
      schemaPath: path.join(root, "schemas", "host-adapter.schema.json"),
      check: false,
      adapterFilter: null, // null = all
    },
    overrides || {}
  );
}

/**
 * Runs generation (or, with check:true, a dry-run drift check) for every
 * adapter definition found under options.adaptersDir. Returns
 * { results: [{ adapterId, mode, ... }], driftCount }.
 *
 * Throws GenerationError (loudly, aborting the whole run before any file is
 * touched) on: an invalid adapter definition, a malformed SKILL.md, or a
 * frontmatter value this generator cannot safely render. Fail-loud-not-
 * silent is the point of every one of those checks -- see the Lane D
 * adversarial test list.
 */
function generateAll(options) {
  const opts = defaultOptions(options);
  const skill = parseSkill(opts.skillPath);
  const schema = JSON.parse(fs.readFileSync(opts.schemaPath, "utf8"));
  let defs = loadAdapterDefs(opts.adaptersDir);

  // Validate EVERY adapter definition before rendering or writing ANYTHING.
  // A single invalid definition aborts the whole run -- partial generation
  // from a partially-valid adapter set is exactly the kind of "mostly
  // works" silent-corruption shape this build's discipline forbids.
  const validationErrors = [];
  for (const { file, def } of defs) {
    const errs = validateAdapterDef(def, schema);
    if (errs.length > 0) {
      validationErrors.push(`${file}:\n  ${errs.join("\n  ")}`);
    }
  }
  if (validationErrors.length > 0) {
    throw new GenerationError(`generateAll: ${validationErrors.length} adapter definition(s) failed schema validation:\n\n${validationErrors.join("\n\n")}`);
  }

  // Validate EVERY adapter definition's targetPath resolves inside
  // opts.root before rendering or writing ANYTHING -- same all-or-nothing
  // posture as the schema-validation pass above (see GROUP 12's "invalid
  // adapter aborts the whole run" guarantee, which this extends to a
  // second class of bad input). A malformed or mistyped targetPath (e.g.
  // containing "../") must never silently write outside the project
  // root, and must never partially generate other, otherwise-valid
  // adapters first. Found by the Lane D non-Anthropic adversarial review
  // (2026-08-04): path.join(opts.root, def.targetPath) previously had no
  // containment check at all.
  const resolvedRoot = path.resolve(opts.root);
  const containmentErrors = [];
  for (const { def } of defs) {
    const resolvedTarget = path.resolve(path.join(opts.root, def.targetPath));
    if (resolvedTarget !== resolvedRoot && !resolvedTarget.startsWith(resolvedRoot + path.sep)) {
      containmentErrors.push(
        `adapter "${def.id}": targetPath ${JSON.stringify(def.targetPath)} resolves to "${resolvedTarget}", which is outside root "${resolvedRoot}"`
      );
    }
  }
  if (containmentErrors.length > 0) {
    throw new GenerationError(
      `generateAll: ${containmentErrors.length} adapter(s) have a targetPath that escapes opts.root:\n\n  ${containmentErrors.join("\n  ")}`
    );
  }

  if (opts.adapterFilter) {
    const wanted = new Set(opts.adapterFilter);
    defs = defs.filter(({ def }) => wanted.has(def.id));
  }

  const results = [];
  let driftCount = 0;

  for (const { def } of defs) {
    const targetPath = path.join(opts.root, def.targetPath);

    if (def.placementMode === "standalone") {
      const content = renderStandaloneContent(skill, def);
      if (opts.check) {
        const r = checkStandalone(targetPath, content);
        if (r.drift) driftCount++;
        results.push(Object.assign({ adapterId: def.id, mode: "standalone" }, r));
      } else {
        const r = writeStandaloneAtomic(targetPath, content);
        results.push(Object.assign({ adapterId: def.id, mode: "standalone" }, r));
      }
    } else if (def.placementMode === "reconciled") {
      const body = renderReconciledBody(skill, def);
      if (opts.check) {
        const r = checkReconciled(targetPath, def.id, body);
        if (r.drift) driftCount++;
        results.push(Object.assign({ adapterId: def.id, mode: "reconciled" }, r));
      } else {
        // NEVER fs.writeFileSync a reconciled target directly -- reconcile()
        // is the only permitted writer. See module header.
        const r = reconcileLib.reconcile(targetPath, body, { blockId: def.id, schemaVersion: BLOCK_SCHEMA_VERSION });
        results.push(Object.assign({ adapterId: def.id, mode: "reconciled" }, r));
      }
    } else {
      throw new GenerationError(`generateAll: adapter "${def.id}" has unknown placementMode "${def.placementMode}"`);
    }
  }

  return { results, driftCount };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--check") out.check = true;
    else if (argv[i] === "--root" && argv[i + 1]) out.root = argv[++i];
    else if (argv[i] === "--skill" && argv[i + 1]) out.skillPath = argv[++i];
    else if (argv[i] === "--adapters-dir" && argv[i + 1]) out.adaptersDir = argv[++i];
    else if (argv[i] === "--schema" && argv[i + 1]) out.schemaPath = argv[++i];
    else if (argv[i] === "--adapters" && argv[i + 1]) out.adapterFilter = argv[++i].split(",").filter(Boolean);
  }
  return out;
}

function main() {
  const cliOpts = parseArgs(process.argv.slice(2));
  try {
    const { results, driftCount } = generateAll(cliOpts);
    for (const r of results) {
      console.log(JSON.stringify(r));
    }
    if (cliOpts.check) {
      if (driftCount > 0) {
        console.error(`\n*** DRIFT DETECTED on ${driftCount} surface(s) -- generated output does not match SKILL.md. Run "node scripts/generate.js" (no --check) to regenerate, or if this was a hand-edit, revert it. ***`);
        process.exit(1);
      }
      console.log("\nAll generated surfaces match SKILL.md (no drift).");
      process.exit(0);
    }
    process.exit(0);
  } catch (e) {
    process.stderr.write(`Error: ${e && e.message ? e.message : String(e)}\n`);
    process.exit(2);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  GenerationError,
  parseSkill,
  loadAdapterDefs,
  validateAdapterDef,
  toYamlScalar,
  renderFrontmatter,
  insertGeneratedFileHeader,
  renderStandaloneContent,
  renderReconciledBody,
  writeStandaloneAtomic,
  checkStandalone,
  checkReconciled,
  generateAll,
  defaultOptions,
  BLOCK_SCHEMA_VERSION,
};
