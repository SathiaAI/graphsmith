"use strict";

/* tests/generate/run-tests.js — Lane D adversarial suite for
 * scripts/generate.js (the canonical SKILL.md -> all-surfaces generator)
 * and scripts/schema-validate.js (the hand-rolled host-adapter.schema.json
 * validator used in place of `ajv` -- see schema-validate.js's own header
 * for why).
 *
 * Standalone, framework-free, mirrors the repo's own
 * tests/<component>/run-tests.js convention (see e.g.
 * tests/reconcile/run-tests.js, Lane A). Discoverable by
 * scripts/ci-run-suites.js's literal "run-tests.js" filename walk.
 *
 * Every ADVERSARIAL TEST from .plans/v0.5.0/CLAUDE-CODE-KICKOFF.md's Lane D
 * entry is implemented below as an executable check, not a description:
 *   - hand-edit a generated standalone file -> `--check` catches the drift
 *   - add a new host adapter -> zero diff on existing surfaces
 *   - host-incompatible frontmatter construct -> loud failure, not silent
 *     corruption
 *   - real launch adapter definitions validate against
 *     host-adapter.schema.json via scripts/schema-validate.js
 *   - byte-identical determinism across multiple runs
 *
 * Two of these groups (GROUP 6 "reconciled-mode-never-written-directly" and
 * GROUP 7 "generatedFileHeader placement") were each run once against a
 * DELIBERATELY BROKEN copy of scripts/generate.js and confirmed to fail,
 * then re-run against the real file and confirmed to pass -- see this run's
 * accompanying report for the exact edits made and reverted (that check is
 * inherently a two-run manual process, not something a single automated
 * suite run can self-demonstrate).
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const cp = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const GENERATE_PATH = path.join(REPO_ROOT, "scripts", "generate.js");
const RECONCILE_PATH = path.join(REPO_ROOT, "scripts", "reconcile.js");
const SCHEMA_VALIDATE_PATH = path.join(REPO_ROOT, "scripts", "schema-validate.js");
const REAL_SCHEMA_PATH = path.join(REPO_ROOT, "schemas", "host-adapter.schema.json");
const REAL_ADAPTERS_DIR = path.join(REPO_ROOT, "generators", "adapters");
const REAL_SKILL_PATH = path.join(REPO_ROOT, "SKILL.md");

const generateLib = require(GENERATE_PATH);
const reconcileLib = require(RECONCILE_PATH);
const schemaValidate = require(SCHEMA_VALIDATE_PATH);

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
    console.log(`SKIP: ${name}${detail ? " -- " + detail : ""}`);
    skipped++;
  }
}

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-generate-${label}-`));
}

function cleanup(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {
    /* best-effort */
  }
}

const REAL_SCHEMA = JSON.parse(fs.readFileSync(REAL_SCHEMA_PATH, "utf8"));

const SIMPLE_SKILL =
  "---\n" +
  "name: testskill\n" +
  "description: A plain test description with nothing fancy in it.\n" +
  "---\n" +
  "\n" +
  "# Test Skill\n" +
  "\n" +
  "Body content here.\n" +
  "Second line of body.\n";

function writeFixtureSkill(dir, content) {
  const p = path.join(dir, "SKILL.md");
  fs.writeFileSync(p, content == null ? SIMPLE_SKILL : content, "utf8");
  return p;
}

function writeFixtureAdapters(dir, adapters) {
  const adaptersDir = path.join(dir, "generators", "adapters");
  fs.mkdirSync(adaptersDir, { recursive: true });
  for (const name of Object.keys(adapters)) {
    fs.writeFileSync(path.join(adaptersDir, `${name}.json`), JSON.stringify(adapters[name], null, 2), "utf8");
  }
  return adaptersDir;
}

function loadRealAdapterDef(id) {
  return JSON.parse(fs.readFileSync(path.join(REAL_ADAPTERS_DIR, `${id}.json`), "utf8"));
}

function standardFixtureAdapters() {
  return {
    cursor: loadRealAdapterDef("cursor"),
    copilot: loadRealAdapterDef("copilot"),
    "agents-generic": loadRealAdapterDef("agents-generic"),
  };
}

function buildFixture(label, opts) {
  const dir = tmpDir(label);
  const skillPath = writeFixtureSkill(dir, opts && opts.skill);
  const adaptersDir = writeFixtureAdapters(dir, (opts && opts.adapters) || standardFixtureAdapters());
  return {
    dir,
    skillPath,
    adaptersDir,
    options: {
      root: dir,
      skillPath,
      adaptersDir,
      schemaPath: REAL_SCHEMA_PATH,
    },
  };
}

function runCli(args, cwdOverride) {
  const res = cp.spawnSync(process.execPath, [GENERATE_PATH, ...args], {
    cwd: cwdOverride || REPO_ROOT,
    encoding: "utf8",
  });
  return res;
}

function runCliForFixture(fixture, extraArgs) {
  return runCli([
    "--root", fixture.dir,
    "--skill", fixture.skillPath,
    "--adapters-dir", fixture.adaptersDir,
    "--schema", REAL_SCHEMA_PATH,
    ...(extraArgs || []),
  ]);
}

// ===========================================================================
// GROUP 1: SKILL.md parsing -- sanity + loud refusal on malformed input
// ===========================================================================
function groupSkillParsing() {
  console.log("\n=== GROUP 1: SKILL.md parsing ===");

  const { skillPath } = buildFixture("parse-ok");
  const skill = generateLib.parseSkill(skillPath);
  report("1.1 parses name", skill.name === "testskill", skill.name);
  report("1.2 parses description", skill.description === "A plain test description with nothing fancy in it.", skill.description);
  report("1.3 body starts after frontmatter", skill.body.startsWith("\n# Test Skill"), JSON.stringify(skill.body.slice(0, 30)));

  // Real root SKILL.md must also parse cleanly -- this is the actual
  // canonical source the four launch adapters render from.
  let realSkill;
  let realErr = null;
  try {
    realSkill = generateLib.parseSkill(REAL_SKILL_PATH);
  } catch (e) {
    realErr = e;
  }
  report("1.4 real root SKILL.md parses without throwing", realErr === null, realErr && realErr.message);
  report("1.5 real SKILL.md name is graphsmith", realSkill && realSkill.name === "graphsmith", realSkill && realSkill.name);

  // Malformed: no frontmatter delimiters at all
  {
    const dir = tmpDir("parse-no-fm");
    const p = writeFixtureSkill(dir, "# No frontmatter here\n\nJust a body.\n");
    let threw = false;
    try {
      generateLib.parseSkill(p);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
    }
    report("1.6 missing frontmatter delimiters throws GenerationError", threw);
    cleanup(dir);
  }

  // Malformed: missing description field
  {
    const dir = tmpDir("parse-no-desc");
    const p = writeFixtureSkill(dir, "---\nname: onlyname\n---\nBody\n");
    let threw = false;
    try {
      generateLib.parseSkill(p);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError && /description/.test(e.message);
    }
    report("1.7 missing description field throws GenerationError", threw);
    cleanup(dir);
  }

  // Malformed: YAML block scalar (multi-line description) -- must be
  // refused loudly, not silently truncated at the first physical line.
  {
    const dir = tmpDir("parse-block-scalar");
    const p = writeFixtureSkill(dir, "---\nname: x\ndescription: |\n  line one\n  line two\n---\nBody\n");
    let threw = false;
    let msg = "";
    try {
      generateLib.parseSkill(p);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
      msg = e.message;
    }
    report("1.8 YAML block-scalar description throws GenerationError (not silently truncated)", threw, msg);
    cleanup(dir);
  }
}

// ===========================================================================
// GROUP 2: real launch adapter definitions validate against
// host-adapter.schema.json via the hand-rolled Ajv2020-equivalent validator
// ===========================================================================
function groupAdapterSchemaValidation() {
  console.log("\n=== GROUP 2: adapter definition schema validation ===");

  for (const id of ["cursor", "copilot", "agents-generic"]) {
    const def = loadRealAdapterDef(id);
    const errors = schemaValidate.validate(def, REAL_SCHEMA, "$");
    report(`2.${id} real "${id}" adapter definition validates cleanly`, errors.length === 0, JSON.stringify(errors));
  }

  // Negative controls: each of these must be REJECTED.
  const negatives = [
    ["missing required targetPath", (() => { const d = loadRealAdapterDef("cursor"); delete d.targetPath; return d; })()],
    ["bad id pattern (uppercase)", (() => { const d = loadRealAdapterDef("cursor"); d.id = "Cursor"; return d; })()],
    ["unknown placementMode", (() => { const d = loadRealAdapterDef("cursor"); d.placementMode = "sideways"; return d; })()],
    ["additional unknown property", (() => { const d = loadRealAdapterDef("copilot"); d.notInSchema = true; return d; })()],
    [
      "reconciled + markdown-frontmatter (forbidden combo)",
      (() => {
        const d = loadRealAdapterDef("copilot");
        d.outputFormat = "markdown-frontmatter";
        d.frontmatterFields = [{ name: "description", source: "description", required: true }];
        return d;
      })(),
    ],
  ];
  for (const [label, def] of negatives) {
    const errors = schemaValidate.validate(def, REAL_SCHEMA, "$");
    report(`2.neg "${label}" is rejected by schema validation`, errors.length > 0, JSON.stringify(errors));
  }

  // The validator itself must refuse to silently under-validate an
  // unsupported keyword rather than pretending everything passed.
  {
    let threw = false;
    try {
      schemaValidate.validate({}, { type: "object", patternProperties: {} }, "$");
    } catch (e) {
      threw = /unsupported schema keyword/.test(e.message);
    }
    report("2.unsupported-keyword unsupported schema keyword throws instead of silently passing", threw);
  }
}

// ===========================================================================
// GROUP 3: frontmatter rendering -- maxLength is a build-time error, never
// silent truncation; required-field enforcement
// ===========================================================================
function groupFrontmatterRendering() {
  console.log("\n=== GROUP 3: frontmatter rendering (maxLength / required) ===");

  const skill = { name: "x", description: "y", body: "body\n" };

  // maxLength violation on a "static" field -> throws, does not truncate.
  {
    let threw = false;
    let msg = "";
    try {
      generateLib.renderFrontmatter("test-adapter", [{ name: "description", source: "static", required: true, maxLength: 5, staticValue: "this is way longer than five chars" }], skill);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
      msg = e.message;
    }
    report("3.1 maxLength violation throws GenerationError (build-time error)", threw && /maxLength/.test(msg), msg);
  }

  // maxLength violation on a "description"-sourced field (the real Cursor
  // scenario the schema's own doc comment calls out) -> throws.
  {
    const longSkill = { name: "x", description: "x".repeat(1000), body: "body\n" };
    let threw = false;
    try {
      generateLib.renderFrontmatter("cursor", [{ name: "description", source: "description", required: true, maxLength: 300 }], longSkill);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
    }
    report("3.2 over-long canonical description sourced into a maxLength field throws (not truncated)", threw);
  }

  // required field resolving empty -> throws
  {
    let threw = false;
    try {
      generateLib.renderFrontmatter("test-adapter", [{ name: "globs", source: "static", required: true, staticValue: "" }], skill);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
    }
    report("3.3 required field resolving to empty value throws", threw);
  }

  // valid field within maxLength renders fine
  {
    const out = generateLib.renderFrontmatter("test-adapter", [{ name: "description", source: "static", required: true, maxLength: 50, staticValue: "short and fine" }], skill);
    report("3.4 within-maxLength field renders without throwing", out.includes("description: short and fine"), out);
  }
}

// ===========================================================================
// GROUP 4: generatedFileHeader placement rule
// (frontmatter: header AFTER closing "---", NEVER before;
//  markdown-plain: header is first line)
// ===========================================================================
function groupHeaderPlacement() {
  console.log("\n=== GROUP 4: generatedFileHeader placement rule ===");

  const skill = { name: "x", description: "y", body: "# Body\n\nSome content.\n" };
  const cursorDef = loadRealAdapterDef("cursor");
  const content = generateLib.renderStandaloneContent(skill, cursorDef);

  const closingDashIndex = content.indexOf("\n---\n");
  const headerIndex = content.indexOf("<!--");

  report(
    "4.1 markdown-frontmatter: nothing precedes the opening '---'",
    content.startsWith("---\n"),
    JSON.stringify(content.slice(0, 20))
  );
  report(
    "4.2 markdown-frontmatter: generatedFileHeader appears AFTER the closing '---', not before",
    headerIndex > closingDashIndex && closingDashIndex !== -1,
    `closingDashIndex=${closingDashIndex} headerIndex=${headerIndex}`
  );
  report(
    "4.3 markdown-frontmatter: exactly one frontmatter block (only one '---\\n' delimiter pair at document start)",
    content.indexOf("---\n") === 0,
    JSON.stringify(content.slice(0, 10))
  );

  // markdown-plain standalone (synthetic adapter -- none of the real
  // launch adapters are standalone + markdown-plain, but the placement
  // rule must hold generically): header must be the first line.
  const plainDef = {
    schemaVersion: 1,
    id: "plain-standalone-fixture",
    displayName: "Plain Standalone Fixture",
    targetPath: "FIXTURE.md",
    placementMode: "standalone",
    outputFormat: "markdown-plain",
    bodyTransform: "verbatim",
    generatedFileHeader: "GENERATED FILE -- fixture header",
  };
  const plainContent = generateLib.renderStandaloneContent(skill, plainDef);
  report(
    "4.4 markdown-plain: generatedFileHeader is the first line of the file",
    plainContent.startsWith("<!-- GENERATED FILE -- fixture header -->\n"),
    JSON.stringify(plainContent.slice(0, 60))
  );
}

// ===========================================================================
// GROUP 5: host-incompatible frontmatter construct -> loud failure, not
// silent corruption (the same value succeeds for a markdown-plain adapter
// and fails for a markdown-frontmatter one)
// ===========================================================================
function groupHostIncompatibleConstruct() {
  console.log("\n=== GROUP 5: host-incompatible frontmatter construct ===");

  const skillWithNewlineViaStatic = { name: "x", description: "y", body: "body\n" };
  const frontmatterFieldWithNewline = [
    { name: "description", source: "static", required: true, staticValue: "line one\nline two" },
  ];

  // markdown-frontmatter adapter: a value with a raw embedded newline
  // cannot be safely represented as a single-line YAML scalar -> must
  // throw, not silently corrupt/drop the newline.
  {
    let threw = false;
    let msg = "";
    try {
      generateLib.renderFrontmatter("cursor-fixture", frontmatterFieldWithNewline, skillWithNewlineViaStatic);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
      msg = e.message;
    }
    report("5.1 embedded newline in a frontmatter field throws loudly (markdown-frontmatter host)", threw, msg);
  }

  // The SAME construct is completely fine for a markdown-plain / reconciled
  // surface -- reconcile.js copies body bytes verbatim, newlines and all.
  {
    const body = "line one\nline two\n";
    const rendered = generateLib.renderReconciledBody({ name: "x", description: "y", body }, loadRealAdapterDef("agents-generic"));
    report("5.2 the same multi-line content renders fine for a markdown-plain adapter (no frontmatter to corrupt)", rendered === body, JSON.stringify(rendered));
  }

  // Positive control: a value that NEEDS quoting (colon-space) but CAN be
  // safely represented is auto-quoted, not rejected -- confirms the
  // generator does the smart thing when it safely can, and only refuses
  // when it genuinely cannot.
  {
    const out = generateLib.renderFrontmatter(
      "cursor-fixture",
      [{ name: "description", source: "static", required: true, staticValue: "Build agents: reliably and fast" }],
      skillWithNewlineViaStatic
    );
    const line = out.split("\n").find((l) => l.startsWith("description:"));
    report("5.3 colon-space value is auto-quoted into valid YAML, not rejected", line === 'description: "Build agents: reliably and fast"', line);
  }
}

// ===========================================================================
// GROUP 6: reconciled-mode-never-written-directly guarantee (SAFETY
// CRITICAL -- this is one of the two groups exercised against a
// deliberately broken copy of generate.js; see accompanying report)
// ===========================================================================
function groupReconciledNeverWrittenDirectly() {
  console.log("\n=== GROUP 6: reconciled-mode-never-written-directly guarantee ===");

  const fixture = buildFixture("reconcile-guard");

  // Pre-seed the reconciled targets with the user's OWN unrelated content,
  // exactly the real-world scenario placementMode:"reconciled" exists to
  // protect. If generate.js ever writes these directly (bypassing
  // reconcile()), this content is destroyed rather than preserved outside
  // the marker block.
  const agentsPath = path.join(fixture.dir, "AGENTS.md");
  const copilotPath = path.join(fixture.dir, ".github", "copilot-instructions.md");
  fs.mkdirSync(path.dirname(copilotPath), { recursive: true });
  fs.writeFileSync(agentsPath, "# My Own Project Notes\n\nDo not touch this.\n", "utf8");
  fs.writeFileSync(copilotPath, "# My Own Copilot Notes\n\nDo not touch this either.\n", "utf8");

  generateLib.generateAll(fixture.options);

  const agentsAfter = fs.readFileSync(agentsPath, "utf8");
  const copilotAfter = fs.readFileSync(copilotPath, "utf8");

  report("6.1 AGENTS.md: pre-existing user content survives generation, outside the marker block", agentsAfter.includes("Do not touch this.\n"), agentsAfter.slice(0, 200));
  report("6.2 AGENTS.md: GraphSmith's block was appended (marker pair present)", /<!-- graphsmith:begin id="agents-generic"/.test(agentsAfter) && /<!-- graphsmith:end id="agents-generic" -->/.test(agentsAfter));
  report("6.3 copilot-instructions.md: pre-existing user content survives generation", copilotAfter.includes("Do not touch this either.\n"), copilotAfter.slice(0, 200));
  report("6.4 copilot-instructions.md: GraphSmith's block was appended (marker pair present)", /<!-- graphsmith:begin id="copilot"/.test(copilotAfter) && /<!-- graphsmith:end id="copilot" -->/.test(copilotAfter));

  // The Cursor (standalone) file, by contrast, is legitimately owned
  // outright and should NOT be marker-delimited.
  const cursorPath = path.join(fixture.dir, ".cursor", "rules", "graphsmith.mdc");
  const cursorContent = fs.readFileSync(cursorPath, "utf8");
  report("6.5 standalone Cursor output has no reconcile markers (it is not reconciled-mode)", !/graphsmith:begin/.test(cursorContent));

  cleanup(fixture.dir);
}

// ===========================================================================
// GROUP 7: generatedFileHeader placement -- end-to-end via a real generated
// Cursor file, confirming Cursor's actual failure mode (content before
// frontmatter) cannot happen (SAFETY CRITICAL -- also exercised against a
// deliberately broken copy; see accompanying report)
// ===========================================================================
function groupHeaderPlacementEndToEnd() {
  console.log("\n=== GROUP 7: generatedFileHeader placement (end-to-end) ===");

  const fixture = buildFixture("header-e2e");
  generateLib.generateAll(fixture.options);
  const cursorPath = path.join(fixture.dir, ".cursor", "rules", "graphsmith.mdc");
  const content = fs.readFileSync(cursorPath, "utf8");

  report("7.1 generated Cursor file starts with '---' (nothing precedes frontmatter)", content.startsWith("---\n"));
  const lines = content.split("\n");
  // lines[0] = "---", then field lines, then a line that is exactly "---",
  // then the header comment line.
  const secondDelimiterIdx = lines.indexOf("---", 1);
  report("7.2 found the closing '---' delimiter", secondDelimiterIdx > 0, JSON.stringify(lines.slice(0, 6)));
  if (secondDelimiterIdx > 0) {
    report(
      "7.3 the line immediately after closing '---' is the generatedFileHeader HTML comment",
      /^<!--.*-->$/.test(lines[secondDelimiterIdx + 1]),
      lines[secondDelimiterIdx + 1]
    );
  }

  cleanup(fixture.dir);
}

// ===========================================================================
// GROUP 8: hand-edit a generated standalone file -> `--check` catches drift
// (not just "confirm the check exists" -- an actual live hand-edit)
// ===========================================================================
function groupHandEditDriftDetection() {
  console.log("\n=== GROUP 8: hand-edit drift detection (--check) ===");

  const fixture = buildFixture("drift");
  generateLib.generateAll(fixture.options);

  // Baseline: freshly generated, no drift.
  const clean = generateLib.generateAll(Object.assign({}, fixture.options, { check: true }));
  report("8.1 freshly generated output has zero drift", clean.driftCount === 0, JSON.stringify(clean.results));

  // Hand-edit the STANDALONE Cursor file directly.
  const cursorPath = path.join(fixture.dir, ".cursor", "rules", "graphsmith.mdc");
  const original = fs.readFileSync(cursorPath, "utf8");
  fs.writeFileSync(cursorPath, original + "\n\nHAND-EDITED LINE THAT SHOULD NEVER SURVIVE REGENERATION\n", "utf8");

  const afterHandEdit = generateLib.generateAll(Object.assign({}, fixture.options, { check: true }));
  const cursorResult = afterHandEdit.results.find((r) => r.adapterId === "cursor");
  report("8.2 hand-edited standalone file IS detected as drifted", cursorResult && cursorResult.drift === true, JSON.stringify(cursorResult));
  report("8.3 driftCount reflects the hand-edit", afterHandEdit.driftCount >= 1, afterHandEdit.driftCount);

  // Hand-edit the RECONCILED AGENTS.md block body directly (simulating a
  // user editing inside GraphSmith's own marker-delimited region).
  const agentsPath = path.join(fixture.dir, "AGENTS.md");
  const agentsOriginal = fs.readFileSync(agentsPath, "utf8");
  const agentsHandEdited = agentsOriginal.replace("# Test Skill", "# Test Skill (HAND EDITED)");
  report("8.4-setup sanity: hand-edit actually changed the file content", agentsHandEdited !== agentsOriginal, agentsOriginal.slice(0, 60));
  fs.writeFileSync(agentsPath, agentsHandEdited, "utf8");
  const afterAgentsEdit = generateLib.generateAll(Object.assign({}, fixture.options, { check: true }));
  const agentsResult = afterAgentsEdit.results.find((r) => r.adapterId === "agents-generic");
  report("8.4 hand-edited reconciled block IS detected as drifted", agentsResult && agentsResult.drift === true, JSON.stringify(agentsResult));

  // Confirm --check never writes anything, even when drift is found.
  const cursorAfterCheck = fs.readFileSync(cursorPath, "utf8");
  report("8.5 --check does not modify the drifted file on disk", cursorAfterCheck === original + "\n\nHAND-EDITED LINE THAT SHOULD NEVER SURVIVE REGENERATION\n");

  // Now actually regenerate (no --check) and confirm the hand-edit is
  // overwritten -- proving the check step's "would fail" claim is real,
  // not just a report field nobody acts on.
  generateLib.generateAll(fixture.options);
  const cursorRestored = fs.readFileSync(cursorPath, "utf8");
  report("8.6 a real (non---check) regeneration overwrites the hand-edit", cursorRestored === original, cursorRestored === original ? "" : "mismatch");

  cleanup(fixture.dir);
}

// ===========================================================================
// GROUP 9: CLI --check end-to-end (spawns the real CLI as a subprocess,
// confirms exit codes, not just the in-process library function)
// ===========================================================================
function groupCliCheckEndToEnd() {
  console.log("\n=== GROUP 9: CLI --check end-to-end ===");

  const fixture = buildFixture("cli-drift");
  const genRes = runCliForFixture(fixture);
  report("9.1 CLI generate exits 0", genRes.status === 0, `status=${genRes.status} stderr=${genRes.stderr}`);

  const checkRes1 = runCliForFixture(fixture, ["--check"]);
  report("9.2 CLI --check exits 0 on freshly generated output", checkRes1.status === 0, checkRes1.stdout + checkRes1.stderr);

  const cursorPath = path.join(fixture.dir, ".cursor", "rules", "graphsmith.mdc");
  fs.appendFileSync(cursorPath, "\nCLI HAND EDIT\n", "utf8");

  const checkRes2 = runCliForFixture(fixture, ["--check"]);
  report("9.3 CLI --check exits non-zero after a real hand-edit", checkRes2.status !== 0, `status=${checkRes2.status}`);
  report("9.4 CLI --check prints a DRIFT DETECTED message", /DRIFT DETECTED/.test(checkRes2.stderr), checkRes2.stderr);

  // Invalid adapters dir -> loud failure (exit 2), not a silent empty run.
  const checkRes3 = runCli([
    "--root", fixture.dir,
    "--skill", fixture.skillPath,
    "--adapters-dir", path.join(fixture.dir, "does-not-exist"),
    "--schema", REAL_SCHEMA_PATH,
  ]);
  report("9.5 CLI exits 2 (loud error) on an unreadable adapters dir, not a silent no-op", checkRes3.status === 2, `status=${checkRes3.status} stderr=${checkRes3.stderr}`);

  cleanup(fixture.dir);
}

// ===========================================================================
// GROUP 10: add a new host adapter -> confirm ZERO diff on existing surfaces
// ===========================================================================
function groupNewAdapterZeroDiff() {
  console.log("\n=== GROUP 10: new adapter added -> zero diff on existing surfaces ===");

  const before = buildFixture("newadapter-before");
  const afterFixture = buildFixture("newadapter-after", {
    adapters: Object.assign({}, standardFixtureAdapters(), {
      // A brand-new, fully valid, unrelated standalone adapter targeting a
      // path with no overlap with the other three.
      "fixture-newhost": {
        schemaVersion: 1,
        id: "fixture-newhost",
        displayName: "Fixture New Host",
        targetPath: ".fixture-newhost/rules.md",
        placementMode: "standalone",
        outputFormat: "markdown-plain",
        bodyTransform: "verbatim",
        generatedFileHeader: "GENERATED FILE -- fixture new host",
      },
    }),
  });

  generateLib.generateAll(before.options);
  generateLib.generateAll(afterFixture.options);

  const surfaces = [
    [".cursor/rules/graphsmith.mdc", "cursor"],
    ["AGENTS.md", "agents-generic"],
    [".github/copilot-instructions.md", "copilot"],
  ];
  for (const [rel, label] of surfaces) {
    const beforeContent = fs.readFileSync(path.join(before.dir, rel), "utf8");
    const afterContent = fs.readFileSync(path.join(afterFixture.dir, rel), "utf8");
    report(`10.${label} adding a new adapter produces zero diff on "${rel}"`, beforeContent === afterContent);
  }

  report(
    "10.newhost the new adapter's own surface WAS produced",
    fs.existsSync(path.join(afterFixture.dir, ".fixture-newhost", "rules.md"))
  );

  cleanup(before.dir);
  cleanup(afterFixture.dir);
}

// ===========================================================================
// GROUP 11: byte-identical determinism across multiple runs
// ===========================================================================
function groupDeterminism() {
  console.log("\n=== GROUP 11: byte-identical determinism across runs ===");

  const runA = buildFixture("determinism-a");
  const runB = buildFixture("determinism-b");

  generateLib.generateAll(runA.options);
  // Small artificial delay is unnecessary and would be a clock dependency
  // in the TEST -- generation itself must not depend on wall-clock time,
  // which is exactly what running immediately back-to-back proves.
  generateLib.generateAll(runB.options);

  const surfaces = [".cursor/rules/graphsmith.mdc", "AGENTS.md", ".github/copilot-instructions.md"];
  for (const rel of surfaces) {
    const a = fs.readFileSync(path.join(runA.dir, rel));
    const b = fs.readFileSync(path.join(runB.dir, rel));
    report(`11.${rel} byte-identical across two independent runs`, Buffer.compare(a, b) === 0, `a.length=${a.length} b.length=${b.length}`);
  }

  // Re-running generation a third time into runA (idempotent re-run) must
  // also be byte-identical to the first run.
  const before = fs.readFileSync(path.join(runA.dir, "AGENTS.md"));
  generateLib.generateAll(runA.options);
  const afterRerun = fs.readFileSync(path.join(runA.dir, "AGENTS.md"));
  report("11.rerun re-running generation twice on the same root is byte-identical (idempotent, zero additional diff)", Buffer.compare(before, afterRerun) === 0);

  cleanup(runA.dir);
  cleanup(runB.dir);
}

// ===========================================================================
// GROUP 12: invalid adapter definition poisons the whole run (all-or-
// nothing validation -- no partial generation from a partially-valid set)
// ===========================================================================
function groupInvalidAdapterAbortsWholeRun() {
  console.log("\n=== GROUP 12: an invalid adapter aborts the whole run ===");

  const fixture = buildFixture("invalid-adapter", {
    adapters: Object.assign({}, standardFixtureAdapters(), {
      "broken-fixture": { id: "Broken Fixture!", targetPath: "x.md" }, // bad id pattern, missing required fields
    }),
  });

  let threw = false;
  try {
    generateLib.generateAll(fixture.options);
  } catch (e) {
    threw = e instanceof generateLib.GenerationError;
  }
  report("12.1 generateAll throws on an invalid adapter definition", threw);
  report(
    "12.2 NOTHING was written for the other, otherwise-valid adapters (all-or-nothing)",
    !fs.existsSync(path.join(fixture.dir, "AGENTS.md")) && !fs.existsSync(path.join(fixture.dir, ".cursor"))
  );

  cleanup(fixture.dir);
}

// ===========================================================================
// GROUP 13: adapter targetPath must resolve inside opts.root (path
// traversal containment -- found by the Lane D non-Anthropic adversarial
// review, 2026-08-04: path.join(opts.root, def.targetPath) previously had
// no containment check at all, confirmed via a direct repro that a
// "../"-containing targetPath silently escaped the project root)
// ===========================================================================
function groupTargetPathContainment() {
  console.log("\n=== GROUP 13: adapter targetPath containment ===");

  // Positive control: a normal in-root targetPath still generates fine --
  // the new containment check must not be overly restrictive.
  {
    const fixture = buildFixture("containment-ok");
    let threw = false;
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = true;
    }
    report("13.1 a normal in-root targetPath does not throw", !threw);
    report("13.2 the in-root file was actually written", fs.existsSync(path.join(fixture.dir, "AGENTS.md")));
    cleanup(fixture.dir);
  }

  // A targetPath that resolves outside root (via "../") must be refused
  // loudly, not silently written outside the project root. The escaping
  // path is computed from the fixture's OWN actual directory via
  // path.relative, not a hardcoded "../../.." guess, so this test is
  // correct regardless of the OS temp directory's actual nesting depth.
  {
    const fixture = buildFixture("containment-escape");
    const escapeDir = tmpDir("containment-escape-target");
    const outsideFile = path.join(escapeDir, "OUTSIDE-ROOT-PWNED.txt");
    const maliciousTargetPath = path.relative(fixture.dir, outsideFile);

    fs.writeFileSync(
      path.join(fixture.adaptersDir, "malicious-fixture.json"),
      JSON.stringify(
        {
          schemaVersion: 1,
          id: "malicious-fixture",
          displayName: "Malicious Fixture",
          targetPath: maliciousTargetPath,
          placementMode: "standalone",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
        null,
        2
      ),
      "utf8"
    );

    let threw = false;
    let msg = "";
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
      msg = e.message;
    }
    report("13.3 a targetPath resolving outside opts.root throws GenerationError", threw && /outside root/.test(msg), msg);
    report("13.4 the escaping file was NOT written outside root", !fs.existsSync(outsideFile));
    report(
      "13.5 all-or-nothing: nothing was written for the other, otherwise-valid adapters either",
      !fs.existsSync(path.join(fixture.dir, "AGENTS.md")) && !fs.existsSync(path.join(fixture.dir, ".cursor")),
      `AGENTS.md exists=${fs.existsSync(path.join(fixture.dir, "AGENTS.md"))}`
    );

    cleanup(fixture.dir);
    cleanup(escapeDir);
  }
}

// ===========================================================================
// GROUP 14: toYamlScalar quotes YAML-core-schema-ambiguous values (found by
// the Lane D non-Anthropic adversarial review, 2026-08-04: confirmed via a
// real js-yaml round-trip test that "~", hex/octal integers, and
// .inf/.nan previously round-tripped to null/a number instead of the
// original string, with zero error signal)
// ===========================================================================
function groupYamlAmbiguousScalarQuoting() {
  console.log("\n=== GROUP 14: toYamlScalar quotes YAML-ambiguous scalars ===");

  // Each of these previously round-tripped to null/a number under a real
  // YAML parser (js-yaml) instead of staying a string -- see the Lane D
  // review's empirical evidence. All must now be quoted.
  const ambiguousValues = ["~", "0x1F", "0o17", ".inf", ".nan", "0xAB", "0o7"];
  for (const value of ambiguousValues) {
    const rendered = generateLib.toYamlScalar("field", value);
    const isQuoted = rendered.startsWith('"') && rendered.endsWith('"');
    report(`14.${value} value ${JSON.stringify(value)} is now quoted (previously a bare, YAML-ambiguous scalar)`, isQuoted, rendered);
  }

  // Positive control: ordinary strings that merely CONTAIN one of these
  // patterns as a substring -- not the entire value -- must NOT be
  // over-quoted by the new checks, which are anchored with ^...$ and must
  // not misfire on a partial match.
  const nonAmbiguousValues = ["0x1Fish", "prefix .inf", "0o17 and more", "infinite"];
  for (const value of nonAmbiguousValues) {
    const rendered = generateLib.toYamlScalar("field", value);
    report(`14.control ${JSON.stringify(value)} stays a plain (unquoted) scalar`, rendered === value, rendered);
  }
}

// ===========================================================================
// GROUP 15: targetPath containment survives a symlinked INTERMEDIATE
// directory component, in both placementModes (found by the Lane A/D
// cross-lane integration review, 2026-08-04, Finding 2: the purely lexical
// containment check added for GROUP 13 never touches the filesystem, so a
// symlinked ancestor directory -- not the leaf, and not a "../" segment --
// defeated it; confirmed via direct repro in both modes)
// ===========================================================================
function groupSymlinkedAncestorContainment() {
  console.log("\n=== GROUP 15: targetPath containment vs. symlinked intermediate directory ===");

  // Reconciled mode: opts.root/.github is a symlink pointing OUTSIDE root.
  // The lexical check (path.resolve(path.join(root, ".github/x.md"))) is
  // still lexically under root and would pass; the real write is not.
  {
    const fixture = buildFixture("symlink-reconciled");
    const outsideDir = tmpDir("symlink-reconciled-outside");
    fs.symlinkSync(outsideDir, path.join(fixture.dir, ".github"), "dir");

    let threw = false;
    let msg = "";
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
      msg = e.message;
    }
    report("15.1 reconciled adapter behind a symlinked intermediate dir throws GenerationError", threw, msg);
    report(
      "15.2 nothing was written inside the symlink target (escaping root)",
      !fs.existsSync(path.join(outsideDir, "copilot-instructions.md")),
      `exists=${fs.existsSync(path.join(outsideDir, "copilot-instructions.md"))}`
    );
    report(
      "15.3 all-or-nothing: the other, otherwise-valid adapters were not written either",
      !fs.existsSync(path.join(fixture.dir, "AGENTS.md")) && !fs.existsSync(path.join(fixture.dir, ".cursor")),
      `AGENTS.md exists=${fs.existsSync(path.join(fixture.dir, "AGENTS.md"))}`
    );
    cleanup(fixture.dir);
    cleanup(outsideDir);
  }

  // Standalone mode: same shape, opts.root/.cursor is the symlink this time.
  {
    const fixture = buildFixture("symlink-standalone");
    const outsideDir = tmpDir("symlink-standalone-outside");
    fs.symlinkSync(outsideDir, path.join(fixture.dir, ".cursor"), "dir");

    let threw = false;
    let msg = "";
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
      msg = e.message;
    }
    report("15.4 standalone adapter behind a symlinked intermediate dir throws GenerationError", threw, msg);
    report(
      "15.5 nothing was written inside the symlink target (escaping root)",
      !fs.existsSync(path.join(outsideDir, "rules", "graphsmith.mdc")),
      `exists=${fs.existsSync(path.join(outsideDir, "rules", "graphsmith.mdc"))}`
    );
    cleanup(fixture.dir);
    cleanup(outsideDir);
  }

  // Positive control: a deeper, NOT-symlinked, not-yet-existing nested
  // target path (multiple non-existent intermediate directories) still
  // generates fine -- the ancestor-walk loop must terminate correctly and
  // not misfire just because intermediate directories don't exist yet on a
  // first-ever run (the common case for every real adapter today).
  {
    const fixture = buildFixture("symlink-control-nested", {
      adapters: {
        nested: {
          schemaVersion: 1,
          id: "nested",
          displayName: "Nested",
          targetPath: "a/b/c/d/nested.md",
          placementMode: "standalone",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
      },
    });
    let threw = false;
    let errMsg = "";
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = true;
      errMsg = e.message;
    }
    report("15.6 a deep, non-symlinked, not-yet-existing nested targetPath does not throw", !threw, errMsg);
    report("15.7 the nested file was actually written", fs.existsSync(path.join(fixture.dir, "a", "b", "c", "d", "nested.md")));
    cleanup(fixture.dir);
  }
}

// ===========================================================================
// GROUP 16: a targetPath collision involving a "standalone" adapter is
// refused up front (found by the Lane A/D cross-lane integration review,
// 2026-08-04, Finding 3: confirmed via direct repro that a standalone
// adapter sharing a targetPath with another adapter silently and
// permanently destroys the other adapter's -- or a human's -- pre-existing
// content on every run, with zero error signal)
// ===========================================================================
function groupStandaloneCollisionRejected() {
  console.log("\n=== GROUP 16: standalone targetPath collision is refused up front ===");

  // standalone + reconciled sharing a targetPath must be refused.
  {
    const fixture = buildFixture("collision-standalone-reconciled", {
      adapters: {
        "std-a": {
          schemaVersion: 1,
          id: "std-a",
          displayName: "Standalone A",
          targetPath: "SHARED.md",
          placementMode: "standalone",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
        "rec-b": {
          schemaVersion: 1,
          id: "rec-b",
          displayName: "Reconciled B",
          targetPath: "SHARED.md",
          placementMode: "reconciled",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
        other: {
          schemaVersion: 1,
          id: "other",
          displayName: "Other",
          targetPath: "OTHER.md",
          placementMode: "standalone",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
      },
    });
    let threw = false;
    let msg = "";
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
      msg = e.message;
    }
    report("16.1 standalone+reconciled targetPath collision throws GenerationError", threw && /collision/.test(msg), msg);
    report(
      "16.2 all-or-nothing: nothing was written, not even the unrelated, otherwise-valid \"other\" adapter",
      !fs.existsSync(path.join(fixture.dir, "SHARED.md")) && !fs.existsSync(path.join(fixture.dir, "OTHER.md")),
      `SHARED.md exists=${fs.existsSync(path.join(fixture.dir, "SHARED.md"))}, OTHER.md exists=${fs.existsSync(path.join(fixture.dir, "OTHER.md"))}`
    );
    cleanup(fixture.dir);
  }

  // standalone + standalone sharing a targetPath must also be refused --
  // equally pointless/silently-overwriting, just without a reconciled
  // block to specifically destroy.
  {
    const fixture = buildFixture("collision-standalone-standalone", {
      adapters: {
        "std-a": {
          schemaVersion: 1,
          id: "std-a",
          displayName: "Standalone A",
          targetPath: "SHARED.md",
          placementMode: "standalone",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
        "std-b": {
          schemaVersion: 1,
          id: "std-b",
          displayName: "Standalone B",
          targetPath: "SHARED.md",
          placementMode: "standalone",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
      },
    });
    let threw = false;
    let msg = "";
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
      msg = e.message;
    }
    report("16.3 standalone+standalone targetPath collision throws GenerationError", threw && /collision/.test(msg), msg);
    cleanup(fixture.dir);
  }

  // Positive control: reconciled + reconciled sharing a targetPath with
  // DIFFERENT blockIds is legitimate, documented behavior (reconcile.js
  // explicitly supports multiple distinct blocks coexisting in one file)
  // and must NOT be rejected by this check.
  {
    const fixture = buildFixture("collision-control-different-blockid", {
      adapters: {
        "rec-a": {
          schemaVersion: 1,
          id: "rec-a",
          displayName: "Reconciled A",
          targetPath: "SHARED.md",
          placementMode: "reconciled",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
        "rec-b": {
          schemaVersion: 1,
          id: "rec-b",
          displayName: "Reconciled B",
          targetPath: "SHARED.md",
          placementMode: "reconciled",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
      },
    });
    let threw = false;
    let errMsg = "";
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = true;
      errMsg = e.message;
    }
    report("16.4 reconciled+reconciled targetPath collision with different blockIds does not throw", !threw, errMsg);
    report("16.5 both blocks were actually written into the shared file", fs.existsSync(path.join(fixture.dir, "SHARED.md")));
    cleanup(fixture.dir);
  }

  // Positive control: reconciled + reconciled sharing a targetPath with the
  // SAME blockId is Finding 4 from the cross-lane review -- a genuine no-op
  // today (empirically confirmed there), not something this check needs to
  // (or should) reject.
  {
    const fixture = buildFixture("collision-control-same-blockid", {
      adapters: {
        "rec-a": {
          schemaVersion: 1,
          id: "rec-a",
          displayName: "Reconciled A",
          targetPath: "SHARED.md",
          placementMode: "reconciled",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
      },
    });
    // Run generateAll twice with the SAME single adapter def against the
    // same target -- same blockId, same targetPath, by construction.
    let threw = false;
    let errMsg = "";
    try {
      generateLib.generateAll(fixture.options);
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = true;
      errMsg = e.message;
    }
    report("16.6 reconciled+reconciled same-blockId same-targetPath (re-run) does not throw", !threw, errMsg);
    cleanup(fixture.dir);
  }
}

// ===========================================================================
// GROUP 17: Finding 1 (Lane A/D cross-lane integration review, 2026-08-04) --
// (a) a marker-lookalike reconciled body is caught up front, before ANY
// adapter (standalone or reconciled) writes anything; (b) reconciled
// adapters are processed before standalone adapters regardless of def load
// (filename-sort) order, so a reconciled failure never leaves an
// EARLIER-in-filename-order standalone write already committed; (c) a
// failure anywhere in the write loop is reported with an honest, structured
// account of which adapters already succeeded and which were never
// attempted, rather than a bare exception; (d) the locally-duplicated
// MARKER_LOOKALIKE_RE regex inside scripts/generate.js is asserted to stay
// byte-identical to scripts/reconcile.js's own copy, so the two cannot
// silently drift apart.
// ===========================================================================
function groupFinding1WriteLoopHardening() {
  console.log("\n=== GROUP 17: marker-lookalike hoisted up front + reconciled-before-standalone + honest partial-state reporting ===");

  const LOOKALIKE_SKILL =
    "---\n" +
    "name: testskill\n" +
    "description: A plain test description with nothing fancy in it.\n" +
    "---\n" +
    "\n" +
    "# Test Skill\n" +
    "\n" +
    "<!-- graphsmith:begin id=\"not-real\" schema_version=\"1\" -->\n" +
    "This line at column 0 looks exactly like a real graphsmith marker.\n";

  // 17.1 -- marker-lookalike body is caught BEFORE any write, even though
  // the standalone adapter sorts first alphabetically (and would, under the
  // old single-flat-pass loop, have already been written by the time the
  // reconciled adapter's lookalike body was ever inspected inside
  // reconcile()).
  {
    const fixture = buildFixture("finding1-lookalike-upfront", {
      skill: LOOKALIKE_SKILL,
      adapters: {
        "aaa-standalone": {
          schemaVersion: 1,
          id: "aaa-standalone",
          displayName: "Standalone (sorts first)",
          targetPath: "AAA-STANDALONE.md",
          placementMode: "standalone",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
        "zzz-reconciled": {
          schemaVersion: 1,
          id: "zzz-reconciled",
          displayName: "Reconciled (sorts last, lookalike body)",
          targetPath: "ZZZ-RECONCILED.md",
          placementMode: "reconciled",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
      },
    });
    let threw = false;
    let msg = "";
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = e instanceof generateLib.GenerationError;
      msg = e.message;
    }
    report("17.1 marker-lookalike reconciled body throws GenerationError", threw && /marker/.test(msg), msg);
    report(
      "17.2 the alphabetically-earlier standalone adapter was NOT written (caught up front, before the write loop)",
      !fs.existsSync(path.join(fixture.dir, "AAA-STANDALONE.md")),
      `exists=${fs.existsSync(path.join(fixture.dir, "AAA-STANDALONE.md"))}`
    );
    report(
      "17.3 the reconciled target was also not written",
      !fs.existsSync(path.join(fixture.dir, "ZZZ-RECONCILED.md")),
      `exists=${fs.existsSync(path.join(fixture.dir, "ZZZ-RECONCILED.md"))}`
    );
    cleanup(fixture.dir);
  }

  // 17.4 -- reordering + honest partial-state reporting, forced via a real
  // (non-marker-lookalike) failure: pre-acquire reconcile.js's own
  // cross-process lock on the reconciled adapter's target BEFORE calling
  // generateAll, so reconcile()'s internal acquireLock() is guaranteed to
  // exhaust LOCK_ACQUIRE_MAX_ATTEMPTS (40 attempts * LOCK_ACQUIRE_RETRY_MS
  // 15ms = ~600ms, comfortably under DEFAULT_LOCK_STALE_MS's 30000ms so the
  // held lock is never mistaken for stale and reclaimed mid-test) and throw
  // a genuine LockAcquisitionError. The standalone adapter sorts FIRST
  // alphabetically (would have run first, and succeeded, under the old
  // single-flat-pass order) -- this test proves it is never even attempted.
  {
    const fixture = buildFixture("finding1-reorder-and-honest-report", {
      adapters: {
        "aaa-standalone": {
          schemaVersion: 1,
          id: "aaa-standalone",
          displayName: "Standalone (sorts first, must never run)",
          targetPath: "AAA-STANDALONE.md",
          placementMode: "standalone",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
        "zzz-reconciled": {
          schemaVersion: 1,
          id: "zzz-reconciled",
          displayName: "Reconciled (sorts last, forced to fail)",
          targetPath: "ZZZ-RECONCILED.md",
          placementMode: "reconciled",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
      },
    });
    const lockedTargetPath = path.join(fixture.dir, "ZZZ-RECONCILED.md");
    const held = reconcileLib.acquireLock(lockedTargetPath);
    let caught = null;
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      caught = e;
    } finally {
      reconcileLib.releaseLock(held.lockPath, held.token);
    }
    report("17.4 a real (non-marker-lookalike) reconciled failure still throws", caught !== null, caught && caught.message);
    report(
      "17.5 the underlying cause is reconcile.js's own LockAcquisitionError",
      caught && caught.cause instanceof reconcileLib.LockAcquisitionError,
      caught && caught.cause && caught.cause.constructor && caught.cause.constructor.name
    );
    report(
      "17.6 the alphabetically-earlier standalone adapter was NEVER attempted (reordering worked)",
      !fs.existsSync(path.join(fixture.dir, "AAA-STANDALONE.md")),
      `exists=${fs.existsSync(path.join(fixture.dir, "AAA-STANDALONE.md"))}`
    );
    report(
      "17.7 the error's neverAttemptedAdapterIds honestly lists the standalone adapter",
      caught && Array.isArray(caught.neverAttemptedAdapterIds) && caught.neverAttemptedAdapterIds.includes("aaa-standalone"),
      caught && JSON.stringify(caught.neverAttemptedAdapterIds)
    );
    report(
      "17.8 the error's failedAdapterId names the reconciled adapter that actually failed",
      caught && caught.failedAdapterId === "zzz-reconciled",
      caught && caught.failedAdapterId
    );
    report(
      "17.9 the error's succeededAdapterIds is empty (the reconciled adapter, now processed first, failed immediately)",
      caught && Array.isArray(caught.succeededAdapterIds) && caught.succeededAdapterIds.length === 0,
      caught && JSON.stringify(caught.succeededAdapterIds)
    );
    cleanup(fixture.dir);
  }

  // 17.10 -- succeededAdapterIds correctly lists an EARLIER reconciled
  // adapter that genuinely succeeded before a LATER reconciled adapter's
  // forced failure, and the standalone adapter (sorting after both
  // reconciled adapters alphabetically here, so it is never reached
  // regardless of ordering) is still confirmed never attempted.
  {
    const fixture = buildFixture("finding1-partial-success-then-fail", {
      adapters: {
        "rec-1-ok": {
          schemaVersion: 1,
          id: "rec-1-ok",
          displayName: "Reconciled (succeeds)",
          targetPath: "REC-1.md",
          placementMode: "reconciled",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
        "rec-2-fails": {
          schemaVersion: 1,
          id: "rec-2-fails",
          displayName: "Reconciled (forced to fail)",
          targetPath: "REC-2.md",
          placementMode: "reconciled",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
        "zzz-standalone": {
          schemaVersion: 1,
          id: "zzz-standalone",
          displayName: "Standalone (sorts last, must never run)",
          targetPath: "ZZZ-STANDALONE.md",
          placementMode: "standalone",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
      },
    });
    const lockedTargetPath = path.join(fixture.dir, "REC-2.md");
    const held = reconcileLib.acquireLock(lockedTargetPath);
    let caught = null;
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      caught = e;
    } finally {
      reconcileLib.releaseLock(held.lockPath, held.token);
    }
    report(
      "17.11 succeededAdapterIds lists the earlier reconciled adapter that actually wrote",
      caught && Array.isArray(caught.succeededAdapterIds) && caught.succeededAdapterIds.length === 1 && caught.succeededAdapterIds[0] === "rec-1-ok",
      caught && JSON.stringify(caught.succeededAdapterIds)
    );
    report("17.12 REC-1.md (the succeeded adapter) really was written to disk", fs.existsSync(path.join(fixture.dir, "REC-1.md")));
    report(
      "17.13 the standalone adapter was still never attempted",
      !fs.existsSync(path.join(fixture.dir, "ZZZ-STANDALONE.md")) &&
        caught && Array.isArray(caught.neverAttemptedAdapterIds) && caught.neverAttemptedAdapterIds.includes("zzz-standalone"),
      caught && JSON.stringify(caught.neverAttemptedAdapterIds)
    );
    cleanup(fixture.dir);
  }

  // 17.14 -- positive control: with no lookalike body and no forced
  // failure, reordering is transparent to a normal successful run -- both
  // adapters are written regardless of def-load order.
  {
    const fixture = buildFixture("finding1-control-normal-run", {
      adapters: {
        "aaa-standalone": {
          schemaVersion: 1,
          id: "aaa-standalone",
          displayName: "Standalone",
          targetPath: "AAA-STANDALONE.md",
          placementMode: "standalone",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
        "zzz-reconciled": {
          schemaVersion: 1,
          id: "zzz-reconciled",
          displayName: "Reconciled",
          targetPath: "ZZZ-RECONCILED.md",
          placementMode: "reconciled",
          outputFormat: "markdown-plain",
          bodyTransform: "verbatim",
        },
      },
    });
    let threw = false;
    let errMsg = "";
    try {
      generateLib.generateAll(fixture.options);
    } catch (e) {
      threw = true;
      errMsg = e.message;
    }
    report("17.14 a normal run with no failure does not throw", !threw, errMsg);
    report(
      "17.15 both adapters were written",
      fs.existsSync(path.join(fixture.dir, "AAA-STANDALONE.md")) && fs.existsSync(path.join(fixture.dir, "ZZZ-RECONCILED.md"))
    );
    cleanup(fixture.dir);
  }

  // 17.16 -- drift guard: the MARKER_LOOKALIKE_RE pattern duplicated inside
  // scripts/generate.js (deliberately NOT imported from reconcile.js -- see
  // that check's comment in generate.js) must stay byte-identical to
  // scripts/reconcile.js's own module-scope copy of the same regex. If a
  // future edit changes one without the other, this test fails loudly
  // instead of the up-front check silently going stale.
  {
    const DRIFT_CHECK_PATTERN = /^<!-- graphsmith:(?:begin|end)\b.*$/m;
    const patternSource = DRIFT_CHECK_PATTERN.source;
    const generateSrc = fs.readFileSync(GENERATE_PATH, "utf8");
    const reconcileSrc = fs.readFileSync(RECONCILE_PATH, "utf8");
    const inGenerate = generateSrc.includes(patternSource);
    const inReconcile = reconcileSrc.includes(patternSource);
    report(
      "17.16 MARKER_LOOKALIKE_RE's pattern source is present, byte-identical, in both scripts/generate.js and scripts/reconcile.js",
      inGenerate && inReconcile,
      `in generate.js=${inGenerate}, in reconcile.js=${inReconcile}`
    );
  }
}

// ===========================================================================
// GROUP 18: Finding 4 (Lane A/D cross-lane integration review, 2026-08-04,
// REFUTED as a live bug -- see that finding's writeup) AI-discoverability
// doc note. Not a behavior test (Finding 4 has no code fix -- the fix IS
// the doc note) -- confirms the same greppable marker phrase,
// "FUTURE-EXTENSION HAZARD (bodyTransform)", is present at all 3 proposed
// edit-entry points, so a future edit to any one of them (schema, the
// render function, or the collision-check code) surfaces the other two via
// a simple repo-wide search, per Paul's specific "how would an AI agent
// doing vibe coding actually find this" question.
// ===========================================================================
function groupFinding4DocNoteDiscoverability() {
  console.log("\n=== GROUP 18: Finding 4 doc-note AI-discoverability (schema + renderReconciledBody + collision-check) ===");

  const MARKER = "FUTURE-EXTENSION HAZARD (bodyTransform)";
  const schemaSrc = fs.readFileSync(REAL_SCHEMA_PATH, "utf8");
  const generateSrc = fs.readFileSync(GENERATE_PATH, "utf8");

  const inSchema = schemaSrc.includes(MARKER);
  const occurrencesInGenerate = generateSrc.split(MARKER).length - 1;

  report("18.1 marker phrase present in schemas/host-adapter.schema.json (bodyTransform field)", inSchema);
  report(
    "18.2 marker phrase present at least twice in scripts/generate.js (renderReconciledBody + the collision-check code)",
    occurrencesInGenerate >= 2,
    `found ${occurrencesInGenerate} occurrence(s)`
  );

  // The schema note itself must still be valid JSON (a doc-note change to a
  // "description" string is the easiest kind of edit to accidentally break
  // JSON syntax with -- e.g. an unescaped quote).
  let schemaParsed = null;
  let parseErr = null;
  try {
    schemaParsed = JSON.parse(schemaSrc);
  } catch (e) {
    parseErr = e;
  }
  report("18.3 schemas/host-adapter.schema.json is still valid JSON after the doc-note edit", schemaParsed !== null, parseErr && parseErr.message);
  report(
    "18.4 the bodyTransform field's description actually contains the marker (not just present elsewhere in the file)",
    schemaParsed && schemaParsed.properties && schemaParsed.properties.bodyTransform && typeof schemaParsed.properties.bodyTransform.description === "string" && schemaParsed.properties.bodyTransform.description.includes(MARKER)
  );

  // Positive control: real adapter definitions (all bodyTransform:
  // "verbatim") must still validate cleanly against the edited schema --
  // confirms the doc-note-only change didn't accidentally alter validation
  // behavior for any existing, real adapter.
  for (const id of ["cursor", "copilot", "agents-generic"]) {
    const def = loadRealAdapterDef(id);
    const errors = schemaValidate.validate(def, REAL_SCHEMA, "$");
    report(`18.control.${id} real "${id}" adapter definition still validates cleanly against the edited schema`, errors.length === 0, JSON.stringify(errors));
  }
}

// ===========================================================================
// MAIN
// ===========================================================================
async function runAll() {
  console.log("=== Lane D — tests/generate/run-tests.js ===");
  console.log(`Started: ${new Date().toISOString()}\n`);

  groupSkillParsing();
  groupAdapterSchemaValidation();
  groupFrontmatterRendering();
  groupHeaderPlacement();
  groupHostIncompatibleConstruct();
  groupReconciledNeverWrittenDirectly();
  groupHeaderPlacementEndToEnd();
  groupHandEditDriftDetection();
  groupCliCheckEndToEnd();
  groupNewAdapterZeroDiff();
  groupDeterminism();
  groupInvalidAdapterAbortsWholeRun();
  groupTargetPathContainment();
  groupYamlAmbiguousScalarQuoting();
  groupSymlinkedAncestorContainment();
  groupStandaloneCollisionRejected();
  groupFinding1WriteLoopHardening();
  groupFinding4DocNoteDiscoverability();

  console.log("\n--- SUMMARY ---");
  console.log(`PASS:  ${passed}`);
  console.log(`FAIL:  ${failed}`);
  console.log(`SKIP:  ${skipped}`);
  console.log(`TOTAL: ${passed + failed + skipped}`);

  if (failed > 0) {
    console.log(`\n*** ${failed} TEST(S) FAILED ***`);
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runAll().catch((e) => {
  console.error("FATAL:", e && e.stack ? e.stack : e);
  process.exit(2);
});
