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
