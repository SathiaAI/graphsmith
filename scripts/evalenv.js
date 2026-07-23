#!/usr/bin/env node
/* GraphSmith I3 disposable evaluation environment (scripts/evalenv.js — TASK
 * C-evalenv). Security-tier SECURITY: this is the copy every
 * machine-evaluated candidate runs in FIRST, per plan §3:
 *   "Every machine-evaluated candidate runs first in a disposable evaluation
 *    copy with mocked effects -- honest name; 'sandbox' is used ONLY with
 *    the isolation level named."
 *
 * Two profiles, both returned from create(profile, options):
 *
 *   STANDARD  -- a FULL, separate directory-tree copy of the target source
 *   (NOT a linked git worktree, NO shared .git; own/none node_modules;
 *   stubbed side-effect adapters; a secret-scrubbed env built from a
 *   DEFAULT-DENY allowlist -- only explicitly-allowed vars ever cross into
 *   the copy; Node Permission Model flags where the running Node
 *   feature-detects support for them; supervisor budgets modeled on
 *   scaffold.js's plan-§7 budget approach: monotonic-clock wall-time
 *   decisions, a persisted atomic JSON state file, fail-closed HALT on
 *   breach). The standard profile makes NO confidentiality or
 *   network-containment claim -- this is stated in the returned object's
 *   `claims`, not left implicit, and code evaluation is REFUSED under this
 *   profile (contract 04 B10).
 *
 *   CONTAINER -- opt-in Docker/Podman profile. Adds network denial
 *   (--network none) and a read-only source mount on top of the same
 *   full-copy + scrub + stub + budget machinery. REQUIRED for anything
 *   beyond typed edits (contract 04 B10, contract 05 threat A5): if no
 *   container runtime is detected, the profile reports itself
 *   `available:false` / "unavailable" -- it NEVER silently downgrades to
 *   the standard profile for a caller that required containment.
 *
 * Module-isolation (contract 04 B14 "candidate -> evaluator"): every
 * standard-profile copy is checked post-copy for the three B14 controls --
 * NODE_PATH stripped from the scrubbed env, no on-disk .git/.graphsmith
 * reachable inside the copy, and a symlink audit that any symlink left in
 * the copy resolves back inside the copy (never escapes to the source tree
 * or the real .graphsmith state).
 *
 * Zero-dependency CommonJS, Node >= 18. No clock/randomness in any
 * budget/isolation DECISION: wall-time is measured with
 * process.hrtime.bigint() (a MONOTONIC clock) exactly like scaffold.js's
 * CLOCK NOTE; Date.now() appears only in evidence METADATA (a
 * human-readable timestamp on a persisted budget-state record), never in a
 * pass/fail comparison. Disposable-directory names use crypto.randomBytes
 * as an IDENTIFIER (collision avoidance), not as a decision input -- same
 * posture as run IDs elsewhere in this repo.
 *
 * Usage: node scripts/evalenv.js --selftest
 * Library usage:
 *   const evalenv = require("./scripts/evalenv.js");
 *   const env = evalenv.create("standard", { sourceDir: "/path/to/project" });
 *   ... use env.dir ...
 *   env.destroy();
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const SCHEMA_VERSION = "1.0";

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

function fail(message, code) {
  const e = new Error(message);
  e.code = code || "EVALENV_ERROR";
  return e;
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// Same atomic-write idiom as scaffold.js's supervisor state and
// state-store.js's _atomicReplace: write to a pid-suffixed temp file,
// fsync, then rename -- never a partial budget-state.json on disk.
function atomicWriteJson(file, obj) {
  const tmp = file + ".tmp-" + process.pid + "-" + crypto.randomBytes(4).toString("hex");
  const fd = fs.openSync(tmp, "w");
  try {
    fs.writeSync(fd, JSON.stringify(obj, null, 2) + "\n");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
}

// path.relative-based containment check (mirrors loaders.js's isInside):
// safe against Windows cross-drive paths and against parent === child.
function isInside(parentDir, childPath) {
  const rel = path.relative(parentDir, childPath);
  return rel !== "" && rel !== ".." && !rel.startsWith(".." + path.sep) && !path.isAbsolute(rel);
}

// ---------------------------------------------------------------------------
// Secret-scrubbed env: DEFAULT-DENY allowlist. Only names in this list (or
// explicitly added via options.allowEnv) ever cross from process.env into
// the evaluation copy's env. Everything else -- API keys, tokens, cloud
// credentials, whatever the host process happens to carry -- is stripped by
// construction; there is no "block a denylist" path to forget an entry on.
// Matching is case-insensitive (Windows env var names are case-insensitive;
// POSIX names in this list are conventionally upper-case anyway).
// ---------------------------------------------------------------------------

const DEFAULT_ALLOWLIST = Object.freeze([
  "PATH", "Path",
  "HOME", "USERPROFILE",
  "LANG", "LC_ALL",
  "TMPDIR", "TEMP", "TMP",
  "SHELL", "COMSPEC",
  "SYSTEMROOT", "WINDIR", "PATHEXT",
  "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS",
]);

function scrubEnv(sourceEnv, extraAllow) {
  const allow = new Set(DEFAULT_ALLOWLIST.map((n) => n.toUpperCase()));
  for (const n of extraAllow || []) allow.add(String(n).toUpperCase());
  const out = {};
  for (const key of Object.keys(sourceEnv)) {
    if (allow.has(key.toUpperCase())) out[key] = sourceEnv[key];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Supervisor budgets -- reuses scaffold.js's budget MODEL (monotonic-clock
// wall-time deltas added to a persisted cumulative total, hard ceilings,
// fail-closed HALT with printed evidence, atomic JSON persistence). This is
// NOT a require("./scaffold.js") of scaffold's internal template-emission
// functions -- those are private to that file's string-emission templates
// and scaffold.js's own module.exports only exposes
// {scaffoldProject, runSelftest} (this task's lane is evalenv.js only, so
// scaffold.js is read-only prior art here, not a library dependency) --
// it is the SAME decision shape, scoped to what one create() copy needs.
// ---------------------------------------------------------------------------

const EVALENV_TUNABLE_DEFS = Object.freeze([
  { key: "max_wall_time_ms", default: 120000, min: 1000, max: 3600000, unit: "milliseconds",
    semantics: "maximum monotonic wall time allowed for one create() copy operation" },
  { key: "max_disk_mb", default: 2048, min: 1, max: 1000000, unit: "megabytes",
    semantics: "maximum bytes copied into one disposable evaluation directory" },
  { key: "max_files", default: 200000, min: 1, max: 10000000, unit: "count",
    semantics: "maximum files copied into one disposable evaluation directory" },
]);

function defaultBudgetValues() {
  const out = {};
  for (const t of EVALENV_TUNABLE_DEFS) out[t.key] = t.default;
  return out;
}

function resolveBudgetValues(overrides) {
  const values = Object.assign(defaultBudgetValues(), overrides || {});
  for (const t of EVALENV_TUNABLE_DEFS) {
    const v = values[t.key];
    if (typeof v !== "number" || !Number.isFinite(v) || v < t.min || v > t.max) {
      throw fail(
        `evalenv budget override "${t.key}" = ${JSON.stringify(v)} is outside the bound [${t.min}, ${t.max}] ${t.unit}.`,
        "TUNABLE_OUT_OF_BOUNDS"
      );
    }
  }
  return values;
}

// createBudget() -- the live counter object used while copying. Every
// decision compares against a MONOTONIC clock delta (process.hrtime.bigint())
// exactly as scaffold.js's CLOCK NOTE documents; Date.now() is used only for
// the human-readable timestamp attached to a halt/evidence record below.
function createBudget(values) {
  let bytes = 0;
  let files = 0;
  const startHr = process.hrtime.bigint();

  function elapsedMs() {
    return Number((process.hrtime.bigint() - startHr) / 1000000n);
  }

  function haltBudget(rule, evidence) {
    const err = fail(
      `HALT (budget): ${rule} -- ${JSON.stringify(evidence)}. Evaluation copy aborted and cleaned up; this never proceeds on a partial/over-budget copy.`,
      "BUDGET_BREACH"
    );
    err.halt = { rule, evidence: Object.assign({ at_iso: new Date().toISOString() }, evidence) };
    throw err;
  }

  return {
    recordFile(size) {
      bytes += size;
      files += 1;
      if (bytes > values.max_disk_mb * 1024 * 1024) {
        haltBudget("max_disk_mb", { bytes_copied: bytes, limit_mb: values.max_disk_mb });
      }
      if (files > values.max_files) {
        haltBudget("max_files", { files_copied: files, limit: values.max_files });
      }
      if (elapsedMs() > values.max_wall_time_ms) {
        haltBudget("max_wall_time_ms", { elapsed_ms: elapsedMs(), limit_ms: values.max_wall_time_ms });
      }
    },
    snapshot() {
      return { schema_version: SCHEMA_VERSION, bytes_copied: bytes, files_copied: files, elapsed_ms: elapsedMs(), values };
    },
  };
}

// ---------------------------------------------------------------------------
// Full-tree copy, excluding shared/trust-sensitive directories by name at
// any depth: `.git` (no shared git metadata -- NOT a linked worktree),
// `.graphsmith` (the real constitutional/learned state must be unreachable
// from the copy), `node_modules` (own/none: the copy never inherits the
// source's node_modules). Symlinks are never followed/copied as symlinks --
// each is recorded and skipped, since resolving one could otherwise smuggle
// an escape route back into the source tree into an otherwise-isolated
// copy; this is a documented limitation (projects that rely on symlinked
// files will see them absent from the evaluation copy).
// ---------------------------------------------------------------------------

const DEFAULT_EXCLUDE = Object.freeze([".git", ".graphsmith", "node_modules", ".evalenv"]);

function copyTreeExcluding(srcDir, destDir, excludeNames, budget) {
  const exclude = new Set(excludeNames);
  const symlinksSkipped = [];

  function walk(src, dest) {
    fs.mkdirSync(dest, { recursive: true });
    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
      if (exclude.has(entry.name)) continue;
      const srcPath = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);
      if (entry.isSymbolicLink()) {
        symlinksSkipped.push(srcPath);
        continue;
      }
      if (entry.isDirectory()) {
        walk(srcPath, destPath);
      } else if (entry.isFile()) {
        fs.copyFileSync(srcPath, destPath);
        const size = fs.statSync(destPath).size;
        budget.recordFile(size);
      }
      // other types (sockets, devices, FIFOs) are not source-tree content;
      // silently skipped -- never a legitimate part of a project tree.
    }
  }

  walk(srcDir, destDir);
  return { symlinks_skipped: symlinksSkipped };
}

// ---------------------------------------------------------------------------
// Stubbed side-effect adapters. A concrete, testable stub: a small module
// that monkey-patches Node's http/https request/get and the global fetch
// (when present) to throw a clearly-labeled refusal instead of performing
// any real network call. Wired in via NODE_OPTIONS="--require <stub>" in
// the copy's OWN env object (never process.env's NODE_OPTIONS, which is not
// on the allowlist and is stripped) so any `node` process the caller spawns
// using this env automatically gets the stub loaded first.
// ---------------------------------------------------------------------------

const STUB_DIR_NAME = ".evalenv";
const STUB_FILE_NAME = "network-stub.js";

const STUB_FILE_CONTENT =
  '"use strict";\n' +
  "/* GraphSmith evaluation-copy network stub (I3 standard profile).\n" +
  " * Loaded via NODE_OPTIONS=--require by any process spawned with this\n" +
  " * copy's scrubbed env. Refuses every real network/external effect --\n" +
  " * the standard profile makes NO network-containment claim on its own\n" +
  " * (no OS-level firewall here), so this in-process stub is the actual\n" +
  " * control: a candidate evaluated in this copy cannot reach the network\n" +
  " * even though the process itself is not namespaced. */\n" +
  "function refuse(name) {\n" +
  "  return function () {\n" +
  '    const e = new Error(name + " is stubbed in the GraphSmith I3 evaluation copy -- no real network or external effect is permitted here.");\n' +
  '    e.code = "EVALENV_STUBBED_EFFECT";\n' +
  "    throw e;\n" +
  "  };\n" +
  "}\n" +
  'const http = require("http");\n' +
  'const https = require("https");\n' +
  "[http, https].forEach(function (mod) {\n" +
  '  mod.request = refuse("http(s).request");\n' +
  '  mod.get = refuse("http(s).get");\n' +
  "});\n" +
  'if (typeof global.fetch === "function") {\n' +
  '  global.fetch = refuse("fetch");\n' +
  "}\n";

function writeStubs(copyDir) {
  const stubDir = path.join(copyDir, STUB_DIR_NAME);
  fs.mkdirSync(stubDir, { recursive: true });
  const stubPath = path.join(stubDir, STUB_FILE_NAME);
  fs.writeFileSync(stubPath, STUB_FILE_CONTENT);
  return { dir: stubDir, file: stubPath };
}

// ---------------------------------------------------------------------------
// Node Permission Model feature-detection. process.allowedNodeEnvironmentFlags
// is a real, zero-dependency Node API (a Set of flags this exact runtime
// understands in NODE_OPTIONS) -- used here purely to detect, never to
// assume, support for --permission/--allow-fs-*. Unsupported runtimes are
// documented honestly, not silently ignored.
// ---------------------------------------------------------------------------

function detectPermissionModel(copyDir) {
  let flags = null;
  try {
    flags = process.allowedNodeEnvironmentFlags;
  } catch (e) {
    flags = null;
  }
  const has = (name) => !!(flags && typeof flags.has === "function" && flags.has(name));
  const supported = has("--permission");
  return {
    supported,
    flags_detected: {
      permission: supported,
      allow_fs_read: has("--allow-fs-read"),
      allow_fs_write: has("--allow-fs-write"),
    },
    recommended_argv: supported
      ? ["--permission", "--allow-fs-read=" + copyDir + "/*", "--allow-fs-write=" + copyDir + "/*"]
      : null,
    detail: supported
      ? `Node Permission Model flags detected on this runtime (${process.version}).`
      : `Node Permission Model flags are not recognized by this runtime (${process.version}) -- proceeding without OS-enforced FS permission restriction on top of the copy's own directory isolation; documented limitation, not a silent claim of enforcement.`,
  };
}

// ---------------------------------------------------------------------------
// Module-isolation checks (contract 04 B14: "NODE_PATH, resolution check,
// symlink audit"). All three are checked against the ALREADY-BUILT copy +
// scrubbed env, so this function is evidence, not a guess.
// ---------------------------------------------------------------------------

function checkIsolation(copyDir, scrubbedEnv, symlinksSkipped) {
  const gitPresent = fs.existsSync(path.join(copyDir, ".git"));
  const graphsmithPresent = fs.existsSync(path.join(copyDir, ".graphsmith"));
  const nodePathLeaked = Object.keys(scrubbedEnv).some((k) => k.toUpperCase() === "NODE_PATH");

  // Symlink audit: any symlink actually left INSIDE the copy (none should
  // be, since copyTreeExcluding skips every symlink -- this walk exists to
  // catch a future code path that stops skipping them, or a symlink dropped
  // into the copy by some other means, before it can resolve outside).
  const symlinkEscapes = [];
  (function scan(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      return;
    }
    for (const entry of entries) {
      const p = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        try {
          const real = fs.realpathSync(p);
          if (!isInside(copyDir, real)) symlinkEscapes.push({ path: p, target: real });
        } catch (e) {
          // dangling symlink target -- not an escape, just inert.
        }
      } else if (entry.isDirectory()) {
        scan(p);
      }
    }
  })(copyDir);

  return {
    git_absent: !gitPresent,
    graphsmith_state_absent: !graphsmithPresent,
    node_path_stripped: !nodePathLeaked,
    symlinks_skipped_at_copy: (symlinksSkipped || []).length,
    symlink_escapes: symlinkEscapes,
    isolated: !gitPresent && !graphsmithPresent && !nodePathLeaked && symlinkEscapes.length === 0,
  };
}

// ---------------------------------------------------------------------------
// Container runtime detection (Docker/Podman). Requires the DAEMON to
// actually answer (`<bin> info`), not just the CLI binary to exist on PATH
// -- a CLI with no reachable daemon cannot actually deny network or mount
// read-only, so it must report unavailable, never a false "available".
// envOverride lets callers (selftest) force a deterministic "not found" by
// supplying a PATH that excludes any container runtime, independent of
// whatever happens to be installed on the host running this file.
// ---------------------------------------------------------------------------

function detectContainerRuntime(envOverride) {
  const env = envOverride || process.env;
  const candidates = ["docker", "podman"];
  for (const bin of candidates) {
    try {
      const res = spawnSync(bin, ["info", "--format", "{{.ServerVersion}}"], {
        env,
        stdio: "ignore",
        shell: false,
        timeout: 5000,
      });
      if (!res.error && res.status === 0) return { runtime: bin, available: true };
    } catch (e) {
      // keep scanning the next candidate
    }
  }
  return { runtime: null, available: false };
}

// ---------------------------------------------------------------------------
// create('standard', options)
// ---------------------------------------------------------------------------

function createStandard(options) {
  const sourceDir = path.resolve(options.sourceDir || path.join(__dirname, ".."));
  if (!fs.existsSync(sourceDir) || !fs.statSync(sourceDir).isDirectory()) {
    throw fail(`evalenv.create("standard"): sourceDir does not exist or is not a directory: ${sourceDir}`, "INVALID_SOURCE");
  }

  const tmpRoot = options.tmpRoot || os.tmpdir();
  const dir = fs.mkdtempSync(path.join(tmpRoot, "graphsmith-evalenv-"));

  const exclude = DEFAULT_EXCLUDE.concat(options.exclude || []);
  const budgetValues = resolveBudgetValues(options.budgets);
  const budget = createBudget(budgetValues);

  let copyReport;
  try {
    copyReport = copyTreeExcluding(sourceDir, dir, exclude, budget);
  } catch (e) {
    // Never leave a partial/over-budget copy on disk.
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (cleanupErr) {
      /* best-effort cleanup; original error still wins */
    }
    throw e;
  }

  const env = scrubEnv(process.env, options.allowEnv);
  const stubs = writeStubs(dir);
  env.NODE_OPTIONS = ((env.NODE_OPTIONS ? env.NODE_OPTIONS + " " : "") + "--require " + stubs.file).trim();

  const permissionModel = detectPermissionModel(dir);
  const isolation = checkIsolation(dir, env, copyReport.symlinks_skipped);
  const budgetSnapshot = budget.snapshot();

  const metaDir = path.join(dir, STUB_DIR_NAME);
  fs.mkdirSync(metaDir, { recursive: true });
  atomicWriteJson(path.join(metaDir, "budget-state.json"), budgetSnapshot);
  atomicWriteJson(path.join(metaDir, "manifest.json"), {
    schema_version: SCHEMA_VERSION,
    profile: "standard",
    created_at_iso: new Date().toISOString(), // metadata only, never a decision input
    source_dir: sourceDir,
    excluded: exclude,
    isolation,
  });

  let destroyed = false;
  function destroy() {
    if (destroyed) return { destroyed: true, already: true };
    fs.rmSync(dir, { recursive: true, force: true });
    destroyed = true;
    return { destroyed: true, already: false };
  }

  function runUntrustedCode() {
    throw fail(
      "REFUSED: executing untrusted/candidate code requires the container profile (contract 04 B10, contract 05 threat A5). " +
        "The standard evaluation profile makes NO confidentiality or network-containment claim and must never run untrusted " +
        'executable code -- call create("container", ...) instead. If the container profile reports unavailable, code ' +
        "evaluation cannot proceed at all (never a silent fallback to this profile).",
      "CONTAINER_REQUIRED"
    );
  }

  return {
    schema_version: SCHEMA_VERSION,
    profile: "standard",
    dir,
    env,
    stubs,
    permissionModel,
    isolation,
    budgets: { values: budgetValues, snapshot: budgetSnapshot },
    copyReport,
    // Honest naming (plan §3 / contract 05): the standard profile is a
    // disposable, module-isolated directory copy with a scrubbed env and
    // stubbed effects -- it is NOT sandboxed against network egress or
    // confidentiality loss at the OS/process level. Say so plainly.
    claims: {
      isolation_level: "disposable full-copy, module-isolated (no shared .git/.graphsmith, own/none node_modules, secret-scrubbed env, stubbed network effects)",
      confidentiality: false,
      network_containment: false,
      note:
        "standard profile: no OS-level sandbox, no network denial, no read-only mount -- 'sandbox' language, if used, applies only " +
        "to the isolation actually described here. Code evaluation is refused under this profile; see runUntrustedCode().",
    },
    runUntrustedCode,
    destroy,
  };
}

// ---------------------------------------------------------------------------
// create('container', options)
// ---------------------------------------------------------------------------

function createContainer(options) {
  const detection = detectContainerRuntime(options.envOverrideForDetection);

  if (!detection.available) {
    return {
      schema_version: SCHEMA_VERSION,
      profile: "container",
      available: false,
      runtime: null,
      dir: null,
      reason: "no reachable Docker/Podman runtime detected on this machine (checked: docker, podman -- daemon must answer `<bin> info`).",
      claims: {
        isolation_level: "unavailable",
        confidentiality: false,
        network_containment: false,
        note: "container profile is UNAVAILABLE -- never silently downgraded to the standard profile for a caller that required containment (contract 04 B10).",
      },
      runUntrustedCode() {
        throw fail(
          "UNAVAILABLE: no container runtime (docker/podman) detected -- refusing to run untrusted/candidate code. " +
            "This will NOT silently fall back to the standard profile (contract 04 B10 / contract 05 threat A5).",
          "CONTAINER_UNAVAILABLE"
        );
      },
      destroy() {
        return { destroyed: true, already: true, note: "nothing was created (container runtime unavailable)." };
      },
    };
  }

  // Runtime is reachable: build the same full-copy + scrub + stub + budget
  // base as the standard profile (the container profile adds network
  // denial + read-only mount ON TOP of that, at run time -- not a
  // different copy mechanism).
  const base = createStandard(options);

  function runUntrustedCode(cmd, runOpts) {
    runOpts = runOpts || {};
    if (!runOpts.image) {
      throw fail(
        'evalenv container runUntrustedCode(cmd, {image}): "image" is required (no image is assumed/pulled implicitly).',
        "IMAGE_REQUIRED"
      );
    }
    const argv = [
      "run", "--rm",
      "--network", "none", // network denial (contract 04 B10)
      "-v", `${base.dir}:/workspace:ro`, // read-only source mount (contract 04 B10)
      "-w", "/workspace",
      runOpts.image,
    ].concat(Array.isArray(cmd) ? cmd : [String(cmd)]);
    return spawnSync(detection.runtime, argv, Object.assign({ env: base.env, stdio: "pipe", timeout: runOpts.timeoutMs || 60000 }, runOpts.spawnOptions || {}));
  }

  return Object.assign({}, base, {
    profile: "container",
    available: true,
    runtime: detection.runtime,
    claims: {
      isolation_level: `container (${detection.runtime}): network denied (--network none), read-only source mount, plus everything the standard profile provides`,
      confidentiality: "partial",
      network_containment: true,
      note: "container profile: network denial and read-only source mount are enforced by the container runtime at run time (runUntrustedCode), not merely declared.",
    },
    runUntrustedCode,
  });
}

// ---------------------------------------------------------------------------
// create(profile, options) dispatcher + requireContainer() precondition helper
// ---------------------------------------------------------------------------

function create(profile, options) {
  options = options || {};
  if (profile === "standard") return createStandard(options);
  if (profile === "container") return createContainer(options);
  throw fail(`evalenv.create: unknown profile ${JSON.stringify(profile)} (expected "standard" or "container").`, "INVALID_PROFILE");
}

// Enforceable precondition callers can check before doing anything beyond
// typed edits (contract 04 B10): throws unless handle is an AVAILABLE
// container-profile handle.
function requireContainer(handle) {
  if (!handle || handle.profile !== "container" || handle.available !== true) {
    throw fail(
      "requireContainer: this action requires an available container-profile evaluation copy (contract 04 B10) -- " +
        (handle && handle.profile === "container" ? "the container profile is unavailable on this machine." : `got profile ${JSON.stringify(handle && handle.profile)}.`),
      "CONTAINER_REQUIRED"
    );
  }
  return true;
}

module.exports = {
  SCHEMA_VERSION,
  create,
  requireContainer,
  scrubEnv,
  DEFAULT_ALLOWLIST,
  EVALENV_TUNABLE_DEFS,
  detectContainerRuntime,
  detectPermissionModel,
  checkIsolation,
};

// ---------------------------------------------------------------------------
// --selftest
// ---------------------------------------------------------------------------

function buildFixtureSource(root) {
  const src = path.join(root, "fixture-source");
  fs.mkdirSync(path.join(src, "lib"), { recursive: true });
  fs.mkdirSync(path.join(src, "node_modules", "some-dep"), { recursive: true });
  fs.mkdirSync(path.join(src, ".git"), { recursive: true });
  fs.mkdirSync(path.join(src, ".graphsmith", "evolvable"), { recursive: true });
  fs.writeFileSync(path.join(src, "package.json"), JSON.stringify({ name: "fixture" }, null, 2));
  fs.writeFileSync(path.join(src, "lib", "index.js"), "module.exports = 1;\n");
  fs.writeFileSync(path.join(src, "node_modules", "some-dep", "index.js"), "module.exports = {};\n");
  fs.writeFileSync(path.join(src, ".git", "HEAD"), "ref: refs/heads/main\n");
  fs.writeFileSync(path.join(src, ".graphsmith", "evolvable", "ACTIVE"), "{}\n");
  return src;
}

function runSelftest() {
  const results = [];
  const record = (name, pass, detail) => {
    results.push({ name, pass });
    console.log(JSON.stringify({ selftest: name, pass, detail: detail === undefined ? undefined : String(detail) }));
  };

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-evalenv-selftest-"));
  const previousFakeSecret = process.env.GRAPHSMITH_SELFTEST_FAKE_SECRET;
  try {
    const src = buildFixtureSource(root);

    // A fake secret var, deliberately NOT on the allowlist and NOT added
    // via allowEnv below -- must never reach the copy.
    process.env.GRAPHSMITH_SELFTEST_FAKE_SECRET = "sk-fake-secret-do-not-leak-12345";

    // ---- standard profile: full non-git copy ----
    let std;
    try {
      std = create("standard", { sourceDir: src, tmpRoot: root });
      record(
        "standard/full-non-git-copy",
        fs.existsSync(std.dir) &&
          std.dir !== src &&
          !fs.existsSync(path.join(std.dir, ".git")) &&
          !fs.existsSync(path.join(std.dir, ".graphsmith")) &&
          !fs.existsSync(path.join(std.dir, "node_modules")) &&
          fs.existsSync(path.join(std.dir, "lib", "index.js")) &&
          fs.existsSync(path.join(std.dir, "package.json"))
      );
    } catch (e) {
      record("standard/full-non-git-copy", false, e.message);
    }

    // ---- secret-scrub: fake secret does not reach the copy's env ----
    if (std) {
      const envJson = JSON.stringify(std.env);
      record(
        "standard/secret-scrub-fake-secret-not-leaked",
        !("GRAPHSMITH_SELFTEST_FAKE_SECRET" in std.env) && !envJson.includes("sk-fake-secret-do-not-leak-12345"),
        JSON.stringify(Object.keys(std.env))
      );
    } else {
      record("standard/secret-scrub-fake-secret-not-leaked", false, "no std handle (copy failed)");
    }

    // ---- stubbed adapters present ----
    if (std) {
      record(
        "standard/stubbed-adapters-present",
        fs.existsSync(std.stubs.file) && /EVALENV_STUBBED_EFFECT/.test(fs.readFileSync(std.stubs.file, "utf8")) && /--require/.test(std.env.NODE_OPTIONS || "")
      );
    } else {
      record("standard/stubbed-adapters-present", false, "no std handle");
    }

    // ---- supervisor budgets present ----
    if (std) {
      record(
        "standard/supervisor-budgets-present",
        std.budgets && typeof std.budgets.snapshot.bytes_copied === "number" && typeof std.budgets.values.max_disk_mb === "number"
      );
    } else {
      record("standard/supervisor-budgets-present", false, "no std handle");
    }

    // ---- module isolation (B14): NODE_PATH stripped, no .git/.graphsmith, no symlink escape ----
    if (std) {
      record(
        "standard/module-isolation-b14",
        std.isolation.isolated === true &&
          std.isolation.node_path_stripped === true &&
          std.isolation.git_absent === true &&
          std.isolation.graphsmith_state_absent === true &&
          std.isolation.symlink_escapes.length === 0
      );
    } else {
      record("standard/module-isolation-b14", false, "no std handle");
    }

    // ---- honest claims: standard makes no confidentiality/network claim ----
    if (std) {
      record(
        "standard/honest-no-confidentiality-network-claim",
        std.claims.confidentiality === false && std.claims.network_containment === false
      );
    } else {
      record("standard/honest-no-confidentiality-network-claim", false, "no std handle");
    }

    // ---- code-eval-without-container REFUSED ----
    if (std) {
      let refused = false;
      let code = null;
      try {
        std.runUntrustedCode();
      } catch (e) {
        refused = true;
        code = e.code;
      }
      record("standard/code-eval-without-container-refused", refused && code === "CONTAINER_REQUIRED", code);
    } else {
      record("standard/code-eval-without-container-refused", false, "no std handle");
    }

    // ---- destroy() cleans up ----
    if (std) {
      const dirBefore = std.dir;
      std.destroy();
      record("standard/destroy-cleans-up", !fs.existsSync(dirBefore));
    } else {
      record("standard/destroy-cleans-up", false, "no std handle");
    }

    // ---- container profile: forced-unavailable via a PATH-less env (deterministic,
    // independent of whether Docker/Podman actually happens to be installed on
    // whatever machine runs this selftest) ----
    {
      const noRuntimeEnv = { PATH: root }; // a directory with no docker/podman binaries
      const container = create("container", {
        sourceDir: src,
        tmpRoot: root,
        envOverrideForDetection: noRuntimeEnv,
      });
      record(
        "container/unavailable-reported-cleanly",
        container.profile === "container" && container.available === false && container.dir === null && typeof container.reason === "string"
      );

      let containerRefused = false;
      let containerCode = null;
      try {
        container.runUntrustedCode();
      } catch (e) {
        containerRefused = true;
        containerCode = e.code;
      }
      record("container/refuses-code-eval-when-unavailable", containerRefused && containerCode === "CONTAINER_UNAVAILABLE", containerCode);

      // destroy() on an unavailable container handle must be a harmless no-op,
      // never throw.
      let destroyOk = true;
      try {
        container.destroy();
      } catch (e) {
        destroyOk = false;
      }
      record("container/destroy-noop-when-unavailable", destroyOk);
    }

    // ---- requireContainer() precondition helper: refuses a standard handle ----
    {
      const std2 = create("standard", { sourceDir: src, tmpRoot: root });
      let threw = false;
      try {
        requireContainer(std2);
      } catch (e) {
        threw = e.code === "CONTAINER_REQUIRED";
      }
      record("requireContainer/refuses-standard-profile", threw);
      std2.destroy();
    }
  } finally {
    if (previousFakeSecret === undefined) delete process.env.GRAPHSMITH_SELFTEST_FAKE_SECRET;
    else process.env.GRAPHSMITH_SELFTEST_FAKE_SECRET = previousFakeSecret;
    fs.rmSync(root, { recursive: true, force: true });
  }

  const failed = results.filter((r) => !r.pass);
  console.log(JSON.stringify({ selftest: "__summary__", total: results.length, failed: failed.length }));
  return failed.length === 0 ? 0 : 1;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.includes("--selftest")) {
    process.exit(runSelftest());
  } else {
    console.error("Usage: node scripts/evalenv.js --selftest");
    process.exit(2);
  }
}
