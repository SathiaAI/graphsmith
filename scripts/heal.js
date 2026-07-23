#!/usr/bin/env node
/* GraphSmith heal.js — Loop 1 self-healing (plan §3.3). Zero-dep CJS, Node ≥ 18.
 *
 * HARD SPLIT (v0.2.0, no exceptions on code):
 *   typed repairs  — prompt / tunables-within-bounds / config / scenario DATA
 *                    staged with I3-standard evidence; auto-apply-eligible ONLY
 *                    when a syntactic capability allowlist shows no external-call
 *                    involvement (policy, not a "proof")
 *   code repairs   — ANY executable file change: STAGED-ONLY. Emit diff +
 *                    diagnosis + plain-English + suggested chaos commands.
 *                    NEVER applied. Manager code is NEVER staged or touched.
 *
 * Diagnosis reads halt/checkpoint/registry state ONLY through a typed-event
 * reader interface. scripts/event-compiler.js is Phase C — the reader below is
 * a thin adapter over state-store typed records, marked for Phase C to replace.
 *
 * CLI: --diagnose | --stage <target> [--proposed <file|inline>] | rollback <id>
 *      | --selftest   [--root <dir>]
 * JSON on stdout, prose on stderr, exit 0/1/2.
 * No LLM / clock / random in decision paths. */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");
const { createStore } = require("./state-store.js");
const Manifest = require("./manifest.js");
const Loaders = require("./loaders.js");

const SCHEMA_VERSION = "1.0";
const HEAL_STAGES_REL = path.join(".graphsmith", "heal-stages");
const EVAL_PROFILE_I3 = "I3-standard";
const CAPABILITY_POLICY_ID = "syntactic-allowlist-v1";

/* ---------------------------------------------------------------------------
 * Shared helpers
 * ------------------------------------------------------------------------- */

function fail(message, code) {
  const err = new Error(message);
  err.code = code || "HEAL_ERROR";
  return err;
}

function sha256Raw(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function sha256Text(text) {
  return sha256Raw(Buffer.from(String(text), "utf8"));
}

function stableId(parts) {
  return sha256Raw(Buffer.from(parts.map(String).join("\0"), "utf8")).slice(0, 24);
}

function toRepoRel(root, absPath) {
  const rel = path.relative(root, absPath);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) {
    throw fail(`Target escapes project root: ${absPath}`, "INVALID_TARGET");
  }
  return rel.split(path.sep).join("/");
}

function ensureInsideRoot(root, absPath) {
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(absPath);
  const rel = path.relative(resolvedRoot, resolved);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) {
    throw fail(`Path escapes project root: ${absPath}`, "INVALID_TARGET");
  }
  return resolved;
}

function stagesDir(root) {
  return path.join(root, HEAL_STAGES_REL);
}

function stagePath(root, healId) {
  return path.join(stagesDir(root), `${healId}.staged.json`);
}

function writeJsonAtomic(filePath, obj) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const body = `${JSON.stringify(obj, null, 2)}\n`;
  const tmp = `${filePath}.tmp.${process.pid}`;
  fs.writeFileSync(tmp, body);
  fs.renameSync(tmp, filePath);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

/* ---------------------------------------------------------------------------
 * Classification — typed vs code; manager never touchable
 * ------------------------------------------------------------------------- */

function normalizeRelPosix(relPosix) {
  return String(relPosix || "")
    .split(/[/\\]+/)
    .filter((p) => p && p !== ".")
    .join("/")
    .replace(/\/+$/, "");
}

function isManagerPath(relPosix) {
  // Case-insensitive + path-normalized basename/path check so MANAGER.js /
  // Manager.js / nested/manager.JS / manager.cjs never stall as "regular code".
  const posix = normalizeRelPosix(relPosix).toLowerCase();
  if (!posix) return false;
  const base = path.posix.basename(posix);
  if (base === "manager.js" || base === "manager.cjs" || base === "manager.mjs") return true;
  // Scaffolded managers and constitutional control surface (any nesting).
  if (/(?:^|\/)manager(?:\.[^/]+)?\.js$/.test(posix)) return true;
  return false;
}

function classifyRelForTarget(root, abs, relPosix) {
  // Prefer realpath so symlinks into manager.* are refused, never staged.
  try {
    const realRoot = fs.realpathSync(root);
    const realAbs = fs.realpathSync(abs);
    const rel = path.relative(realRoot, realAbs);
    if (rel && !rel.startsWith("..") && !path.isAbsolute(rel)) {
      return normalizeRelPosix(rel.split(path.sep).join("/"));
    }
    return normalizeRelPosix(path.basename(realAbs));
  } catch (_) {
    return relPosix;
  }
}

function isExecutablePath(relPosix) {
  return /\.(js|cjs|mjs|ts|tsx|jsx)$/i.test(relPosix);
}

function classifyTarget(relPosix) {
  if (isManagerPath(relPosix)) {
    return { repair_class: "code", kind: "manager", is_manager: true };
  }
  if (isExecutablePath(relPosix)) {
    return { repair_class: "code", kind: "executable", is_manager: false };
  }
  const base = path.posix.basename(relPosix);
  if (relPosix.includes("/workers/") && base.endsWith(".prompt.md")) {
    return { repair_class: "typed", kind: "prompt", is_manager: false };
  }
  if (base === "tunables.json") {
    return { repair_class: "typed", kind: "tunables", is_manager: false };
  }
  if (base === "scenario.json" || /\/scenarios\/.+\.json$/i.test(relPosix) || base.endsWith(".scenario.json")) {
    return { repair_class: "typed", kind: "scenario", is_manager: false };
  }
  if (base.endsWith(".config.json") || base === "workflow.manifest.json" || base.endsWith(".json")) {
    return { repair_class: "typed", kind: "config", is_manager: false };
  }
  if (base.endsWith(".md") || base.endsWith(".txt") || base.endsWith(".yml") || base.endsWith(".yaml")) {
    return { repair_class: "typed", kind: "data", is_manager: false };
  }
  // Unknown → treat as code so we never auto-apply silently.
  return { repair_class: "code", kind: "unknown-executable-surface", is_manager: false };
}

/* ---------------------------------------------------------------------------
 * Capability policy — syntactic allowlist, NOT a proof
 * ------------------------------------------------------------------------- */

const EXTERNAL_CALL_PATTERNS = Object.freeze([
  { id: "node-fs", re: /\brequire\s*\(\s*['"]fs['"]\s*\)|\bfs\.(read|write|append|open|unlink|rm|mkdir|rename|create)/ },
  { id: "node-net", re: /\brequire\s*\(\s*['"](http|https|net|tls|dns|dgram)['"]\s*\)|\b(https?|net|tls|dns)\./ },
  { id: "node-child-process", re: /\brequire\s*\(\s*['"]child_process['"]\s*\)|\b(exec|execFile|spawn|fork)\s*\(/ },
  { id: "fetch", re: /\bfetch\s*\(/ },
  { id: "process-env-or-exit", re: /\bprocess\.(env|exit|binding)\b/ },
  { id: "dynamic-require", re: /\brequire\s*\(\s*[^'"]/ },
  { id: "eval-function", re: /\beval\s*\(|\bnew\s+Function\s*\(/ },
  { id: "worker-threads", re: /\brequire\s*\(\s*['"]worker_threads['"]\s*\)/ },
]);

/* Constructs that defeat static external-call detection. Presence → NOT
 * auto-apply-eligible (fail-closed). Clean prose/knob/data without these stays eligible. */
const STATIC_UNPROVABLE_PATTERNS = Object.freeze([
  { id: "from-char-code", re: /\bString\s*\.\s*from(?:CharCode|CodePoint)\s*\(/ },
  { id: "hex-or-unicode-escape", re: /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]+\}/ },
  { id: "string-concat-assembly", re: /(['"])[^'"]{1,24}\1\s*\+\s*(['"])[^'"]{1,24}\2/ },
  { id: "template-assembly", re: /`[^`]*\$\{[^}]+\}[^`]*`/ },
  { id: "computed-member", re: /(?:\b[\w$]+|\))\s*\[\s*(['"`]).*?\1\s*\]|(?:\b[\w$]+|\))\s*\[\s*[^\]0-9\s][^ \]]*\]/ },
  { id: "dynamic-import", re: /\bimport\s*\(/ },
  { id: "globalthis-indirection", re: /\bglobalThis\s*[.\[]/ },
  { id: "function-constructor", re: /\bFunction\s*\(|\bReflect\s*\.\s*construct\s*\(/ },
]);

function capabilityPolicyScan(texts) {
  const blob = Array.isArray(texts) ? texts.join("\n") : String(texts || "");
  const matched = [];
  for (const p of EXTERNAL_CALL_PATTERNS) {
    if (p.re.test(blob)) matched.push(p.id);
  }
  // Fail-closed: any obfuscation/indirection ⇒ not statically provable clean.
  for (const p of STATIC_UNPROVABLE_PATTERNS) {
    if (p.re.test(blob)) matched.push(p.id);
  }
  return {
    policy: CAPABILITY_POLICY_ID,
    policy_kind: "syntactic-allowlist-fail-closed",
    is_proof: false,
    no_external_calls: matched.length === 0,
    matched_patterns: matched,
  };
}

/* ---------------------------------------------------------------------------
 * Diff (deterministic, no external deps)
 * ------------------------------------------------------------------------- */

function computeUnifiedDiff(before, after, fileName) {
  if (before === after) {
    return `diff --git a/${fileName} b/${fileName}\n--- a/${fileName}\n+++ b/${fileName}\n`;
  }
  const a = String(before).split(/\r?\n/);
  const b = String(after).split(/\r?\n/);
  // Drop trailing empty line artifact from split on final newline.
  if (a.length && a[a.length - 1] === "") a.pop();
  if (b.length && b[b.length - 1] === "") b.pop();
  const lines = [
    `diff --git a/${fileName} b/${fileName}`,
    `--- a/${fileName}`,
    `+++ b/${fileName}`,
    `@@ -1,${a.length} +1,${b.length} @@`,
  ];
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) {
    const left = i < a.length ? a[i] : null;
    const right = i < b.length ? b[i] : null;
    if (left === right) lines.push(` ${left}`);
    else {
      if (left !== null) lines.push(`-${left}`);
      if (right !== null) lines.push(`+${right}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

/* ---------------------------------------------------------------------------
 * Typed-event reader adapter (Phase C wires real event-compiler.js here)
 * ------------------------------------------------------------------------- */

/**
 * PHASE-C-EVENT-COMPILER-ADAPTER
 * scripts/event-compiler.js does not exist yet (Phase C). This adapter exposes
 * the same typed-event reader surface diagnosis needs, sourced ONLY from
 * state-store's schema-validated typed records. It NEVER reads raw prose logs.
 * Phase C replaces getTypedEvents / getTypedHaltDiagnosis bodies with the
 * real compiler output while keeping this module interface stable.
 */
function createTypedEventReader(projectRoot) {
  const root = path.resolve(projectRoot || process.cwd());
  const store = createStore(root);

  function collectTypedEvents() {
    const events = [];

    let windowRec = null;
    try {
      windowRec = store.window.get();
    } catch (err) {
      events.push({
        record_type: "STATE_READ_ERROR",
        channel: "window",
        code: err && err.code ? err.code : "STATE_STORE_ERROR",
      });
    }
    if (windowRec) {
      events.push({
        record_type: "WINDOW_STATE",
        state: windowRec.state,
        flag: !!windowRec.flag,
        state_rev: windowRec.state_rev,
        window: windowRec.window
          ? {
              window_id: windowRec.window.window_id,
              adoption_txid: windowRec.window.adoption_txid,
              tree_id: windowRec.window.tree_id,
              n: windowRec.window.n,
              admitted: windowRec.window.admitted,
              active: windowRec.window.active,
              slot_count: Array.isArray(windowRec.window.slots) ? windowRec.window.slots.length : 0,
            }
          : null,
      });
    }

    let runs = [];
    try {
      runs = typeof store.runRegistry.list === "function" ? store.runRegistry.list() : [];
    } catch (err) {
      events.push({
        record_type: "STATE_READ_ERROR",
        channel: "run_registry",
        code: err && err.code ? err.code : "STATE_STORE_ERROR",
      });
    }
    for (const run of runs) {
      events.push({
        record_type: "RUN_REGISTRY",
        run_id: run.run_id,
        tree_id: run.tree_id,
        status: run.status || run.state || null,
      });
    }

    let rejected = [];
    try {
      rejected = store.rejectedBuffer.list() || [];
    } catch (err) {
      events.push({
        record_type: "STATE_READ_ERROR",
        channel: "rejected_buffer",
        code: err && err.code ? err.code : "STATE_STORE_ERROR",
      });
    }
    for (const row of rejected) {
      events.push({
        record_type: "REJECTED",
        fingerprint: row.fingerprint || null,
      });
    }

    let rollbacks = [];
    try {
      rollbacks = store.rollbackFamilies.list() || [];
    } catch (err) {
      events.push({
        record_type: "STATE_READ_ERROR",
        channel: "rollback_families",
        code: err && err.code ? err.code : "STATE_STORE_ERROR",
      });
    }
    for (const rb of rollbacks) {
      events.push({
        record_type: rb.record_type || "ROLLBACK_RECORDED",
        fingerprint: rb.fingerprint || null,
        family: rb.family || null,
      });
    }

    return events;
  }

  function classifyFromEvents(events) {
    const windowEv = events.find((e) => e.record_type === "WINDOW_STATE");
    const state = windowEv ? windowEv.state : "NO_WINDOW";
    let cause_code = "ok";
    let classification = state || "UNKNOWN";

    if (state === "HALT_HUMAN" || state === "HALT") {
      cause_code = "halt_human";
    } else if (state === "ROLLING_BACK") {
      cause_code = "rolling_back";
    } else if (state === "CLOSED_FLAGGED" || (windowEv && windowEv.flag)) {
      cause_code = "flagged";
    } else if (events.some((e) => e.record_type === "STATE_READ_ERROR")) {
      cause_code = "state_read_error";
      classification = "STATE_READ_ERROR";
    } else if (events.some((e) => e.record_type === "REJECTED")) {
      cause_code = "rejected_buffer_present";
    } else if (state === "NO_WINDOW") {
      cause_code = "no_window";
    }

    return { classification, cause_code, window_state: state };
  }

  return {
    // Marker for Phase C wiring — do not remove.
    __adapter_for: "phase-c-event-compiler",
    __phase: "B-adapter-over-state-store-typed-records",
    __note:
      "Thin typed-event reader over state-store schema records. " +
      "Phase C replaces internals with scripts/event-compiler.js. " +
      "Never feeds raw prose logs to diagnosis.",

    getTypedEvents() {
      return collectTypedEvents();
    },

    getTypedHaltDiagnosis() {
      const evidence = collectTypedEvents();
      const cls = classifyFromEvents(evidence);
      return {
        type: "typed_diagnosis",
        schema_version: SCHEMA_VERSION,
        classification: cls.classification,
        cause_code: cls.cause_code,
        window_state: cls.window_state,
        evidence,
        raw_source: "state-store.typed-records+adapter",
        // Explicit: diagnosis surface is typed events only.
        prose_logs_consulted: false,
      };
    },
  };
}

/* ---------------------------------------------------------------------------
 * Tunables-within-bounds check (typed path only; fail-closed if over bounds)
 * ------------------------------------------------------------------------- */

function loadTunablesBounds(root) {
  // Prefer freeze data from release-shaped manifests if present; else none.
  const candidates = [
    path.join(root, "release.manifest.json"),
    path.join(root, ".graphsmith", "release.manifest.json"),
    path.join(root, "project.manifest.json"),
    path.join(root, ".graphsmith", "project.manifest.json"),
  ];
  for (const p of candidates) {
    if (!fs.existsSync(p)) continue;
    try {
      const m = readJson(p);
      if (m && m.tunables_bounds && typeof m.tunables_bounds === "object") {
        return m.tunables_bounds;
      }
    } catch (_) {
      /* ignore corrupt optional freeze file */
    }
  }
  return null;
}

function tunablesWithinBounds(proposedText, bounds) {
  if (!bounds) {
    return { checked: false, within_bounds: true, violations: [] };
  }
  let obj;
  try {
    obj = JSON.parse(proposedText);
  } catch (_) {
    return { checked: true, within_bounds: false, violations: ["tunables-not-json"] };
  }
  const violations = [];
  for (const [key, rule] of Object.entries(bounds)) {
    if (!rule || typeof rule !== "object") continue;
    if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
    const v = obj[key];
    if (typeof v !== "number" || !Number.isFinite(v)) {
      violations.push(`${key}:not-number`);
      continue;
    }
    if (typeof rule.min === "number" && v < rule.min) violations.push(`${key}:below-min`);
    if (typeof rule.max === "number" && v > rule.max) violations.push(`${key}:above-max`);
  }
  return { checked: true, within_bounds: violations.length === 0, violations };
}

/* ---------------------------------------------------------------------------
 * Target tree identity (manifest.js) for byte-exact rollback proofs
 * ------------------------------------------------------------------------- */

function targetTreeIdentity(root, relPosix) {
  const tree = Manifest.generate("tree", {
    rootDir: root,
    includeOnly: [relPosix],
  });
  const payload = JSON.stringify(tree);
  return {
    schema_version: tree.schema_version,
    files: tree.files,
    tree_sha256: sha256Text(payload),
  };
}

/* ---------------------------------------------------------------------------
 * Diagnose
 * ------------------------------------------------------------------------- */

function diagnose(rootArg) {
  const root = path.resolve(rootArg || process.cwd());
  const reader = createTypedEventReader(root);
  const diagnosis = reader.getTypedHaltDiagnosis();

  let plain;
  switch (diagnosis.cause_code) {
    case "halt_human":
      plain =
        "Run is in HALT_HUMAN. Control flow stopped for a human decision. " +
        "Inspect typed evidence (window/registry/rollback), then stage a typed or code repair.";
      break;
    case "rolling_back":
      plain = "Window is ROLLING_BACK. Do not stage conflicting heals until rollback completes or is acknowledged.";
      break;
    case "flagged":
      plain = "Window flagged. Treat as soft-fail observation; stage repairs only with evidence.";
      break;
    case "state_read_error":
      plain = "Typed state could not be read cleanly. Refuse to guess; restore state-store integrity first.";
      break;
    case "rejected_buffer_present":
      plain = "Rejected-buffer entries present. Prior candidates failed gates; prefer narrow typed repairs.";
      break;
    case "no_window":
      plain = "No active Gate-4 window. Diagnosis has registry/rollback context only.";
      break;
    default:
      plain = "No halt condition detected from typed state records.";
  }

  return {
    schema_version: SCHEMA_VERSION,
    command: "--diagnose",
    diagnosis,
    plain_english: plain,
    evaluation_profile: EVAL_PROFILE_I3,
    // Loaders is the constitutional resolver for evolvable trees; surface
    // only presence, never raw appendix/prompt prose, into diagnosis.
    active_tree: tryActiveTreeMeta(root),
  };
}

function tryActiveTreeMeta(root) {
  try {
    if (typeof Loaders.resolveActive !== "function") return null;
    const ctx = Loaders.resolveActive(root);
    return {
      treeId: ctx.treeId || ctx.tree || null,
      /* deliberately omit content — content is untrusted data, not diagnosis input */
    };
  } catch (_) {
    return null;
  }
}

/* ---------------------------------------------------------------------------
 * Stage (NEVER applies live)
 * ------------------------------------------------------------------------- */

function stageRepair(opts) {
  const root = path.resolve((opts && opts.root) || process.cwd());
  const targetRelIn = opts && opts.target;
  if (!targetRelIn || typeof targetRelIn !== "string") {
    throw fail("target required for --stage", "INVALID_ARGUMENT");
  }

  const abs = ensureInsideRoot(root, path.resolve(root, targetRelIn));
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
    throw fail(`target missing: ${targetRelIn}`, "TARGET_NOT_FOUND");
  }
  const relPosix = toRepoRel(root, abs);
  const classifyRel = classifyRelForTarget(root, abs, relPosix);
  const classification = classifyTarget(classifyRel);
  // Belt-and-suspenders: basename on the request path too (case variants).
  if (!classification.is_manager && isManagerPath(relPosix)) {
    classification.repair_class = "code";
    classification.kind = "manager";
    classification.is_manager = true;
  }

  if (classification.is_manager) {
    throw fail(
      "Manager code is NEVER modified by heal in v0.2.0. Refuse to stage any change to manager.js.",
      "MANAGER_CODE_REFUSED"
    );
  }

  const beforeText = fs.readFileSync(abs, "utf8");
  const proposedText =
    opts.proposedContent === undefined || opts.proposedContent === null
      ? beforeText
      : String(opts.proposedContent);

  const diagnosis =
    opts.fromDiagnosis && typeof opts.fromDiagnosis === "object"
      ? opts.fromDiagnosis
      : createTypedEventReader(root).getTypedHaltDiagnosis();

  const capability = capabilityPolicyScan([beforeText, proposedText]);
  const beforeIdentity = targetTreeIdentity(root, relPosix);
  const evidence = Array.isArray(diagnosis.evidence) ? diagnosis.evidence.slice() : [];

  fs.mkdirSync(stagesDir(root), { recursive: true });

  if (classification.repair_class === "code") {
    const diff = computeUnifiedDiff(beforeText, proposedText, relPosix);
    const healId = stableId([
      "code",
      relPosix,
      sha256Text(beforeText).slice(0, 16),
      sha256Text(proposedText).slice(0, 16),
    ]);
    const record = {
      schema_version: SCHEMA_VERSION,
      heal_id: healId,
      repair_class: "code",
      kind: classification.kind,
      target: relPosix,
      is_manager: false,
      auto_apply_eligible: false,
      applied: false,
      evaluation_profile: null,
      evaluation_status: "staged-only-no-container-profile",
      diagnosis: {
        classification: diagnosis.classification,
        cause_code: diagnosis.cause_code,
        type: diagnosis.type,
      },
      diff,
      plain_english:
        "Code repair is STAGED-ONLY in v0.2.0 (no exceptions). Heal never applies executable changes. " +
        "A human must apply the diff, then verify with chaos. Manager code is never touched.",
      suggested_chaos: [
        "node scripts/chaos.js .",
        "node scripts/chaos.js --help",
      ],
      capability_policy: capability,
      before_sha256: sha256Text(beforeText),
      after_sha256: sha256Text(proposedText),
      target_tree_identity_before: beforeIdentity,
      evidence,
    };
    // Never write proposed executable bytes as an apply payload.
    writeJsonAtomic(stagePath(root, healId), record);
    assertFileUnchanged(abs, beforeText);
    return record;
  }

  // ---- typed path ----
  let boundsCheck = { checked: false, within_bounds: true, violations: [] };
  if (classification.kind === "tunables") {
    boundsCheck = tunablesWithinBounds(proposedText, loadTunablesBounds(root));
    if (boundsCheck.checked && !boundsCheck.within_bounds) {
      throw fail(
        `Tunables exceed frozen bounds: ${boundsCheck.violations.join(",")}`,
        "TUNABLES_BOUNDS_VIOLATION"
      );
    }
  }

  // Auto-apply eligibility requires: no external-call involvement (syntactic)
  // AND (if bounds checked) within bounds. Heal itself still never applies.
  const autoApplyEligible = capability.no_external_calls && boundsCheck.within_bounds;

  const healId = stableId([
    "typed",
    relPosix,
    sha256Text(beforeText).slice(0, 16),
    sha256Text(proposedText).slice(0, 16),
  ]);

  evidence.push({
    record_type: "I3_STANDARD_PROFILE",
    evaluation_profile: EVAL_PROFILE_I3,
    target: relPosix,
    kind: classification.kind,
    capability_policy: capability.policy,
    no_external_calls: capability.no_external_calls,
    tunables_bounds: boundsCheck,
  });

  const record = {
    schema_version: SCHEMA_VERSION,
    heal_id: healId,
    repair_class: "typed",
    kind: classification.kind,
    target: relPosix,
    is_manager: false,
    auto_apply_eligible: autoApplyEligible,
    applied: false,
    evaluation_profile: EVAL_PROFILE_I3,
    evaluation_status: autoApplyEligible ? "auto-apply-eligible" : "human-gated",
    diagnosis: {
      classification: diagnosis.classification,
      cause_code: diagnosis.cause_code,
      type: diagnosis.type,
    },
    before_sha256: sha256Text(beforeText),
    after_sha256: sha256Text(proposedText),
    before_content_base64: Buffer.from(beforeText, "utf8").toString("base64"),
    content_base64: Buffer.from(proposedText, "utf8").toString("base64"),
    target_tree_identity_before: beforeIdentity,
    capability_policy: capability,
    tunables_bounds: boundsCheck,
    plain_english: autoApplyEligible
      ? "Typed repair staged under I3-standard with evidence; capability policy shows no external-call involvement (auto-apply-eligible). Heal does not apply it."
      : "Typed repair staged under I3-standard with evidence; human-gated (capability policy saw external-call surface or bounds gating).",
    evidence,
  };

  writeJsonAtomic(stagePath(root, healId), record);
  assertFileUnchanged(abs, beforeText);
  return record;
}

function assertFileUnchanged(abs, expectedText) {
  const now = fs.readFileSync(abs, "utf8");
  if (now !== expectedText) {
    throw fail("heal mutated a live file during stage — invariant broken", "HEAL_MUTATION_INVARIANT");
  }
}

/* ---------------------------------------------------------------------------
 * Rollback — byte-exact via manifest tree identity; else human forward-recovery
 * ------------------------------------------------------------------------- */

function doRollback(healId, rootArg) {
  const root = path.resolve(rootArg || process.cwd());
  if (!healId || typeof healId !== "string") {
    throw fail("rollback requires <id>", "INVALID_ARGUMENT");
  }
  const sp = stagePath(root, healId);
  if (!fs.existsSync(sp)) {
    throw fail(`Unknown or incomplete heal id: ${healId}`, "ROLLBACK_NOT_FOUND");
  }
  const rec = readJson(sp);

  if (rec.repair_class === "code") {
    throw fail(
      "Rollback refused for code, migration, or non-pre-authorized change; preserve evidence and perform human forward-recovery",
      "FORWARD_RECOVERY_REQUIRED"
    );
  }

  if (rec.repair_class !== "typed") {
    throw fail(
      "Rollback refused; unknown repair class. Preserve evidence and perform human forward-recovery",
      "FORWARD_RECOVERY_REQUIRED"
    );
  }

  if (!rec.target || !rec.before_content_base64 || !rec.before_sha256 || !rec.after_sha256) {
    throw fail(
      "Rollback refused; staged record lacks byte-exact before/after identity. Preserve evidence and perform human forward-recovery",
      "FORWARD_RECOVERY_REQUIRED"
    );
  }

  const abs = ensureInsideRoot(root, path.resolve(root, rec.target));
  if (!fs.existsSync(abs)) {
    throw fail(
      "Rollback refused; target missing on disk. Preserve evidence and perform human forward-recovery",
      "FORWARD_RECOVERY_REQUIRED"
    );
  }

  const currentText = fs.readFileSync(abs, "utf8");
  const currentSha = sha256Text(currentText);

  // Only roll back when the live file still matches the staged after image
  // (i.e. the typed repair was applied), or already matches before (idempotent).
  const beforeBytes = Buffer.from(rec.before_content_base64, "base64");
  const beforeText = beforeBytes.toString("utf8");
  if (sha256Text(beforeText) !== rec.before_sha256) {
    throw fail(
      "Rollback refused; staged before image failed internal sha check. Preserve evidence and perform human forward-recovery",
      "FORWARD_RECOVERY_REQUIRED"
    );
  }

  if (currentSha === rec.before_sha256) {
    // Already at before image — idempotent success; still verify tree identity.
    const identity = targetTreeIdentity(root, rec.target);
    const ok =
      rec.target_tree_identity_before &&
      identity.tree_sha256 === rec.target_tree_identity_before.tree_sha256;
    if (!ok) {
      throw fail(
        "Rollback refused; not byte-exact on manifest tree identity. Preserve evidence and perform human forward-recovery",
        "FORWARD_RECOVERY_REQUIRED"
      );
    }
    return {
      schema_version: SCHEMA_VERSION,
      id: healId,
      state: "ALREADY_ROLLED_BACK",
      tree_identity_verified: true,
      explanation: "Target already matched before-image; manifest tree identity verified byte-exact.",
    };
  }

  if (currentSha !== rec.after_sha256) {
    throw fail(
      "Rollback refused; live file does not match staged after-image (divergent edit). Preserve evidence and perform human forward-recovery",
      "FORWARD_RECOVERY_REQUIRED"
    );
  }

  // Restore before bytes.
  fs.writeFileSync(abs, beforeBytes);

  const restoredSha = sha256Text(fs.readFileSync(abs));
  if (restoredSha !== rec.before_sha256) {
    throw fail(
      "Rollback refused; restore did not re-establish before sha. Preserve evidence and perform human forward-recovery",
      "FORWARD_RECOVERY_REQUIRED"
    );
  }

  const identity = targetTreeIdentity(root, rec.target);
  const treeOk =
    rec.target_tree_identity_before &&
    identity.tree_sha256 === rec.target_tree_identity_before.tree_sha256 &&
    identity.files &&
    identity.files[0] &&
    identity.files[0].sha256 === rec.before_sha256;

  if (!treeOk) {
    // Attempt to re-apply after image is impossible without after bytes always
    // present — content_base64 is the after image for typed repairs.
    if (rec.content_base64) {
      try {
        fs.writeFileSync(abs, Buffer.from(rec.content_base64, "base64"));
      } catch (_) {
        /* best-effort undo */
      }
    }
    throw fail(
      "Rollback refused; not byte-exact on manifest tree identity. Preserve evidence and perform human forward-recovery",
      "FORWARD_RECOVERY_REQUIRED"
    );
  }

  // Record rollback family (typed state only).
  try {
    const store = createStore(root);
    store.rollbackFamilies.append({
      fingerprint: healId,
      family: "heal-typed",
      evidence: {
        restored_target: rec.target,
        before_sha256: rec.before_sha256,
        tree_sha256: identity.tree_sha256,
      },
    });
  } catch (_) {
    // Non-fatal for the file restore; still report verified rollback.
  }

  return {
    schema_version: SCHEMA_VERSION,
    id: healId,
    state: "ROLLED_BACK",
    tree_identity_verified: true,
    explanation:
      "Byte-exact restore of typed repair verified via manifest tree identity (target file sha + tree_sha256).",
  };
}

/* ---------------------------------------------------------------------------
 * Selftest — must PROVE staged-only + manager refuse + typed/code split
 * ------------------------------------------------------------------------- */

function selftest() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-heal-selftest-"));
  const prior = process.env.GRAPHSMITH_TEST_MODE;
  process.env.GRAPHSMITH_TEST_MODE = "1";
  const results = [];
  const rec = (name, pass, detail) => {
    results.push({ name, pass: !!pass, detail: detail || "" });
    process.stderr.write(`${pass ? "PASS" : "FAIL"} ${name}${detail ? ` ${detail}` : ""}\n`);
  };

  try {
    const pr = path.join(base, "proj");
    fs.mkdirSync(path.join(pr, "workers"), { recursive: true });
    fs.mkdirSync(path.join(pr, "scenarios"), { recursive: true });

    const promptRel = "workers/gather.prompt.md";
    const promptAbs = path.join(pr, "workers", "gather.prompt.md");
    fs.writeFileSync(promptAbs, "You are gather. Do safe work only.\n");

    const tunAbs = path.join(pr, "tunables.json");
    fs.writeFileSync(tunAbs, "{\n  \"limit\": 2\n}\n");

    const scenarioAbs = path.join(pr, "scenarios", "smoke.json");
    fs.writeFileSync(scenarioAbs, "{\n  \"id\": \"smoke\"\n}\n");

    const codeAbs = path.join(pr, "worker-step.js");
    fs.writeFileSync(codeAbs, "module.exports.run = async () => 1;\n");

    const mgrAbs = path.join(pr, "manager.js");
    fs.writeFileSync(mgrAbs, "console.log(\"manager\");\n");

    const shaP0 = sha256Text(fs.readFileSync(promptAbs, "utf8"));
    const shaC0 = sha256Text(fs.readFileSync(codeAbs, "utf8"));
    const shaM0 = sha256Text(fs.readFileSync(mgrAbs, "utf8"));
    const shaT0 = sha256Text(fs.readFileSync(tunAbs, "utf8"));

    // Seed typed halt state via state-store.
    const st = createStore(pr);
    st.window.admitPending({ txid: "heal-selftest-tx", fingerprint: "fp-heal", tree_id: "v-healtest", n: 1 });
    const lk = st._testing.acquireLock();
    try {
      st._commit([
        {
          file: "window.json",
          make: (raw, rv) => {
            const v = JSON.parse(raw);
            v.state = "HALT_HUMAN";
            v.state_rev = rv;
            return JSON.stringify(v);
          },
        },
      ]);
    } finally {
      clearInterval(lk.heartbeat);
      st._testing.releaseLock(lk.ownerToken);
    }

    const dg = diagnose(pr);
    rec(
      "diagnose-uses-typed-adapter",
      dg.diagnosis &&
        dg.diagnosis.raw_source === "state-store.typed-records+adapter" &&
        dg.diagnosis.prose_logs_consulted === false
    );
    rec(
      "diagnose-classifies-from-window",
      dg.diagnosis &&
        (dg.diagnosis.classification === "HALT_HUMAN" || dg.diagnosis.cause_code === "halt_human")
    );
    rec(
      "diagnose-evidence-is-typed-only",
      Array.isArray(dg.diagnosis.evidence) &&
        dg.diagnosis.evidence.every((e) => e && typeof e.record_type === "string")
    );

    const typedProposed = "You are gather. Fixed prompt text.\n";
    const stTyped = stageRepair({
      root: pr,
      target: promptRel,
      proposedContent: typedProposed,
      fromDiagnosis: dg.diagnosis,
    });
    rec(
      "typed-stages-evidence-present",
      stTyped.repair_class === "typed" &&
        Array.isArray(stTyped.evidence) &&
        stTyped.evidence.some((e) => e.record_type === "I3_STANDARD_PROFILE") &&
        stTyped.evaluation_profile === EVAL_PROFILE_I3
    );
    rec("typed-marks-eligibility", typeof stTyped.auto_apply_eligible === "boolean");
    rec("typed-never-mutates-file", sha256Text(fs.readFileSync(promptAbs, "utf8")) === shaP0);
    rec("typed-never-sets-applied", stTyped.applied === false);

    // External-call surface in proposed typed content → human-gated.
    const stGated = stageRepair({
      root: pr,
      target: "tunables.json",
      proposedContent: "{\n  \"limit\": 2,\n  \"note\": \"fetch(http://x)\"\n}\n",
    });
    rec("typed-external-call-human-gated", stGated.auto_apply_eligible === false);

    const stCode = stageRepair({
      root: pr,
      target: "worker-step.js",
      proposedContent: "module.exports.run = async () => 99;\n",
      fromDiagnosis: dg.diagnosis,
    });
    rec(
      "code-stages-only-diff",
      stCode.repair_class === "code" &&
        typeof stCode.diff === "string" &&
        stCode.diff.includes("worker-step.js") &&
        !Object.prototype.hasOwnProperty.call(stCode, "content_base64") &&
        stCode.auto_apply_eligible === false
    );
    rec("code-never-mutates-exec", sha256Text(fs.readFileSync(codeAbs, "utf8")) === shaC0);
    rec(
      "code-emits-diagnosis-and-chaos",
      stCode.diagnosis &&
        typeof stCode.plain_english === "string" &&
        Array.isArray(stCode.suggested_chaos) &&
        stCode.suggested_chaos.some((c) => String(c).includes("chaos.js"))
    );

    let mgrRefused = false;
    try {
      stageRepair({ root: pr, target: "manager.js", proposedContent: "hacked();\n" });
    } catch (e) {
      mgrRefused = e.code === "MANAGER_CODE_REFUSED";
    }
    rec("refuses-manager-code", mgrRefused);
    rec("never-mutates-manager", sha256Text(fs.readFileSync(mgrAbs, "utf8")) === shaM0);

    // D1: case / extension / nested manager variants → REFUSED, never staged.
    fs.writeFileSync(path.join(pr, "manager.cjs"), "console.log('cjs');\n");
    fs.writeFileSync(path.join(pr, "manager.mjs"), "console.log('mjs');\n");
    fs.mkdirSync(path.join(pr, "nested"), { recursive: true });
    fs.writeFileSync(path.join(pr, "nested", "manager.js"), "console.log('nested');\n");
    // On case-sensitive FS these are distinct files still named as manager variants.
    const extraCaseFiles = ["MANAGER.js", "Manager.js", "nested/Manager.JS"];
    for (const rel of extraCaseFiles) {
      const absCase = path.join(pr, rel);
      try {
        fs.mkdirSync(path.dirname(absCase), { recursive: true });
        if (!fs.existsSync(absCase)) fs.writeFileSync(absCase, "console.log('case-variant');\n");
      } catch (_) {
        /* case-insensitive FS: collides with manager.js — still exercisable via that path */
      }
    }
    const caseTargets = [
      "manager.js",
      "MANAGER.js",
      "Manager.js",
      "MANAGER.JS",
      "manager.cjs",
      "manager.mjs",
      "nested/manager.js",
      "nested/Manager.JS",
    ];
    const mgrVariants = [];
    for (const t of caseTargets) {
      const tAbs = path.join(pr, t);
      if (!fs.existsSync(tAbs)) {
        // Path does not resolve on this FS layout; skip (classify unit-tested below).
        continue;
      }
      let refused = false;
      let staged = false;
      try {
        const r = stageRepair({ root: pr, target: t, proposedContent: "hacked();\n" });
        staged = !!(r && r.heal_id);
      } catch (e) {
        refused = e.code === "MANAGER_CODE_REFUSED";
      }
      mgrVariants.push(refused && !staged);
    }
    const classifyOnly = [
      "MANAGER.js",
      "Manager.js",
      "nested/foo/manager.cjs",
      "workers/manager.mjs",
      "Manager.BOX.js",
    ].every((p) => {
      const c = classifyTarget(p);
      return c.is_manager === true && c.kind === "manager";
    });
    rec(
      "refuses-manager-case-and-nested-variants",
      mgrVariants.length >= 4 && mgrVariants.every(Boolean) && classifyOnly
    );
    rec(
      "never-stages-manager-variants",
      sha256Text(fs.readFileSync(mgrAbs, "utf8")) === shaM0 &&
        sha256Text(fs.readFileSync(path.join(pr, "manager.cjs"), "utf8")) === sha256Text("console.log('cjs');\n") &&
        sha256Text(fs.readFileSync(path.join(pr, "nested", "manager.js"), "utf8")) ===
          sha256Text("console.log('nested');\n")
    );

    // D2: obfuscation / indirection ⇒ NOT auto-apply-eligible (fail-closed).
    const stFromChar = stageRepair({
      root: pr,
      target: promptRel,
      proposedContent:
        "const e = String.fromCharCode(101,120,101,99); globalThis[e]('whoami');\n",
    });
    rec("obfuscated-fromcharcode-not-eligible", stFromChar.auto_apply_eligible === false);

    const stConcat = stageRepair({
      root: pr,
      target: promptRel,
      proposedContent: "const r = 're'+'quire'; r('fs');\n",
    });
    rec("obfuscated-string-concat-not-eligible", stConcat.auto_apply_eligible === false);

    const stComputed = stageRepair({
      root: pr,
      target: promptRel,
      proposedContent: "const x = require('f' + 's');\nglobalThis['fetch']('https://x');\n",
    });
    rec("obfuscated-computed-require-not-eligible", stComputed.auto_apply_eligible === false);

    const stCleanStill = stageRepair({
      root: pr,
      target: promptRel,
      proposedContent: "You are gather. Plain safe prose only.\n",
    });
    rec("clean-typed-still-eligible", stCleanStill.auto_apply_eligible === true);

    // Simulate human applying the typed repair, then rollback byte-exact.
    fs.writeFileSync(promptAbs, typedProposed);
    let rb;
    try {
      rb = doRollback(stTyped.heal_id, pr);
    } catch (e) {
      rb = { err: e.code || e.message };
    }
    rec("typed-rollback-restore-byte-exact", sha256Text(fs.readFileSync(promptAbs, "utf8")) === shaP0);
    rec(
      "rollback-via-manifest-tree",
      !!(rb && rb.tree_identity_verified === true && /manifest tree identity/i.test(rb.explanation || ""))
    );

    let codeRbRefused = false;
    try {
      doRollback(stCode.heal_id, pr);
    } catch (e) {
      codeRbRefused =
        e.code === "FORWARD_RECOVERY_REQUIRED" &&
        /forward-recovery/i.test(e.message);
    }
    rec("code-rollback-refuses", codeRbRefused);

    // Divergent edit → refuse rollback (not byte-safe).
    fs.writeFileSync(promptAbs, typedProposed);
    fs.writeFileSync(promptAbs, "diverged content\n");
    let divergentRefused = false;
    try {
      doRollback(stTyped.heal_id, pr);
    } catch (e) {
      divergentRefused = e.code === "FORWARD_RECOVERY_REQUIRED";
    }
    // Restore for cleanliness
    fs.writeFileSync(promptAbs, "You are gather. Do safe work only.\n");
    rec("divergent-rollback-refuses", divergentRefused);

    const stageFiles = fs.existsSync(stagesDir(pr)) ? fs.readdirSync(stagesDir(pr)) : [];
    rec("stages-written-to-disk", stageFiles.filter((f) => f.endsWith(".staged.json")).length >= 3);

    // Final invariant: originals of code+manager untouched throughout.
    rec(
      "selftest-proves-exec-and-manager-untouched",
      sha256Text(fs.readFileSync(codeAbs, "utf8")) === shaC0 &&
        sha256Text(fs.readFileSync(mgrAbs, "utf8")) === shaM0 &&
        sha256Text(fs.readFileSync(tunAbs, "utf8")) === shaT0
    );

    const fin = results.every((x) => x.pass);
    rec("selftest-proves-all-constraints", fin);

    return {
      schema_version: SCHEMA_VERSION,
      status: fin ? "pass" : "fail",
      tests: results,
    };
  } finally {
    if (prior === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
    else process.env.GRAPHSMITH_TEST_MODE = prior;
    try {
      fs.rmSync(base, { recursive: true, force: true });
    } catch (_) {
      /* ignore */
    }
  }
}

/* ---------------------------------------------------------------------------
 * CLI
 * ------------------------------------------------------------------------- */

function printUsage() {
  process.stderr.write(
    "Usage: node scripts/heal.js --diagnose | --stage <target> [--proposed <file|inline>] | rollback <id> | --selftest [--root <dir>]\n"
  );
}

function parseRoot(argv) {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--root" && argv[i + 1]) return path.resolve(argv[i + 1]);
  }
  return process.cwd();
}

function parseProposed(argv) {
  const idx = argv.indexOf("--proposed");
  if (idx < 0 || !argv[idx + 1]) return null;
  const v = argv[idx + 1];
  if (fs.existsSync(v) && fs.statSync(v).isFile()) return fs.readFileSync(v, "utf8");
  return v;
}

function main(argv) {
  if (argv.includes("--selftest")) {
    const out = selftest();
    process.stdout.write(`${JSON.stringify(out)}\n`);
    process.exitCode = out.status === "pass" ? 0 : 1;
    return;
  }

  const root = parseRoot(argv);
  const cmd = argv[0];

  if (cmd === "--diagnose") {
    const r = diagnose(root);
    process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
    return;
  }

  if (cmd === "--stage") {
    const positionals = [];
    for (let i = 1; i < argv.length; i++) {
      if (argv[i] === "--root" || argv[i] === "--proposed") {
        i += 1;
        continue;
      }
      if (argv[i].startsWith("-")) continue;
      positionals.push(argv[i]);
    }
    const target = positionals[0];
    if (!target) {
      printUsage();
      process.exitCode = 2;
      return;
    }
    const proposed = parseProposed(argv);
    const r = stageRepair({
      root,
      target,
      proposedContent: proposed,
    });
    process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
    return;
  }

  if (cmd === "rollback") {
    const id = argv[1];
    if (!id || id.startsWith("-")) {
      printUsage();
      process.exitCode = 2;
      return;
    }
    const r = doRollback(id, root);
    process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
    return;
  }

  printUsage();
  process.exitCode = 2;
}

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    const code = e && e.code ? e.code : null;
    process.stderr.write(`${code ? `${code}: ` : "ERROR: "}${e.message}\n`);
    if (
      code === "MANAGER_CODE_REFUSED" ||
      code === "FORWARD_RECOVERY_REQUIRED" ||
      code === "TUNABLES_BOUNDS_VIOLATION" ||
      code === "INVALID_ARGUMENT" ||
      code === "TARGET_NOT_FOUND"
    ) {
      process.exitCode = 2;
    } else {
      process.exitCode = 1;
    }
  }
}

module.exports = {
  diagnose,
  stageRepair,
  doRollback,
  createTypedEventReader,
  classifyTarget,
  capabilityPolicyScan,
  selftest,
  SCHEMA_VERSION,
};
