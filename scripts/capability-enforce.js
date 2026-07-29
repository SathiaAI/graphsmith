#!/usr/bin/env node
/* scripts/capability-enforce.js — turn a per-skill capability grant into
 * ENFORCEMENT, or refuse.
 *
 * WHY THIS EXISTS
 *
 * KNOWN-LIMITATIONS.md §6 says per-skill filesystem / model / subprocess grants
 * are "not enforced per skill in v0.3.0". That is true, and it is only half the
 * story. The VERIFICATION side of per-skill capabilities is already complete:
 *
 *   schemas/capability-grant.schema.json   the grant format, deny-by-default
 *   checks/v040-caps.js                    recomputes requested ⊆ granted, and
 *                                          holds the D1 honesty line: a class may
 *                                          be attested only if it is in `enforced`
 *
 * What was missing is anything that can legitimately PUT a class into `enforced`.
 * `enforced` was an input nobody produced — so in practice only `network` (the
 * supervisor's destination allowlist) could ever honestly appear there, and the
 * schema's careful D1 line guarded a door with no building behind it.
 *
 * This module is that building, for the two classes an OS mechanism can actually
 * carry. It converts a grant into argv for Node's Permission Model, or refuses
 * with a specific reason. It never returns a partial enforcement silently.
 *
 * WHAT IS ACTUALLY ENFORCED, AND HOW IT WAS ESTABLISHED
 *
 * Every claim below was measured on Node v22.22.2, not read from documentation.
 * The same probes ship as tests/capability-enforce/run-tests.js so they re-run
 * on every platform CI touches rather than being a one-time note in a commit.
 *
 *   filesystem   ENFORCEABLE, with a precondition (see SYMLINK PRECONDITION).
 *                --allow-fs-read / --allow-fs-write are path-scoped and
 *                segment-safe: a grant of ".../inputs" does NOT admit
 *                ".../inputs-evil" (measured, all three grant spellings).
 *                Escape attempts that FAILED: "..", process.binding("fs"),
 *                eval-then-require, and NODE_OPTIONS=--no-permission in the
 *                child's own environment. All ERR_ACCESS_DENIED.
 *
 *   subprocess   ENFORCEABLE ONLY AS DENY-ALL. Under --permission,
 *                child_process and worker_threads are denied by default, which
 *                is a real, measured deny-all. But --allow-child-process has NO
 *                per-executable granularity -- it is one boolean for every
 *                executable on the box. Node says so itself; passing it prints
 *                "SecurityWarning: ... It could invalidate the permission model."
 *
 *                So a grant of subprocess.allowed = [] is enforceable and is
 *                enforced. A grant of subprocess.allowed = ["git"] is NOT, and
 *                this module REFUSES it rather than passing --allow-child-process
 *                and reporting the class enforced. Honouring "git only" by
 *                granting every executable would be the exact fail-open shape
 *                D1 exists to forbid: attesting a boundary that is not there.
 *
 *   model        NOT ENFORCEABLE HERE, and never claimed. There is no OS
 *                mechanism for "which model may this skill call" -- it needs a
 *                chokepoint in the model adapter, which is a different layer.
 *                This module never places `model` in `enforced`.
 *
 *   network      OUT OF SCOPE. Already enforced elsewhere (supervisor
 *                destination allowlist; --network none in the container
 *                profile). Not re-claimed here; double-claiming a control from
 *                two places is how an unenforced one survives the removal of
 *                the other.
 *
 * SYMLINK PRECONDITION -- the finding that makes or breaks the filesystem claim
 *
 * The Permission Model resolves the path it is GIVEN. A symlink that already
 * exists inside the granted tree and points outside it is followed, and the read
 * succeeds. Measured, both spellings:
 *
 *     <grant>/escape-link/secret.txt  -> read a file outside the grant. ALLOWED.
 *     <grant>/passwd-link             -> read /etc/passwd.              ALLOWED.
 *
 * Wiring --permission without accounting for that would produce a confident,
 * FALSE enforcement claim -- strictly worse than the honest "not enforced" this
 * module is replacing, because it would be attested in a bundle.
 *
 * What saves it is that the hole is bounded to symlinks PRESENT WHEN THE PROCESS
 * STARTS. A skill cannot create one at runtime: symlinkSync and linkSync with a
 * target outside the write grant are both ERR_ACCESS_DENIED (measured). There is
 * no TOCTOU window.
 *
 * So the filesystem claim is sound exactly when the granted tree is verified
 * symlink-clean beforehand -- which evalenv.js already does, for this reason,
 * under contract 04 B14: checkIsolation() walks the copy, realpath()s every
 * symlink, and reports symlink_escapes. This module REQUIRES that evidence and
 * refuses the filesystem class without it. The two controls compose; neither is
 * sufficient alone, and that is stated rather than assumed.
 *
 * FAIL-CLOSED POSTURE
 *
 * Every uncertainty resolves to "not enforceable": an older runtime, a missing
 * flag, absent or stale isolation evidence, a malformed grant, a request this
 * mechanism cannot express. The caller then has exactly two honest options --
 * do not run the skill, or run it and attest nothing for that class. What the
 * caller must never get from here is argv that looks like enforcement and isn't.
 *
 * Deterministic: no clock, no randomness, no network. Pure function of (grant,
 * targetDir, isolation, runtime flag set). Zero-dep CJS, Node >= 18.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const SCHEMA_VERSION = "1.0";

/* The classes this module can carry. `model` and `network` are deliberately
 * absent -- see the header. Listing them here would be the whole bug. */
const ENFORCEABLE_CLASSES = ["filesystem", "subprocess"];

/* Node flags required per class. Detected against the RUNNING runtime via
 * process.allowedNodeEnvironmentFlags rather than inferred from process.version:
 * a version string tells you what Node claims to be, not what this build
 * supports. */
const REQUIRED_FLAGS = {
  filesystem: ["--permission", "--allow-fs-read", "--allow-fs-write"],
  subprocess: ["--permission"],
};

function detectFlags(flagSet) {
  const set = flagSet || (() => {
    try { return process.allowedNodeEnvironmentFlags; } catch (e) { return null; }
  })();
  const has = (name) => !!(set && typeof set.has === "function" && set.has(name));
  return {
    permission: has("--permission"),
    allow_fs_read: has("--allow-fs-read"),
    allow_fs_write: has("--allow-fs-write"),
    allow_child_process: has("--allow-child-process"),
    allow_worker: has("--allow-worker"),
    _has: has,
  };
}

/* A granted path is usable only if it is absolute and free of "." / ".."
 * segments. Same canonical-path rule checks/v040-caps.js applies to REQUESTED
 * paths -- applied here to GRANTED ones so a grant cannot smuggle in a
 * traversal that the request-side check would have caught. */
function canonicalAbsolute(p) {
  if (typeof p !== "string" || p.length === 0) return null;
  if (p.indexOf("\u0000") !== -1) return null;
  const segs = p.split(/[\\/]/);
  if (segs.some((s) => s === "." || s === "..")) return null;
  if (!path.isAbsolute(p)) return null;
  return p;
}

/* Is `p` the target dir, or strictly under it? Segment-boundary containment, so
 * a grant of "/copy" never admits "/copy-evil". */
function isInside(root, p) {
  const r = path.resolve(root);
  const q = path.resolve(p);
  return q === r || q.startsWith(r.endsWith(path.sep) ? r : r + path.sep);
}

/* ---------------------------------------------------------------------------
 * plan(ctx) -> enforcement plan, or a refusal with a reason per class.
 *
 * ctx = {
 *   grant:     a capability-grant (schemas/capability-grant.schema.json)
 *   targetDir: the directory the skill will run in -- every granted filesystem
 *              path must lie within it, so a grant cannot widen the blast
 *              radius past the disposable copy it was issued for
 *   isolation: evalenv checkIsolation() output for targetDir. REQUIRED for the
 *              filesystem class (symlink precondition). Absent => refused.
 *   flags:     optional Set-like override, for testing a runtime other than the
 *              one running this file
 * }
 * ------------------------------------------------------------------------- */
function plan(ctx) {
  const refusals = [];
  const enforced = [];
  const argv = [];
  const notes = [];

  const refuse = (cls, reason) => { refusals.push({ class: cls, reason }); };

  if (!ctx || typeof ctx !== "object") {
    return result([], [], [{ class: "*", reason: "no context supplied" }], []);
  }
  const grant = ctx.grant;
  if (!grant || typeof grant !== "object" || grant.schema_version !== SCHEMA_VERSION) {
    return result([], [], [{ class: "*", reason: "capability-grant missing or not schema_version " + SCHEMA_VERSION }], []);
  }
  const targetDir = canonicalAbsolute(ctx.targetDir || "");
  if (!targetDir) {
    return result([], [], [{ class: "*", reason: "targetDir must be an absolute, canonical path (no '.'/'..' segment, no NUL)" }], []);
  }

  /* targetDir must BE its own realpath, or the grant is unenforceable.
   *
   * Node's module loader calls realpathSync on the entry script before running it
   * (internal/modules/helpers toRealPath -> Function._findPath). Under --permission
   * that resolution is itself subject to the grant. So if targetDir is reached
   * through a symlink, the resolved path lies outside every granted prefix and the
   * child dies at startup with:
   *
   *     Error: Access to this API has been restricted. Use --allow-fs-read ...
   *         at Object.realpathSync (node:fs)
   *
   * before a single line of it runs. Not hypothetical: this is exactly what happened
   * on macOS CI, where os.tmpdir() is /var/folders/... and /var is a symlink to
   * /private/var. It passed on Linux, where /tmp is a real directory, and failed on
   * every macOS leg -- a grant that looks correct, emits plausible argv, and produces
   * a process that cannot start.
   *
   * Refusing here beats emitting that argv. The caller gets a specific, actionable
   * reason instead of a child that dies with a message pointing at the wrong thing. */
  let realTarget = null;
  try { realTarget = fs.realpathSync(targetDir); } catch (e) { realTarget = null; }
  if (realTarget === null) {
    return result([], [], [{ class: "*", reason: "targetDir does not exist or cannot be resolved: " + targetDir }], []);
  }
  if (path.resolve(realTarget) !== path.resolve(targetDir)) {
    return result([], [], [{
      class: "*",
      reason: "targetDir is reached through a symlink (" + targetDir + " -> " + realTarget + "). Node resolves " +
        "the entry script with realpathSync BEFORE running it, and under --permission that resolution is subject " +
        "to the grant -- so the child would be denied at startup, before running. Pass the resolved path " +
        "(fs.realpathSync) as targetDir and grant paths beneath it",
    }], []);
  }

  const flags = detectFlags(ctx.flags);
  const grants = (grant.grants && typeof grant.grants === "object") ? grant.grants : {};

  /* ---- filesystem ------------------------------------------------------- */
  (function filesystem() {
    const CLS = "filesystem";
    const missing = REQUIRED_FLAGS[CLS].filter((f) => !flags._has(f));
    if (missing.length) {
      return refuse(CLS, "this runtime (" + process.version + ") does not recognise " + missing.join(", ") +
        " -- the Permission Model cannot be applied, so no filesystem boundary is enforced");
    }

    /* The symlink precondition. Refuse on absent evidence as firmly as on bad
     * evidence: "nobody checked" and "the check failed" are the same amount of
     * knowledge about whether a symlink escapes, and both are less than enough. */
    const iso = ctx.isolation;
    if (!iso || typeof iso !== "object" || !Array.isArray(iso.symlink_escapes)) {
      return refuse(CLS, "no symlink audit supplied for targetDir. A symlink that ALREADY EXISTS inside a " +
        "granted tree and points outside it is followed by the Permission Model and the read succeeds " +
        "(measured), so --allow-fs-read alone is not a filesystem boundary. Pass evalenv checkIsolation() " +
        "evidence (contract 04 B14) for this directory");
    }

    /* The evidence must describe THIS directory. The caller supplying it is the
     * party being checked, so without this an audit of directory A -- clean, real,
     * honestly produced -- authorises enforcement of directory B, which nobody
     * looked at. A precondition that does not name its subject is not a
     * precondition. Older evidence without `audited_dir` is refused rather than
     * assumed to match: absent provenance is not matching provenance. */
    if (typeof iso.audited_dir !== "string" || iso.audited_dir.length === 0) {
      return refuse(CLS, "isolation evidence carries no `audited_dir`, so there is nothing to prove it " +
        "describes this targetDir rather than some other directory. Re-run evalenv checkIsolation() " +
        "against " + targetDir);
    }
    if (path.resolve(iso.audited_dir) !== path.resolve(targetDir)) {
      return refuse(CLS, "isolation evidence describes " + iso.audited_dir + ", not targetDir " + targetDir +
        ". An audit of one directory cannot authorise enforcement of another");
    }

    if (iso.symlink_escapes.length > 0) {
      return refuse(CLS, iso.symlink_escapes.length + " symlink(s) inside targetDir resolve OUTSIDE it, and the " +
        "Permission Model follows them. Enforcing here would attest a boundary the tree already defeats. First: " +
        JSON.stringify(iso.symlink_escapes[0]).slice(0, 200));
    }

    /* Hardlinks. A second NAME for the same inode resolves inside the copy, so the
     * symlink walk sees nothing -- but a WRITE through it lands outside. Measured:
     * a grant scoped entirely to the copy overwrote a file outside it while the
     * isolation report said clean. Required, and absent evidence is refused: an
     * audit that did not look for hardlinks cannot certify their absence. */
    if (!Array.isArray(iso.hardlink_suspects)) {
      return refuse(CLS, "isolation evidence has no `hardlink_suspects` array, so the tree was audited for " +
        "symlinks only. A pre-existing HARDLINK is a second name for the same inode: it resolves inside the " +
        "copy, passes the symlink walk, and a write through it modifies a file OUTSIDE the grant (measured). " +
        "Re-run evalenv checkIsolation() from a build that performs the hardlink audit");
    }
    if (iso.hardlink_suspects.length > 0) {
      return refuse(CLS, iso.hardlink_suspects.length + " file(s) inside targetDir have st_nlink > 1 (or could " +
        "not be stat'd). Each is a second name for an inode this copy does not exclusively own, and a write " +
        "through one leaves the grant. First: " + JSON.stringify(iso.hardlink_suspects[0]).slice(0, 200));
    }

    const fsGrant = grants[CLS];
    if (!fsGrant || typeof fsGrant !== "object") {
      return refuse(CLS, "no filesystem grant present (deny-by-default). Nothing is claimed for this class");
    }

    const collect = (list, kind) => {
      if (list === undefined || list === null) return [];
      if (!Array.isArray(list)) return null;
      const out = [];
      for (const raw of list) {
        const p = canonicalAbsolute(raw);
        if (!p) return null;
        /* A granted path outside the disposable copy is refused outright. The
         * grant is issued FOR that copy; honouring a path beyond it would let a
         * grant quietly re-scope itself. */
        if (!isInside(targetDir, p)) {
          refuse(CLS, "granted " + kind + " path " + JSON.stringify(String(raw).slice(0, 120)) +
            " lies outside targetDir -- a grant may not widen past the copy it was issued for");
          return null;
        }
        out.push(p);
      }
      return out;
    };

    const reads = collect(fsGrant.read, "read");
    if (reads === null) return refusals.some((r) => r.class === CLS) ? undefined :
      refuse(CLS, "filesystem.read is not a list of absolute canonical paths -- unreadable grant, refused rather than coerced");
    const writes = collect(fsGrant.write, "write");
    if (writes === null) return refusals.some((r) => r.class === CLS) ? undefined :
      refuse(CLS, "filesystem.write is not a list of absolute canonical paths -- unreadable grant, refused rather than coerced");

    /* The runtime needs at least the entry script readable to start at all. A
     * grant of nothing readable is a grant that cannot run; say so rather than
     * emitting argv that fails confusingly at exec time. */
    if (reads.length === 0 && writes.length === 0) {
      return refuse(CLS, "filesystem grant is present but empty. Deny-all is the default WITHOUT --permission " +
        "argv; emitting flags here would suggest an enforced envelope where the honest statement is 'this skill " +
        "was granted no filesystem access and therefore cannot run'");
    }

    argv.push("--permission");
    for (const p of reads) argv.push("--allow-fs-read=" + p);
    for (const p of writes) argv.push("--allow-fs-write=" + p);
    enforced.push(CLS);
    notes.push("filesystem: " + reads.length + " read path(s), " + writes.length + " write path(s), " +
      "all within targetDir, tree verified symlink-clean (" + (iso.symlinks_skipped_at_copy || 0) +
      " symlink(s) skipped at copy, 0 escaping)");
  })();

  /* ---- subprocess ------------------------------------------------------- */
  (function subprocess() {
    const CLS = "subprocess";
    if (!flags._has("--permission")) {
      return refuse(CLS, "this runtime (" + process.version + ") does not recognise --permission, so " +
        "child_process and worker_threads are not denied");
    }
    const spGrant = grants[CLS];
    const allowed = spGrant && Array.isArray(spGrant.allowed) ? spGrant.allowed : null;

    if (spGrant && !allowed) {
      return refuse(CLS, "subprocess grant present but `allowed` is not a list -- unreadable, refused rather than coerced");
    }
    if (allowed && allowed.length > 0) {
      /* THE honesty case. Node's --allow-child-process is a single boolean over
       * every executable on the machine; it cannot express "git only". Passing
       * it to honour a one-entry allowlist would grant all of them while
       * reporting the class enforced. Node itself flags this: using the flag
       * prints "SecurityWarning: ... It could invalidate the permission model."
       * Refuse, and name the alternative rather than leaving the caller stuck. */
      return refuse(CLS, "grant allows " + allowed.length + " specific executable(s) (" +
        allowed.slice(0, 3).map((s) => JSON.stringify(String(s).slice(0, 40))).join(", ") +
        "), but --allow-child-process has NO per-executable granularity -- it is one boolean over every " +
        "executable on the box, and Node itself warns it 'could invalidate the permission model'. Enforcing " +
        "this grant would mean granting all of them while reporting the class enforced, which is the fail-open " +
        "shape D1 forbids. Enforceable options: an empty allowlist (deny-all, enforced here), or a broker " +
        "process outside this mechanism that owns the allowlist itself");
    }

    /* allowed === [] (explicit deny-all) or the class is absent entirely
     * (deny-by-default). Both are honestly enforced by --permission WITHOUT
     * --allow-child-process / --allow-worker. Measured: child_process.execSync
     * and new Worker() are both ERR_ACCESS_DENIED. */
    if (argv.indexOf("--permission") === -1) argv.push("--permission");
    enforced.push(CLS);
    notes.push("subprocess: deny-all" + (allowed ? " (explicit empty allowlist)" : " (class absent -- deny-by-default)") +
      ". child_process and worker_threads are denied by --permission; neither --allow-child-process nor " +
      "--allow-worker is passed");
  })();

  /* ---- classes this module must never claim ----------------------------- */
  if (grants.model) {
    refuse("model", "no OS mechanism exists for per-skill model restriction; it requires a chokepoint in the " +
      "model adapter, a different layer. Declared, deliberately NOT attested (D1)");
  }
  if (grants.network) {
    notes.push("network: not claimed here. Enforced elsewhere (supervisor destination allowlist; --network none " +
      "under the container profile) and deliberately not re-claimed, so removing one control cannot leave the " +
      "other's attestation standing");
  }

  return result(argv, enforced, refusals, notes);
}

function result(argv, enforced, refusals, notes) {
  return {
    schema_version: SCHEMA_VERSION,
    /* argv to prepend to the child's node invocation. Empty => nothing is
     * enforced by this mechanism; that is a valid, honest outcome. */
    argv,
    /* Exactly what may be written to a capability-grant's `enforced` array and
     * therefore attested. Never includes a class that was refused. */
    enforced: enforced.slice().sort(),
    /* Why each unclaimed class is unclaimed. Present so a caller reporting
     * "not enforced" can say which boundary and why, instead of a bare false. */
    refusals,
    notes,
    /* Convenience: did anything at all get enforced? */
    any: enforced.length > 0,
  };
}

/* Sanity guard: the module must never return a class outside ENFORCEABLE_CLASSES,
 * whatever the input. Cheap, and it turns a future editing mistake into a throw
 * at the call site rather than a false attestation in a signed bundle. */
function planChecked(ctx) {
  const r = plan(ctx);
  for (const c of r.enforced) {
    if (ENFORCEABLE_CLASSES.indexOf(c) === -1) {
      throw new Error("capability-enforce: refusing to report class '" + c + "' as enforced -- this module can " +
        "only carry " + ENFORCEABLE_CLASSES.join("/") + ". This is a bug in capability-enforce.js, not in the grant.");
    }
  }
  return r;
}

module.exports = {
  SCHEMA_VERSION,
  ENFORCEABLE_CLASSES,
  REQUIRED_FLAGS,
  plan: planChecked,
  detectFlags,
  canonicalAbsolute,
  isInside,
};
