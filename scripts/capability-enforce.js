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

/* auditTree(root) — walk `root` and report the two escape shapes the Permission
 * Model does not stop by itself.
 *
 * PHYSICAL, not lexical, and that distinction is the whole point of this function
 * existing separately from evalenv.checkIsolation(). checkIsolation computes its
 * own `audited_dir` with path.resolve() -- which collapses ".." lexically -- while
 * walking the path with readdir, which the kernel resolves physically. Given a
 * symlink component followed by "..", those two disagree: `<dir>/A/../real`
 * lexically equals `<dir>/real`, but if `A` is a symlink the kernel reads a
 * different directory entirely. An adversarial reviewer used exactly that to get a
 * clean audit for a tree nobody walked.
 *
 * Here `root` is already fs.realpathSync()'d by the caller, and every descendant is
 * re-resolved rather than rebuilt with path.join, so the thing audited and the thing
 * named are the same thing by construction.
 *
 * What it looks for:
 *   symlink escape  -- a link whose realpath leaves the tree. The Permission Model
 *                      follows it; measured reading /etc/passwd through one.
 *   hardlink        -- st_nlink > 1 on a regular file. A second NAME for the same
 *                      inode, so realpath stays inside and the symlink walk sees
 *                      nothing, but a WRITE through it lands outside. Fresh copies
 *                      have nlink 1, so anything higher is an anomaly and fails
 *                      closed; proving WHERE the other name is would mean scanning
 *                      the filesystem for the inode.
 * An unreadable directory or unstattable file is an ERROR, not a clean result. */
function auditTree(root) {
  const symlink_escapes = [];
  const hardlink_suspects = [];
  let error = null;

  const inside = (p) => {
    const r = path.resolve(root);
    const q = path.resolve(p);
    return q === r || q.startsWith(r.endsWith(path.sep) ? r : r + path.sep);
  };

  /* st_dev of the root. A bind mount inside the tree is a real directory whose
   * realpath is inside, so nothing above notices it -- but it sits on a DIFFERENT
   * device, and that is cheap to see. Measured: a bind mount of an outside
   * directory onto a granted path gave error:null, 0 suspects, filesystem enforced,
   * and a child that read and wrote outside targetDir entirely. */
  let rootDev = null;
  try { rootDev = fs.lstatSync(root).dev; } catch (e) { /* handled by the walk */ }

  /* st_dev alone is NOT enough, and I checked rather than assumed: a bind mount
   * within the SAME filesystem keeps the same device number.
   *
   *     stat -c %D  <grant>/inputs        -> fe00
   *     stat -c %D  <grant>/inputs/sub    -> fe00   (bind mount of an outside dir)
   *
   * So the dev check catches only cross-filesystem mounts. /proc/self/mountinfo is
   * the signal that actually works on Linux -- every mount point appears there with
   * its mount target as a field. Read once per audit.
   *
   * Where mountinfo does not exist (macOS, Windows) this returns an empty set and
   * same-filesystem bind mounts are NOT detected. That is a real, stated gap rather
   * than a silent one: it needs privileges to create, so the adversary who can do it
   * can generally do worse, but it is not covered and should not be implied to be. */
  const mountTargets = (function readMounts() {
    try {
      const out = new Set();
      for (const line of fs.readFileSync("/proc/self/mountinfo", "utf8").split("\n")) {
        const f = line.split(" ");
        if (f.length > 4 && f[4]) out.add(path.resolve(f[4]));
      }
      return out;
    } catch (e) {
      return null; // no mountinfo on this platform
    }
  })();

  (function walk(dir, depth) {
    if (error) return;
    if (depth > 64) { error = "directory nesting deeper than 64 levels at " + dir; return; }
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      error = "cannot read " + dir + ": " + String((e && e.code) || e);
      return;
    }
    for (const entry of entries) {
      if (error) return;
      const p = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        let real = null;
        try { real = fs.realpathSync(p); } catch (e) { continue; } // dangling: inert
        if (!inside(real)) symlink_escapes.push({ path: p, target: real });
        continue;
      }
      let st;
      try { st = fs.lstatSync(p); } catch (e) {
        hardlink_suspects.push({ path: p, nlink: null, error: String((e && e.code) || e) });
        continue;
      }
      if (mountTargets && mountTargets.has(path.resolve(p)) && path.resolve(p) !== path.resolve(root)) {
        hardlink_suspects.push({
          path: p,
          nlink: null,
          error: "is a MOUNT POINT inside the tree (per /proc/self/mountinfo). Its contents come from " +
            "somewhere this audit cannot vouch for -- a bind mount of an outside directory presents as an " +
            "ordinary directory of nlink-1 files and keeps the same st_dev on the same filesystem",
        });
        continue;
      }
      if (rootDev !== null && st.dev !== rootDev) {
        hardlink_suspects.push({
          path: p,
          nlink: null,
          error: "sits on a different filesystem (st_dev " + String(st.dev) + " vs root " + String(rootDev) +
            ") -- a mount point inside the tree, whose contents this audit cannot vouch for",
        });
        continue;
      }
      if (st.isDirectory()) {
        /* Descend into the REAL directory. Re-resolving here is what stops a
         * symlinked component from being collapsed away by path.join on the way
         * down -- the mixture-of-two-trees walk the reviewer exploited. */
        let realDir = null;
        try { realDir = fs.realpathSync(p); } catch (e) { realDir = null; }
        if (realDir && inside(realDir)) walk(realDir, depth + 1);
        continue;
      }
      if (st.isFile()) {
        if (st.nlink > 1) hardlink_suspects.push({ path: p, nlink: st.nlink });
        continue;
      }
      /* ANYTHING ELSE fails closed. This used to fall off the bottom of the loop
       * with no suspect and no error, so a FIFO, a socket, or a device node inside
       * a granted path was silently fine -- and so was a BIND MOUNT, which presents
       * as an ordinary directory of nlink-1 files whose realpath is inside the tree.
       * A reviewer used one to escape past targetDir entirely with a clean audit.
       *
       * A bind mount is not distinguishable from a real directory by lstat alone
       * (it needs st_dev comparison or /proc/self/mountinfo), so the device check
       * below is what catches it; this branch catches the rest. Either way the rule
       * is the same: a disposable source copy contains regular files, directories
       * and nothing else, so anything else is an anomaly and is refused rather than
       * ignored. */
      hardlink_suspects.push({
        path: p,
        nlink: null,
        error: "unexpected file type in a source copy (not a regular file, directory or symlink)",
      });
    }
  })(root, 0);

  return { root, symlink_escapes, hardlink_suspects, error };
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
  let auditPerformed = null;
  const auditedPaths = [];
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

    /* THE AUDIT IS PERFORMED HERE, NOW, BY THIS MODULE. It is not supplied.
     *
     * The previous design took a caller-provided `isolation` object. Two adversarial
     * reviews broke it, and the second one broke it through the product's own entry
     * points with completely honest, unedited evidence:
     *
     *     evalenv.create()        -> hardlink_suspects: []  isolated: true   (true!)
     *     attacker plants a hardlink AFTER the audit
     *     plan(..., isolation)    -> enforced: [filesystem, subprocess]  refusals: 0
     *     child writes through it -> a file OUTSIDE the copy reads "PWNED"
     *
     * checkIsolation ran once, at create time, on a tree that is clean BY
     * CONSTRUCTION (copyFileSync always yields nlink 1; symlinks are skipped). So
     * the evidence was accurate when produced and worthless when used, and nothing
     * re-checked. The evidence was also forgeable by spelling: a caller could audit
     * `<dir>/A/../real`, which resolves lexically to targetDir but reads a different
     * tree physically, and get a clean report for a directory nobody walked.
     *
     * Both die the same way: the module that grants enforcement now does its own
     * looking, against its own resolved path, at the moment of the decision. There
     * is no evidence parameter left to be stale, forged, or about somewhere else.
     *
     * RESIDUAL WINDOW, stated rather than papered over: a hardlink planted between
     * this audit and the child's exec is still not caught. That window is
     * microseconds instead of the lifetime of the copy, and spawnUnderGrant() below
     * closes it further by re-auditing immediately before spawning. It is not zero.
     * Anything claiming otherwise would be the same false confidence again. */
    /* Audited BELOW, once the granted paths are known -- see AUDIT THE GRANT, NOT
     * THE TREE. Auditing targetDir here was the wrong boundary: plan() attests the
     * GRANTED paths, which are a strict subset of targetDir, so a symlink that
     * stays inside targetDir while leaving the grant passed a clean audit. */

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

    /* AUDIT THE GRANT, NOT THE TREE.
     *
     * The previous version audited targetDir and attested the granted paths. Those
     * are different boundaries -- case 3 above exists precisely because a grant is a
     * strict SUBSET of targetDir -- so a link that stayed inside targetDir while
     * leaving the grant was reported clean. Reproduced end-to-end, no privileges,
     * no race:
     *
     *     <copy>/inputs/data -> ../secrets      (relative; resolves inside <copy>)
     *     grant = <copy>/inputs
     *     auditTree(<copy>)  ->  0 symlinks, 0 hardlinks, no error
     *     child              ->  READ:TOP-SECRET-KEY  WROTE
     *     and pwned.txt landed in <copy>/secrets, which was never granted
     *
     * That also falsified this suite's own case 7a ("sibling directory denied") on a
     * tree the audit called clean. Third round, same shape as the first two: the
     * check was about one thing and the claim was about another.
     *
     * So every granted path is audited against ITSELF. A symlink inside a granted
     * directory must resolve within THAT directory, because that is the boundary
     * --allow-fs-read/write actually draws. */
    for (const p of reads.concat(writes)) {
      const a = auditTree(p);
      if (a.error) {
        return refuse(CLS, "could not audit granted path " + p + " at enforcement time (" + a.error +
          "). An audit that did not complete is not a clean audit");
      }
      if (a.symlink_escapes.length > 0) {
        return refuse(CLS, a.symlink_escapes.length + " symlink(s) inside the GRANTED path " + p +
          " resolve outside it, and the Permission Model follows them. Staying inside targetDir is not " +
          "enough -- the boundary attested here is the grant. First: " +
          JSON.stringify(a.symlink_escapes[0]).slice(0, 180));
      }
      if (a.hardlink_suspects.length > 0) {
        return refuse(CLS, a.hardlink_suspects.length + " file(s) under the GRANTED path " + p +
          " have st_nlink > 1 (or could not be stat'd). Each is a second name for an inode this copy does " +
          "not exclusively own, and a WRITE through one lands outside the grant (measured). First: " +
          JSON.stringify(a.hardlink_suspects[0]).slice(0, 180));
      }
      auditedPaths.push(a);
    }
    auditPerformed = { granted_paths_audited: auditedPaths.map((a) => a.root) };

    argv.push("--permission");
    for (const p of reads) argv.push("--allow-fs-read=" + p);
    for (const p of writes) argv.push("--allow-fs-write=" + p);
    enforced.push(CLS);
    notes.push("filesystem: " + reads.length + " read path(s), " + writes.length + " write path(s), " +
      "each audited BY THIS CALL against ITSELF (not merely against targetDir) — 0 escaping symlinks, " +
      "0 hardlink suspects. Residual window: a link planted between this audit and exec is not caught; " +
      "spawnUnderGrant() re-audits immediately before spawning to narrow it");
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

  return result(argv, enforced, refusals, notes, auditPerformed);
}

function result(argv, enforced, refusals, notes, audit) {
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
    /* The audit THIS call performed, or null if the filesystem class never got
     * that far. Evidence of what was checked and when -- not an input. */
    audit: audit || null,
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

/* spawnUnderGrant(ctx, script, args, spawnOptions) — the recommended entry point.
 *
 * plan() audits, but between plan() returning and a caller spawning, arbitrary time
 * can pass; a caller that plans once and spawns repeatedly reintroduces exactly the
 * staleness that made the previous design exploitable. This wrapper re-audits
 * immediately before exec and refuses if anything changed, so the window is the gap
 * between the audit and the spawn syscall rather than however long the caller held
 * the argv.
 *
 * It is NOT a claim that the window is closed. A hardlink planted in that gap is
 * still not caught, and no user-space audit can close it -- doing that needs the
 * kernel (a bind mount with nosuid/nodev, a mount namespace, or a filesystem the
 * enforced process cannot reach by any other name). Said plainly here because the
 * previous version of this file claimed "there is no TOCTOU window", which was
 * false at system level and true only for links minted by the enforced child.
 *
 * Returns { ok:false, refusals, plan } if enforcement is not available, so a caller
 * cannot accidentally run unconfined by ignoring a field. */
function spawnUnderGrant(ctx, script, args, spawnOptions) {
  const { spawnSync } = require("child_process");
  const first = planChecked(ctx);
  if (first.enforced.indexOf("filesystem") === -1) {
    return { ok: false, refusals: first.refusals, plan: first, result: null };
  }
  /* Re-audit. Cheap next to spawning a process, and it is the difference between
   * "clean when the caller asked" and "clean when the code actually ran". */
  const second = planChecked(ctx);
  if (second.enforced.indexOf("filesystem") === -1) {
    return {
      ok: false,
      refusals: second.refusals.concat([{
        class: "filesystem",
        reason: "the tree passed the audit at plan() time and FAILED a re-audit immediately before spawn -- " +
          "it changed in between. Refusing to run: this is the staleness that made caller-supplied evidence " +
          "exploitable",
      }]),
      plan: second,
      result: null,
    };
  }
  const res = spawnSync(process.execPath, second.argv.concat([script], args || []),
    Object.assign({ encoding: "utf8" }, spawnOptions || {}));
  return { ok: true, refusals: [], plan: second, result: res };
}

module.exports = {
  SCHEMA_VERSION,
  ENFORCEABLE_CLASSES,
  REQUIRED_FLAGS,
  plan: planChecked,
  spawnUnderGrant,
  auditTree,
  detectFlags,
  canonicalAbsolute,
  isInside,
};
