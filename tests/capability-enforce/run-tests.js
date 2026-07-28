/* tests/capability-enforce/run-tests.js — does the capability grant actually BIND?
 *
 * scripts/capability-enforce.js claims that two of the four per-skill capability
 * classes are genuinely enforced. A test that only inspected the argv it returns
 * would prove the module builds a string, which is not the claim. The claim is
 * that a skill handed that argv CANNOT reach outside its grant.
 *
 * So most of this file spawns a real child under the real flags and asserts on
 * what the child was able to do. Where that is impossible -- an older runtime
 * with no Permission Model -- the suite reports INCONCLUSIVE (harness) rather
 * than passing, because "the mechanism did not run" and "the mechanism held" are
 * different facts (contract 10 List C rule 1).
 *
 * The escape attempts are the point. Anyone can demonstrate that a granted read
 * succeeds; the value is in the ones that must FAIL, and in the one that does
 * not (symlinks -- case 6), which is why the module demands a symlink audit
 * before it will claim the filesystem class at all.
 */

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const enforce = require("../../scripts/capability-enforce.js");

let pass = 0;
let fail = 0;
let inconclusive = 0;
let skipped = 0;

function ok(name, detail) {
  pass += 1;
  process.stdout.write("PASS " + name + " - " + detail + "\n");
}
function bad(name, detail) {
  fail += 1;
  process.stdout.write("FAIL " + name + " - " + detail + "\n");
}
function inconc(name, why) {
  inconclusive += 1;
  fail += 1; // fail-closed: still gates, but excluded from product findings
  process.stdout.write("FAIL " + name + " - INCONCLUSIVE (harness): " + why + "\n");
}
function skip(name, scope) {
  skipped += 1;
  process.stdout.write("SKIPPED " + name + " - " + scope + "\n");
}
function assert(name, cond, detail) {
  if (cond) ok(name, detail); else bad(name, detail);
}

const FLAGS = enforce.detectFlags();
const HAVE_PERMISSION = FLAGS.permission && FLAGS.allow_fs_read && FLAGS.allow_fs_write;

/* --------------------------------------------------------------------------
 * Fixture: a "skill copy" with a granted subtree and a sibling it must never
 * reach. The sibling is a sibling on purpose -- "/x/inputs" vs "/x/inputs-evil"
 * is the prefix-overmatch bug that a naive startsWith() grant check produces.
 * ------------------------------------------------------------------------ */
const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "gs-capenf-"));
const COPY = path.join(ROOT, "copy");
const OUTSIDE = path.join(ROOT, "outside");
fs.mkdirSync(path.join(COPY, "inputs"), { recursive: true });
fs.mkdirSync(path.join(COPY, "inputs-evil"), { recursive: true });
fs.mkdirSync(OUTSIDE, { recursive: true });
fs.writeFileSync(path.join(COPY, "inputs", "in.txt"), "GRANTED\n");
fs.writeFileSync(path.join(COPY, "inputs-evil", "sibling.txt"), "SIBLING\n");
fs.writeFileSync(path.join(OUTSIDE, "secret.txt"), "SECRET\n");

const CLEAN_ISOLATION = { symlink_escapes: [], symlinks_skipped_at_copy: 0, isolated: true };

function grantOf(g) {
  return { schema_version: "1.0", skill_id: "probe-skill", grants: g, enforced: [] };
}

/* Run a probe expression in a child under `argv`, and report what it could do.
 * The probe writes one line per attempt: "<label>|ALLOWED|<v>" or "<label>|DENIED|<code>". */
function runProbe(argv, body) {
  const probe = path.join(COPY, "inputs", "probe.js");
  fs.writeFileSync(probe,
    'const fs=require("fs");\n' +
    'const r=(l,f)=>{try{const v=f();process.stdout.write(l+"|ALLOWED|"+String(v).slice(0,40)+"\\n")}' +
    'catch(e){process.stdout.write(l+"|DENIED|"+(e.code||e.message)+"\\n")}};\n' + body);
  const res = spawnSync(process.execPath, argv.concat([probe]), {
    encoding: "utf8", timeout: 30000, windowsHide: true,
  });
  if (res.error) return { error: res.error, verdicts: {} };
  const verdicts = {};
  for (const line of String(res.stdout || "").split("\n")) {
    const p = line.split("|");
    if (p.length >= 3) verdicts[p[0].trim()] = { allowed: p[1] === "ALLOWED", detail: p[2] };
  }
  return { error: null, verdicts, raw: (res.stdout || "") + (res.stderr || "") };
}

const J = JSON.stringify;

/* ==========================================================================
 * 1. Refusals -- pure decision logic, runs on every platform.
 * ========================================================================== */

(function case1_noIsolationEvidence() {
  const name = "1. filesystem refused without a symlink audit";
  const r = enforce.plan({
    grant: grantOf({ filesystem: { read: [path.join(COPY, "inputs")] } }),
    targetDir: COPY,
    // isolation deliberately omitted
  });
  const ref = r.refusals.find((x) => x.class === "filesystem");

  /* The REASON is only assertable where the Permission Model exists. On a runtime
   * without it, capability-enforce refuses on the missing flags first and never
   * reaches the symlink check -- correctly, since there is no enforcement to
   * qualify. Demanding the symlink wording there asserted a code path that cannot
   * run, and failed every Node 18 leg of CI while passing locally on Node 22.
   *
   * The invariant that holds on EVERY runtime is the one that matters: absent
   * isolation evidence, the class is not enforced. Assert that unconditionally,
   * and qualify the reason only where it is reachable. */
  if (!HAVE_PERMISSION) {
    assert(name + " (no Permission Model on " + process.version + ")",
      r.enforced.indexOf("filesystem") === -1,
      "refused — on this runtime for the earlier reason (no --permission), which is why the " +
      "symlink wording is not asserted here: " + (ref ? ref.reason.slice(0, 90) : "no refusal recorded"));
    return;
  }
  assert(name,
    r.enforced.indexOf("filesystem") === -1 && !!ref && /symlink audit/i.test(ref.reason),
    ref ? "refused: " + ref.reason.slice(0, 110) : "NOT refused -- enforced=" + J(r.enforced));
})();

(function case2_symlinkEscapePresent() {
  const name = "2. filesystem refused when the tree has an escaping symlink";
  const r = enforce.plan({
    grant: grantOf({ filesystem: { read: [path.join(COPY, "inputs")] } }),
    targetDir: COPY,
    isolation: { symlink_escapes: [{ path: COPY + "/link", target: OUTSIDE }], symlinks_skipped_at_copy: 0 },
  });
  assert(name, r.enforced.indexOf("filesystem") === -1,
    r.enforced.indexOf("filesystem") === -1
      ? "refused, as it must -- the Permission Model follows a pre-existing symlink out of the grant"
      : "ENFORCED despite a known escape: this would attest a boundary the tree defeats");
})();

(function case3_grantOutsideTarget() {
  const name = "3. a granted path outside targetDir is refused";
  const r = enforce.plan({
    grant: grantOf({ filesystem: { read: [OUTSIDE] } }),
    targetDir: COPY,
    isolation: CLEAN_ISOLATION,
  });
  assert(name, r.enforced.indexOf("filesystem") === -1,
    r.enforced.indexOf("filesystem") === -1
      ? "refused -- a grant may not widen past the copy it was issued for"
      : "a grant re-scoped itself outside the disposable copy and was enforced anyway");
})();

(function case4_nonEmptySubprocessAllowlist() {
  const name = "4. a non-empty subprocess allowlist is REFUSED, not silently widened";
  const r = enforce.plan({
    grant: grantOf({ subprocess: { allowed: ["git"] } }),
    targetDir: COPY,
    isolation: CLEAN_ISOLATION,
  });
  const ref = r.refusals.find((x) => x.class === "subprocess");
  /* Same runtime split as case 1. Without --permission the class is refused for the
   * earlier reason (nothing is denied at all), so the granularity wording is not
   * reachable. The part that must hold everywhere -- the allowlist is never silently
   * widened into an enforcement claim -- is asserted on both paths. */
  if (!HAVE_PERMISSION) {
    assert(name + " (no Permission Model on " + process.version + ")",
      r.enforced.indexOf("subprocess") === -1,
      "refused — on this runtime for the earlier reason (no --permission): " +
      (ref ? ref.reason.slice(0, 90) : "no refusal recorded"));
  } else {
    assert(name,
      r.enforced.indexOf("subprocess") === -1 && !!ref && /granularity/i.test(ref.reason),
      ref ? "refused: --allow-child-process cannot express 'git only'" :
        "ENFORCED a per-executable allowlist the mechanism cannot express -- this is the fail-open shape D1 forbids");
  }
  // and the flag must never appear in argv
  assert("4b. --allow-child-process never emitted",
    r.argv.indexOf("--allow-child-process") === -1,
    r.argv.indexOf("--allow-child-process") === -1 ? "absent from argv" : "PRESENT: " + J(r.argv));
})();

(function case5_modelNeverClaimed() {
  const name = "5. the model class is never reported enforced";
  const r = enforce.plan({
    grant: grantOf({ model: { allowed: ["claude-opus-5"] }, subprocess: { allowed: [] } }),
    targetDir: COPY,
    isolation: CLEAN_ISOLATION,
  });
  assert(name, r.enforced.indexOf("model") === -1,
    r.enforced.indexOf("model") === -1
      ? "declared, not attested -- no OS mechanism exists for it at this layer"
      : "claimed a model boundary that nothing enforces");
})();

/* ==========================================================================
 * 6-9. Behavioural -- spawn a real child and see what it could reach.
 * ========================================================================== */

if (!HAVE_PERMISSION) {
  skip("6-9. behavioural enforcement probes",
    "this runtime (" + process.version + ") does not expose --permission/--allow-fs-*, so the Permission " +
    "Model cannot be exercised at all. THIS RUN PROVIDES NO EVIDENCE THAT ANY FILESYSTEM OR SUBPROCESS " +
    "BOUNDARY HOLDS -- it only shows the refusal logic above is intact. Node >= 20 is required for coverage.");
} else {
  const r = enforce.plan({
    grant: grantOf({
      filesystem: { read: [path.join(COPY, "inputs")], write: [path.join(COPY, "inputs")] },
      subprocess: { allowed: [] },
    }),
    targetDir: COPY,
    isolation: CLEAN_ISOLATION,
  });

  if (r.enforced.indexOf("filesystem") === -1 || r.enforced.indexOf("subprocess") === -1) {
    inconc("6-9. behavioural enforcement probes",
      "the module refused a grant this suite expects it to accept, so the child was never run under " +
      "enforcement and nothing about the boundary was observed. enforced=" + J(r.enforced) +
      " refusals=" + J(r.refusals).slice(0, 300));
  } else {
    const out = runProbe(r.argv,
      'r("in_grant",()=>fs.readFileSync(' + J(path.join(COPY, "inputs", "in.txt")) + ',"utf8").trim());\n' +
      'r("sibling",()=>fs.readFileSync(' + J(path.join(COPY, "inputs-evil", "sibling.txt")) + ',"utf8").trim());\n' +
      'r("outside",()=>fs.readFileSync(' + J(path.join(OUTSIDE, "secret.txt")) + ',"utf8").trim());\n' +
      'r("etc",()=>fs.readFileSync("/etc/passwd","utf8").slice(0,8));\n' +
      'r("write_out",()=>{fs.writeFileSync(' + J(path.join(OUTSIDE, "pwn.txt")) + ',"x");return "wrote"});\n' +
      'r("mk_symlink",()=>{fs.symlinkSync(' + J(OUTSIDE) + ',' + J(path.join(COPY, "inputs", "esc")) + ');return "made"});\n' +
      'r("hardlink",()=>{fs.linkSync(' + J(path.join(OUTSIDE, "secret.txt")) + ',' + J(path.join(COPY, "inputs", "h.txt")) + ');return "made"});\n' +
      'r("subproc",()=>require("child_process").execSync("echo pwned").toString().trim());\n' +
      'r("worker",()=>{new (require("worker_threads").Worker)("",{eval:true});return "spawned"});\n' +
      'r("eval_req",()=>eval(\'require("fs")\').readFileSync(' + J(path.join(OUTSIDE, "secret.txt")) + ',"utf8").trim());\n' +
      'r("binding",()=>process.binding("fs")?"got":"none");\n');

    if (out.error) {
      inconc("6-9. behavioural enforcement probes",
        "could not spawn the probe child: " + String(out.error.message || out.error) +
        ". No boundary was observed either way");
    } else {
      const v = (k) => out.verdicts[k];
      const need = ["in_grant", "sibling", "outside", "etc", "write_out", "mk_symlink",
        "hardlink", "subproc", "worker", "eval_req", "binding"];
      const missing = need.filter((k) => !v(k));
      if (missing.length) {
        inconc("6-9. behavioural enforcement probes",
          "the probe child did not report on " + J(missing) + " -- its output was truncated or it died " +
          "early, so those attempts were neither allowed nor denied as far as this harness can tell. raw=" +
          J(String(out.raw || "").slice(0, 300)));
      } else {
        /* The grant must still WORK. An enforcement that denies everything is
         * trivially safe and useless; if this fails the rest proves nothing. */
        assert("6. the granted read still succeeds", v("in_grant").allowed,
          v("in_grant").allowed ? "read its own input"
            : "DENIED (" + v("in_grant").detail + ") -- the envelope is unusable, so the denials below are vacuous");

        assert("7a. sibling directory denied (no prefix overmatch)", !v("sibling").allowed,
          !v("sibling").allowed ? "inputs-evil/ denied under a grant of inputs/ (" + v("sibling").detail + ")"
            : "ALLOWED -- a grant of X admitted X-evil");
        assert("7b. read outside the copy denied", !v("outside").allowed,
          !v("outside").allowed ? v("outside").detail : "ALLOWED: read " + v("outside").detail);
        assert("7c. /etc/passwd denied", !v("etc").allowed,
          !v("etc").allowed ? v("etc").detail : "ALLOWED: " + v("etc").detail);
        assert("7d. write outside the copy denied", !v("write_out").allowed,
          !v("write_out").allowed ? v("write_out").detail : "ALLOWED -- the skill wrote outside its grant");

        /* The TOCTOU question. A copy-time symlink audit is only meaningful if
         * the skill cannot mint a fresh symlink afterwards. */
        assert("8a. creating a symlink out of the grant denied", !v("mk_symlink").allowed,
          !v("mk_symlink").allowed
            ? "no TOCTOU window: the copy-time audit cannot be invalidated at runtime (" + v("mk_symlink").detail + ")"
            : "ALLOWED -- the skill created its own escape hatch after the audit, which voids the filesystem claim");
        assert("8b. hardlinking a file in from outside denied", !v("hardlink").allowed,
          !v("hardlink").allowed ? v("hardlink").detail : "ALLOWED -- outside content pulled into the grant");

        assert("9a. child_process denied", !v("subproc").allowed,
          !v("subproc").allowed ? "deny-all subprocess holds (" + v("subproc").detail + ")"
            : "ALLOWED: " + v("subproc").detail);
        assert("9b. worker_threads denied", !v("worker").allowed,
          !v("worker").allowed ? v("worker").detail
            : "ALLOWED -- a worker is a subprocess-shaped escape and must be denied with it");
        assert("9c. eval-then-require cannot bypass", !v("eval_req").allowed,
          !v("eval_req").allowed ? v("eval_req").detail : "ALLOWED: bypassed via eval");
        assert("9d. process.binding cannot bypass", !v("binding").allowed,
          !v("binding").allowed ? v("binding").detail : "ALLOWED: raw binding reachable");
      }
    }
  }
}

/* ==========================================================================
 * 10. The symlink hole, demonstrated rather than asserted.
 *
 * This is the finding the module's whole precondition rests on. If a future
 * Node closes the hole, this case tells us -- and the precondition can be
 * relaxed deliberately, with evidence, instead of by assumption.
 * ========================================================================== */

(function case10_symlinkHoleStillReal() {
  const name = "10. pre-existing symlinks still escape the Permission Model";
  if (!HAVE_PERMISSION) {
    skip(name, "no Permission Model on " + process.version + "; the precondition in capability-enforce.js is " +
      "neither confirmed nor refuted on this leg");
    return;
  }
  let linked = false;
  const link = path.join(COPY, "inputs", "escape-link");
  try { fs.rmSync(link, { force: true }); fs.symlinkSync(OUTSIDE, link); linked = true; } catch (e) { /* see below */ }
  if (!linked) {
    /* SKIP, not INCONCLUSIVE, and the distinction cost a full red CI matrix to learn.
     *
     * This was fail-closed: unable to create a symlink -> INCONCLUSIVE -> gates. But
     * an unprivileged Windows runner without Developer Mode CANNOT create symlinks
     * AT ALL. That is a permanent platform property, not a harness malfunction, so
     * the gate would have been red on every Windows leg forever, for a reason no
     * amount of fixing could clear.
     *
     * The discriminator the rest of this repo already uses: the starvation sweep
     * fails a WIRING GAP (a defect in its own setup) and passes an INERT target (the
     * mechanism cannot fire on this platform) while stating it provides no coverage.
     * Creating a symlink here is the same shape -- where the OS forbids it, this case
     * is INERT.
     *
     * INCONCLUSIVE stays for the case below: the probe RAN and did not report. That
     * is a harness malfunction and still gates. "The platform cannot do this" and
     * "I tried and something went wrong" are different facts, and only the second is
     * a reason to stop a merge. */
    skip(name, "this filesystem does not permit creating symlinks (Windows without Developer Mode, or a " +
      "mount that forbids them), so the escape could not be attempted. THIS RUN PROVIDES NO EVIDENCE about " +
      "whether the Permission Model still follows a pre-existing symlink -- the precondition in " +
      "capability-enforce.js is neither confirmed nor refuted here. Coverage comes from legs that can symlink");
    return;
  }
  const out = runProbe(["--permission", "--allow-fs-read=" + path.join(COPY, "inputs")],
    'r("through_link",()=>fs.readFileSync(' + J(path.join(COPY, "inputs", "escape-link", "secret.txt")) + ',"utf8").trim());\n');
  const v = out.verdicts.through_link;
  if (out.error || !v) {
    inconc(name, "the probe did not report: " + String((out.error && out.error.message) || "no verdict line"));
    return;
  }
  if (v.allowed) {
    ok(name, "CONFIRMED still real (read " + J(v.detail) + " from outside the grant). This is exactly why " +
      "capability-enforce.js refuses the filesystem class without a symlink audit -- the precondition is load-bearing");
  } else {
    /* Not a failure -- good news that must not be absorbed silently. */
    ok(name, "the escape was DENIED on " + process.version + " (" + v.detail + "). The hole this module's " +
      "symlink precondition exists for may be closed on this runtime. Do NOT relax the precondition on this " +
      "alone: it must hold on every supported platform, and the audit is cheap. Re-evaluate deliberately");
  }
})();

/* ------------------------------------------------------------------------ */

try { fs.rmSync(ROOT, { recursive: true, force: true }); } catch (e) { /* temp dir, best effort */ }

process.stdout.write("\nSUMMARY PASS=" + pass + " FAIL=" + fail + " SKIPPED=" + skipped +
  (inconclusive ? " (of which INCONCLUSIVE=" + inconclusive + ")" : "") + "\n");
if (!HAVE_PERMISSION) {
  process.stdout.write("NOTE: no Node Permission Model on " + process.version +
    " -- the behavioural half of this suite did not run. Refusal logic only.\n");
}
process.exitCode = fail > 0 ? 1 : 0;
