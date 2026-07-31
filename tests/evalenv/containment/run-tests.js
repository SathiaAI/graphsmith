/* tests/evalenv/containment/run-tests.js — does the container profile
 * actually contain, AND does it still work?
 *
 * REWRITTEN AFTER AN ADVERSARIAL REVIEW FOUND THIS SUITE GREEN ON A BROKEN PROFILE.
 *
 * The first version asserted on evalenv's exported containment-flag CONSTANT and
 * built its own `docker run` argv with NO MOUNT. It reported 7/7 PASS while the
 * shipped profile was functionally dead: "--user 65534" against a copy that
 * fs.mkdtempSync creates at mode 0700 owned by the host uid meant the container
 * could not traverse its own workspace.
 *
 *     --user 65534  ->  ls: can't open '/workspace': Permission denied
 *     no --user     ->  hello.txt
 *
 * Every container-required external tool (scripts/ext-tool-runner.js) would have
 * seen an empty workspace. The suite could not see it because it never called
 * runUntrustedCode() and never mounted anything. Testing the constant instead of
 * the code path is how a test passes a product that does not work.
 *
 * So: this file now drives evalenv.create("container", ...) and runUntrustedCode()
 * — the exact entry point callers use — and case 2 asserts the mount is READABLE
 * before any containment claim is made. An envelope nothing can run in is not
 * secure, it is broken, and the containment assertions below would be vacuous.
 *
 * WHAT DECIDES A SKIP (the other half of the review)
 *
 * Every skip here is decided by evidence INDEPENDENT of the code under test.
 * The previous version asked evalenv.detectContainerRuntime() whether to test
 * evalenv — so breaking the detector made the suite skip and pass, while the
 * container profile became silently unavailable to every caller. Same shape as
 * asking a lock whether it should be picked.
 *
 * Now the suite probes the runtime itself, and DISAGREEMENT IS A FAILURE: if a
 * daemon answers but detectContainerRuntime() reports unavailable, that is a
 * product defect and it fails, loudly. Only genuine platform facts skip:
 *
 *   no runtime answers this probe          -> SKIP (no daemon on this leg)
 *   Windows-container daemon (win32 only)  -> SKIP (cannot express Linux flags)
 *   image not present and not pullable     -> SKIP (supply, not product)
 *
 * The Windows skip is anchored to process.platform === "win32". It used to also
 * match a bare /invalid option/, which a LINUX daemon emits for an unrelated bad
 * argv — measured:
 *     docker: Error response from daemon: create <id>: invalid option: "bogus"
 * so a containment profile that a Linux daemon refused to start would have been
 * reported as "Windows container mode" and passed. On Linux. Green.
 */

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const evalenv = require("../../../scripts/evalenv.js");

let pass = 0;
let fail = 0;
let skipped = 0;

function ok(n, d) { pass += 1; process.stdout.write("PASS " + n + " - " + d + "\n"); }
function bad(n, d) { fail += 1; process.stdout.write("FAIL " + n + " - " + d + "\n"); }
function inconc(n, w) { fail += 1; process.stdout.write("FAIL " + n + " - INCONCLUSIVE (harness): " + w + "\n"); }
function skip(n, s) { skipped += 1; process.stdout.write("SKIPPED " + n + " - " + s + "\n"); }
function assert(n, c, d) { if (c) ok(n, d); else bad(n, d); }

const IMAGE = process.env.GRAPHSMITH_CONTAINMENT_TEST_IMAGE || "alpine:3.20";

function done() {
  process.stdout.write("\nSUMMARY PASS=" + pass + " FAIL=" + fail + " SKIPPED=" + skipped + "\n");
  process.exitCode = fail > 0 ? 1 : 0;
}

/* ---- Independent runtime probe -------------------------------------------
 * Deliberately NOT evalenv.detectContainerRuntime(). This asks the daemon a
 * question of our own so the product's detector can be CHECKED against it rather
 * than trusted. `version --format {{.Server.Version}}` fails when no daemon is
 * listening and succeeds when one is, without reusing the detector's own probe. */
function probeRuntime() {
  for (const bin of ["docker", "podman"]) {
    const r = spawnSync(bin, ["version", "--format", "{{.Server.Version}}"],
      { encoding: "utf8", timeout: 30000, windowsHide: true });
    if (!r.error && r.status === 0 && String(r.stdout || "").trim()) {
      return { runtime: bin, version: String(r.stdout).trim() };
    }
  }
  return null;
}

const probe = probeRuntime();
const detected = evalenv.detectContainerRuntime();
const detectorSaysAvailable = !!(detected && detected.available);

/* ---- 1. The detector must agree with reality ------------------------------
 * This case exists because breaking detectContainerRuntime() used to make the
 * whole suite skip and pass, while making the contract-04-B10 container profile
 * unavailable to every caller. A silent downgrade of a required control is
 * exactly what B10 forbids, so a detector that under-reports must FAIL here. */
if (probe && !detectorSaysAvailable) {
  bad("1. detectContainerRuntime agrees with an independent probe",
    "a " + probe.runtime + " daemon answered an independent probe (server " + probe.version +
    ") but evalenv.detectContainerRuntime() reports UNAVAILABLE. The container profile is the " +
    "REQUIRED control for untrusted code (contract 04 B10); a detector that under-reports makes " +
    "it silently unavailable to every caller while this suite would otherwise skip and pass");
} else if (!probe && detectorSaysAvailable) {
  bad("1. detectContainerRuntime agrees with an independent probe",
    "detectContainerRuntime() reports AVAILABLE but no daemon answered an independent probe. " +
    "Claiming containment that cannot run is worse than reporting none");
} else {
  ok("1. detectContainerRuntime agrees with an independent probe",
    probe ? "both see " + probe.runtime + " server " + probe.version : "both see no runtime");
}

if (!probe) {
  skip("2-8. container containment probes",
    "no container runtime answered an independent probe on this leg. THIS RUN PROVIDES NO " +
    "EVIDENCE THAT ANY CONTAINER CONTAINMENT CONTROL IS ENFORCED, and none that the profile " +
    "still functions. Coverage requires a leg with a reachable docker/podman daemon.");
  done();
  return;
}

/* ---- Image availability: supply, not product ----------------------------- */
const RUNTIME = probe.runtime;
const inspect = spawnSync(RUNTIME, ["image", "inspect", IMAGE],
  { encoding: "utf8", timeout: 60000, windowsHide: true });
if (inspect.error || inspect.status !== 0) {
  const pull = spawnSync(RUNTIME, ["pull", IMAGE],
    { encoding: "utf8", timeout: 300000, windowsHide: true });
  if (pull.error || pull.status !== 0) {
    skip("2-8. container containment probes",
      "a " + RUNTIME + " daemon is reachable but " + IMAGE + " is neither present nor pullable (" +
      String((pull.stderr || "").trim().split("\n").pop() || "pull failed").slice(0, 120) +
      "). THIS RUN PROVIDES NO CONTAINMENT EVIDENCE. Pre-pull the image, or set " +
      "GRAPHSMITH_CONTAINMENT_TEST_IMAGE, for real coverage.");
    done();
    return;
  }
}

/* ---- Drive the REAL profile, through the REAL entry point ----------------- */
const SRC = fs.mkdtempSync(path.join(os.tmpdir(), "gs-containment-src-"));
fs.writeFileSync(path.join(SRC, "sentinel.txt"), "SOURCE-CONTENT\n");

let env = null;
try {
  env = evalenv.create("container", { sourceDir: SRC });
} catch (e) {
  inconc("2-8. container containment probes",
    "evalenv.create(\"container\") threw: " + String((e && e.message) || e));
  fs.rmSync(SRC, { recursive: true, force: true });
  done();
  return;
}

if (!env.available) {
  bad("2-8. container containment probes",
    "a daemon answered but evalenv.create(\"container\") returned available:false — " +
    JSON.stringify(String(env.reason || "").slice(0, 200)));
  fs.rmSync(SRC, { recursive: true, force: true });
  done();
  return;
}

const probeScript = [
  'printf "uid=%s\\n" "$(id -u)"',
  'printf "capeff=%s\\n" "$(awk \'/CapEff/{print $2}\' /proc/self/status)"',
  'printf "nnp=%s\\n" "$(awk \'/NoNewPrivs/{print $2}\' /proc/self/status)"',
  // The regression that shipped: can the container actually SEE its workspace?
  'if cat /workspace/sentinel.txt >/dev/null 2>&1; then printf "mount_readable=YES\\n"; else printf "mount_readable=NO\\n"; fi',
  'if echo x > /workspace/w-probe 2>/dev/null; then printf "mount=WRITABLE\\n"; else printf "mount=READONLY\\n"; fi',
  'if echo x > /rootfs-probe 2>/dev/null; then printf "rootfs=WRITABLE\\n"; else printf "rootfs=READONLY\\n"; fi',
  'if mknod /tmp/devprobe c 1 3 2>/dev/null; then printf "mknod=ALLOWED\\n"; else printf "mknod=DENIED\\n"; fi',
  'if wget -q -T2 -O- http://1.1.1.1 >/dev/null 2>&1; then printf "net=ALLOWED\\n"; else printf "net=DENIED\\n"; fi',
].join("; ");

let res = null;
try {
  res = env.runUntrustedCode(["sh", "-c", probeScript], { image: IMAGE, timeoutMs: 180000 });
} catch (e) {
  bad("2-8. container containment probes",
    "runUntrustedCode() threw on the documented entry point: " + String((e && e.message) || e));
  try { env.destroy(); } catch (_) { /* best effort */ }
  fs.rmSync(SRC, { recursive: true, force: true });
  done();
  return;
}

const stderrText = String((res && res.stderr) || "");
const facts = {};
for (const line of String((res && res.stdout) || "").split("\n")) {
  const m = line.trim().match(/^([a-z_]+)=(.+)$/);
  if (m) facts[m[1]] = m[2];
}
const need = ["uid", "capeff", "nnp", "mount_readable", "mount", "rootfs", "mknod", "net"];
const absent = need.filter((k) => !(k in facts));

/* Windows containers cannot express the Linux containment flags. Anchored to the
 * platform: on win32 only, and only for the specific message. The old condition
 * also matched a bare /invalid option/, which a Linux daemon emits for any bad
 * argv — so a profile a Linux daemon refused to start read as "Windows mode" and
 * passed. */
if (process.platform === "win32" && res.status === 125 &&
    /not supported for Windows containers/i.test(stderrText)) {
  skip("2-8. container containment probes",
    "this " + RUNTIME + " daemon is in WINDOWS CONTAINER mode, which does not support the Linux " +
    "containment flags the profile relies on: " +
    JSON.stringify(stderrText.trim().split("\n")[0].slice(0, 110)) + ". THIS RUN PROVIDES NO " +
    "EVIDENCE THAT ANY CONTAINER CONTAINMENT CONTROL IS ENFORCED — coverage requires a " +
    "Linux-container daemon.");
} else if (res.error || absent.length) {
  inconc("2-8. container containment probes",
    "runUntrustedCode() ran on " + process.platform + "/" + RUNTIME + " but produced no full reading" +
    (res.error ? " (" + String(res.error.message || res.error) + ")" : "") +
    (absent.length ? "; missing " + JSON.stringify(absent) : "") +
    ". status=" + String(res.status) + " stderr=" + JSON.stringify(stderrText.slice(0, 220)) +
    ". Nothing was observed about containment either way");
} else {
  /* THE case the old suite could not fail. Everything below is vacuous without it:
   * a container that cannot read its input is contained and useless. */
  assert("2. the profile still WORKS: /workspace is readable inside the container",
    facts.mount_readable === "YES",
    facts.mount_readable === "YES"
      ? "read the mounted source — containment did not disable the profile"
      : "the container CANNOT READ ITS OWN WORKSPACE. Every container-required external tool " +
        "would see an empty source tree. This is what --user against a 0700 mkdtemp copy does");

  assert("3. runs as a non-root uid", facts.uid !== "0",
    facts.uid !== "0" ? "uid=" + facts.uid + " (root in the container is root on the host under any escape)"
      : "uid=0 — untrusted code is running as root");

  assert("4. all Linux capabilities dropped", /^0+$/.test(facts.capeff),
    /^0+$/.test(facts.capeff) ? "CapEff=" + facts.capeff
      : "CapEff=" + facts.capeff + " — the default set includes CAP_MKNOD, CAP_SETUID, " +
        "CAP_DAC_OVERRIDE and CAP_NET_RAW");

  assert("5. no_new_privs set", facts.nnp === "1",
    facts.nnp === "1" ? "NoNewPrivs=1 — a setuid binary in the image cannot escalate"
      : "NoNewPrivs=" + facts.nnp + " — --user alone does NOT close setuid escalation");

  assert("6. the source mount is read-only", facts.mount === "READONLY",
    facts.mount === "READONLY" ? "untrusted code cannot write back into the evaluation copy (contract 04 B10)"
      : "the mounted source is WRITABLE — untrusted code can rewrite the tree under evaluation");

  assert("7. root filesystem is read-only, capability drop bites",
    facts.rootfs === "READONLY" && facts.mknod === "DENIED",
    "rootfs=" + facts.rootfs + " mknod=" + facts.mknod +
      (facts.rootfs === "READONLY" && facts.mknod === "DENIED"
        ? " (mknod is the behavioural check on case 4, not a re-read of CapEff)"
        : " — expected READONLY/DENIED"));

  assert("8. network egress denied", facts.net === "DENIED",
    facts.net === "DENIED" ? "--network none holds (contract 04 B10)"
      : "network reachable from inside a --network none container");
}

try { env.destroy(); } catch (e) { /* disposable */ }
fs.rmSync(SRC, { recursive: true, force: true });
done();
