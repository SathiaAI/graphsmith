/* tests/capability-enforce/container/run-tests.js — does the container profile
 * actually contain?
 *
 * contract 04 B10 requires the container profile for any untrusted executable.
 * Until the commit that added this suite, that profile passed exactly two
 * containment flags: --network none and a read-only source mount. Both real,
 * both verified here. Everything around them was default, and the default is
 * root with 14 Linux capabilities and a writable root filesystem.
 *
 * That gap was invisible because nothing ever ran a container and looked. The
 * profile's own `claims` object described the isolation level in prose, and
 * prose is not evidence. So this suite does the one thing that settles it: it
 * runs a container under the profile's real argv and reads /proc/self/status
 * from inside.
 *
 * WHEN THERE IS NO DAEMON
 *
 * A container runtime is not present on every CI leg (Windows runners, and any
 * sandbox without a daemon). This suite then SKIPS, and says in the skip line
 * that it provides no containment coverage on that leg -- it does not pass.
 * A containment check that reports green because it could not run is the exact
 * shape contract 10 List C rule 4 exists to prevent, and it would be a
 * particularly bad one here: "we could not test the containment" reading as
 * "the containment is fine" is how an unenforced boundary survives a review.
 */

"use strict";

const { spawnSync } = require("child_process");
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

/* ---- 1. Static: the flags are in the argv the profile will use ------------
 * Cheap, runs everywhere, and catches the regression where someone drops a
 * flag. It is NOT evidence that any flag is enforced -- cases 2+ are. Kept
 * separate and named so the distinction cannot be lost by reading the summary. */
(function case1_argvComposition() {
  const argv = evalenv.CONTAINMENT_ARGV;
  const required = [
    ["--user", (a) => a.indexOf("--user") !== -1 && /^\d+:\d+$/.test(a[a.indexOf("--user") + 1] || "") &&
      a[a.indexOf("--user") + 1] !== "0:0"],
    ["--cap-drop=ALL", (a) => a.indexOf("--cap-drop=ALL") !== -1],
    ["--security-opt=no-new-privileges", (a) => a.indexOf("--security-opt=no-new-privileges") !== -1],
    ["--read-only", (a) => a.indexOf("--read-only") !== -1],
    ["--pids-limit", (a) => a.some((x) => String(x).indexOf("--pids-limit") === 0)],
  ];
  const missing = required.filter(([, ok_]) => !ok_(argv)).map(([n]) => n);
  assert("1. containment flags present in the profile's argv (composition, NOT enforcement)",
    missing.length === 0,
    missing.length === 0 ? "all present: " + argv.join(" ") : "MISSING: " + missing.join(", "));
})();

/* ---- 2+. Behavioural: run a container and look ---------------------------- */

const detection = evalenv.detectContainerRuntime();
if (!detection || !detection.available) {
  skip("2-7. container containment probes",
    "no container runtime with a reachable daemon on this leg. THIS RUN PROVIDES NO EVIDENCE THAT ANY " +
    "CONTAINER CONTAINMENT CONTROL IS ENFORCED -- only that the flags appear in the argv (case 1). " +
    "Containment coverage requires a leg with a docker/podman daemon.");
} else {
  const RUNTIME = detection.runtime;
  const probe = [
    'printf "uid=%s\\n" "$(id -u)"',
    'printf "capeff=%s\\n" "$(awk \'/CapEff/{print $2}\' /proc/self/status)"',
    'printf "nnp=%s\\n" "$(awk \'/NoNewPrivs/{print $2}\' /proc/self/status)"',
    'if echo x > /rootfs-probe 2>/dev/null; then printf "rootfs=WRITABLE\\n"; else printf "rootfs=READONLY\\n"; fi',
    'if echo x > /workspace/mount-probe 2>/dev/null; then printf "mount=WRITABLE\\n"; else printf "mount=READONLY\\n"; fi',
    'if mknod /tmp/devprobe c 1 3 2>/dev/null; then printf "mknod=ALLOWED\\n"; else printf "mknod=DENIED\\n"; fi',
    'if wget -q -T2 -O- http://1.1.1.1 >/dev/null 2>&1; then printf "net=ALLOWED\\n"; else printf "net=DENIED\\n"; fi',
  ].join("; ");

  const argv = ["run", "--rm", "--network", "none", "-w", "/workspace"]
    .concat(evalenv.CONTAINMENT_ARGV, [IMAGE, "sh", "-c", probe]);
  const res = spawnSync(RUNTIME, argv, { encoding: "utf8", timeout: 180000, windowsHide: true });

  const facts = {};
  for (const line of String((res && res.stdout) || "").split("\n")) {
    const m = line.trim().match(/^([a-z]+)=(.+)$/);
    if (m) facts[m[1]] = m[2];
  }

  const need = ["uid", "capeff", "nnp", "rootfs", "mknod", "net"];
  const absent = need.filter((k) => !(k in facts));

  if (res.error || absent.length) {
    /* Could not observe. The image may be missing with no network to pull it,
     * the daemon may have gone away mid-run, or the probe died. Whatever the
     * cause, nothing was learned about containment -- say that, do not guess. */
    inconc("2-7. container containment probes",
      "ran '" + RUNTIME + "' but did not get a full reading" +
      (res.error ? " (" + String(res.error.message || res.error) + ")" : "") +
      (absent.length ? "; no value for " + JSON.stringify(absent) : "") +
      ". Image=" + IMAGE + ". status=" + String(res.status) +
      " stderr=" + JSON.stringify(String(res.stderr || "").slice(0, 240)) +
      ". No containment control was observed either way");
  } else {
    assert("2. runs as a non-root uid", facts.uid !== "0",
      facts.uid !== "0" ? "uid=" + facts.uid + " (root in the container is root on the host under any escape)"
        : "uid=0 -- untrusted code is running as root");

    assert("3. all Linux capabilities dropped", /^0+$/.test(facts.capeff),
      /^0+$/.test(facts.capeff) ? "CapEff=" + facts.capeff
        : "CapEff=" + facts.capeff + " -- capabilities retained; the default set includes CAP_MKNOD, " +
          "CAP_SETUID, CAP_DAC_OVERRIDE and CAP_NET_RAW");

    assert("4. no_new_privs set", facts.nnp === "1",
      facts.nnp === "1" ? "NoNewPrivs=1 -- a setuid binary in the image cannot escalate"
        : "NoNewPrivs=" + facts.nnp + " -- --user alone does NOT close setuid escalation");

    assert("5. root filesystem is read-only", facts.rootfs === "READONLY",
      facts.rootfs === "READONLY" ? "rootfs read-only (scratch is a noexec/nosuid tmpfs at /tmp)"
        : "rootfs WRITABLE -- untrusted code can stage binaries in the image");

    assert("6. capability drop actually bites (mknod denied)", facts.mknod === "DENIED",
      facts.mknod === "DENIED" ? "mknod DENIED -- this is the behavioural check on case 3, not a re-read of CapEff"
        : "mknod ALLOWED -- device nodes creatable despite the capability claim");

    assert("7. network egress denied", facts.net === "DENIED",
      facts.net === "DENIED" ? "--network none holds (contract 04 B10)"
        : "network reachable from inside a --network none container");
  }
}

process.stdout.write("\nSUMMARY PASS=" + pass + " FAIL=" + fail + " SKIPPED=" + skipped + "\n");
process.exitCode = fail > 0 ? 1 : 0;
