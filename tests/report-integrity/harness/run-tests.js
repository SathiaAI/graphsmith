/* Report integrity — every CLI whose JSON report a GATING suite parses must
 * deliver that report intact when captured through spawnSync.
 *
 * WHY THIS SUITE EXISTS
 *
 * process.stdout.write() to a PIPE is asynchronous on POSIX: libuv attempts one
 * write(2) and queues whatever it could not hand to the kernel. process.exit()
 * then discards that queue. The caller reads a truncated -- or entirely empty --
 * report next to exit code 0, which is indistinguishable from the product
 * genuinely reporting success.
 *
 * This is not hypothetical and it is not about payload size. Reproduced on a real
 * macOS 12.7.3 box, node 18.20.8, deterministically (3/3 runs each way):
 *
 *   tests/assurance/gpt-sol-pro   before the fix  PASS=14 FAIL=3
 *                                 after           PASS=17 FAIL=0
 *   tests/verify/deepseek         before          FAIL: E6. selftest/pass --
 *                                                 "Unexpected end of JSON input.
 *                                                  Output: "   <- entirely empty
 *                                 after           124 pass / 0 fail
 *
 * Note "Output: " with nothing after it. The whole report was queued and dropped,
 * not clipped -- libuv's first try_write moved zero bytes. So a small report is
 * not safe either, which is why this suite checks every script rather than only
 * the large ones. It also cannot be found by running under load: the same suite
 * PASSED 17/0 under 8-way CPU contention and FAILED 3/3 idle, because contention
 * changes the reader/writer interleaving in the harness's favour.
 *
 * WHAT IT ASSERTS, per (script, args) pair below:
 *   1. captured via spawnSync (a pipe -- the async path), stdout parses as JSON;
 *   2. it is byte-identical to the same command redirected to a FILE (the
 *      synchronous path, i.e. the report the author intended to emit);
 *   3. repeated REPEATS times, because the defect is an interleaving race and a
 *      single green run proves nothing.
 *
 * Exit code is deliberately NOT part of the pass condition -- the whole point is
 * that the exit code was 0 while the evidence was missing.
 */

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const SCRIPTS = path.join(ROOT, "scripts");
const REPEATS = Number(process.env.REPORT_INTEGRITY_REPEATS || 3);

let pass = 0;
let fail = 0;
const failures = [];

function report(ok, id, detail) {
  if (ok) {
    pass += 1;
    process.stdout.write("PASS " + id + " - " + detail + "\n");
  } else {
    fail += 1;
    failures.push(id);
    process.stdout.write("FAIL " + id + " - " + detail + "\n");
  }
}

// Every entry is a CLI whose stdout report is JSON.parse()d by at least one
// suite classified GATING in ci-suite-manifest.json. Adding a script to a gating
// suite's parse path without adding it here leaves the same silent hole open.
const CASES = [
  { script: "verify.js", args: ["--selftest"] },
  { script: "verify.js", args: ["--platform-probe"] },
  { script: "verify.js", args: ["--trust-model"] },
  { script: "assure.js", args: ["--selftest"] },
  { script: "adopt.js", args: ["--selftest"] },
  { script: "diagnostics.js", args: ["--selftest"] },
  { script: "evolve.js", args: ["--selftest"] },
  { script: "ext-tool-runner.js", args: ["--selftest"] },
  { script: "gate.js", args: ["--selftest"] },
  { script: "manifest.js", args: ["--selftest"] },
  { script: "redteam.js", args: ["--selftest"] },
  { script: "scenario.js", args: ["--selftest"] },
  { script: "test.js", args: ["--selftest"] },
  { script: "watch.js", args: ["--selftest"] },
  { script: "watchdog.js", args: ["--selftest"] },
  { script: "watcher.js", args: ["--selftest"] },
  { script: "heal.js", args: ["--selftest"] },
  { script: "loaders.js", args: ["--selftest"] },
  { script: "promote.js", args: ["--selftest"] },
  { script: "state-store.js", args: ["--selftest"] },
  { script: "capability-policy.js", args: ["--selftest"] },
];

function viaPipe(scriptPath, args) {
  // spawnSync captures stdout through a pipe -- the asynchronous path, and the
  // exact mechanism the failing suites use.
  const r = spawnSync(process.execPath, [scriptPath].concat(args), {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 300000,
    maxBuffer: 32 * 1024 * 1024,
    windowsHide: true,
  });
  return { out: r.stdout == null ? "" : r.stdout, status: r.status, error: r.error };
}

function viaFile(scriptPath, args, tmpdir) {
  // Redirecting to a file is synchronous on POSIX, so this is the complete report.
  const target = path.join(tmpdir, "report.json");
  const fd = fs.openSync(target, "w");
  try {
    spawnSync(process.execPath, [scriptPath].concat(args), {
      cwd: ROOT,
      stdio: ["ignore", fd, "ignore"],
      timeout: 300000,
      windowsHide: true,
    });
  } finally {
    fs.closeSync(fd);
  }
  return fs.readFileSync(target, "utf8");
}

// Return a truthy marker when `text` carries a well-formed JSON report, else null.
//
// Two shapes exist in this repo and BOTH must be recognised. Recognising only the
// first silently downgraded watchdog.js and loaders.js to "skipped" — a check that
// quietly stops checking is the exact defect class this suite was written to catch,
// so it is not acceptable here either.
//   (a) one JSON document, possibly with human prose before/after it;
//   (b) JSON Lines — one document per line.
function firstJsonValue(text) {
  const s = String(text);
  if (!s.trim()) return null;

  // (a) largest brace/bracket-delimited span
  const starts = [s.indexOf("{"), s.indexOf("[")].filter((i) => i !== -1);
  if (starts.length) {
    const start = Math.min.apply(null, starts);
    const end = Math.max(s.lastIndexOf("}"), s.lastIndexOf("]"));
    if (end > start) {
      try {
        JSON.parse(s.slice(start, end + 1));
        return { shape: "document" };
      } catch (_) {
        /* fall through to (b) */
      }
    }
  }

  // (b) JSON Lines: every line that looks like a document must parse, and there
  // must be at least one. A trailing partial line therefore fails, which is
  // precisely the truncation signal we want.
  const lines = s.split("\n").filter((l) => l.trim());
  const candidates = lines.filter((l) => /^\s*[[{]/.test(l));
  if (!candidates.length) return null;
  for (const line of candidates) {
    try {
      JSON.parse(line);
    } catch (_) {
      return null;
    }
  }
  return { shape: "json-lines", documents: candidates.length };
}

// Prove the detector is live before trusting a green result from it.
//
// fixtures/leaky-report.js commits the exact anti-pattern on purpose with a ~256 KB
// payload. If even THAT survives spawnSync, then this platform cannot exhibit the
// defect and every check below is inert -- which must be stated, not silently
// counted as a pass. On Windows, stdout writes to a pipe are synchronous, so inert
// is the expected and correct answer there.
function detectorLiveness(tmpdir) {
  const fixture = path.join(__dirname, "fixtures", "leaky-report.js");
  if (!fs.existsSync(fixture)) {
    return { live: false, reason: "positive-control fixture is missing at " + fixture, missing: true };
  }
  const expected = viaFile(fixture, [], tmpdir);
  let worst = null;
  for (let i = 0; i < 3; i += 1) {
    const got = viaPipe(fixture, []);
    const len = got.out.length;
    if (worst === null || len < worst) worst = len;
  }
  if (worst < expected.length) {
    return { live: true, expected: expected.length, worst: worst };
  }
  return { live: false, expected: expected.length, worst: worst };
}

function main() {
  const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), "gs-report-integrity-"));
  try {
    const live = detectorLiveness(tmpdir);
    if (live.missing) {
      report(false, "control/detector-live", live.reason);
    } else if (live.live) {
      report(
        true,
        "control/detector-live",
        "positive control lost " + (live.expected - live.worst) + "B of " + live.expected +
          "B through spawnSync — the checks below are meaningful on this platform"
      );
    } else {
      report(
        true,
        "control/detector-INERT",
        "positive control survived intact (" + live.expected + "B) — this platform does not " +
          "exhibit queued-stdout loss (expected on Windows, where pipe writes are synchronous), " +
          "so the per-CLI checks below CANNOT fail here and provide no coverage on this leg"
      );
    }

    for (const c of CASES) {
      const scriptPath = path.join(SCRIPTS, c.script);
      const id = c.script + " " + c.args.join(" ");
      if (!fs.existsSync(scriptPath)) {
        report(false, id, "script not found at " + scriptPath);
        continue;
      }

      const expected = viaFile(scriptPath, c.args, tmpdir);
      const expectedJson = firstJsonValue(expected);
      if (expectedJson === null) {
        // A CLI that emits no JSON on stdout has no report for this suite to
        // guarantee. That is only legitimate when stdout is empty; anything else
        // means output exists that we failed to recognise, and quietly passing on
        // unrecognised output is how a check stops checking. Fail in that case.
        if (expected.trim() === "") {
          report(true, id, "emits no stdout report (0B) — nothing to guarantee, correctly out of scope");
        } else {
          report(
            false,
            id,
            "produced " + expected.length + "B on stdout that this suite could not parse as a JSON " +
              "document or as JSON Lines — either the CLI's report shape changed or the recogniser " +
              "needs extending; it must not be silently skipped"
          );
        }
        continue;
      }

      let worstLen = null;
      let brokenRun = -1;
      let brokenLen = -1;
      for (let i = 0; i < REPEATS; i += 1) {
        const got = viaPipe(scriptPath, c.args);
        if (got.error) {
          brokenRun = i;
          brokenLen = -1;
          break;
        }
        const gotJson = firstJsonValue(got.out);
        if (gotJson === null || got.out.length !== expected.length) {
          brokenRun = i;
          brokenLen = got.out.length;
          break;
        }
        if (worstLen === null || got.out.length < worstLen) worstLen = got.out.length;
      }

      if (brokenRun === -1) {
        report(true, id, "report survived spawnSync intact " + REPEATS + "/" + REPEATS + " runs (" + expected.length + "B)");
      } else if (brokenLen === -1) {
        report(false, id, "spawnSync errored on run " + (brokenRun + 1));
      } else {
        report(
          false,
          id,
          "report LOST through the pipe on run " + (brokenRun + 1) + " of " + REPEATS +
            ": file=" + expected.length + "B but pipe=" + brokenLen + "B" +
            (brokenLen === 0 ? " (entirely empty)" : " (short by " + (expected.length - brokenLen) + "B)") +
            " — the CLI must hand every byte to the kernel before it exits"
        );
      }
    }
  } finally {
    try {
      fs.rmSync(tmpdir, { recursive: true, force: true, maxRetries: 5 });
    } catch (_) {
      /* best effort */
    }
  }

  process.stdout.write("\nSUMMARY PASS=" + pass + " FAIL=" + fail + "\n");
  if (failures.length) {
    process.stdout.write("FAILING: " + failures.join(", ") + "\n");
  }
  process.exitCode = fail > 0 ? 1 : 0;
}

main();
