/* POSITIVE CONTROL for tests/report-integrity.
 *
 * Deliberately emits a large JSON report using the exact anti-pattern this suite
 * exists to police -- process.stdout.write() followed immediately by
 * process.exit() -- so the suite can prove its own detector is live on the
 * current platform before trusting a green result from the real CLIs.
 *
 * Without this control, "all reports intact" is ambiguous: it could mean the CLIs
 * are correct, or it could mean the platform cannot exhibit the defect and the
 * checks above are inert. A regression suite that cannot distinguish those two is
 * the same silent-blindness failure it was written to catch.
 *
 * DO NOT "fix" this file. Its brokenness is the point.
 */

"use strict";

const payload = { schema_version: "1.0", control: "leaky-report", checks: [] };
// ~256 KB, comfortably past the pipe buffer on Linux (64 KB) and macOS (8-16 KB).
for (let i = 0; i < 2000; i += 1) {
  payload.checks.push({
    id: "control-check-" + i,
    pass: true,
    detail: "padding to push this report past any pipe buffer capacity ".repeat(2),
  });
}

process.stdout.write(JSON.stringify(payload, null, 2) + "\n");
process.exit(0);
