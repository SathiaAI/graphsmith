/* GraphSmith v0.4.0 Lane R4 — graded trace_mode + secret/PII redaction battery (checks/v040-trace.js).
 * Verifies (a) the execution trace matches its declared `trace_mode` (full / redacted / metadata-only),
 * and (b) that a redacted/exported trace carries NO unredacted secret, PII, or credential — a leaked
 * secret in a trace is a fail-closed defect. The redaction battery is a recall-measured set of
 * secret/PII/credential patterns. Pure; C2 fail-closed. Schema: redaction-policy. Zero-dep CJS, Node >= 18.
 */
"use strict";

// Recall battery — secret / credential / PII patterns. A match in an exported trace = a leak.
const PATTERNS = [
  ["openai-key", /\bsk-[A-Za-z0-9]{20,}\b/],
  ["github-token", /\b(?:ghp|gho|ghs)_[A-Za-z0-9]{30,}\b/],
  ["github-pat", /\bgithub_pat_[A-Za-z0-9_]{40,}\b/],
  ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/],
  ["slack-token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ["bearer-token", /bearer\s+[A-Za-z0-9._~+/-]{20,}=*/i],
  ["private-key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ["assigned-secret", /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?[^\s"']{6,}/i],
  ["email-pii", /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/],
  ["ssn-pii", /\b\d{3}-\d{2}-\d{4}\b/],
  ["credit-card-pii", /\b(?:\d[ -]?){13,16}\b/],
];
const MODES = new Set(["full", "redacted", "metadata-only"]);

/* Scan a string for secret/PII/credential leaks. Returns the list of pattern names that matched. */
function scanLeaks(text) {
  const s = String(text == null ? "" : text);
  const hits = [];
  for (const [name, re] of PATTERNS) { if (re.test(s)) hits.push(name); }
  return hits;
}

/* ctx = { trace_mode, trace: string, redactions?: [ ... ] } */
function verifyTrace(ctx) {
  const evidence = [];
  const assumptions = [
    "The redaction battery is a recall-measured pattern set; a passing scan is a floor, not proof of zero leakage. Pure decision path (no clock/random/network).",
  ];
  const fail = (msg) => ({ status: "failed", evidence, assumptions, failure_domain: "untrusted-input", reason: msg });
  try {
    if (!ctx || typeof ctx !== "object") return fail("no context");
    if (!MODES.has(ctx.trace_mode)) return fail("trace_mode not in {full,redacted,metadata-only}");
    const trace = typeof ctx.trace === "string" ? ctx.trace : (ctx.trace == null ? "" : String(ctx.trace));

    // A leaked secret/PII/credential in ANY mode's exported trace fails closed.
    const leaks = scanLeaks(trace);
    if (leaks.length > 0) return { status: "failed", evidence: ["LEAK: exported trace contains unredacted " + leaks.join(", ") + " — fail-closed"], assumptions, failure_domain: "untrusted-input", reason: "secret/PII leak in trace" };

    // metadata-only must carry no payload bodies (heuristic: no long free-text values / no "content"/"input"/"output" payload keys).
    if (ctx.trace_mode === "metadata-only") {
      if (/"(?:content|input|output|payload|body|arguments)"\s*:/.test(trace)) return fail("metadata-only trace still carries payload fields — mode violated");
    }
    // redacted mode should record what was redacted (redactions[] preserved, chain intact).
    if (ctx.trace_mode === "redacted" && ctx.redactions !== undefined && !Array.isArray(ctx.redactions)) return fail("redacted mode: redactions must be an array");

    evidence.push("trace_mode '" + ctx.trace_mode + "': no secret/PII/credential leak detected across " + PATTERNS.length + " battery patterns.");
    return { status: "verified", evidence, assumptions };
  } catch (e) {
    return { status: "failed", evidence, assumptions, failure_domain: "trusted-core", reason: "exception — failing closed: " + (e && e.message ? e.message : String(e)) };
  }
}

const check = {
  id: "v040-trace",
  run(ctx) {
    const r = verifyTrace(ctx || {});
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice() };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason) { out.reason = r.reason; out.evidence.push("reason: " + r.reason); }
    return out;
  },
};

module.exports = { ...check, verifyTrace, scanLeaks, PATTERNS };

if (require.main === module && process.argv.includes("--selftest")) {
  const clean = check.run({ trace_mode: "full", trace: '{"step":1,"kind":"manager","status":"ok"}' });
  const leakedKey = check.run({ trace_mode: "redacted", trace: '{"note":"token sk-ABCDEFGHIJKLMNOPQRSTUV"}' });
  const leakedEmail = check.run({ trace_mode: "full", trace: '{"user":"alice@example.com"}' });
  const leakedPrivKey = check.run({ trace_mode: "full", trace: "-----BEGIN RSA PRIVATE KEY-----\nMIIB..." });
  const metaWithPayload = check.run({ trace_mode: "metadata-only", trace: '{"step":1,"content":"secret business logic"}' });
  const badMode = check.run({ trace_mode: "verbose", trace: "{}" });
  // Recall check: the battery must catch a representative secret set.
  const secrets = ["sk-ABCDEFGHIJKLMNOPQRSTUV", "ghp_" + "a".repeat(36), "AKIAABCDEFGHIJKLMNOP", "-----BEGIN PRIVATE KEY-----", "password: hunter2xyz", "bob@test.com", "123-45-6789"];
  const caught = secrets.filter((s) => scanLeaks(s).length > 0).length;
  const recall = caught / secrets.length;
  const pass = clean.status === "verified" && leakedKey.status === "failed" && leakedEmail.status === "failed" &&
    leakedPrivKey.status === "failed" && metaWithPayload.status === "failed" && badMode.status === "failed" && recall >= 0.95;
  console.log("v040-trace selftest:", pass ? "OK" : "FAIL",
    "| clean=" + (clean.status === "verified"), "leaked-key=" + (leakedKey.status === "failed"), "leaked-email=" + (leakedEmail.status === "failed"),
    "leaked-privkey=" + (leakedPrivKey.status === "failed"), "meta-payload-rejected=" + (metaWithPayload.status === "failed"),
    "bad-mode=" + (badMode.status === "failed"), "recall=" + (recall * 100).toFixed(0) + "% (" + caught + "/" + secrets.length + ")");
  process.exit(pass ? 0 : 1);
}
