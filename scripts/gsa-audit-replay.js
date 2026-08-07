/* GraphSmith Attestation (GSA) audit replay — scripts/gsa-audit-replay.js.
 * Lane E (GSA follow-up track). Implements the report-generation half of
 * `graphsmith audit replay <bundle.json>` per
 * .plans/gsa-followup/LANE-E-AUDIT-REPLAY-DESIGN.md (frozen, adversarially
 * reviewed 2026-08-01). The CLI subcommand itself lives in
 * scripts/graphsmith-cli.js; this file is the pure report composer.
 *
 * FRAMING (design §1.1): this is a NARRATION layer over two already-built,
 * already-tested pure functions -- verifyBundle() (scripts/gsa-verify.js)
 * and replayBundle()/planDrift() (scripts/gsa-plan.js). This module never
 * recomputes a hash, never verifies a signature, never re-derives a control
 * attestation, and MUST NOT import Node's built-in crypto module or duplicate any of
 * verifyBundle's §9 comparison logic. That ban is enforced as a real,
 * executable check in tests/audit-replay/run-tests.js (GROUP 0), not just
 * this comment.
 *
 * THE LOAD-BEARING SECURITY INVARIANT (design §1.1, §3, §6.5): a dimension
 * may render 'verified' ONLY when verification_provenance is 'live' AND
 * verify_result.status is 'PASS'. Every other combination -- forged/
 * externally-supplied verify_result (verification_provenance:'external'),
 * or a live verify that itself failed -- renders EVERY dimension
 * 'unavailable', regardless of what the supplied verify_result claims.
 * buildDimensions() below has exactly one gate that decides this
 * (`eligible`); there is no other code path into the per-dimension
 * "verified"/"failed" computation. See tests/audit-replay/run-tests.js
 * GROUP 3 for adversarial unit tests constructed specifically to try to
 * defeat this invariant.
 *
 * Pure (no network/clock/random in the decision path -- `generated` is
 * 'unavailable' unless supplied as data by the caller, mirroring
 * gsa-produce.js's own `created: run.created || "unavailable"` pattern).
 * Zero-dep CJS, Node >= 18.
 */
"use strict";

const { replayBundle, planDrift } = require("./gsa-plan.js");
const { scanLeaks, PATTERNS } = require("../checks/v040-trace.js");

const TOOL_NAME = "graphsmith-audit-replay";

// ---------------------------------------------------------------------------
// Marker lists reused for the "marks" section (design §1.4). These are
// DATA -- narration search targets -- not decision logic; the actual
// determinism/control decisions are made by verifyBundle()/gsa-produce.js
// and only narrated here, never recomputed. Duplicated verbatim (not
// imported) because gsa-verify.js/gsa-plan.js do not export these lists;
// verified byte-for-byte against both files as of this build.
const NONDETERMINISTIC_MARKERS = ["skill_generated", "auto_promote", "remote_registry_fetch", "runtime_graph_modification", "unbounded_repair", "undeclared_network"];
const MODEL_DEP_MARKERS = ["model_call", "sampled", "nondeterministic", "llm_"];
// Mirrors gsa-verify.js §9.4's conditional-presence detection regex verbatim.
const REPAIR_MARKER_SOURCE = '"MUTATION_INTENT"|"repair"|"heal"';

const DIMENSION_IDS_BASE = ["provenance_signing", "capability_posture", "determinism_repair", "adversarial_coverage"];
const TITLES = {
  provenance_signing: "Provenance & signing",
  capability_posture: "Capability posture",
  determinism_repair: "Determinism & repair",
  adversarial_coverage: "Adversarial coverage",
  extended_controls_v040: "Extended controls (v0.4.0)",
};
const MODE_ENUM = new Set(["standard", "deterministic", "regulator"]);
const PROFILE_ENUM = new Set(["R", "E", "B", "T", "G", "Q", "A", "X"]);
const APPROVAL_ENUM = new Set(["approved", "quarantined", "generated", "revoked"]);
const SOURCE_ENUM = new Set(["local", "generated", "remote"]);

function own(o, k) { return o && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k); }

function jsonPointerEscape(s) { return String(s).replace(/~/g, "~0").replace(/\//g, "~1"); }

// ---------------------------------------------------------------------------
// §1: structural pre-flight — extract header fields, failing LOUDLY (throw)
// on a bundle too malformed to narrate at all. This is deliberately more
// tolerant than a schema validator: a bundle that is structurally plausible
// (has a manifest with a well-formed bundle_id/mode/profiles) but fails
// deep §9 verification (bad hash/signature/tamper) MUST still produce a
// report, per design §1.1 ("audit replay still runs ... every downstream
// dimension renders unavailable"). Only bundles too broken to even describe
// (no manifest, no bundle_id, no mode) throw here.
// ---------------------------------------------------------------------------
function extractHeaderFields(bundle) {
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    throw new TypeError("audit replay: malformed bundle — expected an object with { manifest, contents }");
  }
  const manifest = bundle.manifest;
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new TypeError("audit replay: malformed bundle — manifest missing or not an object");
  }
  if (typeof manifest.bundle_id !== "string" || !/^gsa-[0-9a-f]{16}$/.test(manifest.bundle_id)) {
    throw new TypeError("audit replay: malformed bundle — manifest.bundle_id missing or not in 'gsa-<16 hex>' form");
  }
  if (!MODE_ENUM.has(manifest.mode)) {
    throw new TypeError("audit replay: malformed bundle — manifest.mode missing or not in {standard,deterministic,regulator}");
  }
  const rawProfiles = Array.isArray(manifest.profiles) ? manifest.profiles : [];
  const asserted_profiles = [...new Set(rawProfiles.filter((p) => PROFILE_ENUM.has(p)))];
  const producer = (manifest.producer && typeof manifest.producer === "object") ? manifest.producer : {};
  return { manifest, bundle_id: manifest.bundle_id, mode: manifest.mode, asserted_profiles, producer };
}

function validateVerifyResultShape(v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) return "verify_result must be an object";
  if (v.status !== "PASS" && v.status !== "FAIL") return "verify_result.status must be 'PASS' or 'FAIL'";
  if (!Array.isArray(v.steps)) return "verify_result.steps must be an array";
  for (const s of v.steps) {
    if (!s || typeof s !== "object" || typeof s.step !== "string" || !["PASS", "FAIL", "UNAVAILABLE"].includes(s.status)) {
      return "verify_result.steps[] entries must have { step: string, status: PASS|FAIL|UNAVAILABLE }";
    }
  }
  if (!Array.isArray(v.confirmed_profiles) || !v.confirmed_profiles.every((p) => typeof p === "string")) return "verify_result.confirmed_profiles must be a string array";
  if (!Array.isArray(v.downgraded_profiles) || !v.downgraded_profiles.every((p) => typeof p === "string")) return "verify_result.downgraded_profiles must be a string array";
  if (typeof v.note !== "string") return "verify_result.note must be a string";
  return null;
}

// ---------------------------------------------------------------------------
// §2: marks — every occurrence of every marker, with byte offset into
// execution_trace (design §1.4). Plain string/regex search over unstructured
// JSONL; explicitly not a timeline (no ordering/click-to-jump guarantee).
// ---------------------------------------------------------------------------
function traceStringAndPointer(manifest, contents) {
  const ref = manifest && manifest.artifacts && manifest.artifacts.execution_trace;
  if (!ref || typeof ref.path !== "string") return { trace: "", pointer: null };
  const pointer = "/contents/" + jsonPointerEscape(ref.path);
  const body = contents ? contents[ref.path] : undefined;
  if (body === undefined) return { trace: "", pointer };
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  return { trace: buf.toString("utf8"), pointer };
}

function byteOffsetOf(str, charIndex) {
  return Buffer.byteLength(str.slice(0, charIndex), "utf8");
}

function findAllLiteral(haystack, needle) {
  const idxs = [];
  if (!needle) return idxs;
  let i = haystack.indexOf(needle);
  while (i !== -1) { idxs.push(i); i = haystack.indexOf(needle, i + needle.length); }
  return idxs;
}

function buildMarks(manifest, contents) {
  const { trace, pointer } = traceStringAndPointer(manifest, contents);
  const marks = [];
  if (!pointer || !trace) return marks;
  for (const marker of NONDETERMINISTIC_MARKERS) {
    for (const i of findAllLiteral(trace, marker)) marks.push({ marker, list: "nondeterministic", pointer, offset: byteOffsetOf(trace, i) });
  }
  for (const marker of MODEL_DEP_MARKERS) {
    for (const i of findAllLiteral(trace, marker)) marks.push({ marker, list: "model-dependent", pointer, offset: byteOffsetOf(trace, i) });
  }
  const re = new RegExp(REPAIR_MARKER_SOURCE, "g");
  let m;
  while ((m = re.exec(trace)) !== null) {
    marks.push({ marker: m[0], list: "repair", pointer, offset: byteOffsetOf(trace, m.index) });
    if (m[0].length === 0) re.lastIndex++; // defensive: this alternation never matches empty, but guard against infinite loop regardless
  }
  marks.sort((a, b) => a.offset - b.offset || a.marker.localeCompare(b.marker) || a.list.localeCompare(b.list));
  return marks;
}

const MARK_EXCERPT_RADIUS = 48; // chars either side of the first occurrence of each unique marker
const MARK_EXCERPT_CAP = 8; // bound the number of raw-trace excerpts added per report

/* THE one place this module copies raw execution_trace bytes into a
 * newly-distributed evidence excerpt (design §7 risk #1: "the first
 * GraphSmith tool whose purpose is to copy raw bytes out of execution_trace
 * into a newly-distributed artifact"). Deliberately unconditional (runs
 * regardless of verification_provenance/verify status, same as marks
 * themselves).
 *
 * SECURITY: `trace` here MUST already be redacted (see composeReport(),
 * which calls redactString() on the full trace before calling this
 * function) — not the raw execution_trace. Redacting only *after* slicing
 * the ±MARK_EXCERPT_RADIUS window (the original design) let a secret that
 * straddled the window boundary get truncated mid-token, so the
 * full-token-length redaction patterns (jwt, hex-token, etc.) would never
 * match the truncated fragment and it would ship unredacted — silently,
 * since redactReport() only logs a redaction event when something actually
 * matched. Redacting the full trace first means any secret is substituted
 * with a "[redacted-by-audit-replay: ...]" placeholder before the excerpt
 * window is ever cut, so truncation can only ever slice into already-safe
 * text. redactReport() still runs on the resulting excerpt below (in
 * composeReport()) as defense in depth; it should normally be a no-op here
 * since this text is already redacted. Bounded to MARK_EXCERPT_CAP unique
 * markers so a trace with thousands of repeated hits doesn't bloat the
 * report; only the first occurrence of each unique marker is excerpted. */
// Matches a redaction placeholder verbatim (see redactString()). Used only
// to widen an excerpt window so it never cuts a placeholder in half -- see
// addMarkExcerptEvidence below.
const REDACTION_PLACEHOLDER_RE = /\[redacted-by-audit-replay: [^\]]*\]/g;

function addMarkExcerptEvidence(trace, marks, addEvidence) {
  if (!trace || !marks.length) return;
  const seen = new Set();
  for (const mk of marks) {
    if (seen.has(mk.marker)) continue;
    if (seen.size >= MARK_EXCERPT_CAP) break;
    seen.add(mk.marker);
    const charIdx = trace.indexOf(mk.marker);
    if (charIdx === -1) continue; // defensive; should always be found since marks were derived from this same trace
    let start = Math.max(0, charIdx - MARK_EXCERPT_RADIUS);
    let end = Math.min(trace.length, charIdx + mk.marker.length + MARK_EXCERPT_RADIUS);
    // `trace` is already redacted (see composeReport()), so what the raw
    // ±radius window can now cut through is a "[redacted-by-audit-replay:
    // ...]" placeholder rather than a raw secret -- not a leak, but a
    // garbled/truncated placeholder is confusing and untrustworthy-looking
    // in a report whose whole job is trustworthy narration. Widen the
    // window to fully include any placeholder it partially overlaps.
    REDACTION_PLACEHOLDER_RE.lastIndex = 0;
    let pm;
    while ((pm = REDACTION_PLACEHOLDER_RE.exec(trace))) {
      const pStart = pm.index;
      const pEnd = pm.index + pm[0].length;
      if (pStart < end && pEnd > start) {
        if (pStart < start) start = pStart;
        if (pEnd > end) end = pEnd;
      }
    }
    const excerpt = trace.slice(start, end);
    addEvidence(mk.pointer, "raw execution_trace excerpt surrounding marker '" + mk.marker + "' (" + mk.list + ") at byte offset " + mk.offset, excerpt);
  }
}

// ---------------------------------------------------------------------------
// §3: skills lens — flat-list filter + naive trace string-search, explicitly
// labeled a downgrade from an "agent lens" (design §2: skills[] has no call
// graph). trace_mentions is co-occurrence evidence, never an invocation
// count (schema description).
// ---------------------------------------------------------------------------
function buildSkillsLens(manifest, contents, lens) {
  const { trace } = traceStringAndPointer(manifest, contents);
  const skills = Array.isArray(manifest.skills) ? manifest.skills : [];
  let list = skills.map((s) => {
    const skill_id = typeof (s && s.skill_id) === "string" ? s.skill_id : "";
    const entry = {
      skill_id,
      version: typeof (s && s.version) === "string" ? s.version : "",
      // NOTE (flagged for reviewer): approval_status/source are passed
      // through verbatim even when outside {approved,quarantined,generated,
      // revoked} / {local,generated,remote} -- attestation-bundle's own
      // producer selftest (scripts/gsa-verify.js --selftest,
      // scripts/gsa-produce.js --selftest) uses source:"authored", which is
      // NOT in that enum, and verifyBundle() never checks it, so a
      // real bundle that legitimately PASSes live verification can still
      // carry an out-of-enum value here. Throwing on it would make
      // audit-replay reject bundles gsa-verify.js itself accepts, which
      // would be a strictly worse trust boundary than the one being
      // narrated. The tradeoff: a report built from such a bundle will not
      // itself strictly validate against schemas/audit-replay-report.
      // schema.json's skillLensEntry enum for that one field. See the
      // build report for this open question.
      approval_status: (s && s.approval_status) != null ? s.approval_status : "quarantined",
      source: (s && s.source) != null ? s.source : "remote",
      trace_mentions: skill_id ? findAllLiteral(trace, skill_id).length : 0,
    };
    if (typeof (s && s.signer) === "string") entry.signer = s.signer;
    return entry;
  });
  if (lens) list = list.filter((e) => e.skill_id === lens);
  return list;
}

// ---------------------------------------------------------------------------
// §4: dimensions. THE structural invariant lives here — see file header.
// ---------------------------------------------------------------------------
function computeRealDimension(id, manifest, addEvidence) {
  if (id === "provenance_signing") {
    const ctrl = manifest.control_attestations || {};
    const ok = ctrl.all_skills_signed_and_approved === true;
    const skills = Array.isArray(manifest.skills) ? manifest.skills : [];
    const evidence = [
      addEvidence("/manifest/bundle_signature", "bundle_signature — confirmed valid by live §9.5", manifest.bundle_signature && manifest.bundle_signature.algo),
      addEvidence("/manifest/graph_signature", "graph_signature — confirmed valid by live §9.6", manifest.graph_signature && manifest.graph_signature.algo),
      addEvidence("/manifest/control_attestations/all_skills_signed_and_approved", "recomputed control (§9.9)", String(ok)),
      addEvidence("/manifest/skills", skills.length + " skill(s) in provenance list"),
    ];
    const out = { id, title: TITLES[id], status: ok ? "verified" : "failed", evidence, assumptions: ["Signature validity is as computed by live verifyBundle(); this dimension only narrates control_attestations.all_skills_signed_and_approved."] };
    if (!ok) out.reason = "control_attestations.all_skills_signed_and_approved is false — not every skill in skills[] is signed, approved, and non-revoked.";
    return out;
  }
  if (id === "capability_posture") {
    const caps = manifest.capabilities || {};
    const evidence = [
      addEvidence("/manifest/capabilities/result", "capabilities.result as attested", String(caps.result)),
      addEvidence("/manifest/capabilities/resources", "declared per-resource-class capability grants (filesystem/network/models/subprocess)"),
    ];
    let ok = caps.result === "satisfied";
    const ext = manifest.control_attestations_v040;
    if (ext && typeof ext === "object" && own(ext, "capability_conformance")) {
      evidence.push(addEvidence("/manifest/control_attestations_v040/capability_conformance", "extended v0.4.0 capability conformance — recomputed by live §9.11", String(ext.capability_conformance)));
      ok = ok && ext.capability_conformance === true;
    }
    const out = { id, title: TITLES[id], status: ok ? "verified" : "failed", evidence, assumptions: ["capabilities.result is a per-run attested value (not itself re-derived by verifyBundle's base §9 checks); the extended v0.4.0 capability_conformance control, when declared, IS recomputed by §9.11."] };
    if (!ok) out.reason = "capabilities.result is not 'satisfied'" + (ext && own(ext, "capability_conformance") && ext.capability_conformance !== true ? ", and/or extended control_attestations_v040.capability_conformance recomputed to false" : "") + ".";
    return out;
  }
  if (id === "determinism_repair") {
    const ctrl = manifest.control_attestations || {};
    const requiresDeterminism = manifest.mode === "deterministic" || manifest.mode === "regulator";
    const detFlag = ctrl.deterministic_mode === true;
    const ok = requiresDeterminism ? detFlag : true;
    const evidence = [
      addEvidence("/manifest/mode", "declared mode", manifest.mode),
      addEvidence("/manifest/control_attestations/deterministic_mode", "recomputed control (§9.9)", String(detFlag)),
    ];
    if (own(manifest.artifacts || {}, "repair_log")) evidence.push(addEvidence("/manifest/artifacts/repair_log", "repair_log artifact present — a repair occurred during this run"));
    const out = { id, title: TITLES[id], status: ok ? "verified" : "failed", evidence, assumptions: ["deterministic_mode is a recomputed control (§9.9): true only if mode is deterministic/regulator AND no NONDETERMINISTIC_MARKERS string is present in execution_trace."] };
    if (!ok) out.reason = "mode='" + manifest.mode + "' requires determinism but control_attestations.deterministic_mode recomputed to false (a nondeterministic marker was found in execution_trace).";
    return out;
  }
  if (id === "adversarial_coverage") {
    const ctrl = manifest.control_attestations || {};
    const ok = ctrl.adversarial_batteries_passed === true;
    const suites = (manifest.adversarial && Array.isArray(manifest.adversarial.suites)) ? manifest.adversarial.suites : [];
    const evidence = [
      addEvidence("/manifest/control_attestations/adversarial_batteries_passed", "recomputed control (§9.9)", String(ok)),
      addEvidence("/manifest/adversarial/suites", suites.length + " suite(s) reported"),
    ];
    const out = { id, title: TITLES[id], status: ok ? "verified" : "failed", evidence, assumptions: ["adversarial_batteries_passed is a recomputed control (§9.9): true only if every suite's blocked === total and total > 0."] };
    if (!ok) out.reason = "control_attestations.adversarial_batteries_passed is false — not every adversarial suite fully blocked its total.";
    return out;
  }
  if (id === "extended_controls_v040") {
    const ext = (manifest.control_attestations_v040 && typeof manifest.control_attestations_v040 === "object") ? manifest.control_attestations_v040 : {};
    const keys = Object.keys(ext);
    const failedKeys = keys.filter((k) => ext[k] !== true);
    const evidence = [addEvidence("/manifest/control_attestations_v040", keys.length + " declared extended control(s): " + keys.join(", "), JSON.stringify(ext))];
    const ok = keys.length > 0 && failedKeys.length === 0;
    const out = { id, title: TITLES[id], status: ok ? "verified" : "failed", evidence, assumptions: ["Each declared v0.4.0 control was RECOMPUTED and confirmed to match by live §9.11 — this dimension is only reachable when verification_provenance is 'live' and verify_result.status is 'PASS' (see buildDimensions' eligibility gate)."] };
    if (!ok) out.reason = keys.length === 0 ? "control_attestations_v040 present but declares no controls." : "extended control(s) recomputed false: " + failedKeys.join(", ") + ".";
    return out;
  }
  throw new Error("audit replay: unknown dimension id '" + id + "'");
}

function buildDimensions(manifest, provenance, verifyResult, addEvidence) {
  const hasExt = own(manifest, "control_attestations_v040");
  const ids = hasExt ? DIMENSION_IDS_BASE.concat(["extended_controls_v040"]) : DIMENSION_IDS_BASE.slice();

  // ============================================================
  // THE structural invariant gate (design §1.1 / §3 / §6.5). This is the
  // ONLY branch point anywhere in this module that can lead to a
  // dimension.status of 'verified'. Do not add a second path into
  // computeRealDimension() below — doing so would reopen the forgery hole
  // the adversarial review found and fixed (a hand-written fake
  // verify_result producing a 'verified'-labeled report).
  // ============================================================
  const eligible = provenance === "live" && !!verifyResult && verifyResult.status === "PASS";

  if (!eligible) {
    let reason;
    if (provenance !== "live") {
      reason = "verification_provenance is 'external' — the supplied verify_result was not independently confirmed by a live verifyBundle() run and cannot be trusted; rendering unavailable per design §1.1/§6.5.";
    } else {
      const steps = (verifyResult && Array.isArray(verifyResult.steps)) ? verifyResult.steps : [];
      const failedStep = steps.find((s) => s && s.status === "FAIL");
      reason = "live verification did not PASS" + (failedStep ? " (failed at " + failedStep.step + (failedStep.detail ? ": " + failedStep.detail : "") + ")" : (verifyResult && verifyResult.note ? " (" + verifyResult.note + ")" : "")) + "; rendering unavailable per design §6.5.";
    }
    return ids.map((id) => ({
      id,
      title: TITLES[id],
      status: "unavailable",
      evidence: [addEvidence("/manifest/mode", "bundle is real and present; this dimension is unavailable due to verification status/provenance, not to bundle content", manifest.mode)],
      assumptions: ["A dimension can only render 'verified' when verification_provenance is 'live' and verify_result.status is 'PASS' (design §1.1, §6.5)."],
      reason,
    }));
  }

  return ids.map((id) => computeRealDimension(id, manifest, addEvidence));
}

// ---------------------------------------------------------------------------
// §5: narrative — template-composed only, never LLM-generated (design §1.2).
// Every fact stated here is one already computed above and traceable to
// evidence_index/dimensions/verify_result/replay_result/marks/drift.
// ---------------------------------------------------------------------------
function buildNarrative({ provenance, verifyResult, replay_result, dimensions, marks, drift }) {
  const parts = [];
  parts.push("Verification provenance: " + provenance + " (verify_result.status=" + (verifyResult && verifyResult.status) + ").");
  const eligible = provenance === "live" && verifyResult && verifyResult.status === "PASS";
  if (!eligible) parts.push("Because verification is not a confirmed live PASS, every dimension below is rendered unavailable — no claim in this report should be read as confirmed trust.");
  const verifiedCount = dimensions.filter((d) => d.status === "verified").length;
  const failedCount = dimensions.filter((d) => d.status === "failed").length;
  const unavailCount = dimensions.filter((d) => d.status === "unavailable").length;
  parts.push(verifiedCount + " of " + dimensions.length + " dimension(s) verified, " + failedCount + " failed, " + unavailCount + " unavailable.");
  parts.push("Replay: reproducible=" + replay_result.reproducible + ", deterministic_confirmed=" + replay_result.deterministic_confirmed + ", " + replay_result.mismatches.length + " mismatch(es), " + replay_result.non_replayable.length + " non-replayable step(s).");
  parts.push(marks.length + " marker occurrence(s) found in execution_trace.");
  if (drift) parts.push("Drift vs prior bundle: " + (drift.safe ? "no destructive changes." : drift.destructive.length + " destructive change(s) detected."));
  return parts.join(" ");
}

// ---------------------------------------------------------------------------
// §6: leak-scan-and-redact (design §6.4). Detection reuses
// checks/v040-trace.js#scanLeaks() verbatim (a recall-measured floor, not
// proof of zero leakage — same honest framing as that module's own docs).
// The substitution-and-evidence-recording step is new code with no existing
// analog to reuse, per §6.4/§8 of the design.
// ---------------------------------------------------------------------------
const PATTERN_MAP = new Map(PATTERNS);

function redactString(s) {
  if (typeof s !== "string" || s.length === 0) return { text: s, hits: [] };
  const names = scanLeaks(s); // detection only, reused verbatim from checks/v040-trace.js
  if (names.length === 0) return { text: s, hits: [] };
  let text = s;
  const hits = [];
  for (const name of names) {
    const re = PATTERN_MAP.get(name);
    if (!re) continue;
    const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
    const g = new RegExp(re.source, flags);
    text = text.replace(g, () => { hits.push(name); return "[redacted-by-audit-replay: " + name + "]"; });
  }
  return { text, hits };
}

/* Mutates and returns `report`: scans every evidence_index[].excerpt and the
 * narrative for known secret/PII/credential patterns, substitutes each
 * match, and records the substitution itself as a NEW evidence_index entry
 * (never silently dropped — design §6.4). Runs unconditionally, even for
 * v0.3.0-only bundles with no trace_redaction control at all. */
function redactReport(report) {
  const events = [];
  for (const entry of report.evidence_index) {
    if (typeof entry.excerpt === "string") {
      const { text, hits } = redactString(entry.excerpt);
      if (hits.length) { entry.excerpt = text; events.push({ pointer: entry.pointer, patterns: hits }); }
    }
  }
  {
    const { text, hits } = redactString(report.narrative);
    if (hits.length) { report.narrative = text; events.push({ pointer: "/narrative", patterns: hits }); }
  }
  for (const ev of events) {
    report.evidence_index.push({
      pointer: ev.pointer,
      description: "leak-scan-and-redact: pattern(s) [" + ev.patterns.join(", ") + "] detected via checks/v040-trace.js#scanLeaks() and substituted at " + ev.pointer + " (a recall-measured floor, not proof of zero leakage — design §6.4).",
    });
  }
  return report;
}

// ---------------------------------------------------------------------------
// §7: top-level composer.
// ---------------------------------------------------------------------------
/* opts = {
 *   bundle: { manifest, contents },
 *   verificationProvenance: "live" | "external",
 *   verifyResult: <verifyBundle() output, live or caller-supplied>,
 *   prevBundle?: { manifest, contents }   -- enables `drift` via planDrift()
 *   lens?: string                        -- filters skills_lens to one skill_id
 *   generated?: string                   -- "unavailable" unless caller supplies a real timestamp as data
 *   toolVersion: string
 * } */
function composeReport(opts) {
  opts = opts || {};
  if (opts.verificationProvenance !== "live" && opts.verificationProvenance !== "external") {
    throw new TypeError("audit replay: verificationProvenance must be 'live' or 'external'");
  }
  const shapeErr = validateVerifyResultShape(opts.verifyResult);
  if (shapeErr) throw new TypeError("audit replay: malformed verify_result — " + shapeErr);

  const { manifest, bundle_id, mode, asserted_profiles, producer } = extractHeaderFields(opts.bundle);
  const contents = (opts.bundle && opts.bundle.contents && typeof opts.bundle.contents === "object") ? opts.bundle.contents : {};
  void producer; // header field retained on the manifest; not part of the frozen §3 schema's top level (schema has no `producer` key) — see build report.

  const evidence_index = [];
  function addEvidence(pointer, description, excerptRaw) {
    const entry = { pointer, description };
    if (excerptRaw !== undefined && excerptRaw !== null) entry.excerpt = String(excerptRaw);
    evidence_index.push(entry);
    return entry;
  }

  const replay_result = replayBundle(opts.bundle); // always computed — pure, safe regardless of provenance/verify status
  const dimensions = buildDimensions(manifest, opts.verificationProvenance, opts.verifyResult, addEvidence);
  const marks = buildMarks(manifest, contents);
  const { trace: traceStr, pointer: tracePointer } = traceStringAndPointer(manifest, contents);
  // Redact the FULL trace before slicing excerpts, not after -- see
  // addMarkExcerptEvidence's header comment for why (excerpt-window
  // truncation could otherwise defeat full-token-length redaction patterns).
  // This redaction happens before any excerpt is added to evidence_index, so
  // redactReport() below won't see these hits on its own pass -- record the
  // same "leak-scan-and-redact" audit-trail entry here that redactReport()
  // would have produced, so a redaction here is never silently dropped
  // (design §6.4), matching the guarantee redactReport() gives every other
  // evidence entry.
  const { text: redactedTraceStr, hits: traceHits } = redactString(traceStr);
  if (traceHits.length && tracePointer) {
    addEvidence(tracePointer, "leak-scan-and-redact: pattern(s) [" + traceHits.join(", ") + "] detected via checks/v040-trace.js#scanLeaks() and substituted at " + tracePointer + " (a recall-measured floor, not proof of zero leakage — design §6.4).");
  }
  addMarkExcerptEvidence(redactedTraceStr, marks, addEvidence); // excerpts sliced from the already-redacted trace; redactReport() below still scans them as defense in depth
  const skills_lens = buildSkillsLens(manifest, contents, opts.lens);

  let drift;
  if (opts.prevBundle) drift = planDrift(opts.prevBundle, opts.bundle);

  const narrative = buildNarrative({ provenance: opts.verificationProvenance, verifyResult: opts.verifyResult, replay_result, dimensions, marks, drift });

  const report = {
    schema_version: "0.2",
    tool: { name: TOOL_NAME, version: opts.toolVersion || "0.0.0" },
    bundle_id,
    generated: opts.generated || "unavailable",
    mode,
    asserted_profiles,
    verification_provenance: opts.verificationProvenance,
    verify_result: opts.verifyResult,
    replay_result,
    dimensions,
    marks,
    skills_lens,
    narrative,
    evidence_index,
  };
  if (drift) report.drift = drift;

  return redactReport(report);
}

module.exports = {
  composeReport,
  validateVerifyResultShape,
  buildDimensions,
  buildMarks,
  buildSkillsLens,
  buildNarrative,
  redactString,
  redactReport,
  extractHeaderFields,
  DIMENSION_IDS_BASE,
  TOOL_NAME,
};
