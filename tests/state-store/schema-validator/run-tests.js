#!/usr/bin/env node
"use strict";

/* tests/state-store/schema-validator/run-tests.js
 *
 * Round 9 (2026-08-29) Option-2 triage on state-store.js. `schemaErrors()` (the recursive
 * draft-2020-12 subset validator at scripts/state-store.js:59-109) is the single largest
 * concentration of surviving mutants in the file -- every existing suite only ever feeds it
 * records the PRODUCT itself constructs, which are always well-formed on the happy path and
 * always hit the same handful of branches (string $refs, one enum, one required check). Most
 * of its type-dispatch branches (`"null"`, `"object"` vs an array, `"array"`, `"integer"`,
 * `"number"`, and the string/boolean fallback), its numeric bounds (minimum/exclusiveMinimum/
 * maximum), its string bounds (minLength/pattern), its array bounds (minItems) and its
 * items-array bubbling (`${location}[${index}]`) are never exercised on their FAILING side by
 * anything.
 *
 * `validateNamedRecord(record, defName, context)` is exported specifically to validate one
 * named $def directly (see its own doc comment in scripts/state-store.js), and every named
 * $def in schemas/state-store.schema.json -- including the normally-internal ones like `slot`,
 * `journalEffect`, `version`, `revision` and `nonEmpty` -- is reachable through it. That means
 * this suite can drive schemaErrors() through nearly every branch with deliberately malformed
 * records, with no need to go through a full StateStore instance at all. */

const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const stateStore = require(path.join(ROOT, "scripts", "state-store.js"));

let failures = 0;
const results = [];

function record(name, status, reason) {
  const line = status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function check(name, cond, reason) {
  if (cond) record(name, "PASS"); else record(name, "FAIL", reason);
}

function tryValidate(defName, value) {
  try { stateStore.validateNamedRecord(value, defName, "ctx"); return { threw: null }; }
  catch (error) { return { threw: error }; }
}

function expectValid(name, defName, value) {
  const { threw } = tryValidate(defName, value);
  check(name, threw === null, `expected ${defName} to validate, got ${threw && threw.message}`);
}

/* Asserts BOTH that it throws CORRUPT_STATE and that the message contains the exact
 * substring named -- a bare "did it throw" check is exactly what let every one of these
 * branches survive mutation until now. */
function expectInvalid(name, defName, value, messageSubstring) {
  const { threw } = tryValidate(defName, value);
  check(name,
    Boolean(threw) && threw.code === "CORRUPT_STATE" && threw.message.includes(messageSubstring),
    `expected CORRUPT_STATE containing ${JSON.stringify(messageSubstring)}, got ${threw ? `${threw.code}: ${threw.message}` : "no error"}`);
}

const HEX32 = "a".repeat(32);
const HEX64A = "a".repeat(64);
const HEX64B = "b".repeat(64);

const validLock = { schema_version: "1.0", pid: 1234, owner_token: HEX32 };
const validEffect = { file: "window.json", before_sha256: HEX64A, after_sha256: HEX64B, content_base64: "eyJ9" };
const validIntent = { schema_version: "1.0", record_type: "MUTATION_INTENT", mutation_id: "m1", state_rev: 0, effects: [validEffect] };
const validDone = { schema_version: "1.0", record_type: "MUTATION_DONE", mutation_id: "m1", state_rev: 0 };
const validSlot = { slot_id: 1, run_id: "r1", status: "active", disposition: null };
const validWindowObj = {
  window_id: "w1", adoption_txid: "w1", candidate_fingerprint: "fp", tree_id: "t1", n: 1,
  baseline_metric: null, created_at: 0, max_window_wall_time_ms: 1, admitted: 0, active: 0, slots: [],
};
const validWindow = { schema_version: "1.0", state_rev: 0, state: "NO_WINDOW", flag: false, window: null };
const validRegistry = { schema_version: "1.0", state_rev: 0, record_type: "REGISTERED", run_id: "r1" };
const validAnchor = { schema_version: "1.0", state_rev: 0, record_type: "ANCHOR_SET", run_id: "r1", chain_head: "h1", expected_terminal_status: "completed_pass" };
const validAlpha = { schema_version: "1.0", state_rev: 0, record_type: "RESERVED", reservation_id: "res1" };
const validRejected = { schema_version: "1.0", state_rev: 0, record_type: "REJECTED", fingerprint: "fp1", value: {} };
const validRollback = { schema_version: "1.0", state_rev: 0, record_type: "ROLLBACK_RECORDED", fingerprint: "fp1" };

function sanityChecksAllValidFixturesActuallyValidate() {
  expectValid("fixture-lock-valid", "lock", validLock);
  expectValid("fixture-journalEffect-valid", "journalEffect", validEffect);
  expectValid("fixture-journalIntent-valid", "journalIntent", validIntent);
  expectValid("fixture-journalDone-valid", "journalDone", validDone);
  expectValid("fixture-slot-valid", "slot", validSlot);
  expectValid("fixture-window-valid-null-window", "window", validWindow);
  expectValid("fixture-window-valid-object-window", "window", { ...validWindow, state: "OBSERVING", window: validWindowObj });
  expectValid("fixture-registry-valid", "registry", validRegistry);
  expectValid("fixture-anchor-valid", "anchor", validAnchor);
  expectValid("fixture-alpha-valid", "alpha", validAlpha);
  expectValid("fixture-rejected-valid", "rejected", validRejected);
  expectValid("fixture-rollback-valid", "rollback", validRollback);
}

/* ---- type dispatch: "null" | "object" (window.window), each half of the union failing
 * distinctly, plus the `!Array.isArray(value)` guard that keeps an array out of "object" ---- */
function typeUnionNullObject() {
  expectInvalid("window-field-string-is-neither-null-nor-object", "window",
    { ...validWindow, window: "not-null-or-object" }, "$.window must be");
  expectInvalid("window-field-number-is-neither-null-nor-object", "window",
    { ...validWindow, window: 42 }, "$.window must be");
  expectInvalid("window-field-array-is-not-object-despite-typeof-object", "window",
    { ...validWindow, window: [] }, "$.window must be");
  expectValid("window-field-null-is-valid", "window", { ...validWindow, window: null });
  expectValid("window-field-plain-object-is-valid", "window", { ...validWindow, state: "OBSERVING", window: validWindowObj });
}

/* ---- type dispatch: "array" (window.window.slots, journalIntent.effects) ---- */
function typeArray() {
  expectInvalid("window-slots-non-array-rejected", "window",
    { ...validWindow, state: "OBSERVING", window: { ...validWindowObj, slots: "not-an-array" } }, "$.window.slots must be");
  expectInvalid("journalIntent-effects-non-array-rejected", "journalIntent",
    { ...validIntent, effects: "not-an-array" }, "$.effects must be");
  expectValid("journalIntent-effects-array-of-one-is-valid", "journalIntent", validIntent);
}

/* ---- type dispatch: "integer" (revision, pid, alpha_slot, slot_id, n) ---- */
function typeInteger() {
  expectInvalid("revision-fractional-rejected", "revision", 1.5, "must be integer");
  expectInvalid("revision-string-rejected", "revision", "0", "must be integer");
  expectValid("revision-zero-is-valid", "revision", 0);
  expectInvalid("lock-pid-fractional-rejected", "lock", { ...validLock, pid: 1.5 }, "$.pid must be");
}

/* ---- type dispatch: "number" (alpha.alpha: exclusiveMinimum 0, maximum 0.05) ---- */
function typeNumber() {
  expectInvalid("alpha-alpha-NaN-rejected", "alpha", { ...validAlpha, alpha: NaN }, "$.alpha must be");
  expectValid("alpha-alpha-well-formed-number-passes-type", "alpha", { ...validAlpha, alpha: 0.01 });
}

/* ---- type dispatch: the string/boolean fallback (`return typeof value === type`) ----
 *
 * window.flag is boolean with no enum ahead of it in schemaErrors' dispatch order, so this
 * is the one field in the schema where a type mismatch reaches the fallback branch directly
 * rather than being intercepted by an enum check first. */
function typeFallbackBoolean() {
  expectInvalid("window-flag-string-is-not-boolean", "window", { ...validWindow, flag: "true" }, "$.flag must be");
  expectInvalid("window-flag-number-is-not-boolean", "window", { ...validWindow, flag: 1 }, "$.flag must be");
  expectValid("window-flag-true-is-valid", "window", { ...validWindow, flag: true });
  expectValid("window-flag-false-is-valid", "window", { ...validWindow, flag: false });
}

/* ---- string constraints: minLength (nonEmpty) and pattern (owner_token, instance/claim
 * tokens use the same `[a-f0-9]{32}` shape elsewhere, but owner_token is state-store's own) ---- */
function stringConstraints() {
  expectInvalid("nonEmpty-empty-string-too-short", "nonEmpty", "", "too short");
  expectValid("nonEmpty-single-char-is-valid", "nonEmpty", "a");
  expectInvalid("lock-owner-token-wrong-length-rejected", "lock", { ...validLock, owner_token: "short" }, "$.owner_token has an invalid format");
  expectInvalid("lock-owner-token-non-hex-char-rejected", "lock", { ...validLock, owner_token: "g".repeat(32) }, "$.owner_token has an invalid format");
  expectValid("lock-owner-token-valid-hex32", "lock", validLock);
}

/* ---- number constraints: minimum, exclusiveMinimum, maximum, at and past each boundary ---- */
function numberConstraints() {
  expectInvalid("revision-negative-below-minimum", "revision", -1, "is below its minimum");
  expectValid("revision-zero-at-minimum-boundary", "revision", 0);

  expectInvalid("lock-pid-zero-below-minimum", "lock", { ...validLock, pid: 0 }, "$.pid is below its minimum");
  expectValid("lock-pid-one-at-minimum-boundary", "lock", { ...validLock, pid: 1 });

  expectInvalid("alpha-slot-zero-below-minimum", "alpha", { ...validAlpha, alpha_slot: 0 }, "$.alpha_slot is below its minimum");
  expectInvalid("alpha-slot-four-above-maximum", "alpha", { ...validAlpha, alpha_slot: 4 }, "$.alpha_slot is above its maximum");
  expectValid("alpha-slot-one-at-minimum-boundary", "alpha", { ...validAlpha, alpha_slot: 1 });
  expectValid("alpha-slot-three-at-maximum-boundary", "alpha", { ...validAlpha, alpha_slot: 3 });

  expectInvalid("alpha-alpha-zero-at-exclusive-minimum-rejected", "alpha", { ...validAlpha, alpha: 0 }, "$.alpha is below its exclusive minimum");
  expectInvalid("alpha-alpha-above-maximum-rejected", "alpha", { ...validAlpha, alpha: 0.06 }, "$.alpha is above its maximum");
  expectValid("alpha-alpha-at-maximum-boundary-valid", "alpha", { ...validAlpha, alpha: 0.05 });
  expectValid("alpha-alpha-small-positive-valid", "alpha", { ...validAlpha, alpha: 0.001 });
}

/* ---- array constraints: minItems, and items-array error bubbling through `${location}[${i}]` ---- */
function arrayConstraints() {
  expectInvalid("journalIntent-empty-effects-below-minItems", "journalIntent", { ...validIntent, effects: [] }, "$.effects has too few items");
  const brokenEffect = { file: "window.json", before_sha256: HEX64A, after_sha256: HEX64B }; // missing content_base64
  expectInvalid("journalIntent-items-error-bubbles-with-index", "journalIntent",
    { ...validIntent, effects: [validEffect, brokenEffect] }, "$.effects[1].content_base64 is required");

  const brokenSlot = { slot_id: 1, run_id: "r1", status: "active" }; // missing disposition
  expectInvalid("window-slots-items-error-bubbles-with-index", "window",
    { ...validWindow, state: "OBSERVING", window: { ...validWindowObj, slots: [brokenSlot] } },
    "$.window.slots[0].disposition is required");
}

/* ---- required / additionalProperties / nested-property propagation ---- */
function requiredAndAdditionalProperties() {
  const { pid, ...lockWithoutPid } = validLock;
  expectInvalid("lock-missing-pid-required", "lock", lockWithoutPid, "$.pid is required");

  const { flag, ...windowWithoutFlag } = validWindow;
  expectInvalid("window-missing-flag-required", "window", windowWithoutFlag, "$.flag is required");

  expectInvalid("lock-unexpected-key-rejected", "lock", { ...validLock, bogus_extra_key: 1 }, "$.bogus_extra_key is not allowed");

  expectInvalid("window-nested-n-type-error-propagates-with-path", "window",
    { ...validWindow, state: "OBSERVING", window: { ...validWindowObj, n: "not-an-integer" } }, "$.window.n must be");
}

/* ---- const mismatches ---- */
function constMismatches() {
  expectInvalid("journalDone-wrong-record-type-const", "journalDone", { ...validDone, record_type: "NOT_DONE" }, '$.record_type must equal "MUTATION_DONE"');
  expectInvalid("version-wrong-const-value", "version", "2.0", '$ must equal "1.0"');
  expectValid("version-correct-const-value", "version", "1.0");
}

/* ---- enum mismatches ---- */
function enumMismatches() {
  expectInvalid("window-state-not-in-enum", "window", { ...validWindow, state: "BOGUS_STATE" }, "$.state has an unsupported value");
  expectInvalid("registry-record-type-not-in-enum", "registry", { ...validRegistry, record_type: "BOGUS" }, "$.record_type has an unsupported value");
  expectInvalid("slot-status-not-in-enum", "slot", { ...validSlot, status: "bogus" }, "$.status has an unsupported value");
  expectInvalid("slot-disposition-not-in-enum-non-string-value", "slot", { ...validSlot, disposition: 42 }, "$.disposition has an unsupported value");
}

/* ---- validateStateRecord (the oneOf top-level dispatch, reachable only through a real
 * store read/write since it is not itself exported) -- pins the exact "matched N schemas"
 * message that a hostile-key test only ever proved threw SOME CORRUPT_STATE, never this
 * one. Uses a throwaway StateStore purely as a vehicle to reach parseStateJson. ---- */
function oneOfDispatchMessageExact() {
  const os = require("os");
  const fs = require("fs");
  const { createStore } = stateStore;
  /* An explicit manual clock, not the default wall clock: this case asserts nothing about
   * lease liveness, so it must not become a new undeclared real-clock construction site
   * for tests/harness-honesty/lease-determinism's dynamic per-suite sweep (it discovers
   * every tests/state-store/*\/run-tests.js and audits every StateStore construction). */
  const { createManualClock } = require("../../_harness/clock.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gs-schema-oneof-"));
  try {
    const prevMode = process.env.GRAPHSMITH_TEST_MODE;
    process.env.GRAPHSMITH_TEST_MODE = "1";
    const store = createStore(root, { leaseMs: 1000, heartbeatMs: 100, clock: createManualClock() });
    store.window.admitPending({ txid: "tx", fingerprint: "fp", tree_id: "t", n: 1 });
    const windowPath = store._path("window.json");
    const poisoned = JSON.parse(fs.readFileSync(windowPath, "utf8"));
    poisoned.unexpected_hostile_key = "boom";
    fs.writeFileSync(windowPath, JSON.stringify(poisoned));
    let threw = null;
    try { store.window.get(); } catch (error) { threw = error; }
    check("oneOf-hostile-key-matches-zero-schemas-exact-message",
      Boolean(threw) && threw.message.includes("matched 0"),
      `expected the error to report "matched 0", got ${threw && threw.message}`);
    check("oneOf-hostile-key-wrapped-with-context",
      Boolean(threw) && threw.message.includes("Invalid state record in window.json"),
      `expected the wrapping validateStateRecord message naming window.json, got ${threw && threw.message}`);
    if (prevMode === undefined) delete process.env.GRAPHSMITH_TEST_MODE; else process.env.GRAPHSMITH_TEST_MODE = prevMode;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function unknownDefNameStillHandled() {
  // Already covered by tests/state-store/atomic-primitives, repeated here only as a sanity
  // anchor so this file's own suite is self-contained for defName-related regressions.
  const { threw } = tryValidate("not-a-real-def-xyz", {});
  check("schema-validator-suite-self-check-unknown-defname", Boolean(threw) && threw.code === "INVALID_ARGUMENT",
    "sanity check regressed: validateNamedRecord's unknown-defName guard");
}

function main() {
  sanityChecksAllValidFixturesActuallyValidate();
  typeUnionNullObject();
  typeArray();
  typeInteger();
  typeNumber();
  typeFallbackBoolean();
  stringConstraints();
  numberConstraints();
  arrayConstraints();
  requiredAndAdditionalProperties();
  constMismatches();
  enumMismatches();
  oneOfDispatchMessageExact();
  unknownDefNameStillHandled();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
