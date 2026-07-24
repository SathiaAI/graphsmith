"use strict";

const assert = require("assert");
const retention = require("../../../../checks/register-retention.js");

let pass = 0;
let fail = 0;
const tests = [];

function test(name, fn) {
  tests.push({ name, fn });
}

function run() {
  for (const t of tests) {
    try {
      t.fn();
      console.log("PASS " + t.name);
      pass++;
    } catch (e) {
      console.log("FAIL " + t.name + " " + (e.message || String(e)));
      fail++;
    }
  }
  console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + tests.length);
  process.exitCode = fail === 0 ? 0 : 1;
}

// Helper to create valid entries
function mkEntry(seq, prev, pkt, anchored = "f".repeat(64)) {
  return {
    schema_version: "1.0",
    seq,
    prev_packet_sha256: prev,
    packet_sha256: pkt,
    anchored_head: anchored,
    recorded_at: "2023-01-01T00:00:00Z"
  };
}

// Helper to create 64-char hex strings
function h(n) {
  return String(n).padStart(2, "0").repeat(32);
}

// 1. TAMPER-EVIDENCE / FAIL-OPEN tests
test("tamper-middle-packet-hash", () => {
  const chain = [
    mkEntry(1, null, h(1)),
    mkEntry(2, h(1), h(2)),
    mkEntry(3, h(2), h(3))
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "verified");

  // Mutate middle entry's packet hash
  chain[1].packet_sha256 = h(99);
  const tampered = retention.run({ chain });
  assert.strictEqual(tampered.status, "failed", "Tampered middle packet hash should fail");
});

test("reorder-entries", () => {
  const chain = [
    mkEntry(1, null, h(1)),
    mkEntry(3, h(2), h(3)),
    mkEntry(2, h(1), h(2))
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Reordered entries should fail");
});

test("duplicate-seq", () => {
  const chain = [
    mkEntry(1, null, h(1)),
    mkEntry(2, h(1), h(2)),
    mkEntry(2, h(2), h(3))
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Duplicate seq should fail");
});

test("seq-gap", () => {
  const chain = [
    mkEntry(1, null, h(1)),
    mkEntry(3, h(1), h(3))
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Sequence gap should fail");
});

test("forge-prev-packet-hash", () => {
  const chain = [
    mkEntry(1, null, h(1)),
    mkEntry(2, h(99), h(2)) // Forged prev hash
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Forged prev_packet_sha256 should fail");
});

test("remove-entry", () => {
  const chain = [
    mkEntry(1, null, h(1)),
    mkEntry(3, h(2), h(3)) // Missing entry 2
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Removed entry should fail");
});

// 2. ANCHORED-HEAD BINDING tests
test("anchored-head-mismatch", () => {
  const chain = [
    mkEntry(1, null, h(1), "a".repeat(64)),
    mkEntry(2, h(1), h(2), "a".repeat(64))
  ];
  const result = retention.run({
    chain,
    expected_anchored_head: "b".repeat(64)
  });
  assert.strictEqual(result.status, "failed", "Anchored head mismatch should fail");
});

test("short-expected-head", () => {
  const chain = [mkEntry(1, null, h(1))];
  const result = retention.run({
    chain,
    expected_anchored_head: "a".repeat(63)
  });
  assert.strictEqual(result.status, "failed", "Short expected head should fail");
});

test("non-hex-expected-head", () => {
  const chain = [mkEntry(1, null, h(1))];
  const result = retention.run({
    chain,
    expected_anchored_head: "g".repeat(64)
  });
  assert.strictEqual(result.status, "failed", "Non-hex expected head should fail");
});

test("empty-expected-head", () => {
  const chain = [mkEntry(1, null, h(1))];
  const result = retention.run({
    chain,
    expected_anchored_head: ""
  });
  assert.strictEqual(result.status, "failed", "Empty expected head should fail");
});

// 3. ROOT tests
test("non-null-root-prev-hash", () => {
  const chain = [
    mkEntry(1, h(1), h(1)) // Root with non-null prev hash
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Non-null root prev hash should fail");
});

// 4. SHAPE tests
test("invalid-entry-schema-version", () => {
  const chain = [
    {
      schema_version: "2.0",
      seq: 1,
      prev_packet_sha256: null,
      packet_sha256: h(1),
      anchored_head: h(1)
    }
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Invalid schema version should fail");
});

test("missing-required-field", () => {
  const chain = [
    {
      schema_version: "1.0",
      seq: 1,
      prev_packet_sha256: null,
      // packet_sha256 missing
      anchored_head: h(1)
    }
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Missing required field should fail");
});

test("extra-field", () => {
  const chain = [
    {
      schema_version: "1.0",
      seq: 1,
      prev_packet_sha256: null,
      packet_sha256: h(1),
      anchored_head: h(1),
      extra_field: "should fail"
    }
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Extra field should fail");
});

test("non-hex-packet-hash", () => {
  const chain = [
    mkEntry(1, null, "g".repeat(64)) // Non-hex packet hash
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Non-hex packet hash should fail");
});

test("non-hex-anchored-head", () => {
  const chain = [
    mkEntry(1, null, h(1), "g".repeat(64)) // Non-hex anchored head
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Non-hex anchored head should fail");
});

test("non-string-packet-hash", () => {
  const chain = [
    {
      schema_version: "1.0",
      seq: 1,
      prev_packet_sha256: null,
      packet_sha256: 123, // Not a string
      anchored_head: h(1)
    }
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Non-string packet hash should fail");
});

test("non-number-seq", () => {
  const chain = [
    {
      schema_version: "1.0",
      seq: "1", // Not a number
      prev_packet_sha256: null,
      packet_sha256: h(1),
      anchored_head: h(1)
    }
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Non-number seq should fail");
});

// 5. MALFORMED INPUT tests
test("circular-reference", () => {
  const entry = mkEntry(1, null, h(1));
  entry.self = entry;
  const chain = [entry];
  const result = retention.run({ chain });
  assert.notStrictEqual(result.status, "verified", "Circular reference should not verify");
  assert.notStrictEqual(result.status, undefined, "Should return a status, not throw");
});

test("proxy-object", () => {
  const entry = mkEntry(1, null, h(1));
  const proxy = new Proxy(entry, {
    get(target, prop) {
      if (prop === "packet_sha256") return "malicious";
      return target[prop];
    }
  });
  const chain = [proxy];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Proxy object should fail");
});

test("bigint-fields", () => {
  const chain = [
    {
      schema_version: "1.0",
      seq: 1n, // BigInt
      prev_packet_sha256: null,
      packet_sha256: h(1),
      anchored_head: h(1)
    }
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "BigInt fields should fail");
});

test("symbol-fields", () => {
  const chain = [
    {
      schema_version: "1.0",
      seq: 1,
      prev_packet_sha256: null,
      packet_sha256: Symbol("test"), // Symbol
      anchored_head: h(1)
    }
  ];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Symbol fields should fail");
});

test("getter-throws", () => {
  const entry = {
    get schema_version() { throw new Error("getter attack"); },
    seq: 1,
    prev_packet_sha256: null,
    packet_sha256: h(1),
    anchored_head: h(1)
  };
  const chain = [entry];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "failed", "Throwing getter should fail");
});

test("null-context", () => {
  const result = retention.run(null);
  assert.strictEqual(result.status, "failed", "Null context should fail");
});

test("undefined-context", () => {
  const result = retention.run(undefined);
  assert.strictEqual(result.status, "failed", "Undefined context should fail");
});

test("non-object-context", () => {
  const result = retention.run("not an object");
  assert.strictEqual(result.status, "failed", "Non-object context should fail");
});

test("non-array-chain", () => {
  const result = retention.run({ chain: "not an array" });
  assert.strictEqual(result.status, "failed", "Non-array chain should fail");
});

// 6. EDGE CASES
test("empty-chain", () => {
  const result = retention.run({ chain: [] });
  assert.strictEqual(result.status, "not-applicable", "Empty chain should be not-applicable");
});

test("single-valid-entry", () => {
  const chain = [mkEntry(1, null, h(1))];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "verified", "Single valid entry should verify");
});

test("single-valid-entry-with-expected-head", () => {
  const head = h(1);
  const chain = [mkEntry(1, null, h(1), head)];
  const result = retention.run({
    chain,
    expected_anchored_head: head
  });
  assert.strictEqual(result.status, "verified", "Single valid entry with matching head should verify");
});

test("large-seq-number", () => {
  const chain = [mkEntry(Number.MAX_SAFE_INTEGER, null, h(1))];
  const result = retention.run({ chain });
  assert.strictEqual(result.status, "verified", "Large seq number should verify");
});

run();
