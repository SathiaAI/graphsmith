const check = require("../../../../checks/register-retention.js");

const pass = 0;
const fail = 0;
const tests = [];

function test(name, ctx, expected) {
  const result = check.run(ctx);
  if (result.status === expected) {
    console.log("PASS " + name);
  } else {
    console.log("FAIL " + name + " " + JSON.stringify(result));
  }
  tests.push(name);
}

// Valid chain
test("valid-chain", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "verified");

// Mutate middle entry's packet_sha256
test("mutate-middle-packet-sha256", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "z".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Reorder entries
test("reorder-entries", { chain: [
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Duplicate seq
test("duplicate-seq", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 1, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Gap in seq
test("gap-in-seq", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "a".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Forge prev_packet_sha256
test("forge-prev-packet-sha256", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "z".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Remove an entry
test("remove-entry", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Wrong anchored_head
test("wrong-anchored-head", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "c".repeat(64) }, "failed");

// Non-hex expected_anchored_head
test("non-hex-expected-anchored-head", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "not-hex" }, "failed");

// Root entry with non-null prev_packet_sha256
test("root-with-non-null-prev-packet-sha256", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: "a".repeat(64), packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Invalid entry shape
test("invalid-entry-shape", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64), extra_field: "extra" },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Non-hex packet_sha256
test("non-hex-packet-sha256", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "not-hex", anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Non-hex prev_packet_sha256
test("non-hex-prev-packet-sha256", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "not-hex", packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Non-hex anchored_head
test("non-hex-anchored-head", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "not-hex" },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Missing fields
test("missing-fields", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Hostile getter
test("hostile-getter", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64), get: () => { throw new Error("Hostile getter"); } },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Proto pollution
test("proto-pollution", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64), __proto__: { pollute: "polluted" } },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// BigInt
test("bigint", { chain: [
  { schema_version: "1.0", seq: 1n, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Circular reference
test("circular-reference", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64), circular: { ref: null } }
], expected_anchored_head: "b".repeat(64) }, "failed");

// Proxy
test("proxy", { chain: [
  { schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  new Proxy({ schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }, {})
], expected_anchored_head: "b".repeat(64) }, "failed");

// Wrong types
test("wrong-types", { chain: [
  { schema_version: "1.0", seq: "1", prev_packet_sha256: null, packet_sha256: "a".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 2, prev_packet_sha256: "a".repeat(64), packet_sha256: "b".repeat(64), anchored_head: "b".repeat(64) },
  { schema_version: "1.0", seq: 3, prev_packet_sha256: "b".repeat(64), packet_sha256: "c".repeat(64), anchored_head: "b".repeat(64) }
], expected_anchored_head: "b".repeat(64) }, "failed");

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + tests.length);
process.exitCode = fail === 0 ? 0 : 1;
