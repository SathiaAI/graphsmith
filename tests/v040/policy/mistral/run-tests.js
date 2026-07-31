"use strict";

const check = require("../../../../checks/v040-policy.js");
let pass = 0, fail = 0;

function test(name, fn) {
  const result = fn();
  if (result === true) {
    console.log("PASS " + name);
    pass++;
  } else {
    // Every fn() here returns a boolean, so the old ternary printed an empty detail on
    // EVERY failure -- three FAIL lines with nothing after them, undiagnosable without
    // editing the file. Say what actually came back.
    console.log("FAIL " + name + " (returned " + JSON.stringify(result) + ")");
    fail++;
  }
}

test("unenforced-bypass-boolean-false", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1"] }
    }
  };
  const controls = { control1: { enforced: false } };
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("unenforced");
});

test("unenforced-bypass-missing-enforced", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1"] }
    }
  };
  const controls = { control1: {} };
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("unenforced");
});

test("unenforced-bypass-string-true", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1"] }
    }
  };
  const controls = { control1: { enforced: "true" } };
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("unenforced");
});

test("unenforced-bypass-number-1", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1"] }
    }
  };
  const controls = { control1: { enforced: 1 } };
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("unenforced");
});

test("unknown-profile-empty-string", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [] }
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "", controls });
  return result.status === "failed" && result.reason.includes("non-empty string");
});

test("unknown-profile-prototype-key", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [] }
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "__proto__", controls });
  return result.status === "failed" && result.reason.includes("unknown profile");
});

test("unknown-profile-constructor", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [] }
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "constructor", controls });
  return result.status === "failed" && result.reason.includes("unknown profile");
});

test("unknown-profile-toString", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [] }
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "toString", controls });
  return result.status === "failed" && result.reason.includes("unknown profile");
});

test("forbidden-enforced", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [], forbids: ["control1"] }
    }
  };
  const controls = { control1: { enforced: true } };
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("forbidden control");
});

test("round-trip-serialize-parse", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1"], forbids: ["control2"] }
    }
  };
  const controls = { control1: { enforced: true } };
  const original = check.run({ policy, profile: "test", controls });
  const serialized = check.serializePolicy(policy);
  const parsed = check.parsePolicy(serialized);
  const roundTrip = check.run({ policy: parsed, profile: "test", controls });
  return original.status === roundTrip.status && original.status === "verified";
});

test("round-trip-failure-case", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1"] }
    }
  };
  const controls = { control1: { enforced: false } };
  const original = check.run({ policy, profile: "test", controls });
  const serialized = check.serializePolicy(policy);
  const parsed = check.parsePolicy(serialized);
  const roundTrip = check.run({ policy: parsed, profile: "test", controls });
  return original.status === roundTrip.status && original.status === "failed";
});

test("malformed-schema-version", () => {
  const policy = {
    schema_version: "2.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [] }
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("schema_version");
});

test("malformed-policy-version", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "v1.0.0",
    profiles: {
      test: { requires: [] }
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("semver");
});

test("malformed-profiles-not-object", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: []
  };
  const controls = {};
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("profiles must be an object");
});

test("malformed-requires-not-array", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: "control1" }
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("requires[] must be an array");
});

test("malformed-control-id-number", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [123] }
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("malformed control id");
});

test("malformed-control-id-object", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [{}] }
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("malformed control id");
});

test("malformed-profile-object", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: []
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("malformed");
});

test("stray-metadata-fields", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1"] }
    },
    extraField: "should not affect decision"
  };
  const controls = { control1: { enforced: true } };
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "verified";
});

test("null-context", () => {
  const result = check.run(null);
  return result.status === "failed" && result.reason.includes("no context");
});

test("null-controls", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [] }
    }
  };
  const result = check.run({ policy, profile: "test", controls: null });
  return result.status === "verified";
});

test("array-controls", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [] }
    }
  };
  const result = check.run({ policy, profile: "test", controls: [] });
  return result.status === "verified";
});

test("bigint-control-id", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [9007199254740991n] }
    }
  };
  const controls = {};
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("malformed control id");
});

test("hostile-getter-control", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1"] }
    }
  };
  const controls = {};
  Object.defineProperty(controls, "control1", {
    get: () => { throw new Error("hostile getter"); },
    configurable: true
  });
  const result = check.run({ policy, profile: "test", controls });
  // The check catches the throwing getter and fails closed with "exception — failing
  // closed: hostile getter". "unenforced" is the reason for a control that is simply
  // NOT enforced; conflating the two hides which of two very different things happened.
  return result.status === "failed" && result.reason.includes("exception");
});

test("proto-pollution-policy", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [] }
    }
  };
  policy.__proto__.malicious = "polluted";
  const controls = {};
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "verified";
});

test("proto-pollution-controls", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1"] }
    }
  };
  const controls = { control1: { enforced: true } };
  controls.__proto__.malicious = { enforced: true };
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "verified";
});

test("proxy-policy", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: [] }
    }
  };
  const proxy = new Proxy(policy, {
    get: (target, prop) => {
      if (prop === "profiles") throw new Error("proxy attack");
      return target[prop];
    }
  });
  const controls = {};
  const result = check.run({ policy: proxy, profile: "test", controls });
  return result.status === "failed" && result.reason.includes("exception");
});

test("proxy-controls", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1"] }
    }
  };
  const controls = { control1: { enforced: true } };
  const proxy = new Proxy(controls, {
    get: (target, prop) => {
      if (prop === "control1") throw new Error("proxy attack");
      return target[prop];
    }
  });
  const result = check.run({ policy, profile: "test", controls: proxy });
  // Same as hostile-getter-control: this fails closed via the exception path.
  return result.status === "failed" && result.reason.includes("exception");
});

test("valid-satisfied-profile", () => {
  const policy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
      test: { requires: ["control1", "control2"], forbids: ["control3"] }
    }
  };
  const controls = {
    control1: { enforced: true },
    control2: { enforced: true }
  };
  const result = check.run({ policy, profile: "test", controls });
  return result.status === "verified";
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
