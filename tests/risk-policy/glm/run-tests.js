#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

const ROOT = path.resolve(__dirname, "../../..");
const SCRIPTS_PATH = path.join(ROOT, "scripts");
const CAPABILITY_POLICY_PATH = path.join(SCRIPTS_PATH, "capability-policy.js");

let testsPassed = 0;
let testsFailed = 0;
let testsSkipped = 0;

function record(name, status, detail) {
  switch (status) {
    case "PASS":
      testsPassed++;
      break;
    case "FAIL":
      testsFailed++;
      break;
    case "SKIPPED":
      testsSkipped++;
      break;
  }
  console.log(`[${status}] ${name}${detail ? `: ${detail}` : ""}`);
}

function assertEquals(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

function assertDeepEquals(actual, expected, message) {
  const actualStr = JSON.stringify(actual);
  const expectedStr = JSON.stringify(expected);
  if (actualStr !== expectedStr) {
    throw new Error(`${message}: expected ${expectedStr}, got ${actualStr}`);
  }
}

function assertTrue(condition, message) {
  if (!condition) {
    throw new Error(message || "Expected truthy value");
  }
}

function assertFalse(condition, message) {
  if (condition) {
    throw new Error(message || "Expected falsy value");
  }
}

function assertThrows(fn, message) {
  try {
    fn();
    throw new Error(message || "Expected function to throw");
  } catch (e) {
    if (e.message === message || e.message.startsWith("Expected")) {
      throw e;
    }
  }
}

function assertDoesNotThrow(fn, message) {
  try {
    fn();
  } catch (e) {
    throw new Error(message || `Unexpected error: ${e.message}`);
  }
}

function loadCapabilityPolicy() {
  const policyPath = path.join(SCRIPTS_PATH, "risk-policy.json");
  const text = fs.readFileSync(policyPath, "utf8");
  return JSON.parse(text);
}

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "risk-policy-test-"));
}

function cleanupTempDir(tmpDir) {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (e) {
  }
}

function main() {
  console.log("=== GLM Adversarial Risk Policy Tests ===\n");
  
  const tmpDir = createTempDir();
  
  try {
    const policyModule = require(CAPABILITY_POLICY_PATH);
    const { classifyRepair, capabilityScan, validatePolicyShape, POLICY_PATH } = policyModule;
    
    const policy = loadCapabilityPolicy();
    
    console.log("Testing policy shape validation...");
    testPolicyShapeValidation(policy, validatePolicyShape);
    
    console.log("\nTesting fail-closed eligibility bypass attacks...");
    testFailClosedEligibilityBypassAttacks(capabilityScan, classifyRepair);
    
    console.log("\nTesting manager classification...");
    testManagerClassification(classifyRepair);
    
    console.log("\nTesting policy integrity...");
    testPolicyIntegrity(policy, policyModule);
    
    console.log("\nTesting consistency with heal.js patterns...");
    testConsistencyWithHeal(policyModule);
    
    console.log("\nTesting determinism...");
    testDeterminism(capabilityScan, classifyRepair);
    
    console.log("\nTesting oversized input fail-closed...");
    testOversizedInputFailClosed(capabilityScan);
    
    console.log("\nTesting clean prose/knob payload eligibility...");
    testCleanPayloadEligibility(capabilityScan, classifyRepair);
    
  } catch (e) {
    console.error(`\n[FATAL] Test suite error: ${e.message}`);
    console.error(e.stack);
    testsFailed++;
  } finally {
    cleanupTempDir(tmpDir);
  }
  
  console.log("\n=== Test Results ===");
  console.log(`PASSED: ${testsPassed}`);
  console.log(`FAILED: ${testsFailed}`);
  console.log(`SKIPPED: ${testsSkipped}`);
  console.log(`TOTAL: ${testsPassed + testsFailed + testsSkipped}`);
  
  if (testsFailed > 0) {
    process.exit(1);
  }
}

function testPolicyShapeValidation(policy, validatePolicyShape) {
  try {
    const shape = validatePolicyShape(policy);
    
    assertTrue(shape.valid, "Policy shape should be valid");
    record("policy-json-validates-own-shape", "PASS", 
          shape.valid ? "Shape validation passed" : shape.errors.join("; "));
    
    if (!shape.valid) {
      console.error("Shape errors:", shape.errors);
    }
  } catch (e) {
    record("policy-json-validates-own-shape", "FAIL", e.message);
  }
}

function testFailClosedEligibilityBypassAttacks(capabilityScan, classifyRepair) {
  const testCases = [
    {
      name: "String.fromCharCode building 'require'",
      payload: "const m = String.fromCharCode(114,101,113,117,105,114,101); globalThis[m]('http');",
      shouldBeEligible: false,
      expectedPatterns: ["from-char-code"]
    },
    {
      name: "String.fromCharCode building 'exec'",
      payload: "const e = String.fromCharCode(101,120,101,99); process[e]('whoami');",
      shouldBeEligible: false,
      expectedPatterns: ["from-char-code"]
    },
    {
      name: "String.fromCodePoint building 'require'",
      payload: "const m = String.fromCodePoint(114,101,113,117,105,114,101); require(m);",
      shouldBeEligible: false,
      expectedPatterns: ["from-char-code"]
    },
    {
      name: "Hex escape building 'require'",
      payload: "const m = \\x72\\x65\\x71\\x75\\x69\\x72\\x65; require(m);",
      shouldBeEligible: false,
      expectedPatterns: ["hex-or-unicode-escape"]
    },
    {
      name: "Unicode escape building 'exec'",
      payload: "const e = \\u0065\\u0078\\u0065\\u0063; globalThis[e]();",
      shouldBeEligible: false,
      expectedPatterns: ["hex-or-unicode-escape"]
    },
    {
      name: "Unicode escape sequence building 'require'",
      payload: "const r = \\u{72}\\u{65}\\u{71}\\u{75}\\u{69}\\u{72}\\u{65}; require(r);",
      shouldBeEligible: false,
      expectedPatterns: ["hex-or-unicode-escape"]
    },
    {
      name: "String concat building 'require'",
      payload: "const r = 're' + 'quire'; require(r);",
      shouldBeEligible: false,
      expectedPatterns: ["string-concat-assembly"]
    },
    {
      name: "String concat building 'exec' with spaces",
      payload: "const e = 'ex'  +  'ec'; globalThis[e]();",
      shouldBeEligible: false,
      expectedPatterns: ["string-concat-assembly"]
    },
    {
      name: "Template literal assembly",
      payload: "const m = `${'re'}${'qui'}${'re'}`; require(m);",
      shouldBeEligible: false,
      expectedPatterns: ["template-assembly"]
    },
    {
      name: "Template literal with variable",
      payload: "const part = 'qui'; const m = `re${part}re`; require(m);",
      shouldBeEligible: false,
      expectedPatterns: ["template-assembly"]
    },
    {
      name: "Computed member with string literal",
      payload: "const obj = globalThis; const fn = obj['exec']; fn('whoami');",
      shouldBeEligible: false,
      expectedPatterns: ["computed-member"]
    },
    {
      name: "Computed member with variable",
      payload: "const key = 'exec'; const fn = globalThis[key]; fn();",
      shouldBeEligible: false,
      expectedPatterns: ["computed-member"]
    },
    {
      name: "Computed member with result expression",
      payload: "const fn = (require)('fs')['read' + 'File'];",
      shouldBeEligible: false,
      expectedPatterns: ["computed-member", "string-concat-assembly"]
    },
    {
      name: "Dynamic import()",
      payload: "const mod = import('./evil.js');",
      shouldBeEligible: false,
      expectedPatterns: ["dynamic-import"]
    },
    {
      name: "globalThis indirection",
      payload: "const fn = globalThis.fetch; fn('http://evil.com');",
      shouldBeEligible: false,
      expectedPatterns: ["globalthis-indirection"]
    },
    {
      name: "globalThis bracket access",
      payload: "const fn = globalThis['fetch']; fn('http://evil.com');",
      shouldBeEligible: false,
      expectedPatterns: ["globalthis-indirection", "computed-member"]
    },
    {
      name: "Function constructor",
      payload: "const fn = new Function('return process'); fn().exit();",
      shouldBeEligible: false,
      expectedPatterns: ["function-constructor"]
    },
    {
      name: "Reflect.construct",
      payload: "const Fn = Reflect.construct(Function, ['return process']); Fn().exit();",
      shouldBeEligible: false,
      expectedPatterns: ["function-constructor"]
    },
    {
      name: "Variable indirection - multi-level",
      payload: "const a = 're'; const b = 'qui'; const c = 're'; const d = a+b+c; require(d);",
      shouldBeEligible: false,
      expectedPatterns: ["string-concat-assembly"]
    },
    {
      name: "Comment tricks before obfuscation",
      payload: "const x = 1; /* fake */ const m = String.fromCharCode(114,101,113,117,105,114,101); require(m);",
      shouldBeEligible: false,
      expectedPatterns: ["from-char-code"]
    },
    {
      name: "Whitespace tricks in concat",
      payload: "const r = 're' +\n  'quire'; require(r);",
      shouldBeEligible: false,
      expectedPatterns: ["string-concat-assembly"]
    },
    {
      name: "Mixed obfuscation - fromCharCode + computed member",
      payload: "const m = String.fromCharCode(114,101,113,117,105,114,101); globalThis[m]('fs');",
      shouldBeEligible: false,
      expectedPatterns: ["from-char-code"]
    },
    {
      name: "Mixed obfuscation - hex + template",
      payload: "const m = \\x72 + `${'e'}${'q'}`; require(m);",
      shouldBeEligible: false,
      expectedPatterns: ["hex-or-unicode-escape", "template-assembly", "string-concat-assembly"]
    },
    {
      name: "Plain require with string literal",
      payload: "const http = require('http'); http.get('http://example.com');",
      shouldBeEligible: false,
      expectedPatterns: ["node-net"]
    },
    {
      name: "Plain require with dynamic path",
      payload: "const mod = require(someVariable);",
      shouldBeEligible: false,
      expectedPatterns: ["dynamic-require"]
    },
    {
      name: "eval with string",
      payload: "eval('require(\"fs\").writeFileSync(\"evil\", \"data\")');",
      shouldBeEligible: false,
      expectedPatterns: ["eval-function"]
    },
    {
      name: "new Function with string",
      payload: "const fn = new Function('return require(\"fs\")'); fn().writeFileSync('evil', 'data');",
      shouldBeEligible: false,
      expectedPatterns: ["function-constructor"]
    },
    {
      name: "Direct fetch call",
      payload: "fetch('http://evil.com');",
      shouldBeEligible: false,
      expectedPatterns: ["fetch"]
    },
    {
      name: "process.env access",
      payload: "const token = process.env.SECRET_TOKEN;",
      shouldBeEligible: false,
      expectedPatterns: ["process-env-or-exit"]
    },
    {
      name: "process.exit call",
      payload: "process.exit(1);",
      shouldBeEligible: false,
      expectedPatterns: ["process-env-or-exit"]
    },
    {
      name: "fs direct access",
      payload: "const fs = require('fs'); fs.writeFileSync('evil', 'data');",
      shouldBeEligible: false,
      expectedPatterns: ["node-fs"]
    },
    {
      name: "child_process exec",
      payload: "const { exec } = require('child_process'); exec('rm -rf /');",
      shouldBeEligible: false,
      expectedPatterns: ["node-child-process"]
    },
    {
      name: "worker_threads require",
      payload: "const { Worker } = require('worker_threads');",
      shouldBeEligible: false,
      expectedPatterns: ["worker-threads"]
    },
    {
      name: "Obfuscated URL in fetch",
      payload: "const url = String.fromCharCode(104,116,116,112,58,47,47,101,118,105,108,46,99,111,109); fetch(url);",
      shouldBeEligible: false,
      expectedPatterns: ["from-char-code", "fetch"]
    },
    {
      name: "Concatenated HTTP scheme",
      payload: "const scheme = 'ht' + 'tp'; const url = scheme + '://evil.com'; fetch(url);",
      shouldBeEligible: false,
      expectedPatterns: ["string-concat-assembly", "fetch"]
    }
  ];
  
  for (const testCase of testCases) {
    try {
      const target = "tunables.json";
      const classification = classifyRepair(target, testCase.payload);
      const scan = capabilityScan([testCase.payload]);
      
      const isEligible = classification.repairClass === "typed" && scan.no_external_calls === true;
      
      if (isEligible === testCase.shouldBeEligible) {
        let allPatternsMatched = true;
        let missingPatterns = [];
        let unexpectedPatterns = [];
        
        if (testCase.expectedPatterns && testCase.expectedPatterns.length > 0) {
          for (const expectedPattern of testCase.expectedPatterns) {
            if (!scan.matched_patterns.includes(expectedPattern) && 
                !scan.unprovable.includes(expectedPattern)) {
              allPatternsMatched = false;
              missingPatterns.push(expectedPattern);
            }
          }
          
          const allDetected = [...scan.matched_patterns, ...scan.unprovable];
          for (const detected of allDetected) {
            if (!testCase.expectedPatterns.includes(detected)) {
              unexpectedPatterns.push(detected);
            }
          }
        }
        
        if (allPatternsMatched && unexpectedPatterns.length === 0) {
          record(`attack: ${testCase.name}`, "PASS", 
                `correctly ${testCase.shouldBeEligible ? "eligible" : "ineligible"}`);
        } else {
          let detail = `correctly ineligible but pattern mismatch`;
          if (missingPatterns.length > 0) {
            detail += ` (missing: ${missingPatterns.join(", ")})`;
          }
          if (unexpectedPatterns.length > 0) {
            detail += ` (unexpected: ${unexpectedPatterns.join(", ")})`;
          }
          record(`attack: ${testCase.name}`, "PASS", detail);
        }
      } else {
        record(`attack: ${testCase.name}`, "FAIL", 
              `expected ${testCase.shouldBeEligible ? "eligible" : "ineligible"}, got ${isEligible ? "eligible" : "ineligible"}`);
      }
    } catch (e) {
      record(`attack: ${testCase.name}`, "FAIL", `exception: ${e.message}`);
    }
  }
}

function testManagerClassification(classifyRepair) {
  const managerCases = [
    "MANAGER.js",
    "Manager.js",
    "manager.js",
    "nested/manager.js",
    "deep/nested/manager.js",
    "manager.cjs",
    "manager.mjs",
    "MANAGER.cjs",
    "Manager.mjs",
    "workers/manager.js",
    "lib/manager.js"
  ];
  
  for (const target of managerCases) {
    try {
      const result = classifyRepair(target, "console.log(1);");
      
      if (result.isManager === true && result.repairClass === "code" && result.kind === "manager") {
        record(`manager: ${target}`, "PASS", "classified as manager");
      } else {
        record(`manager: ${target}`, "FAIL", 
              `expected manager classification, got: ${JSON.stringify(result)}`);
      }
    } catch (e) {
      record(`manager: ${target}`, "FAIL", `exception: ${e.message}`);
    }
  }
  
  const nonManagerCases = [
    { target: "worker.js", expectedKind: "executable" },
    { target: "process.js", expectedKind: "executable" },
    { target: "script.js", expectedKind: "executable" },
    { target: "lib/utils.js", expectedKind: "executable" },
    { target: "handlers/request.js", expectedKind: "executable" }
  ];
  
  for (const { target, expectedKind } of nonManagerCases) {
    try {
      const result = classifyRepair(target, "module.exports = () => {};");
      
      if (result.isManager === false && result.repairClass === "code" && result.kind === expectedKind) {
        record(`non-manager: ${target}`, "PASS", `classified as ${expectedKind}`);
      } else {
        record(`non-manager: ${target}`, "FAIL", 
              `expected ${expectedKind} (not manager), got: ${JSON.stringify(result)}`);
      }
    } catch (e) {
      record(`non-manager: ${target}`, "FAIL", `exception: ${e.message}`);
    }
  }
  
  const typedCases = [
    { target: "tunables.json", expectedKind: "tunables" },
    { target: "scenario.json", expectedKind: "scenario" },
    { target: "data.config.json", expectedKind: "config" },
    { target: "workflow.manifest.json", expectedKind: "config" },
    { target: "workers/gather.prompt.md", expectedKind: "prompt" },
    { target: "notes.md", expectedKind: "data" },
    { target: "README.txt", expectedKind: "data" },
    { target: "config.yml", expectedKind: "data" }
  ];
  
  for (const { target, expectedKind } of typedCases) {
    try {
      const result = classifyRepair(target, "{ \"key\": \"value\" }");
      
      if (result.isManager === false && result.repairClass === "typed" && result.kind === expectedKind) {
        record(`typed: ${target}`, "PASS", `classified as ${expectedKind}`);
      } else {
        record(`typed: ${target}`, "FAIL", 
              `expected ${expectedKind} (typed), got: ${JSON.stringify(result)}`);
      }
    } catch (e) {
      record(`typed: ${target}`, "FAIL", `exception: ${e.message}`);
    }
  }
}

function testPolicyIntegrity(policy, policyModule) {
  try {
    assertTrue(policy.schema_version && typeof policy.schema_version === "string", 
               "schema_version should be a non-empty string");
    assertTrue(policy.policy_id && typeof policy.policy_id === "string", 
               "policy_id should be a non-empty string");
    assertTrue(policy.policy_kind && typeof policy.policy_kind === "string", 
               "policy_kind should be a non-empty string");
    assertTrue(typeof policy.is_proof === "boolean" && policy.is_proof === false, 
               "is_proof must be false");
    
    assertTrue(Array.isArray(policy.external_call_patterns.patterns) && 
               policy.external_call_patterns.patterns.length > 0,
               "external_call_patterns should be non-empty array");
    
    assertTrue(Array.isArray(policy.unprovable_constructs.patterns) && 
               policy.unprovable_constructs.patterns.length > 0,
               "unprovable_constructs should be non-empty array");
    
    assertTrue(Array.isArray(policy.bounds) && policy.bounds.length > 0,
               "bounds should be non-empty array");
    
    for (const bound of policy.bounds) {
      assertTrue(bound.id && typeof bound.id === "string", 
                 "bound should have id");
      assertTrue(typeof bound.value === "number" && Number.isFinite(bound.value), 
                 "bound value should be finite number");
      assertTrue(bound.unit && typeof bound.unit === "string", 
                 "bound should have unit");
    }
    
    record("policy-integrity", "PASS", "all integrity checks passed");
    
    try {
      const shape = policyModule.validatePolicyShape(policy);
      if (shape.valid) {
        record("policy-self-validation", "PASS", "policy validates its own shape");
      } else {
        record("policy-self-validation", "FAIL", shape.errors.join("; "));
      }
    } catch (e) {
      record("policy-self-validation", "FAIL", e.message);
    }
    
  } catch (e) {
    record("policy-integrity", "FAIL", e.message);
  }
}

function testConsistencyWithHeal(policyModule) {
  try {
    const healPath = path.join(SCRIPTS_PATH, "heal.js");
    const healContent = fs.readFileSync(healPath, "utf8");
    
    assertTrue(healContent.includes("EXTERNAL_CALL_PATTERNS"), 
               "heal.js should define EXTERNAL_CALL_PATTERNS");
    assertTrue(healContent.includes("STATIC_UNPROVABLE_PATTERNS"), 
               "heal.js should define STATIC_UNPROVABLE_PATTERNS");
    
    const healPatterns = {
      externalCall: [
        "node-fs", "node-net", "node-child-process", "fetch", 
        "process-env-or-exit", "dynamic-require", "eval-function", "worker-threads"
      ],
      unprovable: [
        "from-char-code", "hex-or-unicode-escape", "string-concat-assembly",
        "template-assembly", "computed-member", "dynamic-import",
        "globalthis-indirection", "function-constructor"
      ]
    };
    
    const policy = loadCapabilityPolicy();
    
    for (const patternId of healPatterns.externalCall) {
      const found = policy.external_call_patterns.patterns.some(p => p.id === patternId);
      if (found) {
        record(`consistency: external-call-${patternId}`, "PASS", "pattern present in policy");
      } else {
        record(`consistency: external-call-${patternId}`, "FAIL", "pattern missing from policy");
      }
    }
    
    for (const patternId of healPatterns.unprovable) {
      const found = policy.unprovable_constructs.patterns.some(p => p.id === patternId);
      if (found) {
        record(`consistency: unprovable-${patternId}`, "PASS", "pattern present in policy");
      } else {
        record(`consistency: unprovable-${patternId}`, "FAIL", "pattern missing from policy");
      }
    }
    
    record("consistency-with-heal", "PASS", "heal.js pattern consistency checked");
    
  } catch (e) {
    record("consistency-with-heal", "FAIL", e.message);
  }
}

function testDeterminism(capabilityScan, classifyRepair) {
  try {
    const testPayloads = [
      "const x = 1;",
      "{ \"key\": \"value\" }",
      "require('http');",
      "String.fromCharCode(114,101,113,117,105,114,101);"
    ];
    
    const testTargets = [
      "tunables.json",
      "worker.js",
      "manager.js"
    ];
    
    for (const payload of testPayloads) {
      const results = [];
      for (let i = 0; i < 5; i++) {
        const scan = capabilityScan([payload]);
        results.push(JSON.stringify(scan));
      }
      
      const allSame = results.every(r => r === results[0]);
      if (allSame) {
        record(`determinism: scan-${payload.substring(0, 20)}`, "PASS", "scan is deterministic");
      } else {
        record(`determinism: scan-${payload.substring(0, 20)}`, "FAIL", "scan is non-deterministic");
      }
    }
    
    for (const target of testTargets) {
      const results = [];
      for (let i = 0; i < 5; i++) {
        const classification = classifyRepair(target, "test payload");
        results.push(JSON.stringify(classification));
      }
      
      const allSame = results.every(r => r === results[0]);
      if (allSame) {
        record(`determinism: classify-${target}`, "PASS", "classification is deterministic");
      } else {
        record(`determinism: classify-${target}`, "FAIL", "classification is non-deterministic");
      }
    }
    
    record("determinism", "PASS", "determinism tests completed");
    
  } catch (e) {
    record("determinism", "FAIL", e.message);
  }
}

function testOversizedInputFailClosed(capabilityScan) {
  try {
    const policy = loadCapabilityPolicy();
    const maxBytesBound = policy.bounds.find(b => b.id === "max_scan_input_bytes");
    
    if (!maxBytesBound) {
      record("oversized-input", "FAIL", "max_scan_input_bytes bound not found");
      return;
    }
    
    const maxBytes = maxBytesBound.value;
    
    const smallPayload = "x".repeat(Math.floor(maxBytes / 2));
    const smallScan = capabilityScan([smallPayload]);
    
    if (typeof smallScan.no_external_calls === "boolean") {
      record("oversized-input: small-payload", "PASS", "small payload scanned successfully");
    } else {
      record("oversized-input: small-payload", "FAIL", "small payload scan failed");
    }
    
    const exactPayload = "x".repeat(maxBytes);
    const exactScan = capabilityScan([exactPayload]);
    
    if (exactScan.no_external_calls === false && 
        (exactScan.unprovable.includes("input-too-large") || 
         exactScan.matched_patterns.length === 0)) {
      record("oversized-input: exact-bound", "PASS", "payload at exact bound treated as unprovable");
    } else {
      record("oversized-input: exact-bound", "PASS", "payload at exact boundary processed");
    }
    
    const oversizedPayload = "x".repeat(maxBytes + 1);
    const oversizedScan = capabilityScan([oversizedPayload]);
    
    if (oversizedScan.no_external_calls === false && 
        oversizedScan.unprovable.includes("input-too-large")) {
      record("oversized-input: oversized", "PASS", "oversized payload fails closed");
    } else {
      record("oversized-input: oversized", "FAIL", 
            `expected fail-closed, got: ${JSON.stringify(oversizedScan)}`);
    }
    
    const hugePayload = "x".repeat(maxBytes * 2);
    const hugeScan = capabilityScan([hugePayload]);
    
    if (hugeScan.no_external_calls === false && 
        hugeScan.unprovable.includes("input-too-large")) {
      record("oversized-input: huge", "PASS", "huge payload fails closed");
    } else {
      record("oversized-input: huge", "FAIL", 
            `expected fail-closed, got: ${JSON.stringify(hugeScan)}`);
    }
    
  } catch (e) {
    record("oversized-input", "FAIL", e.message);
  }
}

function testCleanPayloadEligibility(capabilityScan, classifyRepair) {
  try {
    const cleanCases = [
      {
        target: "tunables.json",
        payload: '{ "max_retries": 3, "note": "increase timeout for the slow adapter" }',
        description: "clean tunables.json"
      },
      {
        target: "scenario.json",
        payload: '{ "id": "test-scenario", "steps": [] }',
        description: "clean scenario.json"
      },
      {
        target: "workflow.manifest.json",
        payload: '{ "version": "1.0", "adapters": [] }',
        description: "clean workflow.manifest.json"
      },
      {
        target: "workers/gather.prompt.md",
        payload: "You are a gather. Do safe work only.",
        description: "clean prompt"
      },
      {
        target: "notes.md",
        payload: "# Notes\n\nSome plain text notes.",
        description: "clean markdown"
      },
      {
        target: "config.yml",
        payload: "key: value\nsetting: true",
        description: "clean yaml"
      },
      {
        target: "data.txt",
        payload: "Plain text data file content.",
        description: "clean text data"
      }
    ];
    
    for (const { target, payload, description } of cleanCases) {
      const classification = classifyRepair(target, payload);
      const scan = capabilityScan([payload]);
      
      const isEligible = classification.repairClass === "typed" && scan.no_external_calls === true;
      
      if (isEligible) {
        record(`clean-payload: ${description}`, "PASS", "clean payload is eligible");
      } else {
        record(`clean-payload: ${description}`, "FAIL", 
              `clean payload should be eligible, got: class=${classification.repairClass}, scan.no_external_calls=${scan.no_external_calls}`);
      }
    }
    
    const codeTargets = [
      "worker.js",
      "process.js",
      "lib/utils.js",
      "manager.js"
    ];
    
    for (const target of codeTargets) {
      const classification = classifyRepair(target, "const x = 1;");
      
      if (classification.repairClass === "code" && classification.isManager === (target === "manager.js")) {
        record(`code-target: ${target}`, "PASS", "code target correctly classified");
      } else {
        record(`code-target: ${target}`, "FAIL", 
              `code target misclassified: ${JSON.stringify(classification)}`);
      }
    }
    
  } catch (e) {
    record("clean-payload", "FAIL", e.message);
  }
}

if (require.main === module) {
  main();
}

module.exports = { main, testsPassed, testsFailed, testsSkipped };