#!/usr/bin/env node
"use strict";

/**
 * scripts/capability-policy.js — GraphSmith v0.2.0 Phase C
 *
 * Zero-dep CJS module that loads the declarative scripts/risk-policy.json
 * and exposes the shared, canonical capability-classification surface:
 *
 *   classifyRepair(target, payload) -> { repairClass, isManager, kind }
 *   capabilityScan(texts)           -> { no_external_calls, matched_patterns, unprovable }
 *
 * This is a SYNTACTIC ALLOWLIST, NOT a proof (plan §3.3, risk-policy.json
 * "is_proof": false). It can only demonstrate the ABSENCE of statically
 * detectable external-call / obfuscation constructs in a payload -- it can
 * never prove a payload is safe to execute. Every gate here is fail-closed:
 * any doubt (unrecognized construct, oversized input) resolves to NOT
 * eligible / NOT provably clean.
 *
 * Deterministic: no clock, no randomness, no network/filesystem side effects
 * beyond reading risk-policy.json once at load time.
 *
 * Aligned with scripts/heal.js STATIC_UNPROVABLE_PATTERNS / EXTERNAL_CALL_PATTERNS
 * and scripts/graphlint.js R5 (eval/exec/new-require ban) in spirit. heal.js
 * and scaffold.js keep their own inline copies today; this module is the
 * shared canonical policy they can later converge onto -- it does not import
 * or mutate either file.
 */

const fs = require("fs");
const path = require("path");

const POLICY_PATH = path.join(__dirname, "risk-policy.json");

function loadPolicyRaw(policyPath) {
  const text = fs.readFileSync(policyPath, "utf8");
  return JSON.parse(text);
}

/* ---------------------------------------------------------------------------
 * Shape validation -- the policy JSON validates against its own declared
 * shape. Lightweight structural check (zero-dep: no schema library).
 * ------------------------------------------------------------------------- */

function isNonEmptyString(v) {
  return typeof v === "string" && v.length > 0;
}

function validatePolicyShape(policy) {
  const errors = [];
  const req = (cond, msg) => {
    if (!cond) errors.push(msg);
  };

  req(policy && typeof policy === "object", "policy must be an object");
  if (!policy || typeof policy !== "object") {
    return { valid: false, errors };
  }

  req(/^\d+\.\d+\.\d+$/.test(String(policy.schema_version)), "schema_version must be a semver string (e.g. '1.0.0')");
  req(isNonEmptyString(policy.policy_id), "policy_id must be a non-empty string");
  req(isNonEmptyString(policy.policy_kind), "policy_kind must be a non-empty string");
  req(typeof policy.is_proof === "boolean" && policy.is_proof === false, "is_proof must be boolean false (this is a policy, not a proof)");

  req(policy.repair_class_taxonomy && typeof policy.repair_class_taxonomy === "object", "repair_class_taxonomy must be an object");
  if (policy.repair_class_taxonomy) {
    req(Array.isArray(policy.repair_class_taxonomy.typed && policy.repair_class_taxonomy.typed.kinds), "repair_class_taxonomy.typed.kinds must be an array");
    req(Array.isArray(policy.repair_class_taxonomy.code && policy.repair_class_taxonomy.code.kinds), "repair_class_taxonomy.code.kinds must be an array");
  }

  req(policy.manager_detection && typeof policy.manager_detection === "object", "manager_detection must be an object");
  if (policy.manager_detection) {
    req(policy.manager_detection.case_insensitive === true, "manager_detection.case_insensitive must be true");
    req(Array.isArray(policy.manager_detection.exact_basenames), "manager_detection.exact_basenames must be an array");
    req(isNonEmptyString(policy.manager_detection.basename_regex), "manager_detection.basename_regex must be a non-empty string");
  }

  req(Array.isArray(policy.classification_rules) && policy.classification_rules.length > 0, "classification_rules must be a non-empty array");
  if (Array.isArray(policy.classification_rules)) {
    const last = policy.classification_rules[policy.classification_rules.length - 1];
    req(last && last.when === "default", "classification_rules must end with a 'default' fallback rule (fail-closed)");
    for (const rule of policy.classification_rules) {
      req(isNonEmptyString(rule.id), "each classification_rule needs a non-empty id");
      req(isNonEmptyString(rule.when), `classification_rule '${rule.id}' needs a 'when' matcher`);
      req(rule.repair_class === "typed" || rule.repair_class === "code", `classification_rule '${rule.id}' repair_class must be 'typed' or 'code'`);
      req(typeof rule.is_manager === "boolean", `classification_rule '${rule.id}' is_manager must be boolean`);
    }
  }

  req(policy.auto_apply_eligibility && typeof policy.auto_apply_eligibility === "object", "auto_apply_eligibility must be an object");
  if (policy.auto_apply_eligibility) {
    req(policy.auto_apply_eligibility.requires_repair_class === "typed", "auto_apply_eligibility.requires_repair_class must be 'typed'");
    req(policy.auto_apply_eligibility.requires_no_external_calls === true, "auto_apply_eligibility.requires_no_external_calls must be true");
    req(policy.auto_apply_eligibility.code_always_ineligible === true, "auto_apply_eligibility.code_always_ineligible must be true");
    req(policy.auto_apply_eligibility.manager_always_ineligible === true, "auto_apply_eligibility.manager_always_ineligible must be true");
  }

  const checkPatternGroup = (group, label) => {
    req(group && Array.isArray(group.patterns) && group.patterns.length > 0, `${label}.patterns must be a non-empty array`);
    if (group && Array.isArray(group.patterns)) {
      const seen = new Set();
      for (const p of group.patterns) {
        req(isNonEmptyString(p.id), `${label} pattern entries need a non-empty id`);
        req(isNonEmptyString(p.pattern), `${label} pattern '${p.id}' needs a non-empty 'pattern' string`);
        req(typeof p.flags === "string", `${label} pattern '${p.id}' needs a string 'flags' (may be empty)`);
        if (isNonEmptyString(p.id)) {
          req(!seen.has(p.id), `${label} pattern id '${p.id}' is duplicated`);
          seen.add(p.id);
        }
        if (isNonEmptyString(p.pattern)) {
          try {
            // eslint-disable-next-line no-new
            new RegExp(p.pattern, p.flags || "");
          } catch (err) {
            errors.push(`${label} pattern '${p.id}' is not a valid regex: ${err.message}`);
          }
        }
      }
    }
  };
  checkPatternGroup(policy.external_call_patterns, "external_call_patterns");
  checkPatternGroup(policy.unprovable_constructs, "unprovable_constructs");

  req(Array.isArray(policy.bounds) && policy.bounds.length > 0, "bounds must be a non-empty array");
  if (Array.isArray(policy.bounds)) {
    for (const b of policy.bounds) {
      req(isNonEmptyString(b.id), "each bound needs a non-empty id");
      req(typeof b.value === "number" && Number.isFinite(b.value), `bound '${b.id}' value must be a finite number`);
      req(isNonEmptyString(b.unit), `bound '${b.id}' needs a unit`);
    }
  }

  return { valid: errors.length === 0, errors };
}

/* ---------------------------------------------------------------------------
 * Compilation -- policy patterns/bounds pre-compiled once at load time.
 * ------------------------------------------------------------------------- */

function compilePolicy(policy) {
  const shape = validatePolicyShape(policy);
  if (!shape.valid) {
    throw new Error(`risk-policy.json failed shape validation:\n  - ${shape.errors.join("\n  - ")}`);
  }

  const compilePatternGroup = (group) =>
    group.patterns.map((p) => ({ id: p.id, re: new RegExp(p.pattern, p.flags || "") }));

  const externalCallPatterns = compilePatternGroup(policy.external_call_patterns);
  const unprovablePatterns = compilePatternGroup(policy.unprovable_constructs);

  const boundsById = {};
  for (const b of policy.bounds) boundsById[b.id] = b;

  const managerBasenames = new Set(policy.manager_detection.exact_basenames.map((b) => b.toLowerCase()));
  const managerRegex = new RegExp(policy.manager_detection.basename_regex, "i");

  return {
    raw: policy,
    externalCallPatterns,
    unprovablePatterns,
    boundsById,
    managerBasenames,
    managerRegex,
    classificationRules: policy.classification_rules.slice().sort((a, b) => (a.order || 0) - (b.order || 0)),
  };
}

const POLICY = compilePolicy(loadPolicyRaw(POLICY_PATH));

/* ---------------------------------------------------------------------------
 * classifyRepair(target, payload) -> { repairClass, isManager, kind }
 * ------------------------------------------------------------------------- */

function normalizeRelPosix(relPosix) {
  return String(relPosix || "")
    .split(/[/\\]+/)
    .filter((p) => p && p !== ".")
    .join("/")
    .replace(/\/+$/, "");
}

function isManagerPath(target) {
  const posix = normalizeRelPosix(target).toLowerCase();
  if (!posix) return false;
  const base = path.posix.basename(posix);
  if (POLICY.managerBasenames.has(base)) return true;
  return POLICY.managerRegex.test(posix);
}

function matchesExtensionIn(posix, extensions, caseInsensitive) {
  const ext = path.posix.extname(posix).replace(/^\./, "");
  const candidate = caseInsensitive ? ext.toLowerCase() : ext;
  const list = caseInsensitive ? extensions.map((e) => e.toLowerCase()) : extensions;
  return list.includes(candidate) && ext.length > 0;
}

function applyRule(rule, posix, base) {
  switch (rule.when) {
    case "manager-path":
      return isManagerPath(posix);
    case "extension-in":
      return matchesExtensionIn(posix, rule.extensions, rule.case_insensitive !== false);
    case "path-contains-and-basename-suffix":
      // posix is normalized WITHOUT a leading slash (normalizeRelPosix strips
      // it), so a top-level "workers/x.prompt.md" would never contain the
      // anchored "/workers/" substring on its own -- only a nested path like
      // "a/workers/x.prompt.md" would. Prepend "/" before the containment
      // check so top-level and nested paths are both matched consistently.
      return ("/" + posix).includes(rule.path_contains) && base.endsWith(rule.basename_suffix);
    case "basename-equals":
      return base === rule.basename;
    case "basename-equals-or-path-regex-or-basename-suffix": {
      if (base === rule.basename_equals) return true;
      const re = new RegExp(rule.path_regex, rule.path_regex_flags || "");
      if (re.test(posix)) return true;
      return base.endsWith(rule.basename_suffix);
    }
    case "basename-suffix-or-basename-equals-or-basename-suffix":
      return (
        base.endsWith(rule.basename_suffix) ||
        base === rule.basename_equals ||
        base.endsWith(rule.fallback_basename_suffix)
      );
    case "basename-suffix-any":
      return rule.basename_suffixes.some((suf) => base.endsWith(suf));
    case "default":
      return true;
    default:
      // Unknown matcher kind: fail-closed, never matches (falls through to default rule).
      return false;
  }
}

/**
 * classifyRepair(target, payload) -> { repairClass, isManager, kind }
 *
 * Classification is driven entirely by `target` (the repair's relative path),
 * mirroring scripts/heal.js classifyTarget/isManagerPath exactly via the
 * declarative classification_rules in risk-policy.json. `payload` is accepted
 * for API symmetry with capabilityScan (a future rule could inspect content),
 * but no current rule depends on it -- classification stays deterministic
 * and path-driven.
 */
function classifyRepair(target, _payload) {
  const posix = normalizeRelPosix(target);
  const base = path.posix.basename(posix);
  for (const rule of POLICY.classificationRules) {
    if (applyRule(rule, posix, base)) {
      return { repairClass: rule.repair_class, isManager: !!rule.is_manager, kind: rule.kind };
    }
  }
  // Unreachable if risk-policy.json ends with a 'default' rule (enforced by
  // validatePolicyShape), but fail-closed here too.
  return { repairClass: "code", isManager: false, kind: "unknown-executable-surface" };
}

/* ---------------------------------------------------------------------------
 * capabilityScan(texts) -> { no_external_calls, matched_patterns, unprovable }
 * ------------------------------------------------------------------------- */

function byteLength(str) {
  return Buffer.byteLength(str, "utf8");
}

/**
 * sanitizeForScan(text) -> string
 *
 * String-literal-aware comment stripper + whitespace collapser, run BEFORE
 * pattern matching so the syntactic allowlist can't be defeated by:
 *   - comment-split keywords: `req/**\/uire("http")` -> `require("http")`
 *   - comment/whitespace insertion between an identifier and its call:
 *     `require /* x *\/ ("http")` -> `require ("http")` (still matches
 *     `\brequire\s*\(`).
 *
 * `//` and `/* *\/` are only treated as comments OUTSIDE string literals
 * (single/double/backtick) so a legitimate string like "http://example.com"
 * is never mistaken for a line comment and truncated -- that would be a
 * fail-OPEN regression (silently dropping the tail of a payload we still
 * need to scan). Comments are removed entirely (not blanked-with-spaces)
 * so a comment sitting directly between two keyword halves can't leave a
 * whitespace gap that would otherwise defeat the bare-token regexes below;
 * genuine whitespace between separate tokens survives as a single space,
 * so real space-separated words are never merged into a keyword they don't
 * form. This mirrors graphlint.js sanitize()'s string-literal-aware comment
 * handling but additionally collapses whitespace (graphlint preserves line
 * structure for line numbers; this scan has no such requirement).
 */
function sanitizeForScan(text) {
  const n = text.length;
  let out = "";
  let i = 0;
  while (i < n) {
    const c = text[i];
    const c2 = text.slice(i, i + 2);
    if (c2 === "//") {
      const nl = text.indexOf("\n", i);
      i = nl === -1 ? n : nl;
      continue;
    }
    if (c2 === "/*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? n : end + 2;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      const quote = c;
      const isTemplate = quote === "`";
      out += c;
      let j = i + 1;
      while (j < n) {
        if (text[j] === "\\") { out += text[j] + (text[j + 1] || ""); j += 2; continue; }
        if (text[j] === quote) { out += text[j]; j++; break; }
        if (!isTemplate && text[j] === "\n") break; // unterminated ' or " ends at newline
        out += text[j];
        j++;
      }
      i = j;
      continue;
    }
    out += c;
    i++;
  }
  return out.replace(/\s+/g, " ").trim();
}

/**
 * capabilityScan(texts) -> { no_external_calls, matched_patterns, unprovable }
 *
 * FAIL-CLOSED: no_external_calls is true ONLY if NO external-call pattern
 * matches AND NO unprovable-construct matches. This is a syntactic allowlist,
 * not a proof (risk-policy.json auto_apply_eligibility, is_proof: false).
 *
 * Matching runs against the SANITIZED (comment-stripped, whitespace-
 * collapsed) view of the payload -- see sanitizeForScan -- so comment-split
 * and comment/whitespace-insertion tricks can't evade either the
 * external-call patterns or the unprovable-construct patterns (which now
 * also include bare-identifier fail-closed checks: `require`, `import`,
 * `fetch`, `exec`/`execSync`/`execFile*`/`spawn*`, `child_process`, `eval`,
 * `Function`, `Reflect.construct`, `globalThis`, `XMLHttpRequest`,
 * `WebSocket`, and the node net modules -- these match the identifier as a
 * bare token so aliasing it through a variable, e.g. `const r = require;
 * r("http")`, can no longer launder it into an eligible payload).
 */
function capabilityScan(texts) {
  const blob = Array.isArray(texts) ? texts.join("\n") : String(texts || "");

  const maxBytes = POLICY.boundsById.max_scan_input_bytes ? POLICY.boundsById.max_scan_input_bytes.value : Infinity;
  const maxReported = POLICY.boundsById.max_reported_matches ? POLICY.boundsById.max_reported_matches.value : Infinity;

  if (byteLength(blob) >= maxBytes) {
    // Fail-closed: cannot bound worst-case scan cost, so treat as unprovable
    // rather than silently truncating/scanning a partial payload.
    return {
      no_external_calls: false,
      matched_patterns: [],
      unprovable: ["input-too-large"].slice(0, maxReported),
    };
  }

  const sanitized = sanitizeForScan(blob);

  const matched = [];
  for (const p of POLICY.externalCallPatterns) {
    if (p.re.test(sanitized)) matched.push(p.id);
  }
  const unprovable = [];
  for (const p of POLICY.unprovablePatterns) {
    if (p.re.test(sanitized)) unprovable.push(p.id);
  }

  return {
    no_external_calls: matched.length === 0 && unprovable.length === 0,
    matched_patterns: matched.slice(0, maxReported),
    unprovable: unprovable.slice(0, maxReported),
  };
}

module.exports = {
  POLICY_PATH,
  loadPolicyRaw,
  validatePolicyShape,
  classifyRepair,
  capabilityScan,
};

/* ---------------------------------------------------------------------------
 * --selftest
 * ------------------------------------------------------------------------- */

function selftest() {
  const results = [];
  const rec = (name, pass, detail) => results.push({ name, pass: !!pass, detail: detail || null });

  // 0. Policy JSON validates against its own declared shape.
  const shape = validatePolicyShape(POLICY.raw);
  rec("policy-json-validates-own-shape", shape.valid, shape.valid ? null : shape.errors.join("; "));

  // 1. Clean prose/knob payload -> eligible (typed repair_class + no_external_calls).
  const cleanTarget = "tunables.json";
  const cleanPayload = '{ "max_retries": 3, "note": "increase timeout for the slow adapter" }';
  const cleanClass = classifyRepair(cleanTarget, cleanPayload);
  const cleanScan = capabilityScan([cleanPayload]);
  const cleanEligible = cleanClass.repairClass === "typed" && cleanScan.no_external_calls === true;
  rec("clean-payload-eligible", cleanEligible, JSON.stringify({ class: cleanClass, scan: cleanScan }));

  // 2. Obfuscated require (fromCharCode/concat/computed) -> NOT eligible (fail-closed).
  const obfuscatedPayload =
    "const m = String.fromCharCode(114,101,113,117,105,114,101); globalThis[m]('ht' + 'tp');";
  const obfuscatedScan = capabilityScan([obfuscatedPayload]);
  const obfuscatedNotEligible = obfuscatedScan.no_external_calls === false && obfuscatedScan.unprovable.length > 0;
  rec("obfuscated-require-not-eligible", obfuscatedNotEligible, JSON.stringify(obfuscatedScan));

  // 3. Plain require('http') external call -> NOT eligible.
  const httpPayload = "const http = require('http'); http.get('http://example.com');";
  const httpScan = capabilityScan([httpPayload]);
  const httpNotEligible = httpScan.no_external_calls === false && httpScan.matched_patterns.includes("node-net");
  rec("plain-require-http-not-eligible", httpNotEligible, JSON.stringify(httpScan));

  // 4. Case-variant manager target -> classified manager.
  const variants = ["MANAGER.js", "Manager.js", "nested/manager.JS", "manager.cjs", "workers/Manager.mjs"];
  const variantResults = variants.map((v) => ({ v, c: classifyRepair(v, "console.log(1);") }));
  const allManagers = variantResults.every((r) => r.c.isManager === true && r.c.repairClass === "code" && r.c.kind === "manager");
  rec("case-variant-manager-classified", allManagers, JSON.stringify(variantResults.map((r) => r.c)));

  // 5. Non-manager executable stays code but is_manager false (sanity boundary check).
  const workerClass = classifyRepair("workers/process.js", "module.exports = () => {};");
  rec(
    "non-manager-executable-classified-code-not-manager",
    workerClass.repairClass === "code" && workerClass.isManager === false && workerClass.kind === "executable",
    JSON.stringify(workerClass)
  );

  // 6. Bypass regressions (Kimi/orchestrator finding): variable indirection
  // and comment-split must both fail closed, and clean prose/knob content
  // must stay eligible.
  const variableIndirectionRequire = capabilityScan(["const r = require; r('http');"]);
  rec(
    "bypass-variable-indirection-require-not-eligible",
    variableIndirectionRequire.no_external_calls === false && variableIndirectionRequire.unprovable.length > 0,
    JSON.stringify(variableIndirectionRequire)
  );

  const variableIndirectionFetch = capabilityScan(["const f = fetch; f('http://evil.com');"]);
  rec(
    "bypass-variable-indirection-fetch-not-eligible",
    variableIndirectionFetch.no_external_calls === false && variableIndirectionFetch.unprovable.length > 0,
    JSON.stringify(variableIndirectionFetch)
  );

  const commentSplitRequire = capabilityScan(["req/**/uire(\"http\").get('x');"]);
  rec(
    "bypass-comment-split-require-not-eligible",
    commentSplitRequire.no_external_calls === false,
    JSON.stringify(commentSplitRequire)
  );

  const variableIndirectionExec = capabilityScan(["const run = exec; run('whoami');"]);
  rec(
    "bypass-variable-indirection-exec-not-eligible",
    variableIndirectionExec.no_external_calls === false && variableIndirectionExec.unprovable.length > 0,
    JSON.stringify(variableIndirectionExec)
  );

  const cleanKnobStillEligible = capabilityScan(['{ "max_retries": 3, "note": "increase timeout for the slow adapter" }']);
  rec(
    "bypass-fix-clean-knob-still-eligible",
    cleanKnobStillEligible.no_external_calls === true,
    JSON.stringify(cleanKnobStillEligible)
  );

  // 7. workers/*.prompt.md must classify as kind:"prompt" (typed), not
  // kind:"data" -- path_contains("/workers/") must match a top-level
  // "workers/..." path, not only a nested one.
  const workerPromptClass = classifyRepair("workers/gather.prompt.md", "You are a gather. Do safe work only.");
  rec(
    "worker-prompt-classified-kind-prompt",
    workerPromptClass.repairClass === "typed" && workerPromptClass.isManager === false && workerPromptClass.kind === "prompt",
    JSON.stringify(workerPromptClass)
  );

  const allPass = results.every((r) => r.pass);
  const output = { selftest: "capability-policy", policy_id: POLICY.raw.policy_id, schema_version: POLICY.raw.schema_version, all_pass: allPass, results };
  console.log(JSON.stringify(output, null, 2));
  if (!allPass) process.exitCode = 1;
}

if (require.main === module && process.argv.includes("--selftest")) {
  selftest();
}
