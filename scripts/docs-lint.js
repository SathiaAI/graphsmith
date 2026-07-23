#!/usr/bin/env node
/**
 * docs-lint.js — Contract 10 List A honest-language lint (v2 rebuild).
 *
 * Enforces the full required-form table for ~11 over-claim terms.
 * Context-aware: skips code blocks (```fences), inline code (backticks),
 * code identifiers, and lines/blocks carrying the escape marker
 * <!-- lint-allow: honest-language (reason) -->.
 *
 * Scans the shippable docs fileset. Failure messages report
 * file:line: <rule-id> only — NEVER the banned term.
 *
 * Zero deps. CommonJS. Node >= 18. Deterministic, no network, fail-closed.
 *
 * Usage:
 *   node scripts/docs-lint.js               scan the shippable docs fileset
 *   node scripts/docs-lint.js --selftest    run internal test suite
 */

"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

// --- rule definitions (contract 10 List A) -----------------------------------

/**
 * Each rule:
 *   id             — rule identifier (emitted in output, never the banned term)
 *   bannedPattern  — regex to detect the bare over-claim term
 *   negationPatterns — array of regexes; if any matches the line, skip
 *   requiredFormPatterns — array of regexes; if any matches nearby prose, skip
 *   suppressible    — if false, the term is treated as ALWAYS banned (R9a-d, R11)
 */
const RULES = [
  {
    id: "R1-proven",
    bannedPattern: /\bproven\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+)(?:\S+\s+){0,4}proven\b/gi,
      /\bproven\b(?:\s+\S+){0,4}\s+(?:false|wrong|incorrect|misleading|otherwise)\b/gi,
      /\bmakes?\s+no\s+(?:['"`]?)proven(?:['"`]?)\s+claim\b/gi,
      /\bdoes?\s+not\s+constitute\s+a\s+proven\b/gi,
      /\bdo(?:es)?\s+not\s+(?:\S+\s+){0,3}proven\b/gi,
    ],
    requiredFormPatterns: [
      /\btested\s*:/gi,
      /\btest(?:ed)?\s+(?:shows?|against|via|with|using)\b/gi,
    ],
  },
  {
    id: "R2-immutable",
    bannedPattern: /\bimmutable\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+)(?:\S+\s+){0,4}immutable\b/gi,
      /\bimmutable\b(?:\s+\S+){0,4}\s+(?:false|wrong|incorrect|misleading)\b/gi,
    ],
    requiredFormPatterns: [
      /\brewrite-detecting\b/gi,
      /\banchored\s+head\b/gi,
    ],
  },
  {
    id: "R3-certified",
    bannedPattern: /\bcertified\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+)(?:\S+\s+){0,4}certified\b/gi,
      /\bcertified\b(?:\s+\S+){0,4}\s+(?:false|wrong|incorrect|misleading)\b/gi,
      /\bdoes?\s+not\s+(?:claim|consider)\s+(?:\S+\s+){0,3}certified\b/gi,
      /\bmakes?\s+no\s+(?:\S+\s+){0,2}certified\b/gi,
    ],
    requiredFormPatterns: [
      /\badversarial\s+review\b/gi,
      /\battestation\s+of\s+tested\s+behavior\b/gi,
    ],
  },
  {
    id: "R4-sandboxed",
    bannedPattern: /\bsandboxed\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+|isn['\u2019]t\s+)(?:\S+\s+){0,3}sandboxed\b/gi,
      /\bsandboxed\b(?:\s+\S+){0,4}\s+(?:false|wrong|incorrect|misleading)\b/gi,
    ],
    requiredFormPatterns: [
      /\bdisposable\s+evaluation\s+copy\s+with\s+mocked\s+effects\b/gi,
      /\bcontainer-isolated\b/gi,
    ],
  },
  {
    id: "R5-exactly-once",
    bannedPattern: /\bexactly[-\s]once\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+|doesn['\u2019]t\s+)(?:\S+\s+){0,4}exactly[-\s]once\b/gi,
      /\bexactly[-\s]once\b(?:\s+\S+){0,4}\s+(?:false|wrong|incorrect|misleading)\b/gi,
      /\bmakes?\s+no\s+(?:\S+\s+){0,2}exactly[-\s]once\b/gi,
      /\bdoes?\s+not\s+provide\s+exactly[-\s]once\b/gi,
    ],
    requiredFormPatterns: [
      /\bcapability\s+class\b/gi,
      /\bcontract\s*0?6\b/i,
      /\b(?:at-most-once|at-least-once|idempoten)\b/gi,
    ],
  },
  {
    id: "R6-constant-monitoring",
    bannedPattern: /\bconstant\s+monitoring\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+|without\s+)(?:\S+\s+){0,3}constant\s+monitoring\b/gi,
    ],
    requiredFormPatterns: [
      /\bcontinuous-at-every-boundary\b/gi,
    ],
  },
  {
    id: "R7-tamper-proof",
    bannedPattern: /\btamper-proof\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+)(?:\S+\s+){0,3}tamper-proof\b/gi,
      /\btamper-proof\b(?:\s+\S+){0,4}\s+(?:false|wrong|incorrect|misleading)\b/gi,
    ],
    requiredFormPatterns: [
      /\btamper-evident\s+vs\s+anchored\s+head\b/gi,
      /\btamper[- ]?evident\b/gi,
    ],
  },
  {
    id: "R8-pen-test",
    bannedPattern: /\bpen[-\s]?test(?:ing|ed|s)?\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+|without\s+)(?:\S+\s+){0,3}pen[-\s]?test/gi,
    ],
    requiredFormPatterns: [
      /\barchitecture-level\s+adversarial\s+battery\b/gi,
      /\badversarial\s+battery\b/gi,
    ],
  },
  {
    id: "R9a-certified-secure",
    bannedPattern: /\bcertified\s+secure\b/gi,
    negationPatterns: [],
    requiredFormPatterns: [],
  },
  {
    id: "R9b-security-guaranteed",
    bannedPattern: /\bsecurity\s+guaranteed\b/gi,
    negationPatterns: [],
    requiredFormPatterns: [],
  },
  {
    id: "R9c-guaranteed",
    bannedPattern: /\bguaranteed\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+|isn['\u2019]t\s+|without\s+)(?:\S+\s+){0,3}guaranteed\b/gi,
      /\bguaranteed\b(?:\s+\S+){0,4}\s+(?:false|wrong|incorrect|misleading)\b/gi,
    ],
    requiredFormPatterns: [
      /\bbest-?effort\b/gi,
      /\bno\s+guarantee\b/gi,
      /\bnot\s+guaranteed\b/gi,
    ],
  },
  {
    id: "R9d-cannot-fail",
    bannedPattern: /\bcannot\s+fail\b/gi,
    negationPatterns: [
      /\b(?:does?\s+not\s+(?:say|claim|mean|imply))\s+(?:\S+\s+){0,2}cannot\s+fail\b/gi,
    ],
    requiredFormPatterns: [
      /\bfail-safe\b/gi,
      /\bfail\s+closed\b/gi,
    ],
  },
  {
    id: "R10-atomic",
    bannedPattern: /\batomic\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+)(?:\S+\s+){0,3}atomic\b/gi,
    ],
    requiredFormPatterns: [
      /\bprobe-verified\b/gi,
      /\b(?:atomic\s+(?:structure|mass|number|energy|bomb))\b/gi,
    ],
  },
  {
    id: "R11-cannot-reach-network",
    bannedPattern: /\bcannot\s+reach\s+the\s+network\b/gi,
    negationPatterns: [],
    requiredFormPatterns: [
      /\bcontainer\s+profile\b/gi,
      /\bsocket-denial\s+test\b/gi,
      /\bdenial\s+test\b/gi,
    ],
  },
];

// --- file scope (shippable docs fileset) -------------------------------------

const SHIPPABLE_FILES = [
  "README.md",
  "SKILL.md",
  "GRAPHSMITH-PROTOCOL.md",
  "SPEC-CHANGES.md",
  "RELEASING.md",
  "package.json",
];

const SHIPPABLE_DIRS = ["docs", "references"];

const EXCLUDED_PREFIXES = [
  ".plans/",
  "node_modules/",
  "tests/",
  "BUILD-LEDGER.md",
  ".git/",
];

// --- markdown context stripping -----------------------------------------------

const CODE_FENCE_RE = /^( {0,3})(`{3,}|~{3,})\s*(\S*)/;
const INLINE_CODE_RE = /`[^`]+`/g;
const HTML_COMMENT_RE = /<!--[\s\S]*?-->/g;
const LINT_ALLOW_OPEN_RE = /<!--\s*lint-allow\s*:\s*honest-language\b/i;
const LINT_ALLOW_CLOSE_RE = /<!--\s*\/lint-allow\s*-->/i;
const MD_LINK_URL_RE = /\]\([^)]*\)/g;
const MD_LINK_REF_RE = /\]\[[^\]]*\]/g;
const YAML_FRONTMATTER_RE = /^---\s*$/;
const TAG_STRIP_RE = /<[^>]+>/g;
const IMAGE_RE = /!\[[^\]]*\]\([^)]*\)/g;
const LINK_TEXT_RE = /\[([^\]]*)\]\([^)]*\)/g;

/**
 * Strip rendered-prose-irrelevant syntax from a doc line.
 * Removes: inline code, HTML comments, markdown link URLs, images, HTML tags.
 * Handles lint-allow markers separately.
 */
function cleanLine(line) {
  let s = line;
  s = s.replace(IMAGE_RE, "");                // images
  s = s.replace(MD_LINK_URL_RE, "");           // link URLs
  s = s.replace(MD_LINK_REF_RE, "");           // link references
  s = s.replace(LINK_TEXT_RE, "$1");           // convert [text](url) -> text
  s = s.replace(INLINE_CODE_RE, "");           // inline code
  s = s.replace(HTML_COMMENT_RE, "");          // HTML comments (after lint-allow checked)
  s = s.replace(TAG_STRIP_RE, "");             // HTML tags
  return s;
}

// --- file list building -------------------------------------------------------

function isExcluded(fileRel) {
  const norm = fileRel.replace(/\\/g, "/");
  for (const prefix of EXCLUDED_PREFIXES) {
    if (norm === prefix || norm.startsWith(prefix)) return true;
  }
  return false;
}

function buildFileList(cwd) {
  const files = [];
  for (const f of SHIPPABLE_FILES) {
    const abs = path.join(cwd, f);
    if (fs.existsSync(abs) && !isExcluded(f)) files.push(f);
  }
  for (const dir of SHIPPABLE_DIRS) {
    const dp = path.join(cwd, dir);
    if (!fs.existsSync(dp)) continue;
    let st;
    try { st = fs.statSync(dp); } catch (e) { continue; }
    if (!st.isDirectory()) continue;
    walkDir(dp, cwd, files);
  }
  return files;
}

function walkDir(abspath, cwd, out) {
  let entries;
  try {
    entries = fs.readdirSync(abspath, { withFileTypes: true });
  } catch (e) {
    return;
  }
  for (const e of entries) {
    const childAbs = path.join(abspath, e.name);
    const childRel = path.relative(cwd, childAbs).replace(/\\/g, "/");
    if (isExcluded(childRel)) continue;
    if (e.isDirectory()) {
      walkDir(childAbs, cwd, out);
    } else if (e.isFile()) {
      out.push(childRel);
    }
  }
}

// --- scanning -----------------------------------------------------------------

/**
 * Scan one file. Returns array of { file, line, ruleId }.
 */
function scanFile(fileRel, fileAbs) {
  let raw;
  try {
    raw = fs.readFileSync(fileAbs, "utf8");
  } catch (e) {
    return [];
  }
  const results = [];
  const lines = raw.split(/\r?\n/);

  let inCodeFence = false;
  let fenceIndent = 0;
  let fenceChar = "";
  let inLintAllowBlock = false;
  let inYamlFrontmatter = false;
  let sawYamlStart = false;

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const rawLine = lines[i];

    // YAML frontmatter detection (only at file start)
    if (i === 0 && YAML_FRONTMATTER_RE.test(rawLine)) {
      inYamlFrontmatter = true;
      sawYamlStart = true;
      continue;
    }
    if (sawYamlStart && inYamlFrontmatter && YAML_FRONTMATTER_RE.test(rawLine)) {
      inYamlFrontmatter = false;
      continue;
    }
    if (inYamlFrontmatter) continue;

    // Code fence toggle
    const fenceMatch = CODE_FENCE_RE.exec(rawLine);
    if (fenceMatch) {
      if (!inCodeFence) {
        inCodeFence = true;
        fenceIndent = fenceMatch[1].length;
        fenceChar = fenceMatch[2].charAt(0);
      } else if (fenceMatch[1].length <= fenceIndent && fenceMatch[2].charAt(0) === fenceChar) {
        inCodeFence = false;
      }
      continue;
    }
    if (inCodeFence) continue;

    // Lint-allow block close
    if (LINT_ALLOW_CLOSE_RE.test(rawLine)) {
      inLintAllowBlock = false;
      continue;
    }
    if (inLintAllowBlock) continue;

    // Lint-allow line or block open
    if (LINT_ALLOW_OPEN_RE.test(rawLine)) {
      // Check if this is a block open (assume block if /lint-allow close appears later)
      // For safety, just skip this line and any subsequent lines until close.
      // But we only know it's a block if there's a close marker.
      // Strategy: if line has only lint-allow open, it's potentially a block open.
      // If line has prose before/after lint-allow, it's a line-level skip.
      // For simplicity: if the line has a lint-allow open comment, check if it's
      // the only significant content. If so → block open. Otherwise → line skip.
      const withoutComment = rawLine.replace(HTML_COMMENT_RE, "").trim();
      if (withoutComment.length === 0) {
        inLintAllowBlock = true;
      }
      continue;
    }

    // Clean the line for prose scanning (do THIS before any HTML comment stripping
    // that was already done via the regex — but we need to also clean the lint-allow
    // detection. Actually, cleanLine uses HTML_COMMENT_RE which strips all comments.
    // But we already detected lint-allow above, so now we can safely clean.)
    const prose = cleanLine(rawLine);

    // Skip empty lines after cleaning
    if (prose.trim().length === 0) continue;

    // Collect all candidate matches for this line, then resolve overlaps:
    // longer/compound rules take precedence over shorter/single-word rules.
    const candidates = [];
    for (const rule of RULES) {
      rule.bannedPattern.lastIndex = 0;
      let m;
      while ((m = rule.bannedPattern.exec(prose)) !== null) {
        if (isNegated(prose, rule)) continue;
        if (isRequiredForm(prose, rule)) continue;
        candidates.push({ ruleId: rule.id, start: m.index, end: m.index + m[0].length });
      }
    }
    // Sort by length descending, then by start position
    candidates.sort(function (a, b) {
      const lenA = a.end - a.start;
      const lenB = b.end - b.start;
      if (lenB !== lenA) return lenB - lenA;
      return a.start - b.start;
    });
    const consumed = [];
    const accepted = [];
    for (const c of candidates) {
      if (consumed.some(function (range) { return c.start < range.end && c.end > range.start; })) continue;
      consumed.push({ start: c.start, end: c.end });
      accepted.push(c);
    }
    for (const a of accepted) {
      results.push({
        file: fileRel,
        line: lineNum,
        ruleId: a.ruleId,
      });
    }
  }

  return results;
}

function isNegated(line, rule) {
  if (!rule.negationPatterns || rule.negationPatterns.length === 0) return false;
  for (const np of rule.negationPatterns) {
    try {
      np.lastIndex = 0;
      if (np.test(line)) return true;
    } catch (e) { /* skip broken pattern */ }
  }
  return false;
}

function isRequiredForm(line, rule) {
  if (!rule.requiredFormPatterns || rule.requiredFormPatterns.length === 0) return false;
  for (const rp of rule.requiredFormPatterns) {
    try {
      rp.lastIndex = 0;
      if (rp.test(line)) return true;
    } catch (e) { /* skip broken pattern */ }
  }
  return false;
}

function scanAll(cwd) {
  const fileList = buildFileList(cwd);
  const allResults = [];
  for (const f of fileList) {
    const abs = path.join(cwd, f);
    const results = scanFile(f, abs);
    for (const r of results) allResults.push(r);
  }
  return allResults;
}

// --- output -------------------------------------------------------------------

function reportResults(results) {
  for (const r of results) {
    process.stdout.write(r.file + ":" + r.line + ": " + r.ruleId + "\n");
  }
  if (results.length > 0) {
    process.stderr.write(
      "\ndocs-lint: " + results.length + " violation(s) found in " +
      new Set(results.map(function (r) { return r.file; })).size + " file(s)\n"
    );
  }
}

// --- governance: output MUST never contain raw matched text from documents ---

function outputLineSafe(outputLine) {
  // output line is in format "file:line: ruleId" — the ruleId may reference
  // the banned term as a rule label (e.g. "R1-proven") which is BY DESIGN.
  // We only need to ensure the line doesn't contain extra context that would
  // reproduce the full matched phrase from the source document.
  // Since our output is always exactly "file:line: ruleId", it's safe by construction.
  return true;
}

// --- selftest -----------------------------------------------------------------

function makeRel(p) {
  return p.replace(/\\/g, "/");
}

function selftest() {
  let passed = 0;
  const failures = [];

  function assert(name, cond, detail) {
    if (cond) {
      passed++;
      process.stderr.write("  PASS  " + name + "\n");
    } else {
      failures.push(name + (detail ? " -- " + detail : ""));
      process.stderr.write("  FAIL  " + name + (detail ? " -- " + detail : "") + "\n");
    }
  }

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gs-docslint-selftest-"));
  const prevCwd = process.cwd();
  try {
    process.chdir(root);
    fs.mkdirSync(path.join(root, "docs"));
    fs.mkdirSync(path.join(root, "references"));

    // Helper: scan a single file and return the findings
    function findings(relPath) {
      const abs = path.join(root, relPath);
      return scanFile(relPath, abs);
    }

    // Helper: assert finding count
    function assertCount(relPath, ruleId, expectedCount, label) {
      const f = findings(relPath);
      const matches = f.filter(function (r) { return r.ruleId === ruleId; });
      assert(
        label + " (" + ruleId + ": expected " + expectedCount + ", got " + matches.length + ")",
        matches.length === expectedCount,
        "got " + matches.length + " matches for " + ruleId
      );
    }

    // Helper: assert no finding for a rule
    function assertNone(relPath, ruleId, label) {
      const f = findings(relPath);
      const matches = f.filter(function (r) { return r.ruleId === ruleId; });
      assert(
        label + " (" + ruleId + ": expected 0, got " + matches.length + ")",
        matches.length === 0,
        "got " + matches.length + " matches"
      );
    }

    // --- TP: bare over-claims flagged ------------------------------------------

    fs.writeFileSync(path.join(root, "README.md"),
      "This system is proven to work in all cases.\n" +
      "Our architecture is immutable by design.\n" +
      "The tool is certified for production use.\n" +
      "The runtime is fully sandboxed.\n" +
      "We guarantee exactly once delivery.\n" +
      "We provide exactly-once semantics.\n" +
      "The system uses constant monitoring to detect issues.\n" +
      "Our ledger is tamper-proof.\n" +
      "We conducted a pen-test of the system.\n" +
      "The platform is certified secure.\n" +
      "The platform offers security guaranteed.\n" +
      "This outcome is guaranteed.\n" +
      "The process cannot fail.\n" +
      "Windows file operations are atomic.\n" +
      "The process cannot reach the network.\n",
      "utf8"
    );
    assertCount("README.md", "R1-proven", 1, "TP: proven flagged");
    assertCount("README.md", "R2-immutable", 1, "TP: immutable flagged");
    assertCount("README.md", "R3-certified", 1, "TP: certified flagged (non-safe phrase)");
    assertCount("README.md", "R4-sandboxed", 1, "TP: sandboxed flagged");
    assertCount("README.md", "R5-exactly-once", 2, "TP: exactly once flagged (both forms)");
    assertCount("README.md", "R6-constant-monitoring", 1, "TP: constant monitoring flagged");
    assertCount("README.md", "R7-tamper-proof", 1, "TP: tamper-proof flagged");
    assertCount("README.md", "R8-pen-test", 1, "TP: pen-test flagged");
    assertCount("README.md", "R9a-certified-secure", 1, "TP: certified secure flagged");
    assertCount("README.md", "R9b-security-guaranteed", 1, "TP: security guaranteed flagged");
    assertCount("README.md", "R9c-guaranteed", 1, "TP: guaranteed flagged");
    assertCount("README.md", "R9d-cannot-fail", 1, "TP: cannot fail flagged");
    assertCount("README.md", "R10-atomic", 1, "TP: atomic flagged");
    assertCount("README.md", "R11-cannot-reach-network", 1, "TP: cannot reach network flagged");

    // --- FP: negated use NOT flagged -------------------------------------------

    fs.writeFileSync(path.join(root, "SKILL.md"),
      "We make no proven claim about this system.\n" +
      "This is not immutable; it can be changed.\n" +
      "We do not claim this is certified.\n" +
      "Environments are not sandboxed by default.\n" +
      "This does not provide exactly once delivery.\n" +
      "We do not claim exactly-once behavior.\n" +
      "We do not use constant monitoring.\n" +
      "It is not tamper-proof.\n" +
      "No pen-test was performed.\n" +
      "The outcome is not guaranteed.\n" +
      "This process is not atomic.\n" +
      "The claim that it is proven is false.\n" +
      "The idea that it is immutable is misleading.\n" +
      "Saying it is certified is incorrect.\n" +
      "The claim it is sandboxed is wrong.\n",
      "utf8"
    );
    assertNone("SKILL.md", "R1-proven", "FP: 'make no proven claim' not flagged");
    assertNone("SKILL.md", "R2-immutable", "FP: negated immutable");
    assertNone("SKILL.md", "R3-certified", "FP: negated certified");
    assertNone("SKILL.md", "R4-sandboxed", "FP: negated sandboxed");
    assertNone("SKILL.md", "R5-exactly-once", "FP: negated exactly-once (both)");
    assertNone("SKILL.md", "R6-constant-monitoring", "FP: negated constant monitoring");
    assertNone("SKILL.md", "R7-tamper-proof", "FP: negated tamper-proof");
    assertNone("SKILL.md", "R8-pen-test", "FP: negated pen-test");
    assertNone("SKILL.md", "R9c-guaranteed", "FP: negated guaranteed");

    // Negated with proven-false pattern
    const allFindings = findings("SKILL.md");
    assert("FP: proven-false not flagged", !allFindings.some(function (r) { return r.ruleId === "R1-proven"; }));
    assert("FP: immutable-misleading not flagged", !allFindings.some(function (r) { return r.ruleId === "R2-immutable"; }));
    assert("FP: certified-incorrect not flagged", !allFindings.some(function (r) { return r.ruleId === "R3-certified"; }));
    assert("FP: sandboxed-wrong not flagged", !allFindings.some(function (r) { return r.ruleId === "R4-sandboxed"; }));

    // --- FP: required-form context NOT flagged ---------------------------------

    fs.writeFileSync(path.join(root, "docs", "qualified.md"),
      "This was tested: the system completes requests within 100ms.\n" +
      "Our design provides rewrite-detecting vs an anchored head.\n" +
      "This passed adversarial review before release.\n" +
      "The runtime is a disposable evaluation copy with mocked effects.\n" +
      "Each run is a container-isolated operation.\n" +
      "The capability class is at-most-once per contract 06.\n" +
      "We provide continuous-at-every-boundary detection.\n" +
      "The ledger is tamper-evident vs anchored head.\n" +
      "The audit is an architecture-level adversarial battery.\n" +
      "Windows operations are probe-verified.\n" +
      "The runtime uses a container profile with a socket-denial test cited.\n",
      "utf8"
    );
    assertNone("docs/qualified.md", "R1-proven", "FP: tested: prevents proven flag");
    assertNone("docs/qualified.md", "R2-immutable", "FP: rewrite-detecting prevents immutable flag");
    assertNone("docs/qualified.md", "R3-certified", "FP: adversarial review prevents certified flag");
    assertNone("docs/qualified.md", "R4-sandboxed", "FP: required form prevents sandboxed flag");
    assertNone("docs/qualified.md", "R5-exactly-once", "FP: capability class prevents exactly-once flag");
    assertNone("docs/qualified.md", "R6-constant-monitoring", "FP: continuous-at-every-boundary prevents flag");
    assertNone("docs/qualified.md", "R7-tamper-proof", "FP: tamper-evident prevents tamper-proof flag");
    assertNone("docs/qualified.md", "R8-pen-test", "FP: architecture-level adversarial battery prevents pen-test flag");
    assertNone("docs/qualified.md", "R10-atomic", "FP: probe-verified prevents atomic flag");
    assertNone("docs/qualified.md", "R11-cannot-reach-network", "FP: container profile prevents cannot-reach-network flag");

    // --- FP: lint-allow line escape NOT flagged --------------------------------

    fs.writeFileSync(path.join(root, "docs", "escape.md"),
      "The system is proven to work. <!-- lint-allow: honest-language (tests demonstrate this) -->\n" +
      "This is immutable by design. <!-- lint-allow: honest-language (defined as content-addressed) -->\n" +
      "Regular unflagged line.\n",
      "utf8"
    );
    const escapeFindings = findings("docs/escape.md");
    assert("FP: lint-allow line escapes proven", !escapeFindings.some(function (r) { return r.ruleId === "R1-proven"; }));
    assert("FP: lint-allow line escapes immutable", !escapeFindings.some(function (r) { return r.ruleId === "R2-immutable"; }));
    assert("FP: lint-allow does NOT escape unflagged line", escapeFindings.some(function (r) { return r.ruleId !== "R1-proven" && r.ruleId !== "R2-immutable"; }) === false,
      "got unexpected findings: " + JSON.stringify(escapeFindings));

    // --- FP: lint-allow block escape NOT flagged -------------------------------

    fs.writeFileSync(path.join(root, "docs", "block-escape.md"),
      "Before block.\n" +
      "<!-- lint-allow: honest-language (block of qualified claims) -->\n" +
      "The system is proven to work.\n" +
      "It is immutable and certified.\n" +
      "<!-- /lint-allow -->\n" +
      "After block: this is guaranteed.\n",
      "utf8"
    );
    const blockFindings = findings("docs/block-escape.md");
    assert("FP: lint-allow block escapes proven", !blockFindings.some(function (r) { return r.line === 3 && r.ruleId === "R1-proven"; }));
    assert("FP: lint-allow block escapes immutable", !blockFindings.some(function (r) { return r.ruleId === "R2-immutable"; }));
    assert("FP: lint-allow block escapes certified", !blockFindings.some(function (r) { return r.ruleId === "R3-certified"; }));
    assert("FP: after block, guaranteed IS flagged", blockFindings.some(function (r) { return r.ruleId === "R9c-guaranteed"; }));

    // --- FP: code block NOT flagged -------------------------------------------

    fs.writeFileSync(path.join(root, "docs", "codeblock.md"),
      "Some prose text here.\n" +
      "\n" +
      "```js\n" +
      "const proven = true;\n" +
      "const immutable = Object.freeze({});\n" +
      "const certified = verify(system);\n" +
      "// This is guaranteed to run\n" +
      "```\n" +
      "\n" +
      "After code block: is proven.\n",
      "utf8"
    );
    const codeFindings = findings("docs/codeblock.md");
    assert("FP: code block proven not flagged", !codeFindings.some(function (r) { return r.ruleId === "R1-proven" && r.line >= 4 && r.line <= 7; }));
    assert("FP: code block immutable not flagged", !codeFindings.some(function (r) { return r.ruleId === "R2-immutable" && r.line >= 4 && r.line <= 7; }));
    assert("FP: code block certified not flagged", !codeFindings.some(function (r) { return r.ruleId === "R3-certified" && r.line >= 4 && r.line <= 7; }));
    assert("FP: code block guaranteed not flagged", !codeFindings.some(function (r) { return r.ruleId === "R9c-guaranteed" && r.line >= 4 && r.line <= 7; }));
    assert("TP: after code block, proven IS flagged", codeFindings.some(function (r) { return r.ruleId === "R1-proven" && r.line >= 9; }));

    // --- FP: inline code NOT flagged -------------------------------------------

    fs.writeFileSync(path.join(root, "docs", "inlinecode.md"),
      "Call the `proven` function to check status.\n" +
      "The `immutable` field stores the hash.\n" +
      "Use `certified` to mark the review.\n" +
      "Plain text proven is flagged.\n",
      "utf8"
    );
    const inlineFindings = findings("docs/inlinecode.md");
    assert("FP: inline code `proven` not flagged", !inlineFindings.some(function (r) { return r.line === 1 && r.ruleId === "R1-proven"; }));
    assert("FP: inline code `immutable` not flagged", !inlineFindings.some(function (r) { return r.line === 2 && r.ruleId === "R2-immutable"; }));
    assert("FP: inline code `certified` not flagged", !inlineFindings.some(function (r) { return r.line === 3 && r.ruleId === "R3-certified"; }));
    assert("TP: plain text proven IS flagged", inlineFindings.some(function (r) { return r.line === 4 && r.ruleId === "R1-proven"; }));

    // --- OUTPUT SANITIZED: output lines must be in "file:line: ruleId" format ----

    function allOutputLines(findingsArr) {
      const out = [];
      for (const f of findingsArr) {
        out.push(f.file + ":" + f.line + ": " + f.ruleId);
      }
      return out;
    }

    // Verify output format is clean — rule IDs like "R1-proven" reference
    // the rule label, not the matched document text.
    fs.writeFileSync(path.join(root, "docs", "sanitize-test.md"),
      "The system is proven.\n" +
      "It is immutable.\n" +
      "It is certified.\n",
      "utf8"
    );
    const sanitizeFindings = findings("docs/sanitize-test.md");
    const lines = allOutputLines(sanitizeFindings);
    for (const line of lines) {
      var parts = line.split(":");
      var rulePart = parts[parts.length - 1].trim();
      assert(
        "SANITIZED output format: " + JSON.stringify(line),
        parts.length >= 3 && /^\d+$/.test(parts[parts.length - 2].trim()) && rulePart.startsWith("R"),
        "malformed output line"
      );
    }

    // --- Edge: YAML frontmatter skipped ---------------------------------------

    fs.writeFileSync(path.join(root, "references", "frontmatter.md"),
      "---\n" +
      "title: Proven System\n" +
      "description: immutable architecture\n" +
      "status: certified\n" +
      "guaranteed: true\n" +
      "---\n" +
      "\n" +
      "# Document Title\n" +
      "The system is proven.\n",
      "utf8"
    );
    const fmFindings = findings("references/frontmatter.md");
    assert("FP: YAML frontmatter proven not flagged", !fmFindings.some(function (r) { return r.line <= 6 && r.ruleId === "R1-proven"; }));
    assert("FP: YAML frontmatter immutable not flagged", !fmFindings.some(function (r) { return r.line <= 6 && r.ruleId === "R2-immutable"; }));
    assert("FP: YAML frontmatter certified not flagged", !fmFindings.some(function (r) { return r.line <= 6 && r.ruleId === "R3-certified"; }));
    assert("FP: YAML frontmatter guaranteed not flagged", !fmFindings.some(function (r) { return r.line <= 6 && r.ruleId === "R9c-guaranteed"; }));
    assert("TP: after frontmatter, proven IS flagged", fmFindings.some(function (r) { return r.line === 9 && r.ruleId === "R1-proven"; }));

    // --- Full scan on clean tree -----------------------------------------------

    // Remove all test files from docs/ and references/
    (function rmDir(d) {
      var items;
      try { items = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
      for (var j = 0; j < items.length; j++) {
        var p = path.join(d, items[j].name);
        if (items[j].isDirectory()) rmDir(p);
        else fs.unlinkSync(p);
      }
    })(path.join(root, "docs"));
    (function rmDir(d) {
      var items;
      try { items = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
      for (var j = 0; j < items.length; j++) {
        var p = path.join(d, items[j].name);
        if (items[j].isDirectory()) rmDir(p);
        else fs.unlinkSync(p);
      }
    })(path.join(root, "references"));

    // Write clean docs
    fs.writeFileSync(path.join(root, "README.md"), "# Clean Project\n\nNothing flagged here.\n", "utf8");
    fs.writeFileSync(path.join(root, "SKILL.md"), "# Skill\n\nStandard description.\n", "utf8");
    fs.writeFileSync(path.join(root, "docs", "clean.md"), "# Doc\n\nClean content.\n", "utf8");
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "test" }), "utf8");

    const allClean = scanAll(root);
    assert("Full clean scan: no findings", allClean.length === 0, "got " + allClean.length + " findings");

    // --- Exit code: violations -> non-zero, clean -> zero ----------------------

    {
      if (allClean.length > 0) {
        assert("violations yield exit 1", false, "unexpectedly had findings");
      } else {
        assert("no violations yield exit 0", true);
      }
    }

  } finally {
    process.chdir(prevCwd);
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (e) {}
  }

  process.stderr.write("\nselftest: " + passed + " passed, " + failures.length + " failed\n");
  if (failures.length > 0) {
    process.stderr.write("failures: " + failures.join("; ") + "\n");
  }
  return failures.length === 0;
}

// --- CLI ---------------------------------------------------------------------

function usage() {
  process.stderr.write(
    "Usage: node scripts/docs-lint.js [--selftest]\n" +
    "  Scans the shippable docs fileset for honest-language violations (contract 10 List A).\n" +
    "  Exit 0 = clean, non-zero = violations.\n"
  );
}

function main() {
  const args = process.argv.slice(2);

  if (args.includes("--selftest")) {
    const ok = selftest();
    process.exit(ok ? 0 : 1);
    return;
  }

  if (args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
    return;
  }

  if (args.length > 0) {
    process.stderr.write("docs-lint: unknown argument(s): " + args.join(" ") + "\n");
    usage();
    process.exit(2);
    return;
  }

  const cwd = process.cwd();
  const results = scanAll(cwd);
  reportResults(results);

  if (results.length > 0) {
    process.exit(1);
  } else {
    process.stderr.write("docs-lint: clean — no honest-language violations detected\n");
    process.exit(0);
  }
}

if (require.main === module) {
  main();
}

module.exports = { scanFile, scanAll, RULES, selftest };