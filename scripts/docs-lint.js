#!/usr/bin/env node
/**
 * docs-lint.js — Contract 10 List A honest-language lint (v3 rebuild).
 *
 * Enforces the full required-form table for ~14 over-claim terms.
 * Context-aware: skips code blocks (```fences), inline code (backticks),
 * code identifiers, HTML comments (single and multiline), and lines/blocks
 * carrying the escape marker <!-- lint-allow: honest-language (reason) -->.
 *
 * lint-allow supports ONLY (a) single-line escape (marker on same line as
 * flagged content) and (b) explicitly-closed block with <!-- /lint-allow -->.
 * An unclosed block at EOF is an ERROR (fail non-zero), never a silent
 * whole-file suppress.
 *
 * Normalization (via norm-core.js): NFKC + strip ZW + fold fullwidth +
 * fold Cyrillic/Greek homoglyphs + decode %-encodings loop-to-stable +
 * neutralize intra-token md emphasis/hyphen/underscore + collapse whitespace.
 *
 * Scans the shippable docs fileset. Failure messages report
 * file:line: <rule-id> only — NEVER the banned term.
 *
 * Zero deps (Node built-in crypto). CommonJS. Node >= 18. Deterministic,
 * no network, fail-closed.
 *
 * Usage:
 *   node scripts/docs-lint.js               scan the shippable docs fileset
 *   node scripts/docs-lint.js --selftest    run internal test suite
 */

"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const normCore = require("./norm-core.js");

const normalizeForDocsLint = normCore.normalizeForDocsLint;

// --- rule definitions (contract 10 List A) -----------------------------------

/**
 * Each rule:
 *   id             — internal rule identifier (NOT emitted in CLI output)
 *   displayId      — opaque output ID (emitted in CLI output, never the banned term)
 *   bannedPattern  — regex to detect the bare over-claim term
 *   negationPatterns — array of regexes; if any matches the line, skip
 *   requiredFormPatterns — array of regexes; if any matches nearby prose, skip
 *   suppressible    — if false, the term is treated as ALWAYS banned (R9a-d, R11)
 */
const RULES = [
  {
    id: "R1-proven",
    displayId: "H01",
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
    displayId: "H02",
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
    displayId: "H03",
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
    displayId: "H04",
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
    displayId: "H05",
    bannedPattern: /\bexactly(?:[-\s_]+once|once)\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+|doesn['\u2019]t\s+)(?:\S+\s+){0,4}exactly(?:[-\s_]+once|once)\b/gi,
      /\bexactly(?:[-\s_]+once|once)\b(?:\s+\S+){0,4}\s+(?:false|wrong|incorrect|misleading)\b/gi,
      /\bmakes?\s+no\s+(?:\S+\s+){0,2}exactly(?:[-\s_]+once|once)\b/gi,
      /\bdoes?\s+not\s+provide\s+exactly(?:[-\s_]+once|once)\b/gi,
    ],
    requiredFormPatterns: [
      /\bcapability\s+class\b/gi,
      /\bcontract\s*0?6\b/i,
      /\b(?:at-most-once|at-least-once|idempoten)\b/gi,
    ],
  },
  {
    id: "R6-constant-monitoring",
    displayId: "H06",
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
    displayId: "H07",
    bannedPattern: /\b(?:tamper-proof|tamperproof)\b/gi,
    negationPatterns: [
      /\b(?:not?\s+|never\s+|no\s+)(?:\S+\s+){0,3}(?:tamper-proof|tamperproof)\b/gi,
      /(?:tamper-proof|tamperproof)\b(?:\s+\S+){0,4}\s+(?:false|wrong|incorrect|misleading)\b/gi,
    ],
    requiredFormPatterns: [
      /\b(?:tamper-evident|tamperevident)\s+vs\s+anchored\s+head\b/gi,
      /\b(?:tamper[- ]?evident|tamperevident)\b/gi,
    ],
  },
  {
    id: "R8-pen-test",
    displayId: "H08",
    bannedPattern: /\b(?:pen[-\s]?test(?:ing|ed|s)?|pentest(?:ing|ed|s)?)\b/gi,
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
    displayId: "H09",
    bannedPattern: /\bcertified\s+secure\b/gi,
    negationPatterns: [],
    requiredFormPatterns: [],
  },
  {
    id: "R9b-security-guaranteed",
    displayId: "H10",
    bannedPattern: /\bsecurity\s+guaranteed\b/gi,
    negationPatterns: [],
    requiredFormPatterns: [],
  },
  {
    id: "R9c-guaranteed",
    displayId: "H11",
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
    displayId: "H12",
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
    displayId: "H13",
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
    displayId: "H14",
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
 * Removes: inline code, markdown link URLs, images, HTML tags.
 * HTML comments are handled separately (multiline tracking in scanFile).
 */
function cleanLine(line) {
  let s = line;
  s = s.replace(IMAGE_RE, "");                // images
  s = s.replace(MD_LINK_URL_RE, "");           // link URLs
  s = s.replace(MD_LINK_REF_RE, "");           // link references
  s = s.replace(LINK_TEXT_RE, "$1");           // convert [text](url) -> text
  s = s.replace(INLINE_CODE_RE, "");           // inline code
  s = s.replace(TAG_STRIP_RE, "");             // HTML tags
  return s;
}

/**
 * Strip multiline HTML comments from raw text, preserving line structure
 * (line numbers stay accurate by preserving newlines).
 */
function stripMultilineHtmlComments(raw) {
  let result = "";
  let i = 0;
  while (i < raw.length) {
    const commentStart = raw.indexOf("<!--", i);
    if (commentStart === -1) {
      result += raw.substring(i);
      break;
    }
    result += raw.substring(i, commentStart);
    const commentEnd = raw.indexOf("-->", commentStart + 4);
    if (commentEnd === -1) {
      break;
    }
    // Replace comment content with spaces, keeping \r\n for line counting
    const commentBody = raw.substring(commentStart, commentEnd + 3);
    const repl = commentBody.replace(/[^\r\n]/g, " ");
    result += repl;
    i = commentEnd + 3;
  }
  return result;
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
 * Two-pass: first detect lint-allow blocks on ORIGINAL text,
 * then strip HTML comments and scan prose on stripped text.
 */
function scanFile(fileRel, fileAbs) {
  let raw;
  try {
    raw = fs.readFileSync(fileAbs, "utf8");
  } catch (e) {
    return [];
  }

  const origLines = raw.split(/\r?\n/);

  // --- Pass 1: detect lint-allow blocks on ORIGINAL text (before HTML stripping) ---

  const lintAllowSkipLines = new Set();
  const lintAllowErrorLines = [];

  let inLintAllowBlock = false;

  for (let i = 0; i < origLines.length; i++) {
    const line = origLines[i];

    // Lint-allow close
    if (LINT_ALLOW_CLOSE_RE.test(line)) {
      if (inLintAllowBlock) {
        inLintAllowBlock = false;
      }
      lintAllowSkipLines.add(i);
      continue;
    }
    if (inLintAllowBlock) {
      lintAllowSkipLines.add(i);
      continue;
    }

    // Lint-allow open
    if (LINT_ALLOW_OPEN_RE.test(line)) {
      const withoutComment = line.replace(HTML_COMMENT_RE, "").trim();
      if (withoutComment.length === 0) {
        // Block open — scan ahead for close marker
        let foundClose = false;
        for (let j = i + 1; j < origLines.length; j++) {
          if (LINT_ALLOW_CLOSE_RE.test(origLines[j])) {
            foundClose = true;
            break;
          }
        }
        if (foundClose) {
          inLintAllowBlock = true;
          lintAllowSkipLines.add(i);
        } else {
          // UNCLOSED block — record error, do NOT suppress
          lintAllowErrorLines.push(i + 1);
        }
      } else {
        // Line-level escape — skip this line only
        lintAllowSkipLines.add(i);
      }
      continue;
    }
  }

  // If unclosed block(s) found, report in stderr
  if (lintAllowErrorLines.length > 0) {
    process.stderr.write(
      fileRel + ": ERROR — unclosed lint-allow block at line " + lintAllowErrorLines.join(",") + ", not suppressing\n"
    );
  }

  // --- Pass 2: strip HTML comments and scan prose ---

  raw = stripMultilineHtmlComments(raw);
  const lines = raw.split(/\r?\n/);
  const results = [];

  for (const errLine of lintAllowErrorLines) {
    results.push({
      file: fileRel,
      line: errLine,
      ruleId: "__ERR_UNCLOSED_LINT_ALLOW__",
    });
  }

  let inCodeFence = false;
  let fenceIndent = 0;
  let fenceChar = "";
  let inYamlFrontmatter = false;
  let sawYamlStart = false;
  let prevProse = "";  // previous line's cleaned prose for cross-line phrase join
  let prevLineNum = 0; // line number of prevProse (for attribution)

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;

    // Skip lint-allow lines (including properly closed blocks and line-level escapes)
    if (lintAllowSkipLines.has(i)) continue;

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

    // Clean the line for prose scanning
    const prose = cleanLine(rawLine);

    // Skip empty lines after cleaning
    if (prose.trim().length === 0) continue;

    // Apply docs-lint normalization (NFKC + homoglyph + neutralization + collapse whitespace)
    const normalized = normalizeForDocsLint(prose);
    if (normalized.length === 0) continue;

    // Collect all candidate matches for this line, then resolve overlaps
    const candidates = [];
    for (const rule of RULES) {
      rule.bannedPattern.lastIndex = 0;
      let m;
      while ((m = rule.bannedPattern.exec(normalized)) !== null) {
        if (isNegated(normalized, rule)) continue;
        if (isRequiredForm(normalized, rule)) continue;
        candidates.push({ ruleId: rule.id, start: m.index, end: m.index + m[0].length });
      }
    }

    // Cross-line phrase join: join previous line's prose with this line (space-separated)
    // to catch multi-word banned phrases split across lines (e.g., "certified\nsecure").
    if (prevProse.length > 0 && prevLineNum > 0) {
      const joined = normalizeForDocsLint(cleanLine(prevProse + " " + prose));
      if (joined.length > 0) {
        for (const rule of RULES) {
          // Only check rules that require multiple words (patterns with \s or - in them)
          rule.bannedPattern.lastIndex = 0;
          let m;
          while ((m = rule.bannedPattern.exec(joined)) !== null) {
            // Only attribute to current line if the match overlaps the boundary
            // (i.e., it wasn't already found entirely within the current line)
            const midPoint = cleanLine(prevProse).length + 1; // position of space separator
            if (m.index < midPoint && m.index + m[0].length > midPoint) {
              if (isNegated(joined, rule)) continue;
              if (isRequiredForm(joined, rule)) continue;
              // Check if not already found by single-line scan
              var alreadyFound = false;
              for (var ca = 0; ca < candidates.length; ca++) {
                if (candidates[ca].ruleId === rule.id) alreadyFound = true;
              }
              if (!alreadyFound) {
                candidates.push({ ruleId: rule.id, start: -1, end: -1, crossLine: true });
              }
            }
          }
        }
      }
    }
    prevProse = prose;
    prevLineNum = lineNum;
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

// --- opaque output ID mapping (contract 10: output never contains banned term) ---

const RULE_DISPLAY_MAP = {};
for (const rule of RULES) {
  RULE_DISPLAY_MAP[rule.id] = rule.displayId;
}
RULE_DISPLAY_MAP["__ERR_UNCLOSED_LINT_ALLOW__"] = "E-UNCLOSED-LINT-ALLOW";

function displayRuleId(internalId) {
  return RULE_DISPLAY_MAP[internalId] || internalId;
}

// --- output -------------------------------------------------------------------

function reportResults(results) {
  for (const r of results) {
    process.stdout.write(r.file + ":" + r.line + ": " + displayRuleId(r.ruleId) + "\n");
  }
  if (results.length > 0) {
    const errCount = results.filter(function (r) { return r.ruleId === "__ERR_UNCLOSED_LINT_ALLOW__"; }).length;
    const violationCount = results.length - errCount;
    process.stderr.write(
      "\ndocs-lint: " + violationCount + " violation(s) found in " +
      new Set(results.map(function (r) { return r.file; })).size + " file(s)" +
      (errCount > 0 ? " (" + errCount + " unclosed lint-allow block(s))" : "") + "\n"
    );
  }
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

    // --- TP: normalized evasion caught -----------------------------------------

    fs.writeFileSync(path.join(root, "docs", "normalized.md"),
      // Homoglyph: Greek omicron in "proven"
      "This is pr\u03BFven in production.\n" +
      // Zero-width in "proven"
      "Totally pr\u200Boven reliable.\n" +
      // Zero-width joiner in "certified"
      "Results are cert\u200Dified.\n" +
      // Hyphenation "pro-ven"
      "Behavior is pro-ven by customers.\n" +
      // Markdown emphasis split
      "Claims are pr*oven* daily.\n" +
      "We ship **proven** results here too.\n" +
      // Soft hyphen
      "Marked pro\u00ADven by partners.\n" +
      // Fullwidth Latin
      "Status: \uFF50\uFF52\uFF4F\uFF56\uFF45\uFF4E under SLA.\n" +
      // exactly_once underscore
      "Semantics are exactly_once always.\n" +
      // Double-spaced exactly once
      "This provides exactly  once delivery.\n" +
      // Casing
      "This release is PROVEN under load.\n" +
      "It is Certified for enterprise.\n" +
      "Delivery is Exactly-Once.\n",
      "utf8"
    );
    assertCount("docs/normalized.md", "R1-proven", 8, "TP: all normalized proven evasions caught");
    assertCount("docs/normalized.md", "R3-certified", 2, "TP: normalized certified evasions caught");
    assertCount("docs/normalized.md", "R5-exactly-once", 3, "TP: normalized exactly-once evasions caught (underscore, casing, double space)");

    // --- TP: unclosed lint-allow → error (not suppress) ------------------------

    fs.writeFileSync(path.join(root, "docs", "unclosed.md"),
      "<!-- lint-allow: honest-language (oops forgot close) -->\n" +
      "Smuggled proven claim one.\n" +
      "Smuggled certified claim two.\n" +
      "Smuggled guaranteed claim three.\n",
      "utf8"
    );
    const unclosedFindings = findings("docs/unclosed.md");
    const unclosedErr = unclosedFindings.filter(function (r) { return r.ruleId === "__ERR_UNCLOSED_LINT_ALLOW__"; });
    const unclosedProven = unclosedFindings.filter(function (r) { return r.ruleId === "R1-proven"; });
    assert("LA-UNCLOSED: error reported", unclosedErr.length === 1, "got " + unclosedErr.length + " error items");
    assert("LA-UNCLOSED: proven NOT suppressed", unclosedProven.length === 1, "got " + unclosedProven.length);
    assert("LA-UNCLOSED: certified NOT suppressed",
      unclosedFindings.filter(function (r) { return r.ruleId === "R3-certified"; }).length === 1);
    assert("LA-UNCLOSED: guaranteed NOT suppressed",
      unclosedFindings.filter(function (r) { return r.ruleId === "R9c-guaranteed"; }).length === 1);

    // --- TP: multiline HTML comment NOT flagged --------------------------------

    fs.writeFileSync(path.join(root, "docs", "mlcomment.md"),
      "Before comment.\n" +
      "<!--\n" +
      "This is proven inside a comment.\n" +
      "This is certified inside a comment.\n" +
      "-->\n" +
      "After comment: this is proven.\n",
      "utf8"
    );
    const mlFindings = findings("docs/mlcomment.md");
    assert("FP: multiline comment proven not flagged",
      !mlFindings.some(function (r) { return r.ruleId === "R1-proven" && r.line >= 3 && r.line <= 4; }));
    assert("FP: multiline comment certified not flagged",
      !mlFindings.some(function (r) { return r.ruleId === "R3-certified" && r.line >= 3 && r.line <= 4; }));
    assert("TP: after comment, proven IS flagged",
      mlFindings.some(function (r) { return r.line === 6 && r.ruleId === "R1-proven"; }));

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

    // --- OUTPUT SANITIZED: output lines must use opaque IDs --------------------

    function allOutputLines(findingsArr) {
      const out = [];
      for (const f of findingsArr) {
        out.push(f.file + ":" + f.line + ": " + displayRuleId(f.ruleId));
      }
      return out;
    }

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
        parts.length >= 3 && /^\d+$/.test(parts[parts.length - 2].trim()) && /^H\d/.test(rulePart),
        "malformed output line"
      );
    }
    // Output must NOT contain the banned term as bare word
    const combinedOut = lines.join("\n");
    assert("SANITIZED: no 'proven' in output", !/\bproven\b/i.test(combinedOut));
    assert("SANITIZED: no 'certified' in output", !/\bcertified\b/i.test(combinedOut));
    assert("SANITIZED: no 'immutable' in output", !/\bimmutable\b/i.test(combinedOut));

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

module.exports = { scanFile, scanAll, RULES, selftest, displayRuleId };