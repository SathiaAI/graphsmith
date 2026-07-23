#!/usr/bin/env node
"use strict";
/**
 * ADVERSARIAL TESTER (≠ DeepSeek builder) — family: grok
 * Target: scripts/docs-lint.js (List A) + scripts/hygiene-scan.js (List B)
 * Lane: tests/banned-lint/grok/ only. Temp fixtures. Zero-dep CJS.
 * Exit 1 if any attack SUCCEEDS against a guarantee that must hold,
 * or if a structural contract check fails.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const REPO = path.resolve(__dirname, "..", "..", "..");
const DOCS_LINT = path.join(REPO, "scripts", "docs-lint.js");
const HYGIENE = path.join(REPO, "scripts", "hygiene-scan.js");
const CI_YML = path.join(REPO, ".github", "workflows", "ci.yml");
const BANNED_PATH_REL = ".plans/hygiene/banned-identifiers.txt";

const docsLint = require(DOCS_LINT);
const hygiene = require(HYGIENE);

const results = [];
const findings = [];
const temps = [];

function record(status, name, detail) {
  const d = detail == null ? "" : String(detail).replace(/\s+/g, " ").trim().slice(0, 320);
  results.push({ status: status, name: name, detail: d });
  console.log(status + "\t" + name + (d ? "\t" + d : ""));
}
function pass(n, d) { record("PASS", n, d); }
function fail(n, d) { record("FAIL", n, d); }
function noteFinding(id, severity, summary) {
  findings.push({ id: id, severity: severity, summary: summary });
}

function mk(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gs-banlint-grok-" + tag + "-"));
  temps.push(root);
  return root;
}
function rmAll() {
  for (var i = 0; i < temps.length; i++) {
    try { fs.rmSync(temps[i], { recursive: true, force: true }); } catch (_) {}
  }
}
function writeTree(root, files) {
  var keys = Object.keys(files);
  for (var i = 0; i < keys.length; i++) {
    var rel = keys[i];
    var abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, files[rel], "utf8");
  }
}
function ruleHits(findingsArr, ruleId) {
  return findingsArr.filter(function (r) { return r.ruleId === ruleId; });
}
function anyRule(findingsArr) {
  return findingsArr && findingsArr.length > 0;
}

function spawnNode(scriptAbs, args, opts) {
  opts = opts || {};
  var env = Object.assign({}, process.env, opts.env || {});
  // Drop secrets unless explicitly set so CI-mode tests are deterministic.
  if (!opts.keepHygieneEnv) {
    delete env.HYGIENE_HMAC_KEY;
    delete env.HYGIENE_DIGESTS;
  }
  if (opts.env) {
    Object.keys(opts.env).forEach(function (k) {
      if (opts.env[k] === null || opts.env[k] === undefined) delete env[k];
      else env[k] = opts.env[k];
    });
  }
  return spawnSync(process.execPath, [scriptAbs].concat(args || []), {
    cwd: opts.cwd || REPO,
    encoding: "utf8",
    timeout: opts.timeout || 20000,
    maxBuffer: 2 * 1024 * 1024,
    env: env,
  });
}

function captureReportDocs(root) {
  // Drive scanFile directly for controlled fixtures; also probe CLI output shape.
  return docsLint.scanAll(root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. FALSE-NEGATIVE — docs-lint over-claim evasion
// ═══════════════════════════════════════════════════════════════════════════

function attackFalseNegatives() {
  const root = mk("fn");
  writeTree(root, {
    "README.md": [
      // A1 casing
      "This release is PROVEN under load.",
      "It is Certified for enterprise.",
      "Delivery is Exactly-Once.",
      // A2 unicode homoglyph (Greek omicron U+03BF in "proven")
      "This is pr\u03BFven in production.",
      // A3 zero-width joiner/space inside term
      "Totally pr\u200Boven reliable.",
      "Results are cert\u200Dified.",
      // A4 hyphenation split
      "Behavior is pro-ven by customers.",
      // A5 markdown emphasis splitting the token
      "Claims are pr*oven* daily.",
      "We ship **proven** results here too.", // should still match
      // A6 line-wrap across newline — two lines form the phrase when joined
      "The pipeline is pro",
      "ven for critical paths.",
      // A7 soft hyphen
      "Marked pro\u00ADven by partners.",
      // A8 fullwidth latin
      "Status: \uFF50\uFF52\uFF4F\uFF56\uFF45\uFF4E under SLA.",
      // A9 exactly_once underscore form
      "Semantics are exactly_once always.",
      // A10 bare multi-word always-banned compounds
      "Platform is certified secure.",
      "Offer is security guaranteed.",
    ].join("\n") + "\n",
  });

  const hits = docsLint.scanFile("README.md", path.join(root, "README.md"));

  // Casing should be caught (gi flag)
  if (ruleHits(hits, "R1-proven").some(function (h) { return h.line === 1; })) {
    pass("FN/casing-PROVEN", "caught line 1");
  } else {
    fail("FN/casing-PROVEN", "PROVEN not flagged");
    noteFinding("FN-CASE", "HIGH", "docs-lint missed case-variant PROVEN");
  }
  if (ruleHits(hits, "R3-certified").some(function (h) { return h.line === 2; })) {
    pass("FN/casing-Certified", "caught line 2");
  } else {
    fail("FN/casing-Certified", "Certified not flagged");
    noteFinding("FN-CASE-CERT", "HIGH", "docs-lint missed Certified casing");
  }
  if (ruleHits(hits, "R5-exactly-once").some(function (h) { return h.line === 3; })) {
    pass("FN/casing-Exactly-Once", "caught line 3");
  } else {
    fail("FN/casing-Exactly-Once", "Exactly-Once not flagged");
    noteFinding("FN-CASE-EO", "HIGH", "docs-lint missed Exactly-Once casing");
  }

  // Homoglyph Greek omicron — several engines miss without NFKC/confusable
  if (ruleHits(hits, "R1-proven").some(function (h) { return h.line === 4; })) {
    pass("FN/homoglyph-greek-omicron", "caught prοven");
  } else {
    fail("FN/homoglyph-greek-omicron", "pr\\u03BFven slipped past");
    noteFinding(
      "FN-HOMOGLYPH",
      "HIGH",
      "docs-lint has no NFKC/confusable fold; Greek-omicron 'prοven' is a bare over-claim false-negative"
    );
  }

  // Zero-width inside term
  if (ruleHits(hits, "R1-proven").some(function (h) { return h.line === 5; })) {
    pass("FN/zwsp-proven", "caught pr\\u200Boven");
  } else {
    fail("FN/zwsp-proven", "zero-width-split proven not flagged");
    noteFinding(
      "FN-ZWSP",
      "HIGH",
      "docs-lint does not strip ZW chars before match; pr\\u200Boven / cert\\u200Dified evade"
    );
  }
  if (ruleHits(hits, "R3-certified").some(function (h) { return h.line === 6; })) {
    pass("FN/zwj-certified", "caught cert\\u200Dified");
  } else {
    fail("FN/zwj-certified", "ZWJ-split certified not flagged");
    // consolidated into FN-ZWSP if not already
    if (!findings.some(function (f) { return f.id === "FN-ZWSP"; })) {
      noteFinding("FN-ZWJ", "HIGH", "docs-lint misses ZWJ-split certified");
    }
  }

  // Hyphenation pro-ven
  if (ruleHits(hits, "R1-proven").some(function (h) { return h.line === 7; })) {
    pass("FN/hyphen-pro-ven", "caught pro-ven");
  } else {
    fail("FN/hyphen-pro-ven", "hyphenated pro-ven not flagged");
    noteFinding(
      "FN-HYPHEN",
      "MEDIUM",
      "docs-lint \\bproven\\b misses hyphenation evasion 'pro-ven'"
    );
  }

  // Markdown emphasis split pr*oven*
  if (ruleHits(hits, "R1-proven").some(function (h) { return h.line === 8; })) {
    pass("FN/md-split-pr*oven*", "caught emphasis-split");
  } else {
    fail("FN/md-split-pr*oven*", "pr*oven* not flagged");
    noteFinding(
      "FN-MD-SPLIT",
      "MEDIUM",
      "docs-lint cleanLine does not strip md emphasis markers; pr*oven* / similar splits evade"
    );
  }

  // **proven** should still match (word body intact)
  if (ruleHits(hits, "R1-proven").some(function (h) { return h.line === 9; })) {
    pass("FN/md-bold-proven-intact", "caught **proven**");
  } else {
    fail("FN/md-bold-proven-intact", "**proven** not flagged");
    noteFinding("FN-MD-BOLD", "HIGH", "docs-lint missed **proven** which still contains the bare term");
  }

  // Line-wrap: "pro" + "\n" + "ven..."
  if (ruleHits(hits, "R1-proven").some(function (h) { return h.line === 10 || h.line === 11; })) {
    pass("FN/linewrap-proven", "caught cross-line");
  } else {
    fail("FN/linewrap-proven", "line-wrapped pro/ven not flagged");
    noteFinding(
      "FN-LINEWRAP",
      "LOW",
      "docs-lint is strictly line-local; wrapping a banned token across a newline is a known evasion"
    );
  }

  // Soft hyphen
  if (ruleHits(hits, "R1-proven").some(function (h) { return h.line === 12; })) {
    pass("FN/softhyphen-proven", "caught soft-hyphen proven");
  } else {
    fail("FN/softhyphen-proven", "soft-hyphen pro\\u00ADven slipped");
    noteFinding(
      "FN-SOFT-HYPHEN",
      "MEDIUM",
      "docs-lint does not strip U+00AD soft hyphen before match"
    );
  }

  // Fullwidth
  if (ruleHits(hits, "R1-proven").some(function (h) { return h.line === 13; })) {
    pass("FN/fullwidth-proven", "caught fullwidth proven");
  } else {
    fail("FN/fullwidth-proven", "fullwidth proven slipped");
    noteFinding(
      "FN-FULLWIDTH",
      "HIGH",
      "docs-lint does not NFKC-fold fullwidth Latin; fullwidth 'proven' is a bare over-claim false-negative"
    );
  }

  // exactly_once underscore
  if (ruleHits(hits, "R5-exactly-once").some(function (h) { return h.line === 14; })) {
    pass("FN/underscore-exactly_once", "caught exactly_once");
  } else {
    fail("FN/underscore-exactly_once", "exactly_once not flagged");
    noteFinding(
      "FN-UNDERSCORE-EO",
      "MEDIUM",
      "R5 pattern is exactly[-\\s]once only; exactly_once underscores evade"
    );
  }

  // Always-banned compounds still fire
  if (ruleHits(hits, "R9a-certified-secure").length > 0) {
    pass("FN/compound-certified-secure", "caught");
  } else {
    fail("FN/compound-certified-secure", "missed");
    noteFinding("FN-R9A", "HIGH", "R9a certified secure not flagged");
  }
  if (ruleHits(hits, "R9b-security-guaranteed").length > 0) {
    pass("FN/compound-security-guaranteed", "caught");
  } else {
    fail("FN/compound-security-guaranteed", "missed");
    noteFinding("FN-R9B", "HIGH", "R9b security guaranteed not flagged");
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. LINT-ALLOW ABUSE — scope leakage
// ═══════════════════════════════════════════════════════════════════════════

function attackLintAllow() {
  const root = mk("la");

  // Line-level: marker on line 1 only must NOT free line 2
  writeTree(root, {
    "docs/line-scope.md":
      "System is proven. <!-- lint-allow: honest-language (demo) -->\n" +
      "Also certified without marker.\n",
  });
  var hits = docsLint.scanFile("docs/line-scope.md", path.join(root, "docs/line-scope.md"));
  if (!hits.some(function (h) { return h.line === 1 && h.ruleId === "R1-proven"; })) {
    pass("LA/line-escapes-own-line", "line 1 not flagged");
  } else {
    fail("LA/line-escapes-own-line", "line-level allow failed to escape own line");
  }
  if (hits.some(function (h) { return h.line === 2 && h.ruleId === "R3-certified"; })) {
    pass("LA/line-does-not-bleed", "line 2 still flagged");
  } else {
    fail("LA/line-does-not-bleed", "line-level allow bled to next line");
    noteFinding("LA-LINE-BLEED", "HIGH", "lint-allow on line N suppressed line N+1");
  }

  // Properly closed block — content inside free, after not free
  writeTree(root, {
    "docs/block-ok.md":
      "Before: this is guaranteed.\n" +
      "<!-- lint-allow: honest-language (block) -->\n" +
      "Inside proven claim.\n" +
      "<!-- /lint-allow -->\n" +
      "After: this is proven.\n",
  });
  hits = docsLint.scanFile("docs/block-ok.md", path.join(root, "docs/block-ok.md"));
  var inside = hits.filter(function (h) { return h.line === 3; });
  var after = hits.filter(function (h) { return h.line === 5 && h.ruleId === "R1-proven"; });
  var before = hits.filter(function (h) { return h.line === 1 && h.ruleId === "R9c-guaranteed"; });
  if (inside.length === 0 && after.length > 0 && before.length > 0) {
    pass("LA/block-closed-scope", "before+after flagged, inside free");
  } else {
    fail(
      "LA/block-closed-scope",
      "before=" + before.length + " inside=" + inside.length + " after=" + after.length
    );
    noteFinding("LA-BLOCK-SCOPE", "HIGH", "closed lint-allow block scope incorrect");
  }

  // Abuse: open marker alone with NO close → rest of file free (scope over-reach)
  writeTree(root, {
    "docs/unclosed.md":
      "<!-- lint-allow: honest-language (oops forgot close) -->\n" +
      "Smuggled proven claim one.\n" +
      "Smuggled certified claim two.\n" +
      "Smuggled guaranteed claim three.\n",
  });
  hits = docsLint.scanFile("docs/unclosed.md", path.join(root, "docs/unclosed.md"));
  if (hits.length === 0) {
    fail("LA/unclosed-disables-rest-of-file", "0 hits — unclosed open marker whitelisted entire file");
    noteFinding(
      "LA-UNCLOSED",
      "HIGH",
      "docs-lint: a lone <!-- lint-allow: honest-language ... --> with no <!-- /lint-allow --> sets inLintAllowBlock=true forever; rest of file is silently suppressed"
    );
  } else {
    pass("LA/unclosed-disables-rest-of-file", "still flagged " + hits.length + " (fail-closed on unclosed)");
  }

  // Abuse: marker misspelling / wrong channel should NOT escape
  writeTree(root, {
    "docs/wrong-marker.md":
      "This is proven. <!-- lint-allow: something-else (nope) -->\n" +
      "<!-- lint-allow:honest-language -->this is certified too\n",
  });
  hits = docsLint.scanFile("docs/wrong-marker.md", path.join(root, "docs/wrong-marker.md"));
  // first line wrong channel: proven MUST still flag (comment strips, proven remains)
  if (hits.some(function (h) { return h.line === 1 && h.ruleId === "R1-proven"; })) {
    pass("LA/wrong-channel-no-escape", "wrong channel did not free proven");
  } else {
    // Implementation: LINT_ALLOW_OPEN_RE is honest-language only; wrong channel comment is stripped by cleanLine, proven remains → should flag. If not, defect.
    fail("LA/wrong-channel-no-escape", "proven on wrong-channel line not flagged: " + JSON.stringify(hits));
  }

  // Stray close without open must not poison later scanning
  writeTree(root, {
    "docs/stray-close.md":
      "<!-- /lint-allow -->\n" +
      "This is proven anyway.\n",
  });
  hits = docsLint.scanFile("docs/stray-close.md", path.join(root, "docs/stray-close.md"));
  if (hits.some(function (h) { return h.ruleId === "R1-proven"; })) {
    pass("LA/stray-close-harmless", "proven still caught after stray close");
  } else {
    fail("LA/stray-close-harmless", "stray close broke detection");
    noteFinding("LA-STRAY-CLOSE", "MEDIUM", "stray /lint-allow prevented later detection");
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. TERM-LEAK — output must never quote banned term / raw identifier
// ═══════════════════════════════════════════════════════════════════════════

function attackTermLeak() {
  const root = mk("tl");
  const CANARY = "ZXQ_UNIQUE_CANARY_9173_SHOULD_NEVER_ECHO";
  const BANNED_ID = "acme-skunkworks-omega-7741";
  writeTree(root, {
    "README.md":
      "Preface " + CANARY + " says the engine is proven beyond debate.\n" +
      "Also mentions " + BANNED_ID + " in plain sight.\n",
    "docs/x.md": "plain.\n",
    ".plans/hygiene/banned-identifiers.txt":
      "# test\n" + BANNED_ID + "\n",
  });

  // docs-lint CLI report must not echo canary prose or the bare word from source beyond rule-id constraint check
  var child = spawnNode(DOCS_LINT, [], { cwd: root });
  var out = (child.stdout || "") + (child.stderr || "");
  if (out.indexOf(CANARY) !== -1) {
    fail("TL/docs-lint-no-source-canary", "stdout/err echoed unique source canary");
    noteFinding("TL-CANARY", "CRITICAL", "docs-lint echoed surrounding source prose (canary) in output");
  } else {
    pass("TL/docs-lint-no-source-canary", "canary absent from output");
  }

  // Contract 10 governance: "Failure messages never quote the banned term."
  // Rule ids currently embed the term (R1-proven). Attack: does default CLI
  // output contain the bare banned English word as a standalone token beyond
  // rule-id suffix, OR does it embed it in rule-id (governance gray zone).
  var embedsInRuleId = /R\d+[a-z]?-proven\b/i.test(out);
  var bareInMsg = /(^|[^A-Za-z0-9-])proven([^A-Za-z0-9-]|$)/i.test(out.replace(/R\d+[a-z]?-proven/gi, "R#"));
  if (bareInMsg) {
    fail("TL/docs-lint-no-bare-term", "bare term leaked outside rule-id");
    noteFinding("TL-BARE", "CRITICAL", "docs-lint printed bare banned term outside rule-id format");
  } else {
    pass("TL/docs-lint-no-bare-term", "no bare term outside rule-id");
  }
  if (embedsInRuleId) {
    // Soft governance conflict: contract says never quote; implementation labels with term.
    fail("TL/docs-lint-ruleid-embeds-term", "output rule-id contains banned term (e.g. R1-proven)");
    noteFinding(
      "TL-RULEID",
      "MEDIUM",
      "docs-lint rule ids embed List A terms (R1-proven, R3-certified, …); contract 10 governance: 'Failure messages never quote the banned term'"
    );
  } else {
    pass("TL/docs-lint-ruleid-embeds-term", "rule ids do not embed List A terms");
  }

  // hygiene local mode must never echo the identifier
  child = spawnNode(HYGIENE, [], { cwd: root });
  out = (child.stdout || "") + (child.stderr || "");
  if (out.toLowerCase().indexOf(BANNED_ID.toLowerCase()) !== -1) {
    fail("TL/hygiene-local-no-echo", "local mode echoed raw identifier");
    noteFinding("TL-HYG-LOCAL", "CRITICAL", "hygiene-scan local mode echoed banned identifier");
  } else {
    pass("TL/hygiene-local-no-echo", "identifier absent; exit=" + child.status);
  }
  // Should still detect and fail non-zero
  if (child.status !== 0) {
    pass("TL/hygiene-local-flags", "exit=" + child.status);
  } else {
    fail("TL/hygiene-local-flags", "expected non-zero on planted id");
    noteFinding("TL-HYG-DETECT", "HIGH", "hygiene-scan local did not fail on planted identifier");
  }

  // hygiene CI mode report must not echo identifier
  var key = "grok-adversarial-key-does-not-ship";
  var norm = hygiene.normalize(BANNED_ID);
  var dig = hygiene.hmacDigest(key, norm);
  child = spawnNode(HYGIENE, ["--ci"], {
    cwd: root,
    keepHygieneEnv: true,
    env: {
      HYGIENE_HMAC_KEY: key,
      HYGIENE_DIGESTS: dig,
    },
  });
  out = (child.stdout || "") + (child.stderr || "");
  if (out.toLowerCase().indexOf(BANNED_ID.toLowerCase()) !== -1) {
    fail("TL/hygiene-ci-no-echo", "CI mode echoed identifier");
    noteFinding("TL-HYG-CI", "CRITICAL", "hygiene-scan --ci echoed banned identifier");
  } else {
    pass("TL/hygiene-ci-no-echo", "identifier absent; exit=" + child.status);
  }
  if (child.status !== 0) {
    pass("TL/hygiene-ci-flags", "exit=" + child.status);
  } else {
    fail("TL/hygiene-ci-flags", "expected non-zero on HMAC match");
    noteFinding("TL-HYG-CI-DETECT", "HIGH", "hygiene-scan --ci missed HMAC match");
  }
  // Error path when key missing must still not invent an identifier leak
  child = spawnNode(HYGIENE, ["--ci"], {
    cwd: root,
    env: { HYGIENE_HMAC_KEY: null, HYGIENE_DIGESTS: null },
  });
  out = (child.stdout || "") + (child.stderr || "");
  if (out.toLowerCase().indexOf(BANNED_ID.toLowerCase()) !== -1) {
    fail("TL/hygiene-ci-err-no-echo", "missing-secret error path echoed id");
    noteFinding("TL-HYG-ERR", "CRITICAL", "CI error path echoed identifier");
  } else {
    pass("TL/hygiene-ci-err-no-echo", "clean error path");
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. HYGIENE HMAC SOUNDNESS
// ═══════════════════════════════════════════════════════════════════════════

function attackHygieneSoundness() {
  // 4a. Repo ships NO cleartext list and NO digests in tracked shippable paths
  var shipProbe = spawnSync(
    process.execPath,
    [
      "-e",
      "var fs=require('fs');var path=require('path');" +
        "function walk(d,acc){var es;try{es=fs.readdirSync(d,{withFileTypes:true});}catch(e){return;}" +
        "for(var i=0;i<es.length;i++){var p=path.join(d,es[i].name);var rel=path.relative(process.cwd(),p).replace(/\\\\/g,'/');" +
        "if(rel==='.git'||rel.indexOf('.git/')===0||rel==='node_modules'||rel.indexOf('node_modules/')===0||rel.indexOf('tests/')===0||rel.indexOf('.plans/')===0)continue;" +
        "if(es[i].isDirectory())walk(p,acc);else if(es[i].isFile())acc.push(rel);}}" +
        "var files=[];walk('.',files);console.log(files.join('\\n'));",
    ],
    { cwd: REPO, encoding: "utf8", timeout: 30000, maxBuffer: 8 * 1024 * 1024 }
  );
  var trackedish = (shipProbe.stdout || "").split(/\r?\n/).filter(Boolean);
  var cleartextHit = null;
  var digestHit = null;
  for (var i = 0; i < trackedish.length; i++) {
    var rel = trackedish[i];
    var base = path.basename(rel).toLowerCase();
    if (base === "banned-identifiers.txt" || base === "banned-strings.json") {
      cleartextHit = rel;
    }
    // Flag any committed file whose sole job looks like a digest bank
    if (/hygiene.*digest/i.test(rel) || /digest.*hygiene/i.test(rel)) {
      digestHit = rel;
    }
  }
  if (!cleartextHit) {
    pass("HY/no-cleartext-list-in-shippable", "no banned-identifiers.txt outside .plans/");
  } else {
    fail("HY/no-cleartext-list-in-shippable", "found " + cleartextHit);
    noteFinding("HY-CLEARTEXT", "CRITICAL", "repo ships cleartext banned list at " + cleartextHit);
  }
  if (!digestHit) {
    pass("HY/no-digest-bank-in-repo", "no hygiene digest artifact path found");
  } else {
    fail("HY/no-digest-bank-in-repo", "found " + digestHit);
    noteFinding("HY-DIGEST-SHIP", "CRITICAL", "repo ships hygiene digests at " + digestHit);
  }

  // Placeholder private list exists only under git-ignored .plans (when present)
  // and must be comments-only / empty of secret-looking digests of real product names.
  var localListAbs = path.join(REPO, ".plans", "hygiene", "banned-identifiers.txt");
  if (fs.existsSync(localListAbs)) {
    var localBody = fs.readFileSync(localListAbs, "utf8");
    var liveIds = localBody.split(/\r?\n/).filter(function (l) {
      return l.trim() && l.trim().charAt(0) !== "#";
    });
    pass("HY/local-list-present-plans", "lines_non_comment=" + liveIds.length);
  } else {
    pass("HY/local-list-absent-ok", "maintainer may not have created list yet");
  }

  // 4b. HMAC is keyed, not plain/unsalted hash
  var keyA = "key-alpha";
  var keyB = "key-beta";
  var payload = hygiene.normalize("secret-project-zeta");
  var hA = hygiene.hmacDigest(keyA, payload);
  var hB = hygiene.hmacDigest(keyB, payload);
  var plain = crypto.createHash("sha256").update(payload, "utf8").digest("hex");
  if (hA !== hB) {
    pass("HY/hmac-key-dependent", "different keys → different digests");
  } else {
    fail("HY/hmac-key-dependent", "digest ignores key");
    noteFinding("HY-HMAC-KEY", "CRITICAL", "hygiene digest not key-dependent");
  }
  if (hA !== plain && hB !== plain) {
    pass("HY/not-unsalted-sha256", "HMAC ≠ plain sha256(payload)");
  } else {
    fail("HY/not-unsalted-sha256", "digest equals unsalted sha256");
    noteFinding("HY-UNSALTED", "CRITICAL", "hygiene digest is unsalted sha256, violates contract 10");
  }
  // Source uses createHmac
  var src = fs.readFileSync(HYGIENE, "utf8");
  if (/createHmac\s*\(\s*["']sha256["']/.test(src)) {
    pass("HY/source-createHmac-sha256", "createHmac('sha256') present");
  } else {
    fail("HY/source-createHmac-sha256", "createHmac sha256 not found in source");
    noteFinding("HY-SRC-HMAC", "CRITICAL", "hygiene-scan.js missing createHmacsha256");
  }
  if (/createHash\s*\(\s*["']sha256["']\s*\)\s*\.update/.test(src) && !/createHmac/.test(src)) {
    fail("HY/no-plain-hash-path", "plain createHash path without HMAC");
    noteFinding("HY-PLAIN-HASH", "CRITICAL", "hygiene-scan uses plain hash path");
  } else {
    pass("HY/no-plain-hash-path", "HMAC path dominates");
  }

  // 4c. Local mode reads BANNED_IDENTIFIERS_PATH and matches after normalize
  var root = mk("hy");
  writeTree(root, {
    ".plans/hygiene/banned-identifiers.txt": "Internal-Codename-Quokka\n",
    "README.md": "References internal codename quokka in docs.\n",
    "docs/ok.md": "harmless\n",
  });
  var ids = ["internalcodenamequokka"]; // normalized form we expect loaders produce
  // Prefer calling exported scanLocal after loading like the script does
  var loaded = (function load() {
    // Reimplement load via normalize of file lines (same contract as script)
    var raw = fs.readFileSync(path.join(root, BANNED_PATH_REL), "utf8");
    return raw.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) {
      return l && l.charAt(0) !== "#";
    }).map(function (l) { return hygiene.normalize(l); }).filter(Boolean);
  })();
  if (loaded.length === 1 && loaded[0] === "internalcodenamequokka") {
    pass("HY/local-normalize-load", "loaded normalized id");
  } else {
    fail("HY/local-normalize-load", "got " + JSON.stringify(loaded));
  }
  var localHits = hygiene.scanLocal(root, loaded);
  if (localHits.some(function (h) { return h.file === "README.md"; })) {
    pass("HY/local-planted-hit", JSON.stringify(localHits[0]));
  } else {
    fail("HY/local-planted-hit", "missed planted identifier");
    noteFinding("HY-LOCAL-MISS", "HIGH", "scanLocal missed normalized identifier in README");
  }
  // Never echo in structured result
  var leaked = JSON.stringify(localHits).toLowerCase().indexOf("quokka") !== -1;
  if (!leaked) {
    pass("HY/local-result-no-echo", "result objects id-free");
  } else {
    fail("HY/local-result-no-echo", "result JSON contains identifier fragment");
    noteFinding("HY-RESULT-ECHO", "CRITICAL", "scanLocal result embeds identifier text");
  }

  // 4d. Evasion vs NFKC+confusable normalization (contents + filenames)
  function expectMatch(label, bannedWrite, proseWrite) {
    var r = mk("ev");
    writeTree(r, {
      ".plans/hygiene/banned-identifiers.txt": bannedWrite + "\n",
      "README.md": proseWrite + "\n",
    });
    var ld = fs.readFileSync(path.join(r, BANNED_PATH_REL), "utf8")
      .split(/\r?\n/).map(function (l) { return l.trim(); })
      .filter(function (l) { return l && l.charAt(0) !== "#"; })
      .map(hygiene.normalize).filter(Boolean);
    var hs = hygiene.scanLocal(r, ld);
    if (hs.length > 0) {
      pass(label, "hit " + hs[0].file + ":" + hs[0].line);
      return true;
    }
    fail(label, "evasion succeeded (0 hits)");
    return false;
  }

  if (!expectMatch(
    "HY/evasion-fullwidth",
    "projectx",
    "see \uFF50\uFF52\uFF4F\uFF4A\uFF45\uFF43\uFF54\uFF58"
  )) {
    noteFinding("HY-EV-FULLWIDTH", "HIGH", "fullwidth content evasion beat local scan");
  }
  if (!expectMatch(
    "HY/evasion-zw",
    "projectx",
    "see p\u200Br\u200Co\u200Dj\u200Be\u200Fc\uFEFFt\u200Bx"
  )) {
    noteFinding("HY-EV-ZW", "HIGH", "zero-width content evasion beat local scan");
  }
  if (!expectMatch(
    "HY/evasion-percent",
    "projectx",
    "see project%78"
  )) {
    // project%78 → projectx after decode
    noteFinding("HY-EV-PCT", "HIGH", "%-encoding evasion beat local scan");
  }
  if (!expectMatch(
    "HY/evasion-mixed-case-hyphen",
    "Project-X",
    "see PROJECT_x now"
  )) {
    noteFinding("HY-EV-MIX", "HIGH", "case/hyphen folding failed");
  }

  // Cyrillic lookalike (confusable map is fullwidth-only — likely FN)
  {
    var r = mk("cyr");
    // Cyrillic 'е' U+0435 looks like Latin 'e'
    var banned = "projectx";
    var prose = "proj\u0435ctx in the wild"; // projectx with Cyrillic e
    writeTree(r, {
      ".plans/hygiene/banned-identifiers.txt": banned + "\n",
      "README.md": prose + "\n",
    });
    var ld = [hygiene.normalize(banned)];
    var hs = hygiene.scanLocal(r, ld);
    // Does normalize fold Cyrillic e?
    var normProse = hygiene.normalize(prose);
    if (hs.length > 0 || normProse.indexOf("projectx") !== -1) {
      pass("HY/evasion-cyrillic-lookalike", "folded or caught norm=" + normProse);
    } else {
      fail("HY/evasion-cyrillic-lookalike", "Cyrillic-е 'projеctx' norm=" + normProse + " ≠ projectx");
      noteFinding(
        "HY-EV-CYR",
        "MEDIUM",
        "confusable map is fullwidth+ZW only; Cyrillic/Greek lookalikes in contents are not folded (proj\\u0435ctx evades)"
      );
    }
  }

  // Filename match
  {
    var r = mk("fnm");
    writeTree(r, {
      ".plans/hygiene/banned-identifiers.txt": "secretnameray\n",
      "docs/secret-name-ray.md": "# empty\n",
      "README.md": "clean\n",
    });
    var ld = [hygiene.normalize("secretnameray")];
    var hs = hygiene.scanLocal(r, ld);
    if (hs.some(function (h) { return h.line === 0; })) {
      pass("HY/filename-match", "line=0 filename hit");
    } else {
      fail("HY/filename-match", "filename not flagged: " + JSON.stringify(hs));
      noteFinding("HY-FNAME", "HIGH", "filename identifier match failed");
    }
  }

  // Fullwidth filename evasion
  {
    var r = mk("fnfw");
    // filename with fullwidth letters
    var fname = "\uFF53\uFF45\uFF43\uFF52\uFF45\uFF54\uFF4E\uFF41\uFF4D\uFF45\uFF52\uFF41\uFF59.md";
    writeTree(r, {
      ".plans/hygiene/banned-identifiers.txt": "secretnameray\n",
      ["docs/" + fname]: "# x\n",
      "README.md": "clean\n",
    });
    var ld = [hygiene.normalize("secretnameray")];
    var hs = hygiene.scanLocal(r, ld);
    if (hs.some(function (h) { return h.line === 0; })) {
      pass("HY/filename-fullwidth", "fullwidth filename caught");
    } else {
      fail("HY/filename-fullwidth", "fullwidth filename evasion");
      noteFinding("HY-FNAME-FW", "HIGH", "fullwidth filename not normalized for match");
    }
  }

  // 4e. CI mode requires secrets; trusted context only in workflow (not in-script)
  {
    var missingKey = spawnNode(HYGIENE, ["--ci"], {
      cwd: mk("cik"),
      env: { HYGIENE_HMAC_KEY: null, HYGIENE_DIGESTS: "abcd" },
    });
    if (missingKey.status !== 0) {
      pass("HY/ci-missing-key-nonzero", "exit=" + missingKey.status);
    } else {
      fail("HY/ci-missing-key-nonzero", "exit 0 without key");
      noteFinding("HY-CI-KEY", "CRITICAL", "--ci with missing HYGIENE_HMAC_KEY exited 0");
    }
    var missingDig = spawnNode(HYGIENE, ["--ci"], {
      cwd: mk("cid"),
      env: { HYGIENE_HMAC_KEY: "k", HYGIENE_DIGESTS: null },
    });
    if (missingDig.status !== 0) {
      pass("HY/ci-missing-digests-nonzero", "exit=" + missingDig.status);
    } else {
      fail("HY/ci-missing-digests-nonzero", "exit 0 without digests");
      noteFinding("HY-CI-DIG", "CRITICAL", "--ci with missing HYGIENE_DIGESTS exited 0");
    }
  }

  // Workflow must gate List B to non-PR trusted context
  if (fs.existsSync(CI_YML)) {
    var yml = fs.readFileSync(CI_YML, "utf8");
    var hasCiScan = /hygiene-scan\.js\s+--ci/.test(yml);
    var hasGuard = /if:\s*github\.event_name\s*!=\s*'pull_request'/.test(yml);
    // Also ensure secrets are referenced and not hardcoded digests
    var hardDigest = /HYGIENE_DIGESTS:\s*['\"][0-9a-fA-F]{32,}/.test(yml);
    var secretRef = /secrets\.HYGIENE_HMAC_KEY/.test(yml) && /secrets\.HYGIENE_DIGESTS/.test(yml);
    if (hasCiScan && hasGuard) {
      pass("HY/ci-yml-trusted-only", "hygiene --ci gated on non-PR");
    } else {
      fail("HY/ci-yml-trusted-only", "hasCiScan=" + hasCiScan + " hasGuard=" + hasGuard);
      noteFinding("HY-CI-YML", "HIGH", "ci.yml does not gate hygiene --ci to trusted non-PR context");
    }
    if (secretRef && !hardDigest) {
      pass("HY/ci-yml-secrets-not-hardcoded", "secrets.* refs only");
    } else {
      fail("HY/ci-yml-secrets-not-hardcoded", "secretRef=" + secretRef + " hardDigest=" + hardDigest);
      noteFinding("HY-CI-HARDCODE", "CRITICAL", "ci.yml hardcodes digests or omits secrets");
    }
    // Script itself does NOT refuse PR context — defense is workflow-only.
    // Record as informational finding if script has no github context check.
    if (!/pull_request|GITHUB_EVENT|trusted/.test(src)) {
      pass(
        "HY/script-trusts-workflow-gate",
        "script has no in-process PR guard (workflow-only) — acceptable if yml gate holds"
      );
    } else {
      pass("HY/script-has-context-guard", "in-script trusted-context check present");
    }
  } else {
    fail("HY/ci-yml-present", "missing .github/workflows/ci.yml");
  }

  // HMAC end-to-end round trip
  {
    var r = mk("rt");
    var key = "round-trip-key";
    var id = "nimbus-internal-42";
    var dig = hygiene.hmacDigest(key, hygiene.normalize(id));
    writeTree(r, { "README.md": "touch " + id + " here\n", "docs/a.md": "x\n" });
    var hs = hygiene.scanCI(r, key, new Set([dig]));
    if (hs.length > 0) {
      pass("HY/hmac-roundtrip", "hit " + hs[0].file + ":" + hs[0].line);
    } else {
      fail("HY/hmac-roundtrip", "no hit");
      noteFinding("HY-RT", "HIGH", "HMAC round-trip failed to detect planted id");
    }
    // Wrong key → miss
    var hs2 = hygiene.scanCI(r, "other-key", new Set([dig]));
    if (hs2.length === 0) {
      pass("HY/hmac-wrong-key-no-match", "wrong key clean");
    } else {
      fail("HY/hmac-wrong-key-no-match", "matched with wrong key");
      noteFinding("HY-WRONG-KEY", "CRITICAL", "HMAC matched under wrong key");
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. FAIL-CLOSED — malformed / missing / unreadable → non-zero, never silent pass
// ═══════════════════════════════════════════════════════════════════════════

function attackFailClosed() {
  // Missing local list → contract/task: fail-closed. Implementation exits 0 (FAIL-OPEN).
  {
    var r = mk("fc-miss");
    writeTree(r, { "README.md": "# clean\n", "docs/a.md": "x\n" });
    // no .plans/hygiene/banned-identifiers.txt
    var child = spawnNode(HYGIENE, [], { cwd: r });
    if (child.status !== 0) {
      pass("FC/local-missing-list-nonzero", "exit=" + child.status);
    } else {
      fail("FC/local-missing-list-nonzero", "exit 0 on missing list (fail-open)");
      noteFinding(
        "FC-MISS-LIST",
        "HIGH",
        "hygiene-scan local mode exits 0 when " + BANNED_PATH_REL + " is missing — fail-open vs task 'fail-closed'"
      );
    }
  }

  // Empty list (comments only) — maintainer-valid; exit 0 is acceptable "nothing to enforce"
  {
    var r = mk("fc-empty");
    writeTree(r, {
      ".plans/hygiene/banned-identifiers.txt": "# only comments\n\n# still empty\n",
      "README.md": "clean\n",
    });
    var child = spawnNode(HYGIENE, [], { cwd: r });
    // Document actual behavior: empty → exit 0. Not necessarily a defect (no policy to enforce).
    if (child.status === 0) {
      pass("FC/local-empty-list-clean", "exit 0 on comments-only list (nothing to enforce)");
    } else {
      pass("FC/local-empty-list-nonzero", "exit=" + child.status + " (strict fail-closed on empty)");
    }
  }

  // Unreadable local list file (chmod 000) — skip on win32 if chmod ineffective
  {
    var r = mk("fc-unreadable");
    writeTree(r, {
      ".plans/hygiene/banned-identifiers.txt": "should-not-read\n",
      "README.md": "clean\n",
    });
    var listAbs = path.join(r, BANNED_PATH_REL);
    var chmodOk = false;
    try {
      fs.chmodSync(listAbs, 0);
      chmodOk = true;
    } catch (_) {}
    if (!chmodOk || process.platform === "win32") {
      // On Windows ACLs often still allow the owner to read after chmod 0 —
      // synthesize unreadable via replacing path with a directory.
      try { fs.unlinkSync(listAbs); } catch (_) {}
      try { fs.mkdirSync(listAbs); } catch (_) {}
      var child = spawnNode(HYGIENE, [], { cwd: r });
      // read of directory throws → load returns [] → currently exit 0
      if (child.status !== 0) {
        pass("FC/local-unreadable-nonzero", "exit=" + child.status);
      } else {
        fail("FC/local-unreadable-nonzero", "exit 0 when list unreadable/dir (fail-open)");
        noteFinding(
          "FC-UNREADABLE",
          "HIGH",
          "hygiene-scan returns [] and exits 0 when banned-identifiers path is unreadable — fail-open"
        );
      }
    } else {
      var child2 = spawnNode(HYGIENE, [], { cwd: r });
      try { fs.chmodSync(listAbs, 0o644); } catch (_) {}
      if (child2.status !== 0) {
        pass("FC/local-unreadable-nonzero", "exit=" + child2.status);
      } else {
        fail("FC/local-unreadable-nonzero", "exit 0 on chmod 0 list");
        noteFinding(
          "FC-UNREADABLE",
          "HIGH",
          "hygiene-scan exits 0 when banned list is unreadable"
        );
      }
    }
  }

  // CI: empty digests string after parse — still requires env set; empty set scans clean → exit 0
  {
    var r = mk("fc-empty-dig");
    writeTree(r, { "README.md": "planted-should-not-matter\n" });
    var child = spawnNode(HYGIENE, ["--ci"], {
      cwd: r,
      keepHygieneEnv: true,
      env: { HYGIENE_HMAC_KEY: "k", HYGIENE_DIGESTS: "\n\n" },
    });
    // Empty digest set + key present = "no policy" clean. Accept exit 0 but note.
    if (child.status === 0) {
      pass("FC/ci-empty-digest-set", "exit 0 with empty digest set (vacuous clean)");
    } else {
      pass("FC/ci-empty-digest-set-strict", "exit=" + child.status);
    }
  }

  // CI missing both secrets — already covered; reinforce non-zero
  {
    var r = mk("fc-ci");
    writeTree(r, { "README.md": "x\n" });
    var child = spawnNode(HYGIENE, ["--ci"], {
      cwd: r,
      env: { HYGIENE_HMAC_KEY: null, HYGIENE_DIGESTS: null },
    });
    if (child.status !== 0) {
      pass("FC/ci-no-secrets-nonzero", "exit=" + child.status);
    } else {
      fail("FC/ci-no-secrets-nonzero", "exit 0");
      noteFinding("FC-CI-SECRETS", "CRITICAL", "--ci without secrets exits 0");
    }
  }

  // docs-lint: violations → non-zero; clean → zero
  {
    var dirty = mk("fc-dl-dirty");
    writeTree(dirty, {
      "README.md": "This is proven.\n",
      "docs/a.md": "ok\n",
    });
    var child = spawnNode(DOCS_LINT, [], { cwd: dirty });
    if (child.status !== 0) {
      pass("FC/docs-lint-dirty-nonzero", "exit=" + child.status);
    } else {
      fail("FC/docs-lint-dirty-nonzero", "exit 0 on bare proven");
      noteFinding("FC-DL-DIRTY", "CRITICAL", "docs-lint exit 0 on bare over-claim");
    }

    var clean = mk("fc-dl-clean");
    writeTree(clean, {
      "README.md": "# fine\nno over claims here\n",
      "docs/a.md": "standard text\n",
    });
    child = spawnNode(DOCS_LINT, [], { cwd: clean });
    if (child.status === 0) {
      pass("FC/docs-lint-clean-zero", "exit 0");
    } else {
      fail("FC/docs-lint-clean-zero", "exit=" + child.status + " out=" + (child.stdout || "").slice(0, 120));
    }
  }

  // docs-lint scanFile on missing file returns [] (library) — silent; CLI uses exist-checked file list so OK
  {
    var hits = docsLint.scanFile("nope.md", path.join(mk("fc-missfile"), "nope.md"));
    if (Array.isArray(hits) && hits.length === 0) {
      pass("FC/docs-lint-missing-file-empty", "scanFile → [] on missing (caller must fail-closed)");
    } else {
      fail("FC/docs-lint-missing-file-empty", "unexpected " + JSON.stringify(hits));
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// main
// ═══════════════════════════════════════════════════════════════════════════

function main() {
  console.log("ADVERSARIAL banned-lint suite — grok vs docs-lint + hygiene-scan");
  console.log("repo=" + REPO.replace(/\\/g, "/"));
  try {
    attackFalseNegatives();
    attackLintAllow();
    attackTermLeak();
    attackHygieneSoundness();
    attackFailClosed();
  } catch (e) {
    fail("SUITE/uncaught", (e && e.stack) || String(e));
    noteFinding("SUITE-CRASH", "CRITICAL", String(e && e.message ? e.message : e));
  }

  var passN = results.filter(function (r) { return r.status === "PASS"; }).length;
  var failN = results.filter(function (r) { return r.status === "FAIL"; }).length;
  var skipN = results.filter(function (r) { return r.status === "SKIPPED"; }).length;

  console.log("");
  console.log("SUMMARY\tPASS=" + passN + "\tFAIL=" + failN + "\tSKIPPED=" + skipN + "\tTOTAL=" + results.length);
  console.log("FINDINGS\tcount=" + findings.length);
  for (var i = 0; i < findings.length; i++) {
    var f = findings[i];
    console.log("FINDING\t" + f.severity + "\t" + f.id + "\t" + f.summary);
  }
  if (findings.length === 0) {
    console.log("FINDING\tNOTE\tZERO\tzero findings — only valid if every attack surface was exercised and held");
  }

  rmAll();
  process.exit(failN > 0 ? 1 : 0);
}

main();
