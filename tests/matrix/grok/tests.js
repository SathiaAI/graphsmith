#!/usr/bin/env node
"use strict";

/**
 * Adversarial battery against scripts/matrix.js (F22 property matrix).
 * Deterministic, zero-dep CJS. Attacks injection, CI URLs, status honesty, malformed input.
 */

const fs = require("fs");
const path = require("path");
const assert = require("assert");

const {
  aggregateReports,
  generateMarkdown,
  generateJson,
  validateCiUrl,
  escapeHtml,
  escapeMarkdown,
  SCHEMA_VERSION,
} = require("../../../scripts/matrix.js");

const FINDINGS = [];
let passed = 0;
let failed = 0;

function record(name, ok, detail) {
  if (ok) {
    passed++;
    console.log(`PASS  ${name}`);
  } else {
    failed++;
    console.log(`FAIL  ${name}`);
    if (detail) console.log(`      ${detail}`);
    FINDINGS.push({ name, detail: detail || "assertion failed" });
  }
}

function expect(name, cond, detail) {
  try {
    if (typeof cond === "function") cond();
    else assert.ok(cond, detail || name);
    record(name, true);
  } catch (e) {
    record(name, false, detail || e.message);
  }
}

const TMP = path.join(".tmp", "matrix-grok-adv");
fs.mkdirSync(TMP, { recursive: true });

function writeReport(name, obj) {
  const p = path.join(TMP, name);
  fs.writeFileSync(p, JSON.stringify(obj));
  return p;
}

function baseReport(platform, profiles, extra) {
  return Object.assign(
    {
      schema_version: "1.0",
      command: "profiles",
      verifier_version: "1.0.0-adv",
      platform,
      node_version: "v20.0.0",
      root: "/adv/root",
      evaluated_at: "2024-06-01T00:00:00Z",
      evaluated_at_source: "SOURCE_DATE_EPOCH",
      profiles,
      profile_string: "adv",
      note: "adversarial",
    },
    extra || {}
  );
}

function allProps(statusMap) {
  const profiles = {};
  for (const p of ["R", "E", "B", "T", "G", "Q", "X"]) {
    const st = statusMap[p] || "unavailable";
    profiles[p] = {
      status: st,
      evidence: statusMap._evidence || [],
      assumptions: statusMap._assumptions || [],
    };
  }
  return profiles;
}

// ─────────────────────────────────────────────────────────────
// 1. RENDER-INJECTION
// ─────────────────────────────────────────────────────────────
console.log("\n=== 1. RENDER-INJECTION ===\n");

(function attackEscapePrimitives() {
  const payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror="alert(1)">',
    '<img src=x onerror=\'alert(1)\'>',
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
    "[click](javascript:alert(1))",
    "[x](https://evil.com)",
    "| broken | table |",
    "**bold** _ital_ `code`",
    "a & b < c > d \"e\" 'f'",
    "\u0000null\u0007bell",
    "{{constructor.constructor('return this')()}}",
  ];

  for (const p of payloads) {
    const h = escapeHtml(p);
    expect(
      `escapeHtml blocks raw markup: ${JSON.stringify(p).slice(0, 48)}`,
      () => {
        // After escape, angle brackets must not remain as raw HTML metacharacters
        assert.ok(!h.includes("<"), `raw < remains in: ${h}`);
        assert.ok(!h.includes(">"), `raw > remains in: ${h}`);
        if (p.includes("<script")) assert.ok(h.includes("&lt;script"), "script not escaped");
        if (/<img/i.test(p)) assert.ok(h.toLowerCase().includes("&lt;img"), "img not escaped");
        if (p.includes("&")) assert.ok(h.includes("&") || h.includes("<") || h.includes(">") || h.includes("&quot;") || h.includes("&#39;"), "amp path broken");
        if (p.includes('"')) assert.ok(h.includes("&quot;"), "dquote not escaped");
        if (p.includes("'")) assert.ok(h.includes("&#39;"), "squote not escaped");
        // onerror= may remain as inert text once <img is escaped — that is correct
      }
    );

    const m = escapeMarkdown(p);
    expect(
      `escapeMarkdown neutralizes md/html: ${JSON.stringify(p).slice(0, 48)}`,
      () => {
        assert.ok(!m.includes("<"), "md path leaves raw <");
        assert.ok(!m.includes(">"), "md path leaves raw >");
        if (p.includes("|")) assert.ok(m.includes("\\|"), "pipe not escaped");
        if (p.includes("*")) assert.ok(m.includes("\\*"), "star not escaped");
        if (p.includes("_")) assert.ok(m.includes("\\_"), "underscore not escaped");
        if (p.includes("`")) assert.ok(m.includes("\\`"), "backtick not escaped");
      }
    );
  }

  expect("escapeHtml(null/undefined) -> empty", () => {
    assert.strictEqual(escapeHtml(null), "");
    assert.strictEqual(escapeHtml(undefined), "");
  });
  expect("escapeMarkdown(null/undefined) -> empty", () => {
    assert.strictEqual(escapeMarkdown(null), "");
    assert.strictEqual(escapeMarkdown(undefined), "");
  });
})();

(function attackEvidenceLeakIntoOutputs() {
  const evilEvidence = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror="alert(1)">',
    '![x](javascript:alert(1))',
    '[link](https://evil.test "t")',
    '</td><script>alert(1)</script>',
    '`" onmouseover="alert(1)`',
  ];
  const evilAssumptions = [
    '<svg onload=alert(1)>',
    '**pwned**',
    "|a|b|",
  ];
  const evilStatus = '<script>alert("status")</script>';
  const evilPlatform = 'linux"><script>alert(1)</script>';

  const rep = baseReport(
    evilPlatform,
    {
      R: {
        status: evilStatus,
        evidence: evilEvidence,
        assumptions: evilAssumptions,
      },
      E: { status: "verified", evidence: evilEvidence, assumptions: evilAssumptions },
      B: { status: "failed", evidence: evilEvidence, assumptions: [] },
      T: { status: "unavailable", evidence: [], assumptions: evilAssumptions },
      G: { status: "not-applicable", evidence: evilEvidence, assumptions: [] },
      Q: { status: "verified", evidence: [], assumptions: [] },
      X: { status: "verified", evidence: [], assumptions: [] },
    },
    {
      verifier_version: '<img src=x onerror=alert(1)>',
      note: '<script>alert(1)</script>',
    }
  );

  const rp = writeReport("inject-evidence.json", rep);
  const { matrix, metadata } = aggregateReports([rp], ["https://ci.example.com/r1"]);
  const md = generateMarkdown(matrix, metadata);
  const json = generateJson(matrix, metadata);
  const jsonStr = JSON.stringify(json);

  expect("evidence[] never appears raw in Markdown", () => {
    for (const ev of evilEvidence) {
      assert.ok(!md.includes(ev), `raw evidence leaked into MD: ${ev}`);
    }
  });

  expect("assumptions[] never appear raw in Markdown", () => {
    for (const a of evilAssumptions) {
      assert.ok(!md.includes(a), `raw assumption leaked into MD: ${a}`);
    }
  });

  expect("hostile status is HTML-escaped in MD cells (not raw)", () => {
    assert.ok(!md.includes(evilStatus), "raw evil status in MD");
    // Status goes through formatStatus → escapeHtml; raw <script> contig from status must not appear
    assert.ok(!md.includes('<script>alert("status")</script>'), "unescaped status XSS");
  });

  expect("evidence/assumptions payloads never create raw tags in MD body cells", () => {
    // evidence is not rendered at all today — if it ever is, escapes must apply
    assert.ok(!md.includes('<img src=x onerror="alert(1)">'), "raw img evidence");
    assert.ok(!md.includes("<svg onload=alert(1)>"), "raw svg assumption");
  });

  expect("JSON consumers get status enum string without fabricating markup fields from evidence", () => {
    const platforms = Object.keys(json.matrix);
    assert.ok(platforms.length >= 1);
    for (const pl of platforms) {
      for (const prop of json.properties) {
        const cell = json.matrix[pl][prop];
        assert.ok(cell && typeof cell.status === "string");
        assert.ok(!Object.prototype.hasOwnProperty.call(cell, "evidence"), "evidence leaked into JSON cell");
        assert.ok(!Object.prototype.hasOwnProperty.call(cell, "assumptions"), "assumptions leaked into JSON cell");
      }
    }
    assert.ok(!jsonStr.includes("<script>alert(\"XSS\")</script>") || jsonStr.includes("\\u003c"), "unexpected");
    // Status may carry attacker text if verify allowed it — must not invent green
    const rCell = json.matrix[platforms[0]].R;
    assert.strictEqual(rCell.status, evilStatus);
  });

  // Pipe/break attempts via status when only escapeHtml is used in cells
  const pipeRep = baseReport("darwin", allProps({
    R: "verified | [pwn](https://evil.test)",
    E: "failed",
    B: "unavailable",
    T: "not-applicable",
    G: "verified",
    Q: "verified",
    X: "verified",
  }));
  const pipePath = writeReport("inject-pipe-status.json", pipeRep);
  const agg2 = aggregateReports([pipePath], [null]);
  const md2 = generateMarkdown(agg2.matrix, agg2.metadata);

  expect("pipe/markdown in status: escapeMarkdown exists but formatStatus may only HTML-escape (probe)", () => {
    // Adversarial check: if plain `|` survives into a table cell, column integrity is broken.
    const matrixLines = md2.split("\n").filter((l) => l.startsWith("| R ") || l.startsWith("| R|") || /^\| R \|/.test(l));
    assert.ok(matrixLines.length >= 1, "R row missing");
    const row = matrixLines[0];
    // Count unescaped pipe delimiters. A well-formed row: leading |, cells, trailing |
    // Properties row for 1 platform: | R | status |  => 3 pipes minimum if status has no raw |
    if (row.includes("verified | [pwn]")) {
      throw new Error(
        "FINDING: status pipes not escaped in Markdown table (escapeMarkdown unused in formatStatus); table can be broken or link-injected"
      );
    }
    // If HTML-only escape, markdown link syntax may still render as a link in GFM
    if (row.includes("[pwn](https://evil.test)")) {
      throw new Error(
        "FINDING: markdown link syntax in status survives into PROPERTY-MATRIX.md (only HTML-escaped, not MD-escaped)"
      );
    }
  });
})();

(function attackPlatformHeaderInjection() {
  const plat = "win32|evil|<script>alert(1)</script>";
  const rep = baseReport(plat, allProps({ R: "verified", E: "verified", B: "verified", T: "verified", G: "verified", Q: "verified", X: "verified" }));
  const rp = writeReport("inject-platform.json", rep);
  const { matrix, metadata } = aggregateReports([rp], [null]);
  const md = generateMarkdown(matrix, metadata);

  expect("hostile platform key does not inject raw <script> into MD header", () => {
    assert.ok(!md.includes("<script>alert(1)</script>"), "raw script in platform header");
  });

  expect("hostile platform key pipe does not break table header (probe)", () => {
    const header = md.split("\n").find((l) => l.startsWith("| Property |"));
    assert.ok(header, "header missing");
    if (header.includes("|evil|") || /win32\|evil/.test(header)) {
      // If platform is concatenated without escapeMarkdown, this is a finding
      const unescapedPipeInName = header.includes("win32|evil");
      if (unescapedPipeInName) {
        throw new Error(
          "FINDING: platform name with | is not markdown-escaped in header row — table column break"
        );
      }
    }
  });
})();

// ─────────────────────────────────────────────────────────────
// 2. HOSTILE CI-URL
// ─────────────────────────────────────────────────────────────
console.log("\n=== 2. HOSTILE CI-URL ===\n");

(function attackCiUrls() {
  const reject = [
    "javascript:alert(1)",
    "JAVASCRIPT:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
    "about:blank",
    " https://evil.example",
    "https://",
    "http://",
    "",
    null,
    undefined,
    123,
    { href: "https://x" },
    "http://example.com\nLocation: https://evil",
    "//evil.example/path",
    "https://evil.example\" onclick=\"alert(1)",
  ];

  for (const u of reject) {
    expect(`validateCiUrl rejects ${JSON.stringify(u)}`, () => {
      assert.strictEqual(validateCiUrl(u), false, `accepted hostile/invalid: ${u}`);
    });
  }

  const accept = [
    "https://ci.example.com/run/1",
    "http://ci.example.com/run/2",
    "https://github.com/org/repo/actions/runs/99",
  ];
  for (const u of accept) {
    expect(`validateCiUrl accepts ${u}`, () => {
      assert.strictEqual(validateCiUrl(u), true);
    });
  }

  // Full pipeline: hostile URL must not become href
  const hostiles = [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    " https://leading-space.example/x",
    "file:///c:/windows/system32",
    "](https://evil.com)[x",
    'https://ok.example/a" onmouseover="alert(1)',
  ];

  for (let i = 0; i < hostiles.length; i++) {
    const url = hostiles[i];
    const rep = baseReport("linux", allProps({
      R: "verified", E: "failed", B: "unavailable", T: "not-applicable",
      G: "verified", Q: "verified", X: "verified",
    }));
    const rp = writeReport(`hostile-ci-${i}.json`, rep);
    const { matrix, metadata } = aggregateReports([rp], [url]);
    const md = generateMarkdown(matrix, metadata);
    const json = generateJson(matrix, metadata);
    const pl = Object.keys(json.matrix)[0];
    const accepted = validateCiUrl(url);

    expect(`hostile ci_run_url pipeline: ${JSON.stringify(url).slice(0, 50)}`, () => {
      if (!accepted) {
        assert.ok(!/href="javascript:/i.test(md), "javascript: href");
        assert.ok(!/href="data:/i.test(md), "data: href");
        assert.ok(!/href="file:/i.test(md), "file: href");
        for (const prop of ["R", "E", "B", "T", "G", "Q", "X"]) {
          assert.strictEqual(json.matrix[pl][prop].ci_url, null, `JSON kept invalid ci_url for ${prop}`);
        }
        // Rejected URL must not appear as an href target
        if (typeof url === "string" && url.length) {
          assert.ok(!md.includes(`href="${url}"`), "rejected URL still raw href");
        }
      } else {
        // Accepted: href must be attribute-safe (quotes escaped). Bare " inside href= is breakout.
        const hrefMatch = md.match(/href="([^"]*)"/);
        if (url.includes('"')) {
          // If validate accepts quote-bearing URL, MD must still escape — never raw breakout
          assert.ok(!md.includes(`href="${url}"`), "quote-bearing URL emitted unescaped in href");
          assert.ok(md.includes("&quot;") || !md.includes("<a href="), "expected &quot; in escaped href");
          throw new Error(
            `FINDING: validateCiUrl accepts URL containing " (${url}) — attribute-injection risk if any consumer skips HTML escape; JSON ci_url stores raw quotes`
          );
        }
        if (typeof url === "string" && /^\s/.test(url)) {
          throw new Error(
            `FINDING: validateCiUrl accepts leading-whitespace URL (${JSON.stringify(url)}) and emits it as href`
          );
        }
        void hrefMatch;
      }
    });
  }

  // Valid URL with HTML/MD-breaking chars must be attribute-escaped if emitted
  const tricky = 'https://ci.example.com/run?a="onclick&b=<x>&c=\'y\'';
  expect("tricky but valid https URL is attribute-safe in MD", () => {
    assert.strictEqual(validateCiUrl(tricky), true);
    const rep = baseReport("darwin", allProps({ R: "verified", E: "verified", B: "verified", T: "verified", G: "verified", Q: "verified", X: "verified" }));
    const rp = writeReport("tricky-ci.json", rep);
    const { matrix, metadata } = aggregateReports([rp], [tricky]);
    const md = generateMarkdown(matrix, metadata);
    assert.ok(md.includes("<a href="), "expected link for valid URL");
    assert.ok(!md.includes('href="' + tricky + '"') || md.includes("&quot;") || md.includes("&"),
      "raw quotes/amps in href");
    // Must not break out of attribute
    assert.ok(!/href="https:\/\/ci\.example\.com\/run\?a="onclick/.test(md), "attribute breakout");
    assert.ok(md.includes("&quot;") || md.includes("&#39;") || md.includes("&"), "URL not HTML-escaped in href");
  });

  // Markdown-breaking URL chars
  const mdBreak = "https://ci.example.com/run/1)_[pwn](http://evil.example";
  expect("URL with MD-break chars: stays inside HTML href, not a second bare MD link", () => {
    const ok = validateCiUrl(mdBreak);
    const rep = baseReport("linux", allProps({ R: "verified", E: "verified", B: "verified", T: "verified", G: "verified", Q: "verified", X: "verified" }));
    const rp = writeReport("mdb-ci.json", rep);
    const { matrix, metadata } = aggregateReports([rp], [mdBreak]);
    const md = generateMarkdown(matrix, metadata);
    const json = generateJson(matrix, metadata);
    if (ok) {
      assert.ok(md.includes("<a href="), "link expected when validate passes");
      // Cells must use HTML anchors, not [status](url) MD links (which break on ) in URL)
      assert.ok(!/\[verified\]\(https:\/\/ci\.example\.com/.test(md), "unexpected MD-link cell format");
      // href= must be double-quote delimited and closed before >
      assert.ok(/href="[^"]*">verified<\/a>/.test(md.replace(/\n/g, " ")) || md.includes("href="), "href clothing");
      assert.strictEqual(json.matrix.Linux.R.ci_url, mdBreak);
    } else {
      assert.strictEqual(json.matrix.Linux.R.ci_url, null);
    }
  });
})();

// ─────────────────────────────────────────────────────────────
// 3. UNAVAILABLE-NEVER-GREEN (F22 / contract 10)
// ─────────────────────────────────────────────────────────────
console.log("\n=== 3. UNAVAILABLE-NEVER-GREEN ===\n");

(function attackUnavailableNeverGreen() {
  // Only darwin present — missing linux/win32 reports
  const onlyDarwin = baseReport("darwin", allProps({
    R: "verified", E: "verified", B: "verified", T: "verified", G: "verified", Q: "verified", X: "verified",
  }));
  const rp = writeReport("only-darwin.json", onlyDarwin);
  const { matrix, metadata } = aggregateReports([rp], ["https://ci.example.com/d"]);
  const md = generateMarkdown(matrix, metadata);
  const json = generateJson(matrix, metadata);

  expect("single-OS report: no fabricated verified for absent OS columns", () => {
    const plats = Object.keys(json.matrix);
    assert.ok(!plats.some((p) => /linux/i.test(p)), "linux column fabricated");
    assert.ok(!plats.some((p) => /win/i.test(p)), "windows column fabricated");
    // Honesty gap: missing platforms absent entirely vs unavailable columns
    // Contract wants missing report → unavailable. Probe:
    if (plats.length === 1) {
      // Document as finding if matrix omits platform instead of unavailable row/col
      // We'll mark finding only if something is falsely green — omission alone is a milder honesty gap
    }
    for (const pl of plats) {
      for (const prop of json.properties) {
        const st = json.matrix[pl][prop].status;
        assert.ok(
          st === "verified" || st === "unavailable" || st === "failed" || st === "not-applicable",
          `unexpected status ${st}`
        );
      }
    }
  });

  expect("FINDING probe: missing platform report should surface as unavailable not omitted", () => {
    // Strict contract 10 / F22: missing report for a platform renders unavailable.
    // Generator only creates columns for platforms present in input — absent OS never shown as unavailable.
    const hasLinux = Object.keys(json.matrix).some((p) => /linux/i.test(p));
    const hasWin = Object.keys(json.matrix).some((p) => /windows|win32/i.test(p));
    if (!hasLinux || !hasWin) {
      throw new Error(
        "FINDING: missing OS reports do not produce unavailable columns — platform simply omitted from matrix (cannot show honest gap for unscanned OS)"
      );
    }
  });

  // Explicit unavailable / not-applicable must never be rewritten to verified
  const mixed = baseReport("linux", {
    R: { status: "unavailable", evidence: [], assumptions: ["no runner"] },
    E: { status: "not-applicable", evidence: [], assumptions: [] },
    B: { status: "failed", evidence: ["boom"], assumptions: [] },
    T: { status: "unavailable", evidence: [], assumptions: [] },
    G: { status: "not-applicable", evidence: [], assumptions: [] },
    Q: { status: "failed", evidence: [], assumptions: [] },
    X: { status: "unavailable", evidence: [], assumptions: [] },
  });
  const rp2 = writeReport("explicit-unavail.json", mixed);
  const agg2 = aggregateReports([rp2], ["https://ci.example.com/l"]);
  const md2 = generateMarkdown(agg2.matrix, agg2.metadata);
  const json2 = generateJson(agg2.matrix, agg2.metadata);
  const linux = json2.matrix.Linux || json2.matrix.linux;

  expect("explicit unavailable stays unavailable (not verified/green)", () => {
    assert.ok(linux);
    assert.strictEqual(linux.R.status, "unavailable");
    assert.strictEqual(linux.T.status, "unavailable");
    assert.strictEqual(linux.X.status, "unavailable");
    assert.ok(!/\| R \|.*verified/.test(md2.split("\n").find((l) => /^\| R \|/.test(l)) || ""), "R flipped green");
  });

  expect("explicit not-applicable stays not-applicable (not verified)", () => {
    assert.strictEqual(linux.E.status, "not-applicable");
    assert.strictEqual(linux.G.status, "not-applicable");
  });

  expect("failed stays failed (not verified)", () => {
    assert.strictEqual(linux.B.status, "failed");
    assert.strictEqual(linux.Q.status, "failed");
  });

  // Partial profiles: missing props → unavailable
  const partial = baseReport("win32", {
    R: { status: "verified", evidence: ["ok"], assumptions: [] },
    // E..X omitted
  });
  const rp3 = writeReport("partial-profiles.json", partial);
  const agg3 = aggregateReports([rp3], [null]);
  const json3 = generateJson(agg3.matrix, agg3.metadata);
  const win = json3.matrix.Windows || json3.matrix.win32;

  expect("omitted property cells are unavailable, never verified", () => {
    assert.strictEqual(win.R.status, "verified");
    for (const p of ["E", "B", "T", "G", "Q", "X"]) {
      assert.strictEqual(win[p].status, "unavailable", `${p} should be unavailable`);
      assert.strictEqual(win[p].ci_url, null);
    }
  });

  const md3 = generateMarkdown(agg3.matrix, agg3.metadata);
  expect("MD omitted props render unavailable text, not verified", () => {
    for (const p of ["E", "B", "T", "G", "Q", "X"]) {
      const row = md3.split("\n").find((l) => l.startsWith(`| ${p} |`));
      assert.ok(row, `${p} row missing`);
      assert.ok(row.includes("unavailable"), `${p} row not unavailable: ${row}`);
      assert.ok(!row.includes("verified"), `${p} row falsely verified: ${row}`);
    }
  });

  // Try to smuggle green via weird status aliases
  const aliases = baseReport("darwin", allProps({
    R: "pass",
    E: "success",
    B: "ok",
    T: "true",
    G: "green",
    Q: "PASS",
    X: "Verified", // case variant
  }));
  const rp4 = writeReport("alias-green.json", aliases);
  const agg4 = aggregateReports([rp4], [null]);
  const json4 = generateJson(agg4.matrix, agg4.metadata);
  const d = json4.matrix.macOS || json4.matrix.darwin;

  expect("non-enum status aliases are not normalized into verified", () => {
    assert.strictEqual(d.R.status, "pass");
    assert.strictEqual(d.E.status, "success");
    assert.notStrictEqual(d.R.status, "verified");
    // Case folding to verified would be a finding
    assert.strictEqual(d.X.status, "Verified");
  });
})();

// ─────────────────────────────────────────────────────────────
// 4. STATUS VOCAB
// ─────────────────────────────────────────────────────────────
console.log("\n=== 4. STATUS VOCAB ===\n");

(function attackStatusVocab() {
  const rep = baseReport("linux", {
    R: { status: "verified", evidence: [], assumptions: [] },
    E: { status: "unavailable", evidence: [], assumptions: [] },
    B: { status: "failed", evidence: [], assumptions: [] },
    T: { status: "not-applicable", evidence: [], assumptions: [] },
    G: { status: "verified", evidence: [], assumptions: [] },
    Q: { status: "failed", evidence: [], assumptions: [] },
    X: { status: "unavailable", evidence: [], assumptions: [] },
  });
  const rp = writeReport("vocab.json", rep);
  const { matrix, metadata } = aggregateReports([rp], ["https://ci.example.com/v"]);
  const md = generateMarkdown(matrix, metadata);
  const json = generateJson(matrix, metadata);
  const linux = json.matrix.Linux;

  const expected = {
    R: "verified",
    E: "unavailable",
    B: "failed",
    T: "not-applicable",
    G: "verified",
    Q: "failed",
    X: "unavailable",
  };

  for (const [prop, st] of Object.entries(expected)) {
    expect(`JSON maps ${prop} → ${st}`, () => {
      assert.strictEqual(linux[prop].status, st);
    });
    expect(`MD shows ${prop} as ${st} (not green-washed)`, () => {
      const row = md.split("\n").find((l) => l.startsWith(`| ${prop} |`));
      assert.ok(row, "row missing");
      assert.ok(row.includes(st), `row lacks ${st}: ${row}`);
      if (st !== "verified") {
        assert.ok(!row.includes("verified"), `${prop} incorrectly includes verified: ${row}`);
      }
    });
  }

  expect("legend documents all four statuses", () => {
    assert.ok(md.includes("| verified |"));
    assert.ok(md.includes("| unavailable |"));
    assert.ok(md.includes("| failed |"));
    assert.ok(md.includes("| not-applicable |"));
    assert.ok(/not a pass|honest gap|never/i.test(md) || md.includes("unavailable"), "honesty note weak");
  });
})();

// ─────────────────────────────────────────────────────────────
// 5. MALFORMED INPUT
// ─────────────────────────────────────────────────────────────
console.log("\n=== 5. MALFORMED INPUT ===\n");

(function attackMalformed() {
  // Empty report set
  expect("empty report set: no throw, empty-ish matrix, no green cells", () => {
    const { matrix, metadata } = aggregateReports([], []);
    assert.deepStrictEqual(matrix, {});
    const md = generateMarkdown(matrix, metadata);
    const json = generateJson(matrix, metadata);
    assert.ok(typeof md === "string" && md.includes("Platform Property Matrix"));
    assert.strictEqual(Object.keys(json.matrix).length, 0);
    assert.ok(!md.includes(">verified<") || true);
    // No platform columns with verified
    assert.ok(!/\| R \|[^\n]*verified/.test(md), "empty matrix fabricated verified row content");
  });

  // Missing profiles key
  const noProf = baseReport("darwin", undefined);
  delete noProf.profiles;
  const rp1 = writeReport("no-profiles.json", noProf);
  expect("report missing profiles: matrices cells unavailable, no verified", () => {
    const { matrix, metadata } = aggregateReports([rp1], [null]);
    // platform may exist with empty cell map
    const md = generateMarkdown(matrix, metadata);
    const json = generateJson(matrix, metadata);
    const pl = Object.keys(json.matrix)[0];
    if (pl) {
      for (const prop of json.properties) {
        assert.strictEqual(json.matrix[pl][prop].status, "unavailable");
      }
      assert.ok(!/\| R \|[^\n]*verified/.test(md), "verified fabricated");
    }
  });

  // profiles: null
  const nullProf = baseReport("linux", null);
  nullProf.profiles = null;
  const rp2 = writeReport("null-profiles.json", nullProf);
  expect("profiles:null handled without throw; no green", () => {
    const { matrix, metadata } = aggregateReports([rp2], [null]);
    const json = generateJson(matrix, metadata);
    const pl = Object.keys(json.matrix)[0];
    if (pl) {
      for (const prop of ["R", "E", "B", "T", "G", "Q", "X"]) {
        assert.strictEqual(json.matrix[pl][prop].status, "unavailable");
      }
    }
  });

  // Corrupt cell: status missing / empty / non-string
  const corrupt = baseReport("win32", {
    R: { evidence: ["x"], assumptions: [] }, // no status
    E: { status: "", evidence: [], assumptions: [] },
    B: { status: null, evidence: [], assumptions: [] },
    T: { status: 1, evidence: [], assumptions: [] },
    G: "not-an-object",
    Q: { status: "verified", evidence: null, assumptions: null },
    X: { status: "failed" },
  });
  const rp3 = writeReport("corrupt-cells.json", corrupt);
  expect("corrupt/missing status cells → unavailable (never green)", () => {
    const { matrix, metadata } = aggregateReports([rp3], ["https://ci.example.com/c"]);
    const json = generateJson(matrix, metadata);
    const win = json.matrix.Windows;
    assert.strictEqual(win.R.status, "unavailable");
    assert.strictEqual(win.E.status, "unavailable");
    assert.strictEqual(win.B.status, "unavailable");
    // status:1 is truthy — may be accepted as status 1
    if (win.T.status === 1 || win.T.status === "1") {
      throw new Error("FINDING: non-string status accepted into matrix cell (status=1)");
    }
    // G not object — skipped
    assert.strictEqual(win.G.status, "unavailable");
    assert.strictEqual(win.Q.status, "verified");
    assert.strictEqual(win.X.status, "failed");
  });

  // Unreadable / invalid JSON file
  const badPath = path.join(TMP, "not-json.json");
  fs.writeFileSync(badPath, "{not json!!!");
  expect("invalid JSON report: skipped, no throw, no green fab", () => {
    const { matrix } = aggregateReports([badPath], [null]);
    // matrix should not have invented platform from bad file
    assert.deepStrictEqual(matrix, {});
  });

  const missingPath = path.join(TMP, "does-not-exist-matrix.json");
  expect("missing file: skipped, empty matrix", () => {
    const { matrix } = aggregateReports([missingPath], [null]);
    assert.deepStrictEqual(matrix, {});
  });

  // Empty profiles object
  const emptyProf = baseReport("darwin", {});
  const rp4 = writeReport("empty-profiles.json", emptyProf);
  expect("empty profiles {}: all unavailable", () => {
    const { matrix, metadata } = aggregateReports([rp4], [null]);
    const json = generateJson(matrix, metadata);
    const mac = json.matrix.macOS;
    for (const p of json.properties) {
      assert.strictEqual(mac[p].status, "unavailable");
      assert.strictEqual(mac[p].ci_url, null);
    }
  });

  // Multi-report overwrite: later report same platform
  const d1 = baseReport("darwin", allProps({ R: "failed", E: "failed", B: "failed", T: "failed", G: "failed", Q: "failed", X: "failed" }));
  const d2 = baseReport("darwin", allProps({ R: "verified", E: "verified", B: "verified", T: "verified", G: "verified", Q: "verified", X: "verified" }));
  const p1 = writeReport("d1.json", d1);
  const p2 = writeReport("d2.json", d2);
  expect("second report same platform overwrites cells (document behavior)", () => {
    const { matrix } = aggregateReports([p1, p2], [null, null]);
    assert.strictEqual(matrix.darwin.R.status, "verified");
  });
})();

// ─────────────────────────────────────────────────────────────
// Cross-checks: schema, links on real verified cells
// ─────────────────────────────────────────────────────────────
console.log("\n=== CROSS-CHECKS ===\n");

(function cross() {
  expect("SCHEMA_VERSION exported", () => {
    assert.ok(SCHEMA_VERSION);
    assert.strictEqual(typeof SCHEMA_VERSION, "string");
  });

  const rep = baseReport("linux", allProps({
    R: "verified", E: "unavailable", B: "failed", T: "not-applicable",
    G: "verified", Q: "verified", X: "verified",
  }));
  const rp = writeReport("cross.json", rep);
  const ci = "https://ci.example.com/cross/1";
  const { matrix, metadata } = aggregateReports([rp], [ci]);
  const md = generateMarkdown(matrix, metadata);
  const json = generateJson(matrix, metadata);

  expect("verified cell gets CI link in MD; unavailable still honest", () => {
    const rRow = md.split("\n").find((l) => l.startsWith("| R |"));
    assert.ok(rRow.includes(`href="${ci}"`) || rRow.includes("href="), "verified lacks CI href");
    assert.ok(rRow.includes("verified"), "verified text");
    const eRow = md.split("\n").find((l) => l.startsWith("| E |"));
    assert.ok(eRow.includes("unavailable"), "E not unavailable");
  });

  expect("JSON schema_version present + ci_url only when valid", () => {
    assert.strictEqual(json.schema_version, SCHEMA_VERSION);
    assert.strictEqual(json.matrix.Linux.R.ci_url, ci);
    assert.strictEqual(json.matrix.Linux.R.status, "verified");
    assert.strictEqual(json.matrix.Linux.E.status, "unavailable");
  });
})();

// ─────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────
console.log("\n========== SUMMARY ==========");
console.log(`PASS: ${passed}`);
console.log(`FAIL: ${failed}`);
console.log(`FINDINGS: ${FINDINGS.length}`);
if (FINDINGS.length === 0) {
  console.log("FINDINGS list empty — verify attacks actually exercised surfaces above.");
} else {
  console.log("\n--- FINDINGS ---");
  FINDINGS.forEach((f, i) => {
    console.log(`${i + 1}. [${f.name}] ${f.detail}`);
  });
}
console.log("=============================");

process.exit(failed > 0 ? 1 : 0);
