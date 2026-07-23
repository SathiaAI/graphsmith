#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const SCHEMA_VERSION = "1.0";
const PROPERTIES = ["R", "E", "B", "T", "G", "Q", "X"];
const PLATFORM_ALIASES = {
  darwin: "macOS",
  linux: "Linux",
  win32: "Windows",
};

function readJsonFile(absPath) {
  let raw;
  try {
    raw = fs.readFileSync(absPath, "utf8");
  } catch (e) {
    return { ok: false, notFound: e.code === "ENOENT", error: `${e.code || "ERROR"}: ${e.message}` };
  }
  try {
    return { ok: true, value: JSON.parse(raw), raw };
  } catch (e) {
    return { ok: false, notFound: false, error: `invalid JSON: ${e.message}` };
  }
}

function validateCiUrl(url) {
  if (!url || typeof url !== "string") return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch (_) {
    return false;
  }
}

function escapeHtml(text) {
  if (text === null || text === undefined) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeMarkdown(text) {
  if (text === null || text === undefined) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\*/g, "\\*")
    .replace(/_/g, "\\_")
    .replace(/`/g, "\\`")
    .replace(/\|/g, "\\|");
}

function formatStatus(status, ciUrl) {
  const validUrl = validateCiUrl(ciUrl);
  const url = validUrl ? escapeHtml(ciUrl) : "";
  const escapedStatus = escapeHtml(status);
  if (url) {
    return `<a href="${url}">${escapedStatus}</a>`;
  }
  return escapedStatus;
}

function aggregateReports(reportFiles, ciUrls) {
  const matrix = {};
  const metadata = {
    platforms: [],
    verifier_versions: [],
    evaluated_at: [],
  };

  for (let i = 0; i < reportFiles.length; i++) {
    const reportPath = reportFiles[i];
    const ciUrl = ciUrls && ciUrls[i] ? ciUrls[i] : null;
    const parsed = readJsonFile(reportPath);

    if (!parsed.ok) {
      console.error(`Failed to read ${reportPath}: ${parsed.error}`);
      continue;
    }

    const report = parsed.value;
    const platform = report.platform;
    const normalizedPlatform = PLATFORM_ALIASES[platform] || platform;

    if (!matrix[platform]) {
      matrix[platform] = {};
      metadata.platforms.push(normalizedPlatform);
    }

    metadata.verifier_versions.push(report.verifier_version);
    if (report.evaluated_at) {
      metadata.evaluated_at.push(report.evaluated_at);
    }

    if (report.profiles) {
      for (const prop of PROPERTIES) {
        const profile = report.profiles[prop];
        if (profile && profile.status) {
          matrix[platform][prop] = {
            status: profile.status,
            ciUrl: ciUrl,
          };
        }
      }
    }
  }

  return { matrix, metadata };
}

function generateMarkdown(matrix, metadata) {
  const platforms = Object.keys(matrix);
  const sortedPlatforms = platforms.sort();

  let lines = [];
  lines.push("# Platform Property Matrix");
  lines.push("");
  lines.push("## Scope");
  lines.push("");
  lines.push("**Tier-0 (agentless) capability profiles** — per-platform verification of core GraphSmith capabilities (R/E/B/T/G/Q/X).");
  lines.push("");
  lines.push("Agent-family matrix rows are added separately by the maintainer through per-agent verification runs (plan §16).");
  lines.push("");
  lines.push("## Legend");
  lines.push("");
  lines.push("| Status | Meaning |");
  lines.push("|--------|---------|");
  lines.push("| verified | Capability is verified on this platform |");
  lines.push("| unavailable | Capability cannot be proven on this platform (not a pass — honest gap) |");
  lines.push("| failed | Capability verification failed |");
  lines.push("| not-applicable | Capability does not apply to this platform |");
  lines.push("");
  lines.push("## Matrix");
  lines.push("");

  lines.push("| Property | " + sortedPlatforms.map((p) => PLATFORM_ALIASES[p] || p).join(" | ") + " |");
  lines.push("|----------|" + sortedPlatforms.map(() => "----------|").join(""));

  for (const prop of PROPERTIES) {
    const row = [prop];
    for (const platform of sortedPlatforms) {
      const cell = matrix[platform] && matrix[platform][prop];
      if (cell && cell.status) {
        row.push(formatStatus(cell.status, cell.ciUrl));
      } else {
        row.push(formatStatus("unavailable", null));
      }
    }
    lines.push("| " + row.join(" | ") + " |");
  }

  lines.push("");
  lines.push("## Metadata");
  lines.push("");
  lines.push(`- Schema version: ${SCHEMA_VERSION}`);
  lines.push(`- Platforms: ${metadata.platforms.filter((v, i, a) => a.indexOf(v) === i).join(", ")}`);
  if (metadata.verifier_versions.length > 0) {
    const uniqueVersions = [...new Set(metadata.verifier_versions)].sort();
    lines.push(`- Verifier versions: ${uniqueVersions.join(", ")}`);
  }
  if (metadata.evaluated_at.length > 0) {
    const sortedDates = [...new Set(metadata.evaluated_at)].sort();
    lines.push(`- Evaluated at: ${sortedDates.join(", ")}`);
  }

  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("Generated by `scripts/matrix.js` — see plan §8/F22 for details.");

  return lines.join("\n");
}

function generateJson(matrix, metadata) {
  const platforms = Object.keys(matrix).sort();
  const output = {
    schema_version: SCHEMA_VERSION,
    generated_at: new Date().toISOString(),
    scope: "Tier-0 (agentless) capability profiles",
    note: "Agent-family matrix rows are added separately by the maintainer (plan §16)",
    platforms: platforms.map((p) => PLATFORM_ALIASES[p] || p),
    properties: PROPERTIES,
    metadata: {
      platforms: metadata.platforms.filter((v, i, a) => a.indexOf(v) === i),
      verifier_versions: [...new Set(metadata.verifier_versions)].sort(),
      evaluated_at: [...new Set(metadata.evaluated_at)].sort(),
    },
    matrix: {},
  };

  for (const platform of platforms) {
    const normalizedPlatform = PLATFORM_ALIASES[platform] || platform;
    output.matrix[normalizedPlatform] = {};
    for (const prop of PROPERTIES) {
      const cell = matrix[platform] && matrix[platform][prop];
      if (cell && cell.status) {
        output.matrix[normalizedPlatform][prop] = {
          status: cell.status,
          ci_url: validateCiUrl(cell.ciUrl) ? cell.ciUrl : null,
        };
      } else {
        output.matrix[normalizedPlatform][prop] = {
          status: "unavailable",
          ci_url: null,
        };
      }
    }
  }

  return output;
}

function ensureDir(dirPath) {
  try {
    fs.mkdirSync(dirPath, { recursive: true });
  } catch (e) {
    if (e.code !== "EEXIST") throw e;
  }
}

function runSelftest() {
  console.log("=== Running selftest ===\n");

  const tmpDir = path.join(".", ".tmp", "matrix-selftest");
  ensureDir(tmpDir);

  const report1 = {
    schema_version: "1.0",
    command: "profiles",
    verifier_version: "1.0",
    platform: "darwin",
    node_version: "v18.0.0",
    root: "/fake/root",
    evaluated_at: "2024-01-15T10:30:00Z",
    evaluated_at_source: "SOURCE_DATE_EPOCH",
    profiles: {
      R: { status: "verified", evidence: ["Test evidence"], assumptions: [] },
      E: { status: "verified", evidence: [], assumptions: [] },
      B: { status: "verified", evidence: [], assumptions: [] },
      T: { status: "verified", evidence: [], assumptions: [] },
      G: { status: "verified", evidence: [], assumptions: [] },
      Q: { status: "verified", evidence: [], assumptions: [] },
      X: { status: "verified", evidence: [], assumptions: [] },
    },
    profile_string: "R:verified E:verified B:verified T:verified G:verified Q:verified X:verified",
    note: "Test report",
  };

  const report2 = {
    schema_version: "1.0",
    command: "profiles",
    verifier_version: "1.0",
    platform: "linux",
    node_version: "v18.0.0",
    root: "/fake/root",
    evaluated_at: "2024-01-15T10:31:00Z",
    evaluated_at_source: "SOURCE_DATE_EPOCH",
    profiles: {
      R: { status: "verified", evidence: [], assumptions: [] },
      E: { status: "unavailable", evidence: [], assumptions: ["Cannot test on this platform"] },
      B: { status: "verified", evidence: [], assumptions: [] },
      T: { status: "failed", evidence: ["Test failure"], assumptions: [] },
      G: { status: "verified", evidence: [], assumptions: [] },
      Q: { status: "unavailable", evidence: [], assumptions: [] },
      X: { status: "not-applicable", evidence: [], assumptions: [] },
    },
    profile_string: "R:verified E:unavailable B:verified T:failed G:verified Q:unavailable X:not-applicable",
    note: "Test report",
  };

  const report3 = {
    schema_version: "1.0",
    command: "profiles",
    verifier_version: "1.0",
    platform: "win32",
    node_version: "v18.0.0",
    root: "C:\\fake\\root",
    evaluated_at: "2024-01-15T10:32:00Z",
    evaluated_at_source: "SOURCE_DATE_EPOCH",
    profiles: {
      R: { status: "verified", evidence: [], assumptions: [] },
      E: { status: "verified", evidence: [], assumptions: [] },
      B: { status: "unavailable", evidence: [], assumptions: [] },
      T: { status: "verified", evidence: [], assumptions: [] },
      G: { status: "verified", evidence: [], assumptions: [] },
      Q: { status: "verified", evidence: [], assumptions: [] },
      X: { status: "verified", evidence: [], assumptions: [] },
    },
    profile_string: "R:verified E:verified B:unavailable T:verified G:verified Q:verified X:verified",
    note: "Test report",
  };

  const report4 = {
    schema_version: "1.0",
    command: "profiles",
    verifier_version: "1.0",
    platform: "darwin",
    node_version: "v18.0.0",
    root: "/fake/root",
    evaluated_at: "2024-01-15T10:33:00Z",
    evaluated_at_source: "SOURCE_DATE_EPOCH",
    profiles: {
      R: {
        status: "verified",
        evidence: [
          'Normal evidence',
          '<script>alert("XSS")</script>',
          '"quote test"',
          "'single quote'",
          '<img src=x onerror="alert(1)">',
        ],
        assumptions: [],
      },
      E: { status: "verified", evidence: [], assumptions: [] },
      B: { status: "verified", evidence: [], assumptions: [] },
      T: { status: "verified", evidence: [], assumptions: [] },
      G: { status: "verified", evidence: [], assumptions: [] },
      Q: { status: "verified", evidence: [], assumptions: [] },
      X: { status: "verified", evidence: [], assumptions: [] },
    },
    profile_string: "R:verified E:verified B:verified T:verified G:verified Q:verified X:verified",
    note: "Test report with malicious payloads in evidence",
  };

  const report1Path = path.join(tmpDir, "report-darwin-1.json");
  const report2Path = path.join(tmpDir, "report-linux.json");
  const report3Path = path.join(tmpDir, "report-win32.json");
  const report4Path = path.join(tmpDir, "report-darwin-2.json");

  fs.writeFileSync(report1Path, JSON.stringify(report1));
  fs.writeFileSync(report2Path, JSON.stringify(report2));
  fs.writeFileSync(report3Path, JSON.stringify(report3));
  fs.writeFileSync(report4Path, JSON.stringify(report4));

  const ciUrls = [
    "https://ci.example.com/run/1",
    "https://ci.example.com/run/2",
    "https://ci.example.com/run/3",
    "https://ci.example.com/run/4",
  ];

  const reportFiles = [report1Path, report2Path, report3Path, report4Path];

  const { matrix, metadata } = aggregateReports(reportFiles, ciUrls);

  console.log("Aggregated matrix:");
  console.log(JSON.stringify(matrix, null, 2));
  console.log("\nMetadata:");
  console.log(JSON.stringify(metadata, null, 2));

  const markdown = generateMarkdown(matrix, metadata);
  const json = generateJson(matrix, metadata);

  const mdPath = path.join(tmpDir, "PROPERTY-MATRIX.md");
  const jsonPath = path.join(tmpDir, "property-matrix.json");

  fs.writeFileSync(mdPath, markdown);
  fs.writeFileSync(jsonPath, JSON.stringify(json, null, 2));

  console.log("\n=== Security verification ===");
  console.log("Checking for unescaped evidence in Markdown output...");
  const mdContent = fs.readFileSync(mdPath, "utf8");
  const hasUnescapedScript = mdContent.includes('<script>') || mdContent.includes('onerror=');
  const hasUnescapedImg = mdContent.includes('<img') && !mdContent.includes('&lt;img');
  const hasUnescapedQuotes = mdContent.includes('"quote test"') && !mdContent.includes('&quot;quote test&quot;');
  console.log(`- Unescaped <script> tags found: ${hasUnescapedScript ? "FAIL" : "PASS"}`);
  console.log(`- Unescaped <img> tags found: ${hasUnescapedImg ? "FAIL" : "PASS"}`);
  console.log(`- Unescaped quotes found: ${hasUnescapedQuotes ? "FAIL" : "PASS"}`);

  if (hasUnescapedScript || hasUnescapedImg || hasUnescapedQuotes) {
    console.error("\n❌ SELFTEST FAILED: Unescaped content detected in Markdown output");
    process.exit(1);
  }

  console.log("\n✅ SELFTEST PASSED");
  console.log("\nGenerated files:");
  console.log(`- Markdown: ${mdPath}`);
  console.log(`- JSON: ${jsonPath}`);

  console.log("\n=== Markdown output preview ===");
  console.log(markdown.substring(0, 2000) + (markdown.length > 2000 ? "\n... (truncated)" : ""));

  return true;
}

function main(argv) {
  const selftestIndex = argv.indexOf("--selftest");
  if (selftestIndex !== -1) {
    const success = runSelftest();
    process.exit(success ? 0 : 1);
  }

  const reportArgs = [];
  const ciUrlArgs = [];

  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--ci-run-url=")) {
      ciUrlArgs.push(argv[i].substring("--ci-run-url=".length));
    } else if (argv[i] === "--ci-run-url" && i + 1 < argv.length) {
      ciUrlArgs.push(argv[i + 1]);
      i++;
    } else if (!argv[i].startsWith("-") && argv[i] !== "matrix.js") {
      reportArgs.push(argv[i]);
    }
  }

  if (reportArgs.length === 0) {
    console.error("Usage: node scripts/matrix.js [--selftest] [--ci-run-url=<url>] <report1.json> [report2.json ...]");
    console.error("       node scripts/matrix.js --selftest");
    process.exit(1);
  }

  const ciUrls = ciUrlArgs.length >= reportArgs.length ? ciUrlArgs.slice(0, reportArgs.length) : [];
  for (let i = ciUrls.length; i < reportArgs.length; i++) {
    ciUrls.push(null);
  }

  const { matrix, metadata } = aggregateReports(reportArgs, ciUrls);

  const markdown = generateMarkdown(matrix, metadata);
  const json = generateJson(matrix, metadata);

  const docsDir = path.join(".", "docs");
  ensureDir(docsDir);

  const mdPath = path.join(docsDir, "PROPERTY-MATRIX.md");
  const jsonPath = path.join(docsDir, "property-matrix.json");

  fs.writeFileSync(mdPath, markdown);
  fs.writeFileSync(jsonPath, JSON.stringify(json, null, 2));

  console.log(`Generated ${mdPath}`);
  console.log(`Generated ${jsonPath}`);
}

if (require.main === module) {
  main(process.argv.slice(2));
}

module.exports = {
  aggregateReports,
  generateMarkdown,
  generateJson,
  validateCiUrl,
  escapeHtml,
  escapeMarkdown,
  SCHEMA_VERSION,
};