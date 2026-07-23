const fs = require('fs');
const path = require('path');
const badge = require('../../../scripts/badge.js');

const COLORS = {
  green: '#3fb950',
  red: '#da3633',
  grey: '#8b949e',
  stale: '#d29922',
};

const REF = '2026-07-23T00:00:00.000Z';
const FRESH_DATE = '2026-07-22T00:00:00.000Z';
const OLD_DATE = '2026-01-01T00:00:00.000Z';

let failed = false;
let log = [];

function assert(cond, msg) {
  if (cond) {
    log.push(`PASS: ${msg}`);
  } else {
    log.push(`FAIL: ${msg}`);
    failed = true;
  }
}

function mkReport(platform, statuses, evaluatedAt, extraEvidence) {
  const profiles = {};
  for (const k of ['R', 'E', 'B', 'T', 'G', 'Q', 'X']) {
    profiles[k] = {
      status: statuses[k] || 'unavailable',
      evidence: extraEvidence ? [{ check: 'x', detail: extraEvidence }] : [],
      assumptions: extraEvidence ? [extraEvidence] : [],
    };
  }
  return { schema_version: '1.0', verifier_version: '1.0', platform, node_version: 'v20', evaluated_at: evaluatedAt, profiles };
}

console.log("=== ADVERSARIAL TEST SUITE: scripts/badge.js ===");

// 1. UNAVAILABLE/NOT-APPLICABLE/FAILED NEVER GREEN
console.log("\n[1] ATTACK: False Green (unavailable/not-applicable/failed)");
const rep1 = mkReport('linux', { R: 'unavailable', E: 'failed', B: 'not-applicable' }, FRESH_DATE);
const m1 = badge.buildModel([rep1], { maxAgeDays: 30, now: REF });
const svg1 = badge.renderSVG(m1);
assert(m1.profiles.R.color !== COLORS.green, "unavailable R is not green");
assert(m1.profiles.R.aggregate === 'unavailable', "unavailable R remains unavailable");
assert(m1.profiles.E.color !== COLORS.green, "failed E is not green");
assert(m1.profiles.B.color !== COLORS.green, "not-applicable B is not green");

// Force a false green manually via effectiveStatus
const effUnavailable = badge.effectiveStatus('unavailable', 'fresh');
assert(effUnavailable.color !== COLORS.green, "effectiveStatus('unavailable') is not green");
const effNotApplicable = badge.effectiveStatus('not-applicable', 'fresh');
assert(effNotApplicable.color !== COLORS.green, "effectiveStatus('not-applicable') is not green");

// 2. STALE-DOWNGRADE + NO-CLOCK
console.log("\n[2] ATTACK: Stale-Downgrade & No-Clock");
const rep2_old = mkReport('linux', { R: 'verified' }, OLD_DATE);
const m2_old = badge.buildModel([rep2_old], { maxAgeDays: 30, now: REF });
assert(m2_old.profiles.R.aggregate !== 'verified', "Old evidence downgrades verified to unavailable aggregate or stale");
assert(m2_old.profiles.R.color !== COLORS.green, "Old evidence verified profile is not green");
assert(m2_old.overallState === 'stale', "Old evidence overall state is stale");

const rep2_unav = mkReport('linux', { R: 'verified' }, 'unavailable');
const m2_unav = badge.buildModel([rep2_unav], { maxAgeDays: 30, now: REF });
assert(m2_unav.platforms[0].freshness.state === 'unattested', "evaluated_at='unavailable' is unattested");
assert(m2_unav.profiles.R.color !== COLORS.green, "unattested verified is not green");

const rep2_fresh = mkReport('linux', { R: 'verified' }, FRESH_DATE);
const m2_noref = badge.buildModel([rep2_fresh], { maxAgeDays: 30, now: null }); // process.env cleared in next lines?
assert(m2_noref.platforms[0].freshness.state === 'unattested', "Fresh evidence without reference date is unattested");

// Check source for Date.now() or new Date() without arguments
const source = fs.readFileSync(path.join(__dirname, '../../../scripts/badge.js'), 'utf8');
assert(!source.match(/Date\.now\(\)/) && !source.match(/new Date\(\)/), "No clock read (Date.now() or new Date()) in source");

// 3. INJECTION / XSS DEFENSE & validateCiUrl Bypass
console.log("\n[3] ATTACK: Injection & CI-RUN-URL schemes");
const payload = '<script>alert(1)</script><img src=x onerror=alert("xss")>';
const rep3 = mkReport('linux', { R: 'verified' }, FRESH_DATE, payload);
rep3.platform = 'linux" onload="attack()';
rep3.verifier_version = '1.0&<';
const m3 = badge.buildModel([rep3], { maxAgeDays: 30, now: REF, ciRunUrl: 'javascript:alert(1)' });
const svg3 = badge.renderSVG(m3);
assert(!svg3.includes('<script>'), "SVG contains NO unescaped <script>");
assert(!svg3.includes('onerror='), "SVG contains NO unescaped onerror=");
assert(!svg3.includes(payload), "Raw payload is never embedded");

// The evidence free text is never rendered at all, so we check that the 
// poisoned platform metadata is properly XML escaped.
assert(svg3.includes('&lt;'), "Poisoned platform metadata is XML escaped");

// CI-RUN-URL Scheme validation attacks
const hostileUrls = [
  'javascript:alert(1)',
  ' javascript:alert(1)',
  '\tjavascript:alert(1)',
  'java\nscript:alert(1)',
  'JAVASCRIPT:alert(1)',
  'data:text/html,<script>',
  'vbscript:msgbox(1)',
  'file:///etc/passwd',
  'ftp://example',
  'relative/path',
  '/absolute/path',
  'http:evil',
  'https:@',
  '//evil',
  'https ://evil',
  'https://\x00'
];
let allHostileBlocked = true;
for (const url of hostileUrls) {
  const m = badge.buildModel([rep1], { maxAgeDays: 30, now: REF, ciRunUrl: url });
  if (m.ciRunUrlIsLink) {
    console.log(`Failed to block URL: ${url}`);
    allHostileBlocked = false;
  }
}
assert(allHostileBlocked, "All hostile/malformed CI run URLs blocked from being a link");

const goodUrl = 'https://github.com/run/123';
const mGoodUrl = badge.buildModel([rep1], { maxAgeDays: 30, now: REF, ciRunUrl: goodUrl });
assert(mGoodUrl.ciRunUrlIsLink, "Valid https:// URL is accepted as a link");
const svgGood = badge.renderSVG(mGoodUrl);
assert(svgGood.includes('<a xlink:href="https://github.com/run/123"'), "Valid link is embedded as a tag");

// 4. ENUM COERCION & Export Checks
console.log("\n[4] ATTACK: Enum Coercion & Export Checks");
assert(badge.enumStatus('verified') === 'verified', "enumStatus('verified') is verified");
assert(badge.enumStatus('unknown-status') === 'unavailable', "enumStatus('unknown-status') coerced to unavailable");
assert(badge.safe(null, 10) === '', "safe(null) is empty string");
assert(badge.xmlEscape('<>"&\'') === '&lt;&gt;&quot;&amp;&#39;', "xmlEscape escapes all special characters");
const rep4 = mkReport('linux', { R: 'super-verified', E: 'almost-failed', B: '', T: null }, FRESH_DATE);
const m4 = badge.buildModel([rep4], { maxAgeDays: 30, now: REF });
assert(m4.profiles.R.aggregate === 'unavailable', "Unknown status 'super-verified' coerced to unavailable");
assert(m4.profiles.E.aggregate === 'unavailable', "Unknown status 'almost-failed' coerced to unavailable");
assert(m4.profiles.B.aggregate === 'unavailable', "Empty status coerced to unavailable");
assert(m4.profiles.T.aggregate === 'unavailable', "Null status coerced to unavailable");

// 5. MULTI-PLATFORM NOT COLLAPSED
console.log("\n[5] ATTACK: Multi-platform collapse");
const rep5_linux = mkReport('linux', { R: 'verified' }, FRESH_DATE);
const rep5_win = mkReport('windows', { R: 'unavailable' }, FRESH_DATE);
const m5 = badge.buildModel([rep5_linux, rep5_win], { maxAgeDays: 30, now: REF });
assert(m5.profiles.R.aggregate === 'unavailable', "verified(linux) + unavailable(windows) -> aggregate unavailable");
assert(m5.profiles.R.color !== COLORS.green, "aggregate verified(linux) + unavailable(windows) is not green");
assert(m5.platforms.length === 2, "Both platforms retained in model");
const d5 = badge.buildDescriptor(m5);
assert(d5.profiles.R.platforms.linux.status === 'verified', "Linux verified status preserved in descriptor");
assert(d5.profiles.R.platforms.windows.status === 'unavailable', "Windows unavailable status preserved in descriptor");

console.log("\n=== FINDINGS ===");
log.forEach(l => console.log(l));

if (failed) {
  console.log("\nSTATUS: FAIL - Some attacks bypassed the defenses.");
  process.exit(1);
} else {
  console.log("\nSTATUS: PASS - All attacks successfully mitigated.");
  process.exit(0);
}
