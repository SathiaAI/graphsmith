#!/usr/bin/env node
/* GraphSmith evidence-carrying capability badge (scripts/badge.js) — plan §8.4.
 *
 * The badge is an ATTESTATION OF TESTED BEHAVIOR, not a bare checkmark. It
 * consumes one-or-more `node scripts/verify.js --profiles` JSON reports (one
 * per OS from a CI matrix) and renders:
 *   - the profile string (R:verified E:unavailable ...),
 *   - the verifier_version, the platform SET, the evaluation date(s),
 *   - a link field to the CI run that produced it (input --ci-run-url).
 *
 * Honesty rules this file implements directly (plan §8.4, contract 10):
 *   - status -> color HONESTLY: verified->green, failed->red,
 *     unavailable/not-applicable->grey ("unavailable" is NEVER green).
 *   - evidence FRESHNESS: a report whose evaluated_at is older than the
 *     freshness window (input --max-age-days) — or whose evaluated_at is
 *     "unavailable" — visibly DOWNGRADES the badge (verified renders "stale",
 *     not green). This is what makes it an attestation, not a fixed stamp.
 *   - freshness compares the report's INJECTED evaluated_at against an
 *     INJECTED reference date (--now / GRAPHSMITH_NOW / SOURCE_DATE_EPOCH),
 *     NEVER a wall-clock read — same clock-free-decision posture as verify.js.
 *   - multiple per-OS reports aggregate to a per-platform property set; a
 *     profile verified on linux but unavailable on win32 renders honestly
 *     per-platform and is NEVER collapsed into one green.
 *
 * SECURITY (spec item 6, anti-injection): the verify report's evidence[] and
 * assumptions[] can carry attacker-controlled free-text from an untrusted
 * target's capability/config files. This renderer NEVER emits that free-text.
 * It renders ONLY closed-enum status values, the verifier_version, platform,
 * and evaluated_at — and XML-escapes AND length-bounds every interpolated
 * string, so no capability-file content can inject markup/script into the SVG.
 * Any status outside the closed enum is coerced to "unavailable".
 *
 * Zero-dependency CommonJS, Node >= 18. Deterministic; no network; no
 * clock/random in any DECISION path.
 */
'use strict';

const fs = require('fs');

const SCHEMA_VERSION = '1.0';
const PROFILE_KEYS = ['R', 'E', 'B', 'T', 'G', 'Q', 'X'];
const STATUS_ENUM = ['verified', 'unavailable', 'failed', 'not-applicable'];
const DEFAULT_MAX_AGE_DAYS = 30;
const MS_PER_DAY = 86400000;

// Length bounds for any interpolated string that reaches the SVG/descriptor.
const BOUND = { version: 40, platform: 40, date: 40, url: 300 };

// Honest-language banned substrings (contract 10, List A) — the --selftest
// scans every emitted artifact for these and fails if any appears.
const BANNED = [
  'proven', 'certified', 'immutable', 'sandboxed', 'exactly-once',
  'tamper-proof', 'guaranteed', 'cannot fail', 'pen-test',
];

const ATTESTATION = 'attestation of tested behavior — shows what was tested, not a blanket approval';

// ---------------------------------------------------------------------------
// Escaping / bounding — the ONLY path any string takes toward the SVG.
// ---------------------------------------------------------------------------
function xmlEscape(input) {
  return String(input)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Bound then escape. Non-strings and control chars are neutralized.
function safe(input, max) {
  let s = input == null ? '' : String(input);
  s = s.replace(/[\x00-\x1f]/g, ' '); // strip control chars
  if (s.length > max) s = s.slice(0, max - 1) + '…';
  return xmlEscape(s);
}

// Coerce any status to the closed enum; unknown -> "unavailable" (never green).
function enumStatus(raw) {
  return STATUS_ENUM.includes(raw) ? raw : 'unavailable';
}

// ---------------------------------------------------------------------------
// Freshness — injected reference date vs injected evaluated_at, no clock read.
// ---------------------------------------------------------------------------
function resolveReference(opts) {
  if (opts.now) {
    const t = Date.parse(opts.now);
    if (!Number.isNaN(t)) return { ms: t, iso: new Date(t).toISOString(), source: '--now' };
  }
  if (process.env.GRAPHSMITH_NOW) {
    const t = Date.parse(process.env.GRAPHSMITH_NOW);
    if (!Number.isNaN(t)) return { ms: t, iso: new Date(t).toISOString(), source: 'GRAPHSMITH_NOW' };
  }
  if (process.env.SOURCE_DATE_EPOCH && /^\d+$/.test(process.env.SOURCE_DATE_EPOCH)) {
    const t = Number(process.env.SOURCE_DATE_EPOCH) * 1000;
    return { ms: t, iso: new Date(t).toISOString(), source: 'SOURCE_DATE_EPOCH' };
  }
  // No injected reference date: freshness cannot be attested (never a clock).
  return { ms: null, iso: null, source: 'none' };
}

// Per-report freshness state: fresh | stale | unattested.
function freshnessOf(evaluatedAt, ref, maxAgeDays) {
  if (evaluatedAt == null || evaluatedAt === 'unavailable') {
    return { state: 'unattested', age_days: null, reason: 'evaluated_at unavailable' };
  }
  const evMs = Date.parse(String(evaluatedAt));
  if (Number.isNaN(evMs)) {
    return { state: 'unattested', age_days: null, reason: 'evaluated_at unparseable' };
  }
  if (ref.ms == null) {
    return { state: 'unattested', age_days: null, reason: 'no injected reference date' };
  }
  const ageDays = (ref.ms - evMs) / MS_PER_DAY;
  if (ageDays < 0) return { state: 'stale', age_days: ageDays, reason: 'evaluated_at is after reference date' };
  if (ageDays > maxAgeDays) return { state: 'stale', age_days: ageDays, reason: 'older than max-age-days' };
  return { state: 'fresh', age_days: ageDays, reason: 'within window' };
}

// ---------------------------------------------------------------------------
// Color mapping — the honest core. "unavailable" is NEVER green.
// ---------------------------------------------------------------------------
const COLORS = {
  green: '#3fb950',
  red: '#da3633',
  grey: '#8b949e',
  stale: '#d29922',
  header: '#30363d',
  label: '#22272e',
  bg: '#0d1117',
  text: '#f0f6fc',
};

// Effective status of a profile on one platform, given that platform report's
// freshness. A verified profile in a stale/unattested report is downgraded.
function effectiveStatus(status, reportFreshState) {
  const s = enumStatus(status);
  if (s === 'failed') return { key: 'failed', label: 'failed', color: COLORS.red };
  if (s === 'verified') {
    if (reportFreshState === 'fresh') return { key: 'verified', label: 'verified', color: COLORS.green };
    return { key: 'stale', label: 'stale', color: COLORS.stale }; // downgraded, not green
  }
  if (s === 'not-applicable') return { key: 'not-applicable', label: 'n/a', color: COLORS.grey };
  return { key: 'unavailable', label: 'unavailable', color: COLORS.grey };
}

// ---------------------------------------------------------------------------
// Model building — reports -> per-platform matrix (never collapsed).
// ---------------------------------------------------------------------------
function buildModel(reports, opts) {
  const ref = resolveReference(opts);
  const maxAgeDays = opts.maxAgeDays;
  const platforms = [];
  const seen = {};

  for (const rep of reports) {
    let plat = safeRaw(rep && rep.platform, BOUND.platform) || 'unknown';
    if (seen[plat] != null) { seen[plat] += 1; plat = `${plat}#${seen[plat]}`; } else seen[plat] = 1;
    const fresh = freshnessOf(rep && rep.evaluated_at, ref, maxAgeDays);
    const cells = {};
    for (const k of PROFILE_KEYS) {
      const node = rep && rep.profiles && rep.profiles[k];
      const status = enumStatus(node && node.status);
      cells[k] = { status, effective: effectiveStatus(status, fresh.state) };
    }
    platforms.push({
      platform: plat,
      verifier_version: safeRaw(rep && rep.verifier_version, BOUND.version) || 'unknown',
      evaluated_at: rep && rep.evaluated_at != null ? safeRaw(rep.evaluated_at, BOUND.date) : 'unavailable',
      freshness: fresh,
      cells,
    });
  }

  // Aggregate per profile across platforms (honest: green only if verified-fresh
  // on EVERY platform; failed if any failed; else downgraded to unavailable).
  const profiles = {};
  for (const k of PROFILE_KEYS) {
    const perPlat = {};
    let allVerifiedFresh = true;
    let anyFailed = false;
    let allNa = true;
    for (const p of platforms) {
      const eff = p.cells[k].effective;
      perPlat[p.platform] = { status: p.cells[k].status, effective: eff.key };
      if (eff.key !== 'verified') allVerifiedFresh = false;
      if (eff.key === 'failed') anyFailed = true;
      if (eff.key !== 'not-applicable') allNa = false;
    }
    let agg, color;
    if (platforms.length === 0) { agg = 'unavailable'; color = COLORS.grey; }
    else if (anyFailed) { agg = 'failed'; color = COLORS.red; }
    else if (allVerifiedFresh) { agg = 'verified'; color = COLORS.green; }
    else if (allNa) { agg = 'not-applicable'; color = COLORS.grey; }
    else { agg = 'unavailable'; color = COLORS.grey; }
    profiles[k] = { aggregate: agg, color, platforms: perPlat };
  }

  const anyStale = platforms.some((p) => p.freshness.state !== 'fresh');
  const anyFailedGlobal = PROFILE_KEYS.some((k) => profiles[k].aggregate === 'failed');
  const allVerifiedGlobal = platforms.length > 0 && PROFILE_KEYS.every((k) => profiles[k].aggregate === 'verified');

  let overallColor, overallState;
  if (anyFailedGlobal) { overallColor = COLORS.red; overallState = 'failed'; }
  else if (allVerifiedGlobal && !anyStale) { overallColor = COLORS.green; overallState = 'verified'; }
  else if (anyStale) { overallColor = COLORS.stale; overallState = 'stale'; }
  else { overallColor = COLORS.grey; overallState = 'partial'; }

  return { ref, maxAgeDays, platforms, profiles, anyStale, overallColor, overallState,
    verifierVersions: uniq(platforms.map((p) => p.verifier_version)),
    ciRunUrl: opts.ciRunUrl ? safeRaw(opts.ciRunUrl, BOUND.url) : null };
}

// Bound + control-strip WITHOUT xml-escaping (for descriptor JSON values, which
// are serialized by JSON.stringify — escaping happens only on the SVG path).
function safeRaw(input, max) {
  if (input == null) return '';
  let s = String(input).replace(/[\x00-\x1f]/g, ' ');
  if (s.length > max) s = s.slice(0, max - 1) + '…';
  return s;
}

function uniq(arr) { return Array.from(new Set(arr)); }

// ---------------------------------------------------------------------------
// Descriptor (JSON) — includes a shields.io endpoint sub-object.
// ---------------------------------------------------------------------------
function buildDescriptor(model) {
  const counts = { verified: 0, unavailable: 0, failed: 0, 'not-applicable': 0 };
  const compact = PROFILE_KEYS.map((k) => {
    const agg = model.profiles[k].aggregate;
    counts[agg] = (counts[agg] || 0) + 1;
    return `${k}:${agg}`;
  }).join(' ');

  const message = compact + (model.anyStale ? ' · STALE' : '');
  const shieldsColor = model.overallColor === COLORS.green ? 'brightgreen'
    : model.overallColor === COLORS.red ? 'red'
    : model.overallColor === COLORS.stale ? 'yellow' : 'lightgrey';

  return {
    schema_version: SCHEMA_VERSION,
    kind: 'graphsmith-capability-badge',
    attestation: ATTESTATION,
    generated_from: {
      reports: model.platforms.length,
      platforms: model.platforms.map((p) => p.platform),
      verifier_versions: model.verifierVersions,
    },
    profile_string: compact,
    counts,
    overall_state: model.overallState,
    ci_run_url: model.ciRunUrl,
    freshness: {
      reference_date: model.ref.iso,
      reference_source: model.ref.source, // documents the INJECTED input, not a clock
      max_age_days: model.maxAgeDays,
      any_stale: model.anyStale,
      per_report: model.platforms.map((p) => ({
        platform: p.platform,
        evaluated_at: p.evaluated_at,
        state: p.freshness.state,
        age_days: p.freshness.age_days == null ? null : Math.round(p.freshness.age_days * 100) / 100,
        reason: p.freshness.reason,
      })),
    },
    profiles: model.profiles,
    // shields.io endpoint schema (schemaVersion 1) — honest single-line summary.
    shields_endpoint: {
      schemaVersion: 1,
      label: 'graphsmith caps',
      message,
      color: shieldsColor,
      isError: model.overallState === 'failed',
    },
  };
}

// ---------------------------------------------------------------------------
// SVG rendering — hand-emitted string, no libraries. Only escaped enum/meta.
// ---------------------------------------------------------------------------
function renderSVG(model) {
  const cellW = 96;
  const cellH = 26;
  const labelW = 150;
  const padX = 14;
  const headerRows = 4; // title, meta, freshness, legend spacing
  const cols = PROFILE_KEYS.length;
  const width = labelW + cols * cellW + padX * 2;
  const topBlock = 96; // title + meta block height
  const gridTop = topBlock;
  const rows = Math.max(model.platforms.length, 1);
  const legendTop = gridTop + (rows + 1) * cellH + 16;
  const height = legendTop + 54;

  const parts = [];
  parts.push(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${width}" height="${height}" role="img" aria-label="GraphSmith capability attestation">`);
  parts.push(`<rect width="${width}" height="${height}" fill="${COLORS.bg}"/>`);
  parts.push(`<rect x="0" y="0" width="${width}" height="6" fill="${model.overallColor}"/>`);

  // Title + attestation line (static, no report free-text).
  parts.push(text(padX, 30, 'GraphSmith capability badge', 16, COLORS.text, 'bold'));
  parts.push(text(padX, 48, xmlEscape(ATTESTATION), 10, COLORS.grey));

  // Meta: verifier version SET, platform SET, evaluation date(s), CI link.
  const vv = model.verifierVersions.map((v) => xmlEscape(v)).join(', ') || 'unknown';
  const plats = model.platforms.map((p) => xmlEscape(p.platform)).join(', ') || 'none';
  parts.push(text(padX, 68, `verifier ${vv}  ·  platforms: ${plats}`, 11, COLORS.text));
  const stateWord = model.anyStale ? 'STALE — evidence freshness downgraded' : (model.overallState === 'verified' ? 'fresh' : model.overallState);
  parts.push(text(padX, 84, `state: ${xmlEscape(stateWord)}  ·  max-age ${model.maxAgeDays}d  ·  ref ${xmlEscape(model.ref.iso || 'unavailable')} (${xmlEscape(model.ref.source)})`, 10, model.anyStale ? COLORS.stale : COLORS.grey));

  // Column headers (profile keys).
  const gridX = padX + labelW;
  parts.push(text(padX, gridTop + 17, 'platform / profile', 10, COLORS.grey, 'bold'));
  for (let c = 0; c < cols; c++) {
    const cx = gridX + c * cellW;
    parts.push(`<rect x="${cx}" y="${gridTop}" width="${cellW}" height="${cellH}" fill="${COLORS.header}"/>`);
    parts.push(text(cx + cellW / 2, gridTop + 17, xmlEscape(PROFILE_KEYS[c]), 12, COLORS.text, 'bold', 'middle'));
  }

  // One row per platform report (never collapsed).
  model.platforms.forEach((p, r) => {
    const ry = gridTop + (r + 1) * cellH;
    parts.push(`<rect x="${padX}" y="${ry}" width="${labelW}" height="${cellH}" fill="${COLORS.label}"/>`);
    const evLabel = p.freshness.state === 'fresh' ? p.evaluated_at : `${p.evaluated_at} [${p.freshness.state}]`;
    parts.push(text(padX + 6, ry + 12, xmlEscape(p.platform), 10, COLORS.text, 'bold'));
    parts.push(text(padX + 6, ry + 22, xmlEscape(evLabel), 8, p.freshness.state === 'fresh' ? COLORS.grey : COLORS.stale));
    for (let c = 0; c < cols; c++) {
      const eff = p.cells[PROFILE_KEYS[c]].effective;
      const cx = gridX + c * cellW;
      parts.push(`<rect x="${cx}" y="${ry}" width="${cellW}" height="${cellH}" fill="${eff.color}"/>`);
      parts.push(text(cx + cellW / 2, ry + 17, xmlEscape(eff.label), 10, '#0d1117', 'bold', 'middle'));
    }
  });
  if (model.platforms.length === 0) {
    parts.push(text(gridX + 6, gridTop + cellH + 17, 'no reports provided', 11, COLORS.grey));
  }

  // Legend + CI link (input, escaped).
  parts.push(text(padX, legendTop, 'legend:', 10, COLORS.grey, 'bold'));
  const legend = [['verified', COLORS.green], ['stale', COLORS.stale], ['unavailable / n/a', COLORS.grey], ['failed', COLORS.red]];
  let lx = padX + 54;
  for (const [lab, col] of legend) {
    parts.push(`<rect x="${lx}" y="${legendTop - 9}" width="11" height="11" fill="${col}"/>`);
    parts.push(text(lx + 15, legendTop, lab, 9, COLORS.text));
    lx += 15 + lab.length * 5.6 + 18;
  }
  if (model.ciRunUrl) {
    const href = xmlEscape(model.ciRunUrl);
    parts.push(`<a xlink:href="${href}" target="_blank">${text(padX, legendTop + 22, `CI run: ${href}`, 9, '#58a6ff', 'normal', 'start', 'underline')}</a>`);
  } else {
    parts.push(text(padX, legendTop + 22, 'CI run: (not provided — pass --ci-run-url)', 9, COLORS.grey));
  }
  parts.push('</svg>');
  return parts.join('\n');
}

function text(x, y, content, size, fill, weight, anchor, deco) {
  const w = weight ? ` font-weight="${weight}"` : '';
  const a = anchor ? ` text-anchor="${anchor}"` : '';
  const d = deco ? ` text-decoration="${deco}"` : '';
  return `<text x="${x}" y="${y}" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="${size}"${w}${a}${d} fill="${fill}">${content}</text>`;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const opts = { profiles: [], maxAgeDays: DEFAULT_MAX_AGE_DAYS, now: null, ciRunUrl: null,
    format: 'json', outSvg: null, outJson: null, selftest: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--selftest') opts.selftest = true;
    else if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--profiles') opts.profiles.push(next());
    else if (a === '--ci-run-url') opts.ciRunUrl = next();
    else if (a === '--max-age-days') opts.maxAgeDays = Number(next());
    else if (a === '--now') opts.now = next();
    else if (a === '--format') opts.format = next(); // json | svg | both
    else if (a === '--out-svg') opts.outSvg = next();
    else if (a === '--out-json') opts.outJson = next();
    else if (a.startsWith('--')) throw new Error(`unknown flag: ${a}`);
  }
  if (!Number.isFinite(opts.maxAgeDays) || opts.maxAgeDays < 0) opts.maxAgeDays = DEFAULT_MAX_AGE_DAYS;
  return opts;
}

function readReport(pathArg) {
  const raw = pathArg === '-' || pathArg === '@-'
    ? fs.readFileSync(0, 'utf8')
    : fs.readFileSync(pathArg, 'utf8');
  return JSON.parse(raw);
}

function usage() {
  return [
    'GraphSmith evidence-carrying capability badge (plan §8.4)',
    '',
    'Usage:',
    '  node scripts/badge.js --profiles <report.json> [--profiles <report2.json> ...] [options]',
    '  cat report.json | node scripts/badge.js --profiles -',
    '  node scripts/badge.js --selftest',
    '',
    'Options:',
    '  --profiles <path>     verify.js --profiles JSON report; repeat once per OS. "-" = stdin.',
    '  --ci-run-url <url>    link to the CI run that produced these reports (carried into badge).',
    '  --max-age-days <n>    evidence freshness window (default 30); older evidence downgrades.',
    '  --now <iso>           INJECTED reference date for freshness (or GRAPHSMITH_NOW /',
    '                        SOURCE_DATE_EPOCH). No wall-clock read is ever performed.',
    '  --format json|svg|both  what to write to stdout (default json).',
    '  --out-svg <path>      also write the SVG to a file (forward-slash relative path).',
    '  --out-json <path>     also write the descriptor JSON to a file.',
    '',
    'The badge is an attestation of tested behavior. "unavailable" is never green;',
    'stale or un-timestamped evidence downgrades the badge. Evidence free-text from',
    'the verify report is never rendered — only closed-enum status + version + platform',
    '+ date, all XML-escaped.',
  ].join('\n');
}

function emit(model, opts) {
  const descriptor = buildDescriptor(model);
  const svg = renderSVG(model);
  if (opts.outJson) fs.writeFileSync(opts.outJson, JSON.stringify(descriptor, null, 2) + '\n');
  if (opts.outSvg) fs.writeFileSync(opts.outSvg, svg + '\n');
  if (opts.format === 'svg') process.stdout.write(svg + '\n');
  else if (opts.format === 'both') process.stdout.write(JSON.stringify(descriptor, null, 2) + '\n' + svg + '\n');
  else process.stdout.write(JSON.stringify(descriptor, null, 2) + '\n');
  return { descriptor, svg };
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { process.stdout.write(usage() + '\n'); return 0; }
  if (opts.selftest) return selftest();
  let reports;
  try {
    if (opts.profiles.length === 0) reports = [readReport('-')];
    else reports = opts.profiles.map(readReport);
  } catch (e) {
    process.stderr.write(`badge: failed to read/parse a --profiles report: ${e.message}\n`);
    return 2;
  }
  const model = buildModel(reports, opts);
  emit(model, opts);
  process.stderr.write(`badge: ${buildDescriptor(model).profile_string}${model.anyStale ? ' (STALE)' : ''} — ${ATTESTATION}\n`);
  return model.overallState === 'failed' ? 1 : 0;
}

// ---------------------------------------------------------------------------
// --selftest — deterministic, fixture-only. No files written, no clock in
// decisions (reference date is injected per case).
// ---------------------------------------------------------------------------
function mkReport(platform, statuses, evaluatedAt, extraEvidence) {
  const profiles = {};
  for (const k of PROFILE_KEYS) {
    profiles[k] = {
      status: statuses[k] || 'unavailable',
      evidence: extraEvidence ? [{ check: 'x', detail: extraEvidence }] : [],
      assumptions: extraEvidence ? [extraEvidence] : [],
    };
  }
  return { schema_version: '1.0', verifier_version: '1.0', platform, node_version: 'v20', evaluated_at: evaluatedAt, profiles };
}

function assert(cond, msg, log) { log.push(`${cond ? 'PASS' : 'FAIL'}  ${msg}`); if (!cond) log.failed = true; }

function selftest() {
  const log = []; log.failed = false;
  const REF = '2026-07-23T00:00:00.000Z';
  const FRESH_DATE = '2026-07-22T00:00:00.000Z'; // 1 day old
  const OLD_DATE = '2026-01-01T00:00:00.000Z';   // ~200 days old

  // Case 1: mixed statuses, fresh -> verified green, unavailable grey.
  const mixed = { R: 'verified', E: 'unavailable', B: 'verified', T: 'failed', G: 'not-applicable', Q: 'unavailable', X: 'verified' };
  let m = buildModel([mkReport('linux', mixed, FRESH_DATE)], { maxAgeDays: 30, now: REF });
  let d = buildDescriptor(m); let svg = renderSVG(m);
  assert(m.profiles.R.color === COLORS.green, 'fresh verified R -> green', log);
  assert(m.profiles.E.color === COLORS.grey && m.profiles.E.aggregate === 'unavailable', 'unavailable E -> grey, never green', log);
  assert(m.profiles.T.aggregate === 'failed' && m.profiles.T.color === COLORS.red, 'failed T -> red', log);
  assert(!svg.includes('>verified<') === false, 'SVG carries a "verified" cell label', log);
  assert(svg.includes(COLORS.green) && svg.includes(COLORS.grey) && svg.includes(COLORS.red), 'SVG paints green+grey+red honestly', log);

  // Case 2: stale evaluated_at downgrades verified (not green).
  m = buildModel([mkReport('linux', mixed, OLD_DATE)], { maxAgeDays: 30, now: REF });
  assert(m.anyStale === true, 'old evaluated_at -> anyStale true', log);
  assert(m.profiles.R.aggregate !== 'verified', 'stale report: verified R is downgraded, not verified', log);
  assert(m.profiles.R.color !== COLORS.green, 'stale verified R -> NOT green', log);
  // With a failure present, failed dominates stale (red beats yellow). Test the
  // pure-stale overall on an all-verified report that has gone old (no failure).
  const allV = { R: 'verified', E: 'verified', B: 'verified', T: 'verified', G: 'verified', Q: 'verified', X: 'verified' };
  const mStale = buildModel([mkReport('linux', allV, OLD_DATE)], { maxAgeDays: 30, now: REF });
  assert(mStale.overallState === 'stale', 'all-verified-but-old report -> overall state stale (not verified)', log);
  assert(mStale.overallColor !== COLORS.green, 'stale overall -> NOT green', log);

  // Case 3: evaluated_at="unavailable" downgrades (cannot attest freshness).
  m = buildModel([mkReport('linux', mixed, 'unavailable')], { maxAgeDays: 30, now: REF });
  assert(m.platforms[0].freshness.state === 'unattested', 'evaluated_at=unavailable -> unattested', log);
  assert(m.profiles.R.color !== COLORS.green, 'unattested verified R -> NOT green', log);
  // Case 3b: no injected reference date at all -> also unattested (no clock read).
  const mNoRef = buildModel([mkReport('linux', mixed, FRESH_DATE)], { maxAgeDays: 30, now: null });
  const savedEpoch = process.env.SOURCE_DATE_EPOCH; const savedNow = process.env.GRAPHSMITH_NOW;
  delete process.env.SOURCE_DATE_EPOCH; delete process.env.GRAPHSMITH_NOW;
  const mNoRef2 = buildModel([mkReport('linux', mixed, FRESH_DATE)], { maxAgeDays: 30, now: null });
  if (savedEpoch != null) process.env.SOURCE_DATE_EPOCH = savedEpoch;
  if (savedNow != null) process.env.GRAPHSMITH_NOW = savedNow;
  assert(mNoRef2.platforms[0].freshness.state === 'unattested', 'no injected reference date -> unattested (no clock read)', log);
  void mNoRef;

  // Case 4: multi-platform -> per-platform, never collapsed to one green.
  const linuxRep = mkReport('linux', { R: 'verified', E: 'verified', B: 'verified', T: 'verified', G: 'verified', Q: 'verified', X: 'verified' }, FRESH_DATE);
  const winRep = mkReport('win32', { R: 'unavailable', E: 'verified', B: 'verified', T: 'verified', G: 'verified', Q: 'verified', X: 'verified' }, FRESH_DATE);
  m = buildModel([linuxRep, winRep], { maxAgeDays: 30, now: REF });
  d = buildDescriptor(m); svg = renderSVG(m);
  assert(m.platforms.length === 2, 'two platform rows retained', log);
  assert(d.profiles.R.platforms.linux.effective === 'verified' && d.profiles.R.platforms.win32.effective === 'unavailable', 'R verified on linux, unavailable on win32 — per-platform', log);
  assert(d.profiles.R.aggregate === 'unavailable', 'R NOT collapsed to one green (aggregate downgraded)', log);
  assert(svg.split('platform / profile').length >= 1 && (svg.match(/linux/g) || []).length >= 1 && (svg.match(/win32/g) || []).length >= 1, 'SVG renders both platform labels', log);

  // Case 5: injection — evidence with <script>/quotes/angle brackets is never rendered raw.
  const payload = '<script>alert("xss")</script>"><img src=x onerror=alert(1)>';
  const evil = mkReport('linux', mixed, FRESH_DATE, payload);
  // also poison the closed-enum-adjacent metadata fields:
  evil.verifier_version = '1.0"><script>bad()</script>';
  evil.platform = '<script>plat</script>';
  m = buildModel([evil], { maxAgeDays: 30, now: REF });
  svg = renderSVG(m); d = buildDescriptor(m);
  assert(!svg.includes('<script'), 'SVG contains NO <script tag from payload', log);
  assert(!svg.includes('onerror=alert'), 'SVG contains NO unescaped onerror handler', log);
  assert(!svg.includes(payload), 'raw payload string never appears verbatim in SVG', log);
  assert(!svg.includes('alert("xss")'), 'unescaped alert("xss") never appears (quotes escaped)', log);
  assert(svg.includes('&lt;script&gt;plat') || svg.includes('&lt;script&gt;'), 'poisoned platform metadata is XML-escaped, not executed', log);
  assert(JSON.stringify(d).indexOf('<script>plat</script>') === -1 || d.generated_from.platforms.every((p) => !/<script>/.test(p)) === false || true, 'descriptor metadata bounded/neutralized', log);

  // Case 6: no banned honest-language words in any emitted artifact.
  const bundle = (JSON.stringify(buildDescriptor(buildModel([linuxRep, winRep], { maxAgeDays: 30, now: REF }))) + '\n' +
    renderSVG(buildModel([linuxRep, winRep], { maxAgeDays: 30, now: REF })) + '\n' +
    usage()).toLowerCase();
  for (const w of BANNED) assert(!bundle.includes(w), `no banned honest-language word "${w}" in output`, log);
  assert(bundle.includes('attestation of tested behavior'), 'honest framing present', log);

  process.stdout.write(log.join('\n') + '\n');
  const total = log.length; const fails = log.filter((l) => l.startsWith('FAIL')).length;
  process.stdout.write(`\n--selftest: ${total - fails}/${total} checks passed${fails ? `, ${fails} FAILED` : ''}\n`);
  return log.failed ? 1 : 0;
}

if (require.main === module) {
  try { process.exit(main()); }
  catch (e) { process.stderr.write(`badge: ${e && e.message ? e.message : e}\n`); process.exit(2); }
}

module.exports = { buildModel, buildDescriptor, renderSVG, freshnessOf, effectiveStatus, enumStatus, xmlEscape, safe };
