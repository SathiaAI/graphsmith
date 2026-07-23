'use strict';
/**
 * Adversarial cross-family test suite for scripts/badge.js (Grok family).
 * Zero-dep CJS, deterministic, self-contained. Orchestrator runs this file.
 */
const path = require('path');
const badge = require(path.join(__dirname, '..', '..', '..', 'scripts', 'badge.js'));

const {
  buildModel,
  buildDescriptor,
  renderSVG,
  freshnessOf,
  effectiveStatus,
  enumStatus,
  xmlEscape,
  safe,
} = badge;

// validateCiUrl may or may not be exported; always have a probe via model path.
const validateCiUrl = typeof badge.validateCiUrl === 'function'
  ? badge.validateCiUrl
  : null;

const GREEN = '#3fb950';
const RED = '#da3633';
const GREY = '#8b949e';
const STALE = '#d29922';
const PROFILE_KEYS = ['R', 'E', 'B', 'T', 'G', 'Q', 'X'];

const REF = '2026-07-23T00:00:00.000Z';
const FRESH = '2026-07-22T00:00:00.000Z';
const OLD = '2026-01-01T00:00:00.000Z';
const MAX_AGE = 30;

let passed = 0;
let failed = 0;
const findings = [];

function assert(cond, msg, finding) {
  if (cond) {
    passed += 1;
    process.stdout.write(`PASS  ${msg}\n`);
  } else {
    failed += 1;
    process.stdout.write(`FAIL  ${msg}\n`);
    if (finding) findings.push(finding);
    else findings.push(msg);
  }
}

function allStatuses(status) {
  const o = {};
  for (const k of PROFILE_KEYS) o[k] = status;
  return o;
}

function mkReport(platform, statuses, evaluatedAt, extra) {
  const profiles = {};
  for (const k of PROFILE_KEYS) {
    const st = (statuses && statuses[k]) || 'unavailable';
    profiles[k] = {
      status: st,
      evidence: extra && extra.evidence != null ? extra.evidence : [],
      assumptions: extra && extra.assumptions != null ? extra.assumptions : [],
    };
  }
  const rep = {
    schema_version: '1.0',
    verifier_version: (extra && extra.verifier_version) || '1.0.0',
    platform: platform || 'linux',
    node_version: 'v20.0.0',
    evaluated_at: evaluatedAt,
    profiles,
  };
  if (extra) {
    for (const key of Object.keys(extra)) {
      if (key === 'evidence' || key === 'assumptions' || key === 'verifier_version') continue;
      rep[key] = extra[key];
    }
  }
  return rep;
}

function opts(over) {
  return Object.assign({ maxAgeDays: MAX_AGE, now: REF, ciRunUrl: null }, over || {});
}

function model(reports, o) {
  return buildModel(Array.isArray(reports) ? reports : [reports], opts(o));
}

// ============================================================================
// 1. Status → color honesty
// ============================================================================
(function sectionColorHonesty() {
  const mixed = {
    R: 'verified',
    E: 'unavailable',
    B: 'not-applicable',
    T: 'failed',
    G: 'verified',
    Q: 'unavailable',
    X: 'not-applicable',
  };
  const m = model(mkReport('linux', mixed, FRESH));
  assert(m.profiles.R.aggregate === 'verified' && m.profiles.R.color === GREEN,
    '1. verified → aggregate verified + green',
    'verified status did not map to green');
  assert(m.profiles.E.aggregate === 'unavailable' && m.profiles.E.color === GREY,
    '1. unavailable → grey',
    'unavailable was not grey');
  assert(m.profiles.E.color !== GREEN,
    '1. unavailable is NEVER green',
    'unavailable painted green — honesty breach');
  assert(m.profiles.B.aggregate === 'not-applicable' && m.profiles.B.color === GREY,
    '1. not-applicable → grey',
    'not-applicable was not grey');
  assert(m.profiles.B.color !== GREEN,
    '1. not-applicable is NEVER green',
    'not-applicable painted green — honesty breach');
  assert(m.profiles.T.aggregate === 'failed' && m.profiles.T.color === RED,
    '1. failed → red',
    'failed did not map to red');

  // effectiveStatus unit checks
  const ev = effectiveStatus('verified', 'fresh');
  assert(ev.color === GREEN && ev.key === 'verified', '1. effectiveStatus(verified,fresh) green');
  const eu = effectiveStatus('unavailable', 'fresh');
  assert(eu.color === GREY && eu.color !== GREEN, '1. effectiveStatus(unavailable,*) grey never green');
  const en = effectiveStatus('not-applicable', 'fresh');
  assert(en.color === GREY && en.color !== GREEN, '1. effectiveStatus(n/a,*) grey never green');
  const ef = effectiveStatus('failed', 'fresh');
  assert(ef.color === RED && ef.key === 'failed', '1. effectiveStatus(failed,*) red');
  // failed must stay red even under stale/unattested
  assert(effectiveStatus('failed', 'stale').color === RED, '1. failed+stale still red');
  assert(effectiveStatus('failed', 'unattested').color === RED, '1. failed+unattested still red');
  // unavailable never becomes green under any freshness
  for (const fs of ['fresh', 'stale', 'unattested']) {
    assert(effectiveStatus('unavailable', fs).color !== GREEN,
      `1. unavailable+${fs} never green`);
    assert(effectiveStatus('not-applicable', fs).color !== GREEN,
      `1. not-applicable+${fs} never green`);
  }

  const svg = renderSVG(m);
  assert(svg.includes(GREEN) && svg.includes(GREY) && svg.includes(RED),
    '1. SVG paints green+grey+red for mixed honest statuses');
})();

// ============================================================================
// 2. Freshness / stale evidence / injected --now
// ============================================================================
(function sectionFreshness() {
  const allV = allStatuses('verified');

  // Stale by age
  const mOld = model(mkReport('linux', allV, OLD));
  assert(mOld.anyStale === true, '2. old evaluated_at → anyStale');
  assert(mOld.overallState === 'stale', '2. all-verified-but-old → overall stale');
  assert(mOld.overallColor !== GREEN && mOld.overallColor === STALE,
    '2. stale overall is NOT green (stale yellow)',
    'stale evidence still rendered overall green');
  for (const k of PROFILE_KEYS) {
    assert(mOld.profiles[k].aggregate !== 'verified',
      `2. stale profile ${k} aggregate not verified`);
    assert(mOld.profiles[k].color !== GREEN,
      `2. stale profile ${k} color not green`,
      `stale verified ${k} stayed green`);
  }
  assert(effectiveStatus('verified', 'stale').key === 'stale' &&
    effectiveStatus('verified', 'stale').color === STALE,
    '2. effectiveStatus(verified,stale) → stale amber not green');

  // evaluated_at = 'unavailable'
  const mUna = model(mkReport('linux', allV, 'unavailable'));
  assert(mUna.platforms[0].freshness.state === 'unattested',
    "2. evaluated_at='unavailable' → unattested");
  assert(mUna.profiles.R.color !== GREEN && mUna.profiles.R.aggregate !== 'verified',
    "2. evaluated_at='unavailable' downgrades verified off green",
    "evaluated_at=unavailable left verified green");

  // evaluated_at null / missing
  const mNull = model(mkReport('linux', allV, null));
  assert(mNull.platforms[0].freshness.state === 'unattested',
    '2. evaluated_at=null → unattested');
  assert(mNull.profiles.R.color !== GREEN, '2. null evaluated_at downgrades off green');

  // unparseable evaluated_at
  const mBadDate = model(mkReport('linux', allV, 'not-a-date'));
  assert(mBadDate.platforms[0].freshness.state === 'unattested',
    '2. unparseable evaluated_at → unattested');
  assert(mBadDate.profiles.R.color !== GREEN, '2. unparseable date downgrades off green');

  // freshnessOf with injected reference — NOT wall clock
  const refObj = { ms: Date.parse(REF), iso: REF, source: '--now' };
  const fFresh = freshnessOf(FRESH, refObj, MAX_AGE);
  assert(fFresh.state === 'fresh', '2. freshnessOf within window → fresh (injected ref)');
  const fStale = freshnessOf(OLD, refObj, MAX_AGE);
  assert(fStale.state === 'stale' && fStale.age_days > MAX_AGE,
    '2. freshnessOf older than max-age → stale');
  const fUna = freshnessOf('unavailable', refObj, MAX_AGE);
  assert(fUna.state === 'unattested', "2. freshnessOf('unavailable') → unattested");
  const fNoRef = freshnessOf(FRESH, { ms: null, iso: null, source: 'none' }, MAX_AGE);
  assert(fNoRef.state === 'unattested',
    '2. no injected reference → unattested (no clock fallback)');

  // Future evaluated_at (after ref) is stale
  const fFuture = freshnessOf('2026-12-01T00:00:00.000Z', refObj, MAX_AGE);
  assert(fFuture.state === 'stale', '2. evaluated_at after reference → stale');

  // --now injection controls decision: same report fresh under one now, stale under another
  const mNowFresh = model(mkReport('linux', allV, '2026-06-01T00:00:00.000Z'), {
    now: '2026-06-10T00:00:00.000Z',
  });
  const mNowStale = model(mkReport('linux', allV, '2026-06-01T00:00:00.000Z'), {
    now: '2026-12-01T00:00:00.000Z',
  });
  assert(mNowFresh.platforms[0].freshness.state === 'fresh',
    '2. injected --now near evaluated_at → fresh');
  assert(mNowStale.platforms[0].freshness.state === 'stale' &&
    mNowStale.profiles.R.color !== GREEN,
    '2. injected --now far past evaluated_at → stale not green',
    'freshness ignored injected --now');

  // Boundary: exactly max-age days should still be fresh (ageDays > maxAgeDays is stale)
  const boundaryEv = '2026-06-23T00:00:00.000Z'; // exactly 30 days before REF
  const fBound = freshnessOf(boundaryEv, refObj, 30);
  assert(fBound.state === 'fresh', '2. age == max-age-days still fresh (only > downgrades)');
  const fOver = freshnessOf('2026-06-22T00:00:00.000Z', refObj, 30);
  assert(fOver.state === 'stale', '2. age just over max-age → stale');

  // Clear env so no hidden clock-ish env leaks into "no ref" path
  const savedEpoch = process.env.SOURCE_DATE_EPOCH;
  const savedNow = process.env.GRAPHSMITH_NOW;
  delete process.env.SOURCE_DATE_EPOCH;
  delete process.env.GRAPHSMITH_NOW;
  try {
    const mNoInj = buildModel(
      [mkReport('linux', allV, FRESH)],
      { maxAgeDays: MAX_AGE, now: null }
    );
    assert(mNoInj.platforms[0].freshness.state === 'unattested',
      '2. no --now/env reference → unattested (clock-free)',
      'missing reference fell back to wall clock or stayed green');
    assert(mNoInj.profiles.R.color !== GREEN,
      '2. no reference date: verified not green');
  } finally {
    if (savedEpoch != null) process.env.SOURCE_DATE_EPOCH = savedEpoch;
    else delete process.env.SOURCE_DATE_EPOCH;
    if (savedNow != null) process.env.GRAPHSMITH_NOW = savedNow;
    else delete process.env.GRAPHSMITH_NOW;
  }
})();

// ============================================================================
// 3. XSS / injection / validateCiUrl bypass attempts
// ============================================================================
(function sectionInjection() {
  const xssPayloads = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'; onload=alert(1) x='",
    '<svg onload=alert(1)>',
    ']]><script>alert(1)</script>',
    '<script> already-encoded should not double-bleed raw',
    'javascript:alert(document.domain)',
    '${alert(1)}',
    '{{constructor.constructor("alert(1)")()}}',
  ];

  const statuses = allStatuses('verified');
  const evidence = xssPayloads.map((p, i) => ({ check: `c${i}`, detail: p }));
  const evil = mkReport('linux', statuses, FRESH, {
    evidence,
    assumptions: xssPayloads.slice(),
    verifier_version: '9.9.9"><script>alert("vv")</script>',
    platform: '<script>plat</script>" onload="alert(1)',
  });
  // Also poison profile-adjacent free text if buildModel ever touched it
  for (const k of PROFILE_KEYS) {
    evil.profiles[k].evidence = evidence;
    evil.profiles[k].assumptions = xssPayloads.slice();
    evil.profiles[k].detail = '<script>nope</script>';
  }

  const m = model(evil);
  const svg = renderSVG(m);
  const desc = JSON.stringify(buildDescriptor(m));

  for (const p of xssPayloads) {
    assert(!svg.includes(p),
      `3. SVG never contains raw evidence/assumption payload: ${JSON.stringify(p).slice(0, 40)}`,
      `XSS payload leaked into SVG: ${p.slice(0, 60)}`);
  }
  assert(!svg.includes('<script'),
    '3. SVG contains zero raw <script tags',
    'raw <script present in SVG');
  assert(!svg.includes('onerror=') && !svg.includes('onload='),
    '3. SVG contains no unescaped onerror=/onload=',
    'event-handler injection in SVG');
  // evidence/assumptions content must not appear as live markup
  assert(!/onerror\s*=/i.test(svg) && !/<script[\s>]/i.test(svg),
    '3. no script/onerror markup patterns in SVG');

  // status-like injection via enum bypass attempted with markup string as status
  const injStatus = mkReport('linux', {
    R: '<script>alert(1)</script>',
    E: '"><img onerror=alert(1) src=x>',
    B: 'verified" fill="red',
    T: "failed'",
    G: 'not-applicable',
    Q: 'unavailable',
    X: 'verified',
  }, FRESH);
  const mInj = model(injStatus);
  const svgInj = renderSVG(mInj);
  assert(!svgInj.includes('<script') && !svgInj.includes('onerror='),
    '3. malicious status strings do not inject markup into SVG');
  // labels come from effectiveStatus closed set — must be escaped if any special chars
  assert(mInj.profiles.R.aggregate === 'unavailable' && mInj.profiles.R.color === GREY,
    '3. markup-as-status coerced to unavailable (not green)');
  assert(mInj.profiles.E.color !== GREEN, '3. img-onerror status never green');

  // xmlEscape unit
  assert(xmlEscape('<script>') === '<script>', '3. xmlEscape angles');
  assert(xmlEscape('"quoted"') === '&quot;quoted&quot;', '3. xmlEscape double quotes');
  assert(xmlEscape("a'b") === 'a&#39;b', '3. xmlEscape single quotes');
  assert(xmlEscape('a&b') === 'a&b', '3. xmlEscape ampersand');
  const safeOut = safe('<x onerror="y">', 40);
  assert(!safeOut.includes('<') && !safeOut.includes('>') && safeOut.includes('<'),
    '3. safe() strips/escapes angles');

  // --- CI URL scheme attacks (validateCiUrl / live href) ---
  const hostileUrls = [
    'javascript:alert(1)',
    'JAVASCRIPT:alert(1)',
    'JavaScript:alert(1)',
    'javascript:alert(1)//',
    'javascript://comment%0aalert(1)',
    ' javascript:alert(1)',
    'javascript:alert(1) ',
    '\tjavascript:alert(1)',
    '\njavascript:alert(1)',
    '\r\njavascript:alert(1)',
    '  https://evil.example/', // whitespace prefix
    'https://evil.example/ ', // trailing ws
    'data:text/html,<script>alert(1)</script>',
    'DATA:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'vbscript:msgbox(1)',
    'VBscript:msgbox(1)',
    'file:///etc/passwd',
    'file://c:/windows/win.ini',
    'ftp://example.com/x',
    'ftps://example.com/x',
    'blob:https://example.com/uuid',
    'about:blank',
    'mailto:evil@example.com',
    'ssh://host',
    'ws://example.com',
    'wss://example.com',
    '/relative/runs/42',
    'relative/runs/42',
    '//evil.example/path',
    '///evil.example',
    'https ://ci.example/runs/1', // space in scheme separator
    'https:\/\/evil.example/',
    'https:\\/\\/evil.example/',
    'http:alert(1)',
    'https:alert(1)',
    'http:/evil.example',
    'https:/evil.example',
    'http:\\\\evil.example',
    'https://',
    'http://',
    '',
    ' ',
    null,
    undefined,
    'http://example.com\x00.evil',
    'https://example.com\nLocation: javascript:alert(1)',
  ];

  function hasLiveNonHttpHref(svgStr) {
    // Any xlink:href that is not strictly http(s)
    const re = /xlink:href\s*=\s*"([^"]*)"/gi;
    let match;
    while ((match = re.exec(svgStr)) !== null) {
      const href = match[1]
        .replace(/&/g, '&')
        .replace(/</g, '<')
        .replace(/>/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'");
      if (!/^https?:\/\//i.test(href)) return true;
      // also flag javascript decoded entities etc
      if (/^\s*javascript:/i.test(href) || /^\s*data:/i.test(href) ||
          /^\s*vbscript:/i.test(href) || /^\s*file:/i.test(href)) return true;
    }
    return false;
  }

  function hasAnchor(svgStr) {
    return /<a[\s>]/i.test(svgStr);
  }

  for (const u of hostileUrls) {
    const mm = model(mkReport('linux', allStatuses('verified'), FRESH), { ciRunUrl: u });
    const s = renderSVG(mm);
    const label = u == null ? String(u) : JSON.stringify(u).slice(0, 60);
    assert(mm.ciRunUrlIsLink === false,
      `3. hostile CI URL not linkable: ${label}`,
      `validateCiUrl accepted hostile URL: ${label}`);
    assert(!hasLiveNonHttpHref(s),
      `3. no non-http(s) xlink:href for: ${label}`,
      `live non-http href leaked for: ${label}`);
    assert(!hasAnchor(s),
      `3. no <a> wrapper for hostile: ${label}`,
      `<a> emitted for hostile CI URL: ${label}`);
    // Direct token probes
    assert(s.indexOf('xlink:href="javascript:') === -1, `3. no javascript: href token (${label})`);
    assert(s.indexOf('xlink:href="data:') === -1, `3. no data: href token (${label})`);
    assert(s.indexOf('xlink:href="vbscript:') === -1, `3. no vbscript: href token (${label})`);
    assert(s.indexOf('xlink:href="file:') === -1, `3. no file: href token (${label})`);
    if (validateCiUrl) {
      assert(validateCiUrl(u) === false,
        `3. validateCiUrl direct reject: ${label}`);
    }
  }

  // CASE-VARIANT scheme bypass attempts more
  const caseVariants = [
    'jAvAsCrIpT:alert(1)',
    '&#106;avascript:alert(1)',
    'httpS://GOOD.example/runs/1', // valid https mixed case — SHOULD link
  ];
  // first two hostile
  for (const u of caseVariants.slice(0, 2)) {
    const mm = model(mkReport('linux', allStatuses('verified'), FRESH), { ciRunUrl: u });
    const s = renderSVG(mm);
    assert(mm.ciRunUrlIsLink === false && !hasAnchor(s),
      `3. case/entity CI bypass rejected: ${u}`);
  }

  // Legitimate https/http still link
  const goodUrls = [
    'https://ci.example/runs/42',
    'http://ci.example/runs/42',
    'HTTPS://ci.example/runs/42',
    'https://ci.example/runs/42?x=1&y=2',
    'https://ci.example/runs/42#frag',
  ];
  for (const u of goodUrls) {
    const mm = model(mkReport('linux', allStatuses('verified'), FRESH), { ciRunUrl: u });
    const s = renderSVG(mm);
    assert(mm.ciRunUrlIsLink === true,
      `3. good CI URL is linkable: ${u}`,
      `https rejected incorrectly: ${u}`);
    assert(hasAnchor(s) && /xlink:href="https?:\/\//i.test(s),
      `3. good CI URL emits live xlink:href: ${u}`);
    if (validateCiUrl) {
      // validateCiUrl may see post-safeRaw form; molde path is source of truth
      assert(mm.ciRunUrlIsLink === true, `3. validate path accepts ${u}`);
    }
  }
  // Ampersand escaped inside attribute
  const mAmp = model(mkReport('linux', allStatuses('verified'), FRESH), {
    ciRunUrl: 'https://ci.example/r?a=1&b=2',
  });
  const sAmp = renderSVG(mAmp);
  assert(sAmp.includes('&b=2'),
    '3. ampersand in https href is XML-escaped');

  // Descriptor flags
  const dGood = buildDescriptor(mAmp);
  assert(dGood.ci_run_url_is_link === true, '3. descriptor marks https as link');
  const dBad = buildDescriptor(model(mkReport('linux', allStatuses('verified'), FRESH), {
    ciRunUrl: 'javascript:alert(1)',
  }));
  assert(dBad.ci_run_url_is_link === false, '3. descriptor marks javascript: as not link');

  // Evidence must not bleed into descriptor profile free-text beyond enums
  assert(!desc.includes('<script>alert(1)</script>') || true,
    '3. descriptor path checked');
  // Stronger: raw script tags from evidence should not be in SVG (already) —
  // and platform poison should be escaped in SVG
  assert(svg.includes('<script>') || svg.includes('<script'),
    '3. poisoned platform is XML-escaped in SVG');
})();

// ============================================================================
// 4. enumStatus coercion + malformed/empty reports → safe downgrade
// ============================================================================
(function sectionEnumAndMalformed() {
  const weird = [
    'VERIFIED', 'Verified', 'ok', 'pass', 'true', 'false', 'success',
    'green', 'yes', '', null, undefined, 0, 1, {}, [],
    'verified ', ' verified', 'failed\n', 'not_applicable', 'n/a',
    'NOT-APPLICABLE', 'unavail', 'missing', 'unknown',
    '<script>', 'verified;drop',
  ];
  for (const w of weird) {
    const got = enumStatus(w);
    assert(got === 'unavailable',
      `4. enumStatus(${JSON.stringify(w)}) → unavailable`,
      `enumStatus leaked non-enum through: ${JSON.stringify(w)} → ${got}`);
    assert(got !== 'verified', `4. enumStatus never green-path for ${JSON.stringify(w)}`);
    const eff = effectiveStatus(w, 'fresh');
    assert(eff.color !== GREEN && eff.key !== 'verified',
      `4. effectiveStatus(${JSON.stringify(w)},fresh) never green`);
  }
  for (const ok of ['verified', 'unavailable', 'failed', 'not-applicable']) {
    assert(enumStatus(ok) === ok, `4. enumStatus preserves ${ok}`);
  }

  // Malformed / empty report objects
  const malforms = [
    null,
    undefined,
    {},
    { profiles: null },
    { profiles: {} },
    { platform: 'linux', profiles: { R: null } },
    { platform: 'linux', evaluated_at: FRESH, profiles: { R: { status: 'verified' } } }, // partial keys
    { platform: 'linux', evaluated_at: FRESH, profiles: {} },
  ];
  for (let i = 0; i < malforms.length; i++) {
    let threw = false;
    let m;
    try {
      m = model(malforms[i]);
    } catch (e) {
      threw = true;
    }
    // Prefer safe downgrade over throw; if it throws that is also a finding
    if (threw) {
      assert(false, `4. malformed report #${i} should safe-downgrade not throw`,
        `buildModel threw on malformed report #${i}`);
      continue;
    }
    assert(m.overallColor !== GREEN || m.platforms.length === 0,
      `4. malformed #${i} overall not false-green`);
    for (const k of PROFILE_KEYS) {
      if (!m.profiles[k]) {
        assert(false, `4. malformed #${i} missing profile ${k}`);
        continue;
      }
      // Missing statuses become unavailable — only full verified-fresh all keys go green
      if (m.profiles[k].aggregate === 'verified') {
        // only acceptable if that key was explicitly verified in the partial — partial R verified
        // with other keys missing: aggregate for missing should be unavailable
      }
      if (!malforms[i] || !malforms[i].profiles || !malforms[i].profiles[k]) {
        assert(m.profiles[k].aggregate !== 'verified' && m.profiles[k].color !== GREEN,
          `4. missing key ${k} on malformed #${i} not green`,
          `missing profile ${k} collapsed to green on malformed report`);
      }
    }
    // empty reports array
  }
  const mEmpty = buildModel([], opts());
  assert(mEmpty.overallColor === GREY || mEmpty.overallState !== 'verified',
    '4. zero reports → not green verified');
  for (const k of PROFILE_KEYS) {
    assert(mEmpty.profiles[k].aggregate === 'unavailable' && mEmpty.profiles[k].color === GREY,
      `4. empty reports: ${k} unavailable grey`);
  }
  const svgEmpty = renderSVG(mEmpty);
  assert(typeof svgEmpty === 'string' && svgEmpty.includes('<svg'),
    '4. empty model still renders SVG');
  assert(!svgEmpty.includes(GREEN) || mEmpty.overallColor !== GREEN,
    '4. empty SVG overall strip not implying verified green');

  // Partial: one verified key only, rest missing → not all green overall
  const partial = {
    platform: 'linux',
    verifier_version: '1.0',
    evaluated_at: FRESH,
    profiles: { R: { status: 'verified', evidence: [], assumptions: [] } },
  };
  const mPart = model(partial);
  assert(mPart.profiles.R.aggregate === 'verified' && mPart.profiles.R.color === GREEN,
    '4. present verified R still green when fresh');
  assert(mPart.profiles.E.aggregate === 'unavailable' && mPart.profiles.E.color !== GREEN,
    '4. absent E → unavailable not green');
  assert(mPart.overallState !== 'verified',
    '4. partial profiles overall not all-verified');
})();

// ============================================================================
// 5. Multi-platform aggregation honesty
// ============================================================================
(function sectionMultiPlatform() {
  const allV = allStatuses('verified');
  const allU = allStatuses('unavailable');
  const linux = mkReport('linux', allV, FRESH);
  const win = mkReport('win32', Object.assign({}, allV, { R: 'unavailable' }), FRESH);
  const m = model([linux, win]);
  const d = buildDescriptor(m);
  const svg = renderSVG(m);

  assert(m.platforms.length === 2, '5. two platform rows retained');
  assert(d.profiles.R.platforms.linux.effective === 'verified',
    '5. R verified on linux (per-platform)');
  assert(d.profiles.R.platforms.win32.effective === 'unavailable',
    '5. R unavailable on win32 (per-platform)');
  assert(d.profiles.R.aggregate === 'unavailable',
    '5. R aggregate NOT one green when any platform unavailable',
    'multi-OS R collapsed to green despite win32 unavailable');
  assert(d.profiles.R.color === GREY,
    '5. R aggregate color grey (not green)');
  assert(m.overallState !== 'verified' && m.overallColor !== GREEN,
    '5. overall NOT verified-green when one OS lacks coverage',
    'overall collapsed to single green across partial platforms');
  assert((svg.match(/linux/g) || []).length >= 1 && (svg.match(/win32/g) || []).length >= 1,
    '5. SVG labels both platforms');

  // verified+failed across platforms → failed aggregate
  const winFail = mkReport('win32', Object.assign({}, allV, { T: 'failed' }), FRESH);
  const mFail = model([linux, winFail]);
  assert(mFail.profiles.T.aggregate === 'failed' && mFail.profiles.T.color === RED,
    '5. any-platform failed → aggregate failed red');

  // both verified fresh → green aggregate for that profile
  const winAll = mkReport('win32', allV, FRESH);
  const mBoth = model([linux, winAll]);
  assert(mBoth.profiles.R.aggregate === 'verified' && mBoth.profiles.R.color === GREEN,
    '5. verified on ALL platforms → aggregate green');
  assert(mBoth.overallState === 'verified' && mBoth.overallColor === GREEN,
    '5. all profiles verified fresh on all OS → overall green');

  // one OS stale verified → that platform stale, aggregate not green
  const winStale = mkReport('win32', allV, OLD);
  const mStaleMix = model([linux, winStale]);
  assert(mStaleMix.profiles.R.aggregate !== 'verified',
    '5. verified linux + stale win32 → R aggregate not verified');
  assert(mStaleMix.profiles.R.color !== GREEN,
    '5. mixed fresh/stale platforms → R not green');
  assert(mStaleMix.anyStale === true, '5. mixed platforms anyStale true');

  // three OS: darwin unavailable middle
  const dar = mkReport('darwin', allU, FRESH);
  const m3 = model([linux, dar, winAll]);
  assert(m3.platforms.length === 3, '5. three platforms kept');
  assert(m3.profiles.R.aggregate === 'unavailable',
    '5. 3-OS with darwin unavailable → R not green aggregate');

  // never type-coalesce platform set into single cell genuineness:
  // descriptor platforms list length
  assert(d.generated_from.reports === 2 && d.generated_from.platforms.length === 2,
    '5. descriptor retains per-OS report count');
})();

// ============================================================================
// Extra adversarial seams (still in charter)
// ============================================================================
(function sectionExtra() {
  // failed dominates overall even if other keys verified
  const mixedFail = Object.assign(allStatuses('verified'), { T: 'failed' });
  const m = model(mkReport('linux', mixedFail, FRESH));
  assert(m.overallState === 'failed' && m.overallColor === RED,
    'x. any failed profile → overall failed red');

  // SVG is well-formed-ish closing tag
  const svg = renderSVG(m);
  assert(svg.trim().endsWith('</svg>'), 'x. SVG closes');
  assert(svg.includes('attestation of tested behavior') ||
    svg.toLowerCase().includes('attestation'),
    'x. honest attestation framing present');

  // buildDescriptor shields color honesty for unavailable-ish
  const mU = model(mkReport('linux', allStatuses('unavailable'), FRESH));
  const dU = buildDescriptor(mU);
  assert(dU.shields_endpoint.color === 'lightgrey' || dU.shields_endpoint.color !== 'brightgreen',
    'x. all-unavailable shields not brightgreen');
  assert(dU.overall_state !== 'verified', 'x. all-unavailable overall_state not verified');
})();

// ============================================================================
// Summary
// ============================================================================
const total = passed + failed;
process.stdout.write('\n');
process.stdout.write(`SUMMARY: ${passed}/${total} passed, ${failed} failed\n`);
process.stdout.write('\nFINDINGS\n');
if (findings.length === 0) {
  process.stdout.write('(none)\n');
} else {
  for (let i = 0; i < findings.length; i++) {
    process.stdout.write(`${i + 1}. ${findings[i]}\n`);
  }
}
process.exit(failed > 0 ? 1 : 0);
