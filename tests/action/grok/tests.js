#!/usr/bin/env node
"use strict";
/**
 * ADVERSARIAL TESTER (≠ the GLM builder) — family: grok
 * Target: reusable CI enforcement — action.yml, templates/graphsmith.gitlab-ci.yml,
 * docs/SUPPLY-CHAIN.md wrapping `node scripts/verify.js --profiles`.
 *
 * GitHub Actions cannot run here: extract + exercise the decision logic, and
 * statically assert the supply-chain discipline.
 *
 * Deterministic, zero-dep CJS. Exit 1 on any FAIL or if FINDINGS is empty
 * without genuine attack coverage (zero-finding invalid).
 */
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const REPO = path.resolve(__dirname, "..", "..", "..");
const ACTION_YML = path.join(REPO, "action.yml");
const GITLAB_YML = path.join(REPO, "templates", "graphsmith.gitlab-ci.yml");
const SUPPLY = path.join(REPO, "docs", "SUPPLY-CHAIN.md");
const CI_YML = path.join(REPO, ".github", "workflows", "ci.yml");
const VERIFY_JS = path.join(REPO, "scripts", "verify.js");

const FULL_SHA_RE = /^[0-9a-f]{40}$/i;
// uses: owner/name@ref  — capture owner/name and ref (before comment)
const USES_RE = /uses:\s*([^\s#]+)/g;
const results = [];
const findings = [];

function record(status, name, detail) {
  const d = detail == null ? "" : String(detail).replace(/\s+/g, " ").trim().slice(0, 400);
  results.push({ status: status, name: name, detail: d });
  console.log(status + "\t" + name + (d ? "\t" + d : ""));
}
function pass(n, d) { record("PASS", n, d); }
function fail(n, d) { record("FAIL", n, d); }
function finding(id, severity, summary) {
  findings.push({ id: id, severity: severity, summary: summary });
}

function readRel(rel) {
  return fs.readFileSync(path.join(REPO, rel), "utf8");
}

/**
 * Faithful extraction of the profile-status case arm that lives identically
 * in action.yml and templates/graphsmith.gitlab-ci.yml.
 * Returns { failedCount, unavailableCount, totalCount, classifications[],
 *           overallStatus, exitCode, events[] }.
 *
 * Vocab handled by the ACTION (as written): failed | unavailable |
 * not-yet-implemented | passed | * (unknown).
 * Vocab emitted by verify --profiles: verified | unavailable | failed |
 * not-applicable.
 */
function decideProfiles(payload, opts) {
  opts = opts || {};
  const failOn = opts.failOn || "unavailable-is-not-failure";
  const required = opts.profiles || "all-available";
  const events = [];
  let failedCount = 0;
  let unavailableCount = 0;
  let totalCount = 0;
  const classifications = [];

  // Fail-closed JSON gate (what the action SHOULD do; probe actual later).
  let data = null;
  let parseOk = false;
  if (payload !== null && payload !== undefined && String(payload).trim() !== "") {
    try {
      data = typeof payload === "string" ? JSON.parse(payload) : payload;
      parseOk = data !== null && typeof data === "object";
    } catch (_) {
      parseOk = false;
    }
  }

  // ACTUAL action behavior has no set -e / no JSON validity gate before the
  // status loop. Empty or bad JSON → node -e may fail → empty profile list →
  // STATUS=passed exit 0. We model that as actualActionBehavior.
  const actual = {
    parseOk: parseOk,
    failOpenOnBadJson: !parseOk, // old/current: continues as pass
  };

  let profilesToCheck = [];
  if (parseOk) {
    if (required === "all-available") {
      profilesToCheck = Object.keys((data && data.profiles) || {});
    } else {
      profilesToCheck = String(required)
        .split(",")
        .map(function (s) { return s.trim(); })
        .filter(Boolean);
    }
  } else {
    // Actual: PROFILES_TO_CHECK empty when require()/parse fails silently-ish.
    profilesToCheck = [];
  }

  for (var i = 0; i < profilesToCheck.length; i++) {
    var prof = profilesToCheck[i];
    totalCount++;
    var profStatus =
      data && data.profiles && data.profiles[prof] && data.profiles[prof].status
        ? String(data.profiles[prof].status)
        : "unknown";

    var bucket = "unknown";
    switch (profStatus) {
      case "failed":
        failedCount++;
        bucket = "failed";
        events.push({ type: "error", msg: "Profile '" + prof + "' is FAILED" });
        break;
      case "unavailable":
        unavailableCount++;
        if (failOn === "unavailable-is-not-failure") {
          bucket = "unavailable-annotate";
          events.push({
            type: "notice",
            msg: "Profile '" + prof + "' is UNAVAILABLE (annotated, not failed)",
          });
        } else {
          failedCount++;
          bucket = "unavailable-as-failure";
          events.push({
            type: "error",
            msg: "Profile '" + prof + "' is UNAVAILABLE (configured as failure)",
          });
        }
        break;
      case "not-yet-implemented":
        bucket = "not-yet-implemented-annotate";
        events.push({
          type: "notice",
          msg: "Profile '" + prof + "' is NOT YET IMPLEMENTED (annotated, not failed)",
        });
        break;
      case "passed":
        bucket = "passed";
        events.push({ type: "notice", msg: "Profile '" + prof + "' is PASSED" });
        break;
      default:
        // includes verify's real success token "verified" and "not-applicable"
        bucket = "unknown";
        events.push({
          type: "warning",
          msg: "Profile '" + prof + "' has unknown status: " + profStatus,
        });
        break;
    }
    classifications.push({ prof: prof, status: profStatus, bucket: bucket });
  }

  var overallStatus;
  var exitCode;
  if (failedCount > 0) {
    overallStatus = "failed";
    exitCode = 1;
  } else if (unavailableCount > 0) {
    overallStatus = "partial";
    exitCode = 0;
  } else {
    overallStatus = "passed";
    exitCode = 0;
  }

  return {
    failedCount: failedCount,
    unavailableCount: unavailableCount,
    totalCount: totalCount,
    classifications: classifications,
    overallStatus: overallStatus,
    exitCode: exitCode,
    events: events,
    actual: actual,
    parseOk: parseOk,
  };
}

/** Ideal/correct semantics against verify's actual vocab. */
function idealDecide(payload, opts) {
  opts = opts || {};
  const failOn = opts.failOn || "unavailable-is-not-failure";
  const required = opts.profiles || "all-available";
  let data;
  try {
    data = typeof payload === "string" ? JSON.parse(payload) : payload;
  } catch (_) {
    return { overallStatus: "failed", exitCode: 1, reason: "malformed-json-fail-closed" };
  }
  if (!data || typeof data !== "object" || !data.profiles || typeof data.profiles !== "object") {
    return { overallStatus: "failed", exitCode: 1, reason: "empty-or-missing-profiles-fail-closed" };
  }
  var keys =
    required === "all-available"
      ? Object.keys(data.profiles)
      : String(required).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  if (keys.length === 0) {
    return { overallStatus: "failed", exitCode: 1, reason: "zero-profiles-fail-closed" };
  }
  var failed = 0;
  var unavail = 0;
  for (var i = 0; i < keys.length; i++) {
    var st =
      data.profiles[keys[i]] && data.profiles[keys[i]].status
        ? data.profiles[keys[i]].status
        : "unknown";
    if (st === "failed") failed++;
    else if (st === "unavailable") {
      if (failOn === "unavailable-is-not-failure") unavail++;
      else failed++;
    } else if (st === "not-applicable") {
      // annotate, not fail
    } else if (st === "verified") {
      // success
    } else {
      // unknown must fail closed
      failed++;
    }
  }
  if (failed > 0) return { overallStatus: "failed", exitCode: 1 };
  if (unavail > 0) return { overallStatus: "partial", exitCode: 0 };
  return { overallStatus: "passed", exitCode: 0 };
}

function fixtureVerifyJson(statusMap) {
  var profiles = {};
  var parts = [];
  Object.keys(statusMap).forEach(function (k) {
    profiles[k] = { status: statusMap[k], evidence: [], assumptions: [] };
    parts.push(k + ":" + statusMap[k]);
  });
  return {
    schema_version: "1.0",
    command: "profiles",
    profiles: profiles,
    profile_string: parts.join(" "),
  };
}

function extractRunBlock(yml, marker) {
  var idx = yml.indexOf(marker);
  if (idx < 0) return "";
  return yml.slice(idx);
}

function thirdPartyUses(ymlText, scopeLabel) {
  var hits = [];
  var m;
  var re = new RegExp(USES_RE.source, "g");
  while ((m = re.exec(ymlText)) !== null) {
    var ref = m[1].trim();
    // skip local composite ./
    if (ref === "./" || ref.indexOf("./") === 0) continue;
    // skip docker://
    if (/^docker:\/\//i.test(ref)) continue;
    var at = ref.lastIndexOf("@");
    if (at < 0) {
      hits.push({ raw: ref, ownerRepo: ref, pin: "", scope: scopeLabel, ok: false, reason: "no-@pin" });
      continue;
    }
    var ownerRepo = ref.slice(0, at);
    var pin = ref.slice(at + 1);
    // degrade tags like v4 / main
    var isFullSha = FULL_SHA_RE.test(pin);
    hits.push({
      raw: ref,
      ownerRepo: ownerRepo,
      pin: pin,
      scope: scopeLabel,
      ok: isFullSha,
      reason: isFullSha ? "full-sha" : "NOT-full-sha(" + pin + ")",
    });
  }
  return hits;
}

// ---------------------------------------------------------------------------
// ATTACK 1 — STATUS-VOCAB CORRECTNESS
// ---------------------------------------------------------------------------
function attackStatusVocab() {
  console.log("\n=== ATTACK 1: STATUS-VOCAB (verified vs passed) ===");

  var action = readRel("action.yml");
  var gitlab = readRel("templates/graphsmith.gitlab-ci.yml");
  var supply = readRel("docs/SUPPLY-CHAIN.md");
  var verifySrc = readRel("scripts/verify.js");

  // Action case arms
  var hasPassedArm = /case[\s\S]*?\bpassed\)/.test(action) || /^\s+passed\)/m.test(action);
  var hasVerifiedArm = /^\s+verified\)/m.test(action);
  var hasNotApplicableArm = /^\s+not-applicable\)/m.test(action);
  var hasNotYetImplArm = /^\s+not-yet-implemented\)/m.test(action);

  // Prove case wording from the source words themselves.
  var actionCase = (action.match(/case "\$PROF_STATUS" in([\s\S]*?)esac/) || [])[1] || "";
  hasPassedArm = /\bpassed\)/.test(actionCase);
  hasVerifiedArm = /\bverified\)/.test(actionCase);
  hasNotApplicableArm = /\bnot-applicable\)/.test(actionCase);
  hasNotYetImplArm = /\bnot-yet-implemented\)/.test(actionCase);

  var glCase = (gitlab.match(/case "\$PROF_STATUS" in([\s\S]*?)esac/) || [])[1] || "";
  var glPassed = /\bpassed\)/.test(glCase);
  var glVerified = /\bverified\)/.test(glCase);
  var glNA = /\bnot-applicable\)/.test(glCase);

  // verify emits verified
  var verifyVocab =
    /status\s*∈\s*\{\s*verified\s*,\s*unavailable\s*,\s*failed\s*,\s*not-applicable\s*\}/.test(
      verifySrc
    ) ||
    /status ∈ \{ verified, unavailable, failed, not-applicable \}/.test(verifySrc) ||
    verifySrc.indexOf('"verified"') >= 0 &&
      verifySrc.indexOf("not-applicable") >= 0 &&
      verifySrc.indexOf("--profiles") >= 0;

  // Fixture with the REAL verify status set
  var fixture = fixtureVerifyJson({
    R: "verified",
    E: "unavailable",
    B: "failed",
    T: "not-applicable",
    G: "verified",
  });
  var actual = decideProfiles(JSON.stringify(fixture), {
    failOn: "unavailable-is-not-failure",
    profiles: "all-available",
  });
  var ideal = idealDecide(JSON.stringify(fixture), {
    failOn: "unavailable-is-not-failure",
  });

  // Drive each status alone to show classification bucket
  var solo = {};
  ["verified", "passed", "failed", "unavailable", "not-applicable", "not-yet-implemented"].forEach(
    function (st) {
      var r = decideProfiles(JSON.stringify(fixtureVerifyJson({ S: st })), {
        failOn: "unavailable-is-not-failure",
      });
      solo[st] = r.classifications[0] ? r.classifications[0].bucket : "none";
    }
  );

  // REPORT actual behavior
  var verifiedBucket = solo.verified;
  var verifiedIsUnknown = verifiedBucket === "unknown";
  var passedIsHandled = solo.passed === "passed";

  if (verifiedIsUnknown) {
    finding(
      "VOCAB-VERIFIED-UNKNOWN",
      "high",
      "action.yml/gitlab case treats verify's real success token 'verified' as unknown (warning). " +
        "Action arm is 'passed' which verify never emits. verified→bucket=" +
        verifiedBucket +
        "; alone exitCode=" +
        decideProfiles(JSON.stringify(fixtureVerifyJson({ R: "verified" }))).exitCode +
        " overall=" +
        decideProfiles(JSON.stringify(fixtureVerifyJson({ R: "verified" }))).overallStatus +
        " (exit still 0 via empty-failure fallthrough, but not counted as explicit pass arm)"
    );
  }
  if (hasPassedArm && !hasVerifiedArm) {
    finding(
      "VOCAB-PASSED-NOT-VERIFIED",
      "high",
      "action.yml case has 'passed)' and lacks 'verified)'; verify --profiles emits status∈{verified,unavailable,failed,not-applicable}"
    );
  }
  if (hasNotYetImplArm && !hasNotApplicableArm) {
    finding(
      "VOCAB-NOT-YET-VS-NOT-APPLICABLE",
      "medium",
      "action.yml handles 'not-yet-implemented' but verify emits 'not-applicable' — both annotate/not-fail today via unknown/nyi paths, but docs+arms disagree with emitter"
    );
  }
  if (glPassed && !glVerified) {
    finding(
      "VOCAB-GITLAB-SAME-BUG",
      "high",
      "templates/graphsmith.gitlab-ci.yml mirrors the passed/verified mismatch"
    );
  }
  // docs claim wrong status names
  if (/\*\*`passed`\*\*/.test(supply) || /-\s+\*\*`passed`\*\*/.test(supply) || supply.indexOf("`passed`") >= 0) {
    if (supply.indexOf("`verified`") < 0 || /Profile Status Types[\s\S]*?`passed`/.test(supply)) {
      finding(
        "VOCAB-DOCS-PASSED",
        "medium",
        "docs/SUPPLY-CHAIN.md documents profile status 'passed' / 'not-yet-implemented' instead of verify's 'verified' / 'not-applicable'"
      );
    }
  }

  // Assertions the TEST itself makes:
  // Fault present → we FAIL the test check name that asserts correct vocab mapping.
  if (verifiedIsUnknown) {
    fail(
      "verified-maps-to-pass-arm",
      "ACTUAL bucket for status= verified is '" +
        verifiedBucket +
        "' (unknown-status branch). Action case arms: passed=" +
        hasPassedArm +
        " verified=" +
        hasVerifiedArm
    );
  } else {
    pass("verified-maps-to-pass-arm", "verified correctly classified as success");
  }

  if (solo.failed === "failed") {
    pass("failed-maps-to-fail-arm", "failed→failed bucket");
  } else {
    fail("failed-maps-to-fail-arm", "failed bucket=" + solo.failed);
  }

  // With mixed fixture: failed present → exit 1 (this part still works)
  if (actual.exitCode === 1 && actual.overallStatus === "failed") {
    pass(
      "mixed-fixture-failed-wins",
      "failed REQUIRED profile forces exit 1; classifications=" +
        actual.classifications
          .map(function (c) {
            return c.prof + ":" + c.status + "→" + c.bucket;
          })
          .join(",")
    );
  } else {
    fail(
      "mixed-fixture-failed-wins",
      "expected exit 1 failed, got exit=" + actual.exitCode + " status=" + actual.overallStatus
    );
  }

  // Explicit: verified alone must be treated as success arm (ideal), and action
  // must not warn. Check warnings on verified-only.
  var vOnly = decideProfiles(JSON.stringify(fixtureVerifyJson({ R: "verified", G: "verified" })));
  var warnedVerified = vOnly.events.some(function (e) {
    return e.type === "warning" && /unknown status: verified/.test(e.msg);
  });
  if (warnedVerified) {
    fail(
      "verified-not-warned-as-unknown",
      "verified profiles emit warning unknown-status; events=" +
        vOnly.events
          .map(function (e) {
            return e.type + ":" + e.msg;
          })
          .join(" | ")
    );
  } else {
    pass("verified-not-warned-as-unknown", "no unknown warning on verified");
  }

  if (vOnly.exitCode === 0 && vOnly.overallStatus === "passed") {
    pass(
      "verified-only-exit-0-via-fallthrough",
      "verified-only still overall=passed exit 0 (FAILED_COUNT path), despite unknown arm — defect is classification not exit"
    );
  } else {
    fail(
      "verified-only-exit-0-via-fallthrough",
      "unexpected exit=" + vOnly.exitCode + " status=" + vOnly.overallStatus
    );
  }

  // Static source agreement
  if (hasVerifiedArm) {
    pass("action-yml-has-verified-arm", "case includes verified)");
  } else {
    fail("action-yml-has-verified-arm", "case missing verified); has passed)=" + hasPassedArm);
  }
  if (glVerified) {
    pass("gitlab-has-verified-arm", "case includes verified)");
  } else {
    fail("gitlab-has-verified-arm", "gitlab case missing verified); has passed)=" + glPassed);
  }
  if (verifyVocab) {
    pass("verify-emits-verified-vocab", "scripts/verify.js documents/emits verified|...|not-applicable");
  } else {
    fail("verify-emits-verified-vocab", "could not confirm verify vocab");
  }

  // ideal vs actual divergence signal
  if (ideal.exitCode === actual.exitCode && actual.exitCode === 1) {
    pass("ideal-actual-exit-agree-on-failed-present", "both exit 1 when a failed profile is present");
  }
}

// ---------------------------------------------------------------------------
// ATTACK 2 — UNAVAILABLE≠FAIL / FAILED=FAIL
// ---------------------------------------------------------------------------
function attackFailOnSemantics() {
  console.log("\n=== ATTACK 2: UNAVAILABLE≠FAIL / FAILED=FAIL ===");

  var unavailOnly = decideProfiles(
    JSON.stringify(fixtureVerifyJson({ E: "unavailable", T: "unavailable" })),
    { failOn: "unavailable-is-not-failure" }
  );
  if (
    unavailOnly.exitCode === 0 &&
    unavailOnly.overallStatus === "partial" &&
    unavailOnly.failedCount === 0 &&
    unavailOnly.unavailableCount === 2
  ) {
    pass(
      "unavailable-default-annotates-not-fail",
      "exit=0 status=partial unavail=" + unavailOnly.unavailableCount
    );
  } else {
    fail(
      "unavailable-default-annotates-not-fail",
      "exit=" +
        unavailOnly.exitCode +
        " status=" +
        unavailOnly.overallStatus +
        " failed=" +
        unavailOnly.failedCount
    );
  }

  var unavailStrict = decideProfiles(
    JSON.stringify(fixtureVerifyJson({ E: "unavailable" })),
    { failOn: "unavailable-is-failure" }
  );
  if (unavailStrict.exitCode === 1 && unavailStrict.failedCount >= 1) {
    pass("unavailable-strict-fails-build", "fail-on=unavailable-is-failure → exit 1");
  } else {
    fail(
      "unavailable-strict-fails-build",
      "exit=" + unavailStrict.exitCode + " failedCount=" + unavailStrict.failedCount
    );
  }

  var failedOnly = decideProfiles(JSON.stringify(fixtureVerifyJson({ B: "failed" })), {
    failOn: "unavailable-is-not-failure",
  });
  if (failedOnly.exitCode === 1 && failedOnly.overallStatus === "failed") {
    pass("failed-required-fails-build", "status=failed → exit 1");
  } else {
    fail("failed-required-fails-build", "exit=" + failedOnly.exitCode);
  }

  // not-applicable must not fail (even though it hits unknown or nyi)
  var naOnly = decideProfiles(JSON.stringify(fixtureVerifyJson({ T: "not-applicable" })));
  if (naOnly.exitCode === 0 && naOnly.failedCount === 0) {
    pass(
      "not-applicable-does-not-fail",
      "bucket=" +
        (naOnly.classifications[0] && naOnly.classifications[0].bucket) +
        " exit=0"
    );
  } else {
    fail("not-applicable-does-not-fail", "exit=" + naOnly.exitCode);
  }

  // GitLab source carries the same default rule textually
  var gitlab = readRel("templates/graphsmith.gitlab-ci.yml");
  var glDefault =
    /GRAPHSMITH_FAIL_ON:-unavailable-is-not-failure/.test(gitlab) ||
    /unavailable-is-not-failure/.test(gitlab);
  var glFailedExit = /FAILED_COUNT -gt 0[\s\S]*exit 1/.test(gitlab) || /exit 1/.test(gitlab);
  var glHeader =
    /unavailable profiles do NOT fail the build[\s\S]*failed profiles DO fail the build/i.test(
      gitlab
    );
  if (glDefault && glFailedExit && glHeader) {
    pass(
      "gitlab-same-unavailable-ne-fail-rule",
      "template documents + implements unavailable≠fail / failed=fail"
    );
  } else {
    fail(
      "gitlab-same-unavailable-ne-fail-rule",
      "default=" + glDefault + " exit=" + glFailedExit + " header=" + glHeader
    );
  }

  var action = readRel("action.yml");
  var actDefault = /default:\s*'unavailable-is-not-failure'/.test(action);
  if (actDefault) {
    pass("action-default-fail-on", "fail-on default unavailable-is-not-failure");
  } else {
    fail("action-default-fail-on", "missing default");
  }
}

// ---------------------------------------------------------------------------
// ATTACK 3 — SHA-PINNING / SUPPLY-CHAIN GATE
// ---------------------------------------------------------------------------
function attackSupplyChain() {
  console.log("\n=== ATTACK 3: SHA-PINNING + SUPPLY-CHAIN DISCIPLINE ===");

  var action = readRel("action.yml");
  var ci = readRel(".github/workflows/ci.yml");
  var supply = readRel("docs/SUPPLY-CHAIN.md");
  var gitlab = readRel("templates/graphsmith.gitlab-ci.yml");

  var actionUses = thirdPartyUses(action, "action.yml");
  var ciUses = thirdPartyUses(ci, "ci.yml");

  // Dogfood job third-party pins (the local ./ does not count)
  var dogfoodIdx = ci.indexOf("dogfood-graphsmith-action");
  var dogfoodBlock = dogfoodIdx >= 0 ? ci.slice(dogfoodIdx) : "";
  var dogfoodUses = thirdPartyUses(dogfoodBlock, "ci.yml#dogfood");

  var all = actionUses.concat(ciUses);
  var badPins = all.filter(function (u) {
    return !u.ok;
  });

  if (actionUses.length === 0) {
    fail("action-has-third-party-uses", "no uses: lines found in action.yml");
  } else if (badPins.filter(function (u) { return u.scope === "action.yml"; }).length === 0) {
    pass(
      "action-third-party-full-sha",
      actionUses
        .map(function (u) {
          return u.ownerRepo + "@" + u.pin.slice(0, 12);
        })
        .join(", ")
    );
  } else {
    fail(
      "action-third-party-full-sha",
      badPins
        .filter(function (u) {
          return u.scope === "action.yml";
        })
        .map(function (u) {
          return u.raw + " " + u.reason;
        })
        .join("; ")
    );
    finding(
      "SHA-ACTION-UNPINNED",
      "critical",
      "action.yml third-party action not full-SHA pinned"
    );
  }

  var ciBad = badPins.filter(function (u) {
    return u.scope === "ci.yml";
  });
  if (ciBad.length === 0 && ciUses.length > 0) {
    pass("ci-yml-third-party-full-sha", "all " + ciUses.length + " third-party uses full-SHA");
  } else {
    fail(
      "ci-yml-third-party-full-sha",
      ciBad
        .map(function (u) {
          return u.raw;
        })
        .join("; ") || "no uses"
    );
    finding("SHA-CI-UNPINNED", "critical", "ci.yml has non-SHA pin(s)");
  }

  // Dogfood: must pin checkout OR reuse composite; local ./ for the action under test is OK
  var dogfoodLocal = /uses:\s*\.\//.test(dogfoodBlock);
  var dogfoodThirdBad = dogfoodUses.filter(function (u) {
    return !u.ok;
  });
  if (dogfoodLocal && dogfoodThirdBad.length === 0) {
    pass(
      "dogfood-job-sha-discipline",
      "dogfood uses ./ + third-party full-SHA count=" + dogfoodUses.length
    );
  } else {
    fail(
      "dogfood-job-sha-discipline",
      "local=" + dogfoodLocal + " bad=" + dogfoodThirdBad.length
    );
  }

  // Align pins between action.yml and ci.yml for the same owner/repo
  var ciByRepo = {};
  ciUses.forEach(function (u) {
    ciByRepo[u.ownerRepo] = ciByRepo[u.ownerRepo] || {};
    ciByRepo[u.ownerRepo][u.pin] = true;
  });
  var drift = [];
  actionUses.forEach(function (u) {
    var pins = ciByRepo[u.ownerRepo];
    if (pins && !pins[u.pin]) {
      drift.push(u.ownerRepo + " action=" + u.pin + " ci≠");
    }
  });
  // Soft: supply doc claims SHA taken from ci.yml
  if (drift.length === 0) {
    pass("action-ci-sha-alignment", "action.yml pins ⊆ ci.yml pins for shared actions");
  } else {
    fail("action-ci-sha-alignment", drift.join("; "));
    finding("SHA-DRIFT", "high", "action.yml pin differs from ci.yml: " + drift.join("; "));
  }

  // No pull_request_target as a trigger (comments that forbid it are fine)
  function hasPrtTrigger(yml) {
    // strip YAML comments before scanning
    var bare = yml.replace(/^\s*#.*$/gm, "");
    return /^\s*pull_request_target\s*:/m.test(bare) ||
      /on:\s*[\s\S]{0,200}pull_request_target/.test(bare);
  }
  var prtAction = hasPrtTrigger(action);
  var prtCi = hasPrtTrigger(ci);
  if (!prtAction && !prtCi) {
    pass(
      "no-pull_request_target",
      "no pull_request_target trigger (ci may mention the ban in comments)"
    );
  } else {
    fail("no-pull_request_target", "found prt trigger action=" + prtAction + " ci=" + prtCi);
    finding("PRT-PRESENT", "critical", "pull_request_target trigger present");
  }

  // permissions: contents: read at workflow top-level
  var topPerm =
    /^permissions:\s*\n\s+contents:\s*read\s*$/m.test(ci) ||
    /permissions:\s*\n\s+contents:\s*read/.test(ci);
  if (topPerm) {
    pass("ci-permissions-contents-read", "workflow permissions contents: read");
  } else {
    fail("ci-permissions-contents-read", "missing top-level contents: read");
    finding("PERMS-MISSING", "high", "ci.yml lacks contents: read");
  }

  // dogfood job permissions
  var dogfoodPerm = /dogfood-graphsmith-action:[\s\S]*?permissions:\s*\n\s+contents:\s*read/.test(
    ci
  );
  if (dogfoodPerm) {
    pass("dogfood-permissions-contents-read", "dogfood job contents: read");
  } else {
    fail("dogfood-permissions-contents-read", "dogfood job missing contents: read");
  }

  // No secret exposure on pull_request triggers for the dogfood / action path:
  // secrets. only acceptable off PR (hygiene already gated). Scan dogfood block.
  var dogfoodSecrets = /\$\{\{\s*secrets\./.test(dogfoodBlock);
  if (!dogfoodSecrets) {
    pass("dogfood-no-secrets", "dogfood job does not reference secrets.*");
  } else {
    fail("dogfood-no-secrets", "dogfood references secrets");
    finding("SECRET-ON-DOGFOOD", "critical", "dogfood job exposes secrets");
  }

  // Hygiene job gates secrets off PR — structural check on ci.yml
  var hygieneSecretGated =
    /if:\s*github\.event_name\s*!=\s*'pull_request'[\s\S]{0,200}secrets\.HYGIENE/.test(ci) ||
    /secrets\.HYGIENE_HMAC_KEY[\s\S]{0,80}/.test(ci) &&
      /if:\s*github\.event_name\s*!=\s*'pull_request'/.test(ci);
  // Narrower read: identity the hygiene step condition
  var hygieneStep =
    ci.indexOf("hygiene-scan") >= 0
      ? ci.slice(Math.max(0, ci.indexOf("List B")), ci.indexOf("dogfood-graphsmith-action"))
      : "";
  var hygieneOk =
    /if:\s*github\.event_name\s*!=\s*'pull_request'/.test(hygieneStep) &&
    /secrets\.HYGIENE/.test(hygieneStep);
  if (hygieneOk) {
    pass("hygiene-secrets-not-on-pr", "HYGIENE_* secrets gated if: event_name != pull_request");
  } else {
    // Not necessarily a failure of THE ACTION under test — note if wrong
    if (/secrets\./.test(hygieneStep) && !/if:\s*github\.event_name\s*!=\s*'pull_request'/.test(hygieneStep)) {
      fail("hygiene-secrets-not-on-pr", "secrets without PR gate in hygiene step");
      finding("SECRET-ON-PR", "critical", "hygiene secrets may run on pull_request");
    } else {
      pass("hygiene-secrets-not-on-pr", "hygiene step pattern ok or absent");
    }
  }

  // SUPPLY-CHAIN.md trust model
  var trustBits = [
    { k: "sha-pinning-principle", re: /SHA Pinning Only|pinned by full commit SHA/i },
    { k: "no-prt", re: /No `?pull_request_target`?/i },
    { k: "no-secret-on-pr", re: /No Secret Exposure on PR|secrets are never available on pull_request/i },
    { k: "contents-read", re: /contents:\s*read|Read-Only Permissions/i },
    { k: "consumer-sha", re: /pin by full commit SHA|MUST pin/i },
    { k: "unavailable-ne-fail", re: /unavailable[\s\S]{0,40}do NOT fail|unavailable[\s\S]{0,40}does NOT fail/i },
    { k: "failed-does-fail", re: /failed[\s\S]{0,40}DO fail|failed[\s\S]{0,40}ALWAYS fails/i },
  ];
  var trustMiss = [];
  trustBits.forEach(function (t) {
    if (!t.re.test(supply)) trustMiss.push(t.k);
  });
  if (trustMiss.length === 0) {
    pass("supply-chain-doc-trust-model", "docs/SUPPLY-CHAIN.md states trust model principles");
  } else {
    fail("supply-chain-doc-trust-model", "missing: " + trustMiss.join(", "));
    finding(
      "DOCS-TRUST-INCOMPLETE",
      "medium",
      "SUPPLY-CHAIN.md missing: " + trustMiss.join(", ")
    );
  }

  // GitLab consumer pin guidance
  if (/full commit SHA, never a tag/i.test(gitlab) || /MUST pin by full commit SHA/i.test(gitlab)) {
    pass("gitlab-consumer-sha-guidance", "template header requires full commit SHA pin");
  } else {
    fail("gitlab-consumer-sha-guidance", "missing consumer SHA pin note");
  }

  // action.yml description requires consumer SHA pin
  if (/pin by full commit SHA/i.test(action)) {
    pass("action-consumer-sha-guidance", "action.yml description requires SHA pin");
  } else {
    fail("action-consumer-sha-guidance", "missing");
  }

  // Tag-shaped uses must not exist
  var tagLike = all.filter(function (u) {
    return /@v\d|@main$|@master$|@latest$/i.test(u.raw);
  });
  if (tagLike.length === 0) {
    pass("no-tag-pins-anywhere", "no @vN/@main/@master/@latest on third-party uses");
  } else {
    fail(
      "no-tag-pins-anywhere",
      tagLike
        .map(function (u) {
          return u.raw;
        })
        .join(", ")
    );
    finding("TAG-PIN", "critical", "tag-shaped action pin present");
  }
}

// ---------------------------------------------------------------------------
// ATTACK 4 — JSON PARSING ROBUSTNESS (stdout pure JSON; stderr summary)
// ---------------------------------------------------------------------------
function attackJsonRobustness() {
  console.log("\n=== ATTACK 4: JSON PARSING ROBUSTNESS ===");

  // Live spawn: stdout must be pure JSON; summary on stderr
  var child = spawnSync(process.execPath, [VERIFY_JS, "--profiles"], {
    cwd: REPO,
    encoding: "utf8",
    timeout: 120000,
    maxBuffer: 8 * 1024 * 1024,
  });
  var stdout = child.stdout || "";
  var stderr = child.stderr || "";

  var parsed = null;
  var parseErr = null;
  try {
    parsed = JSON.parse(stdout);
  } catch (e) {
    parseErr = e.message;
  }

  if (parsed && parsed.profiles && typeof parsed.profile_string === "string") {
    pass(
      "verify-stdout-pure-json",
      "stdout parses; profiles=" + Object.keys(parsed.profiles).join(",")
    );
  } else {
    fail("verify-stdout-pure-json", "parseErr=" + parseErr + " outHead=" + stdout.slice(0, 120));
    finding("VERIFY-STDOUT-NOT-JSON", "critical", "verify --profiles stdout not pure JSON");
  }

  if (/verify --profiles:/.test(stderr) && parsed && stderr.indexOf(parsed.profile_string) >= 0) {
    pass("verify-summary-on-stderr", "one-line summary on stderr carries profile_string");
  } else {
    fail(
      "verify-summary-on-stderr",
      "stderr=" + stderr.slice(0, 200)
    );
  }

  // stderr must NOT be required for JSON parse — stdout alone suffices
  // (modeled: decideProfiles on stdout only)
  if (parsed) {
    var fromStdoutOnly = decideProfiles(stdout);
    pass(
      "stderr-does-not-corrupt-parse",
      "decideProfiles(stdout) parseOk=" +
        fromStdoutOnly.parseOk +
        " total=" +
        fromStdoutOnly.totalCount
    );
  }

  // Simulate bash RESULT=$(cmd) — only stdout captured — polluted if someone
  // redirected 2>&1. Prove that if stderr is concatenated, JSON parse fails,
  // AND the ACTUAL action path fail-OPENS.
  if (parsed) {
    var polluted = stdout + stderr;
    var pollutedDecision = decideProfiles(polluted);
    if (!pollutedDecision.parseOk && pollutedDecision.exitCode === 0 && pollutedDecision.overallStatus === "passed") {
      fail(
        "polluted-stdout-fail-closed",
        "ACTUAL: concat stderr→stdout makes JSON invalid, yet overall=passed exit=0 (FAIL-OPEN)"
      );
      finding(
        "JSON-FAIL-OPEN-POLLUTED",
        "critical",
        "action decision path treats malformed/empty verify JSON as overall=passed exit 0 (no set -e JSON gate). Pollution or empty output will green the build."
      );
    } else if (!pollutedDecision.parseOk && pollutedDecision.exitCode === 1) {
      pass("polluted-stdout-fail-closed", "malformed JSON fails closed");
    } else if (pollutedDecision.parseOk) {
      // stderr happened to still parse? unlikely
      pass("polluted-stdout-fail-closed", "unexpectedly still parsed — skipped");
    } else {
      fail(
        "polluted-stdout-fail-closed",
        "parseOk=" +
          pollutedDecision.parseOk +
          " exit=" +
          pollutedDecision.exitCode +
          " status=" +
          pollutedDecision.overallStatus
      );
      finding(
        "JSON-FAIL-OPEN-POLLUTED",
        "critical",
        "malformed JSON does not fail closed"
      );
    }
  }

  // Empty output
  var empty = decideProfiles("");
  if (empty.exitCode === 0 && empty.overallStatus === "passed" && empty.totalCount === 0) {
    fail(
      "empty-verify-output-fail-closed",
      "ACTUAL: empty RESULT → total=0 FAILED=0 → overall=passed exit 0 (FAIL-OPEN)"
    );
    finding(
      "JSON-FAIL-OPEN-EMPTY",
      "critical",
      "empty verify stdout yields verification-status=passed exit 0"
    );
  } else if (empty.exitCode === 1) {
    pass("empty-verify-output-fail-closed", "empty fails closed");
  } else {
    fail(
      "empty-verify-output-fail-closed",
      "exit=" + empty.exitCode + " status=" + empty.overallStatus
    );
  }

  // Explicit garbage
  var garbage = decideProfiles("not-json{{{");
  if (garbage.exitCode === 0 && garbage.overallStatus === "passed") {
    fail(
      "garbage-verify-output-fail-closed",
      "ACTUAL: garbage JSON → passed exit 0 (FAIL-OPEN)"
    );
    finding(
      "JSON-FAIL-OPEN-GARBAGE",
      "critical",
      "garbage verify stdout yields passed exit 0"
    );
  } else if (garbage.exitCode === 1) {
    pass("garbage-verify-output-fail-closed", "garbage fails closed");
  } else {
    fail("garbage-verify-output-fail-closed", "exit=" + garbage.exitCode);
  }

  // Ideal path must fail closed (document the correct behavior the action lacks)
  var idealEmpty = idealDecide("");
  var idealGarbage = idealDecide("not-json{{{");
  if (idealEmpty.exitCode === 1 && idealGarbage.exitCode === 1) {
    pass("ideal-fail-closed-baseline", "ideal decision fails closed on empty+garbage");
  } else {
    fail("ideal-fail-closed-baseline", "ideal helper broken");
  }

  // action.yml static: capture is RESULT=$(node ...) without 2>&1 — good
  var action = readRel("action.yml");
  var capture = /RESULT=\$\(node scripts\/verify\.js --profiles\)/.test(action);
  var captureMerged = /RESULT=\$\(node scripts\/verify\.js --profiles\s+2>&1\)/.test(action);
  if (capture && !captureMerged) {
    pass(
      "action-captures-stdout-only",
      "RESULT=$(node scripts/verify.js --profiles) without 2>&1 — stderr summary cannot corrupt RESULT"
    );
  } else if (captureMerged) {
    fail("action-captures-stdout-only", "captures with 2>&1 — will pollute JSON");
    finding("CAPTURE-2ERR1", "critical", "action merges stderr into RESULT");
  } else {
    fail("action-captures-stdout-only", "capture pattern not found");
  }

  // action lacks an explicit JSON validity / empty gate before STATUS=passed
  var hasJsonGate =
    /jq\b/.test(action) ||
    /JSON\.parse/.test(action) ||
    /fail.*empty|empty.*fail|invalid.*json|malformed/i.test(action);
  // node -e require path doesn't validate hard with set -e
  var hasSetE = /set -euo? pipefail/.test(action) || /set -e/.test(action);
  if (!hasJsonGate) {
    // already finding via behavioral tests; static confirm
    pass(
      "action-static-no-json-gate-observed",
      "no explicit JSON validity gate in action.yml (set -e=" + hasSetE + ") — matches fail-open behavior"
    );
  } else {
    pass("action-static-no-json-gate-observed", "gate present — behavior tests decide");
  }

  // GitLab redirects stdout only: node ... --profiles > file
  var gitlab = readRel("templates/graphsmith.gitlab-ci.yml");
  var glRedirect = /node scripts\/verify\.js --profiles\s+>\s*\/tmp\/profile-result\.json/.test(
    gitlab
  );
  var glMerged = /--profiles\s+>[\s\S]{0,20}2>&1|--profiles 2>&1/.test(gitlab);
  if (glRedirect && !glMerged) {
    pass("gitlab-stdout-only-redirect", "GitLab redirects stdout only to JSON file");
  } else {
    fail("gitlab-stdout-only-redirect", "redirect pattern missing or merged");
  }
}

// ---------------------------------------------------------------------------
// ATTACK 5 — structural parity action ↔ gitlab decision arms
// ---------------------------------------------------------------------------
function attackParity() {
  console.log("\n=== ATTACK 5: ACTION ↔ GITLAB CASE PARITY ===");
  var action = readRel("action.yml");
  var gitlab = readRel("templates/graphsmith.gitlab-ci.yml");
  var aCase = ((action.match(/case "\$PROF_STATUS" in([\s\S]*?)esac/) || [])[1] || "")
    .replace(/echo ::[a-z]+::/g, "echo ")
    .replace(/::[a-z]+::/g, "");
  var gCase = (gitlab.match(/case "\$PROF_STATUS" in([\s\S]*?)esac/) || [])[1] || "";

  function arms(block) {
    var out = [];
    var re = /^\s*([a-z0-9_*-]+)\)/gm;
    var m;
    while ((m = re.exec(block)) !== null) out.push(m[1]);
    return out;
  }
  var aArms = arms(aCase).filter(function (x) { return x !== "*"; }).sort().join(",");
  var gArms = arms(gCase).filter(function (x) { return x !== "*"; }).sort().join(",");
  if (aArms === gArms && aArms.length) {
    pass("action-gitlab-case-arms-match", "arms=" + aArms);
  } else {
    fail("action-gitlab-case-arms-match", "action=[" + aArms + "] gitlab=[" + gArms + "]");
    finding(
      "PARITY-ARMS",
      "medium",
      "action.yml vs gitlab case arms diverge: " + aArms + " vs " + gArms
    );
  }

  // Both missing verified is already a finding; confirm IDENTICAL wrong vocab
  if (aArms === gArms && /passed/.test(aArms) && !/verified/.test(aArms)) {
    pass(
      "action-gitlab-share-identical-vocab-bug",
      "both share the same wrong arm set (passed, not verified) — single root cause"
    );
  }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
function main() {
  console.log("ADVERSARIAL TESTER grok — tests/action/grok/tests.js");
  console.log("Target: action.yml + templates/graphsmith.gitlab-ci.yml + docs/SUPPLY-CHAIN.md");
  console.log("REPO=" + REPO);

  // Fresh files exist
  ["action.yml", "templates/graphsmith.gitlab-ci.yml", "docs/SUPPLY-CHAIN.md", ".github/workflows/ci.yml", "scripts/verify.js"].forEach(
    function (rel) {
      if (fs.existsSync(path.join(REPO, rel))) pass("exists:" + rel, "ok");
      else fail("exists:" + rel, "missing");
    }
  );

  attackStatusVocab();
  attackFailOnSemantics();
  attackSupplyChain();
  attackJsonRobustness();
  attackParity();

  var fails = results.filter(function (r) {
    return r.status === "FAIL";
  });
  var passes = results.filter(function (r) {
    return r.status === "PASS";
  });

  console.log("\n=== FINDINGS (" + findings.length + ") ===");
  if (findings.length === 0) {
    console.log("(none)");
  } else {
    findings.forEach(function (f, i) {
      console.log(
        String(i + 1) + ". [" + f.severity + "] " + f.id + " — " + f.summary
      );
    });
  }

  console.log("\n=== SUMMARY ===");
  console.log("PASS=" + passes.length + " FAIL=" + fails.length + " FINDINGS=" + findings.length);

  // Zero-finding invalid unless every attack surface was green AND we
  // genuinely exercised each family. If we have fails, findings must be non-empty.
  if (fails.length > 0 && findings.length === 0) {
    console.log("INVALID: FAIL without FINDINGS");
    process.exit(2);
  }
  // If everything "/passed" the meta-tests with zero findings, that is only
  // valid when no defect was observed — require we at least ran attack families
  // (results > 15). Empty FINDINGS with all PASS is allowed only then.
  if (results.length < 15) {
    console.log("INVALID: insufficient attack coverage");
    process.exit(2);
  }

  var overall = fails.length === 0 ? "PASS" : "FAIL";
  // Note: this suite is expected to FAIL while defects live — overall FAIL
  // of the suite means defects found (adversarial success).
  console.log("OVERALL\t" + overall);
  process.exit(fails.length === 0 ? 0 : 1);
}

main();
