/* GraphSmith gauntlet adjudication — tests/gauntlet/adjudicate.js.
 *
 * Shared, IDENTITY-BASED HOLD/BREAK adjudication for the v0.3.0 + v0.4.0
 * batteries. Both used to compare a suite's FAIL *count* against the number of
 * adjudicated false-positives in its ADJUDICATION.md. A count is not an
 * identity: if a documented false-positive starts passing (a tester harness got
 * fixed) at the same moment a NEW, real failure appears, the total is unchanged
 * and the battery reports "hold" — masking a live regression behind someone
 * else's adjudication. Each adjudicated FAIL is now matched by NAME, and each
 * name is consumed at most once, so a substituted failure is a BREAK.
 *
 * IDENTITY of a FAIL line = the text after "FAIL ", truncated at the first "{"
 * and whitespace-collapsed. The truncation exists because some harnesses print
 * the component's own JSON verdict after the case name (ids/hashes/evidence
 * strings vary run to run); nothing before a "{" is component output. Anything
 * else in the line — including "expected=... actual=..." — is part of the
 * identity ON PURPOSE: if the component's behaviour changes, the line changes,
 * the adjudication no longer matches, and a human must re-adjudicate rather
 * than inherit a verdict that was reached about different behaviour.
 *
 * Names still failing that are NOT adjudicated -> BREAK (gates the merge).
 * Adjudicated names that no longer fail -> STALE: reported, never a BREAK; a
 * tester assertion being fixed is progress, not a regression.
 *
 * Reproduce: node tests/gauntlet/adjudicate.js --selftest
 */
"use strict";

function identity(failLine) {
  var body = String(failLine).replace(/^FAIL[ \t]+/, "");
  var cut = body.indexOf("{");
  if (cut !== -1) body = body.slice(0, cut);
  return body.replace(/\s+/g, " ").trim();
}

function failIdentities(out) {
  var lines = String(out).match(/^FAIL[ \t].*$/gm) || [];
  return lines.map(identity);
}

/* adjudicate(out, adjudicatedNames) ->
 *   { failCount, unexpected: [identity...], stale: [name...] }          */
function adjudicate(out, adjudicatedNames) {
  var found = failIdentities(out);
  var remaining = (adjudicatedNames || []).slice();
  var unexpected = [];
  for (var i = 0; i < found.length; i++) {
    var at = remaining.indexOf(found[i]);
    if (at === -1) unexpected.push(found[i]);
    else remaining.splice(at, 1);
  }
  return { failCount: found.length, unexpected: unexpected, stale: remaining };
}

function selftest() {
  var failures = [];
  var passed = 0;
  function check(name, cond, detail) {
    if (cond) { passed++; console.log("  ok   " + name); }
    else { failures.push(name); console.log("  XX   " + name + (detail ? " -- " + detail : "")); }
  }

  check("identity strips the FAIL prefix and collapses whitespace",
    identity("FAIL   null-context  ") === "null-context");
  check("identity truncates at the component's JSON output",
    identity('FAIL proto-pollution {"status":"verified","evidence":["a"]}') === "proto-pollution");
  check("identity keeps expected/actual detail (a behaviour change must re-adjudicate)",
    identity("FAIL ipv4-bypass expected=failed actual=verified") === "ipv4-bypass expected=failed actual=verified");

  var one = adjudicate("PASS a\nFAIL known-fp detail\n", ["known-fp detail"]);
  check("an adjudicated failure is absorbed, nothing unexpected",
    one.failCount === 1 && one.unexpected.length === 0 && one.stale.length === 0, JSON.stringify(one));

  var sub = adjudicate("FAIL brand-new-real-break\n", ["known-fp"]);
  check("SUBSTITUTION: adjudicated FP fixed + a new real failure = BREAK (the count-based gate said hold)",
    sub.failCount === 1 && sub.unexpected.length === 1 && sub.unexpected[0] === "brand-new-real-break" &&
    sub.stale.length === 1 && sub.stale[0] === "known-fp", JSON.stringify(sub));

  var dup = adjudicate("FAIL known-fp\nFAIL known-fp\n", ["known-fp"]);
  check("an adjudication is consumed ONCE — a second identical failure is unexpected",
    dup.unexpected.length === 1, JSON.stringify(dup));

  var pre = adjudicate("FAIL proto-pollution-2 extra\n", ["proto-pollution"]);
  check("a longer name is NOT absorbed by a shorter adjudicated one",
    pre.unexpected.length === 1 && pre.stale.length === 1, JSON.stringify(pre));

  var stale = adjudicate("PASS everything\n", ["known-fp"]);
  check("an adjudicated FP that stopped failing is STALE, not a BREAK",
    stale.failCount === 0 && stale.unexpected.length === 0 && stale.stale.length === 1, JSON.stringify(stale));

  var multiline = adjudicate("noise FAIL not-at-line-start\nFAIL real-one\n", ["real-one"]);
  check("only line-anchored FAIL lines count",
    multiline.failCount === 1 && multiline.unexpected.length === 0, JSON.stringify(multiline));

  console.log("");
  if (failures.length) {
    console.log("adjudicate selftest: FAILED — " + failures.join("; "));
    return false;
  }
  console.log("adjudicate selftest: OK (" + passed + " checks)");
  return true;
}

if (require.main === module) {
  if (process.argv.indexOf("--selftest") !== -1) process.exit(selftest() ? 0 : 1);
  console.error("Usage: node tests/gauntlet/adjudicate.js --selftest");
  process.exit(2);
}

module.exports = { identity: identity, failIdentities: failIdentities, adjudicate: adjudicate, selftest: selftest };
