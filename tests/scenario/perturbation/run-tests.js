#!/usr/bin/env node
"use strict";

/* Regression suite for issue #11.
 *
 * `materializeFixture` used to scale worker delay by `sha256("scale:"+treeId)[0]/64`
 * (0 - 3.98x) and shift the manager budget by `sha256("budget:"+treeId)[1]*5-200`
 * (-200 - +1075ms). Two INDEPENDENT draws. The verdict, however, is an ABSOLUTE comparison
 * against the scenario's frozen `expected` block, so on a scenario whose expectation IS a
 * wall-clock boundary the pass/fail answer was decided by whether two unrelated hash bytes
 * happened to land compatibly. Measured over 200,000 tree ids on `pipeline-budget-fail`:
 * wrong for 37.2% of them.
 *
 * Nothing in CI could catch it. `scenario.js --selftest` replays only `pipeline-normal` and
 * `fanout-normal`, with the fixed ids `selftest-cand` / `selftest-base` -- so it never draws
 * a bad pair. The defect lived entirely on the shipped
 * `replay --paired --candidate <treeId> --baseline <treeId>` path.
 *
 * WHY THIS SUITE ASSERTS ON GENERATED SOURCE rather than on a replayed outcome: a test for
 * a timing defect that decides by running the pipeline is itself timing-dependent, and on a
 * contended runner it would report losing that race as a product finding. That is the exact
 * defect class this file exists to close, so the assertions are made on the numbers baked
 * into the generated manager and workers, which are a pure function of the inputs.
 *
 * The three tree ids below are not illustrative. Each was searched for and reproduces a
 * specific pre-fix failure mode; they are pinned so a regression names its own symptom. */

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const SCENARIO = path.join(ROOT, "scripts", "scenario.js");
const { perturbationSafe, generateManager, generateWorker, TIMING_INVARIANT_OUTCOMES } = require(SCENARIO);

/* pipeline-budget-fail: workers 50/500/50 against budget 200, expecting the run to exceed
 * the budget AFTER 01-gather. The parenthesised numbers are what the OLD code produced. */
const TREES = {
  /* budget drew to 15ms while step one drew to 46ms -> died at step ONE, so
   * `completed_steps: ["01-gather"]` was violated and the tree was failed for the draw. */
  tooTight: "v-36ea7595228a446ac68e8ce1a1fed168c8b4462a406a8f44f1e7662c9868f852",
  /* budget drew to 1145ms while the whole pipeline drew to 327ms -> never exceeded at all,
   * so `outcome: "budget-exceeded"` was violated and the tree was failed for the draw. */
  tooLoose: "v-16066e03ee45a9f9818d47730ae3acc5ce71c20f5c3b1377ff5d2114c44ea990",
  /* drew compatibly (38/375/38 against 75) -- the ~63% of ids that happened to be fine.
   * Included so a regression cannot pass by making every tree look broken. */
  compatible: "v-aaa2eaa706eaa67ea93d89d4dc7b45c5770ede8bb8a16ec06e05f87be05b086c",
};

const BUDGET_SCENARIO = {
  id: "pipeline-budget-fail", shape: "pipeline", tier: "smoke", seed: 1004,
  failure_mode: "budget-fail",
  fixture: {
    pipeline: [
      { step: "01-gather", worker: "gather.js" },
      { step: "02-process", worker: "process.js" },
      { step: "03-deliver", worker: "deliver.js" },
    ],
    workers: {
      "gather.js": { behavior: "ok", delay_ms: 50 },
      "process.js": { behavior: "delay", delay_ms: 500 },
      "deliver.js": { behavior: "ok", delay_ms: 50 },
    },
    budget_ms: 200,
  },
  expected: { outcome: "budget-exceeded", completed_steps: ["01-gather"] },
  invariants: ["no-duplicate-effects", "intent-before-effect"],
};

const NORMAL_SCENARIO = {
  ...BUDGET_SCENARIO,
  id: "pipeline-normal",
  failure_mode: "none",
  expected: { outcome: "complete", completed_steps: ["01-gather", "02-process", "03-deliver"] },
};

let failures = 0;
const results = [];

function record(name, status, reason) {
  console.log(status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`);
  results.push({ name, status });
  if (status === "FAIL") failures++;
}

function check(name, cond, reason) {
  if (cond) record(name, "PASS"); else record(name, "FAIL", reason);
}

/* The generators bake their numbers into source text; read them back out. Regex rather than
 * execution because these are the literals under test. */
function budgetOf(scenario, treeId) {
  const m = /const BUDGET_MS = (\d+);/.exec(generateManager(scenario, treeId));
  if (!m) throw new Error("could not find BUDGET_MS in the generated manager");
  return Number(m[1]);
}

function delayOf(scenario, worker, treeId) {
  const src = generateWorker(worker, scenario.fixture.workers[worker], scenario, treeId);
  const m = /setTimeout\(r, (\d+)\)/.exec(src);
  if (!m) throw new Error(`could not find a delay in the generated worker ${worker}`);
  return Number(m[1]);
}

/* ---- the decision itself ---- */

function theDecisionIsDerivedNotListed() {
  check("budget-boundary-outcome-is-not-perturbation-safe",
    perturbationSafe(BUDGET_SCENARIO) === false,
    "a scenario expecting budget-exceeded was still marked safe to perturb");

  check("timing-invariant-outcomes-stay-perturbation-safe",
    ["complete", "crash-recovered", "halt"].every((o) => perturbationSafe({ expected: { outcome: o } })),
    "an outcome that does not depend on a wall-clock boundary was excluded from perturbation");

  /* The fail-safe direction. A deny-list would silently perturb a NEW timing-sensitive
   * outcome and the symptom would be a wrong verdict, not a red test. An allow-list makes
   * the unknown case merely deterministic. */
  check("unknown-outcome-defaults-to-unperturbed",
    perturbationSafe({ expected: { outcome: "deadline-missed" } }) === false,
    "an outcome nobody has classified was perturbed by default");
  check("missing-expected-block-defaults-to-unperturbed",
    perturbationSafe({}) === false && perturbationSafe(null) === false,
    "a malformed scenario was perturbed by default");

  check("outcome-set-does-not-contain-the-boundary-outcome",
    !TIMING_INVARIANT_OUTCOMES.has("budget-exceeded"),
    "budget-exceeded was added to the timing-invariant set");
}

/* ---- the three pinned trees ---- */

function pinnedTreesNoLongerMoveTheBoundary() {
  const baseBudget = BUDGET_SCENARIO.fixture.budget_ms;
  const baseFirst = BUDGET_SCENARIO.fixture.workers["gather.js"].delay_ms;
  const baseSlow = BUDGET_SCENARIO.fixture.workers["process.js"].delay_ms;

  for (const [label, tree] of Object.entries(TREES)) {
    const budget = budgetOf(BUDGET_SCENARIO, tree);
    const first = delayOf(BUDGET_SCENARIO, "gather.js", tree);
    const slow = delayOf(BUDGET_SCENARIO, "process.js", tree);

    check(`budget-scenario-unperturbed-${label}`,
      budget === baseBudget && first === baseFirst && slow === baseSlow,
      `expected the fixture's own ${baseFirst}/${baseSlow} against ${baseBudget}, got ${first}/${slow} against ${budget}`);

    /* The property that actually matters, stated directly rather than inferred from the
     * numbers being unchanged: step one fits, step one plus step two does not. */
    check(`budget-boundary-holds-${label}`,
      first < budget && first + slow > budget,
      `the expectation is not reachable for this tree: ${first} < ${budget} < ${first + slow} is false`);
  }
}

/* ---- the fix must not have simply disabled perturbation ---- */

function invariantScenariosStillVary() {
  const delays = Object.values(TREES).map((t) => delayOf(NORMAL_SCENARIO, "process.js", t));
  const base = NORMAL_SCENARIO.fixture.workers["process.js"].delay_ms;

  check("timing-invariant-scenario-is-still-perturbed",
    new Set(delays).size > 1,
    `all three trees produced the same delay (${delays.join(", ")}) -- perturbation looks disabled, not scoped`);

  check("timing-invariant-scenario-differs-from-its-base",
    delays.some((d) => d !== base),
    `every tree produced the unperturbed base delay ${base}`);

  /* Perturbation is per-tree deterministic; the evaluator's determinism check depends on it. */
  check("perturbation-is-deterministic-per-tree",
    delayOf(NORMAL_SCENARIO, "process.js", TREES.tooTight) === delayOf(NORMAL_SCENARIO, "process.js", TREES.tooTight),
    "the same tree produced two different delays");
}

/* ---- a null tree id must never perturb ---- */

function nullTreeIsNeverPerturbed() {
  check("null-tree-id-uses-the-fixture-verbatim",
    budgetOf(BUDGET_SCENARIO, null) === BUDGET_SCENARIO.fixture.budget_ms
    && delayOf(NORMAL_SCENARIO, "process.js", null) === NORMAL_SCENARIO.fixture.workers["process.js"].delay_ms,
    "a null tree id still altered the fixture");
}

/* ---- the allow-list must not go dark as the corpus grows ---- */

function everyCorpusOutcomeIsExplicitlyClassified() {
  /* An allow-list fails SAFE (an unclassified outcome is left unperturbed rather than
   * perturbed into a wrong verdict) but it fails SILENTLY: add a genuinely
   * timing-invariant outcome, forget to classify it, and the evaluator quietly stops
   * varying that whole family with nobody the wiser. Round-5 review named this as the
   * cost of choosing an allow-list, and it is a fair charge.
   *
   * So classification is made mandatory rather than optional. Every distinct
   * `expected.outcome` in the shipped corpus must be declared in exactly one of two
   * places: the product's timing-invariant set, or the list below of outcomes whose
   * expectation IS a wall-clock boundary. A new outcome in neither turns this red and
   * forces the decision to be made deliberately, which is the only thing that stops the
   * set rotting. */
  const KNOWN_TIMING_BOUNDARY_OUTCOMES = new Set(["budget-exceeded"]);

  const corpusDir = path.join(ROOT, "scenarios");
  const outcomes = new Map();
  for (const file of fs.readdirSync(corpusDir).filter((f) => f.endsWith(".json"))) {
    const sc = JSON.parse(fs.readFileSync(path.join(corpusDir, file), "utf8"));
    const outcome = sc.expected && sc.expected.outcome;
    if (!outcomes.has(outcome)) outcomes.set(outcome, []);
    outcomes.get(outcome).push(sc.id || file);
  }

  const unclassified = [...outcomes.keys()].filter(
    (o) => !TIMING_INVARIANT_OUTCOMES.has(o) && !KNOWN_TIMING_BOUNDARY_OUTCOMES.has(o));

  check("every-corpus-outcome-is-classified",
    unclassified.length === 0,
    `outcome(s) ${JSON.stringify(unclassified)} appear in the corpus but are declared neither ` +
    "timing-invariant nor timing-boundary. Decide which, in scenario.js and here -- an " +
    "unclassified outcome is silently left unperturbed, which is safe but invisible. " +
    `Scenarios: ${JSON.stringify(unclassified.map((o) => outcomes.get(o)).flat())}`);

  /* And the two sets must stay disjoint, or the derivation is incoherent. */
  const both = [...outcomes.keys()].filter(
    (o) => TIMING_INVARIANT_OUTCOMES.has(o) && KNOWN_TIMING_BOUNDARY_OUTCOMES.has(o));
  check("classification-sets-are-disjoint", both.length === 0,
    `outcome(s) ${JSON.stringify(both)} are declared BOTH timing-invariant and timing-boundary`);
}

function main() {
  theDecisionIsDerivedNotListed();
  everyCorpusOutcomeIsExplicitlyClassified();
  pinnedTreesNoLongerMoveTheBoundary();
  invariantScenariosStillVary();
  nullTreeIsNeverPerturbed();

  const passed = results.filter((r) => r.status === "PASS").length;
  console.log(`SUMMARY passed=${passed} failed=${failures} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
