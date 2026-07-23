# GraphSmith Protocol — v0.1-draft

> **DRAFT — breaking changes possible until v1.0; describes implemented, tested behavior only; seeking independent implementations.**

This document is the public specification of GraphSmith's integrity and evolution protocol. It describes **only behavior that is implemented and covered by tests in this release.** Where a mechanism is a designed seam that is not yet live, it is labeled as such and never presented as done. Every semantic claim below states the assumptions it rests on; claims are written to be **narrower than the implementation**, never wider.

Spec version: **0.1-draft**. Change history and versioning policy live in [`SPEC-CHANGES.md`](./SPEC-CHANGES.md).

---

## 1. Scope and reading guide

GraphSmith is a deterministic, zero-LLM control layer around multi-agent workflows. It has two jobs: verify that the machinery on disk is the machinery that shipped, and route every change to the evolvable surface through a fixed, gated pipeline. The decision code contains no network calls and no clocks or randomness in any pass/fail branch; timestamps appear only as report metadata or injected reproducible-build values.

This spec covers four things, in order:

1. **File-format schemas** — the on-disk artifacts and where their schemas live.
2. **The five protocol invariants (I1–I5)** — the properties the protocol maintains, each with its honest scope and limits.
3. **The capability profiles (R / E / B / T / G, plus Q / X)** — evidence-carrying attestations emitted by `graphsmith verify --profiles`, replacing the earlier L1–L5 conformance ladder.
4. **The four-gate promotion pipeline** — the single change path for the evolvable surface.

**A note on language.** GraphSmith documentation is checked by a machine lint that bans unqualified over-claims and requires evidence-bearing wording instead. The protocol follows the same discipline: a check that a platform cannot establish is reported `unavailable`, never as a pass; independent measurements are reported separately and never blended into a single word.

---

## 2. File-format schemas

**Every GraphSmith artifact carries a `schema_version` field.** Consumers treat any structural or pattern violation as fail-closed corruption — a value to refuse, never to coerce or default. Published JSON Schemas ship under [`schemas/`](./schemas); the manifest and adoption-log formats are specified in `contracts/09-manifest-formats.md`; the adapter capability format in `contracts/06-adapter-capability-schema.md`.

Hashing rule across all artifacts: **raw-byte SHA-256, no content normalization at hash time** (normalizing before hashing would let byte changes evade integrity and would break byte-exact rollback). Path canonicalization — repo-relative, forward slashes, Unicode NFC, case-fold **collision refusal** — applies to paths only.

| Artifact | On-disk location | Schema / spec | `schema_version` |
|---|---|---|---|
| Release manifest | `release.manifest.json` (ships inside the release artifact) | `contracts/09` (`kind: "release"`) | `1.0` |
| Project manifest | `.graphsmith/state/project.manifest.json` | `contracts/09` (`kind: "project"`) | `1.0` |
| Tree manifest | `.graphsmith/evolvable/v-<treehash>/tree.manifest.json` | `schemas/tree-manifest.schema.json` | `1.0` |
| ACTIVE pointer | `.graphsmith/evolvable/ACTIVE` | `schemas/active-pointer.schema.json` | `1.0` |
| Adoption-log entry | `.graphsmith/state/adoption-log.jsonl` | `schemas/adoption-entry.schema.json` | `1.0` |
| Lesson event / evidence map | `events-proposer.jsonl`, `events-evidence.jsonl` | `schemas/lesson-event.schema.json` | `1.0` |
| Adapter capability | `adapters/<name>.capability.json` | `contracts/06` (JSON Schema 2020-12) | `1.0` |
| Promotion journal | `.graphsmith/state/journal.jsonl` | `schemas/promotion-journal.schema.json` | `1.0` |
| State-store records | `.graphsmith/state/*.jsonl`, `window.json` | `schemas/state-store.schema.json` | `1.0` |
| Scenario | corpus scenario files | `schemas/scenario.schema.json` | `1.0` |
| Verify integrity report | stdout of `verify --integrity` | report envelope (below) | `1.0` |
| Verify profiles report | stdout of `verify --profiles` | report envelope (below) | `1.0` |

### 2.1 Key shapes

- **Manifests** (release and project) share a shape: `{ schema_version, kind, release, algo, files: [{ path, sha256 }], constitutional_set: […], tunables_bounds: {…}, created_by: {…} }`. The project manifest adds `parent_release_sha256`, `adoption_log_head` (the anchored head), and `workflow_manifests`. The two are independent trust domains (see I1).
- **ACTIVE pointer**: `{ schema_version, txid, tree, tree_manifest_sha256 }` — a small file naming the active versioned tree and binding its manifest by hash. Read once at run start.
- **Tree manifest**: a **closed inventory** of every payload file in a versioned tree (`files: [{ path, sha256, bytes }]`), excluding only `tree.manifest.json` itself. Loaders and recovery refuse any extra or missing payload file.
- **Adoption-log entry**: `{ schema_version, seq, txid, status: "committing"|"effective"|"aborted", fingerprint, kind, evidence_ref, human: {name, decision, ts}, prev_sha256, entry_sha256 }` — a hash-chained JSONL record.
- **Lesson events** are split into a **proposer view** (closed enums, numbers, and opaque aliases such as `r03`/`s01`/`p02` only — no producer-controlled strings) and a **human evidence map** (alias → real run/step/path, never placed in model context). This split is the only representation in which harvested run data reaches a proposer.

---

## 3. The five protocol invariants (I1–I5)

Each invariant is stated as tested behavior with its explicit limits. None claims prevention where the implementation only detects.

### I1 — Verified integrity at every boundary

A deterministic, zero-LLM **Integrity Sentinel** (`graphsmith verify`) runs at each trust boundary — session start, resume, checkpoint load, prompt/appendix load, adapter load, pre/post heal-evolve, pre-adoption, migration/upgrade, CI, and on demand. "Continuous" here means **continuous-at-every-boundary**, not a resident background monitor.

There are **two independent trust domains**, reported separately and never blended:

- **release-verified** (`yes | no | unavailable`) — the release manifest, whose hashes are pinned by the package integrity chain that delivered the artifact, matches the files on disk.
- **self-consistent** (`yes | no`) — the project manifest, generated at install/scaffold, matches the files on disk.

A plain development checkout that was never installed from a release artifact legitimately reports `release-verified: unavailable` — an honest gap, not a failure.

**Limit:** a privileged local attacker who can rewrite the sentinel and both manifests is **out of scope, stated as such** (attacker class A6). Local self-verification detects same-user drift and mistakes and compromised dependencies; it does not defend against an adversary who already controls the account/host and rewrites the trust anchors. CI cross-checking from a trusted workflow covers shared repositories.

### I2 — Hash-pinned core, one multi-gated change path

The **constitutional core** — the discipline rules, safety halts, human gates, data boundary, and the enforcement machinery itself (gate.js, the sentinel, the event compiler, the risk policy, the scenario runner, loaders, supervisor, CI entries, and every declared bound including tunables' min/max) — is hash-pinned and unreachable by any evolution path. The authoritative constitutional set is named in the release manifest.

**All** evolvable-surface change flows through the four-gate promotion pipeline (§5); the pipeline definition is itself constitutional. **Rollback is not a second path** — it executes an inverse transaction that the human pre-authorized at Gate 3.

### I3 — Isolated evaluation before acceptance

Every machine-evaluated candidate first runs in a **disposable evaluation copy with mocked effects**. Two profiles:

- **Standard profile** — a separate directory tree (a full copy, not a linked git worktree, so there is no shared git metadata), its own or no `node_modules`, stubbed side-effect adapters, a secret-scrubbed default-deny environment, runtime permission flags where supported, and supervisor budgets. **No confidentiality or network-containment claim is made for the standard profile.**
- **Container profile** (opt-in) — adds network denial (a **socket-denial test**) and read-only source, and is **required for anything beyond typed edits**.

The real containment in this release is scope: **v0.2.0 machine-evaluates only typed, schema-validated document/knob edits — never generated code.** Code repairs are staged for a human, never machine-applied.

### I4 — Local evolution, no automatic upstream contribution ("don't call home")

**GraphSmith sends no telemetry, learned state, artifacts, or diagnostics to maintainers or any upstream service, automatically, ever.** This is a claim about GraphSmith's own behavior; it does **not** claim your workflows are offline — your workers may call model APIs. Setting `offline: true` in config separately disables all GraphSmith-originated network activity.

Learned state lives in user-owned files; the installed skill is read-only at runtime and hash-verified; no automated contribution path exists. Users contribute as humans, aided by `graphsmith diagnostics export` — local report generation with preview and redaction, aggregate counters by default, raw prompts excluded, no upload code, and a warning that issue trackers are public.

**Tested scope of the I4 claim:** across a full heal + evolve + adopt cycle, GraphSmith processes started with `offline: true` are exercised under a scoped socket-denial test showing no automatic egress to upstream, and the diagnostics export is tested to be upload-free. This attests the tested paths; it is not a claim about arbitrary user-supplied worker code.

### I5 — Observable, budgeted, killable runs

Every scaffolded run declares deterministic **budgets**; the manager enforces them before any model gets a vote. Runs are observable (`graphsmith watch`). **Tripwires are manager-observed policy checks** (honest scope — not OS-level mediation) that auto-HALT and never auto-continue.

**Kill-safety is adapter-capability-specific.** Resumability of *recorded* state is exercised by a crash/recovery (chaos) harness. On kill/resume, for each intent without a recorded completion, the message states one of:

- **no external effects in flight** (read-only, or nothing pending);
- **safe to resume** — a `local-transactional` effect whose landed/not-landed state was inspected, or an `idempotent-by-key` effect that will retry with the recorded key **assuming the remote honors that key** (an adapter-author declaration, not verified by GraphSmith);
- **reconciliation required** — intent recorded, completion unknown → the loud-HALT path with printed check/fix instructions.

Every unresolved intent defaults to **reconciliation required** until a rule affirmatively upgrades it. Earlier "exactly-once" wording is retired in favor of these capability-class messages (contract 06).

---

## 4. Capability profiles (R / E / B / T / G, plus Q / X)

`graphsmith verify --profiles` emits **evidence-carrying capability profiles**. They replace the older L1–L5 ladder: profiles are **independent axes**, not a linear rank. Each profile returns:

```
{ status ∈ verified | unavailable | failed | not-applicable, evidence[], assumptions[], phase? }
```

A profile a platform cannot establish is `unavailable` with a reason — it is **never** `verified`. Independent axes are never collapsed into one score.

There are two kinds of profile:

- **Capability attestations (R, B, G)** exercise *this installation's* machinery against an **ephemeral fixture under the OS temp directory** — never the target project's live state (a passive sentinel must not take the state-store write lock on a live project). The evidence is a freshly produced recover / halt / refusal from the installed modules.
- **Target attestations (E, T, Q, X)** inspect the project at the root. On a plain checkout these are legitimately `unavailable` (no adapters / no release trust root / not a workflow project).

The report envelope carries `schema_version`, `command: "profiles"`, `platform`, `node_version`, `root`, an **injected** `evaluated_at` (from `--evaluated-at`, `GRAPHSMITH_EVALUATED_AT`, or `SOURCE_DATE_EPOCH`; `unavailable` if none — a decision-path clock call is forbidden), the per-profile results, and a `profile_string` of the form `R:<status> E:<status> B:<status> T:<status> G:<status> Q:<status> X:<status>`.

### R — Resumable local state (capability)

**Check.** Two ephemeral state-store fixtures under the OS temp directory. (1) A committed state survives a restart with a byte-identical slot projection (recovery is a no-op on clean state). (2) A mutation torn by a simulated mid-write crash (the state-store's own test-mode crash hook) is rolled forward by the real journal recovery run in the store constructor. Evidence: the pre/post-restart state hashes and match flag, plus `crash_simulated` and `torn_run_present_after_recovery`. `verified` only when the clean round-trip matches **and** the crash was simulated **and** the torn run is present after recovery.

**Assumptions (verbatim):**
> R is a CAPABILITY attestation of THIS installation's state-store: it exercises a real checkpoint/journal round-trip and a real kill-and-recover on an ephemeral fixture under the OS temp dir — never the target project's live .graphsmith/state (a passive sentinel must not take the state-store write lock on a live project).
>
> The simulated kill uses state-store's own GRAPHSMITH_TEST_MODE crash hook (_testing.crashNextMutationAfter); the RECOVERY exercised is the real, un-mocked journal roll-forward run in the StateStore constructor. State hashes cover clock-free identity fields (run_id/status slots), not lease timestamps.

### E — Effect-reconciled external calls (target)

**Check.** Presence and shape of `adapters/<name>.capability.json` (each needs `schema_version` `1.0`, an `adapter_id` matching `^[a-z0-9-]+$`, a `version` string, and an `effects` array), then a **static** mapping of each declared effect's capability variant to its kill/resume reconciliation class: `read` → no-external-effects; `local-transactional` / `idempotent-by-key` → safe-to-resume; `status-checkable` / `none` → reconciliation-required. Zero adapters → `unavailable`; a structurally invalid declaration or an unmappable effect → `failed`; otherwise `verified`.

**Assumptions (verbatim):**
> E depends entirely on adapter capability declarations (contract 06, adapters/<name>.capability.json). A project that declares zero adapters has no external effects to reconcile — reported 'unavailable', never 'verified'.
>
> E is a STATIC declaration check: it maps each declared effect's capability variant to its kill/resume reconciliation class per contract 06 […]. It does NOT run the runtime reconciliation state machine (e.g. a live status_check); 'status-checkable' is classified conservatively as reconciliation-required until a runtime authoritative status check upgrades it.

### B — Budget-enforced (capability)

**Check.** Scaffold an ephemeral supervised project under the OS temp directory, load its generated supervisor, set `max_steps = 1`, and drive a step budget breach. The supervisor must trip a HALT whose recorded evidence is a `budget`-kind halt with a rule string and an evidence object. Evidence: the recorded halt.

**Assumptions (verbatim):**
> B is a CAPABILITY attestation: it scaffolds an ephemeral supervised project under the OS temp dir, loads its generated supervisor (scaffold.js's supervisor.js), and drives a real budget breach — proving THIS installation's supervisor trips a HALT with recorded evidence. It does not run against the target project.
>
> One representative budget (max_steps) is breached here; scaffold.js's own --selftest exercises the full plan-§7 budget + tripwire matrix.

### T — Trust-root verified (target)

**Check.** Derived from the integrity run: `verified` when `release-verified: yes` **and** `self-consistent: yes`; `unavailable` when `release-verified: unavailable` (no release manifest to anchor to); otherwise `failed`. The two axes are surfaced verbatim in the evidence alongside the failure domain.

**Assumptions (verbatim):**
> T depends on the release trust root: release-verified anchors to the release manifest, self-consistent to the project manifest. These are INDEPENDENT axes (contract 09) and are never collapsed into one score.
>
> 'unavailable' when this checkout was never installed from a release artifact (no release manifest to anchor to) — an honest gap, never green.

### G — Gated learning enabled (capability)

**Check.** Build an ephemeral ACTIVE-pointer fixture and hash it. Run `gate1Static` and `gate3Prepare` on a document candidate, stage the resulting propose-only record into the pending queue, confirm `listPending` shows it, then call `adopt` **without** confirmation. The adopt must refuse, and the ACTIVE pointer must be byte-identical before and after. Evidence: the Gate-1 pass, the Gate-3 packet (reversible / auto-rollback-eligible flags), the pending listing, the refusal, and the unchanged ACTIVE hash. The failure condition is asymmetric: ACTIVE changing after a no-confirm adopt (auto-adoption) is `failed`; a refusal that leaves ACTIVE unchanged is `verified`.

**Assumptions (verbatim):**
> G is a CAPABILITY attestation: it stages a real proposal through gate.js and adopt.js against an ephemeral evolvable fixture — proving Gate-3 is propose-only and adoption requires explicit human confirmation. It does not touch the target project's ACTIVE pointer.
>
> The failure condition is asymmetric and honest: ACTIVE changing after a no-confirm adopt (auto-adoption) is 'failed'; a refusal that leaves ACTIVE byte-identical is 'verified'.

### Q — Assurance-tested (target)

**Check.** Only for a workflow project (`manager.js` + `pipeline.json` at the root). Runs the test battery (unit + scenario-regression + smoke) and an architectural lint. `verified` only when **both** the battery passes and the lint is clean; if the lint is unavailable, Q is `unavailable`, not green; if there is no workflow, `unavailable`. Evidence: the test-suite status/summary/failed-ids/hash and the lint status/findings count.

**Assumptions (verbatim):**
> Q inspects the TARGET workflow at the project root. 'unavailable' (never 'verified') when the target ships no test workflow (no manager.js + pipeline.json).
>
> A passing battery is a FLOOR of tested discipline checks, not proof of correctness (§17 honest-scope boundary).
>
> Q is 'verified' only when BOTH the test battery passes AND architectural lint is clean; if lint is unavailable (graphlint absent) Q is 'unavailable', not green.

### X — Adversarially-tested (target)

**Check.** Only for a workflow project. Runs GraphSmith's discipline/injection **architecture** battery in the evaluation-isolation environment. An `arch.sandbox-open` evidence entry must be present and not `unavailable` before any pass/fail ruling stands (isolation must be confirmed open); otherwise `unavailable`. `verified` only when the battery status is `pass`. Evidence: the battery status/summary/failed-ids/hash, the isolation state, and a model-family-diversity note.

**Assumptions (verbatim):**
> X runs GraphSmith's discipline/injection ARCHITECTURE battery in the redteam I3 sandbox against the target workflow. It tests whether injected content can reach control flow / evolution paths — it does NOT test model-level jailbreak resistance (that belongs to dedicated LLM red-team tools via the §17 external-tool seam).
>
> Model-family diversity is NOT applicable to this architecture battery: the cases are deterministic and model-independent. Model-family-diversity reporting applies only to model-level suites plugged in via the seam.
>
> 'unavailable' (never 'verified') when the target ships no workflow to adversarially test, or when the I3 sandbox cannot be opened on this platform.
>
> A passing battery is a FLOOR: the architecture resisted the shipped/planted cases. Not proof of security (§17 honest-scope boundary).

---

## 5. The four-gate promotion pipeline

Every adoption — and every Gate-4 rollback — executes the same promotion transaction (`contracts/01`). The evolvable surface is materialized as **write-once versioned trees**; a single small pointer file (ACTIVE) names the active tree; a commit is one journaled pointer-file replace. Trees are never modified after validation, and readers see exactly one of the old tree or the new tree — never a mix.

### Gate 1 — Static (deterministic)

`gate1Static(candidate, ctx)`. Checks: fence write-set (a candidate may only touch the evolvable surface), typed-schema validation of each edit, a contradiction screen (advisory-strength), an injection screen on human-promoted prose, appendix caps, fingerprint dedup against the rejected buffer, and a sentinel pass. Proposer edits are addressed by **opaque alias**; any literal path in proposer output is an automatic reject (a real path there is by construction hallucinated or leaked). Fail → reject and buffer the fingerprint.

### Gate 2 — Behavioral (sign-test statistics)

`gate2Behavioral(...)` decides over a recorded, hashed evidence bundle produced by the replay runner; the decision function is deterministic even though replay is honestly stochastic where model providers are. The statistics are normative (`contracts/03`):

- Order: hard invariants → critical slices → one predeclared primary endpoint; short-circuit, never averaged across tiers.
- v0.2.0 freezes **one endpoint type: binary scenario pass/fail.** Continuous scores surface descriptively only.
- Primary endpoint: a **one-sided exact sign test on discordant pairs at α = 0.05** (Bonferroni-split into three preallocated confirmation slots at α = 0.05/3 per corpus state, family-wise error ≤ 0.05). Scenarios are the unit of analysis; runs are paired and seeded.
- A durable alpha ledger records a reservation before any confirmation data is read; a reservation consumes its slot even across a crash.
- Underpowered cycles are declared `INCONCLUSIVE_UNDERPOWERED` up front (not a rejection). Verdicts are reported as promote / reject / inconclusive, never as a claim of correctness.

### Gate 3 — Provisional human adoption (the human packet)

`gate3Prepare(...)` is a pure function producing the adoption packet: the staged diff, a plain-English explanation, the evidence reference, the **pre-authorized inverse transaction**, and `reversible` / `autoRollbackEligible` flags (auto-rollback eligibility is document/knob edits with compatible schemas only). Applying the packet is the promotion transaction, which requires **explicit human confirmation** — `adopt` without confirmation refuses and does not touch ACTIVE. The adoption log is a hash-chained JSONL whose head is anchored in the protected project manifest; it is described as **rewrite-detecting relative to an anchored head**, never as unchangeable.

### Gate 4 — Observation window (operational canary)

An operational canary, **not** a statistical gate. It is **serialized**: at most one active window per project, and no new adoptions while a window is open. A window observes the next N runs (default 5) against the baseline pinned in the adoption packet. Triggers (hard beats soft):

- **Hard** — a hard-invariant failure, budget breach, or tripwire HALT in an observed run → **auto-rollback** by executing the Gate-3 pre-authorized inverse (permitted only for reversible document/knob changes with compatible schemas; code, migrations, and external effects require human forward-recovery), else HALT for a human.
- **Soft** — the predeclared primary metric dipping below baseline → set a FLAG bit and continue; a human reviews at close. Never an auto-rollback.
- **Abandoned** run (crash/OOM/power, lease expired) → the window closes `CLOSED_FLAGGED` for human review; abandonment never auto-rolls-back and never silently passes.

Rolled-back fingerprints are buffered against automatic re-proposal. Gate-4 observations are evidence for humans; they never become proposal or training input automatically.

---

## 6. Trust model and out-of-scope statement

Named attacker classes (`contracts/05`): A1 same-user malicious code (detection only), A2 compromised dependency, A3 hostile contributor, A4 injection via workflow artifacts (the core case), A5 malicious bring-your-own test/tool (container profile required), and **A6 privileged local attacker — out of scope, stated as such.**

`graphsmith verify --trust-model` prints the circular-trust limit: local self-verification detects drift, same-user mistakes, and compromised dependencies, but cannot defend against an attacker who already controls the account/host and rewrites the sentinel and both manifests. The release manifest is the anchor for release-verified; CI cross-checking from a trusted workflow covers shared repositories.

Standing assumptions published with the property matrix: the release artifact's integrity chain is the trust root; the Node.js runtime is uncompromised; the human at Gate 3 reads what they approve (GraphSmith's duty is a plain-English, complete, and honest packet); GraphSmith never prints secrets into logs or evidence.

---

## 7. Verification surface (commands)

- `graphsmith verify --integrity` — the dual-manifest and boundary checks. Exit code `0` (no failure), `1` (evolvable-surface defect → promotion frozen), or `3` (trusted-core defect → managed execution halted). Failure domains: an untrusted-input defect quarantines the object and lets other features continue; an evolvable-surface defect freezes promotion paths; a trusted-core defect halts. Tamper is never silently repaired.
- `graphsmith verify --profiles` — the capability profiles of §4.
- `graphsmith verify --trust-model` — the circular-trust limit in the contract's own words.
- `graphsmith verify --platform-probe` — actually performs a rename-replace while a read handle is held open and reports the **probe-verified** behavior on this platform (never an assumed result), with bounded retry on transient `EPERM`/`EBUSY`.
- `graphsmith verify --selftest` — runs the constitutional attack corpus against a disposable fixture built under the OS temp directory.

---

## 8. Independent implementations

This protocol is published in the hope that others build against it. The invariants, schemas, profile definitions, and gate semantics above are the contract surface. Because this is a `0.1-draft`, expect breaking changes before `v1.0`; track them in [`SPEC-CHANGES.md`](./SPEC-CHANGES.md). Feedback and independent implementations are welcome through the public issue tracker.
