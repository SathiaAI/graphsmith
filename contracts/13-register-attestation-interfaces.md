# Contract 13 — Register + Attestation Interfaces (FROZEN Wave 0, v0.3.0)

**Status:** FROZEN 2026-07-23 for parallel Wave-1 build. This contract is the plug-in surface the register lanes (WS-B) and the GSA core (WS-A) build against. **No Wave-1 lane edits a shared file** — each ships its own module that plugs into the interfaces frozen here. Changing anything in this document after freeze requires a Wave-0 re-open (a council-adopted-fix relaxation → HALT for Paul).

## 1. Frozen schemas (all under `schemas/`, JSON Schema draft 2020-12, `schema_version` const `"1.0"`)
| Schema | Lane | Binds |
|---|---|---|
| `attestation-bundle.schema.json` | WS-A | the GSA bundle manifest (`attestation.json`); profiles enum **R/E/B/T/G/Q/A/X** (D4) |
| `approver-attestation.schema.json` | B-A | who/how/what + detached signature over the packet sha256 |
| `obligations.schema.json` | B-B | obligation → controls[] → evidence → honest coverage verdict |
| `retention-entry.schema.json` | B-C | append-only hash-chained packet record, anchored to the adoption-log head |
| `register-policy.schema.json` | B-D/all | separation-of-duties, `fail_closed:true`, activation preconditions |
| `release-signature.schema.json` | B-D | out-of-band maintainer signature over the release manifest |

## 2. The assure packet-extension contract (namespaced, one writer per key)
`assure.js` core is **not edited** by any lane. The packet gains four frozen, namespaced sub-objects; each lane writes only its own key:

| Key | Lane | Schema | Producer |
|---|---|---|---|
| `packet.approver` | A — approver identity | `approver-attestation` | `checks/register-approver.js` |
| `packet.obligations_coverage` | B — obligations→controls (**make-or-break**) | `obligations` | the `--obligations` reconciler |
| `packet.retention` | C — evidence retention | `retention-entry` | `assure export` + integrity walk |
| `packet.release_signature` | D — air-gapped verify | `release-signature` | release-verify path |

A lane MUST NOT read or write another lane's key. The v0.2.0 packet stays valid: all four keys are OPTIONAL additions; their absence is the honest `stub:true` state.

## 3. The `verify.js` check-registry API (frozen)
`verify.js` core is **not edited** by any lane. It exposes a registry that loads lane checks by convention:

- Each lane ships `checks/register-<lane>.js` exporting:
  ```
  module.exports = {
    id: "register-approver" | "register-obligations" | "register-retention" | "register-airgap",
    // pure: no clock, no randomness, no network in the decision path (C1)
    run(ctx) -> { status: "verified"|"unavailable"|"failed"|"not-applicable",
                  evidence: string[], assumptions: string[], failure_domain?: string }
  };
  ```
- `ctx` provides read-only access to the packet, the frozen schemas, and the anchored head. The check returns the **verify.js report contract** (D3): `{status, evidence, assumptions}` + optional `failure_domain`; **`unavailable` is never rendered green**; exit mapping stays `3/1/0` (trusted-core / evolvable-surface / untrusted-input).
- The registry runs checks in a fixed, name-sorted order (determinism). A missing lane module is `not-applicable`, never a hard error.

## 4. D1–D5 resolutions (frozen; from the reconciliation worksheet + decisions doc)
- **D1 — capabilities scope: ATTEST-ENFORCED-ONLY.** The `attestation-bundle` schema carries the full `capabilities` container, but a v0.3.0 producer populates/attests **only what is actually enforced**: network egress (supervisor destination-allowlist) + external-call presence (`capability-policy.js` scanner). Per-skill fs/model/subprocess **grants are deferred to v0.3.x** and MUST NOT be attested as satisfied when unenforced. §9.7 capability-conformance asserts only enforced classes. *Never attest a boundary you don't enforce (PB-8).*
- **D2 — signing: ed25519 + local keypair** is the v0.3.0 default (matches I4 "no call home"). Keyless/transparency-log is v0.3.x (it needs network, which contradicts provable locality). `algo` enum across all signatures: `ed25519` (RECOMMENDED) | `ecdsa-p256-sha256` | `rsa-pss-sha256`.
- **D3 — verifier report contract: ADOPT `verify.js`'s** `{status, evidence, assumptions}` + `failure_domain` + exit `3/1/0`, `unavailable`-never-green, no-clock-in-decision-path. Single source of truth; the GSA §9 verifier and `graphsmith verify --profiles` agree.
- **D4 — Q profile: DONE.** `profiles` enum is **R/E/B/T/G/Q/A/X**. Q (assurance-tested) already emitted by v0.2.0 `verify.js`; A (attested) is new in GSA and is the floor (§6/§9).
- **D5 — mode is RECOMPUTED, never trusted-as-declared.** `deterministic` = auto_create_skills off · auto_promote off · remote_registries off · runtime_graph_modification off · unbounded_repair off · network deny-unless-allowlisted. `regulator` = deterministic + full adversarial battery ran (X) + `regulator_summary` present + retention-friendly export. A verifier that finds a disabled behavior in the trace MUST fail `control_attestations.deterministic_mode`.

## 5. Two cross-cutting constraints (binding on every lane — gating tests)
- **C1 — Determinism.** Identity and timestamps are **evidence, recorded — never decision inputs** (mirrors `adoption-entry.human.ts`). Every lane ships a mutation test proving no identity/timestamp field reaches a decision branch.
- **C2 — PB-8 fail-closed.** Partial / unmapped / misplaced coverage reports **`not-covered`, loudly**; regulated mode activates only on a complete, valid register. Every lane ships the fail-open repro as a gating test that MUST fail closed.

## 6. Numbering decision (LOCKED, Paul 2026-07-23) — recorded in-repo
**Everything deferred is v0.3.0.** The regulated register (approver identity, obligations→controls, retention) and air-gapped verification ship in **v0.3.0**, not a v0.2.x extension. Consequences (handled in WS-D): the `knosky-sync.js` comment and README/issue-#1 references to a *"v0.2.0 regulated extension"* are reconciled to **v0.3.0**. The honest scope line is unchanged: **GSA attests the register; it is not the register**, and the register produces **evidence, never a "compliant" verdict**.

**Reconciliation note (D7 vs numbering):** the decisions doc D7 ("ship a minimal Article-12 `regulator_summary` now; defer the *full register* to v0.2.x/v0.3.x") predates the locked numbering. Reconciled reading: the **`regulator_summary` bundle field** stays minimal (Article-12-shaped) in v0.3.0, while the **register machinery** (approver / obligations / retention / air-gapped) is built in full in v0.3.0 per WS-B. These are separable — a minimal regulator-facing field over a fully-built register. No scope is silently expanded or cut; flagged for Paul at the Wave-0 gate.
