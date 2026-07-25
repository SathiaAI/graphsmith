# GraphSmith Independent Assurance Program

> **Status:** draft for review (v0.4.0 cycle). Milestone name and the external-reviewer roster are owner-set placeholders below.
> **Scope of a passing result:** a verified GraphSmith Attestation (GSA) bundle is a complete, hash-valid, signature-valid, **unaltered** record of what a run requested and produced. It is **evidence, not certification** — it does not assert the workflow is safe, correct, or compliant.

This page describes how GraphSmith's controls are built and checked, and how an independent party can reproduce and cross-validate the results. It formalizes a practice already applied to every control in the codebase into a program a reviewer or pilot sponsor can cite.

## 1. The no-self-certification model

Every security-relevant control is built and reviewed under a fixed separation of duties:

- **Builder family ≠ tester family.** The model family that writes a control does not review it.
- **Security tier: ≥ 2 non-Anthropic tester families.** Each control is attacked by at least two independent non-Anthropic model families writing adversarial suites whose goal is to break it.
- **A zero-finding review is invalid.** A suite that finds nothing is treated as suspect and audited for rubber-stamping (inverted pass criteria, weak assertions, evidence that never creates the attack condition) before its result is accepted.
- **The orchestrator re-runs every suite.** Results are recomputed from source; exit codes and transcripts are never trusted on their own.
- **Findings are fixed or adjudicated in writing.** Each control carries an `ADJUDICATION.md` recording every real defect fixed and every tester finding adjudicated as not-a-defect, with the reasoning.

Two binding invariants apply to every control:

- **C1 — identity and timestamps are evidence, never decision inputs.** A verdict must not change based on who signed something or when. Signer identity, `added_at`/`recalled_at`, build timestamps, and bundle ids are recorded as evidence and are provably not read by the decision path.
- **C2 — fail closed.** Malformed, missing, hostile, or ambiguous input refuses loudly; it is never coerced into a pass.

## 2. What is independently verifiable

- **GSA conformance vectors.** A fixed set of input→expected-verdict vectors that any conforming verifier must reproduce (`docs/GSA-CONFORMANCE.md`, `scripts/gsa-conformance.js`). A third party runs them against their own verifier and compares.
- **Reproducibility runs.** Each control ships a `--selftest` and a recall/behavior gate; each lane ships adversarial suites under `tests/`. All are zero-dependency and run under Node ≥ 18 with no network, clock, or randomness in any decision path.
- **Verifier cross-validation.** The `graphsmith verify` bin (shipped from the `graphsmith-skill` npm package) runs the normative §9 algorithm; an independent verifier written to the same spec should agree on every conformance vector and on any real bundle.
- **Tamper-evident records.** Bundles are hash-pinned and signed; the verifier recomputes every hash and signature and fails closed on any alteration. Control attestations inside a bundle are recomputed from the bundle's own evidence, never trusted as declared.

## 3. v0.4.0 evidence

Controls added or hardened this cycle, each builder≠tester, ≥2 non-Anthropic families, orchestrator-reproduced, with an adjudication trail:

| Control | What it checks | Trail |
|---|---|---|
| Capability conformance (R1) | requested ⊆ granted per class; a class is attested only if actually enforced (D1) | `tests/v040/caps/ADJUDICATION.md` |
| Side-effect receipts (R2) | recorded external effects reconcile against adapter receipts; evidence-less success is not vouched for | `tests/v040/receipts/ADJUDICATION.md` |
| Signer lifecycle + recall (R3) | revoked signer and recalled attestation fail closed; rotation resolves to a live successor | `tests/v040/signer/ADJUDICATION.md` |
| Secret/PII redaction (R4) | an exported trace carrying an unredacted secret/PII fails closed; recall gate over a declared format set | `tests/v040/trace/ADJUDICATION.md` |
| SBOM + build provenance (R5) | SBOM digest and provenance are recomputed and matched against actual artifact hashes | `tests/v040/provenance/ADJUDICATION.md` |
| Policy-as-code (R8) | versioned enterprise-safe profiles; required control counts only when enforced; unknown profile fails closed | `tests/v040/policy/ADJUDICATION.md` |
| GSA §9.11 integration | the verifier recomputes all five run-time controls from bundle evidence and fails closed on any control-lie | `tests/gsa-ext/ADJUDICATION.md` |

## 4. How an independent reviewer engages

1. Clone the repository at a tagged release and run every `--selftest` and the adversarial suites under `tests/`.
2. Run the GSA conformance vectors against both the shipped verifier and an independent implementation; compare verdicts vector by vector.
3. Inspect each `ADJUDICATION.md` and confirm the reasoning for every finding fixed or adjudicated.
4. Construct new adversarial bundles (control-lies, malformed evidence, tampered artifacts) and confirm the verifier fails closed.
5. Report discrepancies as issues; each becomes a new gating regression vector.

## 5. Owner-set (to be filled)

- **Milestone name:** _(e.g. "GraphSmith v0.3.1 Independent Assurance" — owner to confirm)_
- **External reviewers:** _(roster to be lined up by the owner)_
- **Publication surface:** this page, mirrored to the project website and wiki after review.

---
*Language note: this page uses the project's required honest-language forms — tamper-evident, adversarially-reviewed, replay-verifiable, hash-pinned — and avoids the banned over-claim vocabulary. GraphSmith produces evidence, not an assertion of safety or compliance.*
