# GraphSmith Attestation (GSA) — Known Limitations

> **Evidence, not certification.** A valid GSA bundle records *what a run requested and produced, and that the record is unaltered* — it does not show the workflow is safe, correct, or compliant. This page consolidates the honesty boundaries stated across [`SECURITY.md`](.plans/v0.3.0/graphsmith-v0.3.0-SECURITY.md), the threat model's residual-risks section, the compliance-evidence crosswalk, and the README. Each limitation states the honest boundary and the control that *partially* addresses it. Nothing here is new scope — it is the scattered caveats gathered in one place.
>
> Language follows the repo's honest-language lint: results are **tested** (not "proven"), records are **tamper-evident** (not "tamper-proof"), pins are **hash-pinned**, external effects are **run-once / replay-verified** (not "exactly-once"), effect behaviour is described by **capability class**, and independent checking is **adversarial review**.

## 1. What GSA verifies
A conformant verifier runs the ordered §9 checks and fails closed at the first violation:
- **Manifest validity + path safety** — the manifest matches the schema; every artifact path is canonical (no traversal, no backslash, NFC).
- **Artifact integrity** — every artifact's recomputed raw-byte SHA-256 and length match the manifest (hash-bound).
- **Manifest + graph signatures** — the record is **tamper-evident**: any change to the manifest or the plan (graph / policy / skill-set hashes) invalidates the signature.
- **Recomputed control attestations** — all five controls are recomputed from the run's own evidence and must match what the bundle claims; a **contradictory bundle does not verify** (e.g. an executed unsigned skill alongside `all_skills_signed_and_approved=true`).
- **Profiles** — a profile the evidence does not support is downgraded to `unavailable`, never rendered green.

*Control:* the reference verifier (`scripts/gsa-verify.js`), exercised by the cross-family adversarial review recorded in `tests/gsa/ADJUDICATION.md`.

## 2. What GSA does NOT verify
- **That a workflow is safe, correct, or compliant.** A passing adversarial-review battery is a **floor**, not a proof of security, and never evidence of compliance to a regulator.
- **Model-level jailbreak / prompt-injection of the LLM itself.** GSA tests *architecture-level* injection resistance — that untrusted text is kept out of control flow and evolution paths — not model internals. *Control:* route model-jailbreak findings to dedicated LLM red-team tools through the external-tool seam, which records their results alongside the bundle.
- **The internals of third-party skills or external tools you install.** GSA records their provenance and runs them under the container capability class; it does not audit their code.
- **Anything with the documented controls disabled** (e.g. running with deterministic/enterprise-safe mode off). The attestation reports the posture it observed; it cannot vouch for a run that turned its controls off.
- **The compliance program itself** — data-layer access control and data minimisation at source; model validation, bias/fairness, and accuracy testing; the human-oversight *process*; risk classification / DPIA; vendor management; and the legal determination of compliance. GSA gives the verifiable technical substrate those programs stand on, and says so. *Control:* the compliance-evidence crosswalk maps each obligation to the control that produces evidence for it, and marks obligations with no executable control as manual-only — never covered.

## 3. Replay limitations
Replay recomputes the **deterministic** hashes from the bundle's own contents and confirms they reproduce. **Model-dependent steps are not replayable** — a run that called a model is reported `non_replayable`, shown as `unavailable`, never green. Replay confirms the record is internally reproducible; it does not re-execute external calls. *Control:* `scripts/gsa-plan.js` `replayBundle`, which lists non-replayable steps explicitly.

## 4. External side-effect limitations
The crash/recovery (chaos) harness tests exactly two properties: crash recovery, and **run-once, replay-verified** execution of *recorded* effects, with a loud halt when an external send's outcome is uncertain. This is **not** exactly-once against the outside world: true **single-delivery to an external system requires an idempotency key that system honours** (an `idempotent-by-key` capability-class declaration by the adapter author, not something GSA verifies). Every unresolved intent defaults to **reconciliation-required** until a rule affirmatively upgrades it. *Control:* the write-ahead intent + loud reconciliation halt (invariant I5) and the adapter capability classes in `contracts/06`.

## 5. Generated-skill limitations
GSA machine-evaluates only typed, schema-validated document/knob edits. **Generated code is never machine-applied** — code repairs are staged for a human through the four-gate pipeline. The `auto_skill_creation_disabled` control attestation records that no autonomously-created, unapproved skill ran in the same trust flow; if one did, the bundle does not verify that control. *Control:* the four-gate promotion pipeline (Gate 3 is propose-only; adoption requires explicit human confirmation) + the recomputed control attestation.

## 6. Per-skill capability limitations
GSA v0.3.0 attests **only what is actually enforced**: network egress (the supervisor's destination allowlist) and external-call presence (the capability-policy scanner). **Per-skill filesystem, model, and subprocess grants are not enforced per skill in v0.3.0** — that enforcement lands in **v0.4.0**; until then it is the container capability class (required for anything beyond typed edits), attested at the profile level, not a per-skill grant. GSA does not attest a boundary it does not enforce. *Control (interim, coarser than per-skill):* the container capability class — a whole-run isolation boundary required for anything beyond typed edits — stands in for per-skill grants until v0.4.0; the enforced-only capability attestation (decision D1) reports honestly what *is* enforced and marks the rest unavailable rather than claiming it.

## 7. Signer-trust limitations
GSA verification shows a bundle **was signed by the claimed key and is unaltered**. Whether to **trust that key is the verifier's policy** — an allowlist, an org key, or a transparency log (GSA-SPEC §5.5). The default is a local keypair, which attests "signed by *a* key"; cross-organisation non-repudiation is weaker until keyless / transparency-log signing (opt-in, targeted for a later draft). A **privileged local attacker** who can already rewrite the producer, the verifier, and the signing keys on the same machine is **out of scope, stated as such** — local self-verification detects same-user drift and mistakes, not a root adversary; CI cross-checking from a trusted workflow covers shared repositories. *Control:* the verifier-supplied trusted-key set + out-of-band maintainer signature for air-gapped verification (register Lane D, v0.3.0).

---
*This document is publication-hygiene clean. See also the worked offline-verifier transcript in [`docs/examples/offline-verify.md`](docs/examples/offline-verify.md).*
