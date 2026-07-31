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
GSA attests **only what is actually enforced**, per resource class:

| Class | Enforced? | By what |
|---|---|---|
| **network** | yes | supervisor destination allowlist; `--network none` under the container profile |
| **filesystem** | **no** | — see below |
| **subprocess** | **no** | — see below |
| **model** | **no** | no mechanism at this layer; needs a chokepoint in the model adapter |

**Per-skill filesystem, model and subprocess grants are NOT enforced.** A grant may declare them; nothing applies them, and the GSA capability attestation never marks them satisfied (decision D1: a class is attested only if it appears in the grant's `enforced` list, and only `network` ever does).

### Why this says "no" rather than "yes, with caveats"

An enforcement module was built on Node's Permission Model (`--permission`, `--allow-fs-read/write`) and **withdrawn**. Five rounds of adversarial review found successive ways for code inside the grant to read or write outside it, each round after the previous had been reported as fixed:

| # | Escape | Status when found |
|---|---|---|
| 1 | pre-existing **symlink** out of the tree | followed by the Permission Model; read `/etc/passwd` through one |
| 2 | pre-existing **hardlink** — a second *name* for the same inode | resolves *inside*, passes any symlink walk, and a **write** through it modifies the file outside |
| 3 | **stale audit** — clean at copy time, link planted after | evidence honest when produced, worthless when used |
| 4 | **forged spelling** — `<dir>/A/../real`, lexical vs physical | clean report for a tree nobody walked |
| 5 | audit contained against the copy, attestation about the **grant** | a link staying inside the copy while leaving the grant |
| 6 | **dangling symlink** | `realpath` fails so the audit skips it, but `open(O_CREAT)` follows it and creates the file at the target |
| 7 | a **granted path that is itself a symlink** | the audit never checked its own root |

The pattern across all seven is one thing: **the check was about a different boundary than the claim.** Each fix was narrower than the last, which is convergence — but the module was shipping a *green attestation*, and a false "enforced" in a signed bundle is worse than an honest "not enforced". So it was removed rather than shipped with a sixth round pending.

**What this costs:** nothing that was previously working. Per-skill grants were never enforced before this attempt either; this section previously said so, briefly said otherwise, and now says so again — accurately.

**What would be needed to do it properly:** the residual hole is a TOCTOU window no user-space audit can close — a link planted between the audit and `exec`. That needs the kernel: a bind mount with `nosuid`/`nodev`, a mount namespace, or a filesystem the enforced process cannot reach under any other name. A path-prefix check applied from user space to a tree an adversary can write to is the wrong tool, and the review history above is what that looks like in practice.

*Control (coarser than per-skill, and real):* the **container capability class** — a whole-run isolation boundary required for anything beyond typed edits (contract 04 B10). It runs untrusted code non-root, with all Linux capabilities dropped, `no-new-privileges`, a read-only rootfs and read-only source mount, network denied, and pid/memory/cpu caps. Each of those is verified by running a container through the real entry point (`evalenv.create("container")` → `runUntrustedCode()`) and reading `/proc/self/status` from inside — see `tests/evalenv/containment/`. That suite also asserts the profile still *functions* (the mount is readable) before making any containment claim, because an envelope nothing can run in is broken rather than secure.

## 7. Signer-trust limitations
GSA verification shows a bundle **was signed by the claimed key and is unaltered**. Whether to **trust that key is the verifier's policy** — an allowlist, an org key, or a transparency log (GSA-SPEC §5.5). The default is a local keypair, which attests "signed by *a* key"; cross-organisation non-repudiation is weaker until keyless / transparency-log signing (opt-in, targeted for a later draft). A **privileged local attacker** who can already rewrite the producer, the verifier, and the signing keys on the same machine is **out of scope, stated as such** — local self-verification detects same-user drift and mistakes, not a root adversary; CI cross-checking from a trusted workflow covers shared repositories. *Control:* the verifier-supplied trusted-key set + out-of-band maintainer signature for air-gapped verification (register Lane D, v0.3.0).

---
*This document is publication-hygiene clean. See also the worked offline-verifier transcript in [`docs/examples/offline-verify.md`](docs/examples/offline-verify.md).*
