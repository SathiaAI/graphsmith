# SPEC-CHANGES — GraphSmith Protocol

> **DRAFT — breaking changes possible until v1.0.** This file tracks changes to [`GRAPHSMITH-PROTOCOL.md`](./GRAPHSMITH-PROTOCOL.md) using semantic versioning, governance-lite.

## Versioning policy

The protocol is versioned `MAJOR.MINOR[-tag]`:

- **MAJOR** — an incompatible change to a wire format, an invariant, a profile definition, or a gate semantic. Independent implementations must expect to change code.
- **MINOR** — a backward-compatible addition (a new optional field, a new profile, a clarified limit) that does not break a conforming reader.
- **-tag** — a pre-release qualifier (`-draft`). While a `-draft` tag is present, **any** change may be breaking; the MAJOR/MINOR distinction is advisory until `v1.0`.

**Constitutional-set changes are not routine.** Any change that touches the constitutional set — the hash-pinned enforcement machinery and declared bounds named in the release manifest (which includes the honest-language rule list and the promotion-pipeline definition) — requires **protected review plus a release-manifest hash bump**, recorded with a build-ledger row. Such changes are called out explicitly in the entry below, never folded silently into an unrelated change.

Every entry records: the version, the date, what changed, and — where relevant — the migration note for existing artifacts. Because all artifacts carry `schema_version`, a format change ships with a `schema_version` bump and a stated migration path.

---

## [0.3-draft] — 2026-07-24

Extended run-time control attestations. Adds five optional, namespaced **extended controls** to the GSA bundle and teaches the verifier (§9.11) to **recompute** each from the bundle's own evidence, failing closed on any claimed-but-unsupported control (D5). Backward-compatible with a `0.2-draft` reader: a bundle without `control_attestations_v040` verifies unchanged.

### Added

- **Five extended controls (`control_attestations_v040`).** `capability_conformance` (R1), `effects_reconciled` (R2), `signer_trust` (R3), `trace_redaction` (R4), `build_provenance` (R5). Each is optional and declared-only — a bundle attests only the controls it claims.
- **Namespaced evidence keys.** `capability_grant`, `effects[].receipt`, `signer_registry`, `trace_mode`, and `build_provenance` carry the per-control evidence the verifier recomputes against. Five frozen schemas back them: `capability-grant`, `side-effect-receipt`, `signer-registry`, `attestation-recall`, `redaction-policy` (Contract 14).
- **§9.11 verification step.** After the five original control attestations (§9.9), the verifier recomputes each declared extended control through its check module from the bundle's own §9.3-verified evidence and requires the claim to match. `trace_redaction` recomputes against the execution-trace bytes; a bundle claiming redaction whose trace still carries an unredacted secret or PII fails closed. Malformed or unknown extended-control keys fail closed.
- **`graphsmith verify` bin.** A fail-closed CLI shipped from the `graphsmith-skill` package runs the §9 algorithm (including §9.11) for CI and enterprise verifiers.
- **Conformance vectors.** Four §9.11 vectors added to the conformance kit (a valid extended bundle plus redaction-lie, unknown-control, and malformed-block negatives); 14 vectors total.

### Notes

- Still a `-draft`: wire formats and verification semantics may change incompatibly before `v1.0`.
- **Binding invariants unchanged:** **C1** identity/timestamps are evidence, never decision inputs; **C2** fail-closed; **D1** enforced-only attestation; **D5** recompute, never trust-as-declared. Every extended control was built by one model family and adversarially reviewed by ≥2 non-Anthropic families, with the GSA §9.11 integration itself put through the same council.
- **Constitutional-set flag:** §9.11 is an edit to the hash-pinned `gsa-verify.js` sentinel — landed under **protected review + council (≥2 non-Anthropic families) + a release-manifest hash bump + a build-ledger row**. The integration adds a backward-compatible step; no existing §9 step changed.
- **Migration:** none for existing bundles — a `0.2-draft` bundle without `control_attestations_v040` verifies identically. A producer opts in by adding the key plus evidence and re-signing.

---

## [0.2-draft] — 2026-07-23

Attestation additions. Extends the protocol with the **GraphSmith Attestation (GSA)** companion standard — a portable, signed, replayable, tamper-evident record of one AI-workflow run — and freezes the register interfaces that v0.3.0 builds. Backward-compatible with a `0.1-draft` reader: every addition is optional. This entry records the **frozen Wave-0 contracts**; the implementing edits land in v0.3.0 under the notes below.

### Added

- **Profile A (attested).** The `profiles` set is now **R / E / B / T / G / Q / A / X**. A asserts a complete, hash-valid, signature-valid GSA bundle exists (GSA §9) and is the floor: a bundle failing verification asserts no profiles. Q (assurance-tested) is unchanged and already emitted by v0.2.0.
- **GSA companion spec + bundle schema.** `schemas/attestation-bundle.schema.json` (frozen) and the GSA specification (verification algorithm §9, capability profiles, operating modes standard/deterministic/regulator, five recomputed control attestations). GSA is producer-agnostic and is **evidence, never certification** — a binding non-goal.
- **Register interface freeze (Contract 13).** Five frozen schemas — `approver-attestation`, `obligations`, `retention-entry`, `register-policy`, `release-signature` — plus the namespaced assure packet-extension keys (`packet.approver` / `.obligations_coverage` / `.retention` / `.release_signature`) and the `verify.js` check-registry API. These are the plug-in surface for the v0.3.0 regulated register (approver identity, obligations→controls, retention, air-gapped verification).
- **Signing.** Ed25519 + local keypair is the default signing model (D2), preserving I4 "no call home"; the algo set is `ed25519` (RECOMMENDED) | `ecdsa-p256-sha256` | `rsa-pss-sha256`.

### Notes

- Still a `-draft`: wire formats, the profile set, and gate/verification semantics may change incompatibly before `v1.0`.
- **Decisions frozen (D1–D5):** capabilities attest **enforced-only** (D1); signing local-keypair now, keyless later (D2); adopt `verify.js`'s `{status,evidence,assumptions}`+`failure_domain`+exit `3/1/0` report contract (D3); Q added (D4); `mode` is **recomputed from evidence, never trusted-as-declared** (D5). Full text in Contract 13 and `.plans/v0.3.0/graphsmith-v0.3.0-decisions.md`.
- **Two binding constraints** carry into every register lane: **C1** identity/timestamps are evidence, never decision inputs; **C2** partial/unmapped coverage is `not-covered`, loudly (PB-8 fail-closed).
- **Constitutional-set flag:** wiring the check-registry loader into `verify.js` and adding the register checks are edits to the hash-pinned sentinel — they will land in v0.3.0 under **protected review + a release-manifest hash bump + a build-ledger row**, never folded silently. This Wave-0 entry freezes the *interface* only; no constitutional file is modified yet.

---

## [0.1-draft] — 2026-07-23

Initial public draft of the GraphSmith Protocol. Describes implemented, tested behavior only; claims are written narrower than the implementation.

### Added

- **File-format schemas.** Documented the on-disk artifacts, each carrying a `schema_version` field, with references to the published `schemas/` (tree manifest, ACTIVE pointer, adoption entry, lesson event, promotion journal, state-store records, scenario) and to the manifest and adapter-capability formats in the contracts. Hashing rule fixed as raw-byte SHA-256 with path-only canonicalization and case-fold collision refusal.
- **The five protocol invariants (I1–I5),** each with its honest scope and limits: I1 dual trust domains (release-verified vs self-consistent, reported separately; A6 out of scope); I2 hash-pinned core with a single multi-gated change path and rollback as a pre-authorized inverse; I3 disposable evaluation copy with mocked effects (standard) and container-isolated (container), with the containment-by-scope note that only typed document/knob edits are machine-evaluated; I4 no automatic upstream contribution, scoped to the tested socket-denial and upload-free diagnostics paths; I5 observable, budgeted, killable runs with adapter-capability-specific kill-safety messages.
- **Capability profiles R / E / B / T / G, plus Q / X,** replacing the earlier L1–L5 conformance ladder. Each profile documents the exact check `verify --profiles` runs, the evidence it emits, and its explicit assumptions. Status values are `verified | unavailable | failed | not-applicable`; `unavailable` is never reported as a pass, and independent axes are never collapsed into one score.
- **The four-gate promotion pipeline:** Gate 1 static fence/injection screen; Gate 2 behavioral sign-test statistics (one binary endpoint, α = 0.05 with a three-slot alpha ledger); Gate 3 the human adoption packet with a pre-authorized inverse and an anchored-head adoption log described as rewrite-detecting; Gate 4 the serialized observation-window canary with hard-trigger auto-rollback and soft-trigger flagging.
- **Trust model** with named attacker classes and the explicit A6 out-of-scope statement, plus the verification-command surface and exit-code semantics.
- **Unmissable draft banner** at the top of the protocol document.

### Notes

- This is a `-draft` release: the wire formats, invariants, profile set, and gate semantics may change incompatibly before `v1.0`.
- Continuous-score Gate-2 endpoints, the Loop-W tuner, and runtime effect reconciliation (the live `status_check` state machine behind profile E) are designed seams that are **not** part of this release's tested surface and are not specified here as implemented.

---

## Entry template (for future changes)

```
## [X.Y[-tag]] — YYYY-MM-DD

### Added | Changed | Deprecated | Removed | Fixed
- <what changed>. <migration note if a format/schema_version bump is involved>.
- Constitutional-set change (if any): <what>, protected review + release-manifest hash bump, ledger row <id>.
```
