# Contract 14 — v0.4.0 Interfaces (FROZEN Wave 0)

**Status:** FROZEN 2026-07-24 for parallel Wave-1 build. The plug-in surface the v0.4.0 lanes (R1–R4, E) build against. **No Wave-1 lane edits a shared file** — each ships its own module + `checks/v040-<lane>.js` that plugs into the frozen registry. Changing anything here after freeze re-opens Wave 0 (a council-adopted-fix relaxation → HALT for Paul).

## 1. Frozen schemas (under `schemas/`, draft 2020-12, `schema_version` const `"1.0"`, `graphsmith.dev` `$id`)
| Schema | Req | Binds |
|---|---|---|
| `capability-grant.schema.json` | R1 | per-skill fs/model/subprocess/network grants + the **`enforced`** list (only enforced classes may be attested) |
| `side-effect-receipt.schema.json` | R2 | adapter-namespaced receipt `{action, external_id?, idempotency_key?, status, ts=evidence}` |
| `signer-registry.schema.json` | R3 | approved signers + lifecycle (active/rotated/revoked) + rotation chain |
| `attestation-recall.schema.json` | R3 | recall/revoke a published bundle; recalled → fail-closed on re-verify |
| `redaction-policy.schema.json` | R4 | `trace_mode` (full/redacted/metadata-only) + redaction rules (secret/pii/credential) |

**Revocation design (decision, flag at gate):** signer/key revocation is carried by `signer-registry.status = revoked` + `attestation-recall` — **not** a separate `revocation-list.schema.json`. One registry is the trust source; recall handles already-published bundles. Consolidate rather than duplicate (mirrors the v0.3.0 single-source discipline).

## 2. GSA bundle extension (namespaced, one writer per key)
The `attestation-bundle.schema.json` core is **not edited** by any lane. Four namespaced additions, each written by one lane:
| Key | Lane | Schema |
|---|---|---|
| `capabilities.grants` (per-resource `requested ⊆ granted` result, per class) | R1 | capability-grant |
| `effects[].receipt` | R2 | side-effect-receipt |
| `signer_registry` (the registry a bundle was verified against, + recall pointer) | R3 | signer-registry / attestation-recall |
| `trace_mode` | R4 | redaction-policy |
All four are OPTIONAL additions — a v0.3.0 bundle stays valid; their absence is the honest "not-declared" state.

## 3. `verify.js` / `gsa-verify` check-registry (frozen)
Each lane ships `checks/v040-<lane>.js` exporting the frozen contract:
```
module.exports = { id: "v040-caps"|"v040-receipts"|"v040-signer"|"v040-trace",
  run(ctx) -> { status: "verified"|"unavailable"|"failed"|"not-applicable", evidence[], assumptions[], failure_domain? } };
```
Pure (no clock/random/network in the decision path). The verifier **recomputes** every new control from evidence (D5 — never trust-as-declared); `unavailable` is never rendered green; exit mapping stays `3/1/0`.

## 4. Binding rules (gating tests on every lane)
- **D1 — enforced-only capability attestation (R1, the credibility line).** A resource class appears in `capabilities.grants` result as satisfied ONLY if it is in the grant's `enforced` list AND the engine truly enforced it. A bundle that attests "requested ≤ granted: satisfied" over an engine that fails open is the single most credibility-ending failure — never attest a boundary not enforced. Fail-open mutation test per class is gating.
- **C1 — identity/timestamps are evidence, never decision inputs.** `ts` / `added_at` / `recalled_at` are recorded and verified, never routed on. Mutation test per lane.
- **C2 — fail-closed.** Revoked signer / recalled attestation / `UNKNOWN_EFFECT` / unmet redaction / unenforced-but-requested class → refuse, loudly. Never coerce or default.
- **Honest language (R2).** External single-delivery is **run-once, replay-verified** of recorded effects — **never "exactly-once"**. The word must not appear in code or copy.

## 5. Constitutional-set flag
Wiring the `v040-*` check-registry into `gsa-verify` / `verify.js` and adding the new recomputed controls are edits to the hash-pinned verifier — they land under **protected review + a release-manifest hash bump + a build-ledger row**, never folded silently. This Wave-0 entry freezes the *interface* only; no constitutional file is modified yet.

## 6. SPEC bump
The GSA spec takes a **draft-minor** bump for these additive (but breaking, pre-1.0) fields, recorded in SPEC-CHANGES with per-change conformance impact. Profiles unchanged; the new controls extend `control_attestations` recomputation.
