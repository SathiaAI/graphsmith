# Contract 06 — Adapter Capability Schema (v2 — declarations are assumptions, not truth)
Status: DRAFT v2 (post-panel-pass-1: GPT-19/20, Gemini-5). Every adapter declares capabilities; the manager derives kill/resume behavior. Undeclared adapters cannot be invoked (fail-closed; graphlint R6).

## Schema (JSON Schema 2020-12, `additionalProperties: false` throughout; file `adapters/<name>.capability.json`)
```json
{
  "schema_version": "1.0",
  "adapter_id": "^[a-z0-9-]+$",
  "version": "semver",
  "effects": [ { "effect_id": "^[a-z0-9-]+$", "effect_type": "...", "capability": { "oneOf": "see variants" },
                 "destinations": ["see constraints"], "rate_cap_per_run": "int ≥ 1" } ]
}
```
**Capability variants (mutually exclusive `oneOf` — GPT-20; JSON-Schema conditionals enforce the pairings):**
| Variant | Required fields | Valid for |
|---|---|---|
| `local-transactional` | `inspection: {marker_path_pattern | journal_convention}` — the deterministic on-disk convention the manager checks to decide landed/not-landed (P2-GPT-10; a bare label is schema-rejected) | `effect_type: "local"` ONLY. External effect_types CANNOT declare it — schema-rejected |
| `idempotent-by-key` | `idempotency_key_param` (where `runId:step` goes [KnoSky: scripts/scaffold.js:263]) | external effects |
| `status-checkable` | `status_check: {method, path, op_identity_param, authoritative: bool, outcomes: {completed[], definitively_not_executed[], unknown[]}, retry_after_absence: "requires-idempotency-key" \| "declared-final" , inherit_auth: bool \| headers[] (P2-Gemini-4)}` | external effects |
| `none` | — | external effects (the honest default) |
| `read-only` | — | `effect_type: "read"` |
**Destinations:** absolute scheme+host+path patterns; scheme ∈ {https}; no bare `*` host; wildcards only in the path tail; matched post-canonicalization (lowercase host, resolved dots, observed post-redirect destination must ALSO match). DNS re-resolution is not claimed (documented limit).

## Runtime binding (GPT-20)
Every write-ahead intent record (the v0.1.1 guard [KnoSky: scripts/scaffold.js:260-267]) is extended to carry `{effect_id, capability_file_sha256}` — a kill/resume decision is made against the DECLARATION IN FORCE AT INTENT TIME, never a later edit. Capability files are hashed in workflow.manifest.json (contract 09); editing one is a gated change (F23: full Gate 2 with live-shaped fixtures).

## Kill/resume derivation (GPT-19 — reconciliation is a runtime state machine, not a label)
On kill/resume, for each intent-without-completion, in order:
1. `read-only` / no intents in flight → **"no external effects in flight."**
2. `local-transactional` → local state inspected (transaction either landed or didn't) → **"safe to resume (local effect, inspected)."**
3. `status-checkable` → resume runs the **reconciliation state machine FIRST** (P2-GPT-10 semantics): call `status_check` with the recorded `op_identity_param` (and forwarded auth per `inherit_auth`). ONLY two outcomes resolve the intent: `completed` (journaled as done) or `definitively_not_executed` from an `authoritative: true` check — and a retry after confirmed absence is permitted ONLY under the declared `retry_after_absence` guarantee (idempotency key or remote finality); a `definitively_not_executed` that cannot exclude a delayed original effect must be declared `authoritative: false` by the adapter author. `unknown`, unavailable, non-authoritative, or auth-failed → **falls through to 5**.
4. `idempotent-by-key` → **"resume will retry with the recorded idempotency key — safe ASSUMING the remote honors the declared key (declaration by the adapter author, not verified by GraphSmith)"** (Gemini-5 wording requirement — the assumption is IN the message).
5. `none`, or any unresolved case → **"reconciliation required"** → the LOUD-HALT path with printed check/fix instructions [KnoSky: scripts/scaffold.js:252-259].
Default posture: **every unresolved intent is "reconciliation required" until a rule above affirmatively upgrades it** (GPT-19).

## Honesty rules
- "exactly-once-recorded" language retired; messages state class + which adapter + which declaration + what is assumed vs verified.
- Contract tests (Gate 2, F23) verify the adapter SENDS what it declares (key present, destinations match, status path called) against live-shaped fixtures — they establish adapter-side conformance ONLY; remote-side honoring is always labeled an assumption.
- A declaration the contract tests cannot support fails lint (R6).
