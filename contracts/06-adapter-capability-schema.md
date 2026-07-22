# Contract 06 — Adapter Capability Schema (I5 kill-safety, pass-2 fix F1)
Status: DRAFT. Every scaffolded adapter (anything that performs an external effect) declares its capabilities; the manager derives the kill/resume message from the declaration. Undeclared adapters cannot be invoked (fail-closed; graphlint R6 checks presence — contract 11).

## Schema (JSON Schema draft 2020-12; file: `adapters/<name>.capability.json`)
```json
{
  "schema_version": "1.0",
  "adapter_id": "string (^[a-z0-9-]+$)",
  "version": "semver string",
  "effects": [
    {
      "effect_type": "send | charge | post | write-remote | delete-remote | read-only",
      "destinations": ["canonical URL pattern, e.g. https://api.example.com/v1/*"],
      "idempotency": "idempotent-by-key | status-checkable | none",
      "idempotency_key_param": "string | null  (where runId:step goes, if idempotent-by-key)",
      "status_check": { "method": "string", "path": "string" } ,
      "transactional_local": "boolean (effect is local-filesystem transactional)",
      "rate_cap_per_run": "integer ≥ 1"
    }
  ]
}
```
`read-only` effects need no idempotency declaration. `destinations` feed the §7 destination allowlist (canonicalized post-redirect where observable).

## Derived kill-safety class (deterministic function, implemented in the manager)
| Declaration | Kill/resume message class |
|---|---|
| all effects `read-only` OR no adapter invoked yet in flight | **no external effects in flight** |
| every in-flight effect `idempotent-by-key` (key honored) OR `transactional_local` OR `status-checkable` (auto-reconciled by status check on resume) | **safe to resume** |
| any in-flight effect with `idempotency: none` and intent-without-completion | **reconciliation required** → the existing LOUD-HALT path [KnoSky: scripts/scaffold.js:252-259] with the printed check/fix instructions [KnoSky: scripts/scaffold.js:201 (README template)] |

## Honesty rules
- "exactly-once-recorded" language is retired; messages state the class + why (which adapter, which declaration).
- The declaration is DATA from the adapter author: contract tests (Gate 2 for prompt/adapter changes, F23) compare stub behavior against live-shaped request fixtures; a declaration the tests can't support fails lint.
- Idempotency keys: `runId + ":" + step`, as v0.1.1 already constructs [KnoSky: scripts/scaffold.js:263].
