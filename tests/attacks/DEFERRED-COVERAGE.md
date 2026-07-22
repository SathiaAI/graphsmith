# Deferred coverage gaps (attack corpus)

Honest map of attacker-class surfaces this corpus does **not** yet exercise.
Target components land in later phases — do not treat absence as a silent pass.

| Gap | Contract / surface | Owning phase | Notes |
|---|---|---|---|
| **A5 malicious BYO-tool** | Container-required refusal / network denial / read-only source / env scrub; report strings display-only, never control flow (contract 04-B10) | **Phase C** (evalenv + redteam) | No attack cell yet. |
| **A4 typed-event source authentication + safety-gap invalidation** | Source auth on typed events; invalidation when safety-relevant evidence is missing | **Phase C** (event-compiler) | Marker-string coverage exists elsewhere; source-auth / gap-invalidation do not. |
| **A2 compromised-dependency** | Content-hash / SHA-pin refusal for pinned tooling | **Phase A CI** (`scripts/ci-check-pr-separation.js`, SHA-pinned actions — landing now) + **Phase E** action/badge | Once CI lands: SHA-pinned actions + content-hash checks are CI-covered; corpus still owes a dedicated refusal attack when tooling surface is callable in-harness. |
| **A3 hostile-contributor** | Trusted-workflow secret isolation; PR separation (evaluator vs corpus) | **Phase A CI** (`scripts/ci-check-pr-separation.js`) + **Phase E** action/badge | PR-separation is CI-covered once that script is enforced on PRs; secret-isolation / trusted-context still Phase E corpus territory. |

## Explicitly out of scope (not deferred)

- **A6 privileged host rewriter** mid-flight (lock + journal + both manifests): contract 05 out of scope for local zero-dep scripts.
- **Cross-host NFS cache races**: out of scope.

## Related in-corpus UNAVAILABLE (not a gap — harness limit)

- `toctou/true-parallel-rename-race`: not proven in the single-process harness; deferred to multi-process `verify --platform-probe` (per-platform results).
