# Contract 05 — Threat Model
Status: DRAFT. Phase A deliverable (plan §11-A). Assets: the constitutional core (I2), learned state, run evidence, user secrets in env, external-effect safety, the project's money/data touched by workflows.

## Attacker classes (named, per plan §11-A)
| Class | In scope? | What GraphSmith does | What it does NOT claim |
|---|---|---|---|
| A1 — Same-user malicious code (a rogue script/agent running as the user) | YES (detection) | dual-manifest drift detection at every boundary (I1); tamper never silently repaired; failure domains (plan §5) | no resident protection; cannot stop a live same-user process — it detects and refuses to run under compromised enforcement |
| A2 — Compromised dependency | YES | zero-dependency scaffolds [KnoSky: scripts/scaffold.js:2-3]; pinned, content-hash-verified tooling (the KnoSky pattern: pinned version + baked-in hash, refuse on mismatch [KnoSky: SKILL.md:36]); CI action pinned by commit SHA (plan §8.2) | cannot vet the user's own workflow dependencies |
| A3 — Hostile contributor (malicious PR to a repo using the protocol) | YES | deterministic merge boundary: CI verify + gates; evaluator/corpus PRs separated from behavior PRs (plan §3.5); trusted-workflow model | human review remains the last line; GraphSmith is evidence, not judgment |
| A4 — Injection via workflow artifacts (poisoned halt messages, lint output, appendix text, instruction-shaped content in harvested data) | YES — the core case | typed events only (contract 07); delimiters + subordination + marker refusal (B2/B3); injection corpus as regression tests; cross-model adversarial batteries (contract 12 Tier 2) | model-level jailbreak resistance is NOT tested here (§17 honest-scope boundary — dedicated tools via the seam) |
| A5 — Malicious BYO test / external tool (§17 seam) | YES | **container profile REQUIRED for any untrusted executable test/tool (GPT-18): network denied, source read-only, scrubbed env; no container available → the tool integration reports "unavailable"** — the standard profile never runs untrusted executables; report strings are display-only data, never control flow (contract 04 B10) | model-level jailbreak resistance still out of scope (§17 boundary) |
| A6 — Privileged local attacker (root/admin who can rewrite sentinel + both manifests) | **OUT OF SCOPE — stated** (I1) | CI cross-check from the trusted workflow covers shared repos | local self-verification detects drift and agent mistakes, not a root-level adversary |

## Mapping to invariants
A1→I1/I2 (detect, refuse, halt domains) · A2→I1 trust roots + pinning · A3→I2 single gated path + CI · A4→I3 isolation + typed boundaries + I2 unreachable core · A5→I3/I5 containment + honest claims · A6→documented limit, release manifest is the anchor.

## Standing assumptions (published with the property matrix)
1. The release artifact's integrity chain (registry checksum at install) is the T-profile trust root.
2. Node.js runtime is uncompromised (A6 corollary).
3. The human at Gate 3 reads what they approve; GraphSmith's duty is that the packet is plain-English, complete, and honest.
4. Secrets hygiene: GraphSmith never prints secrets into logs/evidence; secret-scrubbed env in evaluation copies (I3); diagnostics export redacts by default (I4).
