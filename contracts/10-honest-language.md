# Contract 10 — Honest-Language Rules + Banned-Strings Lint (lint-checkable)
Status: DRAFT. Two lists, one lint (runs in the CI docs job, plan Phase F). Applies to every repo-bound artifact: README, SKILL.md, PROTOCOL.md, references/, docs/, release notes, code comments, commit messages.

## List A — Honest-language phrase rules (public copy)
| Banned (unqualified) | Required form |
|---|---|
| proven | "tested: <what the test shows>" — never beyond test evidence (PA-1 lesson) |
| immutable | "rewrite-detecting vs an anchored head" |
| certified / certification | "adversarial review" / "attestation of tested behavior" |
| sandboxed / sandbox | "disposable evaluation copy with mocked effects" (standard) or "container-isolated" (container profile, named) |
| exactly-once | "exactly-once *recorded*; external exactly-once requires an idempotency key the system honors" |
| constant monitoring / always-on | "continuous-at-every-boundary" |
| tamper-proof | "tamper-evident vs anchored head" |
| pen-test / penetration test (about GraphSmith's own capability) | "architecture-level adversarial battery" (§17 boundary) |
| certified secure / security guaranteed / guaranteed | (no permitted form — remove the claim) |
| cannot reach the network (standard profile) | (container profile only, with the socket-denial test cited) |
Lint mechanics: case-insensitive phrase match on rendered text; per-line allowlist marker `<!-- lint-allow: honest-language (reason) -->` for quoting-the-ban contexts like this file; CI fails on any unallowed hit.

## List B — Publication hygiene (maintainer directive, plan Phase F)
No references to external research projects, their orgs, repos, or paper identifiers in ANY repo-bound artifact. Mechanism (keeps the identifiers themselves out of the repo):
1. The raw identifier list lives ONLY in the maintainer's private workspace (`.plans/hygiene/banned-identifiers.txt` — git-ignored; Paul supplies/extends it).
2. The repo ships `ci/banned-hashes.json`: `{ "algo": "sha256", "normalize": "lowercase, strip non-alphanumerics", "hashes": ["…"] }`.
3. The docs-job lint normalizes every token n-gram (n = 1..4) of each shipped text file the same way and fails on any hash match. Hashes reveal nothing; the list is maintainable privately.
4. Failure message says "publication-hygiene violation in <file>:<line>" WITHOUT echoing the matched term into public CI logs.

## Scope notes
- Council-review docs for `docs/reviews/` are scrubbed to List B before commit; raw pass-1/pass-2 responses stay internal (plan Phase F).
- The lint tool itself is constitutional-set adjacent (CI entry), Phase A CI deliverable; List A/B content updates are routine-tier.
