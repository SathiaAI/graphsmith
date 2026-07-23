# Contract 10 — Honest-Language Rules + Banned-Strings Lint (v2)
Status: DRAFT v2 (post-panel-pass-1: Gemini-1, GPT-21/22, DeepSeek-5). Applies to every repo-bound artifact.

## List A — Honest-language phrase rules (public copy)
Banned unqualified → required form: **proven** → "tested: <what the test shows>" · **immutable** → "rewrite-detecting vs an anchored head" · **certified** → "adversarial review"/"attestation of tested behavior" · **sandboxed** → "disposable evaluation copy with mocked effects" (standard) / "container-isolated" (container) · **exactly-once** → state the capability class + assumption per contract 06 (no fixed replacement phrase — GPT-22) · **constant monitoring** → "continuous-at-every-boundary" · **tamper-proof** → "tamper-evident vs anchored head" · **pen-test** (about GraphSmith itself) → "architecture-level adversarial battery" · **certified secure / security guaranteed / guaranteed / cannot fail** → remove the claim · **atomic** (about Windows behavior) → probe-verified wording only (contract 01) · **cannot reach the network** → container profile only, socket-denial test cited.

Lint mechanics (GPT-22): context-aware — scans rendered prose and comments, skips code identifiers and quoted-ban contexts carrying `<!-- lint-allow: honest-language (reason) -->` (this file and the rules fixtures use it); ships with a tested fixture corpus (true-positive + false-positive cases) like the lint-corpus pattern [KnoSky: tests/lint-corpus/expected.json]; rule-list changes are **constitutional-set changes** (protected review + manifest hash bump), never routine.

## List B — Publication hygiene (v2 mechanism — Gemini-1/GPT-21: unsalted hashes are dictionary-attackable)
1. **Prevention (primary): local pre-commit/pre-release scanner** on the maintainer's machine — reads the RAW private list (`.plans/hygiene/banned-identifiers.txt`, git-ignored, maintainer-supplied) and blocks the commit/release. The raw list never leaves the private workspace.
2. **Detection (secondary): trusted-CI scan with a keyed digest.** The repo ships NO digests. The CI docs job (trusted context only — push to main / release; never fork-PR contexts) receives `HYGIENE_HMAC_KEY` and `HYGIENE_DIGESTS` as CI secrets and scans HMAC-SHA256(key, normalized n-gram) per token n-gram, n = 1..len(longest identifier) derived per-identifier (DeepSeek-5 — no fixed n=4 cap). Nothing in the repo is dictionary-attackable; public CI logs never echo matches (file:line only).
3. Normalization: Unicode NFKC + confusable folding, lowercase, strip non-alphanumerics, decode %-encodings and URLs; applied to file contents AND filenames. History note (GPT-21): CI detects post-push; prevention is step 1 — this split is stated, not hidden.
4. Scope: docs/reviews/ publications scrubbed pre-commit; raw pass-1/pass-2 council responses remain internal-only.

## Governance
Both lists versioned; every change = a ledger row + manifest bump. The lint tool lane: contract 11 (docs-lint). Failure messages never quote the banned term.
