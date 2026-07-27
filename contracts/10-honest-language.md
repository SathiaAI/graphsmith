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

## List C — Honest verdict vocabulary (machine output, not public copy)

Lists A and B govern prose a reader sees. List C governs the words a HARNESS is allowed to
print about itself. Same principle, different audience: a verdict word must not claim more
than the run established. The repo already applies this at cycle level — contract 03
declares an underpowered cycle `INCONCLUSIVE_UNDERPOWERED` rather than a rejection
("Underpowered ≠ defective"), and contract 12 reports an unestablishable property
"unavailable — never green". List C states the same rule for test harnesses, which had no
governed vocabulary and drifted as a result.

Admissible verdicts, and what each one asserts:

| Verdict | Asserts | Counts as |
|---|---|---|
| `PASS` | the case ran and the property held | pass |
| `FAIL` | the case ran and the property did not hold | failure, gates |
| `SKIPPED` | the case did NOT run; states why. Never a pass | neither |
| `INCONCLUSIVE (harness)` | the case could not establish its preconditions, so it observed nothing about the product. Reported on a FAIL line so it is fail-closed, and tagged so no reader or summary counts it as a product finding | failure, gates |
| `ADJUDICATED` | the case ran; a reviewer's expectation was formally overruled in the lane's `ADJUDICATION.md`; the harness asserts the ruled-correct behaviour instead | neither |

Rules:

1. **A verdict may not be reached from an unobserved result.** A wait that expired, a child
   killed by the harness's own timeout, a collection that was never populated, and a
   dependency that failed to load are all absences of observation. Each is
   `INCONCLUSIVE (harness)`, never a PASS and never a product FAIL. Discriminate on the
   specific signal (for spawns: `error.code === "ETIMEDOUT"`); a bare `status === null` also
   means "killed by a signal" and must not be read as a timeout.
2. **No verdict path may be unfalsifiable.** Two branches of one condition must not both
   report success, and an assertion must not accept more than one outcome. A case that
   cannot fail carries no coverage while reading green.
3. **`ADJUDICATED` requires a citation** to the `ADJUDICATION.md` ruling that settled it,
   enforced in the helper: a missing or empty citation is a FAIL, not an ADJUDICATED. It
   still asserts the ruled-correct behaviour, so a regression away from that behaviour
   fails loudly. Neither flipping an overruled expectation silently (which erases the
   record that two reviewer families disagreed) nor leaving it permanently red (which
   trains readers to ignore red) is admissible.
4. **A skip states its scope.** A leg where a platform-dependent control did not run must
   not read the same as a leg where it ran and refused; the count of unexercised controls is
   printed.
5. **Detection, not inspection.** `tests/harness-honesty/starvation/` enforces rule 1
   mechanically by scaling every harness deadline toward zero and requiring that each
   resulting failure be tagged — arithmetic rather than review. A suite listed there that
   does not route its deadlines through `tests/_harness/deadline.js` fails as a wiring gap
   rather than passing vacuously.

## Governance
All three lists versioned; every change = a ledger row + manifest bump. The lint tool lane:
contract 11 (docs-lint); List C rule 3 is enforced in each harness helper and rule 1 in
`tests/harness-honesty/starvation/`. Failure messages never quote the banned term.
