# GraphSmith Release Process

This document describes the release process for GraphSmith. All releases are reviewed, not certified. The process emphasizes adversarial review, evidence-carrying attestations, and honest reporting of tested behavior.

## Pre-release review checklist

Every GraphSmith release passes through the following review steps. The review is performed by a named human release owner and includes adversarial testing by multiple model families.

### 1. Named human release owner

- [ ] A named human release owner is designated for this release
- [ ] The release owner's name is recorded in the release notes
- [ ] The release owner attests to the tested behavior documented in this release

### 2. Full verify/selftest/attack battery on 3-OS CI

Before any release, the full verification suite must pass on all supported operating systems:

- [ ] CI verify job passes on ubuntu-latest (Node 18 and 22)
- [ ] CI verify job passes on windows-latest (Node 18 and 22)
- [ ] CI verify job passes on macos-latest (Node 18 and 22)
- [ ] Linter self-test (line-pinned regression corpus) passes
- [ ] Dogfood lint of the skill's own scripts passes
- [ ] Scaffold and chaos tests pass
- [ ] Phase A selftests pass on all three OSes (manifest.js, state-store.js, loaders.js, scenario.js, promote.js, gate.js, verify.js, ci-check-pr-separation.js)
- [ ] All committed test suites under tests/<component>/<family>/run-tests.js pass
- [ ] PR separation guard validates that no evaluator/corpus changes are mixed with behavior changes

### 3. Adversarial review of the release candidate

The release candidate is reviewed by at least two non-Anthropic model families. Dissenting opinions are preserved in the release notes.

- [ ] Adversarial review completed by ≥2 non-Anthropic model families
- [ ] All review findings are documented in the release notes
- [ ] Dissenting opinions are preserved verbatim in the release notes
- [ ] Review findings are addressed or explicitly deferred with rationale

### 4. Evaluator freeze at release candidate

The Gate-2 evaluator and corpus are frozen at the release candidate. No evaluator or corpus changes may occur within a release.

- [ ] Evaluator and corpus are frozen at the release candidate
- [ ] Any post-RC evaluator or corpus changes will ride in separate PRs
- [ ] PR separation guard has validated the separation of evaluator/corpus from behavior changes
- [ ] Evaluator fingerprint is recorded in the release notes

### 5. Honest-language audit

All public-facing documentation must pass honest-language lint and publication hygiene scan before release.

- [ ] docs-lint (List A) passes with zero violations attributable to RELEASING.md
- [ ] hygiene-scan (List B) passes with zero violations attributable to RELEASING.md
- [ ] All release notes have been audited for banned phrases (proven, immutable, certified, sandboxed, exactly-once, constant monitoring, tamper-proof, pen-test, certified secure, security guaranteed, guaranteed, cannot fail, atomic, cannot reach the network) <!-- lint-allow: honest-language (documenting banned phrase list) -->
- [ ] Where banned phrases appear, they are replaced with required forms (tested:, rewrite-detecting, adversarial review, disposable evaluation copy with mocked effects, container-isolated, capability class, continuous-at-every-boundary, tamper-evident, architecture-level adversarial battery)
- [ ] lint-allow comments are used only where genuinely definitional, with reasons stated

## Release mechanics

This section references the actual CI/CD pipeline that implements the release process.

### CI pipeline (`.github/workflows/ci.yml`)

The CI workflow enforces the following gates:

- **3-OS verify matrix:** ubuntu-latest, windows-latest, macos-latest × Node 18, 22
- **Phase A selftests:** Component selftests and committed test suites on all three OSes
- **PR separation guard:** Prevents mixing evaluator/corpus changes with behavior changes in the same PR
- **Docs hygiene:** Runs honest-language lint and publication hygiene scan on all public copy
- **Dogfood:** Runs GraphSmith's own verify action against itself

### Publish pipeline (`.github/workflows/publish.yml`)

The publish workflow enforces:

- **SHA-pinned actions:** All third-party GitHub Actions are pinned by full commit SHA
- **Verify before publish:** The full CI verify job must pass before anything is published
- **Secrets safety:** NPM_TOKEN is only available on release/workflow_dispatch triggers, never on pull_request triggers

### Supply chain trust model

The supply chain model is documented in `docs/SUPPLY-CHAIN.md`. Key points:

- SHA pinning only for all third-party actions
- No secret exposure on PR triggers
- Consumer SHA pinning requirements for downstream repos
- Read-only permissions model
- No `pull_request_target` usage

### Dogfooding

GraphSmith runs its own verify action and wears its own badge:

- The `dogfood-graphsmith-action` job in CI runs the GraphSmith verify action against the repo itself
- The release notes include GraphSmith's own capability profile badge
- Unavailable profiles on any platform render as unavailable, never green

## Credibility requirements checklist

Every release must satisfy the credibility requirements from §8 of the build plan.

### 8.1 Claims narrower than implementation

- [ ] All claims in release notes are narrower than the implementation
- [ ] No claim is made that the implementation does not support
- [ ] Limitations and assumptions are explicitly stated

### 8.2 Adversarial suites public and reproducible

All adversarial test suites are public and reproducible:

- [ ] Constitutional attack suite is public under tests/attacks/constitutional/
- [ ] TOCTOU race harness is public under tests/attacks/toctou/
- [ ] Module-escape suite is public under tests/attacks/module-escape/
- [ ] Each suite includes a README with setup and reproduction instructions
- [ ] Release notes cite the specific test suites used for adversarial review

### 8.3 Per-platform property matrix published

- [ ] Platform property matrix is published in docs/PROPERTY-MATRIX.md
- [ ] Matrix covers all supported platforms (Linux, Windows, macOS)
- [ ] Each property reports verified/unavailable/failed with evidence
- [ ] Unavailable properties are never reported as verified

### 8.4 Negative results reproducible

- [ ] All negative results are documented with reproduction steps
- [ ] "Flat is flat" — null results are reported as null, never spun
- [ ] Held-out table and noise floor are included in release notes (see Noise-floor reporting below)

### 8.5 Explicit assumptions on every semantic claim

Every semantic claim states its assumptions:

- [ ] E-profile claim states dependency on adapter capability declarations (contract 06)
- [ ] T-profile claim states dependency on the release trust root
- [ ] R-profile claim states it tests installation machinery against an ephemeral fixture
- [ ] B-profile claim states it tests supervisor budget enforcement on an ephemeral fixture
- [ ] G-profile claim states it tests gate.js against an ephemeral evolvable fixture
- [ ] Q-profile claim states it tests the target workflow's test battery and lint
- [ ] X-profile claim states it tests the target workflow against an architecture-level adversarial battery

### 8.6 Badge is evidence-carrying

The capability badge is evidence-carrying:

- [ ] Badge renders the profile string (R:status E:status B:status T:status G:status Q:status X:status)
- [ ] Badge includes the verifier version
- [ ] Badge includes the platform set
- [ ] Badge includes the evaluation date
- [ ] Badge links to the CI run that produced it
- [ ] Unavailable profiles render as unavailable, never green
- [ ] Stale evidence downgrades the badge
- [ ] Badge semantics include evidence freshness

### 8.7 Draft-protocol banner present

- [ ] GRAPHSMITH-PROTOCOL.md includes the draft banner: "DRAFT — breaking changes possible until v1.0; describes implemented, tested behavior only; seeking independent implementations"
- [ ] SPEC-CHANGES.md tracks breaking changes
- [ ] No v1.0 stability claim is made in this release

## Noise-floor reporting

Release notes must include the held-out table, noise floor, and flat-is-flat reporting from the evaluator-stability memo.

- [ ] Held-out evaluation table is included in release notes
- [ ] Noise floor metrics are reported with confidence intervals
- [ ] "Flat is flat" — null results are reported as null, never spun as positive
- [ ] Evaluator stability memo is produced and preserved for this release
- [ ] Any evaluator drift is explicitly called out

### Flat-is-flat discipline

When evaluation results show no meaningful difference:

- [ ] Results are reported as "no significant difference detected"
- [ ] No attempt is made to spin a null result as positive
- [ ] Confidence intervals are provided to show the precision of the null result
- [ ] The evaluation budget and statistical power are disclosed

## Post-release verification

After publication, the following verification steps are performed:

- [ ] Published package passes `graphsmith verify --integrity`
- [ ] Published package passes `graphsmith verify --selftest`
- [ ] Capability profile badge is generated and published
- [ ] Release notes are published to the repository
- [ ] Evaluator stability memo is archived

## Release owner attestation

By signing off on this checklist, the release owner attests that:

1. All items in this checklist have been completed or explicitly deferred with rationale
2. The release notes accurately reflect tested behavior, not hypothetical claims
3. All adversarial review findings have been preserved, including dissent
4. The honest-language and publication hygiene gates have passed
5. The capability badge accurately reflects the platform's verified capabilities
6. The release follows the supply chain model documented in SUPPLY-CHAIN.md

---

**Review, not certification:** This process is a review and attestation of tested behavior. It is not a certification of security, correctness, or fitness for any particular purpose. Users must evaluate GraphSmith against their own requirements and threat models.