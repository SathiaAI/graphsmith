# GraphSmith Protocol v0.1-draft Review Findings

**Reviewer:** GLM-4.7 (z-ai/glm-4.7, non-Anthropic — independent of the Claude/Sonnet protocol author; the "Claude Sonnet" self-label the model emitted here was corrected by the orchestrator to reflect the actual reviewing model and preserve cross-family independence)  
**Date:** 2026-07-23  
**Scope:** GRAPHSMITH-PROTOCOL.md + SPEC-CHANGES.md vs actual implementation  
**Review Type:** Public-facing spec accuracy verification

---

## Executive Summary

This review conducted a comprehensive cross-check of the GraphSmith Protocol v0.1-draft documentation against the actual implementation. The verification examined substantive claims across four domains:

1. **Accuracy/Claims-narrower-than-code** - No claims found wider than implementation
2. **Honest-language** - Zero violations attributable to the protocol documents
3. **Publication hygiene** - No external research project/org/repo/paper identifiers
4. **Completeness** - All required protocol components present and correct

**Overall Assessment:** ZERO CRITICAL or HIGH findings. The protocol documentation accurately reflects the implemented behavior, with claims written narrower than the implementation as intended.

---

## Detailed Findings

### 1. Accuracy / Claims-Narrower-Than-Code

#### Profile Implementations vs Documentation

**R Profile (Resumable local state)** - VERIFIED ✓
- **Documentation:** "Two ephemeral state-store fixtures under the OS temp directory. (1) A committed state survives a restart with a byte-identical slot projection (recovery is a no-op on clean state). (2) A mutation torn by a simulated mid-write crash (the state-store's own test-mode crash hook) is rolled forward by the real journal recovery run in the store constructor."
- **Implementation:** `scripts/verify.js:1206-1274` - `profileResumableState()` function
- **Assumptions match:** Verbatim match between documented assumptions and code comments (lines 1208-1211)
- **Status:** Documentation accurately reflects implementation

**E Profile (Effect-reconciled external calls)** - VERIFIED ✓
- **Documentation:** "Presence and shape of adapters/<name>.capability.json (each needs schema_version 1.0, an adapter_id matching ^[a-z0-9-]+$, a version string, and an effects array), then a static mapping of each declared effect's capability variant to its kill/resume reconciliation class"
- **Implementation:** `scripts/verify.js:1283-1336` - `profileEffectReconciliation()` function
- **Assumptions match:** Verbatim match (lines 1284-1287)
- **Static mapping implementation:** `reconciliationClassForEffect()` function (lines 1024-1042) with RECONCILIATION_BY_VARIANT table (lines 1016-1022)
- **Status:** Documentation accurately reflects implementation

**B Profile (Budget-enforced)** - VERIFIED ✓
- **Documentation:** "Scaffold an ephemeral supervised project under the OS temp directory, load its generated supervisor (scaffold.js's supervisor.js), and drive a step budget breach. The supervisor must trip a HALT whose recorded evidence is a budget-kind halt with a rule string and an evidence object."
- **Implementation:** `scripts/verify.js:1344-1393` - `profileBudgetEnforced()` function
- **Assumptions match:** Verbatim match (lines 1346-1349)
- **Status:** Documentation accurately reflects implementation

**T Profile (Trust-root verified)** - VERIFIED ✓
- **Documentation:** "Derived from the integrity run: verified when release-verified: yes and self-consistent: yes; unavailable when release-verified: unavailable (no release manifest to anchor to); otherwise failed."
- **Implementation:** `scripts/verify.js:1561-1584` - T profile construction in `runProfiles()` function
- **Assumptions match:** Verbatim match (lines 1577-1580)
- **Status:** Documentation accurately reflects implementation

**G Profile (Gated learning enabled)** - VERIFIED ✓
- **Documentation:** "Build an ephemeral ACTIVE-pointer fixture and hash it. Run gate1Static and gate3Prepare on a document candidate, stage the resulting propose-only record into the pending queue, confirm listPending shows it, then call adopt without confirmation. The adopt must refuse, and the ACTIVE pointer must be byte-identical before and after."
- **Implementation:** `scripts/verify.js:1401-1462` - `profileGatedLearning()` function
- **Assumptions match:** Verbatim match (lines 1404-1407)
- **Status:** Documentation accurately reflects implementation

**Q Profile (Assurance-tested)** - VERIFIED ✓
- **Documentation:** "Only for a workflow project (manager.js + pipeline.json at the root). Runs the test battery (unit + scenario-regression + smoke) and an architectural lint. verified only when both the battery passes and the lint is clean; if the lint is unavailable, Q is unavailable, not green."
- **Implementation:** `scripts/verify.js:1470-1511` - `profileAssuranceTested()` function
- **Assumptions match:** Verbatim match (lines 1471-1475)
- **Status:** Documentation accurately reflects implementation

**X Profile (Adversarially-tested)** - VERIFIED ✓
- **Documentation:** "Only for a workflow project. Runs GraphSmith's discipline/injection architecture battery in the evaluation-isolation environment. An arch.sandbox-open evidence entry must be present and not unavailable before any pass/fail ruling stands (isolation must be confirmed); otherwise unavailable."
- **Implementation:** `scripts/verify.js:1518-1552` - `profileAdversariallyTested()` function
- **Assumptions match:** Verbatim match (lines 1519-1524)
- **Status:** Documentation accurately reflects implementation

#### Four-Gate Pipeline Description

**Gate 1 (Static)** - VERIFIED ✓
- **Documentation:** "gate1Static(candidate, ctx). Checks: fence write-set (a candidate may only touch the evolvable surface), typed-schema validation of each edit, a contradiction screen (advisory-strength), an injection screen on human-promoted prose, appendix caps, fingerprint dedup against the rejected buffer, and a sentinel pass."
- **Implementation:** `scripts/gate.js:124-276` - `gate1Static()` function
- **Checks implemented:** All documented checks present (lines 145-273)
- **Status:** Documentation accurately reflects implementation

**Gate 2 (Behavioral)** - VERIFIED ✓
- **Documentation:** "Primary endpoint: a one-sided exact sign test on discordant pairs at α = 0.05 (Bonferroni-split into three preallocated confirmation slots at α = 0.05/3 per corpus state, family-wise error ≤ 0.05)."
- **Implementation:** `scripts/gate.js:371-565` - `decideGate2()` function
- **Statistical parameters:** BONFERRONI_ALPHA = 0.05 / 3 (line 23), MAX_ALPHA_SLOTS = 3 (line 26)
- **Status:** Documentation accurately reflects implementation

**Gate 3 (Provisional human adoption)** - VERIFIED ✓
- **Documentation:** "gate3Prepare(...) is a pure function producing the adoption packet: the staged diff, a plain-English explanation, the evidence reference, the pre-authorized inverse transaction, and reversible/autoRollbackEligible flags"
- **Implementation:** `scripts/gate.js:584-632` - `gate3Prepare()` function
- **Status:** Documentation accurately reflects implementation

**Gate 4 (Observation window)** - VERIFIED ✓
- **Documentation:** "An operational canary, not a statistical gate. It is serialized: at most one active window per project, and no new adoptions while a window is open."
- **Implementation:** `scripts/gate.js:637-664` - Gate 4 delegation functions; `scripts/adopt.js:247-287` - `close()` function with GATE4_OUTCOMES validation
- **Status:** Documentation accurately reflects implementation

#### Promote.js Transaction Semantics

**I2 Commit Semantics** - VERIFIED ✓
- **Documentation:** "All evolvable-surface change flows through the four-gate promotion pipeline (§5); the pipeline definition is itself constitutional. Rollback is not a second path — it executes an inverse transaction that the human pre-authorized at Gate 3."
- **Implementation:** `scripts/promote.js:520-615` - `promote()` function; `scripts/promote.js:776-808` - `rollback()` function
- **Transaction structure:** Matches documented phases (LEASED→STAGED→VALIDATED→LOGGED→SWAPPED→MANIFEST→TX_DONE)
- **Status:** Documentation accurately reflects implementation

---

### 2. Honest-Language (Contract 10)

**Lint Results:** 
- Command: `node scripts/docs-lint.js` (scans shippable docs fileset)
- Status: **52 violations found in 8 other files**
- GRAPHSMITH-PROTOCOL.md: **0 violations**
- SPEC-CHANGES.md: **0 violations**

**Manual Scan Results:**
No banned unqualified terms found in protocol documents:
- "proven" - Not present
- "immutable" - Not present (uses "rewrite-detecting")
- "certified" - Not present (uses "attestation")
- "constant monitoring" - Not present (uses "continuous-at-every-boundary")
- "atomic" - Not present (uses "probe-verified")
- "exactly-once" - Not present (uses "capability class")
- "tamper-proof" - Not present (uses "tamper-evident")
- "guaranteed" - Not present (uses "best-effort")

**Assessment:** Both protocol documents pass honest-language checks with zero violations.

---

### 3. Publication Hygiene (Plan §145)

**Scan Results:**
- No external research project identifiers
- No external organization names
- No external repository references
- No external paper citations
- No vendor/product/org tokens

**Assessment:** No publication hygiene issues detected. The documentation contains only GraphSmith-specific terminology and internal references.

---

### 4. Completeness

**Required Components - All Present:**

| Component | Location | Status |
|-----------|----------|--------|
| I1 - Verified integrity at every boundary | GRAPHSMITH-PROTOCOL.md:61-73 | ✓ Present |
| I2 - Hash-pinned core, one multi-gated change path | GRAPHSMITH-PROTOCOL.md:75-79 | ✓ Present |
| I3 - Isolated evaluation before acceptance | GRAPHSMITH-PROTOCOL.md:81-88 | ✓ Present |
| I4 - Local evolution, no automatic upstream contribution | GRAPHSMITH-PROTOCOL.md:90-96 | ✓ Present |
| I5 - Observable, budgeted, killable runs | GRAPHSMITH-PROTOCOL.md:98-108 | ✓ Present |
| R Profile | GRAPHSMITH-PROTOCOL.md:128-137 | ✓ Present |
| E Profile | GRAPHSMITH-PROTOCOL.md:139-145 | ✓ Present |
| B Profile | GRAPHSMITH-PROTOCOL.md:147-154 | ✓ Present |
| T Profile | GRAPHSMITH-PROTOCOL.md:156-163 | ✓ Present |
| G Profile | GRAPHSMITH-PROTOCOL.md:165-172 | ✓ Present |
| Q Profile | GRAPHSMITH-PROTOCOL.md:174-183 | ✓ Present |
| X Profile | GRAPHSMITH-PROTOCOL.md:185-196 | ✓ Present |
| Gate 1 | GRAPHSMITH-PROTOCOL.md:203-206 | ✓ Present |
| Gate 2 | GRAPHSMITH-PROTOCOL.md:208-216 | ✓ Present |
| Gate 3 | GRAPHSMITH-PROTOCOL.md:218-220 | ✓ Present |
| Gate 4 | GRAPHSMITH-PROTOCOL.md:222-230 | ✓ Present |
| Schemas | GRAPHSMITH-PROTOCOL.md:26-46 | ✓ Present |
| Trust model | GRAPHSMITH-PROTOCOL.md:233-240 | ✓ Present |
| Exit codes | GRAPHSMITH-PROTOCOL.md:245-246 | ✓ Present |

**Assessment:** All required protocol components are present and accurately documented.

---

## Designed-but-Unshipped Features

The protocol correctly identifies designed-but-unshipped features as NOT implemented:

**SPEC-CHANGES.md:35-36:**
> "Continuous-score Gate-2 endpoints, the Loop-W tuner, and runtime effect reconciliation (the live status_check state machine behind profile E) are designed seams that are not part of this release's tested surface and are not specified here as implemented."

**Assessment:** Honest flagging of unimplemented features. No claims of completion for unshipped functionality.

---

## Claims Verification Summary

### Verified Claims (Sample)

1. **"R is a CAPABILITY attestation of THIS installation's state-store"** - VERIFIED
   - Source: `scripts/verify.js:1209`
   - Implementation creates ephemeral fixtures under OS temp dir

2. **"E depends entirely on adapter capability declarations"** - VERIFIED
   - Source: `scripts/verify.js:1285`
   - Implementation only checks declarations, never runtime behavior

3. **"B is a CAPABILITY attestation: it scaffolds an ephemeral supervised project"** - VERIFIED
   - Source: `scripts/verify.js:1347`
   - Implementation uses scaffold.js to create temp project

4. **"T depends on the release trust root: release-verified anchors to the release manifest"** - VERIFIED
   - Source: `scripts/verify.js:1578`
   - Implementation derives T from runIntegrity() results

5. **"G is a CAPABILITY attestation: it stages a real proposal through gate.js and adopt.js"** - VERIFIED
   - Source: `scripts/verify.js:1405`
   - Implementation directly calls gate.gate1Static() and adopt.adopt()

6. **"Q is 'verified' only when BOTH the test battery passes AND architectural lint is clean"** - VERIFIED
   - Source: `scripts/verify.js:1503`
   - Implementation returns verified only when testPass && lintClean

7. **"Gate 2 freezes one endpoint type: binary scenario pass/fail"** - VERIFIED
   - Source: `contracts/03-statistical-appendix.md:5` and `scripts/gate.js:23`
   - Implementation uses BONFERRONI_ALPHA with binary pass/fail

### No Claims Wider Than Implementation

All substantive claims in the protocol documentation are **narrower than or equal to** the actual implementation. No claims found that assert more capability than the code delivers.

---

## Conclusion

The GraphSmith Protocol v0.1-draft documentation is **accurate, honest, and complete** relative to the actual implementation. The protocol successfully:

1. **Documents only implemented behavior** - No unimplemented features presented as done
2. **Uses honest language** - Zero violations of banned over-claim terms
3. **Maintains publication hygiene** - No external research/organization identifiers
4. **Writes claims narrower than implementation** - All claims verified against source code
5. **Completely specifies the protocol** - All invariants, profiles, gates, and schemas present

The draft banner ("breaking changes possible until v1.0") is appropriate for this stage of development.

**Recommendation:** The protocol documentation is ready for public review as an accurate specification of the implemented behavior.