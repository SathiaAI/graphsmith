# Contribution / Prior-Art Submission: An Open, Verifiable Attestation Record for AI Agent Workflows

**To:** NIST AI program — the working effort on AI agent interoperability / the anticipated *AI Agent Interoperability Profile* (venue to be confirmed: RFI response, public comment on a draft, or working-group contribution).
**From:** GraphSmith (SathiaAI), maintainers of the GraphSmith Attestation (GSA) specification and reference implementation.
**Date:** ⟨submission date⟩. **Status:** DRAFT for review before submission.
**License of contributed material:** GSA specification and schemas are Apache-2.0; the reference implementation is MIT. This contribution is offered openly for incorporation or reference.

> **Note on scope and honesty.** GSA is a technical *evidence* layer, not a compliance certification. This submission offers an implemented, open reference for the record-keeping/attestation portion of agent interoperability. We make no claim that GSA determines compliance; that remains with deployers and regulators.

## 1. Executive summary
Agent-to-tool connectivity has largely standardized (MCP is broadly adopted), but there is **no interoperable, verifiable standard for the record of what an agent run actually did.** Organizations implement audit logging ad hoc at the gateway; records are frequently not tamper-evident or independently verifiable — the gap regulators (e.g., EU AI Act Article 12) are moving to close. We submit **GSA** as existing prior-art and an open reference: an implemented, tested, permissively-licensed **attestation-record format + verification algorithm + conformance suite**. We recommend the Profile specify an interoperable attestation record along these lines, and we offer GSA (or its relevant parts) as a starting point and our participation in the effort.

## 2. The gap the Profile should address
For agent interoperability to be trustworthy across vendors, a run's record must be:
- **Portable** across agents/runtimes (not vendor-specific log shapes).
- **Tamper-evident and independently verifiable** (cryptographic, not access-control-only).
- **Reproducible/replayable** where the run is deterministic, with model-dependent steps marked.
- **Provenance-bearing** for the skills/tools/capabilities used, including approval status.
- **Evidence-scoped** — a record of what happened, explicitly *not* a certification of safety or compliance.

MCP does not specify this (audit is out of its scope); NIST AI RMF and ISO/IEC 42001 give governance frameworks but not a concrete, verifiable record format. This is the interoperability seam the Profile can standardize.

## 3. What GSA provides (implemented today)
- **A bundle format** (`attestation-bundle.schema.json`, JSON Schema draft 2020-12): goal, typed plan, compiled+signed graph, per-skill provenance (version, implementation hash, approval status, signature), capability manifest (requested vs granted), execution trace, outputs — all content-addressed and hash-chained.
- **A signing model**: pre-execution graph signature (approval/non-repudiation) + whole-bundle signature; keyless (transparency-log) optional, local keypair default; no PKI required.
- **A verification algorithm** (specified, reference-implemented): schema, path-safety, artifact integrity, signatures, capability conformance, provenance, and control re-computation — fail-closed.
- **Capability profiles** (independently verifiable claims) and explicit, machine-checkable control attestations (e.g., "no autonomously-created skill executed," "deterministic mode," "adversarial battery passed").
- **A conformance suite**: golden vectors (valid + negative) that a conformant verifier must pass/reject at defined steps.

## 4. Alignment with NIST AI RMF and existing regimes
- **GOVERN** — enforced, documented capability policy + approval status per skill.
- **MAP** — the typed plan/graph maps intended actions and data touch before execution.
- **MEASURE** — the verifier's profile report + adversarial battery results are repeatable, evidence-linked measurements.
- **MANAGE** — drift/destructive-change detection, budgets, staged reversible repair, one-command replay.
GSA records also map to **EU AI Act Article 12** record-keeping (tamper-evident, output-verifiable, exportable), which we document in a separate crosswalk available on request.

## 5. Interoperability properties (why GSA suits a standard)
- **Spec, not a binary** — JSON Schemas + a canonical hashing/signing algorithm + a verification procedure + vectors; implementable in any language by any vendor.
- **Complements MCP** — a thin attestation shim at the MCP boundary can emit records for any MCP-speaking agent, so a standard record is adoptable without per-vendor code.
- **Open and fork-resistant** — Apache-2.0 spec, MIT reference, a published no-relicense commitment.

## 6. Recommendations for the Profile
1. Specify a **normative, interoperable attestation-record format** for agent runs (GSA offered as a reference).
2. Require **cryptographic tamper-evidence and independent verifiability**, not access-control-only logging.
3. Adopt **profile-based, independently-verifiable capability claims** rather than a single pass/fail badge.
4. Require **provenance + approval status** for skills/tools used, with revocation awareness.
5. Frame records as **evidence, not certification**, with explicit stated limits (a passing battery is a floor; boundary-only records labeled as such).
6. Include **conformance test vectors** so verifier implementations are interoperable, not just documents.

## 7. What we offer
The Apache-2.0 specification, schemas, and conformance vectors; the MIT reference producer/verifier; a crosswalk to Article 12 and the RMF; and our active participation in the working effort, including willingness to **align field names and semantics** with the Profile rather than insist on ours. Our interest is a single interoperable record the whole ecosystem can emit and verify.

## 8. Availability & contact
Specification, schema, reference implementation, and conformance vectors: ⟨public links⟩. Contact: ⟨name, role, email⟩. We can present a 30-minute technical walkthrough and a live verification demo at the working group's convenience.

---
*Prepared as an open contribution. Confirm the correct NIST venue/format (RFI, public comment window, or working-group intake) before submission; adapt the header accordingly.*
