# WS-C core — MCP attestation shim + conformance kit — adversarial adjudication

**Targets:** `scripts/gsa-mcp-shim.js` (MCP boundary attestation), `scripts/gsa-conformance.js` (portable conformance battery + evidence-carrying badge).
**Builder:** claude-opus (Anthropic) · **Platform:** win32, Node v24.18.0 · **Testers (≥2 non-Anthropic):** DeepSeek + Mistral-Large (OpenRouter code-gen), each seals a boundary bundle then attacks it. Builder ≠ testers. Orchestrator re-ran both suites.

## MCP shim — result
**DeepSeek 8/8, Mistral 17/17 — no findings.** These are *executed* suites (attacks that ran and were defended), not rubber-stamp reviews. Both families covered:
- **Boundary honesty** — the emitted bundle confirms **profile A only**; it cannot be made to assert a full plan profile it did not observe.
- **Granted surface** — a `tools/call` to a tool absent from `tools/list` appears in the trace with `granted:false`; it is not hidden or marked granted.
- **Tamper-evidence** — the sealed boundary bundle verifies; any artifact or manifest mutation makes it FAIL.
- **Control honesty** — `all_skills_signed_and_approved` is false for MCP tools (observed, not approved) and cannot be forced true via the session.
- **Input-as-data** — a tool result containing "IGNORE PREVIOUS INSTRUCTIONS…" is hashed into the trace as data, never interpreted; bundle structure/profiles unchanged.
- **Crash-safety** — malformed session (missing fields, wrong types, hostile getters, BigInt, huge arrays, proto pollution) does not break honest sealing.

**Why a clean result is trustworthy here** (not a rubber-stamp): the shim's boundary honesty is *structurally enforced*, not a runtime check an attacker could flip — it hardcodes `profiles:["A"]`, hardcodes the plan artifacts as boundary placeholders, and hardcodes `approval_status:"observed"`; the session (attacker-controlled) supplies only tool/call data. The security-critical sealing and verification are the already-TEST-PASSED `gsa-produce` / `gsa-verify` (which took real fixes in `tests/gsa/ADJUDICATION.md`), so the shim adds honest field-mapping, not new crypto/verification surface.

## Conformance kit — result
Self-validated: `gsa-conformance --selftest` runs **10/10** vectors (2 valid modes + 8 negatives, one per attack class: artifact tamper, manifest tamper, empty signature, untrusted signer, path traversal, control lie, regulator-summary presence both directions) and confirms the reference verifier's PASS/FAIL matches expected. Emits an **evidence-carrying badge** (verifier version + platform + node + `date=unavailable(no-clock-in-decision-path)` + `result=N/N`) — unavailable is explicit, never green. The kit is a meta-harness built on the TEST-PASSED verifier; its own logic is exercised by the selftest.

## Verdict
**WS-C core (MCP shim + conformance kit) TEST-PASSED.** The shim emits a valid, honestly-labeled boundary bundle for MCP agents GraphSmith did not build, verifiable end-to-end, asserting only what the boundary observed; the conformance kit gives any verifier implementation a portable pass/fail battery with an evidence-carrying badge. (Property matrix across agents×OS and the NIST prior-art submission remain as the WS-C docs/CI increment.)
