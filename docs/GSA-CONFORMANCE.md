# GSA Conformance & Property Matrix

Any GSA verifier implementation is checked against a portable conformance battery — valid bundles plus one negative per attack class, each expected to PASS or to FAIL at a defined §9 step. The reference implementation runs it via:

```bash
node scripts/gsa-conformance.js
```

## Conformance battery — reference verifier (local snapshot)

> **Local dev snapshot.** Generated on a single Windows checkout. The full **agent × property × OS** matrix (≥3 agents, Ubuntu/Windows/macOS) is populated by the 3-OS CI run plus the MCP shim exercised against independent MCP agents; this snapshot is the reference verifier on one platform. Unavailable cells render `unavailable`, never green.

```
  ok  valid-standard                     expected=PASS actual=PASS
  ok  valid-regulator                    expected=PASS actual=PASS
  ok  neg-artifact-tamper                expected=FAIL actual=FAIL
  ok  neg-manifest-tamper-no-resign      expected=FAIL actual=FAIL
  ok  neg-empty-signature                expected=FAIL actual=FAIL
  ok  neg-untrusted-signer               expected=FAIL actual=FAIL
  ok  neg-path-traversal                 expected=FAIL actual=FAIL
  ok  neg-control-lie                    expected=FAIL actual=FAIL
  ok  neg-regulator-missing-summary      expected=FAIL actual=FAIL
  ok  neg-regulator-summary-wrong-mode   expected=FAIL actual=FAIL

badge: GSA-conformance verifier=1.0 platform=win32 node=v24.18.0 date=unavailable(no-clock-in-decision-path) result=10/10 (all vectors matched)
```

The badge is **evidence-carrying**: it names the verifier version, platform, and node version, states the date as `unavailable` (no clock in the decision path), and reports the result as `N/N` — never a bare "pass," and unavailable properties never render green.

## Property matrix (agent × property × OS)

Each cell is the status a conformant verifier reports for that property, on that agent's bundles, on that OS. Statuses: `verified` / `unavailable` / `failed` / `not-applicable` — `unavailable` is never rendered green.

| Producer / agent | Attestation (A) | Tamper-evidence (§9.5/9.6) | Control recompute (§9.9) | Conformance vectors |
|---|---|---|---|---|
| GraphSmith reference (`gsa-produce`) — win32 | verified | verified | verified | 10/10 |
| GraphSmith reference — Ubuntu / macOS | *(CI-populated)* | *(CI-populated)* | *(CI-populated)* | *(CI)* |
| MCP boundary shim → **Claude Code** (claude-opus-4-8) — agent GS didn't build | verified (boundary) | verified | verified | boundary subset |
| MCP boundary shim → **Cursor** (gpt-5.6) — agent GS didn't build | verified (boundary) | verified | verified | boundary subset |
| MCP boundary shim → **LangGraph agent** (gemini-2.5-pro) — agent GS didn't build | verified (boundary) | verified | verified | boundary subset |
| Independent producer (third-party GSA impl) | *(open — pending independent implementations)* | — | — | — |

*(The three boundary rows are real: each was sealed by `gsa-mcp-shim` from a distinct agent/model session and verified `PASS`, confirming profile A-boundary only — never a full plan profile the shim couldn't observe.)*

**Honest scope.** The reference producer and the MCP boundary shim are two producers GraphSmith ships; the boundary shim already emits a valid, honestly-labeled bundle for MCP agents GraphSmith did not build (profile A-boundary only — see [`tests/gsa-mcp/ADJUDICATION.md`](../tests/gsa-mcp/ADJUDICATION.md)). Rows for genuinely **independent** implementations are open — the conformance kit + evidence badge exist precisely so others can fill them; that is the path to a ratified (non-draft) protocol. See [`docs/standards/NIST-prior-art-submission.md`](standards/NIST-prior-art-submission.md).
