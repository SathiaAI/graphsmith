# GraphSmith `audit replay` (Lane E) — Design Doc

**Status:** design frozen after independent adversarial review (2026-08-01). Not yet built. Part of the GSA follow-up track — see `CANONICAL-SOURCE.md` in this same folder for scope, sequencing, and the open items Paul needs to confirm before this is built.

**Grounded against the live repo** (`SathiaAI/graphsmith`, `main`, fetched directly): `schemas/attestation-bundle.schema.json`, `scripts/gsa-verify.js`, `scripts/gsa-produce.js`, `scripts/gsa-plan.js`, `scripts/gsa-register.js`, `scripts/graphsmith-cli.js`, `checks/v040-caps.js`, `checks/v040-trace.js`, `checks/v040-provenance.js`, `KNOWN-LIMITATIONS.md`, `docs/GSA-CONFORMANCE.md`, `docs/examples/offline-verify.md`, `README.md`, `package.json`.

**Adversarial review:** an independent reviewer (fresh context, no access to this doc's authoring reasoning) found 2 HIGH, 4 MEDIUM, 2 LOW issues in the first draft. All are fixed in this version; each fix is marked inline as `[Fixed per adversarial review, YYYY-MM-DD]`. The two HIGH findings were real design gaps (a forgery path, and a schema bug independently confirmed by running the schema through a validator), not stylistic notes — both are described in full below rather than glossed over.

---

## 0. Corrections to the background brief

1. **`scripts/gsa-plan.js` already exists and already does half of "replay."** It exports `replayBundle(bundle)` — recomputes every artifact's SHA-256, the graph/policy/skill-set hashes, and reports `{reproducible, deterministic_confirmed, mismatches, non_replayable}`, honestly marking model-dependent trace lines `non_replayable` rather than failing on them — and `planDrift(prev, curr)` — diffs two bundle manifests and flags destructive changes. Both are pure, tested (`--selftest` passes, documented in `KNOWN-LIMITATIONS.md` §3), and **not wired into `graphsmith-cli.js` at all**. This is a CLI-and-narrative layer on top of two already-built, already-reviewed pure functions — not a green-field build.
2. **The literal string "audit replay" appears zero times in the repo.** `scripts/graphsmith-cli.js` implements exactly `verify` and `--version`. The README's roadmap describes `plan → sign → apply → verify → replay` as an aspirational lifecycle shape; no `plan`/`sign`/`apply`/`replay` subcommand exists.
3. **This exact question has already been through a decision round** — see `claude/graphsmith-post-mortem-track-scoping-2026-08-01.md` (project doc) and `CANONICAL-SOURCE.md`.

---

## 1. What `graphsmith audit replay` outputs

### 1.1 Framing — narration, not a new trust primitive

`audit replay` must never recompute a hash, verify a signature, or re-derive a control attestation itself. It consumes `verifyBundle()` and `replayBundle()`/`planDrift()` outputs, and is forbidden from importing `crypto` or duplicating any of `verifyBundle`'s §9 comparison logic — **to be enforced by a new lint rule as part of this build** (`[Fixed per adversarial review: this rule does not exist yet — the first draft described it in present tense as if already built]`).

**`[Fixed per adversarial review — HIGH]` Verification provenance is now a first-class, required field.** The first draft let a caller skip live verification via `--no-verify` and hand in an arbitrary `verify_result` on stdin, with no field anywhere recording whether that result came from a real `verifyBundle()` run or was supplied externally. A reviewer confirmed this let anyone hand-write a fabricated `{"status":"PASS",...}` and get a fully narrated "verified" report for any bundle, including one that would fail real verification — the crypto-import ban only guards the *code path*, not the *data path*. Fixed by adding `verification_provenance: "live" | "external"` as a required top-level field. **Rule: when `verification_provenance` is `"external"`, every dimension renders `unavailable` regardless of the supplied `verify_result`'s content** — the same treatment as a `FAIL`. This makes `--no-verify` still usable for CI pipelines that already ran `verify` and want to avoid paying for it twice (its original purpose), while making it structurally impossible for externally-supplied input to ever produce a `verified` dimension. A forged PASS can still be supplied, but it can never be rendered as trustworthy by this tool.

If a bundle fails live §9 verification, `audit replay` still runs (so a user can see *why* it failed and what a tampered bundle claims), but every downstream dimension renders `unavailable`, citing the verification failure as the reason.

### 1.2 Report structure

- **Header** — `bundle_id`, `producer`, `mode`, `profiles` (as asserted), tool name/version, `generated` (`"unavailable"` unless the caller supplies a timestamp as data — no clock read in the decision path, mirrors `gsa-produce.js`'s own `created: run.created || "unavailable"` pattern).
- **Verify narration** — verbatim pass-through of `verifyBundle()`.
- **Replay narration** — verbatim pass-through of `replayBundle()`. `[Fixed per adversarial review — MEDIUM]`: this is now a required field in the schema (§3), matching the prose here, which always treats it as a standing section, not an optional one — the first draft had it required in prose but optional in the schema.
- **Drift (optional)** — present only when the caller supplies a second, prior bundle via `--diff`. Wraps `planDrift(prev, curr)` verbatim.
- **Dimensions** — four fixed, always-present, evidence-anchored scored sections (§1.3), plus one conditional fifth when the bundle carries `control_attestations_v040`.
- **Marks** — evidence-anchored occurrences of known string markers inside `execution_trace` (§1.4).
- **Skills lens** — one entry per `skills[]` provenance record, plus a count of literal string-mentions of that `skill_id` inside `execution_trace` (a shallow lens — see §2 for why).
- **Narrative** — a short plain-English paragraph, template-composed (never LLM-generated) from the dimension statuses and verify/replay results.
- **Evidence index** — a flat list of every JSON-Pointer evidence citation used anywhere in the report.

### 1.3 The four core dimensions

1. **Provenance & signing** — `graph_signature`, `bundle_signature`, `skills[]`, `control_attestations.all_skills_signed_and_approved`.
2. **Capability posture** — `capabilities.result`/`capabilities.resources`, `control_attestations_v040.capability_conformance` when present.
3. **Determinism & repair** — `mode`, `control_attestations.deterministic_mode`, marker occurrences (§1.4), `repair_log` presence.
4. **Adversarial coverage** — `adversarial.suites[]`, `control_attestations.adversarial_batteries_passed`.

Conditional fifth, **extended controls (v0.4.0)**: present only when `control_attestations_v040` is present, rendering each of its five checks. **`[Fixed per adversarial review — LOW, ties into the HIGH fix above]`**: the real `verifyBundle()` only returns one aggregate `"11-extended-controls"` step, not the five individual booleans — rendering this dimension requires reading `manifest.control_attestations_v040` directly, which is safe *only* when `verification_provenance` is `"live"` and `verify_result.status` is `"PASS"`. This dependency is now explicit; combined with the provenance fix in §1.1, a forged/external input can no longer reach this dimension at all.

Status vocabulary: `PASS→verified`, `FAIL→failed`, `UNAVAILABLE→unavailable` — reusing `verifyBundle`'s existing vocabulary rather than inventing a parallel one.

### 1.4 Marks

Every occurrence of every marker from `NONDETERMINISTIC_MARKERS` (6), the repair regex, and `MODEL_DEP_MARKERS` (4, from `gsa-plan.js`), reported with byte offset into `execution_trace`. Explicitly not a timeline — no ordering or click-to-jump guarantee, since matching is plain string search against unstructured JSONL with no published schema.

---

## 2. Mapping mindwalk's ideas onto GSA's data model

| mindwalk concept | GSA equivalent | Verdict |
|---|---|---|
| Agent lenses | `skills[]` is a flat provenance list, no call graph | **Doesn't fit** — ships a much shallower "skills lens" instead (flat-list filter + naive trace string-search), explicitly labeled as a downgrade, not a renamed equivalent |
| Timeline marks | 10 string markers matched via `indexOf`/regex against unstructured trace | **Partial fit** — occurrence-with-offset is buildable today; typed/ordered/clickable is not, because `execution_trace` has no schema |
| Inspector | No file-visit/tool-call event schema | **Doesn't fit as a literal file-inspector** — reframed as lookup over the collections GSA *does* structure: `artifacts`, `skills[]`, `adversarial.suites[]`, `capabilities.resources`, `redactions[]` |
| Sealed-subprocess judge, mechanical verdicts | GraphSmith's own zero-LLM-in-decision-paths ethos | **Fits exactly** — the narrative composer is this pattern natively, not an import |
| Fixed 4-dimension report, evidence-anchored findings | — | **Fits as a pattern**, different 4 dimensions, chosen from what GSA's schema actually requires |
| 3D visualization | — | **Out of scope entirely** — zero runtime dependencies, no UI framework anywhere in the tree |

---

## 3. JSON Schema (draft 2020-12) — `audit-replay-report.schema.json`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://graphsmith.dev/schemas/audit-replay-report.schema.json",
  "title": "GraphSmith audit replay report",
  "description": "Output of `graphsmith audit replay <bundle.json>`. A narrative report over an already-produced GSA attestation bundle. Recomputes nothing itself -- pure consumer of scripts/gsa-verify.js#verifyBundle() and scripts/gsa-plan.js#replayBundle()/#planDrift(). A report whose verification_provenance is 'external', or whose verify_result.status is not PASS, MUST render every dimension unavailable -- it must never narrate an unverified, forged, or tampered bundle as trustworthy.",
  "type": "object",
  "required": ["schema_version", "tool", "bundle_id", "generated", "mode", "asserted_profiles", "verification_provenance", "verify_result", "replay_result", "dimensions", "marks", "skills_lens", "narrative", "evidence_index"],
  "additionalProperties": false,
  "properties": {
    "schema_version": { "const": "0.2" },
    "tool": {
      "type": "object",
      "required": ["name", "version"],
      "additionalProperties": false,
      "properties": {
        "name": { "const": "graphsmith-audit-replay" },
        "version": { "type": "string", "minLength": 1 }
      }
    },
    "bundle_id": { "type": "string", "pattern": "^gsa-[0-9a-f]{16}$" },
    "generated": {
      "description": "UTC timestamp the report was produced, or 'unavailable' -- no clock read in the decision path. [Fixed per adversarial review -- HIGH: the first draft used `oneOf` here, which is broken under draft 2020-12's default (non-format-asserting) semantics -- confirmed by running the schema through Python's jsonschema.Draft202012Validator, which correctly rejects 'unavailable' as matching BOTH oneOf branches simultaneously, since `format` is annotation-only unless a validator opts into format-assertion. Fixed by switching to `anyOf`, which only requires at least one branch to match and has no exclusivity requirement.]",
      "anyOf": [
        { "type": "string", "const": "unavailable" },
        { "type": "string", "format": "date-time" }
      ]
    },
    "mode": { "enum": ["standard", "deterministic", "regulator"] },
    "asserted_profiles": {
      "type": "array",
      "uniqueItems": true,
      "items": { "enum": ["R", "E", "B", "T", "G", "Q", "A", "X"] }
    },
    "verification_provenance": {
      "enum": ["live", "external"],
      "description": "[Fixed per adversarial review -- HIGH] 'live': verify_result came from a real verifyBundle() run performed by this invocation. 'external': verify_result was supplied by the caller (e.g. via --no-verify + stdin) and is NOT independently confirmed. When this is 'external', every entry in `dimensions` MUST have status 'unavailable' regardless of what verify_result claims -- this is the structural fix that closes the forgery path a reviewer found in the first draft (a hand-written fake PASS could otherwise produce a fully 'verified'-labeled report)."
    },
    "verify_result": {
      "description": "Verbatim output of gsa-verify.js#verifyBundle() when verification_provenance is 'live'; the caller-supplied value when 'external'. Never re-derived by this tool either way.",
      "type": "object",
      "required": ["status", "steps", "confirmed_profiles", "downgraded_profiles", "note"],
      "additionalProperties": false,
      "properties": {
        "status": { "enum": ["PASS", "FAIL"] },
        "steps": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["step", "status"],
            "additionalProperties": false,
            "properties": {
              "step": { "type": "string" },
              "status": { "enum": ["PASS", "FAIL", "UNAVAILABLE"] },
              "detail": { "type": "string" }
            }
          }
        },
        "confirmed_profiles": { "type": "array", "items": { "type": "string" } },
        "downgraded_profiles": { "type": "array", "items": { "type": "string" } },
        "note": { "type": "string" }
      }
    },
    "replay_result": {
      "description": "Verbatim output of gsa-plan.js#replayBundle(). [Fixed per adversarial review -- MEDIUM: this was optional in the first draft's schema despite being described in prose as an always-run, standing section -- now required, matching the prose in Section 1.2.]",
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "reproducible": { "type": "boolean" },
        "deterministic_confirmed": { "type": "boolean" },
        "mismatches": { "type": "array", "items": { "type": "string" } },
        "non_replayable": { "type": "array", "items": { "type": "string" } }
      },
      "required": ["reproducible", "deterministic_confirmed", "mismatches", "non_replayable"]
    },
    "drift": {
      "description": "Present only when a prior bundle was supplied via --diff. Verbatim output of gsa-plan.js#planDrift(prev, curr).",
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "added": { "type": "array", "items": { "type": "string" } },
        "removed": { "type": "array", "items": { "type": "string" } },
        "changed": { "type": "array", "items": { "type": "string" } },
        "destructive": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["kind"],
            "properties": {
              "kind": { "enum": ["artifact-removed", "output-changed", "mode-downgrade", "profile-dropped", "error"] },
              "key": { "type": "string" },
              "from": { "type": "string" },
              "to": { "type": "string" },
              "profile": { "type": "string" },
              "detail": { "type": "string" }
            }
          }
        },
        "safe": { "type": "boolean" }
      },
      "required": ["added", "removed", "changed", "destructive", "safe"]
    },
    "dimensions": {
      "type": "array",
      "minItems": 4,
      "maxItems": 5,
      "items": { "$ref": "#/$defs/dimension" }
    },
    "marks": {
      "type": "array",
      "items": { "$ref": "#/$defs/mark" }
    },
    "skills_lens": {
      "type": "array",
      "items": { "$ref": "#/$defs/skillLensEntry" }
    },
    "narrative": {
      "type": "string",
      "minLength": 1,
      "description": "Plain-English summary, template-composed from dimensions/verify_result/replay_result/marks. Never LLM-generated; must not assert anything not traceable to evidence_index."
    },
    "evidence_index": {
      "type": "array",
      "items": { "$ref": "#/$defs/evidencePointer" }
    }
  },
  "$defs": {
    "dimension": {
      "type": "object",
      "required": ["id", "title", "status", "evidence", "assumptions"],
      "additionalProperties": false,
      "properties": {
        "id": { "enum": ["provenance_signing", "capability_posture", "determinism_repair", "adversarial_coverage", "extended_controls_v040"] },
        "title": { "type": "string", "minLength": 1 },
        "status": { "enum": ["verified", "failed", "unavailable"] },
        "evidence": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/evidencePointer" } },
        "assumptions": { "type": "array", "items": { "type": "string" } },
        "reason": { "type": "string", "description": "Required in practice when status != verified; enforced by the report generator, not the schema, since JSON Schema can't express a cross-field conditional this cleanly without duplicating the whole dimension shape per status." }
      }
    },
    "mark": {
      "type": "object",
      "required": ["marker", "list", "pointer", "offset"],
      "additionalProperties": false,
      "properties": {
        "marker": { "type": "string", "minLength": 1 },
        "list": { "enum": ["nondeterministic", "repair", "model-dependent"] },
        "pointer": { "type": "string", "description": "JSON Pointer to the artifact (always execution_trace today)." },
        "offset": { "type": "integer", "minimum": 0 }
      }
    },
    "skillLensEntry": {
      "type": "object",
      "required": ["skill_id", "version", "approval_status", "source", "trace_mentions"],
      "additionalProperties": false,
      "properties": {
        "skill_id": { "type": "string" },
        "version": { "type": "string" },
        "approval_status": { "enum": ["approved", "quarantined", "generated", "revoked"] },
        "source": { "enum": ["local", "generated", "remote"] },
        "signer": { "type": "string" },
        "trace_mentions": {
          "type": "integer",
          "minimum": 0,
          "description": "Count of literal skill_id string occurrences found in execution_trace by plain string search. NOT a structural call count -- evidence of co-occurrence only, never presented as an invocation count."
        }
      }
    },
    "evidencePointer": {
      "type": "object",
      "required": ["pointer", "description"],
      "additionalProperties": false,
      "properties": {
        "pointer": { "type": "string", "description": "RFC 6901 JSON Pointer into the bundle's manifest (prefix /manifest/...) or contents (prefix /contents/<path>)." },
        "description": { "type": "string", "minLength": 1 },
        "excerpt": { "type": "string", "description": "A short literal value or truncated excerpt. Never fabricated; omitted rather than approximated when large or when redaction status is unknown." }
      }
    }
  }
}
```

---

## 4. CLI surface

```
graphsmith audit replay <bundle.json> [options]

  --keys <trusted-keys.json>   Same shape as `verify`. Without it, provenance_signing renders
                                unavailable for authenticity, same as `verify` does.
  --revoked <hashes.json>      Same shape as `verify`.
  --diff <prior-bundle.json>   Enables the drift section (planDrift). Optional.
  --lens <skill_id>            Filter skills_lens/marks to one skill_id. Optional.
  --json                       Emit the full machine-readable report (schema in §3). Default is a
                                human-readable rendering in the existing `§9.x step / status / note`
                                house style (docs/examples/offline-verify.md).
  --no-verify                  Accept a precomputed verify_result via stdin instead of running
                                verifyBundle() live. Sets verification_provenance to "external" --
                                every dimension renders unavailable regardless of the supplied
                                result's content (see §1.1, §3). For CI pipelines that already ran
                                `verify` and don't want to pay for it twice; NOT a way to get a
                                "verified" report without a real verify.
```

Deliberately not included: `--reproduce`, `--execute`, or any flag implying re-running the workflow (§5). `--keys`/`--revoked`/`--json` deliberately mirror `graphsmith verify`'s existing flags.

---

## 5. Explicit scope cuts

- **"Reproduce the run" is not feasible today, and this design does not attempt it.** `replayBundle()` confirms deterministic hashes reproduce and honestly reports model-dependent steps as `non_replayable` — there is no re-executable harness captured anywhere in a GSA bundle. Building true reproduction would require a different, much larger schema change to GSA itself.
- **No agent-lens replay** — `skills[]` has no call-graph structure; the skills lens is a flat-list filter plus naive string search, explicitly labeled as such.
- **No typed/ordered timeline** — marker occurrences with byte offsets, not semantic events, because `execution_trace` has no published schema.
- **No arbitrary-entity inspector** — scoped to GSA's genuinely structured collections (`artifacts`, `skills[]`, `adversarial.suites[]`, `capabilities.resources`, `redactions[]`), not to files or tool calls.
- **No visualization/UI** — CLI + JSON report only.
- **No coverage of raw coding-agent session logs** — that's Lane F, a separate, unrelated log format.
- **`--diff` covers only bundle-to-bundle structural drift** via `planDrift` — reports *what* changed, not *why*.

---

## 6. Evidence-anchoring rules

1. **Every dimension, mark, and skills-lens entry MUST carry at least one `evidencePointer`** resolving to a real field in the input bundle — enforced structurally via `minItems: 1` on every dimension's `evidence` array.
2. **`excerpt` values must be literal substrings/values from the bundle, never paraphrased or inferred.**
3. **The narrative paragraph may only state what's traceable to `evidence_index`**, enforced by construction: the narrative composer's only inputs are the already-built `dimensions`/`marks`/`verify_result` structures.
4. **A leak-through scan runs on the report's own output before it's emitted**, using `checks/v040-trace.js#scanLeaks()`, applied even to v0.3.0-only bundles that never went through a `trace_redaction` check at all. Any match is replaced with `"[redacted-by-audit-replay: <pattern-name>]"`, and the substitution is itself recorded as evidence, never silently dropped. **`[Fixed per adversarial review — MEDIUM]`**: the first draft's phrase "confirm zero leak-through" overclaimed what this reused module actually guarantees — `scanLeaks()`'s own code comment states its pattern battery is "a recall-measured floor, not proof of zero leakage." Restated accurately: this scan **detects** known secret/PII patterns with a documented recall floor (≥95% across 18 patterns per its own self-test); it is not a proof of zero leakage, and the design doesn't claim it is. Also clarified: `scanLeaks()` performs *detection only* — it returns matched pattern names, not substitution. The substitution-and-evidence-recording step described here is genuinely new code with no existing analog to reuse (this distinction matters for the sizing in §8, which the first draft's phrasing blurred).
5. **A report whose `verification_provenance` is `"external"`, or whose `verify_result.status` is `"FAIL"`, renders every dimension `unavailable`**, citing the reason as evidence. No code path can produce a `verified` dimension status under either condition — a structural invariant intended to be directly unit-tested (construct bundles that fail for every distinct §9 reason, and construct forged-external inputs, and assert every dimension downgrades in both cases).

---

## 7. Security-tier judgment — unhedged

**No, this does not need GSA's full security-tier bar** (≥2 independent non-Anthropic-family reviewers, adversarial gauntlet-scale battery, orchestrator re-run discipline). **It also does not get Wave-1's lighter bar as-is.**

**`[Fixed per adversarial review — MEDIUM]`** A reviewer noted this doc's first draft didn't reconcile its tier judgment against this project's own prior precedent: `claude/graphsmith-v0.3.0-council-hardening-plan.md` classifies "`plan/apply/sign/replay` UX, drift/destructive-change detection" as **"routine"** tier — well below even Wave 1's bar. That precedent predates this design and covers a narrower surface (drift/destructive-change detection alone, no raw-trace excerpting, no forged-input handling). This doc's escalation above "routine" is deliberate, not an oversight: excerpting raw `execution_trace` bytes into a newly-distributed artifact, and handling `--no-verify`'s externally-supplied input path (§1.1), are both real risks the "routine" precedent's scope never had to consider. The judgment below supersedes that precedent for this specific capability.

**Why it doesn't need the full bar:** the design makes zero new trust claims. It recomputes no hash, verifies no signature, and re-derives none of the `control_attestations` booleans — architecturally forbidden from doing so (a lint rule bans `require("crypto")` and re-implementing any §9 comparison), and the `verification_provenance` fix in §1.1 closes the one path a reviewer found where forged input could otherwise reach a `verified`-labeled dimension. Everything the report asserts about bundle validity is a verbatim pass-through of already-security-tier-reviewed `verifyBundle()`/`replayBundle()` output.

**Why it isn't zero-scrutiny either:** two real, specific risks, neither carried by Wave 1's lanes:

1. **A new secret-handling boundary.** `audit replay` is the first GraphSmith tool whose purpose is to copy raw bytes out of `execution_trace` into a newly-distributed artifact (the report), applying retroactively to every v0.3.0-only bundle with no redaction history at all. A bug here is a genuinely new leak class.
2. **Narrative fidelity is a new correctness surface.** A dimension rendered `verified` when the underlying evidence doesn't support it is a false-green in the report layer, read by exactly the audience least likely to go re-check the raw JSON underneath.

**The concrete bar:** builder ≠ reviewer (mandatory everywhere), plus **at least one non-Anthropic-family adversarial pass** targeting: (a) secret/PII patterns embedded in raw `execution_trace`, confirming the leak-scan-and-redact path behaves as documented (a recall floor, not a zero-leak guarantee — §6.4) including for bundles with no `control_attestations_v040`; (b) fuzzed and deliberately-forged `verify_result`/`replay_result`/`verification_provenance` inputs, confirming the narrative composer never asserts an unsupported dimension status and never silently degrades on malformed input where it should fail loudly. One family, one focused pass — narrower than the ≥2-family gauntlet reserved for `gsa-verify.js`/`gsa-produce.js`/the MCP shim, because nothing here is a new trust primitive, but real enough to need a review pass built for these two specific risks rather than a generic UX pass.

---

## 8. Sizing

Roughly **one Wave-1-lane's worth of core-build effort — comparable to Lane A (the `AGENTS.md` reconciler)** — with a review bar one notch above what Wave 1 gets, per §7.

Two of the three main data sources (`verifyBundle()`, `replayBundle()`/`planDrift()`) are already built, tested, and documented — this design adds a CLI subcommand, a report schema, a narrative template composer, marker-occurrence scanning, and the skills-lens filter: composition and rendering over existing pure functions, not new algorithms. Genuinely new work: the JSON Schema and its own conformance vectors; the leak-scan-*substitution* step (detection is reused from `checks/v040-trace.js`, substitution-and-evidence-recording is not, per §6.4's fix); and the adversarial pass in §7.

---

## 9. Open questions for Paul

- Does `--diff` belong in v1, or is bundle-to-bundle drift a fast-follow? `planDrift` is already built either way.
- Should the redaction check reuse `checks/v040-trace.js`'s exact battery, or does excerpting need a wider pattern set given it's scanning arbitrary slices rather than a whole trace? Recommend starting with the exact existing battery, revisiting if the §7 adversarial pass finds gaps.
- Should this track get the same `CLAUDE-CODE-KICKOFF.md` + `WAVE-0-PROMPT.md` treatment v0.5.0 got before building starts? (See `CANONICAL-SOURCE.md` — recommended yes, not yet confirmed.)
