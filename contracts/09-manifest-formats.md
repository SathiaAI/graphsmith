# Contract 09 — Manifest Formats (I1 dual trust domains) + Adoption Log
Status: DRAFT. Two manifests, two claims (plan §2-I1): release manifest proves "release-verified"; project manifest proves "self-consistent." The sentinel reports WHICH it established, never a blended claim.

## Release manifest (`release.manifest.json`, ships inside the release artifact)
```json
{
  "schema_version": "1.0",
  "kind": "release",
  "release": "0.2.0",
  "algo": "sha256",
  "files": [ { "path": "scripts/gate.js", "sha256": "…" } ],
  "constitutional_set": [ "paths… (contract 00 list)" ],
  "tunables_bounds": { "<knob>": { "min": 0, "max": 0, "unit": "…", "semantics": "…" } },
  "created_by": { "ci_workflow": "…", "run_url": "…" }
}
```
Trust root: the package integrity chain that delivered the artifact (contract 05, assumption 1). Hashing rules: canonical repo-relative paths, forward slashes, case-folded compare, Unicode NFC, **normalized line endings (LF) before hashing** — Windows checkouts rewrite CRLF, so raw-byte hashes would false-alarm on every Windows machine (plan §3.1 canonicalization list; the cross-platform burn risk, plan §12).

## Project manifest (`.graphsmith/project.manifest.json`, generated at install/scaffold)
Same shape plus:
```json
{ "kind": "project", "generated_at": "…", "parent_release_sha256": "hash of release.manifest.json",
  "adoption_log_head": "sha256 of the latest adoption-log entry (the anchored head, F15)",
  "workflow_manifests": [ { "path": "…/workflow.manifest.json", "sha256": "…" } ] }
```
Updated ONLY by the promotion transaction (contract 01, VERIFIED→DONE) — the manifest head IS the CAS target.

## Workflow manifest (`workflow.manifest.json`, per scaffolded project — plan §3.6)
Frozen-file hashes (manager, routing, stop rules, intent guards, **tunables bounds**), loader policy, budget declarations (§7 set), adapter capability files (contract 06). Language: "separated for review and future tuning" — never "evolution-ready."

## Adoption log (`.graphsmith/adoption-log.jsonl`)
Hash-chained JSONL: each entry `{ schema_version, seq, txid, fingerprint, kind, evidence_ref, human: {name, decision, ts}, prev_sha256, entry_sha256 }`.
- Claim discipline: **rewrite-detecting relative to the anchored head** (head lives in the protected project manifest) — NEVER described as "immutable" (F15).
- Optional `graphsmith anchor export` emits the head for external anchoring (stronger claims are the USER'S to make).
- Verification: sentinel walks the chain from the anchored head; any break → evolvable-surface freeze domain (plan §5).

## Sentinel reporting (verify --integrity)
Output states exactly one of: `release-verified` (release manifest chain intact) / `self-consistent` (project manifest only) / the failure domain engaged. The circular-trust limit is printed on request (`--trust-model`): a privileged local attacker who rewrites sentinel + both manifests is out of scope (A6), stated in those words.
