# Contract 04 — Trust-Boundary Matrix (v2 — coverage extended; B1/B4 corrected)
Status: DRAFT v2 (post-panel-pass-1: GPT-16/17). Columns: artifact, trust, validation, trusted root, failure outcome (sentinel domain), race control.

| # | Boundary | Artifact | Trust | Validation | Trusted root | Failure outcome | Race control |
|---|---|---|---|---|---|---|---|
| B1 | Session resume | checkpoints | UNTRUSTED | JSON parse; corrupt → backup; **if the step has a recorded intent without completion, corruption routes to LOUD-HALT reconciliation — never silent re-run (GPT-16)**; otherwise re-run [KnoSky: scripts/scaffold.js:128-147] | manager | quarantine / HALT per above | per-run lease-lock [KnoSky: scripts/scaffold.js:64-113] |
| B2 | Appendix load | learned.md (via ACTIVE tree) | UNTRUSTED | token cap 1,500; delimiter wrap; subordination preamble; marker refusal | appendix loader (constitutional) | quarantine file; workflows continue | tree immutable; pointer read once at start |
| B3 | Prompt load | workers/*.prompt.md | UNTRUSTED data, trusted loader | size/encoding/NFC/canonical-path/delimiter | prompt loader | quarantine; missing prompt → refuse start | manifest hash pre-load |
| B4 | Harvest → compiler | run records | UNTRUSTED | typed events only (contract 07); **source authentication per event type; safety-relevant gaps invalidate the cycle (GPT-14/16)** | event-compiler | `harvest_invalid` — no proposals from partial evidence | compiler reads snapshots |
| B5 | Proposer → pipeline | candidates | UNTRUSTED | typed schema; fence; contradiction screen; R5 static screen; dedup | gate.js | reject + buffer | batch-before-scoring |
| B6 | Evaluation → adoption | Gate-2 evidence bundle | trusted iff produced by pinned evaluator under trusted process | bundle hash; evaluator pin | gate.js + manifest | evolvable-surface freeze | evaluator frozen per cycle |
| B7 | Gate 3 | packet + inverse | human-approved | plain-English; inverse pre-authorization | Paul | nothing applies | promotion lock |
| B8 | Manifest load | release + project manifests | TRUST ANCHORS (independent axes — contract 09) | integrity chain / self-consistency | sentinel | trusted-core defect → HALT | CAS on head |
| B9 | Adapter response | API results | UNTRUSTED | contract tests (F23); capability declaration = ASSUMPTION (contract 06) | manager | undeclared destination → tripwire HALT | allowlist post-redirect |
| B10 | §17 external tools / BYO tests | executable code + reports | UNTRUSTED CODE | **container profile REQUIRED for any untrusted executable (GPT-18); no container → tool reports "unavailable"**; report JSON schema-validated; report strings display-only, never control flow | assure runner | malformed → unavailable | subprocess caps |
| B11 | KnoSky index | city-data.json | UNTRUSTED pointers | read live file before edit [KnoSky: SKILL.md:38] | reading agent | re-index | rebuilt on demand |
| B12 | Model provider | LLM output | SEMI-TRUSTED (pinned) | version recorded; worker-only | manager | mid-cycle change invalidates cycle | — |
| B13 | Skill install | release artifact | via package integrity chain [KnoSky: scripts/knosky-sync.js, SKILL.md:36] | hash verify, refuse mismatch | installer | refuse | — |
| B14 | Candidate → evaluator | eval copy contents | UNTRUSTED | module-isolation (NODE_PATH, resolution check, symlink audit); secret-scrub; held-out access audit (empty access log required) | evalenv | candidate rejected + cycle audit | disposable copy per candidate |
| B15 | Promotion journal/state → live | journal, ACTIVE, staged trees | trusted (written only by promote.js under lock) | inspect-and-roll-forward recovery; owner-token lease | promote.js | HALT with evidence on unclassifiable state | contract 01 lock + CAS |
| B16 | Run ↔ window store | registration records | trusted (window-store only writer) | CAS on state_rev | window-store.js | refuse start during ROLLING_BACK | contract 02 CAS |
| B17 | Untrusted PR → CI | PR content | UNTRUSTED | trusted-workflow model: secrets & attestations only in trusted contexts; action pinned by SHA | CI config (constitutional) | fail check | GitHub trust model documented |
| B18 | Migration/upgrade → learned state | .graphsmith/ state | UNTRUSTED data | documented local API only; redaction test (F16) | migration API | refuse + backup | schema_version gate |
| B19 | Diagnostics export | report | leaves ONLY by human hand | preview + redaction; aggregate default; zero upload code (static-checked); "issue trackers are public" warning | diagnostics.js | — | — |
| B20 | Badge/evidence links | rendered badge | public claim | evidence-carrying semantics (§8.4); stale → downgrade; unprovable → unavailable | badge.js + CI run | never green without evidence | freshness check |
| B21 | Adoption-packet rendering | diff + explanation shown to human | derived from UNTRUSTED candidate | delimiter-wrapped quoting; candidate text clearly fenced as quoted material in the packet | gate3Prepare | — | packet hash recorded |
| B22 | Lab agent → scorer | left-behind workspace | UNTRUSTED (agent-controlled) | pristine out-of-workspace verifier + harness-owned ledgers (contract 12) | lab/score.js (pinned copy) | cell fails / unavailable | per-cell isolation |

**Standing rule (narrowed per GPT-16):** untrusted content is DATA; the SYNTACTIC controls above (typed views, opaque aliases, delimiters, subordination, closed enums) make directive text structurally inert on machine paths. Residual risk — semantically instruction-shaped content inside values a human or model still sees (e.g., quoted packet text) — is not claimed away; it is tested by the injection corpus (contract 12 Tier 2) and bounded by human-gated adoption.
