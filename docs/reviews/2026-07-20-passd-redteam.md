# GraphSmith v0.1.1 RC — Pass D Red-Team (Pre-Release Gate)

**Artifact:** `graphsmith-v0.1.1-rc-merged.tgz` extracted over a fresh clone of `SathiaAI/graphsmith` (public v0.1.0 @ `77a1ddf`).
**Method:** Execution-grounded adversarial review on Windows 11 Pro, Node v24.18.0. Every probe was *run*, not desk-reviewed; survived (resisted) attacks are recorded as evidence alongside broken ones.
**Scope:** the diff is the patch under review — **7 files with real content changes**: `README.md`, `SKILL.md`, `package.json`, `scripts/{chaos,graphlint,knosky-sync,scaffold}.js`. `install.js`, `references/*`, `.github/workflows/publish.yml`, `LICENSE`, `.gitignore` are **byte-identical to v0.1.0 modulo CRLF** (verified with `git diff --ignore-all-space`). Matches maintainer disposition §11.
**Constraints checked:** zero runtime deps ✓, one public skill ✓, Node 18+ cross-platform ✓, scaffold works with no API keys ✓. Propose-only; nothing applied, nothing pushed, no issues touched.

> ✅ **Rule-6 SATISFIED.** Executed by 1× Anthropic lead (Opus 4.8) + 2× Anthropic verifier subagents (Sonnet), **plus three non-Anthropic families via OpenRouter — OpenAI `gpt-5.1`, Google `gemini-2.5-pro`, DeepSeek `deepseek-r1`** — each given the code excerpts + executed evidence and asked to attack. Full participation and dissent in §5.
>
> **Correction (honesty note):** an earlier draft of this report wrongly declared Rule-6 unmet, concluding "non-Anthropic unreachable" from my Agent tool's model list alone. It was wrong — `OPENROUTER_API_KEY` was present in the environment the whole time (wrapped in literal `<...>` brackets, which broke the auth header until stripped). I asserted a limitation instead of verifying it against the live environment — exactly the failure mode CLAUDE.md's evidence rule warns against. The non-Anthropic panel was then run for real; its results (including a **unanimous dissent to HOLD**) are folded in below.

---

## 0. Release verdict

**Council verdict: HOLD** *(3 of 3 non-Anthropic families — gpt-5.1, gemini-2.5-pro, deepseek-r1 — unanimous).*
**Lead (Anthropic) dissents to: SHIP AFTER LISTED BLOCKERS.** Both positions preserved below; not averaged (Rule-6).

**Why the split.** The lead's execution shows the three named blockers (PD-1/2/5) are each individually cheap and the core discipline works under *process crash*. All three non-Anthropic families push back harder: they argue the flagship "a crash inside a send window **halts loudly** instead of silently re-sending" guarantee is **not delivered under realistic failure** — power loss (PD-1), and — newly surfaced by the panel — an at-least-once pattern with **no idempotency key actually wired** (gpt-5.1, PD-12) and **no run-level lock** (gemini, PD-13) — and that the "proof" chaos harness **structurally cannot test that class** (gpt-5.1, PD-14). Their shared conclusion: the PA-1 fix's *appearance* of exactly-once outruns what it delivers, so it should not ship as-is. DeepSeek: *"not patchable without redesign."* Given the framework pre-ranks false-assurance as Critical and the panel is unanimous on the reasoning, **the council verdict governs: HOLD until PD-1 + PD-12 + PD-14 are addressed (not just the doc blockers).**

The patch is nonetheless a genuine, substantial improvement: the flagship PA-1 double-send is closed for process crashes and honestly re-scoped; PA-2/PA-7/PA-9 are fully closed; the linter redesign (PA-4/5/6) works cross-file and cross-language with a self-test that has real teeth. Three items still violate the skill's own "relentless honesty about limitations" mandate and are each a small fix:

**Ship-blockers (all cheap):**
- **PD-1** — the write-ahead intent/effect logs are never `fsync`'d (only checkpoints are), so under the *exact power-loss threat model PA-2 was patched for*, the PA-1 double-send **re-opens** and the "halts loudly instead of silently re-sending" promise is falsified. (Independently reproduced twice.)
- **PD-2** — three shipped docs (`README.md:144`, `references/full-build-system.md:141`, `references/multi-agent-coordination.md:34`) still instruct the **unpinned `npx knosky .`** — the pre-patch PA-3 invocation Google called a "ship-stopper" — while the roadmap advertises "supply-chain pinning" as shipped. The script was hardened; the docs weren't.
- **PD-5** — `README.md:184` claims "**every council probe is now a regression test**." Only the 5 linter probes (E5–E7) are regression cases; E3/E4/E9/E10 are not, and CI (`publish.yml`) doesn't even run `--selftest`. A false-assurance claim of the exact class v0.1.0 shipped wrong.

Everything else is `fix-in-v0.1.2` or `accept-risk`. None of the remaining findings threaten the zero-dep / no-keys / one-skill / cross-platform constraints.

---

## 1. Findings table

Severity = reviewer-adopted. ▶ marks a command actually executed. Every finding was reproduced by ≥1 independent context; PD-1/3/4 reproduced by **two**.

| ID | Surface | Sev | Attack (▶ = executed) | File(s) | Proposed fix (propose, never apply) | Disposition |
|---|---|---|---|---|---|---|
| **PD-1** | A | **High** | ▶ Manager `fsync`s checkpoints but the worker stub's `intents.log`/`effects.log` use bare `appendFileSync` (no fsync). Simulate the on-disk state a power loss leaves (real effect fired to `ext.log`, intent line lost, no completion, no checkpoint) → `node manager.js run-Z` **completes with no halt, `ext.log` grows 1→2 — silent double-send.** SIGKILL does *not* trigger it (page cache survives) → power-loss/kernel-crash only. Re-opens PA-1 and falsifies the "halts loudly" claim (README:65). | `scripts/scaffold.js` (worker stub L170/172; manager L38-48) | fsync the log fd after each append (`openSync`+`writeSync`+`fsyncSync`+`close`), or write intent+completion as one fsync'd record. At minimum, extend the checkpoint power-loss caveat to the WAL and the "halts loudly" promise. | **ship-blocker** |
| **PD-2** | E/F | **High** | ▶ `grep -rniE "npx +(-y +)?knosky"` shows **unpinned** `npx knosky .` in `README.md:144`, `references/full-build-system.md:141`, `references/multi-agent-coordination.md:34`, while only `knosky-sync.js`/`SKILL.md` pin `@0.6.3`. Anyone following the docs literally reintroduces PA-3. Roadmap (README:184) claims "supply-chain pinning" shipped. | `README.md`, `references/full-build-system.md`, `references/multi-agent-coordination.md` | Pin every doc invocation to `npx knosky@<pin> .` or route all of them through `knosky-sync.js`. Reconcile the reference docs with the patched script. | **ship-blocker** |
| **PD-3** | C | **Medium** | ▶ chaos halt branch = `if ((out2+err2).includes("UNRESOLVED SIDE EFFECT")) { pass; exit 0 }` — it never verifies the halt is legitimate or that `effects.log` has no dupes. A guard-less worker that unconditionally re-sends then throws that string → across 12 chaos runs, **6 printed `SAFETY PASS` exit 0 with `ext.log` = 2** (a real double-send certified as safe). The "proof" on the halt path is a grep. | `scripts/chaos.js` (L66-76) | On the halt path, assert intent-without-completion actually holds in the run dir **and** run the `effects.log` dedup check before declaring a pass; don't key the verdict on a string. | fix-in-v0.1.2 |
| **PD-4** | D | **Medium** | ▶ Linter never strips comments/strings. `while(true)` in a `//` comment and in a `"string literal"` inside an LLM-reachable file each fire **HIGH R1** (`node graphlint.js c_comment` / `c_string`). Ships live in the corpus: `node graphlint.js tests/lint-corpus` flags **`e6a-unbounded-condition.js:1`** (a header comment). `--selftest` is blind — dirty corpus files have `mustFind` but no `mustBeCleanAtOrAbove`. This is the FP class a parent build reportedly had; the merge is **not** immune. | `scripts/graphlint.js`, `tests/lint-corpus/expected.json` | Strip line/block comments and string literals before matching (or skip comment-only lines); add precision assertions to the dirty corpus files so the FP can't ship green. | fix-in-v0.1.2 |
| **PD-5** | F | **Medium** | ▶ `README.md:184` "every council probe is now a regression test." `expected.json` note scopes regression cases to **E5–E7 only**; E3/E4/E9/E10 have no automated test. ▶ `publish.yml` runs only `npm publish` — no `--selftest`/chaos gate, so "fails on any precision/recall regression" (README:153) is enforced only if a human runs it locally. | `README.md`, `.github/workflows/publish.yml` | Scope the claim to the linter probes; wire `graphlint.js --selftest` (and ideally a scaffold+chaos smoke) into the release workflow so the claim becomes true. | **ship-blocker** (claim) |
| **PD-6** | D | Low | ▶ Unbounded LLM loops via `setInterval` and recursion produce **zero R1** (`node graphlint.js c_interval` / `c_recursion`). Recursion **is** disclosed in the blind-spots header; **`setInterval`/`setTimeout`/`process.nextTick` are not** (grep: absent from the file entirely). | `scripts/graphlint.js` (header L18-22) | Add a timer-callback heuristic, or at minimum add timer-driven loops to the documented blind-spots list. | fix-in-v0.1.2 |
| **PD-7** | A/B | Low | ▶ `intents.log`/`effects.log` are separate, unpaired, un-fsync'd writes → a power loss can leave them inconsistent, causing a **spurious HALT** on an otherwise auto-resumable run (`rm effects.log; keep intents.log` → every intended step halts). ▶ `.corrupt-<ms>` backups accumulate unbounded (3 corruptions → 3 files, never cleaned). *(gemini)* `intents.log`/`effects.log` are append-only, never rotated/truncated → unbounded disk growth for long-running/frequently-reused runs. | `scripts/scaffold.js` | Pair the two records durably (or derive one from the other); prune/cap `.corrupt-*` backups; rotate or compact the logs. | fix-in-v0.1.2 |
| **PD-8** | A | Low | ▶ Duplicate step names in `pipeline.json` (`[{"step":"01-x"...},{"step":"01-x"...}]`) → the **second step is silently skipped** (shared checkpoint/effects name) and the run reports `complete` (exit 0) having never run it. ▶ A newline in a step name crashes the manager (exit 1). No step-name validation. | `scripts/scaffold.js` (manager) | Validate step names unique + filesystem-safe at manager start; fail loudly on collision. | fix-in-v0.1.2 |
| **PD-9** | E | Low | ▶ `if (process.env.GRAPHSMITH_OFFLINE)` is a truthy check — `GRAPHSMITH_OFFLINE=0 node knosky-sync.js` **still forces offline** ("0" is truthy in JS). A user setting `=0` to disable offline gets the opposite. | `scripts/knosky-sync.js:24` | Check explicitly for `"1"`/`"true"`. | fix-in-v0.1.2 |
| **PD-10** | E | Medium | Static: pinned `npx knosky@0.6.3` carries **no integrity hash/lockfile** — a republished/compromised 0.6.3 tarball still executes. The **default (non-offline) path auto-downloads+executes** third-party `knosky` every Phase-0 with the agent's permissions. Per the task's own observation, `npx knosky@0.6.3 --version` writes `.knosky/` to cwd — a side effect of the *readiness check*. None of this residual is disclosed; "no data leaves your machine from the skill's scripts" (README:169) is imprecise given the npm/npx network calls. *(Assessed by code-path + provided observation; the untrusted package was deliberately NOT executed.)* | `scripts/knosky-sync.js`, `README.md`, `SKILL.md` | State the residual: pin ≠ integrity; the default path executes remote code; offer/set an integrity or `--package-lock` path; note the `.knosky/` side effect; soften the absolute "nothing leaves the machine" wording. | accept-risk (disclose) |
| **PD-11** | D | Low | ▶ `node graphlint.js path/to/file.js` scans the **whole parent directory**, not the file (`collectFiles` uses `path.dirname` for a file arg). Confusing sibling findings + `..\other.js` relative paths. | `scripts/graphlint.js:49-60` | When given a file, lint only that file. | accept-risk |
| **PD-12** | A/F | **Medium** | *(gpt-5.1)* The stub comment promises "idempotency key: `runId+":"+step`" but the scaffold **never wires or exposes it** — the pattern is at-least-once, not "no double-send," even with fsync. Combined with PD-1 this means the flagship guarantee is undelivered in the general case, not just an edge case. | `scripts/scaffold.js` (worker stub) | Actually thread `runId+":"+step` into a dedupe hook (or a clearly-marked TODO the harness checks), and scope the README no-double-send claim to "recorded effects" only. | fix-in-v0.1.2 |
| **PD-13** | A | Low–Med | *(gemini)* **No run-level lock** on `.runs/<id>`. Two managers on the *same explicit* runId is a latent TOCTOU: both `readLines` "not done," both fire. PA-7 only prevents *default-id* collision, not concurrent same-id execution. ▶ Reviewer could **not** reproduce in 60 concurrent attempts (Node ~80ms startup jitter serializes writes; the intent log then halts the losers) — so **architecturally real, low practical exploitability** across separate processes; higher in-process or on a loaded host. | `scripts/scaffold.js` (manager) | Take an exclusive lock (e.g. `wx` lockfile) on `.runs/<id>` at manager start; refuse concurrent same-run execution. | accept-risk (PLAUSIBLE) |
| **PD-14** | C | **Medium** | *(gpt-5.1)* The chaos harness only SIGKILLs a live process; it **cannot simulate delayed/unflushed writes**, so it structurally **can never exercise the PD-1 power-loss class** — the exact failure that breaks the flagship claim. "Proof" covers only the failure modes it can stage. | `scripts/chaos.js` | State the harness's fault-model limits explicitly (process-crash only, not power-loss/flush-lag); don't let a green imply power-loss safety. | fix-in-v0.1.2 |
| **PD-15** | D | Low | *(gpt-5.1 + gemini)* `CLOCK_DICE` requires a routing keyword within **3 lines**, so hoisting defeats it: `const r = Math.random(); /* many lines */ if (r>0.5) llm()`. Non-deterministic routing via a helper feeding a router elsewhere is a false-negative class the rule claims to catch. | `scripts/graphlint.js:121-124` | Track clock/random values to their use in a branch (data-flow), or widen/disclose the window limit. | fix-in-v0.1.2 |

**Resisted attacks (survived → the fix works):** PA-1 core double-send under SIGKILL (loud halt, no dup); PA-2 truncated/0-byte checkpoint recovery; PA-7 runId entropy; PA-9 degenerate detection; the merge-seam string coupling; the `shell:win32` injection surface; `GRAPHSMITH_OFFLINE=1` zero-network; `.tmp` leftover handling; 2-hop transitive LLM reachability; full Python parity. Detailed in §2.

---

## 2. Execution log (everything run — resisted and broken)

Environment: Windows 11 Pro, Node v24.18.0, Git Bash. Scaffolded projects live in the session scratchpad; **no file under `graphsmith-rc` was modified.**

**Static / syntax**
- ▶ `node --check` on all 5 scripts + 9 corpus files → **all OK**.
- ▶ `git diff --ignore-all-space --stat` → real content changes in exactly 7 files; references/install/workflow/LICENSE whitespace-only (no hidden doc reverts — reference docs are byte-identical to v0.1.0).

**Linter (PA-4/5/6, surface D)**
- ▶ `node graphlint.js --selftest` → **recall 4/4, precision 4/4, exit 0**. RESISTED.
- ▶ `node graphlint.js tests/lint-corpus` → 6 findings incl. **`e6a:1` (comment) HIGH R1 false positive** (PD-4). BROKEN.
- ▶ Selftest teeth: mirrored linter to scratch, planted a **precision** regression (removed `FRAMEWORK_RESP` exclusion) → `e7` FP → **exit 1**; planted a **recall** regression (neutralized both loop regexes) → e6a/e6b miss → **exit 1**. Selftest genuinely fails on planted regressions. RESISTED.
- ▶ Comment `while(true)` (`c_comment`) → HIGH R1 FP. String literal `while(true)` (`c_string`) → HIGH R1 FP. Clock-in-comment (`c_clockcomment`) → R4 REVIEW FP. BROKEN (PD-4).
- ▶ `setInterval` LLM loop (`c_interval`) and recursion (`c_recursion`) → 0 R1. FN (PD-6). Blind-spots header discloses recursion, **not** timer loops.
- ▶ 2-hop transitive reachability (manager→mid→worker[LLM], loop in manager) → **`manager.js:2` HIGH R1 "via imported worker."** RESISTED (fix robust to depth).
- ▶ Dynamic `require(variable)` → missed; **disclosed** blind spot (fair).
- ▶ Python parity (subagent B): `while not done:`+LLM → R1; `while True:` → R1; `time.time()`+`if x%2` → R4; unkeyed `requests.post(.../charge)` → R3; **cross-file `from worker import step` → R1 "(via imported worker)"**; `for i in range(3):` clean → no R1. **No Python false negative.** RESISTED.

**Scaffold + run + resume (surface A/B)**
- ▶ `scaffold.js proj` → manager/pipeline/workers/README generated. `node manager.js run-A` → 3 steps ok + `__done__`; re-run → all "skipped (checkpoint exists)". RESISTED (idempotent resume).
- ▶ **E3 double-send:** real effect (`emails_sent.log`) placed in the write-ahead window; SIGKILL between send and completion. Resume → **loud `UNRESOLVED SIDE EFFECT`, exit 1, emails stay at 1.** No silent re-send. **PA-1 CLOSED** for process crash.
- ▶ Both README remediation paths: "it DID happen" (append to `effects.log`) → completes, emails stay 1; "it did NOT" (delete intent line) → re-sends (2→3). Both behave exactly as documented. RESISTED.
- ▶ **PD-1 power-loss double-send:** simulated post-power-loss state (intent lost, effect fired, no completion/checkpoint) → resume **completes silently, emails 1→2.** BROKEN. Independently reproduced by subagent A (`ext.log` 1→2, no halt). SIGKILL proven not to trigger it (page cache survives).
- ▶ **E4a** truncated checkpoint (`{"01-gather":"do`) → backed up `.corrupt-<ms>`, re-runs, exit 0. **E4b** 0-byte checkpoint → same. **PA-2 CLOSED** (no permanent brick).
- ▶ `.tmp` leftover from a mid-write crash → ignored on resume (checked against final name), never mistaken for a checkpoint. RESISTED.
- ▶ `.corrupt-*` accumulation: 3 corruptions → 3 backups, uncleaned (PD-7). chaos `checkpoints()` correctly excludes `.corrupt-*` and `.tmp` (neither ends in `.json`). RESISTED (miscount) / minor (accumulation).
- ▶ Delete `effects.log` keep `intents.log` → spurious HALT on every step (PD-7). Duplicate step names → 2nd silently skipped (PD-8). Newline step name → crash (PD-8).

**Chaos harness (PA-9 + merge seam, surface C)**
- ▶ chaos ×8 on the stub → **8/8 ALL CHECKS PASSED**, kill landed 1/3 mid-flight. Not hollow (kill genuinely interrupts; run 2 completes correctly). The stub writes intent+effect back-to-back *before* its 300ms sleep, so the halt path is essentially never exercised by the default stub (noted, low).
- ▶ **PA-9 degenerate:** single-step instant worker (run finishes before kill) → **"Degenerate run… nothing was interrupted"**, exit 1, ×4. **PA-9 CLOSED** (no hollow green).
- ▶ **PD-3 SAFETY-PASS gaming:** guard-less worker that re-sends + throws the magic string → 12 chaos runs, **6 × `SAFETY PASS` exit 0 with `ext.log`=2** (certified double-send). BROKEN. Independently reproduced by subagent A.
- ▶ Merge-seam strings: resume log line `{"...","step":"01-gather","status":"skipped (checkpoint exists)",...}` matches chaos grep `"step":"X","status":"skipped`; halt error text matches `"UNRESOLVED SIDE EFFECT"`. Confirmed end-to-end through both the `SAFETY PASS` and `ALL CHECKS PASSED` paths. RESISTED (coupling holds).
- ▶ Windowed real effect via chaos → both `SAFETY PASS` (kill in window) and `ALL CHECKS PASSED` (kill outside) keep `ext.log`=1 under SIGKILL (guard holds); verdict is timing-dependent but both are legitimate passes.

**Supply chain (PA-3, surface E)**
- ▶ `GRAPHSMITH_OFFLINE=1 node knosky-sync.js` → prints skip, exit 0, **no `.knosky/` created, no npx/npm call** (offline block exits before any `tryRun`). "skips all network" VERIFIED.
- ▶ `GRAPHSMITH_OFFLINE=0 …` → **also offline** (truthy `"0"`, PD-9).
- ▶ Data-flow: `PIN="0.6.3"` is a literal; every `execFileSync` arg is a compile-time constant; the only external value (`latest` from `npm view`) is used **only** in a regex + `console.log`, never passed to exec → **no injection**, incl. the `shell:win32` branch. RESISTED. (The untrusted `knosky` package itself was deliberately not executed — PD-10 assessed statically.)
- ▶ `grep` across all docs → unpinned `npx knosky .` in 3 docs (PD-2); `publish.yml` = `npm publish` only, no selftest gate (PD-5).

**Reference-doc audit (subagent B, surface F)**
- ▶ `git show HEAD:references/*` vs RC → all three reference docs byte-identical to v0.1.0 (no reverts — but also **not updated** to match the patched script, root of PD-2). `graduation.md` claim "checkpoint read/write isolated in `executeStep`" VERIFIED against the generated manager; rung-4 "exactly-once" correctly scoped to external engines (no overclaim). KnoSky MCP tool-name list in the docs is an **unverified assumption** (package existence confirmed by council E9; MCP surface untested here).

---

## 3. Regression verdict (surface G) — per original council finding

| Finding | Verdict | Evidence |
|---|---|---|
| **PA-1** (false exactly-once / double-send) | **PARTIALLY CLOSED** | Flagship double-send **closed for process crash** (E3: loud halt, emails stay 1) and docs honestly re-scoped (README:65/119/166, SKILL:89-92). **Residual PD-1:** un-fsync'd WAL re-opens the double-send under power loss and falsifies "halts loudly." Docs class largely fixed; durability class not. |
| **PA-2** (corrupt checkpoint brick) | **CLOSED** | E4a/E4b: truncated + 0-byte checkpoints back up and re-run (exit 0). `fsyncSync` before `rename` verified in code (scaffold L45). |
| **PA-3** (supply chain) | **PARTIALLY CLOSED** | Script hardened: pinned `@0.6.3`, no global install, no shell interpolation, offline flag (VERIFIED). **But** 3 docs still show unpinned `npx knosky .` (PD-2), no integrity hash + default auto-execute undisclosed (PD-10). |
| **PA-4** (dead R4 clock rule) | **CLOSED** | R4 fires on `Date.now()`/`time.time()` near control flow in JS **and** Python (E5 + Python case 3); duration-math correctly excluded. Caveat: comment-text R4 FP (PD-4). |
| **PA-5** (linter false negatives) | **CLOSED** | Cross-file manager/worker caught (2-hop + Python `from x import y`); `while(!done)` caught; `existsSync`-only no longer silences an unkeyed charge (E6a/b/c + Python). |
| **PA-6** (linter false positives) | **CLOSED w/ new regression** | Original cases fixed: clean Express file → 0 MEDIUM+ (E7 precision passes). **New FP class introduced:** comments/strings (PD-4). |
| **PA-7** (runId collision) | **CLOSED** | 3 concurrent default-id managers → 3 distinct `run-<ms>-<entropy>` dirs. |
| **PA-9** (hollow green) | **CLOSED** | Degenerate detection fires (exit 1) when a run finishes before the kill. |
| **PA-8** (stale file survives `--force`) | **Correctly NOT claimed fixed** | `install.js` unchanged (overlay copy); roadmap lists only linter/exactly-once/checkpoints/supply-chain as shipped. No silent overclaim. Remains fix-later as dispositioned. |

---

## 4. Merge-seam report (two-build provenance)

The RC merges two independent implementations (prior Claude Code session + Claude.ai session). Seam-attributable findings:

- **String coupling — HOLDS (good news).** The two contracts that cross build boundaries — chaos's grep for `"step":"X","status":"skipped` and for `"UNRESOLVED SIDE EFFECT"` — both match the scaffold's actual output in every path (resume, `SAFETY PASS`, `ALL CHECKS PASSED`). The #1 predicted merge risk did **not** materialize. Residual fragility: the skipped-line match depends on `JSON.stringify` key order (`runId,step,status,ms`); both come from one scaffold source, so it's safe today but brittle to any future reorder.
- **Durability model not unified (PD-1).** One build added checkpoint `fsync` (the PA-2 response); the other added the write-ahead intent pattern (the PA-1 response). The merge shipped both but **did not reconcile their durability guarantees** — checkpoints are power-loss-durable, the WAL they cooperate with is not. This asymmetry is the seam that re-opens the flagship bug.
- **Code fixed, docs not (PD-2).** `knosky-sync.js` was rewritten to pin the version; the reference docs that duplicate the invocation were left untouched (byte-identical to v0.1.0). The supply-chain fix landed in one surface and not the parallel documentation surface — a classic merge gap. The roadmap's "supply-chain pinning shipped" reads the script, not the docs.
- **No reverted doc claims.** The specific hazard "reverted doc claims" did **not** occur; the reference docs are unchanged, not reverted. The problem is staleness, not reversion.

---

## 5. Dissent log + participation record

### Participation (Pass D)
| Context | Model (family) | Role | Contributed |
|---|---|---|---|
| Lead | **Claude Opus 4.8 (1M)** — *Anthropic* | Executed full probe battery A–G | PA-1..PA-9 regression evidence; PD-1..PD-11; merge-seam; claim audit |
| Verifier A | **Claude Sonnet** — *Anthropic* | Adversarial refutation of top findings | Independently CONFIRMED PD-1/3/4; sharpened PD-6 |
| Coverage B | **Claude Sonnet** — *Anthropic* | Python parity + reference-doc audit | PD-2; Python no-FN result; graduation.md verification |
| Panelist | **OpenAI `gpt-5.1`** — *non-Anthropic* | Adversarial review of code + evidence | **PD-12** (idempotency key never wired); **PD-14** (harness can't test flush-lag); PA-9 guard doesn't assert an unresolved intent occurred; npx-is-itself-an-unpinned-bootstrap; verdict **HOLD** |
| Panelist | **Google `gemini-2.5-pro`** — *non-Anthropic* | Adversarial review of code + evidence | **PD-13** (no run-level lock / TOCTOU); unbounded log growth (→PD-7); PD-15 hoisting; PD-5→High; verdict **HOLD** |
| Panelist | **DeepSeek `deepseek-r1`** — *non-Anthropic* | Adversarial review of code + evidence | PD-3→High ("silent data corruption"); atomic-fsync-both-logs; PD-6 setTimeout FN; "not patchable without redesign"; verdict **HOLD** |

**Rule-6 status: MET** — 3 non-Anthropic families participated (via OpenRouter; connectivity verified with a live call before the substantive prompt). See the honesty-correction note at the top: an earlier draft wrongly declared this unmet. A **zero-finding review is invalid** per the framework; this pass surfaced **15 findings** (2 High + the panel's additions), all execution-grounded or code-cited.

### Dissent (preserved, not averaged)
- **Release verdict — the core disagreement.** **All three non-Anthropic families independently returned HOLD**, not ship-after-blockers. Their shared reason: the flagship "halts loudly / no silent re-send" guarantee is not delivered under realistic failure (PD-1 power loss + PD-12 no idempotency wiring + PD-13 no lock), and the chaos harness structurally can't test that class (PD-14) — so the *appearance* of exactly-once outruns delivery. DeepSeek: *"not patchable without redesign… ship-blocker severity underestimated."* gpt-5.1: *"the flagship PA-1 fix is not actually delivered."* gemini: *"the design itself is flawed,"* citing its TOCTOU race. **The lead (Anthropic) dissents:** under executed evidence the three named blockers are each cheap (fsync the WAL; pin 3 doc lines; fix one sentence + wire CI), the core works under process crash (E3), and PD-13's race could **not** be reproduced in 60 concurrent attempts. **Not averaged: the council verdict (HOLD) governs the headline; the lead's SHIP-AFTER-BLOCKERS position is recorded as the minority view.**
- **PD-1 severity — converged up.** Verifier A narrowed it to power-loss/kernel-crash only (SIGKILL provably preserves the append). All three non-Anthropic families nonetheless rated it High/ship-blocker and tied it to the flagship claim. Adopted High.
- **PD-13 (gemini's TOCTOU) — scoped down by execution.** Gemini rated the concurrent-same-runId race a design-invalidating flaw. Lead execution: not reproducible across separate `node` processes (startup jitter + the intent log serialize/halt the losers). Recorded as **PLAUSIBLE / architecturally real, low practical exploitability** — dissent preserved with the counter-evidence, neither side erased.
- **gemini offline-mode claim — REFUTED by execution.** Gemini asserted the `execFileSync` warm-up runs *before* the `GRAPHSMITH_OFFLINE` check. False: the offline `process.exit(0)` is at knosky-sync.js:27, the network call at :30; `GRAPHSMITH_OFFLINE=1` was executed and made zero calls / created no `.knosky/`. Model claim recorded and corrected.
- **deepseek "double-send without power loss" — REFUTED by execution.** DeepSeek claimed a crash after the effect but before the `effects.log` write double-sends with no power loss needed. Under SIGKILL it does **not** — the intent log (written first) is preserved, so resume HALTS (proven in E3). It collapses into PD-1 only when the intent write itself is lost (power loss). Recorded and corrected.
- **PD-3 / PD-5 severity — panel pushed up.** gpt-5.1 and deepseek up-scoped PD-3 (Med→High: "enables silent data corruption"); gemini up-scoped PD-5 to High ("critical failure of process transparency"). Lead held PD-3 at Medium (requires a non-compliant worker) and PD-5 at Medium-with-ship-blocker-on-the-claim. Disagreement preserved.
- **PD-6 — narrowed by Verifier A:** recursion IS disclosed; only `setInterval`/timer loops are undisclosed. deepseek independently flagged the same `setTimeout` gap.

*Convergence note: the non-Anthropic panel did NOT rubber-stamp — it split from the lead on the headline verdict (HOLD vs ship-after-blockers), up-scoped two severities, and added four findings the lead missed; the lead in turn refuted two of the panel's claims with execution. This is genuine cross-family disagreement, which the framework treats as a sign of a real review rather than a manufactured consensus.*

---

## 6. Bottom line

v0.1.1 does what a patch built on "proof, not promises" should: it closes the flagship double-send for the common (process-crash) case, honestly re-scopes the exactly-once language, kills the permanent-brick and runId-collision bugs, and rebuilds the linter into something that genuinely catches the cross-file split it advertises — with a self-test that fails on planted regressions. It is close to shippable.

Where the lead and the non-Anthropic council part ways is instructive. The lead, from executed evidence, sees three cheap honesty fixes standing between the RC and a ship: the un-fsync'd write-ahead log that re-opens the flagship bug under the very power-loss model the patch elsewhere defends against (**PD-1**), the three docs that still hand users the retired supply-chain invocation (**PD-2**), and the "every council probe is now a regression test" overclaim the corpus and CI don't back (**PD-5**).

All three non-Anthropic families (gpt-5.1, gemini-2.5-pro, deepseek-r1) go further and say **HOLD** — because PD-1 is not alone: the idempotency key the pattern advertises is **never wired** (PD-12), there is **no run-level lock** (PD-13), and the "proof" harness **cannot even stage** the power-loss failure that breaks the claim (PD-14). Their point is that the flagship promise — *halts loudly instead of silently re-sending* — is an appearance the current code cannot fully cash, and appearances of safety are the one thing this skill exists to refuse. That is a strong argument and it governs the headline verdict.

The reconciliation is narrow: PD-1 + PD-12 + PD-14 must be closed together (durably record the write-ahead log **and** actually wire/scope the idempotency guard **and** state the harness's fault-model limits) so the no-double-send claim becomes true rather than plausible — then the doc fixes (PD-2/PD-5) clear the remaining false-assurance, and the rest ride to v0.1.2. Under that bar the disagreement dissolves: the lead's "cheap fixes" and the council's "don't ship the appearance" describe the same required work.

*End of Pass D. Rule-6 met (3 non-Anthropic families). No RC files modified; nothing pushed; no issues touched. Adoption decisions are the maintainer's.*

---

## 7. Maintainer disposition (appended post-review, 2026-07-20)

**The council's HOLD is adopted — and its bar is exceeded.** Rather than shipping the three "cheap blockers" of the lead's minority position, the respin addresses **all fifteen findings**: twelve fixed outright, three bounded by *stated, disclosed principle* (log rotation → graduation-ladder trigger; cross-file data-flow → the zero-dependency auditability constraint, named in the linter's blind-spots header; air-gapped supply-chain verification → the v0.2.0 regulated-industries extension). No claim was softened to avoid work.

Key closures, each with an executable probe now in the permanent battery:
- **PD-1/PD-12/PD-14 (the flagship chain):** the write-ahead intent/effect logs are fsync'd, making the power-loss failure mode *become* the designed halt; the `idempotencyKey` (`runId:step`) is a real wired variable in every stub; the chaos harness stages the lost-flush state and proves the halt — the failure class the council said the harness "structurally cannot test" is now a standing test. DeepSeek's "not patchable without redesign" is answered by construction: fsync-before-effect makes lost-intent-with-fired-effect impossible, so the architecture was one durability guarantee short, not wrong.
- **PD-3:** a SAFETY PASS is earned by on-disk intent/effect state and a dedup check, never by a string. Both the council's gaming worker and a log-forging variant now FAIL (6/6 and 4/4 in verification).
- **PD-13:** per-run lock with pid-liveness staleness (the coordination layer's own claim-with-a-lease rule, applied to the manager); concurrent-refuse and stale-steal are chaos probes.
- **PD-4:** comment/string sanitization with line-number preservation; the corpus gained line-pinned, max-count assertions so a comment FP can never again pass the selftest (mutation-tested: a planted regression exits 1).
- **PD-2/PD-5:** every doc invocation pinned; the regression claim rewritten to what is true; a CI workflow (Linux+Windows, Node 18+22) runs selftest + dogfood + scaffold + chaos on every push, and npm publish is gated behind it.
- **PD-10:** content-integrity pin — the sha512 of the reviewed knosky tarball is baked in and verified before any execution is recommended (refuse-on-mismatch, tested); residuals disclosed in README.
- **PD-6/PD-15:** `setInterval` loops detected; same-file clock/random value tracking catches the hoisted-randomness attack (duration math excluded — timeouts are stop rules); remaining gaps named in the blind-spots header.
- **PD-7/PD-8/PD-9/PD-11:** corrupt-backup cap (3), step-name validation (duplicate/unsafe names fail at start), strict `GRAPHSMITH_OFFLINE` parsing, single-file lint mode.

The respin was verified against every executed repro in §2 of this report before being resubmitted to the council for Pass E.
