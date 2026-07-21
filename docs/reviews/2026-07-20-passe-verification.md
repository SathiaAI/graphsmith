# GraphSmith v0.1.1 RC2 — Pass E Verification

**Mission:** verify that each of Pass D's fifteen findings (PD-1…PD-15) is genuinely closed or honestly bounded in RC2, and attack the fixes themselves. Narrower than a red team; the anchor is the maintainer disposition in `docs/reviews/2026-07-20-passd-redteam.md` §7 — every claim there is what is being tested.
**Method:** execution-grounded on Windows 11 / Node v24.18.0 (the lock + fsync paths are Windows-sensitive — tested here). Every ▶ was run. RC2 was read, executed, and attacked; nothing modified, nothing pushed.
**Artifact:** `F:\Users\PaulPoulose\GraphSmith\graphsmith-v0.1.1-rc2` (has the §7 disposition, `ci.yml`, new corpus e8a/e8b/e8c). The 4 changed scripts + corpus + README/SKILL + CI are the patch under review.

> **Rule-6 SATISFIED** — the three families that authored the Pass D HOLD judged RC2: OpenAI `gpt-5.1`, Google `gemini-2.5-pro`, DeepSeek `deepseek-r1` (via OpenRouter). **Split verdict, dissent preserved (§4): 1 SHIP, 2 HOLD — both HOLDs on a *different* newly-introduced Low residual, each a one-line fix.** No family disputes that the original 15 are substantively closed.

---

## 0. Release verdict

**Council verdict: SHIP AFTER LISTED BLOCKERS.** The two blockers are the exact residuals the two HOLD voters named, and both are one-line honesty fixes:
- **PE-1** — the linter's PD-4 fix states "rules must never fire on string literals," but a **multi-line template literal** still false-positives HIGH R1. Either handle multi-line backtick strings in the sanitizer, or add them to the blind-spots header (currently undisclosed). *(gemini's blocker.)*
- **PE-3** — `chaos.js:72` comment claims "a worker that re-sends and then throws the magic string **must FAIL here**," but a worker that leaves a real unresolved intent AND re-sends externally gets SAFETY PASS (ext=2, 6/6). The mechanism is within the disclosed "recorded-effects-only" scope; the **comment overstates it** and must be corrected to match. *(deepseek's blocker.)*

**Per family:** gpt-5.1 = **SHIP** (residuals fail-safe, none reopens a safety hole); gemini-2.5-pro = **HOLD on PE-1**; deepseek-r1 = **HOLD on PE-3**. **Lead (Opus)** concurs with SHIP-AFTER-LISTED-BLOCKERS: RC2 genuinely answers Pass D's HOLD — the flagship power-loss double-send, the string-gamed safety pass, the missing lock, and the missing CI gate are all closed and re-verified — but by the skill's own zero-false-assurance standard, the two comment/disclosure gaps the dissenters caught should close first. They are ~2 lines total.

**This is the strongest signal the process produces and it is earned by execution:** the same three non-Anthropic families that held RC1 now agree every substantive Pass D defect is fixed; they withhold an unconditional SHIP only over two honesty-of-wording residuals, not over any reopened risk.

---

## 1. Verdict table (PD-1 … PD-15)

| PD | Verdict | Re-run repro / fix-attack (▶ executed) |
|---|---|---|
| **PD-1** WAL not durable → power-loss double-send | **CLOSED** | ▶ Worker now uses `appendDurable()` = `openSync(a)+writeSync+fsyncSync+close` per intent/effect line (verified in code, scaffold.js:212-215/232/238); intent fsync'd *before* the effect. ▶ Real effect in the send→record window + SIGKILL → resume **HALTS, emails stay 1**. ▶ chaos **power-loss probe** stages intent-without-completion and the manager HALTS (passes on Windows). Residual: torn partial WAL line — README discloses "disk corruption beyond torn writes" not covered. |
| **PD-2** unpinned `npx knosky` in 3 docs | **CLOSED** | ▶ `grep -rniE "npx.*knosky"` across README/SKILL/references → **0 unpinned**; all `knosky@0.6.3`. |
| **PD-3** SAFETY PASS = bare string grep | **CLOSED (disclosed residual → PE-3)** | ▶ Halt now verified against on-disk `intents/effects`: requires ≥1 unresolved intent, fails on any effects dup. ▶ Pass D gaming worker **FAILS 4/4**; log-forging worker **FAILS 3/3** ("halt string without halt state"). ▶ Residual: real-unresolved-intent + unguarded external re-send → SAFETY PASS ext=2 (6/6) — disclosed recorded-only scope; comment overstates (PE-3). |
| **PD-4** linter FP on loop/clock in comments/strings | **CLOSED (new gap → PE-1)** | ▶ Two-view sanitizer (bareLines blanks comment+string contents, line-preserving). ▶ selftest green; e6a fires only R1@5 (not comment L1); e8a immunity file = 0 findings. ▶ Mutation test: break sanitizer → **selftest exits 1** (e6a 2×>max1; e8a precision fails). ▶ Clean on URLs, `//`-in-strings, escaped quotes, Python triple-quotes, duration-math. ▶ **New gap PE-1:** multi-line template literal → HIGH R1 FP. |
| **PD-5** "every probe a regression test" + no CI gate | **CLOSED** | ▶ Roadmap claim rewritten to an accurate Pass-D-HOLD account (README:184-185). ▶ `ci.yml` = syntax+selftest+dogfood+scaffold+resume+chaos on **[ubuntu,windows]×[node18,22]**; `publish.yml` publish `needs: verify` which `uses: ./ci.yml` → publish is gated. |
| **PD-6** setInterval loop FN | **CLOSED** | ▶ `setInterval` added to R1; e8b → **R1@5**. setTimeout-recursion remains a **disclosed** blind spot (header L21). |
| **PD-7** unbounded `.corrupt-*` backups / log growth | **CLOSED / BOUNDED-AS-DISCLOSED** | ▶ 5 corruptions → **capped at 3** backups. Log rotation deliberately excluded → disclosed (README:171, graduation ladder). |
| **PD-8** duplicate/unsafe step names silently skip | **CLOSED** | ▶ Duplicate → exit 1 "each step needs its own checkpoint"; `a/b` → exit 1 "Invalid step name". Validated at start. |
| **PD-9** `GRAPHSMITH_OFFLINE=0` still offline | **CLOSED** | ▶ Strict parse `["1","true","yes"]`: "0"/"false"/"no"/""/"2" → not offline; "1"/"true"/"yes" → offline. |
| **PD-10** pinned npx, no integrity | **CLOSED (residual disclosed)** | ▶ Baked sha512 **exactly matches** live registry hash for knosky@0.6.3. ▶ Tampered baked hash → **INTEGRITY MISMATCH exit 1, no npx execution**. Unreachable → "unverified" (no false "verified"). Registry-trusting residual disclosed in-code + README:171. |
| **PD-11** `graphlint <file>` scans whole dir | **CLOSED** | ▶ `graphlint <file>` → "Scanned 1 files". |
| **PD-12** idempotency key never wired | **CLOSED** | ▶ `const idempotencyKey = ctx.runId+":"+ctx.step` is a live variable in every stub (scaffold.js:234) with a comment to pass it to the real call; README claim matches. (Still the user's job to pass it into their API call — inherent to a stub.) |
| **PD-13** no run lock → concurrent double-fire | **CLOSED (residual → PE-2)** | ▶ SIGKILL mid-run leaves `.lock` → next run **"stale lock… stolen"**, resumes, completes, releases on exit. ▶ Two concurrent stealers of a stale lock → **exactly one runs (ext=1)**. ▶ Live holder → 2nd **refuses**. Residual: pid-only liveness → pid-reuse false-refuse (PE-2, undisclosed). |
| **PD-14** harness can't stage power-loss | **CLOSED** | ▶ Standing **power-loss probe** in chaos.js (L118-133) stages flush-loss state and asserts the halt; runs in CI. A guardless worker fails it loudly. |
| **PD-15** hoisted clock/random FN | **CLOSED** | ▶ Same-file taint tracking: e8c → **R4@12**; duration-math excluded (no FP on `Date.now()-t0; if(elapsed>…)`). Cross-file/through-helper deferred → disclosed (header + README:171). |

**Regression check (Pass A carry-over):** ▶ `install.js` is byte-identical to RC1 (overlay copy) — **PA-8 remains fix-later, not silently claimed fixed**. Full chaos passes on Windows (all six probes green).

---

## 2. New findings (PE-1 … PE-3)

| ID | Sev | Finding (▶ executed) | File | Fix | Disposition |
|---|---|---|---|---|---|
| **PE-1** | Low–Med | ▶ A **multi-line template literal** containing `while (true)` on line 3 → **HIGH R1 false positive** (`node graphlint.js san_tpl` → `w.js:3 R1`). The string scanner breaks on `\n` for backticks (graphlint.js:74), so template lines after the first are parsed as code. PD-4's own invariant is "rules must never fire on string literals"; a multi-line template is a string literal. Undisclosed (header lists regex-literals, not multi-line templates). LLM prompt templates commonly span lines — the linter's own target audience. | `scripts/graphlint.js:72-77` | Don't break the backtick scan on `\n` (template literals are multi-line); or add multi-line templates to the blind-spots header. | **fix-in-v0.1.2** (gemini: ship-blocker) |
| **PE-2** | Low | The run lock uses **pid-only liveness** (`process.kill(pid,0)`). ▶ If the OS reuses a dead holder's pid for an unrelated live process, `acquireLock` sees "alive" → **refuses a crashed, resumable run** until that process dies. Conservative (no double-execution), but undisclosed; pids recycle, especially on Windows. | `scripts/scaffold.js:67-76` | Add a boot-id or lock-mtime tiebreak, or disclose the pid-reuse edge in the scaffolded README's locking note. | accept-risk / fix-in-v0.1.2 |
| **PE-3** | Low | ▶ `chaos.js:72` comment: "a worker that re-sends and then throws the magic string **must FAIL here**." But a worker that leaves a *real* unresolved intent AND re-sends externally unguarded gets **SAFETY PASS with ext=2** (6/6). The mechanism is correct within the disclosed "exactly-once **recorded** effects" scope (the harness can't see the external system), but the inline comment claims a guarantee the check doesn't deliver — a localized false-assurance, the class this skill pre-ranks Critical. | `scripts/chaos.js:70-73` | Reword the comment to the delivered guarantee (string-only gaming fails; external re-send is out of scope, needs an idempotency key). | **fix-in-v0.1.2** (deepseek: ship-blocker) |

All three are Low-severity and **fail-safe** (linter over-reports; lock over-refuses; PE-3 is a comment). None reopens a Pass D safety hole. PE-1 and PE-3 are the two listed release blockers per the HOLD voters.

---

## 3. CI + exclusions + claim audit

**CI (PD-5).** ▶ `ci.yml` matrix `[ubuntu-latest, windows-latest] × [node 18, 22]` runs: syntax check → `graphlint --selftest` → dogfood lint `scripts/` → scaffold → run+resume → `chaos.js`. `publish.yml` `publish` job `needs: verify`, and `verify` `uses: ./.github/workflows/ci.yml` (ci.yml declares `workflow_call`). **`npm publish` cannot fire unless the full battery is green on all four cells.** The README's "gated in CI" is now true. (Nit: CI checks out and runs only what's in the repo; it does not itself execute the untrusted `knosky` package — correct.)

**Three principled exclusions (§7) — all disclosed in the shipped artifact:**
1. *Log rotation* → README:171 ("(1) No log rotation at this tier… which the graduation ladder already bounds… move to SQLite, rung 2"). ✓
2. *Cross-file/through-helper data-flow* → graphlint.js header L18-23 ("cross-file or through-helper data flow (same-file… IS done)") + README:171 (2). ✓
3. *Air-gapped supply-chain verification* → knosky-sync.js:19-22 + README:171 (3) ("the baked content hash defeats label reassignment but still queries the registry; offline verification… v0.2.0"). ✓
None is silent; each names its revisit trigger.

**Claim audit (README / SKILL / scaffolded README).** ▶ The outcome table's power-loss claim (README:65 "including after power loss: the write-ahead intent log is fsync'd, and the harness stages the lost-flush state to prove the halt") is now **backed by execution**. "exactly-once" is consistently scoped to *recorded* effects + external-idempotency-key caveat; no residual absolute overclaim (`grep` for un-scoped "exactly once"/"proven"/"guarantee" → only defensible uses). The scaffolded README's four "proven mechanically by the chaos harness" claims (crash recovery, recorded exactly-once, power-loss halt, same-run locking) each map to a passing chaos probe. The roadmap "Reviewed" section honestly narrates the Pass D HOLD over the lead's dissent — no overclaim.

---

## 4. Participation + dissent log

| Family | Verdict | Position (verbatim gist) |
|---|---|---|
| **OpenAI `gpt-5.1`** *(non-Anthropic)* | **SHIP** | "PD-1/3/12/14/13 all CLOSED… remaining issues are either documented scope limits or conservative/precision defects. RC2 earns the SHIP that RC1 did not." Rates PE-1 "not a ship-blocker — linter fails safe"; PE-2 "conservative, availability not safety"; PE-3 "localized to a comment." |
| **Google `gemini-2.5-pro`** *(non-Anthropic)* | **HOLD** | Confirms PD-1/PD-3/PD-13 "genuinely resolved… `fsyncSync` robust, chaos probe correctly flags issues." Blocks on **PE-1**: "a linter false positive on multi-line template literals… impacts LLM prompt usage… a clear blocker to proceeding." |
| **DeepSeek `deepseek-r1`** *(non-Anthropic)* | **HOLD** | "PD-1 CLOSED; PD-12/14 CLOSED; PD-13 CLOSED (residual low-risk)." Blocks on **PE-3**: the chaos comment "misleads users into trusting a nonexistent safety property. This invalidates PD-3's verification." |
| **Lead — Claude Opus 4.8** *(Anthropic, executor)* | **SHIP-AFTER-LISTED-BLOCKERS** | All 15 substantively closed and re-verified by execution; PE-1/PE-3 are the two dissenters' one-line honesty fixes and should close first under the skill's own zero-false-assurance rule; PE-2 accept-risk. |

**Dissent preserved, not averaged.** The panel does **not** converge on a single verdict — 1 SHIP, 2 HOLD — and the two HOLDs are on **different** residuals (gemini: PE-1; deepseek: PE-3), which is itself evidence of independent review rather than a shared script. All three agree the original fifteen are closed; gpt-5.1 alone judges the new residuals non-blocking. The lead adopts the union of the two HOLD conditions as the listed blockers (both cheap), which satisfies every family: gpt-5.1's SHIP is unaffected by two extra one-line fixes; gemini's and deepseek's blockers are each addressed. No position was softened to manufacture consensus.

**Disagreement with the lead, recorded:** gpt-5.1 would ship *now*; the lead and two families would not. The lead sides with the stricter reading because PE-1 violates PD-4's own stated invariant ("never fire on string literals") and PE-3 is exactly the false-assurance-in-wording the skill exists to refuse — the same reasoning that turned Pass D's lead-minority into the council's HOLD.

---

## 5. Bottom line

RC2 is the respin Pass D asked for and then some. Executed verification confirms the flagship chain is genuinely closed: the write-ahead logs are fsync'd so the power-loss double-send becomes the designed halt (PD-1), the safety pass is earned by on-disk state instead of a string (PD-3), the idempotency key is wired (PD-12), and the harness now stages the very failure class it once couldn't test (PD-14) — all standing in a cross-platform CI that gates publish (PD-5). The run lock (PD-13), integrity pin (PD-10), sanitizer with line-pinned selftest teeth (PD-4), setInterval/hoist rules (PD-6/15), and the smaller fixes (PD-2/7/8/9/11) all survive their attacks. The three principled exclusions are disclosed where §7 says, and PA-8 is honestly still fix-later.

What stands between RC2 and an unconditional, unanimous SHIP is small and precise: a multi-line-template false positive that contradicts the linter's own "immune to string literals" claim (PE-1), and a chaos comment that promises more than the check delivers (PE-3). The same standard that produced Pass D's HOLD — do not ship an appearance the code can't cash — says correct those two lines first. Do that, and this is a clean SHIP; two of three HOLD authors have already said the substance is there.

*End of Pass E. RC2 unmodified; nothing pushed; no issues touched. Adoption decision is the maintainer's.*

---

## 6. Maintainer closure record (appended post-review, 2026-07-20)

The council's ship condition — "correct those two lines first, and this is a clean SHIP" — is met, and PE-2 was fixed properly rather than accepted, on the maintainer's direction that manual `.lock` deletion is not an acceptable recovery path for non-technical users.

**Process:** fixes were built from a written charter by a separate builder session (Claude Opus 4.8, Claude Code, Windows 11) and independently verified by the orchestrator by re-executing the full battery plus additional adversarial probes. Builder report and verification evidence summarized below; scope confirmed by diff — exactly six files modified, one corpus case added, `docs/` untouched.

- **PE-1 — CLOSED.** Backtick strings no longer terminate at newline in the sanitizer; template contents (including `${…}` interpolations, now disclosed in the blind-spots header) are treated as string content. ▶ The Pass E repro produces zero R1/R4; new corpus case `e8d-multiline-template.js` (zero-findings assertion) makes it a permanent regression; a verified-different mutant reverting the fix fails the selftest (exit 1). Additional probes: unterminated template, escaped backtick, and quotes-inside-template all clean, while a real `while(!done)` outside the template in the same file still fires R1 — recall preserved.
- **PE-2 — CLOSED (upgraded from the review's accept-risk/disclose options).** The lock is now a lease: a live manager renews the lockfile mtime every 5s (unref'd heartbeat); an acquirer steals on dead pid (fast path) or on live-pid-with-expired-lease (≥30s), and refuses only on live-pid-with-fresh-heartbeat — with a message that tells a non-technical user the situation self-resolves. This is coordination rule 2 applied to the manager itself. ▶ Verified both directions manually and via the harness's new pid-reuse probe (7 checks per chaos run, ×3 green); kill-then-plain-re-run recovers with zero manual steps; a live run whose worker blocks 2× the lease is protected by the heartbeat (probed); garbage env overrides fall back to defaults. Disclosed residual: a fully synchronous CPU-blocked step longer than the lease starves the heartbeat (scaffolded README notes it; keep long work async).
- **PE-3 — CLOSED.** The chaos comment now states the delivered guarantee: halts are certified by on-disk state; string-only gaming and forged logs fail; external re-sends are out of recorded-effects scope and are the idempotency key's job. ▶ No behavior change; the PD-3 gaming worker still fails (forged halt rejected, exit 1).

**Release decision:** v0.1.1 ships as RC3. Per §4, gpt-5.1's SHIP stands unconditionally; gemini-2.5-pro's and deepseek-r1's blockers (PE-1, PE-3) are closed, and PE-2 exceeded the asked remedy. All three review reports (council, Pass D, Pass E) publish with the release.
