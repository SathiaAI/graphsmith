# GraphSmith — Multi-Model Adversarial Council Review (published summary)

> Scrubbed public summary of the 2026-07-20 cross-model review. Full internal working notes are kept in the maintainer's private workspace; this page is the published record, with dissents preserved.

**Method.** One Anthropic model executed the review pass on Windows 11 / Node v24.18.0 and produced ground-truth evidence by running the actual scripts; three **non-Anthropic** model families then reviewed adversarially — GPT-5.1, Gemini 2.5 Pro, and DeepSeek R1. Findings are reconciled below with disagreements preserved, not averaged. Two or more non-Anthropic families participated in every pass (the skill's own no-self-certification rule, applied to the review itself).

**Scope.** Pass A — the shipped v0.1.0 (executed against live scripts). Pass B and Pass C — two v0.2.0 designs (reviewed on paper, before any code existed).

## Verdict

- **v0.1.0 — needs a patch** (unanimous). Architecturally sound and genuinely useful — the manager / checkpoint / resume discipline works as executed — but it shipped a headline durability claim that execution falsified, plus a supply-chain exposure and a durability defect. All three were fixable in a v0.1.x patch without breaking installed users or the zero-dependency / one-skill constraints.
- **v0.2.0 designs — ship only with the listed fixes** (2 of 3 families; one dissented to redesign, preserved below). Each design carried at least one Critical "false-assurance" hole that had to be closed on the drawing board first.

## The three must-fix findings (Pass A, executed)

1. **The headline single-delivery claim was over-stated.** <!-- lint-allow: honest-language (naming the corrected over-claim) --> The outcome table advertised recorded effects as *"proven exactly-once"*; a torn-write test (kill a real side effect after it fires but before it is recorded, then resume) produced a genuine double-send while the harness still reported success. Council-adopted severity: **Critical** — a documentation-level false assurance, escalated by all three families from the executor's initial "implementation bug." **Fixed** by correcting the claim to its honest boundary (crash recovery + no duplicate *recorded* effects; true end-to-end single delivery needs an idempotency key the external system honors) **and** adding a write-ahead intent pattern that halts loudly on an intent-without-completion instead of silently re-sending.
2. **A corrupted or 0-byte checkpoint could permanently brick a run** (High, unanimous) — a power-loss-reachable failure that inverted "resume, never restart" into "permanently dead." **Fixed:** the checkpoint parse is wrapped (a bad file is treated as not-done and re-run), the write-ahead log is fsync'd before the pointer swap, and manual recovery is documented.
3. **The grounding sync was an unpinned, auto-run, globally-installed dependency** (High; one family called it a ship-stopper, one Medium, range preserved) — a compromised publish could propagate to every user. **Fixed:** pinned-version, on-demand, content-hash-verified; no silent global escalation; a skip flag for sensitive environments.

The review also found and the maintainer **redesigned** (going further than the council proposed) the architecture linter — making it project-aware with an executable, line-pinned regression corpus so its own rules can't silently fail.

## Design findings (Pass B / Pass C)

The two v0.2.0 designs were probed for "false-assurance" holes: a regulated-mode that could activate on a partial or misplaced register (appearance of coverage without substance); policy text that could be treated as control logic (injection); a review gate that could be rubber-stamped; and a cross-seam chaos harness that promised more than a zero-dependency runtime can deliver. Each was addressed by failing closed, treating configuration as data (never instructions), requiring every blast-radius statement to reference an executable check or be marked *unverified*, and descoping the chaos claim to what the harness genuinely controls — with an honest coverage report for the rest.

## Dissents (preserved, not averaged)

- One family held the **strongest honesty line**: *"A tool for building reliable systems must be, above all else, relentlessly honest about its own limitations."* — anchoring the must-fix ranking.
- The supply-chain severity ranged **Critical / High / Medium** across the three families; the council adopted **High**, noting the author-owned-package mitigant sits between those positions.
- Both v0.2.0 design verdicts had **one family dissenting to full redesign** while two accepted ship-with-fixes; the council adopted ship-with-fixes but narrowed the dissent to the specific mechanisms (activation model; cross-seam chaos) that genuinely needed redesign.
- A note on agreement: the three families **disagreed** on several severities and on both design verdicts — convergence here is not rubber-stamping, which the framework explicitly treats as suspect.

## Outcome

All findings were **accepted**, several escalated by the maintainer toward *more* fixing rather than less. Twice now the review process has caught the project's own claims outrunning its code — and both times the report was published and the code was fixed. That is the same discipline the skill prescribes to its users.
