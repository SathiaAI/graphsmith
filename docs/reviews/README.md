# Adversarial review reports

GraphSmith is reviewed the way it asks you to review your own work: independently, by models from different families than the one that built it, with disagreements preserved rather than averaged. These are the published summaries; the maintainer's private working notes stay in a private workspace.

## Reports

- **[2026-07-20 — Multi-Model Adversarial Council Review](2026-07-20-council-review.md)** — three non-Anthropic families (GPT-5.1, Gemini 2.5 Pro, DeepSeek R1) reviewed the shipped v0.1.0 (executed against live scripts) and two v0.2.0 designs. The council **held the release**: it found the headline single-delivery claim over-stated, a power-loss durability defect, and a supply-chain exposure. All were fixed — with code, not wording.

- **Pre-release red team (v0.1.1 candidate).** A fourth pass: the same three non-Anthropic families attacked the live scripts by executing them, before the release candidate shipped. The findings — a residual send-then-record window, a checkpoint that could brick a run, and a linter rule that silently never fired — were reproduced and closed (fsync'd write-ahead logs, a staged power-loss probe, a state-verified safety-pass, a project-aware linter with a line-pinned regression corpus, and CI gates on every push).

- **Verification pass.** Confirmed the adopted fixes held under re-execution and that no claim in the public copy outran the tested behavior.

## The rule these reviews follow

A review that finds nothing is treated as suspect, not as success. Reviewers must be a different model family than the builder, and every finding is reproduced against the live code before it counts — the same no-self-certification discipline the skill prescribes to its users. Twice now this process has caught the project's own claims outrunning its code, and both times the report was published and the code was fixed.
