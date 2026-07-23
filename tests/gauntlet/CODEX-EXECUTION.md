# Independent gauntlet execution — Codex CLI (OpenAI harness)

The GraphSmith v0.2.0 gauntlet, executed by **Codex CLI (OpenAI models)** — a different
model + harness than the orchestrator, and not opencode — per the directive to run the
tests THROUGH other models. Verbatim result:

```
===== GAUNTLET BATTERY: HOLD=153  BREAK=0  TOTAL=153 =====   exit 0
===== GAP-TESTS (multi-model contributed): HOLD=19  BREAK=0  TOTAL=19 =====   exit 0
```

172 tests, 0 failures, independently confirmed (2026-07-23).

Plus: 5 fresh models (Mistral-Large, Command-R-Plus, DeepSeek-Chat, Qwen3-Max, MiniMax-M2)
independently reviewed the battery source + result via direct OpenRouter API. All judged
the tests genuinely adversarial; two were skeptical 153/0 was "too clean." Their gap-finding
surfaced two real defects (bidi-control evasion in norm-core; Markdown-link injection in
matrix escapeMarkdown) — both fixed and re-verified (tests/gauntlet/gap-tests.js).
