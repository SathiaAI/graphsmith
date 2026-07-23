# GraphLint Scope Exemption Fix Confirmed

## Findings

**NO REGRESSIONS.**

The recent fix tightening the `R5` scope exemption to apply *only* to `graphlint`'s own constitutional `scripts/` directory (resolving to `__dirname` of `graphlint.js`) is working perfectly.

- The spoofable scope hole where a mock `scripts/` directory in a scaffolded project could bypass `R5` has been closed. 
- The test suite in `tests/graphlint/gemini/run-tests.js` has been amended to reflect this correct behavior. It correctly expects a mock `scripts/` directory containing `eval()` or `exec()` to be flagged with an `R5` violation.
- The `R5` exemptions on `graphlint`'s *real* constitutional `scripts/` directory remain intact.
- Nested `scripts/` subdirectories (`scaffolded-project/scripts/`) continue to be correctly flagged.
- The `--selftest` and recall/precision checks continue to pass.

All tests are green.
