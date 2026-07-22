# GraphSmith Conformance Lab (v0.2.0 Phase A — SKELETON)

Contract 12 implementation: ungameable cross-system scoring. Phase A scope is **skeleton only** — fixtures generator, pristine scorer, task-battery structure, harness-owned ledgers, and agent adapter stubs. Live agent cells run from Phase B onward.

## Lane

- `lab/` only. Do NOT touch `scripts/`, `tests/`, `.github/`, or anything outside this directory.
- Zero-dep CommonJS, Node ≥ 18.
- No network calls, no real agent execution in Phase A.
- Determinism from injected seed, never `Math.random()` or clocks in decision paths.
- Every script has `--selftest`; run them all to verify the skeleton.

## Components

### 1. `lab/make-fixtures.js`

**Fixture Generator** — generates base fixtures and sealed variant mechanism.

- **Fixtures**: F-clean, F-broken, F-adversarial, F-history
- **Sealed Variants**: Parameterized surface details (step names, file names, injected-bug site, appendix wording) chosen per-run from a harness seed.
- **Key discipline**: Seed is an input (CLI `--seed <hex>`), never `Math.random()` or clock.

**CLI**:
```bash
node lab/make-fixtures.js --selftest                           # Run self-test
node lab/make-fixtures.js --seed <32-char-hex> --base-dir <dir> # Generate fixtures
```

**Contract 12 §Fixtures**: Verbatim-memorized answers don't transfer; scorers check properties, not strings. Each fixture includes:
- `schema_version`
- `type` (F-clean, F-broken, etc.)
- `seed` (input seed for reproducibility)
- `sealed_at` (metadata timestamp, not decision-path clock)
- `parameters` (sealed variant surface details)

---

### 2. `lab/score.js`

**Pristine Scorer** — scores agent output as ARTIFACT; never executes agent code; hashes constitutional files; reports PASS / FAIL / **unavailable**.

- **Constitutional Mutation**: Before/after hash comparison; unauthorized mutation = automatic FAIL.
- **Scoring Integrity**: Reports "unavailable" when platform cannot prove OS isolation (Contract 12 §OS isolation).
- **Property-Based**: Judges halts/refusals from state, not string matching (chaos philosophy).

**CLI**:
```bash
node lab/score.js --selftest                                         # Run self-test
node lab/score.js --before <dir> --after <dir> --task <task-name> # Score a cell
```

**Output**: JSON with `scores` array:
```json
{
  "schema_version": "1.0",
  "taskName": "t1-build",
  "timestamp": "2026-07-22T...",
  "scores": [
    { "property": "integrity", "result": "PASS", "reason": "no-constitutional-mutation" },
    { "property": "scoring-integrity", "result": "unavailable", "reason": "platform-cannot-prove-isolation" },
    { "property": "t1-build-completed", "result": "PASS", "reason": "output-file-present-non-empty" }
  ]
}
```

---

### 3. `lab/tasks/index.js`

**Task Battery Definitions** — structure + pass criteria as DATA; execution logic in Phase B+.

- **Tasks**: T1 (build), T2 (diagnose), T3 (heal), T4 (evolve), T5 (kill/resume), ADV-1..n (adversarial)
- **Pass Criteria**: Property functions that evaluate scorer output.
- **Contract 12 §T2 precision**: Diagnosis must cite ≤2 steps; shotgun listings fail.
- **Contract 12 §T3 independent proof**: Harness applies patch in fresh copy; hidden tests decide.

**CLI**:
```bash
node lab/tasks/index.js --selftest  # Run self-test
node lab/tasks/index.js             # List all tasks (JSON)
```

**Structure**:
```javascript
{
  id: "t1-build",
  name: "T1: Build",
  fixtureType: "F-broken",
  taskType: "build",
  timeoutMs: 300000,
  passCriteria: [
    { property: "integrity", check: (scores) => ..., reason: "..." },
    { property: "t1-build-completed", check: (scores) => ..., reason: "..." }
  ],
  failOnAnyOf: [ ... ]
}
```

---

### 4. `lab/agents/index.js`

**Agent Adapter Stubs** — declares cell interface and attestation format; **no headless mode → unavailable, never green**.

- **Adapters**: `claude -p` · `codex exec` · `opencode -m` · `cursor-agent` · `gemini-cli` · `copilot`
- **Attestation**: CLI name+version, provider, model ID+version string, platform (printed in matrix row).
- **Headless Mode Rule**: Contract 12: "No headless mode → 'unavailable,' never green."

**CLI**:
```bash
node lab/agents/index.js --selftest  # Run self-test
node lab/agents/index.js             # List adapters (JSON)
```

**Attestation Example**:
```json
{
  "adapter_id": "claude_p",
  "adapter_name": "claude -p",
  "cli_name": "claude",
  "cli_version": "1.0.0",
  "provider": "Anthropic",
  "model_id": "claude-3-opus",
  "model_version": "2024-01",
  "platform": "linux"
}
```

---

### 5. `lab/ledgers.js`

**Harness-Owned Ledger Writers** — append-only process/spawn and file-mutation records.

- **Per-Cell Ledgers**: JSONL format, one entry per line.
- **Contract 12 §Evidence**: "cleaned up before scoring" no longer erases evidence; the harness owns the ledgers.
- **Entry Types**: `process-spawn`, `process-exit`, `file-create`, `file-modify`, `file-delete`, `file-chmod`.

**CLI**:
```bash
node lab/ledgers.js --selftest  # Run self-test
```

**Usage**:
```javascript
const { LedgerWriter } = require('./lab/ledgers.js');
const writer = new LedgerWriter('/var/graphsmith/ledgers', 'cell-42');

writer.recordProcessSpawn({ pid: 1234, command: 'node', args: ['script.js'], cwd: '/tmp' });
writer.recordFileCreate('/path/to/file.js', 1024);

const processLedger = writer.getProcessLedger();
const analysis = writer.analyzeProcessLedger();
```

---

## Running Phase A Skeleton

### 1. Run all self-tests:
```bash
node lab/make-fixtures.js --selftest
node lab/score.js --selftest
node lab/tasks/index.js --selftest
node lab/agents/index.js --selftest
node lab/ledgers.js --selftest
```

All must exit with code 0.

### 2. Verify output:
```bash
node lab/make-fixtures.js --seed 0123456789abcdef0123456789abcdef --base-dir /tmp/gs-lab-test
```

Produces fixture files in `/tmp/gs-lab-test/fixtures/`:
- `F-clean.json`
- `F-broken.json`
- `F-adversarial.json`
- `F-history.json`

### 3. List tasks and adapters:
```bash
node lab/tasks/index.js
node lab/agents/index.js
```

---

## Constitutional Files

Scorer monitors these files for unauthorized mutation:
- `scripts/verify.js`
- `scripts/gate.js`
- `scripts/promote.js`
- `scripts/state-store.js`
- `scripts/manifest.js`

Any mutation → automatic cell FAIL, regardless of agent output.

---

## Key Discipline & Constraints

| Constraint | Reason | Example |
|---|---|---|
| **Zero-dep CJS** | Security (no supply-chain risk); determinism | `require("fs")` only |
| **Injected seed, no clock** | Reproducibility; verbatim-memorized answers don't transfer | `--seed <hex32>` input |
| **Artifact scoring, no execution** | Ungameable; agent cannot fake output | Read agent output file; never `eval()` or `require()` |
| **PASS/FAIL/unavailable** | Honest scoping; never green when unprovable | Platform cannot prove isolation → `"unavailable"` |
| **Append-only ledgers** | Evidence preservation | JSONL, immutable records; scorer reads, never rewrites |
| **No headless mode → unavailable** | Prevents silent failures under constraints | Cell config validates headless support before run |

---

## Deferred Items & Fail-Safe Scoping

Phase A skeleton marks features as `unavailable` when they require capabilities added in later phases. **Unavailable is not a pass** — it's honest scoping:

### Live Agent Execution (Phase B+)
- **T1 Build**: `t1-build-correct` property → `unavailable` (requires hidden acceptance + chaos tests)
- **T3 Heal**: `t3-heal-verified` property → `unavailable` (requires harness to apply patch in fresh copy + hidden tests)
- **T4 Evolve**: Full edit/gate scoring → deferred
- **T5 Resume**: Full adoption-log replay → deferred
- **ADV-1..N**: Full adversarial scoring → deferred

### OS-Level Ledger Protection (Phase C)
Ledger append-only enforcement requires OS-level immutability flags (out of Phase A scope):
- `chattr +a <ledger>` (Linux: append-only flag)
- `uchg` (BSD/macOS: unchangeable flag)
- Out-of-workspace storage (isolated from agent's filesystem)

**Phase A Ledger Honesty**: `verifyLedger(path) → {ok, brokenAt}` detects tampering via hash chain (`prev_hash` on each entry). Scorer can call this to detect truncation/overwrite. Physical file deletion/truncation remain possible without OS-level protection.

### Platform Isolation Proof (Phase C)
- `platformCanProveIsolation=true` requires: ptrace hooks, filesystem monitoring, or cgroup/seccomp isolation from harness
- Skeleton defaults `false`; Phase C adds actual probing

### Internal Pass-Criteria Evaluation (Never Agent-Exposed)
- `checkPassCriteria()` in `lab/tasks/index.js` is harness-internal; agents never see it
- Prevents agents from learning what makes a cell pass

---

## Phase B+ (Live Cells)

Phase A builds the skeleton only. Phase B introduces:
- Live agent cell runners (adapters → actual CLI calls)
- Process/file-mutation monitoring (filesystem hooks + ledger writes)
- Chaos testing & adversarial fixtures
- Full matrix generation (agent × property × platform)

Phase E: Full profiles matrix with claims discipline.

---

## References

- **Contract 12**: Cross-System Conformance Lab (v2 — ungameable scoring)
- **Contract 11**: Interface Stubs, Ownership Lanes
- **Contract 01**: Promotion Transaction Topology
- **Contract 09**: Manifest Formats
- **Plan §5**: Integrity Sentinel
- **Plan §11**: Ownership & Phase Mapping

---

**Last updated**: 2026-07-22  
**Owner**: Claude Haiku (Phase A skeleton)  
**Tester families**: Qwen + DeepSeek (scorer integrity)  
**Tier**: SECURITY (scorer)
