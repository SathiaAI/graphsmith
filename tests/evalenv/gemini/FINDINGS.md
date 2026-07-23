# Findings: `scripts/evalenv.js` Security & Functional Review

This document contains the adversarial testing results for `evalenv.js`.

## Required Attacks

### 1. Isolation / Escape
- **Test:** Created a standard profile evaluation copy from a source directory containing `.git`, `.graphsmith`, and `node_modules` folders, as well as directory junctions pointing outside the tree (`link_out`) and to `../..` (`link_up`).
- **Result:** **PASS**. The evaluation copy successfully excluded `.git`, `.graphsmith`, and `node_modules`. Directory junctions/symlinks were correctly skipped and did not resolve into the copy. `NODE_PATH` was properly scrubbed from the environment variables, ensuring module isolation.

### 2. Secret-scrub (default-deny)
- **Test:** Set various fake secret environment variables (`FAKE_SECRET`, `AWS_ACCESS_KEY_ID`, `OPENROUTER_API_KEY`, `PATH_SNEAKY`) alongside allowlisted ones (`PATHEXT`) prior to creating a standard evaluation copy.
- **Result:** **PASS**. Only the explicitly allowed variables from `DEFAULT_ALLOWLIST` (like `PATHEXT`) were permitted into the copy's `env`. All other variables, regardless of naming similarity or prefix, were successfully scrubbed.

### 3. Container-required (B10)
- **Test:** Attempted to call `runUntrustedCode()` on a standard profile handle; called `requireContainer()` on a standard profile; simulated a missing container runtime and attempted to run untrusted code on the unavailable container handle.
- **Result:** **PASS**. 
  - `runUntrustedCode()` on standard profile threw `CONTAINER_REQUIRED`.
  - `requireContainer(standard_handle)` threw `CONTAINER_REQUIRED`.
  - Container profiles instantiated with no reachable runtime accurately reported `available: false` and properly threw `CONTAINER_UNAVAILABLE` when code execution was attempted, with no silent downgrade to standard.

### 4. Budgets + Destroy
- **Test:** Configured a copy budget below the number of files in the source directory; ensured breach halted execution (`BUDGET_BREACH`) and fully cleaned up the partial directory. Invoked `destroy()` twice on a valid handle.
- **Result:** **PASS**. Budgets successfully halt excessive copying and partial directories are not left behind. Double `destroy()` invocation is a safe no-op.

### 5. Honest Claims
- **Test:** Examined the standard profile's `claims` object.
- **Result:** **PASS**. The `claims` correctly reflect `confidentiality: false` and `network_containment: false`. The standard profile accurately describes its exact level of isolation without over-claiming sandbox capabilities.

### 6. Determinism
- **Test:** Ran identical calls to `create()` sequentially.
- **Result:** **PASS**. Outputs match entirely (excluding random entropy strictly used for directory ID creation and wall-time elapsed deltas), verifying that there is no reliance on clocks or randomness for functional decision paths.

---

## Defects Discovered

### Defect 1: Budget Bypass via Empty Directories (Denial of Service)
- **Description:** In the `copyTreeExcluding` function, the `budget.recordFile(size)` method is only invoked if `entry.isFile()` is true. `fs.mkdirSync` is called for every directory regardless. An attacker can construct a deeply nested tree or a flat array of millions of *empty* directories. Because `entry.isDirectory()` never calls `recordFile(0)` or a `recordDirectory()` equivalent, neither `files` nor `bytes` counters are incremented, completely bypassing the `max_files` budget and causing a Denial of Service through excessive filesystem operations and memory exhaustion.
- **Severity:** Medium/High (Denial of Service / Budget Evasion).
- **Fix:** Update `budget` to track directories. Inside the `if (entry.isDirectory())` branch, invoke a counter increment (e.g., `budget.recordDirectory()`) to ensure the total number of filesystem entries remains bound by the `max_files` limit.

### Defect 2: Secret-Scrub Bypass in Container Profile via `runOpts.spawnOptions`
- **Description:** In `createContainer`'s `runUntrustedCode`, `spawnSync` is passed an options object constructed via: `Object.assign({ env: base.env, stdio: "pipe", timeout: ... }, runOpts.spawnOptions || {})`. Because `Object.assign` merges from right to left, if the calling evaluator happens to pass its own `process.env` (or partial unscrubbed env) via `runOpts.spawnOptions.env`, it will completely override `base.env`. This inadvertently shatters the secret-scrubbing boundary and silently leaks host secrets into the container.
- **Severity:** Medium.
- **Fix:** Explicitly enforce the scrubbed environment after applying `spawnOptions` (e.g., `const opts = Object.assign({}, ..., runOpts.spawnOptions); opts.env = base.env;`), or at minimum merge the custom environment safely by scrubbing it first.

### Defect 3: In-Process Stub Does Not Prevent Non-HTTP Network Access
- **Description:** The `STUB_FILE_CONTENT` monkey-patches `http`, `https`, and `global.fetch`. The code comments assert: *"this in-process stub is the actual control: a candidate evaluated in this copy cannot reach the network"*. However, a trusted evaluator tool or candidate code (if mistakenly run under the standard profile) could effortlessly bypass this stub using raw TCP/UDP modules (`require('net')`, `require('dgram')`, `require('tls')`) or by spawning a child process (`child_process.execSync('curl ...')`). While the standard profile explicitly disclaims network containment in its `claims`, the comment phrasing is misleading regarding the strength of the stub.
- **Severity:** Low (as containment is explicitly disclaimed and untrusted code execution is refused in standard mode).
- **Fix:** Amend the misleading comment in `STUB_FILE_CONTENT` to state it acts as an accidental-leak guard for HTTP requests, not a true containment control against adversarial execution.

## Coverage Limitations
- Testing `runUntrustedCode` success flows (e.g., verifying network drops and actual mount read-only states) requires a real, functional container runtime environment (Docker/Podman daemon) running during the test suite. Given the requirement to run purely within an unprivileged Node environment without external dependencies, these runtime assertions must be verified using a real container engine.