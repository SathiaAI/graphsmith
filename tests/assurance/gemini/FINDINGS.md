# Assurance Test Findings

- **Attack 1 (Malicious BYO Containment):** PASS. Tool requiring container reported `unavailable` and did not run unconfined.
- **Attack 1 (Lying Exit Code):** PASS. Exit-code contract honored.
- **HONEST-SCOPE (ext-tool-runner BYO output):** PASS. No banned strings found.
- **HONEST-SCOPE (ext-tool-runner trusted output):** PASS. No banned strings found.
- **Attack 2 (Architecture Resistance):** PASS. Redteam battery catches planted injection, scored from state.
- **Attack 2 (BYO Attack Case):** PASS. Declarative BYO case scored from state.
- **Attack 3 (Determinism):** PASS. Test suites provide deterministic pass/fail (outputs identical save for temp dir differences).
- **Attack 4 (Assure Minimal Packet):** PASS. Emits a valid packet with >=1 battery and is honest about being a stub.
- **HONEST-SCOPE (assure packet output):** PASS. No banned strings found.
- **Attack 6 (No In-Place Mutation):** PASS. `.graphsmith/` was not mutated by the testing harness.

**Verdict**: PASS with 0 defects.
