# WS-A — GSA verifier + producer + plan/replay — adversarial adjudication

**Targets:** `scripts/gsa-verify.js` (§9 verifier), `scripts/gsa-produce.js` (bundle producer), `scripts/gsa-plan.js` (drift/destructive + replay).
**Builder:** claude-opus (Anthropic) · **Platform:** win32, Node v24.18.0 · **Testers (≥2 non-Anthropic):** DeepSeek + Mistral-Large (OpenRouter code-gen), each authored a suite that produces a valid signed bundle then attacks it; orchestrator re-ran both. Builder ≠ testers.

## Real defects found + fixed (both from Mistral's `different-algorithms`, all 3 sig algorithms round-tripped)
1. **RSA-PSS producer sign — `data`/`key` arguments swapped (HIGH).** `crypto.sign("sha256", {key,padding}, buf)` passed the key-object as `data`; producing an RSA-PSS bundle threw. **Fixed:** `crypto.sign("sha256", buf, {key,padding,saltLength})`.
2. **RSA-PSS salt-length mismatch (MEDIUM).** Sign and verify pinned no `saltLength`, so a signed RSA-PSS bundle failed verification ("invalid salt length"). **Fixed:** both pin `RSA_PSS_SALTLEN_DIGEST`. (Ed25519 — the default/RECOMMENDED — and ECDSA-P256 round-tripped correctly throughout.)

Post-fix: **Mistral 28/29, DeepSeek 11/12**, all three selftests green.

## Adjudicated NOT defects (two-sided validation gate)
- **Mistral `profile-confusion-X-without-evidence` — tester-code bug.** The test throws `ReferenceError: keys is not defined` — a variable undefined in its own scope; it never exercises the verifier. (Its sibling `profile-confusion-A-without-evidence` PASSED.)
- **DeepSeek `profile_confusion` — test-construction error.** It sets `adversarial.suites[0].blocked=0` (making the battery fail) but leaves `control_attestations.adversarial_batteries_passed=true` — a **control lie** — and re-signs with `JSON.stringify` instead of canonical JCS. My verifier correctly FAILs it (manifest-signature + control-attestation steps). The behavior it *meant* to check — an honest bundle asserting X without earning it gets X **downgraded to unavailable**, not confirmed — is proven by `gsa-produce --selftest` (a 3/10 battery → X downgraded, bundle still PASS).

## Coverage confirmed (both families, all correctly defended)
signature strip/replace/untrusted-signer · manifest tamper (mode/profile/artifact-sha256/control-attestations) · artifact-byte tamper · control-attestation lie · profile confusion (A/X honest downgrade) · path traversal / backslash / non-NFC unicode · conditional presence (regulator_summary ↔ mode; repair_log) · canonicalization (key-reordering, distinct-manifest-same-hash) · revoked skill · malformed bundle (null/undefined/wrong-type/circular/proxy/BigInt/hostile-getter → FAIL, never throws).

## Verdict
**WS-A GSA core TEST-PASSED.** Two non-Anthropic families; Mistral found 2 genuine RSA-PSS defects (fixed, re-verified), remaining misses adjudicated as tester-side. §9 verification holds under executed attack: only a genuinely valid, signed, unaltered bundle PASSes; every tamper vector fails closed; unearned profiles downgrade to unavailable (never green); the producer is honest-by-construction. Pure decision paths throughout. (Deep capability-grant/skill-provenance/full-replay — §9.7/9.8/9.11 — remain the next increment; scoped, not claimed.)
