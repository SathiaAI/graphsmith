# FINDINGS — adversarial test of `scripts/verify.js` (Integrity Sentinel, family: grok)

**Lane:** `tests/verify/grok/` only  
**Target:** `scripts/verify.js` (Claude Sonnet builder)  
**Contracts:** `09-manifest-formats.md` (dual axes, adoption-log rewrite-detecting vs anchored head), `05-threat-model.md` (A6 OOS), plan §5 failure domains  
**Deps examined:** `scripts/manifest.js`, `scripts/loaders.js`, `scripts/state-store.js` (SCHEMA_VERSION import only — no lock ops)  
**Runner:** `node tests/verify/grok/run-tests.js` (zero-dep CJS; **exit 1 on any FAIL**)  
**Fixtures:** OS temp dirs only — never repo `.graphsmith/`, never git  

---

## How to run

```bash
node tests/verify/grok/run-tests.js
```

---

## Verbatim suite output (authoritative run)

```
# grok adversarial verify (Integrity Sentinel) suite
# target=F:\Users\PaulPoulose\GraphSmith\graphsmith\scripts\verify.js
# platform=win32 node=v24.18.0
PASS	FD/happy-path	domain=none
PASS	FD/trusted-core/scripts/gate.js/halt-exit-3	exit=3
PASS	FD/trusted-core/scripts/gate.js/not-silently-repaired
PASS	FD/trusted-core/scripts/verify.js/halt-exit-3	exit=3
PASS	FD/trusted-core/scripts/verify.js/not-silently-repaired
PASS	FD/trusted-core/scripts/promote.js/halt-exit-3	exit=3
PASS	FD/trusted-core/scripts/promote.js/not-silently-repaired
PASS	FD/trusted-core/scripts/state-store.js/halt-exit-3	exit=3
PASS	FD/trusted-core/scripts/state-store.js/not-silently-repaired
PASS	FD/trusted-core/scripts/manifest.js/halt-exit-3	exit=3
PASS	FD/trusted-core/scripts/manifest.js/not-silently-repaired
PASS	FD/evolvable-payload/frozen-exit-1	exit=1
PASS	FD/appendix-marker/quarantine-exit-0-continue	exit=0
PASS	AX/yes-yes/separate-fields	rv=yes sc=yes
PASS	AX/no-yes	rv=no sc=yes
PASS	AX/yes-no	rv=yes sc=no
PASS	AX/no-no	rv=no sc=no fd=trusted-core
PASS	AX/bare-checkout/unavailable-not-failure	rv=unavailable sc=no
PASS	AX/cli-json-has-both-axes	stderr=verify --integrity: release-verified=yes self-consistent=yes failure_domain=none
PASS	AX/cli-stderr-both-axes
PASS	ADOP/break-prev_sha256/evolvable-surface	entry[1] (seq 2) prev_sha256 does not match entry[0].entry_sha256 — chain break
PASS	ADOP/report-no-immutable-word
PASS	ADOP/source-rewrite-detecting-claim
PASS	ADOP/error-language-is-chain-not-immutable	entry[1] (seq 2) prev_sha256 does not match entry[0].entry_sha256 — chain break
PASS	ADOP/head-anchor-mismatch/evolvable-surface
PASS	FN/crlf-lf-swap-caught	rv=no
PASS	FN/same-length-byte-flip-caught	actual≠expected
PASS	FN/nfd-path-refused-or-mismatch	{"path":"scripts/café.js","status":"invalid-path"}
PASS	FN/explicit-NFD-path-invalid-path	scripts/café.js
SKIPPED	FN/symlink-swap-constitutional	no symlink privilege: EPERM
PASS	FN/tamper+release-only-no-false-verified	rv=yes sc=no fd=evolvable-surface
PASS	FN/A6-dual-manifest-rewrite-evades-SENTINEL-LIMIT	expected: dual-manifest rewrite yields clean axes — A6 out of scope (contract 05)
PASS	FN/A6-trust-model-discloses-limit	out-of-scope
PASS	FN/corrupt-release-manifest-trusted-core
PASS	LANG/no-banned-terms-user-facing	9 surfaces scanned
PASS	LANG/preferred-replacements-in-source
PASS	SIDE/disk-unchanged-across-two-integrity-runs	files=14
PASS	SIDE/no-state.lock-created
PASS	SIDE/cli-integrity-read-only	exit=0
PASS	SIDE/repeatable-same-domain
PASS	PROBE/structure	rename_succeeded=false retries=6
PASS	PROBE/claim-mentions-live-platform	Probe-verified: on win32, rename-replace over an open read handle FAILED (EPERM) after 6 bounded retries — contract 01 requires bounded EPERM/EBUSY retry + jour
PASS	PROBE/result-consistent-failure	EPERM
PASS	PROBE/cli-live	exit=0
PASS	PROBE/not-fake-check-name
PASS	XTRA/profiles-T-independent-axes	status=verified
PASS	XTRA/missing-project-manifest	evolvable-surface
PASS	XTRA/adoption-seq-gap	entry[1] seq 99 is not entry[0].seq + 1
PASS	FN/adoption-content-spoof-without-relink	DEFECT D1 (MEDIUM): entry body spoofable while linkage digests untouched; chain reports ok (documented pending entry-schema canonicalization)
PASS	FN/extra-undeclared-file-not-in-release-list	DEFECT D2 (LOW/DOCUMENTED): verifyFileList cannot see extras outside declared paths; attacker-added scripts/backdoor.js ignored unless listed
PASS	XTRA/verify-selftest-pass	selftest: 35 passed, 0 failed
PASS	XTRA/exports
# summary	PASS=51	FAIL=0	SKIPPED=1	total=52
```

**Exit code:** `0` (no FAIL)  
**Environment:** Windows win32, Node v24.18.0  

---

## Attacks vs results

| # | Attack | Result |
|---|--------|--------|
| 1a | Tamper each constitutional-set file (`gate/verify/promote/state-store/manifest`) | **PASS** — `release_verified=no`, `failure_domain=trusted-core`, exit **3**, `halted=true`; bytes **not** silently repaired |
| 1b | Tamper evolvable-tree payload (worker prompt) | **PASS** — `evolvable-surface`, `frozen=true`, exit **1** |
| 1c | Poison appendix with marker sequence (re-hash tree so integrity stays green) | **PASS** — appendix `quarantined` / `marker-sequence`, `failure_domain=none`, exit **0** (workflows continue) |
| 2 | Force all 4 release×self-consistent combos | **PASS** — yes/yes, no/yes, yes/no, no/no all reported as **separate fields**, never a single `verified` key |
| 2b | Bare checkout | **PASS** — `release_verified=unavailable`, domain `none`, exit 0 (not a false failure) |
| 3 | Break adoption-log `prev_sha256` | **PASS** — `chain-broken` → `evolvable-surface`; language is chain/anchor, **not** “immutable” |
| 3b | Mismatch `adoption_log_head` | **PASS** — `chain-broken` / evolvable-surface |
| 4a | CRLF↔LF on constitutional file | **PASS** — raw-byte SHA-256 catches; trusted-core |
| 4b | Same-length single-byte flip | **PASS** — hash-mismatch → trusted-core |
| 4c | NFD path tokens in file list | **PASS** — `invalid-path` |
| 4d | Symlink-swap constitutional file | **SKIPPED** — no symlink privilege (`EPERM`) on this Windows host |
| 4e | Tampered file + rewritten release only | **PASS** — no false dual-green: `self_consistent=no`, domain ≠ none |
| 4f | A6: tamper + rewrite **both** manifests | **PASS (limit confirmed)** — axes go green; `--trust-model` states A6 out-of-scope |
| 4g | Corrupt release JSON | **PASS** — `corrupt=true`, trusted-core (not silently “unavailable”) |
| 5 | Banned terms in user-facing output | **PASS** — scanned integrity/profiles/trust/probe ± halt/frozen JSON: no `constant monitoring` / `immutable` / `tamper-proof` / `certified` |
| 6 | Side effects / write-lock | **PASS** — two integrity runs leave disk snapshot identical; no `state.lock`; CLI path read-only |
| 7 | `--platform-probe` live | **PASS** — hosted probe reports real win32 **EPERM** under open handle (not canned “atomic success”) |

---

## Defects

### D1 — MEDIUM — Adoption-log entry **content** not bound to `entry_sha256`

**Evidence:** `FN/adoption-content-spoof-without-relink`  
**What works:** linkage (`prev_sha256` chain + anchored head + seq monotonicity) detects splices/rewrites of the **digest fields**.  
**What fails:** attacker may alter `txid`, `fingerprint`, `human`, `kind`, etc. while leaving `entry_sha256` / `prev_sha256` / `seq` untouched → status stays `ok`, `failure_domain=none`.  
**Why:** verify.js intentionally does **not** recompute `entry_sha256` (header + contracts 09 note: no closed serialization in `schemas/adoption-entry.schema.json` yet). Claim is honestly “rewrite-detecting vs anchored head,” not content-integrity of every field.  
**Fix:** when `schemas/adoption-entry.schema.json` ships, pin canonical JCS/JSON serialization; recompute `entry_sha256 = H(canonical(entry without entry_sha256))` for every line; treat mismatch as `chain-broken` / evolvable-surface. Until then, surface an explicit report note: `content_hash_verified: false` so operators do not over-read “ok”.

### D2 — LOW (documented design limit) — Release/project `verifyFileList` does not detect **extras**

**Evidence:** `FN/extra-undeclared-file-not-in-release-list`  
**What works:** every path **in** the manifest is hash/symlink/path-checked.  
**What fails:** a new undeclared file (e.g. `scripts/backdoor.js`) is invisible to release/project axes. Evolvable trees **do** detect extras via `manifest.verifyTree` full walk.  
**Why:** documented deviation in verify.js header — full `walkDir` on a live project root risks false positives on `.git`/`node_modules`/editor symlinks.  
**Fix (options):** (a) walk **only** paths under each constitutional prefix listed in release; (b) optional `--strict-extras` when root is a clean staging dir; (c) require constitutional_set directory closed inventories in release build. Do **not** silently walk entire repo without pruning.

### Not defects (confirmed limits / honest behavior)

| Item | Severity | Notes |
|------|----------|--------|
| A6 dual-manifest + sentinel rewrite | OOS | Confirmed: rewriting both manifests yields dual-yes. `--trust-model` discloses A6. Catastrophic false-verified **requires** A6-class rewrite (or shipping a compromised sentinel binary itself — outside this process’s verification of the on-disk fixture scripts). |
| Platform rename under open handle on win32 = EPERM | OK | Probe is live and honest; not a hardcoded “atomic=yes”. |
| Symlink constitutional swap | Coverage gap here | Host lacked symlink privilege; source path: `verifyFileList` returns `symlink-refused` when `lstat` sees a link — untested live on this agent host. |

---

## Catastrophic false-negative hunt (summary)

**Question:** can verify report a clean dual-axis “all good” while a constitutional file is actually tampered, **without** A6?

| Vector | Clean dual-yes while core tampered? |
|--------|-------------------------------------|
| CRLF↔LF | **No** — caught |
| Same-length flip | **No** — caught |
| NFD path weirdness | Invalid path, not silent accept |
| Tamper + rewrite release only | **No** — project axis fails |
| Tamper + no manifest update | **No** — trusted-core exit 3 |
| Extra undeclared file | Dual-yes **for declared files only**; not a “core file listed as ok while bytes differ” — different gap (D2) |
| Dual manifest rewrite | **Yes** — A6 OOS, disclosed |

**Worst in-scope residual:** D1 (adoption forensic fields forgeable under intact digests) and D2 (undeclared extras). Neither yields “hash ok” for a constitutional path whose bytes changed under unchanged manifests.

---

## Honest coverage statement

- **Covered thoroughly:** failure-domain matrix (trusted-core / evolvable-surface / untrusted-input quarantine), independent axes (4 combos + bare + CLI), adoption linkage break + head mismatch, raw-byte hash false-negatives (CRLF, same-length), honest-language surfaces, read-only/`state.lock` absence, live platform-probe, A6 disclosure, builder `--selftest` (35/35).  
- **Partially covered:** constitutional **symlink** swap (SKIPPED EPERM on this host). Claim on symlink refusal rests on code-path inspection + unit structure matching loaders/manifest, not a live green on this run.  
- **Not covered here:** network/supply-chain of how `release.manifest.json` was produced; runtime supervisor destination feed (hook correctly `unavailable`); multi-process races against promote.js during verify; non-Windows probes of rename-success path (this host saw EPERM only).  
- **Residual risk:** D1/D2 above; A6 as published.  
- **Zero-finding claim is INVALID:** this suite actively reports **D1** and **D2**. No catastrophic “dual-yes on typically-tampered core under honest manifests” was observed.

---

## Tester identity

- Family lane: **grok** (`tests/verify/grok/`)  
- Builder of SUT: Claude Sonnet (different family — review separation held)  
- No modifications outside lane; did not edit `scripts/verify.js` or repo state beyond tests under this directory.  
