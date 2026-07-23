# FINDINGS — adversarial test of `scripts/adopt.js` (family: grok)

**Lane:** `tests/adopt/grok/` only (no `scripts/` edits)  
**Runner:** `node tests/adopt/grok/run-tests.js`  
**Verdict source:** on-disk state (`ACTIVE`, `adoption-log.jsonl`, `pending-proposals.jsonl`, `window.json`, journal) + exit codes — never log string matching  
**Last run:** PASS=63 FAIL=4 SKIPPED=0 → **exit 1**

---

## Executive summary

Core confirmation gate (`opts.confirm === true || opts.yes === true`) is **strict** and resists type-coercion smuggling for API callers.  
Happy path confirmed adopt → promote → Gate-4 OBSERVING → observe → close(pass) is **correct on disk**.  
Double-adopt tombstones cleanly; siblings intact; corrupt mid-file JSONL fails closed.

**Four defects** remain (one HIGH confirmation-trap, one HIGH close semantic hole, two MEDIUM). Zero-finding review would be invalid.

---

## Defects

### D1 — HIGH — CLI confirmation trap: `--yes false` still adopts

**Attack:** `node scripts/adopt.js adopt <id> --yes false --project-root <tmp>`  
**Observed:** exit 0, `adopted:true`, ACTIVE/adoption-log/window mutated.  
**Root cause (`scripts/adopt.js` `parseFlags`):**
```js
if (a === "--yes" || a === "-y") flags.yes = true;
// ...
else positional.push(a);  // bare "false" becomes positional junk
```
`--yes` is a pure boolean flag; the following token `false` is **not** bound as its value. Operators / agents scripting “explicit denial” get a silent adopt.

**Fix:**
1. Prefer value-taking form: `--yes=true` only, or reject bare `--yes` when next argv is a boolean-looking token (`false`/`0`/`no`).
2. Or parse `--yes <bool>` and require explicit true via `["1","true","yes"].includes(v)`.
3. Refuse adopt unless a dedicated confirmation channel is unambiguously true; never treat unknown positionals as ignorable after `--yes`.

**Disk evidence:** `cli-confirm:cli-adopt-yes-false-token` FAIL — `mut=changed:active`.

---

### D2 — HIGH — `close(..., "fail")` silently maps to `CLOSED_PASS`

**Attack:** After confirmed adopt + filled canary slot, `close(root, txid, "fail")`.  
**Observed:** window state → `CLOSED_PASS`; ACTIVE still on adopted tree.  
**Root cause:** `adopt.close` is a thin delegate to `gate.gate4Close` → `stateStore.closeWindow`.  
`closeWindow` only special-cases:
- `rolled_back` → `CLOSED_ROLLED_BACK`
- `halt_human` → `HALT_HUMAN`
- `flagged` / flag bit → `CLOSED_FLAGGED`
- hard slot disposition → `ROLLING_BACK`
- **else → `CLOSED_PASS`**

Literal `"fail"` (and any unknown string) **passes** the canary window. Task contract (`C-adopt-test` / contract 02) expects fail → rollback (doc/knob inverse) or refuse (code) — not a silent pass.

**Fix (adopt.js and/or state-store):**
1. Closed outcome vocabulary: accept only `pass | rolled_back | flagged | halt_human` (and maybe `fail` as alias).
2. Unknown outcomes → throw `INVALID_ARGUMENT` (fail-closed).
3. Map documented `fail` to the Gate-4 hard/soft path or require callers use `rolled_back` after invoking `promote.rollback`.

**Disk evidence:** `close-fail:outcome-fail-literal` FAIL.

---

### D3 — HIGH / contract gap — `close(..., "rolled_back")` does not execute inverse promote

**Attack:** `close(root, txid, "rolled_back")` after canary terminalized.  
**Observed:** window → `CLOSED_ROLLED_BACK` (**PASS**), but ACTIVE bytes **unchanged** (still adopted tree).  
**Contract 02 / 01:** ROLLING_BACK / rolled-back path “Executes the pre-authorized inverse via contract 01”.  
**adopt.close** only flips window state; it never calls `promote.rollback(txid)`. A human or healer reading “CLOSED_ROLLED_BACK” may believe ACTIVE was inverted when it was not.

**Fix:**
1. `adopt.close(projectRoot, windowId, "rolled_back"|"fail")` should orchestrate: close window intent → `promote.rollback(windowId)` for doc/knob+reversible+auto_rollback_eligible → refuse with `FORWARD_RECOVERY_REQUIRED` for code/migration.
2. Or document that close is **window-only** and require a separate `adopt.rollback` command — and make `rolled_back` close refuse unless inverse already committed (soor ACTIVE already restored).

**Disk evidence:** `close-fail:rolled_back-ACTIVE-note` FAIL — ACTIVE identical before/after close.

---

### D4 — MEDIUM — `adopt(root, id, null)` throws instead of structured refuse

**Attack:** `adopt(projectRoot, proposalId, null)`  
**Observed:** `TypeError: Cannot read properties of null (reading 'confirm')`  
**Impact:** confirmation path does not fail-closed with `{adopted:false, refused:true, reason:ADOPTION_REQUIRES_HUMAN_CONFIRMATION}`; callers that catch loosely may mis-handle. Disk untouched (no adopt) — so not a silent adopt, but not the required refuse shape.

**Fix:**
```js
opts = opts && typeof opts === "object" && !Array.isArray(opts) ? opts : {};
```
before reading `confirm`/`yes`.

**Disk evidence:** `confirm-bypass:api-opts-null` FAIL; ACTIVE/pending unchanged.

---

## Attacks that passed (selected)

| Attack | Result | Notes |
|---|---|---|
| API missing/`false`/string/`0`/`1`/`"yes"`/`{}`/`[1]`/`Object(true)` confirm | PASS | Strict `=== true` |
| `yes: "true"` / `yes: 1` API | PASS | Refused |
| Extra 4th arg `true` smuggle | PASS | Ignored |
| `__proto__` / string `"TRUE"` smuggle | PASS | Refused |
| CLI without `--yes`, bare `--confirm`, `--yes=true` token | PASS | No disk mutation |
| CLI `--yes` positive control | PASS | Adopts; ACTIVE moves |
| `listPending` / CLI list / observe / close side effects | PASS | No ACTIVE/log/pending adopt |
| Static only-path: only `adopt.js` calls `promoteApi.promote` | PASS | evolve uses `recover` only |
| Double-adopt + sibling B | PASS | Tombstone ADOPTED; B pending; append-only |
| Mid-file corrupt JSONL | PASS | `CORRUPT_STATE`, no partial adopt |
| Torn tail | PASS | Prior good line still adoptable |
| Path traversal edit `../../outside.txt` | PASS | `INVALID_PACKET`, no escape write |
| Status spoof `ADOPTED` without tombstone via adopt | PASS | `PROPOSAL_NOT_PENDING` |
| E2E confirm → WINDOW_PENDING/FINAL → OBSERVING → observe → close(pass) keeps tree | PASS | Full disk chain |

---

## Confirmation guarantee (THE requirement)

| Path | Must | Verdict |
|---|---|---|
| `adopt(root,id)` / `{confirm:false}` / truthy-but-wrong | REFUSE + disk frozen | **HOLD** (API) |
| CLI without `--yes` | REFUSE + disk frozen | **HOLD** |
| CLI `--yes false` | REFUSE | **BROKEN (D1)** |
| Only `{confirm:true}` / `--yes` adopts | yes | **HOLD** (plus intentional `{yes:true}` API alias for CLI binding) |
| list/observe/close never adopt | yes | **HOLD** |
| Double-adopt refuses | yes | **HOLD** |
| Fail-closed malformed pending | yes | **HOLD** |
| close(fail) correct per contract 02 | rollback or refuse | **BROKEN (D2, D3)** |

---

## Severity rollup for builder

1. **D1** — fix `parseFlags` confirmation parsing (security-tier trap).  
2. **D2** — close outcome whitelist; never default unknown → PASS.  
3. **D3** — wire inverse promote on rollback close, or refuse close until inverse done.  
4. **D4** — normalize `opts` before property access.

---

## How to re-run

```bash
node tests/adopt/grok/run-tests.js
```

Temp dirs under OS tmp (`gs-adopt-grok-*`); cleaned at end. Never touches repo `.graphsmith/`.
