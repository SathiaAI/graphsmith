# GSA attach-mode shim -- wiring guide for an embedding gateway

**Audience:** an enterprise integrator whose own MCP gateway process already calls
`scripts/gsa-mcp-shim.js`'s `sealBoundaryBundle()` per observed MCP session, and now
needs to wire in the attach-mode preconditions FR-7 describes: a live writer-claim held
for the whole process lifetime, gated by this deployment's confirmed gateway mode.

**Module:** `scripts/gsa-attach-shim.js`, exporting `AttachModeShim`.

**What this is not:** a standalone server, a process supervisor, or anything that owns
its own process lifecycle. It is a library your already-running gateway process
`require()`s. It never calls `process.exit()` and never installs its own signal
handlers -- every lifecycle decision below is something *your* process does, using the
three methods this shim exposes (`start()`, `stop()`, `status()`).

## The exact call sequence

### 1. At process startup, before accepting any MCP session

```js
const { AttachModeShim } = require("graphsmith/scripts/gsa-attach-shim.js");

const shim = new AttachModeShim(process.cwd(), {
  // optional overrides -- all pass straight through to WriterClaim unmodified:
  // hostId, instanceId, heartbeatMs, staleAfterMs, skewToleranceMs, clock, onClaimLost
});

try {
  shim.start();
} catch (error) {
  // FR-1's refusal message is already in error.message; error.code is one of:
  //   GATEWAY_MODE_NOT_DECLARED | GATEWAY_MODE_UNREADABLE | GATEWAY_MODE_MALFORMED |
  //   GATEWAY_MODE_INVALID | GATEWAY_MODE_NOT_CONFIRMED | GATEWAY_MODE_KEY_MISSING |
  //   GATEWAY_MODE_CONFIRMATION_MISMATCH | GATEWAY_MODE_WRONG_BINARY |
  //   WRITER_CLAIM_FOREIGN_HOST | WRITER_CLAIM_HELD | WRITER_CLAIM_CLOCK_SKEW |
  //   WRITER_CLAIM_AMBIGUOUS | WRITER_CLAIM_CONTENTION | WRITER_CLAIM_NO_HOST_ID
  console.error(error.message);
  process.exit(1);   // YOUR process decides to exit -- the shim never does this itself
}
```

`shim.start()` does exactly three things, in this order, and throws before doing the
next one if the previous one fails:

1. Reads and validates `.graphsmith/gateway-mode.json` against the mode-selection
   contract (schema + HMAC confirmation check), refusing unless it declares and confirms
   `mode: "attach"`.
2. Calls `WriterClaim.acquire()` against `.graphsmith/state`, refusing (with FR-1's
   existing named-identity refusal message) if another instance already holds the claim.
3. Calls `WriterClaim.startHeartbeat()`.

This happens **once per process**, at startup -- not per MCP session, per FR-7's own
wording ("acquired via `WriterClaim.acquire()` at process startup (not per-session)").

### 2. Per observed MCP session -- unchanged, nothing to wire

Keep calling `sealBoundaryBundle()` from `scripts/gsa-mcp-shim.js` exactly as you already
do, at whatever call site you already have. This shim does not sit in that path, wrap it,
or need to be told about it. If `shim.start()` above returned without throwing, the
writer-claim precondition FR-1 requires before *any* MCP session is already satisfied for
the rest of this process's life (kept alive by the heartbeat) -- there is nothing further
to check per-session.

### 3. On clean shutdown

```js
function shutdown(signal) {
  try {
    shim.stop();   // stops the heartbeat, releases the writer-claim
  } finally {
    process.exit(0);
  }
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
```

`shim.stop()` is idempotent and safe to call even if `start()` never completed (e.g. it
threw before acquiring). Call it from whatever shutdown path your process already has --
it does not need to be the only thing that runs on SIGTERM/SIGINT.

### 4. Optional: health-check surface

```js
shim.status();
// => { started: boolean, mode: "attach" | null, writerClaim: <WriterClaim.status() shape> }
```

Safe to call at any time; never throws.

## What this shim deliberately does NOT do

- It does not know about or call `sealBoundaryBundle()` -- see step 2 above.
- It does not implement FR-8 (host-identity collision resistance) -- `WriterClaim`'s
  existing `os.hostname()`-based `defaultHostId()` is used unmodified. Track 2.1's scope.
- It does not update `KNOWN-LIMITATIONS.md` (AC-5) -- Track 2.2's scope.
- It does not implement FR-9 (synchronous heartbeat-starvation hardening) or FR-10
  (crash-window guarded auto-recovery) -- both are explicitly deferred in the TRD pending
  a real caller with known synchronous call-graph/operational-surface shape. If your
  gateway's own per-session work includes a synchronous section that could plausibly run
  longer than `staleAfterMs` (default 45s), that is exactly the audit FR-9 asks for
  before it can be scoped -- flag it rather than assuming this shim covers it.
- It does not write `.graphsmith/gateway-mode.json` or
  `.graphsmith/state/gateway-mode.key` -- those are owned exclusively by the
  `graphsmith gateway mode set` CLI (mode-selection contract, MS-FR-2/MS-FR-3). This
  shim only ever reads them.
