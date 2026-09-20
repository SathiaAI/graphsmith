# Runbook: gateway-session chain corruption recovery

> Referenced from every `GATEWAY_CHAIN_STRUCTURAL_FAILURE` diagnostic this gateway
> writes (`<state_dir>/gateway-startup-failure.json`) and from every
> `GATEWAY_CHAIN_HEAD_DIVERGED` refusal it logs mid-run. Ships alongside round-1
> fix-plan commit 4 (`chain.reconcileHead` + the classified append-time HEAD/tail
> check) per Paul's 2026-09-15 startup-posture decision
> (`claude/graphsmith-fix-round-plan-round1-2026-09-15.md`,
> `docs/contracts/chain-validity.md` SS4): a hard-failed startup must always end in a
> concrete next step, never just a stopped process. Read this top to bottom before
> touching `chain.jsonl` or `HEAD.json` by hand -- every option below is destructive in
> a different way, and picking the wrong one can destroy attested history that was
> otherwise recoverable.

## 1. Is this actually corruption, or just a lagging pointer?

Not every divergence between `HEAD.json` and `chain.jsonl` needs this runbook. Two
classes of divergence are **not** corruption and are already handled automatically,
under the writer-claim, by this gateway itself:

- **A single-step lagging `HEAD`** (the chain's own tail is exactly one entry ahead of
  `HEAD`, and the link hash matches) is auto-repaired the moment the next session tries
  to append, or at the next startup by `chain.reconcileHead`. This is the ordinary
  signature of a crash between `chain.jsonl`'s own append and `HEAD.json`'s update. You
  do not need this runbook for it -- just restart the gateway (or let the next session
  close normally) and check `gateway.js status` afterward.
- **Any size of lagging `HEAD`, found at startup**, where the chain independently
  verifies end-to-end and `HEAD` names a genuine, hash-verified entry somewhere earlier
  in that same chain, is repaired by `chain.reconcileHead` before the gateway ever
  starts accepting sessions.

If the gateway is refusing to start with a `GATEWAY_CHAIN_STRUCTURAL_FAILURE`
diagnostic (check `<state_dir>/gateway-startup-failure.json`), or a running gateway is
refusing every session close with `GATEWAY_CHAIN_HEAD_DIVERGED` /
`GATEWAY_CHAIN_INTEGRITY_FAILED`, you are past the automatic cases. Read the
diagnostic's `message`/`reason` field first -- it names exactly which of the cases below
you are in (a fork, a broken hash link, a sequence gap, an invalid genesis, HEAD ahead
of the chain's own tail, or an unreadable/torn tail) before you pick a recovery option.

## 2. Before doing anything else

1. **Stop the gateway process** if it is somehow still running (it should already have
   refused to start, or be about to exit after a runtime refusal -- confirm it is not
   silently retrying).
2. **Back up the entire `<state_dir>/gateway-sessions/` directory** (`chain.jsonl`,
   `HEAD.json`, every `<bundle_id>.json`, and the `quarantine/` subdirectory if present)
   to a separate location before touching anything. Every option below assumes you can
   get back to exactly this state if you make a mistake.
3. **Do not delete or hand-edit `chain.jsonl`/`HEAD.json` directly** until you have
   picked one of the three options below and understand its consequences. A single
   `sed`/manual JSON edit that produces a shape-valid-looking record is exactly how a
   silent, undetected fork gets introduced.

## 3. Option A -- restore from backup

**Use this when** you have an independent, trusted backup of `<state_dir>/gateway-
sessions/` taken before the corruption occurred (a nightly snapshot, a filesystem
snapshot, etc.), and the corrupted window since that backup is small enough that losing
the sessions recorded in it is acceptable.

1. Confirm the backup itself verifies: run the chain-integrity check
   (`checks/register-gateway-sessions.js`, or `gateway.js status` once the gateway can
   start against a copy of the backup in a scratch `state_dir`) against the backup
   **before** restoring it over the live directory.
2. Stop the gateway (if not already stopped), replace the live `gateway-sessions/`
   directory with the verified backup, and restart.
3. Any bundles/WALs newer than the backup are now orphaned. Move them to a separate
   `manual-review/` directory outside `state_dir` for a human to inspect -- do not
   delete them; they may still be useful evidence even though they can no longer be
   chain-appended automatically.

**Cost:** every session sealed after the backup was taken is gone from the attested
chain, even if it was otherwise legitimate.

## 4. Option B -- truncate at the last known-good entry

**Use this when** the failure is localized to the chain's own **tail** (the last one or
two records) -- e.g. a torn/unparseable final record from a crash mid-write, or a
tampered/malformed final entry -- and every entry before it verifies cleanly. This is
the right choice when you do **not** have a recent backup but most of the chain's
history is still trustworthy.

1. Run the structural validator against `chain.jsonl` up to (but not including) the
   suspect final record(s) to confirm everything before that point is genuinely intact
   (hashes, links, sequence, genesis). Do not assume -- verify.
2. Truncate `chain.jsonl` to end exactly after the last entry that verified. Use a tool
   that truncates at a byte offset you have confirmed corresponds to a complete,
   newline-terminated record -- never a text editor's own line-ending guess.
3. Rebuild `HEAD.json` from that new, truncated tail (see the exact record shape in
   Option C step 2 below).
4. Move the bundle file(s) for any entries you truncated away into `manual-review/`
   (outside `state_dir`) rather than deleting them.
5. Restart the gateway. `chain.reconcileHead` will confirm the truncated chain verifies
   and that `HEAD.json` matches its new tail before accepting any session.

**Cost:** every entry from the first bad record onward is removed from the attested
chain, whether or not each individual one was itself legitimate (a sequence gap is not
repairable in place -- an entry that comes after a bad one can never be re-attached
without also being re-verified from scratch).

## 5. Option C -- rebuild `HEAD` from the validated chain tail

**Use this when** `chain.jsonl` itself is fully intact and verifies end-to-end, and the
**only** thing wrong is `HEAD.json` -- but the divergence is worse than the single-step
or verified-ancestor cases this gateway already repairs automatically (for example,
`HEAD.json` was manually edited to a bogus value, or points at a `seq` beyond the
chain's own real tail, or was lost/replaced by something that does not correspond to any
real entry in the chain at all).

1. Run the structural validator against the **entire** `chain.jsonl` with `head`
   omitted/ignored to confirm it independently verifies (correct genesis, contiguous
   `seq`, every link hash and entry hash correct) end-to-end. If it does **not**
   verify, stop -- you are actually in Option B or Option A's territory, not this one.
2. Take the chain's own last entry (the highest `seq`, confirmed correct by step 1) and
   write `HEAD.json` as exactly:
   ```json
   {
     "schema_version": "1.0",
     "seq": <that entry's seq>,
     "bundle_id": "<that entry's bundle_id>",
     "entry_sha256": "<that entry's entry_sha256>"
   }
   ```
   Do not hand-construct any field other than by copying it verbatim from the verified
   tail entry.
3. Restart the gateway. `chain.reconcileHead` re-verifies the same thing you just did by
   hand before accepting any session, so a mistake here fails startup again rather than
   silently taking effect.

**Cost:** none to the chain's own history -- this option only ever repairs the pointer,
never the chain -- but it requires you to have correctly confirmed step 1's "fully
intact, end-to-end" precondition; skipping that verification and rebuilding `HEAD` over
a chain that does **not** actually verify silently converts a detectable corruption into
an falsely-"healthy"-looking gateway.

## 6. After recovery

- Confirm `gateway.js status` reports `session_chain_integrity: { status: "verified" }`
  before considering the incident closed.
- Investigate *why* the corruption happened (disk full, a manual edit, a filesystem
  fault, a bug) before it recurs -- none of the three options above address root cause.
- If you used Option A or Option B, the sessions you removed from the attested chain are
  gone from `SG-FR-7`'s guarantee even though their raw bundle/WAL files may still exist
  in `manual-review/`; do not re-append them later by hand -- that would itself be
  exactly the kind of undetectable, unattested mutation this chain exists to prevent.
