# Worked example — offline GSA verification (network denied)

This is release evidence: the reference GSA verifier checking a golden bundle with the **network denied** (socket-denial). Every `net`/`http`/`https`/`dns` entry point is replaced with a tripwire that throws, so any attempted network I/O during verification would fail loudly. Verification completes because it is a pure, offline procedure — it reads the bundle, recomputes hashes, and checks signatures locally.

The transcript below is **real, captured output** — not fabricated. Reproduce it yourself:

```bash
node scripts/gsa-offline-demo.js
```

The runner (`scripts/gsa-offline-demo.js`) installs the socket-denial tripwire, produces a golden regulator-mode bundle with the reference producer, signs it with a local ed25519 key, then runs the ordered §9 checks. Steps that are unavailable are shown as `UNAVAILABLE`, never green.

## Transcript

```
GraphSmith Attestation — offline verification (network denied via socket-denial)
node v24.18.0 · verifier scripts/gsa-verify.js · bundle gsa-abcdef0123456789
mode=regulator  asserted-profiles=[A,X]

  §9 step                       status        note
  --------------------------------------------------------------------------
  9.1  manifest validity        PASS          schema + required structure
  9.2  path safety              PASS          no traversal / backslash / non-NFC
  9.3  artifact integrity       PASS          raw-byte SHA-256 + length hash-bound
  9.4  conditional presence     PASS          regulator_summary present (mode=regulator)
  9.5  manifest signature       PASS          tamper-evident; recomputed manifest hash matches
  9.6  graph signature          PASS          graph||policy||skill-set hashes bound + signed
  9.7  capability conformance   UNAVAILABLE   network-egress + external-call presence attested; per-skill grant = v0.4.0
  9.8  skill provenance         PASS          skill_set_hash binds all executed skills (checked in 9.6)
  9.9  control attestations     PASS          all 5 recomputed from evidence, match the claims
  9.10 profiles                 PASS          confirmed=[A,X] downgraded=[]
  9.11 replay                   UNAVAILABLE   model-dependent run; deterministic hashes reproduce; non-replayable=[model_call]
  --------------------------------------------------------------------------
  OVERALL: PASS   (a PASS asserts only §1 scope: what ran + record unaltered — not safety/correctness/compliance)

network tripwire: intact — no net/http/https/dns call was made during verification.
```

## What this shows — and what it does not

- **Offline.** The tripwire stayed intact: no `net`/`http`/`https`/`dns` call was made. Verification needs no network — it is a local, hash-and-signature procedure.
- **Ordered, fail-closed.** The §9 checks run in order; a real bundle would stop at the first violation. Here a valid, signed bundle passes each implemented step.
- **Unavailable is not green.** Two steps are honestly `UNAVAILABLE`, not passed:
  - **9.7 capability conformance** — v0.3.0 attests network egress + external-call presence; per-skill filesystem/model/subprocess grant enforcement is targeted for v0.4.0 (see [`KNOWN-LIMITATIONS.md`](../../KNOWN-LIMITATIONS.md) §6).
  - **9.11 replay** — this run called a model, so its model-dependent step is `non_replayable`; the deterministic hashes still reproduce (see [`KNOWN-LIMITATIONS.md`](../../KNOWN-LIMITATIONS.md) §3).
- **A PASS is narrow.** It asserts only that the record is complete and unaltered and reflects what ran — not that the workflow is safe, correct, or compliant.

See [`KNOWN-LIMITATIONS.md`](../../KNOWN-LIMITATIONS.md) for the full honesty boundary and [`tests/gsa/ADJUDICATION.md`](../../tests/gsa/ADJUDICATION.md) for the verifier's cross-family adversarial review.
