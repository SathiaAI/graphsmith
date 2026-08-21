# GraphSmith Attestation (GSA) — Known Limitations

> **Evidence, not certification.** A valid GSA bundle records *what a run requested and produced, and that the record is unaltered* — it does not show the workflow is safe, correct, or compliant. This page consolidates the honesty boundaries stated across [`SECURITY.md`](.plans/v0.3.0/graphsmith-v0.3.0-SECURITY.md), the threat model's residual-risks section, the compliance-evidence crosswalk, and the README. Each limitation states the honest boundary and the control that *partially* addresses it. Nothing here is new scope — it is the scattered caveats gathered in one place.
>
> Language follows the repo's honest-language lint: results are **tested** (not "proven"), records are **tamper-evident** (not "tamper-proof"), pins are **hash-pinned**, external effects are **run-once / replay-verified** (not "exactly-once"), effect behaviour is described by **capability class**, and independent checking is **adversarial review**.

## 1. What GSA verifies
A conformant verifier runs the ordered §9 checks and fails closed at the first violation:
- **Manifest validity + path safety** — the manifest matches the schema; every artifact path is canonical (no traversal, no backslash, NFC).
- **Artifact integrity** — every artifact's recomputed raw-byte SHA-256 and length match the manifest (hash-bound).
- **Manifest + graph signatures** — the record is **tamper-evident**: any change to the manifest or the plan (graph / policy / skill-set hashes) invalidates the signature.
- **Recomputed control attestations** — all five controls are recomputed from the run's own evidence and must match what the bundle claims; a **contradictory bundle does not verify** (e.g. an executed unsigned skill alongside `all_skills_signed_and_approved=true`).
- **Profiles** — a profile the evidence does not support is downgraded to `unavailable`, never rendered green.

*Control:* the reference verifier (`scripts/gsa-verify.js`), exercised by the cross-family adversarial review recorded in `tests/gsa/ADJUDICATION.md`.

## 2. What GSA does NOT verify
- **That a workflow is safe, correct, or compliant.** A passing adversarial-review battery is a **floor**, not a proof of security, and never evidence of compliance to a regulator.
- **Model-level jailbreak / prompt-injection of the LLM itself.** GSA tests *architecture-level* injection resistance — that untrusted text is kept out of control flow and evolution paths — not model internals. *Control:* route model-jailbreak findings to dedicated LLM red-team tools through the external-tool seam, which records their results alongside the bundle.
- **The internals of third-party skills or external tools you install.** GSA records their provenance and runs them under the container capability class; it does not audit their code.
- **Anything with the documented controls disabled** (e.g. running with deterministic/enterprise-safe mode off). The attestation reports the posture it observed; it cannot vouch for a run that turned its controls off.
- **The compliance program itself** — data-layer access control and data minimisation at source; model validation, bias/fairness, and accuracy testing; the human-oversight *process*; risk classification / DPIA; vendor management; and the legal determination of compliance. GSA gives the verifiable technical substrate those programs stand on, and says so. *Control:* the compliance-evidence crosswalk maps each obligation to the control that produces evidence for it, and marks obligations with no executable control as manual-only — never covered.

## 3. Replay limitations
Replay recomputes the **deterministic** hashes from the bundle's own contents and confirms they reproduce. **Model-dependent steps are not replayable** — a run that called a model is reported `non_replayable`, shown as `unavailable`, never green. Replay confirms the record is internally reproducible; it does not re-execute external calls. *Control:* `scripts/gsa-plan.js` `replayBundle`, which lists non-replayable steps explicitly.

## 4. External side-effect limitations
The crash/recovery (chaos) harness tests exactly two properties: crash recovery, and **run-once, replay-verified** execution of *recorded* effects, with a loud halt when an external send's outcome is uncertain. This is **not** exactly-once against the outside world: true **single-delivery to an external system requires an idempotency key that system honours** (an `idempotent-by-key` capability-class declaration by the adapter author, not something GSA verifies). Every unresolved intent defaults to **reconciliation-required** until a rule affirmatively upgrades it. *Control:* the write-ahead intent + loud reconciliation halt (invariant I5) and the adapter capability classes in `contracts/06`.

## 5. Generated-skill limitations
GSA machine-evaluates only typed, schema-validated document/knob edits. **Generated code is never machine-applied** — code repairs are staged for a human through the four-gate pipeline. The `auto_skill_creation_disabled` control attestation records that no autonomously-created, unapproved skill ran in the same trust flow; if one did, the bundle does not verify that control. *Control:* the four-gate promotion pipeline (Gate 3 is propose-only; adoption requires explicit human confirmation) + the recomputed control attestation.

## 6. Per-skill capability limitations
GSA attests **only what is actually enforced**, per resource class:

| Class | Enforced? | By what |
|---|---|---|
| **network** | yes | supervisor destination allowlist; `--network none` under the container profile |
| **filesystem** | **no** | — see below |
| **subprocess** | **no** | — see below |
| **model** | **no** | no mechanism at this layer; needs a chokepoint in the model adapter |

**Per-skill filesystem, model and subprocess grants are NOT enforced.** A grant may declare them; nothing applies them, and the GSA capability attestation never marks them satisfied (decision D1: a class is attested only if it appears in the grant's `enforced` list, and only `network` ever does).

### Why this says "no" rather than "yes, with caveats"

An enforcement module was built on Node's Permission Model (`--permission`, `--allow-fs-read/write`) and **withdrawn**. Five rounds of adversarial review found successive ways for code inside the grant to read or write outside it, each round after the previous had been reported as fixed:

| # | Escape | Status when found |
|---|---|---|
| 1 | pre-existing **symlink** out of the tree | followed by the Permission Model; read `/etc/passwd` through one |
| 2 | pre-existing **hardlink** — a second *name* for the same inode | resolves *inside*, passes any symlink walk, and a **write** through it modifies the file outside |
| 3 | **stale audit** — clean at copy time, link planted after | evidence honest when produced, worthless when used |
| 4 | **forged spelling** — `<dir>/A/../real`, lexical vs physical | clean report for a tree nobody walked |
| 5 | audit contained against the copy, attestation about the **grant** | a link staying inside the copy while leaving the grant |
| 6 | **dangling symlink** | `realpath` fails so the audit skips it, but `open(O_CREAT)` follows it and creates the file at the target |
| 7 | a **granted path that is itself a symlink** | the audit never checked its own root |

The pattern across all seven is one thing: **the check was about a different boundary than the claim.** Each fix was narrower than the last, which is convergence — but the module was shipping a *green attestation*, and a false "enforced" in a signed bundle is worse than an honest "not enforced". So it was removed rather than shipped with a sixth round pending.

**What this costs:** nothing that was previously working. Per-skill grants were never enforced before this attempt either; this section previously said so, briefly said otherwise, and now says so again — accurately.

**What would be needed to do it properly:** the residual hole is a TOCTOU window no user-space audit can close — a link planted between the audit and `exec`. That needs the kernel: a bind mount with `nosuid`/`nodev`, a mount namespace, or a filesystem the enforced process cannot reach under any other name. A path-prefix check applied from user space to a tree an adversary can write to is the wrong tool, and the review history above is what that looks like in practice.

*Control (coarser than per-skill, and real):* the **container capability class** — a whole-run isolation boundary required for anything beyond typed edits (contract 04 B10). It runs untrusted code non-root, with all Linux capabilities dropped, `no-new-privileges`, a read-only rootfs and read-only source mount, network denied, and pid/memory/cpu caps. Each of those is verified by running a container through the real entry point (`evalenv.create("container")` → `runUntrustedCode()`) and reading `/proc/self/status` from inside — see `tests/evalenv/containment/`. That suite also asserts the profile still *functions* (the mount is readable) before making any containment claim, because an envelope nothing can run in is broken rather than secure.

## 7. Signer-trust limitations
GSA verification shows a bundle **was signed by the claimed key and is unaltered**. Whether to **trust that key is the verifier's policy** — an allowlist, an org key, or a transparency log (GSA-SPEC §5.5). The default is a local keypair, which attests "signed by *a* key"; cross-organisation non-repudiation is weaker until keyless / transparency-log signing (opt-in, targeted for a later draft). A **privileged local attacker** who can already rewrite the producer, the verifier, and the signing keys on the same machine is **out of scope, stated as such** — local self-verification detects same-user drift and mistakes, not a root adversary; CI cross-checking from a trusted workflow covers shared repositories. *Control:* the verifier-supplied trusted-key set + out-of-band maintainer signature for air-gapped verification (register Lane D, v0.3.0).

## 8. The state-store lock is not tied to a file descriptor
Exclusive access to `.graphsmith/state` is held by a **lock file plus an mtime and a pid**, not by the operating system. The textbook alternative — a lock whose lifetime is bound to the owner's open file descriptor, so that the kernel releases it the instant the owner dies — **cannot be built here at zero runtime dependencies**, and this is recorded as a limitation rather than tracked as pending work because nothing about it is pending.

Node exposes no file locking at all. On the exact runtime CI uses:

```
$ node -e "const fs=require('fs'); console.log(process.version, typeof fs.flock, fs.constants.O_EXLOCK)"
v22.22.2 undefined undefined
```

There is no `fs.flock`, no `fcntl`, no `O_EXLOCK`, and no `LOCK_*` constant on any supported platform. The three ways out are each worse than the limitation: a **native addon** (`fs-ext` and equivalents) requires prebuilds or `node-gyp` across {ubuntu, macos, windows} x node {18, 22} and ends GraphSmith's zero-dependency property, which is itself a security claim for something installed into a developer toolchain; **shelling out to `flock(1)`** is not portable — it is absent from a standard Windows environment and its availability on macOS is package-dependent; and `open(..., "wx")` / `mkdir`, which is what is used today, is genuinely atomic but is not bound to the process.

**What this costs, precisely.** Ownership has to be inferred from two observable facts instead of held by the kernel: is the owning pid observably alive, and has the lock been renewed recently. Both are approximations of the fact actually wanted, which is *"is the owner still making progress"*:

- a holder doing long work **without touching the store** renews nothing, so a sufficiently long non-store phase is stealable — the lock is only refreshed at the durable writes inside `_commit`;
- `pid` liveness is not owner identity. A crashed owner in a foreign pid namespace, or a recycled pid, can read as alive. This costs a bounded wait (at most one lease) and never a false steal, because a steal additionally requires the lock to have gone unrenewed;
- the age is a **wall-clock subtraction** against a filesystem mtime and is therefore not monotone. That one used to be a wedge — a lock whose mtime sat in the future was read as freshly renewed and refused indefinitely, including to `recover()` — and is now gated explicitly (contract 01 clause (d), `tests/state-store/clock-skew/`). The gate makes the failure honest; it does not make the mtime a reliable clock.

*Control:* both gates must agree before a lock is taken (`scripts/state-store.js`), renewal happens synchronously at every durable write rather than on a timer that could not fire, `_assertStillOwned` stops a superseded run **before** it writes rather than at release, and every reachable lock state is pinned by `tests/state-store/clock-skew/` with mutation controls.

**What would be needed to do it properly:** a decision that a native dependency is acceptable, *and* a real deployment with concurrent writers to justify it. Neither holds today — single-writer use does not exercise the gap, and adding a compiled dependency to remove a hazard that use does not reach would be a net loss in the property that matters more.

## 9. The MCP shim seals a session it is handed — it does not capture live traffic

`scripts/gsa-mcp-shim.js` (`sealBoundaryBundle`) takes an already-assembled `session` object — `initialize`, the granted `tools[]`, and the `calls[]` already made — and maps it into a signed boundary-tier (profile A) attestation bundle. That is the whole of what exists: hashing, tracing, and sealing data that is passed in. **Nothing produces that `session` object from a live MCP connection.**

The design doc ([`.plans/v0.3.0/graphsmith-v0.3.0-mcp-attestation-shim-design.md`](.plans/v0.3.0/graphsmith-v0.3.0-mcp-attestation-shim-design.md), §4) describes four deployment modes for capturing real traffic: a local proxy sitting between an MCP client and its servers, a client-side plugin hooking an agent's MCP middleware, server-side middleware wrapping a tool server, and a gateway integration for enterprise MCP gateways. **None of the four exist in code.** There is no JSON-RPC interceptor, no stdio wrapper, no HTTP reverse proxy, and no gateway-attachment point anywhere in the tree — confirmed by grepping the current source for `gateway`/`proxy`/`interceptor`: the only hits are an unrelated word-count comment and a JS `Proxy`-trap comment, neither part of MCP capture.

**What this costs, precisely.** A caller who wants a real boundary attestation for a live MCP session must build the capture themselves — record `initialize`, `tools/list`, and every `tools/call` into the `session` shape the shim expects — before `sealBoundaryBundle` can do anything. The shim's own selftest (`--selftest` in the same file) demonstrates this: it hand-constructs a `session` literal in the test rather than deriving one from a running MCP exchange, because there is no code path that would derive one.

*Control:* the shim's contract is narrow and honestly scoped — it never claims to observe anything beyond the `session` object it is given (the file's own header comment states the boundary-only, profile-A-never-full-profiles limit), and the produced bundle's `decision_record.md` states plainly that the agent's plan was not observed. There is no false "captured live" claim anywhere in the emitted bundle.

**What would be needed to do it properly:** implement one of the four deployment modes in §4 of the design doc — most naturally the local proxy, since it needs no changes to the agent or to any MCP server. That is unbuilt work, not a documentation gap.

---
*This document is publication-hygiene clean. See also the worked offline-verifier transcript in [`docs/examples/offline-verify.md`](docs/examples/offline-verify.md).*
