# Security

## Status

Pre-launch. The program runs on devnet and in an in-process test suite. It has **not**
been independently audited and is **not** deployed to mainnet. Do not use it with real
funds until the pre-mainnet checklist below is done.

This repository holds the on-chain escrow program, the host-side engine, and the
maker/taker daemon. The Monero side lives in the companion
[`monero`](https://github.com/SutureCash/monero) repo: 2-of-2 key aggregation, shared-address
derivation, and a `monero-wallet-rpc` lock/scan/sweep driver that's been run end-to-end on
stagenet. The cross-chain decision logic that sequences both sides lives in `engine/swap.rs`,
with the executor seam in `engine/executor.rs` (both pure and exhaustively tested). The
`daemon/` crate implements that seam over live chains — the `sol-escrow` program via Solana
RPC (`sol.rs`) and the Monero driver via `monero-wallet-rpc` (`xmr.rs`) — and `live.rs` is
the watcher + run loop that turns chain state into the machine's events. It is proven offline
by a two-party simulation driven through the real watcher (happy path + abort / griefing /
late-refund recoveries), and `examples/swap_devnet.rs` is the live runner.

What that still leaves open, and why it matters for safety:

- **The full swap has not yet been run hands-off on live devnet + stagenet.** The pieces are
  tested in isolation and against an in-process simulation; the first real end-to-end run is
  the next milestone. Until then, treat the daemon as unproven against real network timing.
- **No crash-resume yet.** A daemon that stops mid-swap must be restarted manually; it does
  not reconstruct the swap phase from on-chain state. The on-chain timelocks keep funds
  recoverable in the meantime, but an operator has to act.
- **No maker/taker discovery.** Counterparties and terms are configured by hand, so there is
  no protection yet against malicious offers beyond the per-swap checks below.

## What the on-chain program enforces

- **Account identity.** Every settle path (`claim`/`refund`/`set_ready`/`close`) checks
  the escrow account is owned by the program, is exactly the expected size, and sits at
  the PDA re-derived from its own `(locker, id, bump)`. A look-alike account is rejected.
- **Commitment points.** At `lock`, both committed points are checked to be on the
  Ed25519 curve, canonically encoded (`y < p`), and not the identity point (which would
  have the trivial secret `0`). Prime-order subgroup membership is _not_ verified on-chain
  (see the limitation below).
- **Reveal canonicality.** A revealed scalar is rejected unless it is canonical (`< L`)
  _before_ the curve op, so the on-chain syscall's mod-L reduction can't let a malleable
  alias (`s`, `s + L`, ...) settle and store an unusable Monero key half.
- **One settlement.** The two timelock windows are disjoint — at most one of claim/refund
  is valid at any instant — and a `settled` flag makes it fire exactly once.
- **Bounded fee.** The routing fee is capped at 3% (300 bps) and is computed with a
  128-bit intermediate; the claimer payout uses checked arithmetic.
- **Reveal binding.** A claim/refund only succeeds if `reveal · G` equals the committed
  point, computed on-chain with the curve25519 syscall.
- **Funds only move to the committed parties** (`claimer`, `fee_recipient`, `locker`); a
  payout target can't be the escrow account itself.

## Known limitations and assumptions

Read these before trusting the protocol with anything real.

- **An off-chain check is load-bearing.** Before Alice locks her XMR, her client _must_
  verify that the on-chain `claim_point` equals `s_a · G` — i.e. that the committed
  Solana point really is her Monero key half. The chain cannot enforce this; the client
  must. If it's skipped, a malicious counterparty can commit a point Alice can't use. The
  daemon enforces it: `LiveChains::lock_xmr` (`daemon/src/live.rs`) refuses to lock and
  raises a fault if the commitment doesn't match, and there's a test that asserts this.
  Any other client has to do the same — it's a protocol obligation, not just this one's.
- **Second-mover griefing.** Bob can watch Alice lock her XMR and then abort (early
  refund) before `t0`. No one loses principal — Bob's refund reveals `s_b`, so Alice
  recovers her XMR — but Alice still pays the Monero transaction fees for a swap that
  never completed. This is inherent to atomic swaps where one side commits first on the
  costlier chain. Mitigations: the taker waits for `set_ready` (or locks close to `t0`)
  before committing XMR; a maker bond can be added later.
- **Prime-order subgroup membership is unverified.** The on-chain check confirms a committed
  point is on-curve, canonically encoded, and non-identity, but it cannot cheaply prove the
  point lies in the prime-order subgroup (there is no syscall for it). A torsion or otherwise
  non-prime-order committed point can only brick its _own_ swap — no scalar `s·G` ever equals
  it, so its reveal can never settle (a griefing/DoS, never theft) — and it is caught by the
  taker's off-chain `claim_point == s_a·G` check before any XMR is locked.
- **Timelocks use the validator clock.** `unix_timestamp` is validator-estimated and can
  drift. The program enforces a 10-minute minimum window, but clients should still set
  generous margins so neither side is pushed out of its window by skew.

## Pre-mainnet checklist (blockers)

- [ ] **Independent security audit** of the full protocol.
- [ ] **Finalize the program.** Set the upgrade authority to a published, timelocked
      multisig/governance, or make the program immutable (`solana program deploy --final`).
      A live unilateral upgrade key can replace the program with one that drains every
      escrow — which would void the "no custodian, trust only the math" guarantee.
- [ ] **Run `cargo audit`** against the committed `Cargo.lock` (RustSec advisory DB).
- [ ] **Resolve the npm advisory.** There is a moderate advisory in a transitive `uuid`
      (under `@solana/web3.js` -> `jayson`). It affects **client/test tooling only**, not
      on-chain code. Do **not** run `npm audit fix --force` — it downgrades `@solana/web3.js`
      to a broken version. Pin a fixed `uuid` via a package override instead.
- [ ] **Fuzz / property-test** the timelock windows and the reveal check, and pin a
      reproducible build of the program.
- [ ] **Bind the reveal to the settler's signature** (recommended hardening). `claim` and
      `refund` authorize by reveal-knowledge alone and do not require `claimer`/`locker` to
      sign. An on-chain observer who extracts a pending reveal from the mempool can front-run
      the settler with their own transaction — funds still go to the committed party, but the
      secret is published at an attacker-chosen moment, widening the front-run surface. Adding
      `claimer.is_signer` / `locker.is_signer` removes it. Deferred because it is an invasive
      cross-layer change (program + TS bindings + daemon settle paths) that must land together.

## Trust model

Suture is self-custodial: you hold your own keys throughout, and the program never takes
custody of your coins — it escrows the SOL side and releases it on a cryptographic
reveal. Until the upgrade authority is finalized (see the checklist), you are also
trusting whoever holds that authority. That is the one piece of the "trustless" claim
that is not yet true, and it is a mainnet blocker.

## Reporting a vulnerability

Please report security issues privately — do not open a public GitHub issue.

- Preferred: a GitHub private security advisory via the repository's **Security** tab
  ("Report a vulnerability").
- Or reach the team on Telegram: https://t.me/SutureCash

There is no bug bounty yet (pre-launch), but responsible disclosure is appreciated and
will be credited.
