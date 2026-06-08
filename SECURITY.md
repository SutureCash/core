# Security

## Status

Pre-launch. The program runs on devnet and in an in-process test suite. It has **not**
been independently audited and is **not** deployed to mainnet. Do not use it with real
funds until the pre-mainnet checklist below is done.

This repository is the **SOL side** of the swap — the on-chain escrow program and the
host-side engine. The Monero side lives in the companion
[`monero`](https://github.com/SutureCash/monero) repo: 2-of-2 key aggregation, shared-address
derivation, and a `monero-wallet-rpc` lock/scan/sweep driver that's been run end-to-end on
stagenet. The cross-chain swap state machine — the decision logic that sequences both sides lives in `engine/swap.rs`, with the executor seam and a full two-party simulation in
`engine/executor.rs` (both pure and exhaustively tested). Still missing: the daemon that
implements that seam over live chains (Solana RPC + `monero-wallet-rpc`) and the
maker/taker discovery on top. So end-to-end protocol safety still depends on code that
doesn't exist in this repo yet.

## What the on-chain program enforces

- **Account identity.** Every settle path (`claim`/`refund`/`set_ready`/`close`) checks
  the escrow account is owned by the program, is exactly the expected size, and sits at
  the PDA re-derived from its own `(locker, id, bump)`. A look-alike account is rejected.
- **Commitment points.** At `lock`, both committed points are checked to be on the
  Ed25519 curve and not the identity point (which would have the trivial secret `0`).
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
  must. If it's skipped, a malicious counterparty can commit a point Alice can't use.
- **Second-mover griefing.** Bob can watch Alice lock her XMR and then abort (early
  refund) before `t0`. No one loses principal — Bob's refund reveals `s_b`, so Alice
  recovers her XMR — but Alice still pays the Monero transaction fees for a swap that
  never completed. This is inherent to atomic swaps where one side commits first on the
  costlier chain. Mitigations: the taker waits for `set_ready` (or locks close to `t0`)
  before committing XMR; a maker bond can be added later.
- **Non-canonical point encodings.** The on-chain curve check accepts non-canonical (but
  on-curve) encodings. A non-canonical commitment can only brick its _own_ swap (a
  griefing/DoS, never theft), and it's caught by the off-chain canonical check above.
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
      (under `@solana/web3.js` → `jayson`). It affects **client/test tooling only**, not
      on-chain code. Do **not** run `npm audit fix --force` — it downgrades `@solana/web3.js`
      to a broken version. Pin a fixed `uuid` via a package override instead.
- [ ] **Fuzz / property-test** the timelock windows and the reveal check, and pin a
      reproducible build of the program.

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
