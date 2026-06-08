# Suture core

[![CI](https://github.com/SutureCash/core/actions/workflows/ci.yml/badge.svg)](https://github.com/SutureCash/core/actions/workflows/ci.yml)

The protocol behind [suture.cash](https://suture.cash): trustless, self-custodial
atomic swaps between Monero (XMR) and Solana (SOL). No bridge, no custodian, no
wrapped tokens. Two people trade directly, and cryptography is the only thing
either side has to trust.

This repository is the **core**: the on-chain Solana program, the host-side swap
engine, and the daemon that runs the two together against live chains. The Monero side
(2-of-2 keys + wallet driver) lives in the companion
[`monero`](https://github.com/SutureCash/monero) repo; the desktop/GUI client that drives
it all lives in a separate repo.

> Status: pre-launch. The program runs end to end on a local validator and in an
> in-process test suite. It has **not** been audited and is **not** on mainnet. Use
> devnet/testnet only until that changes.

## How a swap works

Alice holds XMR and wants SOL. Bob holds SOL and wants XMR.

1. **Shared key.** Each side generates a Monero key half — a scalar on the Ed25519
   curve. Alice has `s_a`, Bob has `s_b`; the public points are `P_a = s_a·G` and
   `P_b = s_b·G`. The XMR gets locked to the 2-of-2 address `P_a + P_b`, whose spend
   key is `s_a + s_b` — a number neither of them knows alone.
2. **Bob locks SOL** in the escrow program, naming `P_a` as the claim point and
   `P_b` as the refund point.
3. **Alice locks XMR** in the 2-of-2 address.
4. **Alice claims the SOL** by revealing `s_a`. The program checks `s_a·G == P_a`,
   releases the SOL, and the revealed `s_a` is now on-chain. Claiming and revealing
   are the same step.
5. **Bob sweeps the XMR** by reading `s_a`, adding his `s_b`, and spending the 2-of-2.

If Alice never claims, two timelocks let Bob refund his SOL by revealing `s_b`, which
lets Alice rebuild `s_a + s_b` and recover her XMR. Whatever happens, no one can walk
away with both coins.

### One curve, no DLEQ proof

Monero and Solana both sign on Ed25519. So a single point `P_a` is at once Alice's
Solana claim commitment and her Monero public key half — same bytes, nothing to
convert. The closest prior art, the ETH⇄XMR swap, has to carry a discrete-log-equality
proof because Ethereum verifies on secp256k1 while Monero is on Ed25519. Suture skips
that entirely, and the program verifies the reveal with Solana's `curve25519` syscall.

### The two timelocks

A single escrow can be claimed or refunded, never both. The windows are arranged so
they can't overlap:

- before `t0`, and before Bob calls `set_ready`: only Bob can refund (an early abort
  if Alice never locked her XMR);
- once ready, or after `t0`, and before `t1`: only Alice can claim;
- at or after `t1`: only Bob can refund (Alice missed her window).

## Layout

```
programs/sol-escrow/   the on-chain program (native Rust, builds to BPF)
engine/                host-side swap engine: state machine + key math + reveal checks (Rust)
daemon/                maker/taker daemon: runs the engine against live Solana + Monero (Rust)
client/                TypeScript bindings + a live end-to-end SOL-side swap script
tests/                 program test suite (solana-bankrun, in-process)
```

The `engine` decides _what_ each party should do (a pure state machine, no I/O); the
`daemon` is what _does_ it — it depends on both this repo's Solana program and the sibling
`monero` repo's wallet driver, implements the engine's `SwapChains` seam over Solana RPC and
`monero-wallet-rpc`, and turns chain confirmations back into the machine's events. That
cross-repo dependency is the seam where the two halves of the protocol finally meet.

## Build and test

Prerequisites: the [Solana CLI](https://docs.anza.xyz/cli/install) (provides
`cargo-build-sbf` and `solana-test-validator`), a Rust toolchain, and Node.

```bash
# on-chain program -> target/deploy/sol_escrow.so
cd programs/sol-escrow && cargo build-sbf && cd ../..

# program test suite (lock / claim / refund / timelocks / fees / reveal)
npm install
npm test

# host-side engine
cd engine && cargo test && cargo run --example walkthrough && cd ..
```

## Run a real swap

Against a local validator (deterministic, no faucet needed):

```bash
solana-test-validator --reset &              # in another shell
solana config set --url localhost
solana airdrop 5
solana program deploy target/deploy/sol_escrow.so \
  --program-id target/deploy/sol_escrow-keypair.json
RPC_URL=http://127.0.0.1:8899 npm run devnet
```

Against devnet, fund the address `solana address` prints (the CLI faucet is often
rate-limited — https://faucet.solana.com works in a browser), then:

```bash
solana config set --url devnet
solana program deploy target/deploy/sol_escrow.so \
  --program-id target/deploy/sol_escrow-keypair.json
npm run devnet
```

The script locks SOL, opens the claim window, claims by revealing `s_a`, and then
checks on-chain that the secret was published and that `s_a + s_b` reconstructs the
Monero key.

## Run the full cross-chain swap

`npm run devnet` proves the SOL side only. The `daemon` runs a _whole_ swap — SOL on
devnet and XMR on Monero stagenet — hands-off, driven by the engine. It needs the sibling
`monero` repo checked out next to this one and a `monero-wallet-rpc` per party (see that
repo's `STAGENET.md`):

```bash
cd daemon
cargo test                       # offline: the two-party swap simulation through the live wiring
cargo run --example swap_devnet  # the real thing (needs funded devnet + stagenet wallets)
```

`examples/swap_devnet.rs` documents the environment it expects. Because the daemon depends
on `../monero` by path, cloning `core` alone is enough to build the program, the engine, and
the tests, but not the daemon.

## License

GPL-3.0-or-later. See [`LICENSE`](./LICENSE). Copyleft is deliberate: for a
self-custodial protocol, keeping every fork open-source is what lets anyone audit
the code they're trusting with their funds.
