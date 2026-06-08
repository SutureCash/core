// SPDX-License-Identifier: GPL-3.0-or-later

//! The Suture maker/taker daemon — the piece that runs an XMR⇄SOL swap to completion by
//! driving the [`suture_engine`] state machine against both live chains.
//!
//! `core` (this repo) holds the Solana escrow and the swap engine; the sibling `monero`
//! repo holds the 2-of-2 key engine and the wallet driver. Each is a self-contained half,
//! and nothing connected them — until here. This crate depends on both and implements the
//! engine's [`SwapChains`](suture_engine::executor::SwapChains) seam over them:
//!
//! - [`sol`] builds, signs, and sends the `sol-escrow` instructions over Solana RPC, and
//!   reads the escrow account back.
//! - [`xmr`] locks / scans / sweeps the Monero 2-of-2 over `monero-wallet-rpc`, reusing the
//!   `suture-monero` driver proven on stagenet.
//! - [`live`] ties them together: [`live::LiveChains`] is the seam, and [`live::run`] is the
//!   loop — observe an event, feed the state machine, carry out what it decides.
//!
//! What the executor's simulation modeled, this runs for real: one hands-off swap across
//! Solana devnet and Monero stagenet. See `examples/swap_devnet.rs`.

pub mod live;
pub mod sol;
pub mod xmr;

pub use live::{run, EscrowView, LiveChains, SolBackend, XmrBackend};
pub use sol::{Escrow, Rpc, RpcSol, SolError, SwapInstruction, SwapTerms};
pub use xmr::{commit_matches, FunderWallet, XmrChain};
