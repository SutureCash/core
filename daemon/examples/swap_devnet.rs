// SPDX-License-Identifier: GPL-3.0-or-later

//! One hands-off XMR⇄SOL swap across **Solana devnet** and **Monero stagenet**, driven by
//! the swap state machine through `LiveChains` — the executor's simulation made real.
//!
//! It plays both roles in one process so a single command exercises the whole protocol:
//! the maker (Bob) locks SOL in the `sol-escrow` program; the taker (Alice) locks XMR in
//! the 2-of-2; the maker arms the claim window; the taker claims the SOL (revealing s_a);
//! the maker reads s_a off-chain and sweeps the XMR. Each side's daemon loop is the same
//! poll -> `swap.on(event)` -> `execute` cycle the library ships.
//!
//! ## Prerequisites
//!
//! - A funded **Solana devnet** keypair (the payer/locker): `solana airdrop 2`.
//! - The program deployed on devnet; its id is read from `target/deploy/sol_escrow-keypair.json`.
//! - **Two `monero-wallet-rpc`** instances on stagenet, no RPC login (each party runs its
//!   own — they must not share a wallet slot):
//!     - the taker's, holding a funded `funder` wallet (`TAKER_MONERO_RPC`, default :38084);
//!     - the maker's, used to scan and sweep the 2-of-2 (`MAKER_MONERO_RPC`, default :38083).
//!   Both pointed at the same stagenet node.
//!
//! ## Run
//!
//!     SOLANA_RPC=https://api.devnet.solana.com \
//!     PAYER=~/.config/solana/id.json \
//!     MAKER_MONERO_RPC=http://127.0.0.1:38083 \
//!     TAKER_MONERO_RPC=http://127.0.0.1:38084 \
//!     cargo run --example swap_devnet
//!
//! Env knobs: `SOL_AMOUNT` lamports (default 0.05 SOL), `XMR_PICONERO` (default 0.05 XMR),
//! `FUNDER` taker wallet name (default "funder"), `PAYOUT` Monero address the maker sweeps
//! to (default: the funder's own address, so a stagenet run is reusable).

use std::str::FromStr;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use monero::{Address, Network, PrivateKey};
use serde_json::json;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use suture_engine::executor::execute;
use suture_engine::random_scalar;
use suture_engine::swap::{Phase, Role, Swap};
use suture_monero::wallet::WalletRpc;
use suture_monero::{PartyShare, Shared};

use suture_daemon::live::LiveChains;
use suture_daemon::sol::{Rpc, RpcSol, SwapTerms};
use suture_daemon::xmr::{FunderWallet, XmrChain};

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
const PICONERO_PER_XMR: f64 = 1e12;
const FEE_BPS: u16 = 300; // 3%, the program's cap

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A spend half drawn as a curve25519 scalar (the engine's currency) together with the
/// Monero key view of the same scalar, so the on-chain `claim_point` and the Monero key
/// half are literally the same point.
struct Half {
    spend: Scalar,
    party: PartyShare,
}

impl Half {
    fn new() -> Self {
        let spend = random_scalar();
        let party = PartyShare {
            spend: PrivateKey::from_slice(spend.as_bytes()).expect("canonical scalar"),
            view: PartyShare::generate().view,
        };
        
        Self { spend, party }
    }

    fn point(&self) -> [u8; 32] {
        EdwardsPoint::mul_base(&self.spend).compress().to_bytes()
    }
}

fn program_id() -> Pubkey {
    // The address `cargo build-sbf` generated, same source the TS client reads.
    let path = "target/deploy/sol_escrow-keypair.json";
    let kp = solana_sdk::signer::keypair::read_keypair_file(path)
        .unwrap_or_else(|e| panic!("read program keypair {path}: {e}"));
    kp.pubkey()
}

fn main() {
    let solana_rpc = env("SOLANA_RPC", "https://api.devnet.solana.com");
    let maker_xmr_rpc = env("MAKER_MONERO_RPC", "http://127.0.0.1:38083");
    let taker_xmr_rpc = env("TAKER_MONERO_RPC", "http://127.0.0.1:38084");
    let payer_path = env("PAYER", &format!("{}/.config/solana/id.json", env("HOME", "")));
    let funder = env("FUNDER", "funder");
    let sol_amount: u64 = env("SOL_AMOUNT", &(LAMPORTS_PER_SOL / 20).to_string())
        .parse()
        .expect("SOL_AMOUNT");
    let xmr_amount: u64 = env("XMR_PICONERO", "50000000000").parse().expect("XMR_PICONERO");

    // Key halves: s_a (taker) and s_b (maker). The points are the Solana commitments.
    let alice = Half::new();
    let bob = Half::new();
    let claim_point = alice.point(); // s_a·G
    let refund_point = bob.point(); // s_b·G

    // The shared 2-of-2 Monero address and the view secret both parties scan with.
    let shared = Shared::aggregate(&alice.party, &bob.party);
    let lock_addr = shared.address(Network::Stagenet);

    // Solana accounts.
    let payer = solana_sdk::signer::keypair::read_keypair_file(&payer_path)
        .unwrap_or_else(|e| panic!("read payer {payer_path}: {e}"));
    let program = program_id();
    let claimer = Keypair::new(); // Alice's SOL receiving account (fresh)
    let fee_recipient = Keypair::new(); // treasury stand-in (fresh; fee > rent so a credit is fine)

    let now = unix_now();
    let t0 = now + 2 * 3600; // generous: set_ready opens the claim window long before this
    let t1 = now + 4 * 3600;

    let terms = SwapTerms {
        id: random_scalar().to_bytes(),
        locker: payer.pubkey(),
        claimer: claimer.pubkey(),
        fee_recipient: fee_recipient.pubkey(),
        claim_point,
        refund_point,
        amount: sol_amount,
        fee_bps: FEE_BPS,
        t0,
        t1,
    };
    let escrow = terms.escrow_pda(&program);

    println!("Suture end-to-end swap — Solana devnet + Monero stagenet\n");
    println!("solana rpc : {solana_rpc}");
    println!("program    : {program}");
    println!("escrow PDA : {escrow}");
    println!("SOL amount : {} SOL", terms.amount as f64 / LAMPORTS_PER_SOL as f64);
    println!("XMR amount : {} XMR", xmr_amount as f64 / PICONERO_PER_XMR);
    println!("2of2 addr  : {lock_addr}");

    // The taker's funder wallet supplies the XMR and sets the scan restore height; it's
    // also the demo payout so a stagenet run returns the funds.
    let taker_rpc = WalletRpc::new(&taker_xmr_rpc);
    taker_rpc.call("close_wallet", json!({})).ok();
    taker_rpc
        .call("open_wallet", json!({ "filename": funder, "password": "" }))
        .expect("open funder wallet on taker rpc");
    taker_rpc.refresh().ok();
    let funder_addr_str = taker_rpc
        .call("get_address", json!({ "account_index": 0 }))
        .expect("get_address")["address"]
        .as_str()
        .expect("address string")
        .to_string();
    let restore_height = taker_rpc.call("get_height", json!({}))
        .expect("get_height")["height"]
        .as_u64()
        .expect("height");
    taker_rpc.call("close_wallet", json!({})).ok();

    let payout = Address::from_str(&env("PAYOUT", &funder_addr_str)).expect("payout address");
    println!("payout     : {payout}");
    println!("restore_h  : {restore_height}\n");

    // The maker (Bob): locks SOL, scans the 2-of-2, sweeps it. No funder wallet.
    let maker_sol = RpcSol::new(
        Rpc::new(&solana_rpc),
        program,
        terms.clone(),
        // The single funded keypair signs/pays every transaction in this demo; the program
        // doesn't require the claimer to sign, so it can also pay the taker's claim.
        Keypair::try_from(&payer.to_bytes()[..]).unwrap(),
        bob.spend.to_bytes(),
    );
    let maker_xmr = XmrChain::new(
        &maker_xmr_rpc,
        lock_addr,
        shared.view_secret,
        restore_height,
        xmr_amount,
        payout,
        None,
        "maker",
    );
    let mut maker_chains = LiveChains::new(Role::Maker, bob.spend, claim_point, refund_point, maker_sol, maker_xmr);

    // The taker (Alice): locks XMR from the funder, claims the SOL.
    let taker_sol = RpcSol::new(
        Rpc::new(&solana_rpc),
        program,
        terms.clone(),
        Keypair::try_from(&payer.to_bytes()[..]).unwrap(),
        alice.spend.to_bytes(),
    );
    let taker_xmr = XmrChain::new(
        &taker_xmr_rpc,
        lock_addr,
        shared.view_secret,
        restore_height,
        xmr_amount,
        payout,
        Some(FunderWallet { filename: funder, password: String::new() }),
        "taker",
    );
    let mut taker_chains = LiveChains::new(Role::Taker, alice.spend, claim_point, refund_point, taker_sol, taker_xmr);

    let (mut maker, maker_start) = Swap::start_maker(t0, t1, bob.spend);
    let (mut taker, _taker_start) = Swap::start_taker(t0, t1, alice.spend);

    // Kick off: the maker locks the SOL.
    println!("[maker] locking SOL...");
    for action in maker_start {
        execute(action, &mut maker_chains);
        if let Some(fault) = maker_chains.take_fault() {
            eprintln!("maker lock failed: {fault}");
            std::process::exit(1);
        }
    }

    // Drive both parties until the swap completes. The clock is real unix time; the long
    // wait is the maker's sweep blocking on the Monero unlock (~10 blocks).
    let poll = Duration::from_secs(15);
    let deadline = now + 3 * 3600;
    loop {
        let t = unix_now();
        let before = (maker.phase(), taker.phase());

        drive("maker", &mut maker, &mut maker_chains, t);
        drive("taker", &mut taker, &mut taker_chains, t);

        let after = (maker.phase(), taker.phase());
        if after != before {
            println!("  maker={:?}  taker={:?}", after.0, after.1);
        }
        if after.0 == Phase::Done && after.1 == Phase::Done {
            break;
        }
        if t > deadline {
            eprintln!("deadline passed without completing the swap");
            std::process::exit(1);
        }
        sleep(poll);
    }

    println!("\nSwap complete: the taker holds the SOL, the maker swept the XMR.");

    // `close` is pure rent housekeeping after the settle — outside the swap machine, so the
    // maker calls it directly on its Solana backend.
    println!("Reclaiming the escrow rent...");
    match maker_chains.sol_backend().close() {
        Ok(sig) => println!("close: {sig}"),
        Err(e) => eprintln!("close failed (rent left in the PDA): {e}"),
    }
}

/// One poll -> state-machine -> execute cycle for a party. A fault on any fund-moving step
/// stops the run — the on-chain timelocks keep funds recoverable from here.
fn drive(name: &str, swap: &mut Swap, chains: &mut LiveChains<RpcSol, XmrChain>, t: i64) {
    for event in chains.poll(t) {
        for action in swap.on(event) {
            execute(action, chains);
            if let Some(fault) = chains.take_fault() {
                eprintln!("[{name}] {fault}");
                std::process::exit(1);
            }
        }
    }
}
