// SPDX-License-Identifier: GPL-3.0-or-later

//! A narrated happy-path swap, computed with real Ed25519 operations. Run it with:
//!
//!     cargo run --example walkthrough
//!
//! It's the same flow the test suite checks, printed step by step.

use suture_engine::{shared_secret, KeyShare, MoneroVault, SolEscrow};

fn main() {
    println!("Suture XMR⇄SOL swap, happy path\n");

    // Each side makes a Monero key half on Ed25519.
    let alice = KeyShare::generate(); // holds XMR, wants SOL
    let bob = KeyShare::generate(); // holds SOL, wants XMR
    println!("1. setup");
    println!("   P_a = {}", hex(&alice.public.compress().to_bytes()));
    println!("   P_b = {}", hex(&bob.public.compress().to_bytes()));

    // Bob escrows 5 SOL, naming P_a as the claim point and P_b as the refund point.
    let mut sol = SolEscrow::lock(alice.public, bob.public, 5_000_000_000, 1000);
    println!("2. Bob locks 5 SOL (claim point P_a, refund point P_b, timelock at slot 1000)");

    // Alice locks 0.25 XMR into the 2-of-2 address P_a + P_b.
    let xmr = MoneroVault::lock(&alice.public, &bob.public, 250_000_000_000);
    println!("3. Alice locks 0.25 XMR into the 2-of-2 address");
    println!(
        "   neither half sweeps it alone: alice={}, bob={}",
        xmr.try_sweep(&alice.secret),
        xmr.try_sweep(&bob.secret),
    );

    // Alice claims the SOL; the claim publishes s_a.
    let payout = sol.claim(alice.secret, 10).expect("claim");
    let s_a = sol.revealed.expect("revealed");
    println!("4. Alice claims {} lamports, which publishes s_a", payout);

    // Bob reads s_a, adds s_b, and sweeps the XMR.
    let swept = xmr.try_sweep(&shared_secret(&s_a, &bob.secret));
    println!("5. Bob combines s_a + s_b and sweeps the XMR: {}", swept);

    assert!(swept, "swap should complete");
    println!("\ndone — both sides settled, no third party held the funds");
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);

    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    
    s
}
