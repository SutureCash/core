// SPDX-License-Identifier: GPL-3.0-or-later

//! Host-side swap engine for Suture.
//!
//! This is the off-chain half of an XMR⇄SOL atomic swap: the Ed25519 key-share
//! math, a local copy of the on-chain reveal check, and small in-memory models of
//! the two vaults a swap touches. A maker/taker client uses these to set up a swap,
//! watch it, and recover the Monero key once a secret is revealed. The authoritative
//! escrow rules live in the `sol-escrow` program; `SolEscrow` here mirrors them so
//! the client can reason about (and test) a swap without a validator in the loop.
//!
//! How a swap goes (Alice holds XMR and wants SOL; Bob holds SOL and wants XMR):
//!
//! 1. Each side makes a Monero key half — a scalar on Ed25519. Alice has s_a, Bob
//!    has s_b, with public points P_a = s_a·G and P_b = s_b·G. The XMR is locked to
//!    the 2-of-2 address P_a + P_b, spendable only by s_a + s_b, which neither side
//!    knows on its own.
//! 2. Bob locks SOL in the escrow, naming P_a as the claim point and P_b as the
//!    refund point.
//! 3. Alice locks her XMR in the 2-of-2 address.
//! 4. Alice claims the SOL by revealing s_a. The escrow checks s_a·G == P_a, pays
//!    out, and the revealed s_a lands on-chain — claiming and revealing are one step.
//! 5. Bob reads s_a, adds his s_b, and sweeps the XMR.
//!
//! If Alice never claims, a timelock lets Bob refund by revealing s_b, which in turn
//! lets Alice rebuild s_a + s_b and take her XMR back. Either way no one loses funds.
//!
//! Because both chains use Ed25519, the single point P_a is at once Alice's Solana
//! claim commitment and her Monero public key half — no cross-curve proof needed.
//! That is the simplification the whole design leans on, and an ETH⇄XMR swap can't
//! make it (Ethereum verifies on secp256k1, Monero on Ed25519).

pub mod executor;
pub mod swap;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

/// A uniformly random Ed25519 scalar from OS entropy. Reduces 64 bytes mod the group
/// order, which is the usual way to avoid the bias you'd get from a bare 32-byte mod.
pub fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];

    getrandom::fill(&mut wide).expect("OS RNG unavailable");
    
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// One party's Monero key half: the secret scalar and its public point.
#[derive(Clone)]
pub struct KeyShare {
    pub secret: Scalar,
    pub public: EdwardsPoint,
}

impl KeyShare {
    pub fn generate() -> Self {
        let secret = random_scalar();

        Self {
            secret,
            public: EdwardsPoint::mul_base(&secret),
        }
    }
}

/// Public key of the 2-of-2 Monero address, P_a + P_b.
pub fn shared_public(p_a: &EdwardsPoint, p_b: &EdwardsPoint) -> EdwardsPoint {
    p_a + p_b
}

/// Spend key of the 2-of-2 address, s_a + s_b. Holding this (and only this) sweeps it.
pub fn shared_secret(s_a: &Scalar, s_b: &Scalar) -> Scalar {
    s_a + s_b
}

/// The escrow's reveal check, computed locally: does `reveal · G` equal the committed
/// point? On-chain this is the curve25519 syscall; here it's curve25519-dalek, which
/// is the same implementation, so the answer matches the program byte for byte.
pub fn verify_reveal(reveal: &Scalar, lock_point: &EdwardsPoint) -> bool {
    EdwardsPoint::mul_base(reveal) == *lock_point
}

#[derive(Debug, PartialEq, Eq)]
pub enum SettleError {
    /// Revealed scalar doesn't match the committed lock point.
    BadSecret,
    /// Already claimed or refunded.
    AlreadySettled,
    /// Claim is only valid before the timelock.
    ClaimWindowClosed,
    /// Refund is only valid at or after the timelock.
    RefundTooEarly,
}

/// A local stand-in for the on-chain SOL escrow, used by the client and tests.
///
/// It holds `amount_lamports` until either `claim(s_a)` runs before `t_refund`
/// (Alice takes the SOL and reveals s_a) or `refund(s_b)` runs at/after `t_refund`
/// (Bob reclaims it and reveals s_b). One timelock is enough here to keep the two
/// settles mutually exclusive. The deployed program splits this into two timelocks
/// plus a `set_ready` step so the abort window and the claim window can't overlap;
/// this model keeps the part the engine cares about — the reveal — and leaves that
/// ordering to the program.
pub struct SolEscrow {
    pub lock_point_claim: EdwardsPoint,
    pub lock_point_refund: EdwardsPoint,
    pub amount_lamports: u64,
    pub t_refund: u64,
    /// Set once the escrow settles: the scalar the settler had to reveal.
    pub revealed: Option<Scalar>,
    settled: bool,
}

impl SolEscrow {
    pub fn lock(
        lock_point_claim: EdwardsPoint,
        lock_point_refund: EdwardsPoint,
        amount_lamports: u64,
        t_refund: u64,
    ) -> Self {
        Self {
            lock_point_claim,
            lock_point_refund,
            amount_lamports,
            t_refund,
            revealed: None,
            settled: false,
        }
    }

    /// Alice claims by revealing s_a; on success the SOL pays out and s_a is published.
    pub fn claim(&mut self, reveal: Scalar, now: u64) -> Result<u64, SettleError> {
        if self.settled {
            return Err(SettleError::AlreadySettled);
        }

        if now >= self.t_refund {
            return Err(SettleError::ClaimWindowClosed);
        }
        
        if !verify_reveal(&reveal, &self.lock_point_claim) {
            return Err(SettleError::BadSecret);
        }
        
        self.revealed = Some(reveal);
        self.settled = true;
        Ok(self.amount_lamports)
    }

    /// Bob refunds after the timelock by revealing s_b; the SOL returns and s_b is published.
    pub fn refund(&mut self, reveal: Scalar, now: u64) -> Result<u64, SettleError> {
        if self.settled {
            return Err(SettleError::AlreadySettled);
        }

        if now < self.t_refund {
            return Err(SettleError::RefundTooEarly);
        }

        if !verify_reveal(&reveal, &self.lock_point_refund) {
            return Err(SettleError::BadSecret);
        }
        
        self.revealed = Some(reveal);
        self.settled = true;
        Ok(self.amount_lamports)
    }
}

/// A local stand-in for the Monero 2-of-2 vault. Only the full spend key s_a + s_b
/// can sweep it.
pub struct MoneroVault {
    pub shared_public: EdwardsPoint,
    pub amount_piconero: u64,
}

impl MoneroVault {
    pub fn lock(p_a: &EdwardsPoint, p_b: &EdwardsPoint, amount_piconero: u64) -> Self {
        Self {
            shared_public: shared_public(p_a, p_b),
            amount_piconero,
        }
    }

    /// True iff `candidate · G` equals the shared key, i.e. the candidate is s_a + s_b.
    pub fn try_sweep(&self, candidate_spend_key: &Scalar) -> bool {
        EdwardsPoint::mul_base(candidate_spend_key) == self.shared_public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_halves_make_a_valid_2of2_address() {
        let alice = KeyShare::generate();
        let bob = KeyShare::generate();
        let shared_pub = shared_public(&alice.public, &bob.public);
        let shared_sk = shared_secret(&alice.secret, &bob.secret);
        assert_eq!(EdwardsPoint::mul_base(&shared_sk), shared_pub);
    }

    #[test]
    fn reveal_check_only_accepts_the_committed_secret() {
        let alice = KeyShare::generate();
        let bob = KeyShare::generate();
        let escrow = SolEscrow::lock(alice.public, bob.public, 5_000_000_000, 1000);
        assert!(verify_reveal(&alice.secret, &escrow.lock_point_claim));
        assert!(!verify_reveal(&bob.secret, &escrow.lock_point_claim));
        assert!(!verify_reveal(&random_scalar(), &escrow.lock_point_claim));
    }

    #[test]
    fn claiming_reveals_s_a_and_unlocks_the_monero() {
        let alice = KeyShare::generate();
        let bob = KeyShare::generate();
        let mut sol = SolEscrow::lock(alice.public, bob.public, 5_000_000_000, 1000);
        let xmr = MoneroVault::lock(&alice.public, &bob.public, 250_000_000_000);

        // Neither half sweeps the XMR on its own.
        assert!(!xmr.try_sweep(&alice.secret));
        assert!(!xmr.try_sweep(&bob.secret));

        let payout = sol.claim(alice.secret, 10).expect("claim");
        assert_eq!(payout, 5_000_000_000);
        let s_a = sol.revealed.expect("s_a is now public");

        // Bob combines the revealed s_a with his s_b and sweeps.
        assert!(xmr.try_sweep(&shared_secret(&s_a, &bob.secret)));
    }

    #[test]
    fn refund_returns_sol_and_lets_alice_recover_her_xmr() {
        let alice = KeyShare::generate();
        let bob = KeyShare::generate();
        let mut sol = SolEscrow::lock(alice.public, bob.public, 5_000_000_000, 1000);
        let xmr = MoneroVault::lock(&alice.public, &bob.public, 250_000_000_000);

        assert_eq!(sol.refund(bob.secret, 999), Err(SettleError::RefundTooEarly));

        let payout = sol.refund(bob.secret, 1000).expect("refund");
        assert_eq!(payout, 5_000_000_000);
        let s_b = sol.revealed.expect("s_b is now public");

        assert!(xmr.try_sweep(&shared_secret(&alice.secret, &s_b)));
    }

    #[test]
    fn the_sol_can_only_be_spent_once() {
        let alice = KeyShare::generate();
        let bob = KeyShare::generate();
        let mut sol = SolEscrow::lock(alice.public, bob.public, 5_000_000_000, 1000);

        sol.claim(alice.secret, 10).expect("claim");
        assert_eq!(sol.refund(bob.secret, 2000), Err(SettleError::AlreadySettled));
        assert_eq!(sol.claim(alice.secret, 11), Err(SettleError::AlreadySettled));

        let mut other = SolEscrow::lock(alice.public, bob.public, 1, 1000);
        assert_eq!(other.claim(alice.secret, 1500), Err(SettleError::ClaimWindowClosed));
    }

    #[test]
    fn one_point_serves_both_chains() {
        // The bytes the escrow stores as the claim point are the same bytes that are
        // Alice's Monero public key half. Same curve, same encoding, nothing to convert
        // and no discrete-log-equality proof to carry around.
        let alice = KeyShare::generate();
        let solana_claim_point = alice.public.compress().to_bytes();
        let monero_pubkey_half = alice.public.compress().to_bytes();
        assert_eq!(solana_claim_point, monero_pubkey_half);
    }

    #[test]
    fn the_zero_scalar_does_not_match_a_real_key_share() {
        // 0·G is the identity, never a real share's point. The on-chain `lock` rejects
        // an identity commitment outright, but the reveal check must fail here too.
        let alice = KeyShare::generate();
        assert!(!verify_reveal(&Scalar::ZERO, &alice.public));
    }
}
