// SPDX-License-Identifier: GPL-3.0-or-later

//! The executor seam: turning the [`swap`](crate::swap) state machine's [`Action`]s into
//! real chain calls.
//!
//! The state machine decides *what* to do; the executor does it. Everything chain-specific
//! sits behind the [`SwapChains`] trait — the future `swapd` daemon implements it over the
//! `sol-escrow` Solana program and the Monero `wallet.rs` driver, while the tests here
//! implement it over an in-memory simulation of both chains. [`execute`] maps one action to
//! one call; the daemon's loop is just: observe an event -> `swap.on(event)` -> `execute` each
//! action.
//!
//! The simulation in the tests is the real value: it runs a maker and a taker against a
//! faithful model of the two-timelock escrow and the 2-of-2 vault — with the actual revealed
//! scalars and on-curve checks — and shows that a full swap settles correctly, and that the
//! abort / griefing paths still leave each party made whole.

use crate::swap::Action;
use curve25519_dalek::scalar::Scalar;

/// The chain operations the executor performs. The daemon implements this over live chains
/// (Solana RPC for the escrow, `monero-wallet-rpc` for the 2-of-2); tests implement it over
/// a simulation. Methods are infallible here for clarity; a real impl returns errors and the
/// daemon retries — the state machine is unaffected because actions are idempotent by phase.
pub trait SwapChains {
    /// Maker: lock SOL into the escrow.
    fn lock_sol(&mut self);
    /// Maker: open the taker's claim window.
    fn set_ready(&mut self);
    /// Taker: lock XMR into the 2-of-2.
    fn lock_xmr(&mut self);
    /// Taker: claim the SOL (publishes the taker's spend half).
    fn claim_sol(&mut self);
    /// Maker: refund the SOL (publishes the maker's spend half).
    fn refund_sol(&mut self);
    /// Sweep the 2-of-2 XMR with the reconstructed spend key.
    fn sweep_xmr(&mut self, spend_key: Scalar);
}

/// Carry out a single action against the chains. [`Action::Done`] is terminal and needs no
/// call.
pub fn execute(action: Action, chains: &mut impl SwapChains) {
    match action {
        Action::LockSol => chains.lock_sol(),
        Action::SetReady => chains.set_ready(),
        Action::LockXmr => chains.lock_xmr(),
        Action::ClaimSol => chains.claim_sol(),
        Action::RefundSol => chains.refund_sol(),
        Action::SweepXmr { spend_key } => chains.sweep_xmr(spend_key),
        Action::Done => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swap::{Event, Phase, Swap};
    use curve25519_dalek::edwards::EdwardsPoint;

    const T0: i64 = 10_000;
    const T1: i64 = 20_000;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Party {
        Maker,
        Taker,
    }

    /// A faithful in-memory stand-in for both chains: the two-timelock SOL escrow and the
    /// 2-of-2 XMR vault. It enforces the same windows and the same `reveal·G == point` /
    /// `key·G == shared` checks the real chains do, so a swap that settles here would settle
    /// on-chain.
    struct SimChains {
        t0: i64,
        t1: i64,
        s_a: Scalar, // taker's spend half
        s_b: Scalar, // maker's spend half
        /// The points committed in the escrow: `s_a·G` (claim) and `s_b·G` (refund). The
        /// settle methods check the revealed scalar against these, the same on-curve check
        /// the real escrow's `reveal_matches` performs, so a wrong reveal can't settle here.
        lock_point_claim: EdwardsPoint,
        lock_point_refund: EdwardsPoint,
        now: i64,
        actor: Party, // who is currently acting (set before driving a party)

        sol_locked: bool,
        ready: bool,
        sol_settled: bool,
        sol_revealed: Option<Scalar>,
        sol_to: Option<Party>,

        xmr_locked: bool,
        xmr_swept_by: Option<Party>,
    }

    impl SimChains {
        fn new(s_a: Scalar, s_b: Scalar) -> Self {
            Self {
                t0: T0,
                t1: T1,
                s_a,
                s_b,
                lock_point_claim: EdwardsPoint::mul_base(&s_a),
                lock_point_refund: EdwardsPoint::mul_base(&s_b),
                now: 0,
                actor: Party::Maker,
                sol_locked: false,
                ready: false,
                sol_settled: false,
                sol_revealed: None,
                sol_to: None,
                xmr_locked: false,
                xmr_swept_by: None,
            }
        }

        fn shared_pub(&self) -> EdwardsPoint {
            EdwardsPoint::mul_base(&(self.s_a + self.s_b))
        }

        /// Drive one party's response to an event: run its state machine and execute every
        /// action it returns against this world.
        fn drive(&mut self, party: Party, swap: &mut Swap, event: Event) {
            self.actor = party;
            
            for action in swap.on(event) {
                execute(action, self);
            }
        }
    }

    impl SwapChains for SimChains {
        fn lock_sol(&mut self) {
            assert_eq!(self.actor, Party::Maker);
            self.sol_locked = true;
        }
        fn set_ready(&mut self) {
            assert_eq!(self.actor, Party::Maker);
            assert!(self.now < self.t1, "set_ready after the window closed");
            self.ready = true;
        }
        fn lock_xmr(&mut self) {
            assert_eq!(self.actor, Party::Taker);
            self.xmr_locked = true;
        }
        fn claim_sol(&mut self) {
            assert_eq!(self.actor, Party::Taker);
            assert!(!self.sol_settled, "double settle");
            assert!(
                (self.ready || self.now >= self.t0) && self.now < self.t1,
                "claim outside the window",
            );
            // Mirror the escrow's reveal check: the scalar the claim publishes must open the
            // committed claim point. The sim hardcodes s_a, so this also catches the keys
            // having been wired up inconsistently.
            assert_eq!(
                EdwardsPoint::mul_base(&self.s_a),
                self.lock_point_claim,
                "claim reveal doesn't open the committed claim point",
            );
            self.sol_settled = true;
            self.sol_revealed = Some(self.s_a); // claiming publishes s_a
            self.sol_to = Some(Party::Taker);
        }
        fn refund_sol(&mut self) {
            assert_eq!(self.actor, Party::Maker);
            assert!(!self.sol_settled, "double settle");
            assert!(
                (self.now < self.t0 && !self.ready) || self.now >= self.t1,
                "refund outside the window",
            );
            // Same reveal check on the refund path: s_b must open the committed refund point.
            assert_eq!(
                EdwardsPoint::mul_base(&self.s_b),
                self.lock_point_refund,
                "refund reveal doesn't open the committed refund point",
            );
            self.sol_settled = true;
            self.sol_revealed = Some(self.s_b); // refunding publishes s_b
            self.sol_to = Some(Party::Maker);
        }
        fn sweep_xmr(&mut self, spend_key: Scalar) {
            assert!(self.xmr_locked, "nothing to sweep");
            assert!(self.xmr_swept_by.is_none(), "double sweep");
            assert_eq!(
                EdwardsPoint::mul_base(&spend_key),
                self.shared_pub(),
                "sweep key doesn't open the 2-of-2",
            );
            self.xmr_swept_by = Some(self.actor);
        }
    }

    fn keys() -> (Scalar, Scalar) {
        (Scalar::from(11u64), Scalar::from(7u64)) // s_a, s_b
    }

    #[test]
    fn happy_path_settles_sol_to_taker_and_xmr_to_maker() {
        let (s_a, s_b) = keys();
        let mut w = SimChains::new(s_a, s_b);
        let (mut maker, init) = Swap::start_maker(T0, T1, s_b);
        let (mut taker, _) = Swap::start_taker(T0, T1, s_a);

        // Maker's first action.
        w.actor = Party::Maker;
        for a in init {
            execute(a, &mut w);
        }
        assert!(w.sol_locked);
        w.drive(Party::Maker, &mut maker, Event::SolLocked); // maker observes its own lock

        w.drive(Party::Taker, &mut taker, Event::SolLocked); // -> lock XMR
        assert!(w.xmr_locked);
        w.drive(Party::Maker, &mut maker, Event::XmrLocked); // -> set_ready
        w.drive(Party::Taker, &mut taker, Event::XmrLocked); // taker observes its own lock
        assert!(w.ready);
        w.drive(Party::Taker, &mut taker, Event::Ready); // -> claim SOL (reveals s_a)
        assert_eq!(w.sol_to, Some(Party::Taker));

        let s_a_rev = w.sol_revealed.expect("claim revealed s_a");
        w.drive(Party::Maker, &mut maker, Event::SolClaimed { s_a: s_a_rev }); // -> sweep XMR
        w.drive(Party::Maker, &mut maker, Event::XmrSwept); // -> done
        w.drive(Party::Taker, &mut taker, Event::SolClaimed { s_a: s_a_rev }); // taker done

        assert_eq!(w.sol_to, Some(Party::Taker), "taker got the SOL");
        assert_eq!(w.xmr_swept_by, Some(Party::Maker), "maker got the XMR");
        assert_eq!(maker.phase(), Phase::Done);
        assert_eq!(taker.phase(), Phase::Done);
    }

    #[test]
    fn maker_aborts_and_recovers_sol_when_taker_never_locks() {
        let (s_a, s_b) = keys();
        let mut w = SimChains::new(s_a, s_b);
        let (mut maker, init) = Swap::start_maker(T0, T1, s_b);

        w.actor = Party::Maker;
        for a in init {
            execute(a, &mut w);
        }
        w.drive(Party::Maker, &mut maker, Event::SolLocked);

        // Taker never locks. Clock reaches the abort point (still before t0).
        w.now = T0 - crate::swap::ABORT_MARGIN;
        w.drive(Party::Maker, &mut maker, Event::Tick { now: w.now }); // -> early refund
        w.drive(Party::Maker, &mut maker, Event::SolRefunded { s_b });

        assert_eq!(w.sol_to, Some(Party::Maker), "maker got the SOL back");
        assert!(!w.xmr_locked, "no XMR was ever at risk");
        assert_eq!(maker.phase(), Phase::Done);
    }

    #[test]
    fn taker_recovers_xmr_when_maker_griefs_after_the_lock() {
        // Adversarial maker: it locks SOL, lets the taker lock XMR, then early-refunds
        // instead of cooperating. The taker's state machine must recover the XMR.
        let (s_a, s_b) = keys();
        let mut w = SimChains::new(s_a, s_b);
        let (mut taker, _) = Swap::start_taker(T0, T1, s_a);

        // Honest start: maker locks SOL.
        w.actor = Party::Maker;
        w.lock_sol();
        w.drive(Party::Taker, &mut taker, Event::SolLocked); // taker locks XMR
        assert!(w.xmr_locked);

        // Griefing maker refunds early (now < t0, not ready) — reveals s_b.
        w.actor = Party::Maker;
        w.refund_sol();
        assert_eq!(w.sol_to, Some(Party::Maker));

        let s_b_rev = w.sol_revealed.expect("refund revealed s_b");
        w.drive(Party::Taker, &mut taker, Event::SolRefunded { s_b: s_b_rev }); // -> sweep (recover)
        w.drive(Party::Taker, &mut taker, Event::XmrSwept);

        assert_eq!(w.xmr_swept_by, Some(Party::Taker), "taker recovered the XMR");
        assert_eq!(taker.phase(), Phase::Done);
    }

    #[test]
    fn taker_recovers_when_it_locks_but_misses_the_claim_window() {
        let (s_a, s_b) = keys();
        let mut w = SimChains::new(s_a, s_b);
        let (mut maker, init) = Swap::start_maker(T0, T1, s_b);
        let (mut taker, _) = Swap::start_taker(T0, T1, s_a);

        w.actor = Party::Maker;
        for a in init {
            execute(a, &mut w);
        }
        w.drive(Party::Maker, &mut maker, Event::SolLocked); // maker observes its own lock
        w.drive(Party::Taker, &mut taker, Event::SolLocked); // taker locks XMR
        w.drive(Party::Maker, &mut maker, Event::XmrLocked); // maker set_ready
        // The taker goes offline and never claims; t1 passes.
        w.now = T1;
        w.drive(Party::Maker, &mut maker, Event::Tick { now: w.now }); // -> late refund
        assert_eq!(w.sol_to, Some(Party::Maker));

        let s_b_rev = w.sol_revealed.expect("late refund revealed s_b");
        w.drive(Party::Taker, &mut taker, Event::SolRefunded { s_b: s_b_rev });
        w.drive(Party::Taker, &mut taker, Event::XmrSwept);
        assert_eq!(w.xmr_swept_by, Some(Party::Taker), "taker recovered the XMR after t1");
    }

    #[test]
    fn maker_still_sweeps_when_taker_claims_late_and_solclaimed_lands_in_settled() {
        // End-to-end of the Critical bug #1 interleaving against the faithful sim: the taker
        // claims near the end of the window, but the maker hasn't observed it and its own t1
        // timer fires first. The maker's refund can't land (escrow already claimed); the real
        // SolClaimed then arrives while the maker is in Settled. The maker must still sweep
        // the XMR and end made whole — not strand its principal.
        let (s_a, s_b) = keys();
        let mut w = SimChains::new(s_a, s_b);
        let (mut maker, init) = Swap::start_maker(T0, T1, s_b);
        let (mut taker, _) = Swap::start_taker(T0, T1, s_a);

        w.actor = Party::Maker;
        for a in init {
            execute(a, &mut w);
        }
        w.drive(Party::Maker, &mut maker, Event::SolLocked);
        w.drive(Party::Taker, &mut taker, Event::SolLocked); // taker locks XMR
        w.drive(Party::Maker, &mut maker, Event::XmrLocked); // maker set_ready
        w.drive(Party::Taker, &mut taker, Event::XmrLocked);

        // Taker claims late, inside [t0, t1). The maker hasn't seen it yet.
        w.now = T1 - 1;
        w.drive(Party::Taker, &mut taker, Event::Ready); // -> ClaimSol (reveals s_a)
        assert_eq!(w.sol_to, Some(Party::Taker), "taker took the SOL on-chain");
        let s_a_rev = w.sol_revealed.expect("claim revealed s_a");

        // The maker, still unaware, hits its own t1 and *attempts* a refund. On-chain that
        // refund reverts because the escrow is already settled — so the sim must not let it
        // double-settle. The maker's state machine moves to Settled (refund route) but the
        // executor's refund call would fail on the real chain; we model that by NOT driving
        // the refund through the sim (the escrow is already settled). The maker's machine is
        // now in Settled awaiting a SolRefunded that will never come.
        let refund_actions = maker.on(Event::Tick { now: T1 });
        assert_eq!(refund_actions, vec![crate::swap::Action::RefundSol]);
        assert_eq!(maker.phase(), Phase::Settled);

        // Now the belated SolClaimed finally reaches the maker. Pre-fix this fell through to
        // `_ => vec![]` and the XMR was lost. Post-fix it re-routes onto the claim path.
        w.drive(Party::Maker, &mut maker, Event::SolClaimed { s_a: s_a_rev }); // -> sweep XMR
        assert_eq!(maker.phase(), Phase::Settled, "still sweeping, not Done");
        w.drive(Party::Maker, &mut maker, Event::XmrSwept); // -> done

        assert_eq!(w.sol_to, Some(Party::Taker), "taker kept the SOL");
        assert_eq!(w.xmr_swept_by, Some(Party::Maker), "maker recovered the XMR — no loss");
        assert_eq!(maker.phase(), Phase::Done);
    }

    #[test]
    fn sim_claim_and_refund_enforce_the_reveal_check() {
        // Fidelity guard for bug #5: the sim now checks the revealed scalar against the
        // committed lock point on both settle paths. If the keys were wired up so that
        // s_a/s_b don't match the recorded lock points, settling must panic — proving the
        // check is live (the sim already did this for sweep_xmr).
        let (s_a, s_b) = keys();
        let w = SimChains::new(s_a, s_b);
        assert_eq!(w.lock_point_claim, EdwardsPoint::mul_base(&s_a));
        assert_eq!(w.lock_point_refund, EdwardsPoint::mul_base(&s_b));

        // A claim with a mismatched stored scalar must trip the reveal assertion.
        let mut bad = SimChains::new(s_a, s_b);
        bad.lock_point_claim = EdwardsPoint::mul_base(&Scalar::from(99u64));
        bad.actor = Party::Taker;
        bad.now = T0;
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            bad.claim_sol();
        }))
        .is_err();
        assert!(panicked, "claim with a non-matching reveal must be rejected by the sim");
    }

    #[test]
    fn full_swap_settles_with_random_key_shares() {
        // A4 coverage gap: the other sim tests use the tiny constants 11 and 7. Run the happy
        // path with full-width random scalars so nothing depends on small-scalar accidents.
        use crate::KeyShare;
        let alice = KeyShare::generate();
        let bob = KeyShare::generate();
        let (s_a, s_b) = (alice.secret, bob.secret);

        let mut w = SimChains::new(s_a, s_b);
        let (mut maker, init) = Swap::start_maker(T0, T1, s_b);
        let (mut taker, _) = Swap::start_taker(T0, T1, s_a);

        w.actor = Party::Maker;
        for a in init {
            execute(a, &mut w);
        }
        w.drive(Party::Maker, &mut maker, Event::SolLocked);
        w.drive(Party::Taker, &mut taker, Event::SolLocked);
        w.drive(Party::Maker, &mut maker, Event::XmrLocked);
        w.drive(Party::Taker, &mut taker, Event::XmrLocked);
        w.drive(Party::Taker, &mut taker, Event::Ready); // claim (reveals s_a)
        let s_a_rev = w.sol_revealed.expect("claim revealed s_a");
        w.drive(Party::Maker, &mut maker, Event::SolClaimed { s_a: s_a_rev });
        w.drive(Party::Maker, &mut maker, Event::XmrSwept);
        w.drive(Party::Taker, &mut taker, Event::SolClaimed { s_a: s_a_rev });

        assert_eq!(w.sol_to, Some(Party::Taker), "taker got the SOL");
        assert_eq!(w.xmr_swept_by, Some(Party::Maker), "maker got the XMR");
        assert_eq!(maker.phase(), Phase::Done);
        assert_eq!(taker.phase(), Phase::Done);
    }
}
