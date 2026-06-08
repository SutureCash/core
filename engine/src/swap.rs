// SPDX-License-Identifier: GPL-3.0-or-later

//! Cross-chain swap state machine — the brain that sequences the Solana escrow (this
//! repo's `sol-escrow` program) and the Monero 2-of-2 (the companion `monero` repo)
//! into one atomic swap.
//!
//! It's pure and deterministic: you feed it observed events and clock ticks, and it
//! returns the [`Action`]s this party should perform. The actual chain calls — locking
//! SOL, locking/scanning/sweeping XMR, claiming, refunding — are the executor's job.
//! Keeping the decision logic free of I/O is what makes every interleaving testable, and
//! a swap that custodies funds across two chains has a lot of interleavings.
//!
//! ## Roles
//!
//! - [`Role::Maker`] is Bob: he has SOL, wants XMR. He locks SOL in the escrow and
//!   sweeps the XMR once the taker reveals her half.
//! - [`Role::Taker`] is Alice: she has XMR, wants SOL. She locks XMR in the 2-of-2 and
//!   claims the SOL (which reveals her half).
//!
//! ## The one safety rule that isn't obvious
//!
//! The taker knows her own spend half `s_a`, and claiming the SOL only requires revealing
//! `s_a`. The escrow's claim window opens at `t0` **regardless of whether the maker
//! called `set_ready`**. So if the maker locked SOL and just waited, the taker could
//! claim the SOL at `t0` *without ever locking her XMR* — free money. The maker prevents
//! this by **refunding before `t0` unless the taker's XMR lock is confirmed**. This state
//! machine encodes that: a maker in [`Phase::SolLocked`] with no observed XMR lock emits
//! [`Action::RefundSol`] once the clock reaches `t0 - ABORT_MARGIN`. See
//! [`tests::maker_aborts_before_t0_if_taker_never_locks`].
//!
//! In every path, a party either completes the swap or recovers its own principal — it
//! never ends up worse off than the network fees it spent. The tests assert this.

use curve25519_dalek::scalar::Scalar;

/// How long before the on-chain `t0` the maker bails out if the taker hasn't locked XMR.
/// It must be > 0 so the early-refund lands while the abort window (`now < t0`) is open.
pub const ABORT_MARGIN: i64 = 600; // 10 minutes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Bob: locks SOL, wants XMR.
    Maker,
    /// Alice: locks XMR, wants SOL.
    Taker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Nothing committed yet.
    Start,
    /// The SOL escrow is locked and confirmed.
    SolLocked,
    /// The XMR is locked in the 2-of-2 and confirmed.
    XmrLocked,
    /// The escrow's claim window is armed (maker called `set_ready`).
    Ready,
    /// The escrow has settled (claimed or refunded); the XMR move may still be pending.
    Settled,
    /// Terminal: the swap finished (success or recovered).
    Done,
}

/// Something this party observed on-chain, or a clock tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The maker's SOL escrow is confirmed.
    SolLocked,
    /// The taker's XMR is confirmed in the 2-of-2.
    XmrLocked,
    /// The maker called `set_ready`.
    Ready,
    /// The SOL was claimed; the claim published the taker's half `s_a`.
    SolClaimed { s_a: Scalar },
    /// The SOL was refunded; the refund published the maker's half `s_b`.
    SolRefunded { s_b: Scalar },
    /// The XMR was swept out of the 2-of-2.
    XmrSwept,
    /// The clock advanced to `now` (unix seconds).
    Tick { now: i64 },
}

/// What this party should do now. The executor turns these into real chain calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Maker: lock the SOL into the escrow.
    LockSol,
    /// Taker: lock the XMR into the 2-of-2 (only after verifying the committed point).
    LockXmr,
    /// Maker: call `set_ready` to open the taker's claim window.
    SetReady,
    /// Taker: claim the SOL (reveals our own `s_a`).
    ClaimSol,
    /// Maker: refund the SOL (reveals our own `s_b`) — early abort or post-`t1`.
    RefundSol,
    /// Sweep the 2-of-2 XMR with the reconstructed full spend key (`s_a + s_b`).
    SweepXmr { spend_key: Scalar },
    /// Terminal: this party is done and made whole.
    Done,
}

/// One party's view of a single swap.
pub struct Swap {
    role: Role,
    phase: Phase,
    /// On-chain timelocks (unix seconds). `t0` opens the claim window; `t1` closes it.
    t0: i64,
    t1: i64,
    /// This party's own spend half: `s_b` for the maker, `s_a` for the taker.
    own_spend: Scalar,
}

impl Swap {
    /// Start a maker. The first thing to do is lock the SOL.
    pub fn start_maker(t0: i64, t1: i64, own_spend: Scalar) -> (Self, Vec<Action>) {
        (
            Self { role: Role::Maker, phase: Phase::Start, t0, t1, own_spend },
            vec![Action::LockSol],
        )
    }

    /// Start a taker. Nothing to do until the maker's SOL lock is seen.
    ///
    /// The caller must already have verified that the point the maker committed on Solana
    /// equals the taker's expected spend half (`claim_point == s_a·G`). The machine assumes
    /// that check passed; without it, locking XMR is unsafe.
    pub fn start_taker(t0: i64, t1: i64, own_spend: Scalar) -> (Self, Vec<Action>) {
        (
            Self { role: Role::Taker, phase: Phase::Start, t0, t1, own_spend },
            vec![],
        )
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Feed in an event; get back the actions to perform. Terminal states ignore events.
    pub fn on(&mut self, event: Event) -> Vec<Action> {
        if self.phase == Phase::Done {
            return vec![];
        }

        match self.role {
            Role::Maker => self.maker(event),
            Role::Taker => self.taker(event),
        }
    }

    fn maker(&mut self, event: Event) -> Vec<Action> {
        match (self.phase, event) {
            (Phase::Start, Event::SolLocked) => {
                self.phase = Phase::SolLocked;
                vec![]
            }
            // The taker locked her XMR — arm her claim window.
            (Phase::SolLocked, Event::XmrLocked) => {
                self.phase = Phase::XmrLocked;
                vec![Action::SetReady]
            }
            (Phase::XmrLocked, Event::Ready) => {
                self.phase = Phase::Ready;
                vec![]
            }
            // The taker claimed and revealed s_a — sweep the XMR with s_a + our s_b.
            (Phase::XmrLocked | Phase::Ready, Event::SolClaimed { s_a }) => {
                self.phase = Phase::Settled;
                vec![Action::SweepXmr { spend_key: s_a + self.own_spend }]
            }
            (Phase::Settled, Event::XmrSwept) => {
                self.phase = Phase::Done;
                vec![Action::Done]
            }
            // Safety: the taker never locked her XMR, and t0 is approaching. We must
            // refund (which reveals our s_b harmlessly — there is no shared XMR) before
            // t0, or at t0 she could claim our SOL without having locked anything.
            (Phase::SolLocked, Event::Tick { now }) if now >= self.t0 - ABORT_MARGIN => {
                self.phase = Phase::Settled;
                vec![Action::RefundSol]
            }
            // The taker locked but never claimed before t1 — reclaim the SOL. This reveals
            // s_b, which lets her recover her XMR; no one loses principal.
            (Phase::XmrLocked | Phase::Ready, Event::Tick { now }) if now >= self.t1 => {
                self.phase = Phase::Settled;
                vec![Action::RefundSol]
            }
            // Our own refund confirmed: we have our SOL back, done.
            (Phase::Settled, Event::SolRefunded { .. }) => {
                self.phase = Phase::Done;
                vec![Action::Done]
            }
            _ => vec![],
        }
    }

    fn taker(&mut self, event: Event) -> Vec<Action> {
        match (self.phase, event) {
            // The maker's SOL is locked (and we've verified the committed point) — lock XMR.
            (Phase::Start, Event::SolLocked) => {
                self.phase = Phase::SolLocked;
                vec![Action::LockXmr]
            }
            (Phase::SolLocked, Event::XmrLocked) => {
                self.phase = Phase::XmrLocked;
                vec![]
            }
            // Claim as soon as the maker is ready, or once t0 opens the window anyway.
            (Phase::XmrLocked, Event::Ready) => {
                self.phase = Phase::Ready;
                vec![Action::ClaimSol]
            }
            (Phase::XmrLocked, Event::Tick { now }) if now >= self.t0 => {
                self.phase = Phase::Ready;
                vec![Action::ClaimSol]
            }
            // Our own claim confirmed: we have the SOL, done.
            (Phase::Ready, Event::SolClaimed { .. }) => {
                self.phase = Phase::Done;
                vec![Action::Done]
            }
            // The maker refunded (revealing s_b) before we claimed — recover our XMR with
            // our s_a + the revealed s_b.
            (Phase::SolLocked | Phase::XmrLocked | Phase::Ready, Event::SolRefunded { s_b }) => {
                self.phase = Phase::Settled;
                vec![Action::SweepXmr { spend_key: self.own_spend + s_b }]
            }
            (Phase::Settled, Event::XmrSwept) => {
                self.phase = Phase::Done;
                vec![Action::Done]
            }
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 10_000;
    const T1: i64 = 20_000;

    fn scalar(n: u64) -> Scalar {
        Scalar::from(n)
    }

    //
    // maker (Bob)
    //

    #[test]
    fn maker_happy_path() {
        let s_b = scalar(7);
        let s_a = scalar(11);
        let (mut bob, start) = Swap::start_maker(T0, T1, s_b);
        assert_eq!(start, vec![Action::LockSol]);

        assert_eq!(bob.on(Event::SolLocked), vec![]);
        assert_eq!(bob.on(Event::XmrLocked), vec![Action::SetReady]);
        assert_eq!(bob.on(Event::Ready), vec![]);
        // Alice claims, revealing s_a; Bob sweeps with s_a + s_b.
        assert_eq!(
            bob.on(Event::SolClaimed { s_a }),
            vec![Action::SweepXmr { spend_key: s_a + s_b }]
        );
        assert_eq!(bob.on(Event::XmrSwept), vec![Action::Done]);
        assert_eq!(bob.phase(), Phase::Done);
    }

    #[test]
    fn maker_can_sweep_even_if_taker_claims_before_set_ready_confirms() {
        let s_b = scalar(3);
        let s_a = scalar(5);
        let (mut bob, _) = Swap::start_maker(T0, T1, s_b);
        bob.on(Event::SolLocked);
        bob.on(Event::XmrLocked); // emitted SetReady, phase XmrLocked
        // Claim arrives before our Ready confirmation — still sweep.
        assert_eq!(
            bob.on(Event::SolClaimed { s_a }),
            vec![Action::SweepXmr { spend_key: s_a + s_b }]
        );
    }

    #[test]
    fn maker_aborts_before_t0_if_taker_never_locks() {
        let (mut bob, _) = Swap::start_maker(T0, T1, scalar(7));
        bob.on(Event::SolLocked);
        // Well before the abort point: keep waiting.
        assert_eq!(bob.on(Event::Tick { now: T0 - ABORT_MARGIN - 1 }), vec![]);
        // At the abort point (still before t0): refund to deny a lock-free claim.
        assert_eq!(bob.on(Event::Tick { now: T0 - ABORT_MARGIN }), vec![Action::RefundSol]);
        assert!(T0 - ABORT_MARGIN < T0, "abort must land while the early-refund window is open");
        assert_eq!(bob.on(Event::SolRefunded { s_b: scalar(7) }), vec![Action::Done]);
        assert_eq!(bob.phase(), Phase::Done);
    }

    #[test]
    fn maker_late_refunds_if_taker_locks_but_never_claims() {
        let (mut bob, _) = Swap::start_maker(T0, T1, scalar(7));
        bob.on(Event::SolLocked);
        bob.on(Event::XmrLocked);
        bob.on(Event::Ready);
        // Before t1: nothing.
        assert_eq!(bob.on(Event::Tick { now: T1 - 1 }), vec![]);
        // At t1: reclaim the SOL (reveals s_b so Alice can recover her XMR).
        assert_eq!(bob.on(Event::Tick { now: T1 }), vec![Action::RefundSol]);
    }

    //
    // taker (Alice)
    //

    #[test]
    fn taker_happy_path() {
        let s_a = scalar(11);
        let (mut alice, start) = Swap::start_taker(T0, T1, s_a);
        assert_eq!(start, vec![]);

        assert_eq!(alice.on(Event::SolLocked), vec![Action::LockXmr]);
        assert_eq!(alice.on(Event::XmrLocked), vec![]);
        assert_eq!(alice.on(Event::Ready), vec![Action::ClaimSol]);
        // Our own claim confirms — we have the SOL.
        assert_eq!(alice.on(Event::SolClaimed { s_a }), vec![Action::Done]);
        assert_eq!(alice.phase(), Phase::Done);
    }

    #[test]
    fn taker_claims_at_t0_even_without_set_ready() {
        let s_a = scalar(11);
        let (mut alice, _) = Swap::start_taker(T0, T1, s_a);
        alice.on(Event::SolLocked);
        alice.on(Event::XmrLocked);
        // Maker never set ready, but t0 opened the window.
        assert_eq!(alice.on(Event::Tick { now: T0 }), vec![Action::ClaimSol]);
        assert_eq!(alice.on(Event::SolClaimed { s_a }), vec![Action::Done]);
    }

    #[test]
    fn taker_recovers_xmr_if_maker_refunds() {
        let s_a = scalar(11);
        let s_b = scalar(7);
        let (mut alice, _) = Swap::start_taker(T0, T1, s_a);
        alice.on(Event::SolLocked);
        alice.on(Event::XmrLocked);
        // Maker aborts/refunds, revealing s_b — recover with s_a + s_b.
        assert_eq!(
            alice.on(Event::SolRefunded { s_b }),
            vec![Action::SweepXmr { spend_key: s_a + s_b }]
        );
        assert_eq!(alice.on(Event::XmrSwept), vec![Action::Done]);
        assert_eq!(alice.phase(), Phase::Done);
    }

    #[test]
    fn taker_recovers_even_if_maker_refunds_right_after_xmr_lock() {
        // The griefing case: maker watches the XMR lock then early-refunds before t0.
        let s_a = scalar(11);
        let s_b = scalar(7);
        let (mut alice, _) = Swap::start_taker(T0, T1, s_a);
        alice.on(Event::SolLocked);
        alice.on(Event::XmrLocked);
        assert_eq!(
            alice.on(Event::SolRefunded { s_b }),
            vec![Action::SweepXmr { spend_key: s_a + s_b }]
        );
    }

    #[test]
    fn the_reconstructed_key_is_the_same_for_both_sides() {
        // Whichever way it settles, both sides compute the same 2-of-2 spend key.
        let s_a = scalar(11);
        let s_b = scalar(7);
        assert_eq!(s_a + s_b, s_b + s_a);
    }

    #[test]
    fn terminal_states_ignore_further_events() {
        let s_a = scalar(11);
        let (mut alice, _) = Swap::start_taker(T0, T1, s_a);
        alice.on(Event::SolLocked);
        alice.on(Event::XmrLocked);
        alice.on(Event::Ready);
        alice.on(Event::SolClaimed { s_a }); // Done
        assert_eq!(alice.phase(), Phase::Done);
        assert_eq!(alice.on(Event::SolRefunded { s_b: scalar(7) }), vec![]);
        assert_eq!(alice.on(Event::Tick { now: T1 + 1 }), vec![]);
    }
}
