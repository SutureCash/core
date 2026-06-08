// SPDX-License-Identifier: GPL-3.0-or-later

//! The live executor: the engine's [`SwapChains`] seam implemented over real chains, plus
//! the watcher and run loop that turn chain observations into the state machine's events.
//!
//! This is where the two repos finally meet. The [`swap`](suture_engine::swap) state
//! machine decides *what* to do; [`LiveChains`] does it — `lock_sol`/`set_ready`/`refund`
//! go to the `sol-escrow` program over Solana RPC ([`crate::sol`]), `lock_xmr`/`sweep_xmr`
//! go to the Monero 2-of-2 over `monero-wallet-rpc` ([`crate::xmr`]). The other direction
//! is [`LiveChains::poll`]: it reads the escrow account and the 2-of-2 balance, plus a
//! clock, and emits the [`Event`]s the machine consumes. The daemon loop is exactly what
//! the executor's doc comment promised: observe an event -> `swap.on(event)` -> `execute`.
//!
//! The `SwapChains` methods are infallible by signature (the engine's design), so a failed
//! chain call is recorded as a *fault* the run loop surfaces and stops on, rather than
//! silently dropped. Because every event is derived from on-chain state, a stopped daemon
//! can be restarted and the timelocks keep funds recoverable in the meantime.

use crate::xmr::commit_matches;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use std::thread::sleep;
use std::time::Duration;
use suture_engine::executor::{execute, SwapChains};
use suture_engine::swap::{Event, Phase, Role, Swap};

/// The slice of escrow state the watcher needs. Built from the decoded on-chain account
/// (or a simulation in tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowView {
    pub ready: bool,
    pub settled: bool,
    /// The scalar published when the escrow settled (zero until then).
    pub revealed: [u8; 32],
}

/// The Solana operations the executor and watcher need. The live impl is
/// [`crate::sol::RpcSol`]; tests supply a simulation. Errors are returned as strings so a
/// single fault channel can carry failures from either chain.
pub trait SolBackend {
    fn lock(&mut self) -> Result<(), String>;
    fn set_ready(&mut self) -> Result<(), String>;
    fn claim(&mut self) -> Result<(), String>;
    fn refund(&mut self) -> Result<(), String>;
    /// The current escrow state, or `None` if it hasn't been created yet.
    fn read_escrow(&mut self) -> Result<Option<EscrowView>, String>;
}

/// The Monero operations the executor and watcher need. The live impl is
/// [`crate::xmr::XmrChain`]; tests supply a simulation.
pub trait XmrBackend {
    fn lock(&mut self) -> Result<(), String>;
    /// True once the locked output is visible in the 2-of-2.
    fn locked(&mut self) -> Result<bool, String>;
    fn sweep(&mut self, spend_key: Scalar) -> Result<(), String>;
}

/// One party's live view of a swap: the two chain backends plus enough key material to run
/// the load-bearing commitment check and to tell a claim reveal from a refund reveal.
pub struct LiveChains<S, X> {
    role: Role,
    /// This party's own spend half — `s_b` (maker) or `s_a` (taker).
    own_spend: Scalar,
    /// `s_a · G`: the taker's half. A reveal matching this is a claim.
    claim_point: [u8; 32],
    /// `s_b · G`: the maker's half. A reveal matching this is a refund.
    refund_point: [u8; 32],
    sol: S,
    xmr: X,

    fault: Option<String>,
    /// Set once this party's own sweep lands, so the watcher can emit `XmrSwept`.
    swept: bool,

    // The watcher emits each transition once.
    seen_sol_locked: bool,
    seen_xmr_locked: bool,
    seen_ready: bool,
    seen_settled: bool,
    seen_xmr_swept: bool,
}

impl<S: SolBackend, X: XmrBackend> LiveChains<S, X> {
    pub fn new(
        role: Role,
        own_spend: Scalar,
        claim_point: [u8; 32],
        refund_point: [u8; 32],
        sol: S,
        xmr: X,
    ) -> Self {
        Self {
            role,
            own_spend,
            claim_point,
            refund_point,
            sol,
            xmr,
            fault: None,
            swept: false,
            seen_sol_locked: false,
            seen_xmr_locked: false,
            seen_ready: false,
            seen_settled: false,
            seen_xmr_swept: false,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// The Solana backend, for operations outside the swap state machine — e.g. a maker
    /// calling `close` to reclaim the escrow rent after a settled swap.
    pub fn sol_backend(&mut self) -> &mut S {
        &mut self.sol
    }

    /// Take any recorded fault (a chain call that failed). The run loop checks this after
    /// each action and stops if a fund-moving step couldn't be carried out.
    pub fn take_fault(&mut self) -> Option<String> {
        self.fault.take()
    }

    fn fail(&mut self, what: &str, e: String) {
        let msg = format!("{what} failed: {e}");

        if self.fault.is_none() {
            self.fault = Some(msg);
        }
    }

    /// Read the chains and the clock; emit the events the state machine hasn't seen yet, in
    /// causal order (lock -> xmr lock -> ready -> settle -> sweep), with a `Tick` last so the
    /// machine can act on timeouts. Transient read errors are skipped — the next poll retries.
    pub fn poll(&mut self, now: i64) -> Vec<Event> {
        let mut events = Vec::new();

        if let Ok(Some(escrow)) = self.sol.read_escrow() {
            if !self.seen_sol_locked {
                self.seen_sol_locked = true;
                events.push(Event::SolLocked);
            }
            
            if escrow.settled {
                // Once the escrow has settled, the settlement is the only meaningful
                // transition. Suppressing the pre-settlement events matters on a catch-up
                // poll (a daemon that fell behind, or came back after a refund): a stale
                // `Ready` would otherwise drive the taker to attempt a claim the program
                // has already closed off, and the recovery path keys off the settle event
                // regardless of which earlier phases were observed.
                if !self.seen_settled {
                    self.seen_settled = true;
                    if let Some(event) = self.settle_event(&escrow.revealed) {
                        events.push(event);
                    }
                }
            } else {
                if !self.seen_xmr_locked {
                    if let Ok(true) = self.xmr.locked() {
                        self.seen_xmr_locked = true;
                        events.push(Event::XmrLocked);
                    }
                }
                if escrow.ready && !self.seen_ready {
                    self.seen_ready = true;
                    events.push(Event::Ready);
                }
            }
        }

        if self.swept && !self.seen_xmr_swept {
            self.seen_xmr_swept = true;
            events.push(Event::XmrSwept);
        }

        events.push(Event::Tick { now });
        events
    }

    /// Classify a revealed scalar: a reveal whose point is `claim_point` came from a claim
    /// (it's `s_a`); one matching `refund_point` came from a refund (`s_b`).
    fn settle_event(&self, revealed: &[u8; 32]) -> Option<Event> {
        let ct = Scalar::from_canonical_bytes(*revealed);
        if !bool::from(ct.is_some()) {
            return None;
        }

        let scalar = ct.unwrap();
        let point = EdwardsPoint::mul_base(&scalar).compress().to_bytes();
        if point == self.claim_point {
            Some(Event::SolClaimed { s_a: scalar })
        } else if point == self.refund_point {
            Some(Event::SolRefunded { s_b: scalar })
        } else {
            None
        }
    }
}

impl<S: SolBackend, X: XmrBackend> SwapChains for LiveChains<S, X> {
    fn lock_sol(&mut self) {
        if let Err(e) = self.sol.lock() {
            self.fail("lock_sol", e);
        }
    }

    fn set_ready(&mut self) {
        if let Err(e) = self.sol.set_ready() {
            self.fail("set_ready", e);
        }
    }

    fn lock_xmr(&mut self) {
        // The load-bearing off-chain check: never lock XMR unless the point committed on
        // Solana is our own spend half. Otherwise a malicious maker could commit a point we
        // can't settle against and strand the XMR.
        if !commit_matches(&self.own_spend, &self.claim_point) {
            self.fail(
                "lock_xmr",
                "committed claim_point does not equal s_a·G — refusing to lock".into(),
            );
            return;
        }
        
        if let Err(e) = self.xmr.lock() {
            self.fail("lock_xmr", e);
        }
    }

    fn claim_sol(&mut self) {
        if let Err(e) = self.sol.claim() {
            self.fail("claim_sol", e);
        }
    }

    fn refund_sol(&mut self) {
        if let Err(e) = self.sol.refund() {
            self.fail("refund_sol", e);
        }
    }

    fn sweep_xmr(&mut self, spend_key: Scalar) {
        match self.xmr.sweep(spend_key) {
            Ok(()) => self.swept = true,
            Err(e) => self.fail("sweep_xmr", e),
        }
    }
}

/// Run a party's swap to completion: poll -> drive the state machine -> execute its actions,
/// until the swap is `Done` or a fault / deadline stops it. `clock` returns the current unix
/// time (a closure so callers — and tests — control it). The caller executes the start
/// actions (e.g. the maker's first `LockSol`) before calling this.
pub fn run<S, X>(
    swap: &mut Swap,
    chains: &mut LiveChains<S, X>,
    clock: impl Fn() -> i64,
    poll_interval: Duration,
    deadline: i64,
) -> Result<(), String>
where
    S: SolBackend,
    X: XmrBackend,
{
    loop {
        let now = clock();

        for event in chains.poll(now) {
            for action in swap.on(event) {
                execute(action, chains);
                if let Some(fault) = chains.take_fault() {
                    return Err(fault);
                }
            }
        }

        if swap.phase() == Phase::Done {
            return Ok(());
        }

        if now > deadline {
            return Err(format!("deadline {deadline} passed without completing the swap"));
        }

        sleep(poll_interval);
    }
}

//
// Adapters: the live backends implement the traits above over the concrete RPC clients.
//

impl SolBackend for crate::sol::RpcSol {
    fn lock(&mut self) -> Result<(), String> {
        crate::sol::RpcSol::lock(self).map(|_| ()).map_err(|e| e.to_string())
    }
    fn set_ready(&mut self) -> Result<(), String> {
        crate::sol::RpcSol::set_ready(self).map(|_| ()).map_err(|e| e.to_string())
    }
    fn claim(&mut self) -> Result<(), String> {
        crate::sol::RpcSol::claim(self).map(|_| ()).map_err(|e| e.to_string())
    }
    fn refund(&mut self) -> Result<(), String> {
        crate::sol::RpcSol::refund(self).map(|_| ()).map_err(|e| e.to_string())
    }
    fn read_escrow(&mut self) -> Result<Option<EscrowView>, String> {
        crate::sol::RpcSol::read_escrow(self)
            .map(|opt| {
                opt.map(|e| EscrowView {
                    ready: e.ready,
                    settled: e.settled,
                    revealed: e.revealed,
                })
            })
            .map_err(|e| e.to_string())
    }
}

impl XmrBackend for crate::xmr::XmrChain {
    fn lock(&mut self) -> Result<(), String> {
        crate::xmr::XmrChain::lock(self).map(|_| ()).map_err(|e| e.to_string())
    }
    fn locked(&mut self) -> Result<bool, String> {
        crate::xmr::XmrChain::locked(self).map_err(|e| e.to_string())
    }
    fn sweep(&mut self, spend_key: Scalar) -> Result<(), String> {
        crate::xmr::XmrChain::sweep(self, spend_key).map(|_| ()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use suture_engine::swap::Action;

    const T0: i64 = 10_000;
    const T1: i64 = 20_000;

    /// One shared world both parties' backends read and write — the daemon-level analog of
    /// the executor's `SimChains`, but split across two `LiveChains` so the watcher's event
    /// derivation is exercised end to end. It enforces the same escrow windows and 2-of-2
    /// key check the real chains do.
    struct World {
        exists: bool,
        ready: bool,
        settled: bool,
        revealed: [u8; 32],
        xmr_locked: bool,
        xmr_swept: bool,
        now: i64,
        s_a: Scalar,
        s_b: Scalar,
    }

    type Shared = Rc<RefCell<World>>;

    fn world(s_a: Scalar, s_b: Scalar) -> Shared {
        Rc::new(RefCell::new(World {
            exists: false,
            ready: false,
            settled: false,
            revealed: [0u8; 32],
            xmr_locked: false,
            xmr_swept: false,
            now: 0,
            s_a,
            s_b,
        }))
    }

    struct SimSol {
        w: Shared,
        reveal: [u8; 32],
    }

    impl SolBackend for SimSol {
        fn lock(&mut self) -> Result<(), String> {
            self.w.borrow_mut().exists = true;

            Ok(())
        }
        fn set_ready(&mut self) -> Result<(), String> {
            let mut w = self.w.borrow_mut();
            if w.now >= T1 {
                return Err("set_ready after the window closed".into());
            }
            w.ready = true;

            Ok(())
        }
        fn claim(&mut self) -> Result<(), String> {
            let mut w = self.w.borrow_mut();
            if w.settled {
                return Err("double settle".into());
            }

            let open = w.ready || w.now >= T0;
            if !(open && w.now < T1) {
                return Err("claim outside the window".into());
            }

            w.settled = true;
            w.revealed = self.reveal;

            Ok(())
        }
        fn refund(&mut self) -> Result<(), String> {
            let mut w = self.w.borrow_mut();
            if w.settled {
                return Err("double settle".into());
            }

            let early = w.now < T0 && !w.ready;
            let late = w.now >= T1;
            if !(early || late) {
                return Err("refund outside the window".into());
            }

            w.settled = true;
            w.revealed = self.reveal;

            Ok(())
        }
        fn read_escrow(&mut self) -> Result<Option<EscrowView>, String> {
            let w = self.w.borrow();
            if !w.exists {
                return Ok(None);
            }

            Ok(Some(EscrowView {
                ready: w.ready,
                settled: w.settled,
                revealed: w.revealed,
            }))
        }
    }

    struct SimXmr {
        w: Shared,
        /// A maker that hasn't yet observed the taker's lock — models the propagation race
        /// where the maker aborts before seeing the XMR (its abort still reveals `s_b`).
        blind: bool,
    }

    impl XmrBackend for SimXmr {
        fn lock(&mut self) -> Result<(), String> {
            self.w.borrow_mut().xmr_locked = true;

            Ok(())
        }
        fn locked(&mut self) -> Result<bool, String> {
            if self.blind {
                return Ok(false);
            }

            Ok(self.w.borrow().xmr_locked)
        }
        fn sweep(&mut self, spend_key: Scalar) -> Result<(), String> {
            let mut w = self.w.borrow_mut();
            if !w.xmr_locked {
                return Err("nothing to sweep".into());
            }
            if w.xmr_swept {
                return Err("double sweep".into());
            }

            let shared = EdwardsPoint::mul_base(&(w.s_a + w.s_b));
            if EdwardsPoint::mul_base(&spend_key) != shared {
                return Err("sweep key does not open the 2-of-2".into());
            }

            w.xmr_swept = true;

            Ok(())
        }
    }

    fn chains(role: Role, own: Scalar, w: &Shared, reveal: Scalar, blind: bool) -> LiveChains<SimSol, SimXmr> {
        let claim_point = EdwardsPoint::mul_base(&w.borrow().s_a).compress().to_bytes();
        let refund_point = EdwardsPoint::mul_base(&w.borrow().s_b).compress().to_bytes();
        
        LiveChains::new(
            role,
            own,
            claim_point,
            refund_point,
            SimSol { w: w.clone(), reveal: reveal.to_bytes() },
            SimXmr { w: w.clone(), blind },
        )
    }

    /// Drive one poll -> state-machine -> execute cycle for a party, asserting no fault.
    fn step(swap: &mut Swap, lc: &mut LiveChains<SimSol, SimXmr>, now: i64) {
        for event in lc.poll(now) {
            for action in swap.on(event) {
                execute(action, lc);
                assert!(lc.take_fault().is_none(), "unexpected fault driving {:?}", lc.role());
            }
        }
    }

    fn keys() -> (Scalar, Scalar) {
        (Scalar::from(11u64), Scalar::from(7u64)) // s_a, s_b
    }

    #[test]
    fn happy_path_drives_both_parties_to_done() {
        let (s_a, s_b) = keys();
        let w = world(s_a, s_b);
        let (mut maker, m_init) = Swap::start_maker(T0, T1, s_b);
        let (mut taker, _t_init) = Swap::start_taker(T0, T1, s_a);
        let mut mc = chains(Role::Maker, s_b, &w, s_b, false);
        let mut tc = chains(Role::Taker, s_a, &w, s_a, false);

        for a in m_init {
            execute(a, &mut mc); // LockSol
        }
        assert!(w.borrow().exists);

        // A handful of poll cycles is plenty for the whole handshake to settle.
        for _ in 0..12 {
            step(&mut maker, &mut mc, 0);
            step(&mut taker, &mut tc, 0);
            if maker.phase() == Phase::Done && taker.phase() == Phase::Done {
                break;
            }
        }

        assert_eq!(maker.phase(), Phase::Done);
        assert_eq!(taker.phase(), Phase::Done);
        let wb = w.borrow();
        assert!(wb.settled, "escrow settled");
        assert_eq!(wb.revealed, s_a.to_bytes(), "claim published s_a");
        assert!(wb.xmr_swept, "maker swept the XMR");
    }

    #[test]
    fn maker_aborts_and_recovers_when_taker_never_locks() {
        let (s_a, s_b) = keys();
        let w = world(s_a, s_b);
        let (mut maker, m_init) = Swap::start_maker(T0, T1, s_b);
        let mut mc = chains(Role::Maker, s_b, &w, s_b, false);

        for a in m_init {
            execute(a, &mut mc);
        }

        // No taker. Advance to the abort point (still before t0).
        let now = T0 - suture_engine::swap::ABORT_MARGIN;
        w.borrow_mut().now = now;
        for _ in 0..6 {
            step(&mut maker, &mut mc, now);
            if maker.phase() == Phase::Done {
                break;
            }
        }

        assert_eq!(maker.phase(), Phase::Done);
        let wb = w.borrow();
        assert!(wb.settled);
        assert_eq!(wb.revealed, s_b.to_bytes(), "refund published s_b");
        assert!(!wb.xmr_locked, "no XMR was ever at risk");
    }

    #[test]
    fn taker_recovers_when_maker_aborts_after_the_xmr_lock() {
        // The griefing race: the taker locks XMR, but the maker (not yet seeing it) aborts
        // before t0. The abort reveals s_b, so the taker rebuilds s_a + s_b and recovers.
        let (s_a, s_b) = keys();
        let w = world(s_a, s_b);
        let (mut maker, m_init) = Swap::start_maker(T0, T1, s_b);
        let (mut taker, _t) = Swap::start_taker(T0, T1, s_a);
        let mut mc = chains(Role::Maker, s_b, &w, s_b, true); // maker is blind to the lock
        let mut tc = chains(Role::Taker, s_a, &w, s_a, false);

        for a in m_init {
            execute(a, &mut mc);
        }

        // Taker sees the SOL lock and locks XMR.
        step(&mut taker, &mut tc, 0);
        assert!(w.borrow().xmr_locked);

        // Maker reaches the abort point without having observed the lock -> refunds.
        let now = T0 - suture_engine::swap::ABORT_MARGIN;
        w.borrow_mut().now = now;
        for _ in 0..6 {
            step(&mut maker, &mut mc, now);
            if maker.phase() == Phase::Done {
                break;
            }
        }
        assert!(w.borrow().settled);
        assert_eq!(w.borrow().revealed, s_b.to_bytes());

        // Taker observes the refund and recovers the XMR.
        for _ in 0..6 {
            step(&mut taker, &mut tc, now);
            if taker.phase() == Phase::Done {
                break;
            }
        }
        assert_eq!(taker.phase(), Phase::Done);
        assert!(w.borrow().xmr_swept, "taker recovered the XMR");
    }

    #[test]
    fn taker_recovers_when_it_locks_but_misses_the_claim_window() {
        let (s_a, s_b) = keys();
        let w = world(s_a, s_b);
        let (mut maker, m_init) = Swap::start_maker(T0, T1, s_b);
        let (mut taker, _t) = Swap::start_taker(T0, T1, s_a);
        let mut mc = chains(Role::Maker, s_b, &w, s_b, false);
        let mut tc = chains(Role::Taker, s_a, &w, s_a, false);

        for a in m_init {
            execute(a, &mut mc);
        }

        // The taker comes online once, locks XMR, then goes offline before claiming.
        step(&mut taker, &mut tc, 0);
        assert!(w.borrow().xmr_locked);

        // The maker observes the lock and arms the claim window — but the taker, now
        // offline, never claims.
        for _ in 0..4 {
            step(&mut maker, &mut mc, 0);
        }
        assert!(w.borrow().ready);
        assert!(!w.borrow().settled, "the taker never claimed");

        // t1 passes and the maker reclaims the SOL.
        let now = T1;
        w.borrow_mut().now = now;
        for _ in 0..6 {
            step(&mut maker, &mut mc, now);
            if maker.phase() == Phase::Done {
                break;
            }
        }
        assert!(w.borrow().settled);
        assert_eq!(w.borrow().revealed, s_b.to_bytes(), "late refund revealed s_b");

        // The taker comes back, sees the refund, and recovers the XMR with s_a + s_b.
        for _ in 0..6 {
            step(&mut taker, &mut tc, now);
            if taker.phase() == Phase::Done {
                break;
            }
        }
        assert_eq!(taker.phase(), Phase::Done);
        assert!(w.borrow().xmr_swept, "taker recovered the XMR after t1");
    }

    #[test]
    fn refusing_to_lock_xmr_on_a_mismatched_commitment_is_a_fault() {
        // If the on-chain claim_point isn't the taker's s_a·G, lock_xmr must refuse.
        let (s_a, s_b) = keys();
        let w = world(s_a, s_b);
        let mut tc = LiveChains::new(
            Role::Taker,
            s_a,
            EdwardsPoint::mul_base(&Scalar::from(999u64)).compress().to_bytes(), // wrong claim_point
            EdwardsPoint::mul_base(&s_b).compress().to_bytes(),
            SimSol { w: w.clone(), reveal: s_a.to_bytes() },
            SimXmr { w: w.clone(), blind: false },
        );

        execute(Action::LockXmr, &mut tc);
        assert!(tc.take_fault().is_some(), "a mismatched commitment must fault, not lock");
        assert!(!w.borrow().xmr_locked, "no XMR locked against a bad commitment");
    }
}
