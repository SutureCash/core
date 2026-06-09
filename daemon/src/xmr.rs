// SPDX-License-Identifier: GPL-3.0-or-later

//! The Monero side of the live executor: verify the on-chain commitment, lock into the
//! 2-of-2, scan it view-only, and sweep it with the reconstructed key.
//!
//! This drives `monero-wallet-rpc` through the `suture-monero` `wallet.rs` calls, in the
//! exact order `examples/swap_stagenet.rs` proved on live stagenet (lock -> scan -> sweep).
//! A `monero-wallet-rpc` serves one open wallet at a time, so [`XmrChain`] tracks which of
//! the funder / watch / sweep wallets is open and switches as each phase needs it.

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use monero::{Address, PrivateKey};
use serde_json::json;
use std::thread::sleep;
use std::time::Duration;
use suture_monero::wallet::{WalletError, WalletRpc};
use suture_monero::sweep_keypair;

/// The load-bearing off-chain check from SECURITY.md: before locking XMR, the taker must
/// confirm the point committed on Solana (`claim_point`) is its own spend half `s_a·G`.
/// The chain can't enforce this; if it's skipped, a malicious maker can commit a point the
/// taker can never settle against, stranding the locked XMR.
pub fn commit_matches(own_spend: &Scalar, claim_point: &[u8; 32]) -> bool {
    EdwardsPoint::mul_base(own_spend).compress().to_bytes() == *claim_point
}

/// The taker's funding wallet — an already-existing `monero-wallet-rpc` wallet file with a
/// stagenet balance, opened to send the lock from.
#[derive(Clone)]
pub struct FunderWallet {
    pub filename: String,
    pub password: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum WalletKind {
    None,
    Funder,
    Watch,
    Sweep,
}

/// How long to wait for the locked output to unlock before sweeping (Monero locks an
/// output for ~10 blocks), and how often to re-scan.
const UNLOCK_TRIES: u32 = 60;
const UNLOCK_POLL: Duration = Duration::from_secs(30);

/// The live Monero backend for one party.
pub struct XmrChain {
    rpc: WalletRpc,
    /// The shared 2-of-2 address the XMR is locked into.
    lock_addr: Address,
    /// `v_a + v_b` — scans the shared address; also the view half of the sweep wallet.
    view_secret: PrivateKey,
    restore_height: u64,
    amount: u64,
    /// Where the winner sweeps the XMR to.
    payout: Address,
    /// The taker carries a funder wallet to lock from; the maker doesn't lock, so `None`.
    funder: Option<FunderWallet>,
    /// Password for the watch/sweep wallet files this swap creates on the wallet-rpc's disk.
    /// The sweep wallet holds the full 2-of-2 spend key, so a blank password would let anyone
    /// with read access to that directory open it and sweep — the caller must supply a real one.
    wallet_password: String,
    /// Single-use wallet filenames for this swap (never reuse a shared wallet).
    watch_file: String,
    sweep_file: String,

    open: WalletKind,
    created_watch: bool,
    created_sweep: bool,
}

impl XmrChain {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rpc_url: &str,
        lock_addr: Address,
        view_secret: PrivateKey,
        restore_height: u64,
        amount: u64,
        payout: Address,
        funder: Option<FunderWallet>,
        wallet_password: &str,
        tag: &str,
    ) -> Self {
        Self {
            rpc: WalletRpc::new(rpc_url),
            lock_addr,
            view_secret,
            restore_height,
            amount,
            payout,
            funder,
            wallet_password: wallet_password.to_string(),
            watch_file: format!("suture-watch-{tag}"),
            sweep_file: format!("suture-sweep-{tag}"),
            open: WalletKind::None,
            created_watch: false,
            created_sweep: false,
        }
    }

    /// Close whatever wallet is open. `monero-wallet-rpc` serves one wallet at a time, so a
    /// failed close that we then *believed* succeeded would leave `self.open` pointing at the
    /// wrong wallet — and a later sweep could drain the wrong file. So only clear `open` if
    /// the close actually succeeded; surface the error otherwise.
    fn close_open(&mut self) -> Result<(), WalletError> {
        if self.open == WalletKind::None {
            return Ok(());
        }

        match self.rpc.close_wallet() {
            Ok(_) => {
                self.open = WalletKind::None;
                Ok(())
            }
            Err(e) => Err(WalletError::Transport(format!(
                "failed to close the {:?} wallet (open state now unknown): {e}",
                self.open
            ))),
        }
    }

    fn ensure_watch(&mut self) -> Result<(), WalletError> {
        if self.open == WalletKind::Watch {
            return Ok(());
        }

        self.close_open()?;
        if self.created_watch {
            self.rpc.call(
                "open_wallet",
                json!({ "filename": self.watch_file, "password": self.wallet_password }),
            )?;
        } else {
            self.rpc.open_watch_wallet(
                &self.watch_file,
                &self.lock_addr,
                &self.view_secret,
                self.restore_height,
                &self.wallet_password,
            )?;
            self.created_watch = true;
        }
        self.open = WalletKind::Watch;

        Ok(())
    }

    /// Lock: send `amount` from the taker's funder wallet into the 2-of-2. Returns the tx
    /// hash. Maker callers have no funder and get a clear error.
    pub fn lock(&mut self) -> Result<String, WalletError> {
        let funder = self
            .funder
            .clone()
            .ok_or_else(|| WalletError::Transport("no funder wallet configured to lock from".into()))?;

        self.close_open()?;
        self.rpc.call(
            "open_wallet",
            json!({ "filename": funder.filename, "password": funder.password }),
        )?;
        self.open = WalletKind::Funder;
        self.rpc.refresh()?;

        let res = self.rpc.lock(&self.lock_addr, self.amount)?;
        self.close_open()?;

        Ok(res["tx_hash"].as_str().unwrap_or_default().to_string())
    }

    /// True once the locked output is *confirmed and spendable* in the 2-of-2
    /// (`unlocked_balance ≥ amount`), not merely seen at 0-conf (`balance`). The maker arms
    /// `set_ready` — an irreversible commitment that opens the taker's claim window — off
    /// this signal, so it must reflect real confirmed XMR: a 0-conf or reorg-dropped output
    /// must not count, or the maker could open the claim window against XMR that never lands.
    pub fn locked(&mut self) -> Result<bool, WalletError> {
        self.ensure_watch()?;

        // A failed refresh means the balance below is stale; don't silently trust it.
        if let Err(e) = self.rpc.refresh() {
            eprintln!("xmr locked(): refresh failed, balance may be stale: {e}");
        }

        let b = self.rpc.balance()?;
        let unlocked = b["unlocked_balance"].as_u64().unwrap_or(0);

        Ok(unlocked >= self.amount)
    }

    /// Sweep: rebuild the full wallet from `s_a + s_b`, wait for the output to unlock, and
    /// sweep everything to the payout address. Returns the sweep tx hashes.
    pub fn sweep(&mut self, spend_key: Scalar) -> Result<Vec<String>, WalletError> {
        let spend = PrivateKey::from_slice(spend_key.as_bytes())
            .map_err(|e| WalletError::Transport(format!("reconstructed spend key invalid: {e}")))?;
        let keys = sweep_keypair(spend, self.view_secret);

        self.close_open()?;
        if self.created_sweep {
            self.rpc.call(
                "open_wallet",
                json!({ "filename": self.sweep_file, "password": self.wallet_password }),
            )?;
        } else {
            self.rpc.open_sweep_wallet(
                &self.sweep_file,
                &self.lock_addr,
                &keys,
                self.restore_height,
                &self.wallet_password,
            )?;
            self.created_sweep = true;
        }
        self.open = WalletKind::Sweep;

        // Wait for the output to unlock; sweep_all fails if nothing is spendable yet.
        let mut unlocked = false;
        for _ in 0..UNLOCK_TRIES {
            // A stale balance read here would burn the whole wait on bad data, so surface
            // refresh failures rather than swallowing them.
            if let Err(e) = self.rpc.refresh() {
                eprintln!("xmr sweep(): refresh failed during unlock wait, balance may be stale: {e}");
            }

            let b = self.rpc.balance()?;
            if b["unlocked_balance"].as_u64().unwrap_or(0) >= self.amount {
                unlocked = true;
                break;
            }

            sleep(UNLOCK_POLL);
        }

        // If we timed out without the output unlocking, do NOT sweep blindly — sweep_all on
        // nothing-spendable just errors, and worse a partial state could move the wrong
        // funds. Bail with the wallet filename so the operator can open it and sweep by hand;
        // the funds are sitting in this wallet file, recoverable.
        if !unlocked {
            return Err(WalletError::Transport(format!(
                "sweep timed out waiting for the 2-of-2 output to unlock after {} tries; \
                 the XMR is in wallet file '{}' — open it and sweep manually",
                UNLOCK_TRIES, self.sweep_file
            )));
        }

        let swept = self.rpc.sweep_all(&self.payout)?;
        self.close_open()?;

        let txs = swept["tx_hash_list"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        
        Ok(txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monero::PublicKey;

    #[test]
    fn commit_matches_only_its_own_point() {
        let s = Scalar::from(123456789u64);
        let point = EdwardsPoint::mul_base(&s).compress().to_bytes();
        assert!(commit_matches(&s, &point));

        let other = EdwardsPoint::mul_base(&Scalar::from(987654321u64))
            .compress()
            .to_bytes();
        assert!(!commit_matches(&s, &other));
    }

    #[test]
    fn a_dalek_scalar_and_a_monero_key_agree_on_the_point() {
        // The seam the whole daemon rests on: the engine works in curve25519-dalek
        // scalars, the Monero side in `monero` keys. A scalar's point under dalek must
        // equal the same scalar's Monero public key, or `claim_point` and the Monero key
        // half would diverge. Same curve, same basepoint, same compression — so they do.
        let s = Scalar::from(424242u64);

        let dalek_point = EdwardsPoint::mul_base(&s).compress().to_bytes();

        let priv_key = PrivateKey::from_slice(s.as_bytes()).expect("canonical scalar");
        let monero_point = PublicKey::from_private_key(&priv_key).as_bytes().to_vec();

        assert_eq!(dalek_point.to_vec(), monero_point);
    }

    #[test]
    fn reconstructed_spend_scalar_round_trips_to_a_private_key() {
        let s = Scalar::from(11u64) + Scalar::from(7u64); // s_a + s_b
        let key = PrivateKey::from_slice(s.as_bytes()).expect("valid key");
        assert_eq!(key.as_bytes(), s.as_bytes());
    }
}
