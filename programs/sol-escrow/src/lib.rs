// SPDX-License-Identifier: GPL-3.0-or-later

//! SOL side of a Suture XMR⇄SOL atomic swap.
//!
//! Bob has SOL and wants XMR; Alice has XMR and wants SOL. Bob locks his SOL here
//! and commits to two Ed25519 points: Alice's `claim_point` (= s_a·G) and his own
//! `refund_point` (= s_b·G), where s_a and s_b are the two halves of the 2-of-2
//! Monero spend key. Whoever settles the escrow has to hand over the matching
//! scalar, and the program publishes it. That published scalar is exactly what the
//! other party needs to complete the trade on the Monero side, which is what makes
//! the swap atomic without anyone holding both coins.
//!
//! Two timelocks order the endgame so the two sides can never both win or both lose:
//!
//!   - before t0 (and before Bob calls set_ready): only Bob can refund — an early
//!     abort if Alice never locked her XMR.
//!   - once ready (or t0 passes) and before t1: only Alice can claim. Claiming
//!     reveals s_a, letting Bob sweep the XMR.
//!   - at/after t1: only Bob can refund — Alice missed her window. Refunding reveals
//!     s_b, letting Alice recover her XMR.
//!
//! The windows never overlap, so at most one of claim/refund is ever valid, and the
//! `settled` flag makes sure it happens exactly once.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_curve25519::{
    edwards::{multiply_edwards, PodEdwardsPoint},
    scalar::PodScalar,
};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::{clock::Clock, Sysvar},
};
use solana_system_interface::instruction as system_instruction;

/// Compressed Ed25519 basepoint. Same generator Monero builds its keys on, which
/// is why a point committed here doubles as a Monero public key share with no
/// cross-curve proof. (Little-endian: 0x58 followed by 31 bytes of 0x66.)
const ED25519_BASEPOINT: PodEdwardsPoint = PodEdwardsPoint([
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
]);

const ESCROW_SEED: &[u8] = b"escrow";

/// The System Program address is the all-zero pubkey.
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// Basis points are out of 10_000. Cap the fee so a buggy or malicious offer can't
/// swallow the whole trade.
const MAX_FEE_BPS: u16 = 300; // 3%

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum SwapInstruction {
    /// Bob locks `amount` lamports and pins the swap terms.
    /// Accounts: [locker (signer, writable), escrow PDA (writable), system program]
    Lock {
        id: [u8; 32],
        claimer: [u8; 32],
        fee_recipient: [u8; 32],
        claim_point: [u8; 32],
        refund_point: [u8; 32],
        amount: u64,
        fee_bps: u16,
        t0: i64,
        t1: i64,
    },
    /// Bob signals he has seen Alice's XMR lock, opening Alice's claim window early.
    /// Accounts: [escrow PDA (writable), locker (signer)]
    SetReady,
    /// Alice claims the SOL by revealing s_a. Pays claimer (minus fee) and fee_recipient.
    /// Accounts: [escrow PDA (writable), claimer (writable), fee_recipient (writable)]
    Claim { reveal: [u8; 32] },
    /// Bob reclaims the SOL by revealing s_b inside a refund window.
    /// Accounts: [escrow PDA (writable), locker (writable)]
    Refund { reveal: [u8; 32] },
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Default)]
pub struct Escrow {
    pub locker: [u8; 32],
    pub claimer: [u8; 32],
    pub fee_recipient: [u8; 32],
    pub claim_point: [u8; 32],
    pub refund_point: [u8; 32],
    pub amount: u64,
    pub fee_bps: u16,
    pub t0: i64,
    pub t1: i64,
    pub id: [u8; 32],
    pub bump: u8,
    pub ready: bool,
    pub settled: bool,
    /// Zero until the escrow settles, then the scalar that was revealed to settle it.
    pub revealed: [u8; 32],
}

impl Escrow {
    // Fixed-size struct, so the account size is constant.
    const LEN: usize = 32 * 5 + 8 + 2 + 8 + 8 + 32 + 1 + 1 + 1 + 32;
}

#[derive(Clone, Copy)]
pub enum EscrowError {
    BadSecret = 0,
    AlreadySettled,
    NotInClaimWindow,
    NotInRefundWindow,
    Unauthorized,
    BadAccount,
    FeeTooHigh,
    BadWindows,
}

impl From<EscrowError> for ProgramError {
    fn from(e: EscrowError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match SwapInstruction::try_from_slice(data)? {
        SwapInstruction::Lock {
            id,
            claimer,
            fee_recipient,
            claim_point,
            refund_point,
            amount,
            fee_bps,
            t0,
            t1,
        } => lock(
            program_id,
            accounts,
            id,
            claimer,
            fee_recipient,
            claim_point,
            refund_point,
            amount,
            fee_bps,
            t0,
            t1,
        ),
        SwapInstruction::SetReady => set_ready(accounts),
        SwapInstruction::Claim { reveal } => claim(accounts, reveal),
        SwapInstruction::Refund { reveal } => refund(accounts, reveal),
    }
}

#[allow(clippy::too_many_arguments)]
fn lock(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    id: [u8; 32],
    claimer: [u8; 32],
    fee_recipient: [u8; 32],
    claim_point: [u8; 32],
    refund_point: [u8; 32],
    amount: u64,
    fee_bps: u16,
    t0: i64,
    t1: i64,
) -> ProgramResult {
    if fee_bps > MAX_FEE_BPS {
        return Err(EscrowError::FeeTooHigh.into());
    }
    
    // t0 < t1 keeps the abort / claim / refund windows in the right order, and a
    // claim window has to actually exist.
    if t0 >= t1 {
        return Err(EscrowError::BadWindows.into());
    }

    let iter = &mut accounts.iter();
    let locker = next_account_info(iter)?;
    let escrow_ai = next_account_info(iter)?;
    let system = next_account_info(iter)?;

    if !locker.is_signer {
        return Err(EscrowError::Unauthorized.into());
    }
    if *system.key != SYSTEM_PROGRAM_ID {
        return Err(EscrowError::BadAccount.into());
    }

    let (expected, bump) =
        Pubkey::find_program_address(&[ESCROW_SEED, locker.key.as_ref(), &id], program_id);
    if expected != *escrow_ai.key {
        return Err(EscrowError::BadAccount.into());
    }

    // Create the PDA with rent + the locked amount in one shot, owned by us so we
    // can move its lamports out later without a signature.
    let rent = Rent::get()?.minimum_balance(Escrow::LEN);
    let lamports = rent
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    invoke_signed(
        &system_instruction::create_account(
            locker.key,
            escrow_ai.key,
            lamports,
            Escrow::LEN as u64,
            program_id,
        ),
        &[locker.clone(), escrow_ai.clone(), system.clone()],
        &[&[ESCROW_SEED, locker.key.as_ref(), &id, &[bump]]],
    )?;

    let escrow = Escrow {
        locker: locker.key.to_bytes(),
        claimer,
        fee_recipient,
        claim_point,
        refund_point,
        amount,
        fee_bps,
        t0,
        t1,
        id,
        bump,
        ready: false,
        settled: false,
        revealed: [0u8; 32],
    };
    store(&escrow, escrow_ai)?;

    msg!("locked {} lamports, t0={}, t1={}", amount, t0, t1);

    Ok(())
}

fn set_ready(accounts: &[AccountInfo]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let escrow_ai = next_account_info(iter)?;
    let locker = next_account_info(iter)?;

    let mut escrow = load(escrow_ai)?;
    if escrow.settled {
        return Err(EscrowError::AlreadySettled.into());
    }

    if !locker.is_signer || locker.key.to_bytes() != escrow.locker {
        return Err(EscrowError::Unauthorized.into());
    }

    // No point arming the claim window once it has already closed.
    if now()? >= escrow.t1 {
        return Err(EscrowError::NotInClaimWindow.into());
    }
    
    escrow.ready = true;
    store(&escrow, escrow_ai)?;

    Ok(())
}

fn claim(accounts: &[AccountInfo], reveal: [u8; 32]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let escrow_ai = next_account_info(iter)?;
    let claimer = next_account_info(iter)?;
    let fee_recipient = next_account_info(iter)?;

    let mut escrow = load(escrow_ai)?;
    if escrow.settled {
        return Err(EscrowError::AlreadySettled.into());
    }
    
    // Alice's window: open once Bob is ready or t0 has passed, closed at t1.
    let t = now()?;
    let open = escrow.ready || t >= escrow.t0;
    if !(open && t < escrow.t1) {
        return Err(EscrowError::NotInClaimWindow.into());
    }
    if !reveal_matches(&reveal, &escrow.claim_point) {
        return Err(EscrowError::BadSecret.into());
    }
    if claimer.key.to_bytes() != escrow.claimer
        || fee_recipient.key.to_bytes() != escrow.fee_recipient
    {
        return Err(EscrowError::BadAccount.into());
    }

    let fee = (escrow.amount as u128 * escrow.fee_bps as u128 / 10_000u128) as u64;
    let to_claimer = escrow.amount - fee; // fee <= 3% of amount, so this never underflows

    // Both payouts have to leave their accounts rent-exempt: the runtime rejects any
    // credit that puts an account at a non-zero balance below the rent minimum. The
    // fee account is meant to be a long-lived, already-funded treasury, and a real
    // swap amount dwarfs the rent floor, so this holds in practice.
    move_lamports(escrow_ai, claimer, to_claimer)?;
    if fee > 0 {
        move_lamports(escrow_ai, fee_recipient, fee)?;
    }

    escrow.revealed = reveal;
    escrow.settled = true;
    store(&escrow, escrow_ai)?;

    // Bob's daemon watches for this to pull s_a off-chain and sweep the XMR.
    msg!("claimed; revealed {}", hex32(&reveal));

    Ok(())
}

fn refund(accounts: &[AccountInfo], reveal: [u8; 32]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let escrow_ai = next_account_info(iter)?;
    let locker = next_account_info(iter)?;

    let mut escrow = load(escrow_ai)?;
    if escrow.settled {
        return Err(EscrowError::AlreadySettled.into());
    }

    // Bob's window: early abort before t0 (only while not yet ready), or after t1.
    let t = now()?;
    let early = t < escrow.t0 && !escrow.ready;
    let late = t >= escrow.t1;
    if !(early || late) {
        return Err(EscrowError::NotInRefundWindow.into());
    }
    if !reveal_matches(&reveal, &escrow.refund_point) {
        return Err(EscrowError::BadSecret.into());
    }
    if locker.key.to_bytes() != escrow.locker {
        return Err(EscrowError::BadAccount.into());
    }

    move_lamports(escrow_ai, locker, escrow.amount)?;

    escrow.revealed = reveal;
    escrow.settled = true;
    store(&escrow, escrow_ai)?;

    msg!("refunded; revealed {}", hex32(&reveal));

    Ok(())
}

/// The check the whole thing rests on: does `reveal · G` land on the committed
/// point? On-chain this is the curve25519 syscall; off-chain (tests) it's
/// curve25519-dalek. A non-canonical scalar makes the syscall return None, which
/// we treat as a failed reveal.
fn reveal_matches(reveal: &[u8; 32], point: &[u8; 32]) -> bool {
    match multiply_edwards(&PodScalar(*reveal), &ED25519_BASEPOINT) {
        Some(p) => &p.0 == point,
        None => false,
    }
}

fn now() -> Result<i64, ProgramError> {
    Ok(Clock::get()?.unix_timestamp)
}

/// Move lamports between two program-visible accounts. The escrow PDA is owned by
/// this program, so its balance can be debited directly without a CPI.
fn move_lamports(from: &AccountInfo, to: &AccountInfo, amount: u64) -> ProgramResult {
    **from.try_borrow_mut_lamports()? = from
        .lamports()
        .checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;
    **to.try_borrow_mut_lamports()? = to
        .lamports()
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    Ok(())
}

fn load(ai: &AccountInfo) -> Result<Escrow, ProgramError> {
    Ok(Escrow::try_from_slice(&ai.data.borrow())?)
}

fn store(escrow: &Escrow, ai: &AccountInfo) -> ProgramResult {
    let mut data = ai.data.borrow_mut();
    let mut cursor = &mut data[..];

    escrow.serialize(&mut cursor)?;
    
    Ok(())
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);

    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    
    s
}
