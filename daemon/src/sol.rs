// SPDX-License-Identifier: GPL-3.0-or-later

//! The Solana side of the live executor: build, sign, and send the `sol-escrow`
//! instructions, and read the escrow account back.
//!
//! Transactions are built and signed with `solana-sdk`, then shipped over plain JSON-RPC
//! (the same blocking HTTP client the Monero driver uses), so the daemon doesn't pull in
//! the whole `solana-client` tree. The instruction and account layouts here mirror the
//! program's `SwapInstruction` / `Escrow` byte-for-byte — they're the Rust twin of the
//! TypeScript bindings in `client/program.ts`, and the encoding tests pin that.

use borsh::{BorshDeserialize, BorshSerialize};
use serde_json::{json, Value};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

/// PDA seed, matching the program's `ESCROW_SEED`.
pub const ESCROW_SEED: &[u8] = b"escrow";

/// The System Program address is the all-zero pubkey — the same constant the program
/// checks `lock`'s system account against.
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// The on-chain instruction set. Borsh serializes an enum as a 1-byte discriminant
/// (Lock=0, SetReady=1, Claim=2, Refund=3, Close=4) followed by the variant's fields in
/// order — identical to the program's `SwapInstruction` and to `encodeLock` et al. in the
/// TS client. The fields are little-endian, which Borsh and the TS `Buffer.write*LE` agree on.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum SwapInstruction {
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
    SetReady,
    Claim {
        reveal: [u8; 32],
    },
    Refund {
        reveal: [u8; 32],
    },
    Close,
}

/// The escrow account, as the program lays it out. Decode-only here; the program owns
/// writes. `LEN` must match `Escrow::LEN` on-chain (253 bytes) or `read_escrow` rejects
/// the account.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
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
    pub revealed: [u8; 32],
}

impl Escrow {
    pub const LEN: usize = 32 * 5 + 8 + 2 + 8 + 8 + 32 + 1 + 1 + 1 + 32;
}

/// Everything that pins a single swap on the SOL side. Both parties hold the same terms
/// (it's what they agreed to off-chain); each derives the same escrow PDA from them.
#[derive(Clone)]
pub struct SwapTerms {
    pub id: [u8; 32],
    /// The maker's Solana account: funds the escrow, receives a refund.
    pub locker: Pubkey,
    /// The taker's SOL receiving account.
    pub claimer: Pubkey,
    pub fee_recipient: Pubkey,
    /// `s_a · G` — the taker's spend half. Settling with `s_a` claims.
    pub claim_point: [u8; 32],
    /// `s_b · G` — the maker's spend half. Settling with `s_b` refunds.
    pub refund_point: [u8; 32],
    pub amount: u64,
    pub fee_bps: u16,
    pub t0: i64,
    pub t1: i64,
}

impl SwapTerms {
    /// The escrow PDA for these terms under `program_id`.
    pub fn escrow_pda(&self, program_id: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[ESCROW_SEED, self.locker.as_ref(), &self.id], program_id).0
    }
}

#[derive(Debug)]
pub enum SolError {
    /// Network / transport / JSON decode problem.
    Transport(String),
    /// The JSON-RPC node returned an error object.
    Rpc { code: i64, message: String },
    /// A response wasn't shaped the way we expected.
    Decode(String),
    /// A transaction didn't confirm within the timeout.
    Timeout(String),
}

impl std::fmt::Display for SolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SolError::Transport(e) => write!(f, "transport error: {e}"),
            SolError::Rpc { code, message } => write!(f, "rpc error {code}: {message}"),
            SolError::Decode(e) => write!(f, "decode error: {e}"),
            SolError::Timeout(e) => write!(f, "timeout: {e}"),
        }
    }
}

impl std::error::Error for SolError {}

/// A minimal blocking JSON-RPC client for a Solana node's HTTP endpoint.
pub struct Rpc {
    url: String,
    commitment: String,
}

impl Rpc {
    /// `url` like `https://api.devnet.solana.com`. Uses "confirmed" commitment.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            commitment: "confirmed".to_string(),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, SolError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });

        let mut resp = ureq::post(&self.url)
            .send_json(&body)
            .map_err(|e| SolError::Transport(e.to_string()))?;
        let value: Value = resp
            .body_mut()
            .read_json()
            .map_err(|e| SolError::Transport(e.to_string()))?;

        if let Some(err) = value.get("error") {
            return Err(SolError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            });
        }

        value
            .get("result")
            .cloned()
            .ok_or_else(|| SolError::Decode("response had no result".into()))
    }

    /// A recent blockhash to anchor a transaction to.
    pub fn latest_blockhash(&self) -> Result<Hash, SolError> {
        let r = self.call(
            "getLatestBlockhash",
            json!([{ "commitment": self.commitment }]),
        )?;
        let s = r["value"]["blockhash"]
            .as_str()
            .ok_or_else(|| SolError::Decode("no blockhash in response".into()))?;
        
        Hash::from_str(s).map_err(|e| SolError::Decode(format!("bad blockhash: {e}")))
    }

    /// Submit a signed transaction; returns its signature (base58).
    pub fn send_transaction(&self, tx: &Transaction) -> Result<String, SolError> {
        let wire = bincode::serialize(tx).map_err(|e| SolError::Decode(e.to_string()))?;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, wire);

        let r = self.call(
            "sendTransaction",
            json!([b64, { "encoding": "base64", "preflightCommitment": self.commitment }]),
        )?;
        r.as_str()
            .map(str::to_string)
            .ok_or_else(|| SolError::Decode("sendTransaction returned no signature".into()))
    }

    /// Poll until a signature reaches our commitment level, or fail.
    pub fn confirm(&self, sig: &str, timeout: Duration, interval: Duration) -> Result<(), SolError> {
        let mut waited = Duration::ZERO;

        loop {
            let r = self.call(
                "getSignatureStatuses",
                json!([[sig], { "searchTransactionHistory": false }]),
            )?;

            let status = &r["value"][0];
            if !status.is_null() {
                if let Some(err) = status.get("err") {
                    if !err.is_null() {
                        return Err(SolError::Rpc {
                            code: 0,
                            message: format!("transaction failed: {err}"),
                        });
                    }
                }

                let level = status["confirmationStatus"].as_str().unwrap_or("");
                if level == "confirmed" || level == "finalized" {
                    return Ok(());
                }
            }

            if waited >= timeout {
                return Err(SolError::Timeout(format!("{sig} not confirmed in {timeout:?}")));
            }

            sleep(interval);
            waited += interval;
        }
    }

    /// The raw account data, or `None` if the account doesn't exist.
    pub fn get_account_data(&self, pubkey: &Pubkey) -> Result<Option<Vec<u8>>, SolError> {
        let r = self.call(
            "getAccountInfo",
            json!([pubkey.to_string(), { "encoding": "base64", "commitment": self.commitment }]),
        )?;

        let value = &r["value"];
        if value.is_null() {
            return Ok(None);
        }

        let b64 = value["data"][0]
            .as_str()
            .ok_or_else(|| SolError::Decode("account data not base64".into()))?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
            .map_err(|e| SolError::Decode(e.to_string()))?;

        Ok(Some(bytes))
    }

    pub fn get_balance(&self, pubkey: &Pubkey) -> Result<u64, SolError> {
        let r = self.call(
            "getBalance",
            json!([pubkey.to_string(), { "commitment": self.commitment }]),
        )?;

        r["value"]
            .as_u64()
            .ok_or_else(|| SolError::Decode("no balance in response".into()))
    }
}

/// Build the instruction data for a settle (claim/refund) reveal.
pub fn lock_ix(program_id: &Pubkey, escrow: &Pubkey, terms: &SwapTerms) -> Instruction {
    Instruction::new_with_borsh(
        *program_id,
        &SwapInstruction::Lock {
            id: terms.id,
            claimer: terms.claimer.to_bytes(),
            fee_recipient: terms.fee_recipient.to_bytes(),
            claim_point: terms.claim_point,
            refund_point: terms.refund_point,
            amount: terms.amount,
            fee_bps: terms.fee_bps,
            t0: terms.t0,
            t1: terms.t1,
        },
        vec![
            AccountMeta::new(terms.locker, true),
            AccountMeta::new(*escrow, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
    )
}

pub fn set_ready_ix(program_id: &Pubkey, escrow: &Pubkey, locker: &Pubkey) -> Instruction {
    Instruction::new_with_borsh(
        *program_id,
        &SwapInstruction::SetReady,
        vec![
            AccountMeta::new(*escrow, false),
            AccountMeta::new_readonly(*locker, true),
        ],
    )
}

pub fn claim_ix(
    program_id: &Pubkey,
    escrow: &Pubkey,
    claimer: &Pubkey,
    fee_recipient: &Pubkey,
    reveal: [u8; 32],
) -> Instruction {
    Instruction::new_with_borsh(
        *program_id,
        &SwapInstruction::Claim { reveal },
        vec![
            AccountMeta::new(*escrow, false),
            AccountMeta::new(*claimer, false),
            AccountMeta::new(*fee_recipient, false),
        ],
    )
}

pub fn refund_ix(program_id: &Pubkey, escrow: &Pubkey, locker: &Pubkey, reveal: [u8; 32]) -> Instruction {
    Instruction::new_with_borsh(
        *program_id,
        &SwapInstruction::Refund { reveal },
        vec![
            AccountMeta::new(*escrow, false),
            AccountMeta::new(*locker, false),
        ],
    )
}

pub fn close_ix(program_id: &Pubkey, escrow: &Pubkey, locker: &Pubkey) -> Instruction {
    Instruction::new_with_borsh(
        *program_id,
        &SwapInstruction::Close,
        vec![
            AccountMeta::new(*escrow, false),
            AccountMeta::new(*locker, true),
        ],
    )
}

/// How long to wait for a transaction to confirm, and how often to poll.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(90);
const CONFIRM_INTERVAL: Duration = Duration::from_secs(2);

/// The live Solana backend: one party's keypair, the swap terms, and the reveal it would
/// publish when settling. A maker calls lock / set_ready / refund; a taker calls claim.
/// Both can read the escrow.
pub struct RpcSol {
    pub rpc: Rpc,
    pub program_id: Pubkey,
    pub escrow: Pubkey,
    pub terms: SwapTerms,
    /// The party's fee payer (and signer where the instruction needs one): the locker
    /// keypair for the maker, the taker's funding keypair for the claim.
    pub signer: Keypair,
    /// This party's own spend scalar, little-endian — `s_b` for a maker, `s_a` for a taker.
    pub reveal: [u8; 32],
}

impl RpcSol {
    pub fn new(
        rpc: Rpc,
        program_id: Pubkey,
        terms: SwapTerms,
        signer: Keypair,
        reveal: [u8; 32],
    ) -> Self {
        let escrow = terms.escrow_pda(&program_id);
        
        Self {
            rpc,
            program_id,
            escrow,
            terms,
            signer,
            reveal,
        }
    }

    fn send(&self, ix: Instruction) -> Result<String, SolError> {
        let blockhash = self.rpc.latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&self.signer.pubkey()),
            &[&self.signer],
            blockhash,
        );
        let sig = self.rpc.send_transaction(&tx)?;

        self.rpc.confirm(&sig, CONFIRM_TIMEOUT, CONFIRM_INTERVAL)?;

        Ok(sig)
    }

    pub fn lock(&self) -> Result<String, SolError> {
        self.send(lock_ix(&self.program_id, &self.escrow, &self.terms))
    }

    pub fn set_ready(&self) -> Result<String, SolError> {
        self.send(set_ready_ix(&self.program_id, &self.escrow, &self.terms.locker))
    }

    pub fn claim(&self) -> Result<String, SolError> {
        self.send(claim_ix(
            &self.program_id,
            &self.escrow,
            &self.terms.claimer,
            &self.terms.fee_recipient,
            self.reveal,
        ))
    }

    pub fn refund(&self) -> Result<String, SolError> {
        self.send(refund_ix(
            &self.program_id,
            &self.escrow,
            &self.terms.locker,
            self.reveal,
        ))
    }

    pub fn close(&self) -> Result<String, SolError> {
        self.send(close_ix(&self.program_id, &self.escrow, &self.terms.locker))
    }

    pub fn read_escrow(&self) -> Result<Option<Escrow>, SolError> {
        match self.rpc.get_account_data(&self.escrow)? {
            None => Ok(None),
            Some(data) => {
                if data.len() != Escrow::LEN {
                    return Err(SolError::Decode(format!(
                        "escrow is {} bytes, expected {}",
                        data.len(),
                        Escrow::LEN
                    )));
                }
                
                Escrow::try_from_slice(&data)
                    .map(Some)
                    .map_err(|e| SolError::Decode(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escrow_len_matches_the_program() {
        // The program's Escrow::LEN; the devnet script hard-codes ESCROW_SIZE = 253.
        assert_eq!(Escrow::LEN, 253);
    }

    #[test]
    fn instruction_discriminants_and_lengths_match_the_ts_client() {
        // Borsh enum = 1-byte discriminant + fields. These are the exact bytes the TS
        // `encode*` helpers produce, which the deployed program already accepts.
        assert_eq!(borsh::to_vec(&SwapInstruction::SetReady).unwrap(), vec![1]);
        assert_eq!(borsh::to_vec(&SwapInstruction::Close).unwrap(), vec![4]);

        let claim = borsh::to_vec(&SwapInstruction::Claim { reveal: [0u8; 32] }).unwrap();
        assert_eq!(claim.len(), 33);
        assert_eq!(claim[0], 2);

        let refund = borsh::to_vec(&SwapInstruction::Refund { reveal: [9u8; 32] }).unwrap();
        assert_eq!(refund.len(), 33);
        assert_eq!(refund[0], 3);
        assert_eq!(&refund[1..], &[9u8; 32]);
    }

    #[test]
    fn lock_encoding_is_byte_exact() {
        // discriminant + id + claimer + fee_recipient + claim_point + refund_point
        // + amount(u64 LE) + fee_bps(u16 LE) + t0(i64 LE) + t1(i64 LE)
        let ix = SwapInstruction::Lock {
            id: [1u8; 32],
            claimer: [2u8; 32],
            fee_recipient: [3u8; 32],
            claim_point: [4u8; 32],
            refund_point: [5u8; 32],
            amount: 0x0102_0304_0506_0708,
            fee_bps: 0x0A0B,
            t0: 0x1112_1314_1516_1718,
            t1: 0x2122_2324_2526_2728,
        };
        let bytes = borsh::to_vec(&ix).unwrap();

        assert_eq!(bytes.len(), 1 + 32 * 5 + 8 + 2 + 8 + 8);
        assert_eq!(bytes[0], 0); // Lock discriminant

        let mut off = 1;
        for (chunk, fill) in [(32, 1u8), (32, 2), (32, 3), (32, 4), (32, 5)] {
            assert!(bytes[off..off + chunk].iter().all(|&b| b == fill));
            off += chunk;
        }
        // little-endian scalars
        assert_eq!(&bytes[off..off + 8], &0x0102_0304_0506_0708u64.to_le_bytes());
        off += 8;
        assert_eq!(&bytes[off..off + 2], &0x0A0Bu16.to_le_bytes());
        off += 2;
        assert_eq!(&bytes[off..off + 8], &0x1112_1314_1516_1718i64.to_le_bytes());
        off += 8;
        assert_eq!(&bytes[off..off + 8], &0x2122_2324_2526_2728i64.to_le_bytes());
    }

    #[test]
    fn escrow_round_trips_through_borsh() {
        // Build an escrow the way the program would store it, serialize, and decode — the
        // field order and widths must line up or settled/revealed land in the wrong place.
        let original = Escrow {
            locker: [10u8; 32],
            claimer: [11u8; 32],
            fee_recipient: [12u8; 32],
            claim_point: [13u8; 32],
            refund_point: [14u8; 32],
            amount: 50_000_000,
            fee_bps: 300,
            t0: 1_900_000_000,
            t1: 1_900_003_600,
            id: [15u8; 32],
            bump: 254,
            ready: true,
            settled: true,
            revealed: [16u8; 32],
        };
        let bytes = borsh::to_vec(&original).unwrap();
        assert_eq!(bytes.len(), Escrow::LEN);

        let decoded = Escrow::try_from_slice(&bytes).unwrap();
        assert_eq!(decoded, original);
        assert!(decoded.settled && decoded.ready);
        assert_eq!(decoded.revealed, [16u8; 32]);
        assert_eq!(decoded.fee_bps, 300);
    }

    #[test]
    fn escrow_pda_is_deterministic_from_terms() {
        let program_id = Pubkey::new_unique();
        let terms = SwapTerms {
            id: [7u8; 32],
            locker: Pubkey::new_unique(),
            claimer: Pubkey::new_unique(),
            fee_recipient: Pubkey::new_unique(),
            claim_point: [1u8; 32],
            refund_point: [2u8; 32],
            amount: 1,
            fee_bps: 0,
            t0: 0,
            t1: 600,
        };
        let a = terms.escrow_pda(&program_id);
        let b = terms.escrow_pda(&program_id);
        assert_eq!(a, b);
        // Same seeds the program re-derives in `load`.
        let (expected, _) = Pubkey::find_program_address(
            &[ESCROW_SEED, terms.locker.as_ref(), &terms.id],
            &program_id,
        );
        assert_eq!(a, expected);
    }
}
