// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Full behavioural test suite for the sol-escrow program, run in-process against
 * the compiled BPF binary with solana-bankrun. bankrun lets us warp the clock,
 * which is what makes the two-timelock windows testable without waiting in real time.
 *
 * Build the program first: `cd programs/sol-escrow && cargo build-sbf`, then `npm test`.
 */
import {
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import assert from "node:assert/strict";
import { BanksClient, Clock, ProgramTestContext, start } from "solana-bankrun";
import {
  bytesEqual,
  claimIx,
  combinePoints,
  combineScalars,
  decodeEscrow,
  DEPLOY_DIR,
  escrowPda,
  KeyShare,
  loadProgramId,
  LockArgs,
  lockIx,
  pointFromScalar,
  randomId,
  randomShare,
  refundIx,
  setReadyIx,
} from "../client/program";

// bankrun finds `sol_escrow.so` through this env var.
process.env.BPF_OUT_DIR ||= DEPLOY_DIR;
process.env.SBF_OUT_DIR ||= DEPLOY_DIR;

// Custom error codes, in the same order as the program's EscrowError enum.
const ERR = {
  BadSecret: 0,
  AlreadySettled: 1,
  NotInClaimWindow: 2,
  NotInRefundWindow: 3,
  Unauthorized: 4,
  BadAccount: 5,
  FeeTooHigh: 6,
  BadWindows: 7,
};

const ESCROW_SIZE = 253n; // bytes; must match Escrow::LEN in the program
const AMOUNT = BigInt(2 * LAMPORTS_PER_SOL);
const FEE_BPS = 300; // 3%
const FEE = (AMOUNT * BigInt(FEE_BPS)) / 10_000n;

// A fixed "now" keeps the timelock arithmetic obvious.
const NOW = 1_900_000_000n;
const T0 = NOW + 1_000n;
const T1 = NOW + 2_000n;

const programId = loadProgramId();

describe("sol-escrow", () => {
  let ctx: ProgramTestContext;
  let client: BanksClient;
  let bob: Keypair; // locker; pre-funded, also pays tx fees
  let escrowRent: bigint;

  beforeEach(async () => {
    ctx = await start([{ name: "sol_escrow", programId }], []);
    client = ctx.banksClient;
    bob = ctx.payer;
    escrowRent = (await client.getRent()).minimumBalance(ESCROW_SIZE);
    await setNow(NOW);
  });

  async function setNow(ts: bigint): Promise<void> {
    const c = await client.getClock();

    ctx.setClock(
      new Clock(
        c.slot,
        c.epochStartTimestamp,
        c.epoch,
        c.leaderScheduleEpoch,
        ts,
      ),
    );
  }

  function txFrom(
    ixs: TransactionInstruction[],
    feePayer: PublicKey,
  ): Transaction {
    const tx = new Transaction();
    tx.recentBlockhash = ctx.lastBlockhash;
    tx.feePayer = feePayer;

    ixs.forEach((ix) => tx.add(ix));

    return tx;
  }

  async function ok(
    ixs: TransactionInstruction[],
    signers: Keypair[],
  ): Promise<void> {
    const tx = txFrom(ixs, signers[0].publicKey);
    tx.sign(...signers);

    await client.processTransaction(tx);
  }

  async function fails(
    ixs: TransactionInstruction[],
    signers: Keypair[],
    code: number,
  ): Promise<void> {
    const tx = txFrom(ixs, signers[0].publicKey);
    tx.sign(...signers);

    const res = await client.tryProcessTransaction(tx);
    assert.notEqual(res.result, null, "expected the transaction to fail");

    const detail = `${res.result}\n${(res.meta?.logMessages ?? []).join("\n")}`;
    assert.ok(
      detail.includes(`custom program error: 0x${code.toString(16)}`),
      `expected custom error 0x${code.toString(16)}, got:\n${detail}`,
    );
  }

  interface Swap {
    id: Uint8Array;
    alice: KeyShare; // s_a, revealed when Alice claims
    bobShare: KeyShare; // s_b, revealed when Bob refunds
    claimer: Keypair;
    feeRecipient: Keypair;
    escrow: PublicKey;
    lockArgs: LockArgs;
  }

  function makeSwap(overrides: Partial<LockArgs> = {}): Swap {
    const id = randomId();
    const alice = randomShare();
    const bobShare = randomShare();
    const claimer = Keypair.generate();
    const feeRecipient = Keypair.generate();
    const [escrow] = escrowPda(programId, bob.publicKey, id);
    const lockArgs: LockArgs = {
      id,
      claimer: claimer.publicKey,
      feeRecipient: feeRecipient.publicKey,
      claimPoint: alice.point,
      refundPoint: bobShare.point,
      amount: AMOUNT,
      feeBps: FEE_BPS,
      t0: T0,
      t1: T1,
      ...overrides,
    };

    return { id, alice, bobShare, claimer, feeRecipient, escrow, lockArgs };
  }

  const lock = (s: Swap) =>
    ok([lockIx(programId, bob.publicKey, s.escrow, s.lockArgs)], [bob]);

  async function readEscrow(pubkey: PublicKey) {
    const acct = await client.getAccount(pubkey);
    assert.ok(acct, "escrow account should exist");

    return decodeEscrow(acct!.data);
  }

  //
  // locking
  //

  it("locks SOL into the escrow PDA and records the terms", async () => {
    const s = makeSwap();
    await lock(s);

    assert.equal(await client.getBalance(s.escrow), escrowRent + AMOUNT);

    const e = await readEscrow(s.escrow);
    assert.equal(e.amount, AMOUNT);
    assert.equal(e.feeBps, FEE_BPS);
    assert.equal(e.t0, T0);
    assert.equal(e.t1, T1);
    assert.equal(e.ready, false);
    assert.equal(e.settled, false);
    assert.ok(bytesEqual(e.claimPoint, s.alice.point));
    assert.ok(bytesEqual(e.refundPoint, s.bobShare.point));
    assert.ok(e.revealed.every((b) => b === 0));
  });

  it("rejects a fee above the 3% cap", async () => {
    const s = makeSwap({ feeBps: 301 });

    await fails(
      [lockIx(programId, bob.publicKey, s.escrow, s.lockArgs)],
      [bob],
      ERR.FeeTooHigh,
    );
  });

  it("rejects timelocks that aren't strictly ordered", async () => {
    const s = makeSwap({ t0: T1, t1: T0 });

    await fails(
      [lockIx(programId, bob.publicKey, s.escrow, s.lockArgs)],
      [bob],
      ERR.BadWindows,
    );
  });

  //
  // claim (happy + reveal)
  //

  it("lets Alice claim with s_a, pays out minus fee, and reveals the secret", async () => {
    const s = makeSwap();
    await lock(s);
    await ok([setReadyIx(programId, s.escrow, bob.publicKey)], [bob]);

    // ready is set, so Alice can claim even before t0.
    await ok(
      [
        claimIx(
          programId,
          s.escrow,
          s.claimer.publicKey,
          s.feeRecipient.publicKey,
          s.alice.reveal,
        ),
      ],
      [bob],
    );

    assert.equal(await client.getBalance(s.claimer.publicKey), AMOUNT - FEE);
    assert.equal(await client.getBalance(s.feeRecipient.publicKey), FEE);
    assert.equal(await client.getBalance(s.escrow), escrowRent); // amount fully disbursed

    const e = await readEscrow(s.escrow);
    assert.equal(e.settled, true);
    assert.ok(bytesEqual(e.revealed, s.alice.reveal), "claim publishes s_a");

    // The revealed s_a + Bob's s_b reconstructs the 2-of-2 Monero spend key, which
    // is exactly what lets Bob sweep the XMR. Neither half does it alone.
    const shared = combinePoints(s.alice.point, s.bobShare.point);
    const spendKey = combineScalars(s.alice.scalar, s.bobShare.scalar);
    assert.ok(
      bytesEqual(pointFromScalar(spendKey), shared),
      "reveal completes the Monero key",
    );
    assert.ok(!bytesEqual(pointFromScalar(s.alice.scalar), shared));
    assert.ok(!bytesEqual(pointFromScalar(s.bobShare.scalar), shared));
  });

  it("lets Alice claim at t0 even without set_ready", async () => {
    const s = makeSwap();
    await lock(s);
    await setNow(T0); // window opens at t0 regardless of ready
    await ok(
      [
        claimIx(
          programId,
          s.escrow,
          s.claimer.publicKey,
          s.feeRecipient.publicKey,
          s.alice.reveal,
        ),
      ],
      [bob],
    );
    assert.equal((await readEscrow(s.escrow)).settled, true);
  });

  it("rejects a claim with the wrong secret", async () => {
    const s = makeSwap();
    await lock(s);
    await ok([setReadyIx(programId, s.escrow, bob.publicKey)], [bob]);
    // s_b is not s_a, and a random scalar certainly isn't either.
    await fails(
      [
        claimIx(
          programId,
          s.escrow,
          s.claimer.publicKey,
          s.feeRecipient.publicKey,
          s.bobShare.reveal,
        ),
      ],
      [bob],
      ERR.BadSecret,
    );
    await fails(
      [
        claimIx(
          programId,
          s.escrow,
          s.claimer.publicKey,
          s.feeRecipient.publicKey,
          randomShare().reveal,
        ),
      ],
      [bob],
      ERR.BadSecret,
    );
  });

  it("rejects a non-canonical scalar (curve op returns nothing)", async () => {
    const s = makeSwap();
    await lock(s);
    await ok([setReadyIx(programId, s.escrow, bob.publicKey)], [bob]);
    const nonCanonical = new Uint8Array(32).fill(0xff); // >= L, not a valid scalar
    await fails(
      [
        claimIx(
          programId,
          s.escrow,
          s.claimer.publicKey,
          s.feeRecipient.publicKey,
          nonCanonical,
        ),
      ],
      [bob],
      ERR.BadSecret,
    );
  });

  it("rejects a claim paid to the wrong recipient", async () => {
    const s = makeSwap();
    await lock(s);
    await ok([setReadyIx(programId, s.escrow, bob.publicKey)], [bob]);
    const stranger = Keypair.generate().publicKey;
    await fails(
      [
        claimIx(
          programId,
          s.escrow,
          stranger,
          s.feeRecipient.publicKey,
          s.alice.reveal,
        ),
      ],
      [bob],
      ERR.BadAccount,
    );
    await fails(
      [
        claimIx(
          programId,
          s.escrow,
          s.claimer.publicKey,
          stranger,
          s.alice.reveal,
        ),
      ],
      [bob],
      ERR.BadAccount,
    );
  });

  it("rejects a claim before ready and before t0", async () => {
    const s = makeSwap();
    await lock(s); // no set_ready, now == NOW < t0
    await fails(
      [
        claimIx(
          programId,
          s.escrow,
          s.claimer.publicKey,
          s.feeRecipient.publicKey,
          s.alice.reveal,
        ),
      ],
      [bob],
      ERR.NotInClaimWindow,
    );
  });

  it("rejects a claim at/after t1", async () => {
    const s = makeSwap();
    await lock(s);
    await ok([setReadyIx(programId, s.escrow, bob.publicKey)], [bob]);
    await setNow(T1); // window closes exactly at t1
    await fails(
      [
        claimIx(
          programId,
          s.escrow,
          s.claimer.publicKey,
          s.feeRecipient.publicKey,
          s.alice.reveal,
        ),
      ],
      [bob],
      ERR.NotInClaimWindow,
    );
  });

  //
  // refund (both windows)
  //

  it("lets Bob abort-refund before t0, returning SOL and revealing s_b", async () => {
    const s = makeSwap();
    await lock(s); // not ready, now < t0
    await ok(
      [refundIx(programId, s.escrow, bob.publicKey, s.bobShare.reveal)],
      [bob],
    );

    assert.equal(await client.getBalance(s.escrow), escrowRent); // amount returned
    const e = await readEscrow(s.escrow);
    assert.equal(e.settled, true);
    assert.ok(
      bytesEqual(e.revealed, s.bobShare.reveal),
      "refund publishes s_b",
    );

    // s_b + s_a still reconstructs the key, so Alice can recover her XMR.
    const shared = combinePoints(s.alice.point, s.bobShare.point);
    const spendKey = combineScalars(s.alice.scalar, s.bobShare.scalar);
    assert.ok(bytesEqual(pointFromScalar(spendKey), shared));
  });

  it("lets Bob refund after t1", async () => {
    const s = makeSwap();
    await lock(s);
    await ok([setReadyIx(programId, s.escrow, bob.publicKey)], [bob]);
    await setNow(T1); // Alice's window has closed
    await ok(
      [refundIx(programId, s.escrow, bob.publicKey, s.bobShare.reveal)],
      [bob],
    );
    assert.equal((await readEscrow(s.escrow)).settled, true);
    assert.equal(await client.getBalance(s.escrow), escrowRent);
  });

  it("blocks a refund while ready and before t1 (Alice's window is protected)", async () => {
    const s = makeSwap();
    await lock(s);
    await ok([setReadyIx(programId, s.escrow, bob.publicKey)], [bob]);
    // ready, NOW < t1: not an abort (ready) and not yet late.
    await fails(
      [refundIx(programId, s.escrow, bob.publicKey, s.bobShare.reveal)],
      [bob],
      ERR.NotInRefundWindow,
    );
  });

  it("rejects a refund with the wrong secret", async () => {
    const s = makeSwap();
    await lock(s); // refund window open (early abort)
    await fails(
      [refundIx(programId, s.escrow, bob.publicKey, s.alice.reveal)], // s_a, not s_b
      [bob],
      ERR.BadSecret,
    );
  });

  //
  // settle-once + authorization
  //

  it("won't settle twice (claim then refund)", async () => {
    const s = makeSwap();
    await lock(s);
    await ok([setReadyIx(programId, s.escrow, bob.publicKey)], [bob]);
    await ok(
      [
        claimIx(
          programId,
          s.escrow,
          s.claimer.publicKey,
          s.feeRecipient.publicKey,
          s.alice.reveal,
        ),
      ],
      [bob],
    );
    await setNow(T1);
    await fails(
      [refundIx(programId, s.escrow, bob.publicKey, s.bobShare.reveal)],
      [bob],
      ERR.AlreadySettled,
    );
  });

  it("won't settle twice (refund then claim)", async () => {
    const s = makeSwap();
    await lock(s);
    await ok(
      [refundIx(programId, s.escrow, bob.publicKey, s.bobShare.reveal)],
      [bob],
    );
    await setNow(T0);
    await fails(
      [
        claimIx(
          programId,
          s.escrow,
          s.claimer.publicKey,
          s.feeRecipient.publicKey,
          s.alice.reveal,
        ),
      ],
      [bob],
      ERR.AlreadySettled,
    );
  });

  it("only lets the locker call set_ready", async () => {
    const s = makeSwap();
    await lock(s);
    const mallory = Keypair.generate();
    // mallory signs the set_ready account slot but isn't the locker.
    await fails(
      [setReadyIx(programId, s.escrow, mallory.publicKey)],
      [bob, mallory],
      ERR.Unauthorized,
    );
  });
});
