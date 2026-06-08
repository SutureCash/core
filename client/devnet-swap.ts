// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Runs one full XMR⇄SOL swap, SOL side only, against a live cluster (devnet by
 * default), with a full lamport ledger: it snapshots balances before and after every
 * step and checks the fee / rent / payout math against what the program should do.
 * Lifecycle exercised: lock -> set_ready -> claim -> close.
 *
 *   RPC_URL   cluster endpoint            (default: https://api.devnet.solana.com)
 *   PAYER     path to the funded keypair  (default: ~/.config/solana/id.json)
 *
 * The Monero side isn't touched here; the point is to prove the on-chain reveal and
 * the accounting end to end on a real validator.
 */
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  bytesEqual,
  claimIx,
  closeIx,
  combinePoints,
  combineScalars,
  decodeEscrow,
  escrowPda,
  loadProgramId,
  lockIx,
  pointFromScalar,
  randomId,
  randomShare,
  setReadyIx,
} from "./program";

const RPC_URL = process.env.RPC_URL ?? "https://api.devnet.solana.com";
const PAYER_PATH =
  process.env.PAYER ?? join(homedir(), ".config", "solana", "id.json");

const ESCROW_SIZE = 253; // bytes; must match Escrow::LEN in the program
const AMOUNT = 0.05 * LAMPORTS_PER_SOL;
const FEE_BPS = 300; // 3%
const FEE = Math.floor((AMOUNT * FEE_BPS) / 10_000);

function loadKeypair(path: string): Keypair {
  return Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(path, "utf8"))),
  );
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const sol = (lamports: number) =>
  `${(lamports / LAMPORTS_PER_SOL).toFixed(9)} SOL`;

async function main() {
  const conn = new Connection(RPC_URL, "confirmed");
  const bob = loadKeypair(PAYER_PATH); // locker; also the fee payer
  const programId = loadProgramId();
  const rentEscrow = await conn.getMinimumBalanceForRentExemption(ESCROW_SIZE);

  const alice = randomShare(); // s_a, revealed on claim
  const bobShare = randomShare(); // s_b, Bob keeps this
  const claimer = Keypair.generate(); // Alice's SOL receiving address (fresh, starts at 0)
  const feeRecipient = Keypair.generate(); // protocol treasury stand-in (fresh, starts at 0)
  const id = randomId();
  const [escrow] = escrowPda(programId, bob.publicKey, id);

  const now = Math.floor(Date.now() / 1000);
  const t0 = BigInt(now + 3600);
  const t1 = BigInt(now + 7200);

  console.log("cluster   :", RPC_URL);
  console.log("program   :", programId.toBase58());
  console.log("escrow    :", escrow.toBase58());
  console.log("amount    :", sol(AMOUNT));
  console.log("fee (3%)  :", sol(FEE));
  console.log("escrow rent:", sol(rentEscrow));

  const bal = (k: PublicKey) => conn.getBalance(k);
  const snapshot = async (label: string) => {
    const [b, c, f, e] = await Promise.all([
      bal(bob.publicKey),
      bal(claimer.publicKey),
      bal(feeRecipient.publicKey),
      bal(escrow),
    ]);
    console.log(
      `\n[${label}]\n  bob=${sol(b)}  claimer=${sol(c)}  fee=${sol(f)}  escrow=${sol(e)}`,
    );
    return { b, c, f, e };
  };

  const before = await snapshot("before");

  const lockSig = await sendAndConfirmTransaction(
    conn,
    new Transaction().add(
      lockIx(programId, bob.publicKey, escrow, {
        id,
        claimer: claimer.publicKey,
        feeRecipient: feeRecipient.publicKey,
        claimPoint: alice.point,
        refundPoint: bobShare.point,
        amount: BigInt(AMOUNT),
        feeBps: FEE_BPS,
        t0,
        t1,
      }),
    ),
    [bob],
  );
  console.log("lock      :", lockSig);
  const afterLock = await snapshot("after lock");

  const readySig = await sendAndConfirmTransaction(
    conn,
    new Transaction().add(setReadyIx(programId, escrow, bob.publicKey)),
    [bob],
  );
  console.log("set_ready :", readySig);

  const claimSig = await sendAndConfirmTransaction(
    conn,
    new Transaction().add(
      claimIx(
        programId,
        escrow,
        claimer.publicKey,
        feeRecipient.publicKey,
        alice.reveal,
      ),
    ),
    [bob],
  );
  console.log("claim     :", claimSig);
  const afterClaim = await snapshot("after claim");

  // Read the settled escrow BEFORE closing it — close reaps the account.
  const e = decodeEscrow((await conn.getAccountInfo(escrow))!.data);
  assert.ok(e.settled, "escrow should be settled");
  assert.ok(bytesEqual(e.revealed, alice.reveal), "claim must publish s_a");
  const shared = combinePoints(alice.point, bobShare.point);
  const spendKey = combineScalars(alice.scalar, bobShare.scalar);
  assert.ok(
    bytesEqual(pointFromScalar(spendKey), shared),
    "s_a + s_b rebuilds the Monero key",
  );

  const closeSig = await sendAndConfirmTransaction(
    conn,
    new Transaction().add(closeIx(programId, escrow, bob.publicKey)),
    [bob],
  );
  console.log("close     :", closeSig);
  const afterClose = await snapshot("after close");

  //
  // verify the ledger (the parties that aren't the fee payer have no tx-fee noise)
  //
  console.log("\n--- ledger checks ---");
  const checks: [string, number, number][] = [
    ["escrow after lock = rent + amount", afterLock.e, rentEscrow + AMOUNT],
    ["claimer received = amount - fee", afterClaim.c - before.c, AMOUNT - FEE],
    ["fee recipient received = fee", afterClaim.f - before.f, FEE],
    ["escrow after claim = rent", afterClaim.e, rentEscrow],
    ["escrow after close = 0", afterClose.e, 0],
  ];
  for (const [label, got, want] of checks) {
    const ok = got === want;
    console.log(`  ${ok ? "OK " : "XX "}${label}: got ${got}, want ${want}`);
    assert.equal(got, want, label);
  }

  // bob pays every tx fee and funds/recovers the rent; show his net and the implied fees.
  const bobNet = afterClose.b - before.b;
  const rentReclaimed = afterClose.b - afterClaim.b; // ~ rent minus the close tx fee
  const txFees = -(bobNet + AMOUNT); // bob's loss beyond the swapped amount = total tx fees
  console.log(
    `  bob net = ${sol(bobNet)} (swapped out ${sol(AMOUNT)} + ~${txFees} lamports tx fees)`,
  );
  console.log(
    `  rent reclaimed on close = ${sol(rentReclaimed)} (rent ${rentEscrow} - 1 tx fee)`,
  );
  assert.ok(rentReclaimed > 0, "close should return rent to bob");

  console.log("\nrevealed s_a:", hex(e.revealed));
  console.log("swap settled, closed, and the ledger checks out.");
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
