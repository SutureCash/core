// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Runs one full XMR⇄SOL swap, SOL side only, against a live cluster (devnet by
 * default). It locks SOL, opens the claim window with set_ready, then claims by
 * revealing s_a — the same sequence the test suite exercises in-process, but here
 * it hits a real validator and prints the transaction signatures.
 *
 *   RPC_URL   cluster endpoint            (default: https://api.devnet.solana.com)
 *   PAYER     path to the funded keypair  (default: ~/.config/solana/id.json)
 *
 * The Monero side isn't touched here: the point is to prove the on-chain reveal
 * works end to end. The script verifies that claiming published s_a and that
 * s_a + s_b reconstructs the 2-of-2 Monero key the off-chain wallet would sweep.
 */
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  bytesEqual,
  claimIx,
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

function loadKeypair(path: string): Keypair {
  return Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(path, "utf8"))),
  );
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

async function main() {
  const conn = new Connection(RPC_URL, "confirmed");
  const bob = loadKeypair(PAYER_PATH); // locker; also pays fees
  const programId = loadProgramId();

  console.log("cluster :", RPC_URL);
  console.log("program :", programId.toBase58());
  console.log(
    "payer   :",
    bob.publicKey.toBase58(),
    `(${(await conn.getBalance(bob.publicKey)) / LAMPORTS_PER_SOL} SOL)`,
  );

  const alice = randomShare(); // s_a, revealed on claim
  const bobShare = randomShare(); // s_b, Bob keeps this
  const claimer = Keypair.generate(); // Alice's SOL receiving address
  const feeRecipient = Keypair.generate();
  const id = randomId();
  const [escrow] = escrowPda(programId, bob.publicKey, id);

  const now = Math.floor(Date.now() / 1000);
  const t0 = BigInt(now + 3600);
  const t1 = BigInt(now + 7200);
  const amount = BigInt(0.05 * LAMPORTS_PER_SOL);
  const feeBps = 300; // 3%
  const fee = (amount * BigInt(feeBps)) / 10_000n;

  // The fee account is a treasury that already exists on a real deployment. Here we
  // fund a throwaway one to its rent-exempt minimum so the small fee credit is legal.
  const rentMin = await conn.getMinimumBalanceForRentExemption(0);
  await sendAndConfirmTransaction(
    conn,
    new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: bob.publicKey,
        toPubkey: feeRecipient.publicKey,
        lamports: rentMin,
      }),
    ),
    [bob],
  );

  const lockSig = await sendAndConfirmTransaction(
    conn,
    new Transaction().add(
      lockIx(programId, bob.publicKey, escrow, {
        id,
        claimer: claimer.publicKey,
        feeRecipient: feeRecipient.publicKey,
        claimPoint: alice.point,
        refundPoint: bobShare.point,
        amount,
        feeBps,
        t0,
        t1,
      }),
    ),
    [bob],
  );
  console.log("\nlock      :", lockSig);

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

  const info = await conn.getAccountInfo(escrow);
  if (!info) throw new Error("escrow account vanished");

  const e = decodeEscrow(info.data);

  console.log("\n--- result ---");
  console.log("settled        :", e.settled);
  console.log("revealed s_a   :", hex(e.revealed));
  console.log("expected s_a   :", hex(alice.reveal));
  console.log(
    "claimer balance:",
    await conn.getBalance(claimer.publicKey),
    "lamports",
  );
  console.log("expected       :", Number(amount - fee), "lamports");
  console.log(
    "fee recipient  :",
    await conn.getBalance(feeRecipient.publicKey),
    "lamports (rent +",
    Number(fee),
    "fee)",
  );

  const shared = combinePoints(alice.point, bobShare.point);
  const spendKey = combineScalars(alice.scalar, bobShare.scalar);
  const reconstructs = bytesEqual(pointFromScalar(spendKey), shared);
  console.log(
    "monero key OK  :",
    reconstructs,
    "(s_a + s_b -> 2-of-2 spend key)",
  );

  if (!e.settled || !bytesEqual(e.revealed, alice.reveal) || !reconstructs)
    throw new Error("swap did not settle as expected");

  console.log("\nswap settled on-chain.");
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
