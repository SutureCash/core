// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Client-side bindings for the sol-escrow program.
 *
 * Everything the off-chain world needs to talk to the on-chain escrow lives here:
 * instruction encoding, account decoding, PDA derivation, and the Ed25519
 * key-share math that links the SOL side of a swap to the Monero side. The test
 * suite and the devnet script both build on this module.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const Point = ed25519.Point;
const L = Point.Fn.ORDER; // Order of the Ed25519 prime-order subgroup. Scalars (Monero key halves) live mod L.

export const REPO_ROOT = join(__dirname, "..");
export const DEPLOY_DIR = join(REPO_ROOT, "target", "deploy");
export const PROGRAM_KEYPAIR_PATH = join(DEPLOY_DIR, "sol_escrow-keypair.json");

/**
 * The program's address, taken from the keypair `cargo build-sbf` generated.
 */
export function loadProgramId(): PublicKey {
  const bytes = Uint8Array.from(
    JSON.parse(readFileSync(PROGRAM_KEYPAIR_PATH, "utf8")),
  );
  return Keypair.fromSecretKey(bytes).publicKey;
}

//
// Ed25519 key shares
//
// A swap needs a 2-of-2 Monero key split into two scalars, s_a (Alice) and s_b
// (Bob). The escrow never sees a scalar until someone settles; it only holds the
// public points s_a·G and s_b·G. Revealing a scalar to the program is what hands
// the other party the half they were missing.

/**
 * One half of the shared Monero key.
 */
export interface KeyShare {
  /** The secret scalar s, reduced into [1, L). */
  scalar: bigint;
  /** s as 32 little-endian bytes — the form the program's curve check expects. */
  reveal: Uint8Array;
  /** s·G compressed: the lock point committed on-chain, and the Monero pubkey half. */
  point: Uint8Array;
}

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;

  return r >= 0n ? r : r + m;
}

function leToBig(bytes: Uint8Array): bigint {
  let n = 0n;

  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);

  return n;
}

function bigToLe(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);

  for (let i = 0; i < len; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }

  return out;
}

export function shareFromScalar(scalar: bigint): KeyShare {
  const s = mod(scalar, L) || 1n; // 0 has no inverse and can't be multiplied; nudge it.

  return {
    scalar: s,
    reveal: bigToLe(s, 32),
    point: Point.BASE.multiply(s).toBytes(),
  };
}

/**
 * Fresh random key share. 64 bytes reduced mod L gives a uniform scalar.
 */
export function randomShare(): KeyShare {
  return shareFromScalar(leToBig(new Uint8Array(randomBytes(64))));
}

/**
 * s_a + s_b mod L — the full Monero spend key, once both halves are known.
 */
export function combineScalars(a: bigint, b: bigint): bigint {
  return mod(a + b, L);
}

/**
 * P_a + P_b — the 2-of-2 Monero public key the combined spend key maps to.
 */
export function combinePoints(a: Uint8Array, b: Uint8Array): Uint8Array {
  return Point.fromBytes(a).add(Point.fromBytes(b)).toBytes();
}

/**
 * s·G, the public point for a scalar.
 */
export function pointFromScalar(scalar: bigint): Uint8Array {
  return Point.BASE.multiply(mod(scalar, L) || 1n).toBytes();
}

export function randomId(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

/**
 * The escrow account address for a given locker + swap id.
 */
export function escrowPda(
  programId: PublicKey,
  locker: PublicKey,
  id: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("escrow"), locker.toBuffer(), Buffer.from(id)],
    programId,
  );
}

//
// instruction encoding (mirrors the Borsh enum in the program)
//

const u16 = (n: number): Buffer => {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);

  return b;
};
const u64 = (n: bigint | number): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));

  return b;
};
const i64 = (n: bigint | number): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(BigInt(n));

  return b;
};

export interface LockArgs {
  id: Uint8Array;
  claimer: PublicKey;
  feeRecipient: PublicKey;
  claimPoint: Uint8Array;
  refundPoint: Uint8Array;
  amount: bigint;
  feeBps: number;
  t0: bigint;
  t1: bigint;
}

// The leading byte is the Borsh enum discriminant: Lock=0, SetReady=1, Claim=2, Refund=3.
export function encodeLock(a: LockArgs): Buffer {
  return Buffer.concat([
    Buffer.from([0]),
    Buffer.from(a.id),
    a.claimer.toBuffer(),
    a.feeRecipient.toBuffer(),
    Buffer.from(a.claimPoint),
    Buffer.from(a.refundPoint),
    u64(a.amount),
    u16(a.feeBps),
    i64(a.t0),
    i64(a.t1),
  ]);
}
export const encodeSetReady = (): Buffer => Buffer.from([1]);
export const encodeClaim = (reveal: Uint8Array): Buffer =>
  Buffer.concat([Buffer.from([2]), Buffer.from(reveal)]);
export const encodeRefund = (reveal: Uint8Array): Buffer =>
  Buffer.concat([Buffer.from([3]), Buffer.from(reveal)]);

//
// instruction builders (account order matches the program's expectations)
//

export function lockIx(
  programId: PublicKey,
  locker: PublicKey,
  escrow: PublicKey,
  args: LockArgs,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: locker, isSigner: true, isWritable: true },
      { pubkey: escrow, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: encodeLock(args),
  });
}

export function setReadyIx(
  programId: PublicKey,
  escrow: PublicKey,
  locker: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: escrow, isSigner: false, isWritable: true },
      { pubkey: locker, isSigner: true, isWritable: false },
    ],
    data: encodeSetReady(),
  });
}

export function claimIx(
  programId: PublicKey,
  escrow: PublicKey,
  claimer: PublicKey,
  feeRecipient: PublicKey,
  reveal: Uint8Array,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: escrow, isSigner: false, isWritable: true },
      { pubkey: claimer, isSigner: false, isWritable: true },
      { pubkey: feeRecipient, isSigner: false, isWritable: true },
    ],
    data: encodeClaim(reveal),
  });
}

export function refundIx(
  programId: PublicKey,
  escrow: PublicKey,
  locker: PublicKey,
  reveal: Uint8Array,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: escrow, isSigner: false, isWritable: true },
      { pubkey: locker, isSigner: false, isWritable: true },
    ],
    data: encodeRefund(reveal),
  });
}

//
// account decoding
//

export interface EscrowState {
  locker: Uint8Array;
  claimer: Uint8Array;
  feeRecipient: Uint8Array;
  claimPoint: Uint8Array;
  refundPoint: Uint8Array;
  amount: bigint;
  feeBps: number;
  t0: bigint;
  t1: bigint;
  id: Uint8Array;
  bump: number;
  ready: boolean;
  settled: boolean;
  revealed: Uint8Array;
}

export function decodeEscrow(data: Uint8Array): EscrowState {
  const b = Buffer.from(data);
  let o = 0;

  const take = (n: number): Uint8Array => {
    const slice = Uint8Array.from(b.subarray(o, o + n));
    o += n;

    return slice;
  };

  const locker = take(32);
  const claimer = take(32);
  const feeRecipient = take(32);
  const claimPoint = take(32);
  const refundPoint = take(32);
  const amount = b.readBigUInt64LE(o);
  o += 8;
  const feeBps = b.readUInt16LE(o);
  o += 2;
  const t0 = b.readBigInt64LE(o);
  o += 8;
  const t1 = b.readBigInt64LE(o);
  o += 8;
  const id = take(32);
  const bump = b[o++];
  const ready = b[o++] !== 0;
  const settled = b[o++] !== 0;
  const revealed = take(32);

  return {
    locker,
    claimer,
    feeRecipient,
    claimPoint,
    refundPoint,
    amount,
    feeBps,
    t0,
    t1,
    id,
    bump,
    ready,
    settled,
    revealed,
  };
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;

  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;

  return true;
}
