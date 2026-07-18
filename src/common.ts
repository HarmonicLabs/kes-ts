/**
 * Shared KES primitives — port of IOHK kes-summed-ed25519 `common.rs`.
 * Paper: Malkin, Micciancio, Miner — eprint.iacr.org/2001/034
 */
import { blake2b_256 } from "@harmoniclabs/crypto";

export const INDIVIDUAL_SECRET_SIZE = 32;
export const SIGMA_SIZE = 64;
export const PUBLIC_KEY_SIZE = 32;
export const SEED_SIZE = 32;
export const PERIOD_SIZE = 4;

/** Sum (non-compact) signature size at depth d: 64 + d*64 */
export function sumSigSize(depth: number): number {
    return SIGMA_SIZE + depth * (PUBLIC_KEY_SIZE * 2);
}

/** Compact signature size at depth d: 64 + (d+1)*32 */
export function compactSigSize(depth: number): number {
    return SIGMA_SIZE + (depth + 1) * PUBLIC_KEY_SIZE;
}

/**
 * SK body size at depth d (without trailing period u32):
 * 32 + d*32 + d*64 = 32 + d*96
 */
export function skBodySize(depth: number): number {
    return INDIVIDUAL_SECRET_SIZE + depth * 32 + depth * (PUBLIC_KEY_SIZE * 2);
}

export function skWithPeriodSize(depth: number): number {
    return skBodySize(depth) + PERIOD_SIZE;
}

export function depthTotal(depth: number): number {
    return 2 ** depth;
}

export function depthHalf(depth: number): number {
    if (depth <= 0) throw new Error("depthHalf requires depth > 0");
    return 2 ** (depth - 1);
}

export function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
    return diff === 0;
}

/**
 * Hash two public keys: Blake2b-256(lhs || rhs).
 * NO domain prefixes (unlike seed split).
 */
export function hashPair(lhs: Uint8Array, rhs: Uint8Array): Uint8Array {
    if (lhs.length !== PUBLIC_KEY_SIZE || rhs.length !== PUBLIC_KEY_SIZE) {
        throw new Error("hashPair expects 32-byte public keys");
    }
    const buf = new Uint8Array(PUBLIC_KEY_SIZE * 2);
    buf.set(lhs, 0);
    buf.set(rhs, PUBLIC_KEY_SIZE);
    return blake2b_256(buf);
}

/**
 * Split a 32-byte seed into two children, zero the parent.
 * left  = Blake2b-256([1] || seed)
 * right = Blake2b-256([2] || seed)
 */
export function splitSeed(seed: Uint8Array): { left: Uint8Array; right: Uint8Array } {
    if (seed.length !== SEED_SIZE) {
        throw new Error(`splitSeed: expected ${SEED_SIZE} bytes, got ${seed.length}`);
    }
    const leftIn = new Uint8Array(SEED_SIZE + 1);
    leftIn[0] = 1;
    leftIn.set(seed, 1);
    const rightIn = new Uint8Array(SEED_SIZE + 1);
    rightIn[0] = 2;
    rightIn.set(seed, 1);
    const left = blake2b_256(leftIn);
    const right = blake2b_256(rightIn);
    seed.fill(0);
    return { left, right };
}

export function readPeriod(sk: Uint8Array, bodySize: number): number {
    if (sk.length < bodySize + PERIOD_SIZE) {
        throw new Error("SK too short for period");
    }
    const b = sk.subarray(bodySize, bodySize + PERIOD_SIZE);
    return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
}

export function writePeriod(sk: Uint8Array, bodySize: number, period: number): void {
    const p = period >>> 0;
    sk[bodySize] = (p >>> 24) & 0xff;
    sk[bodySize + 1] = (p >>> 16) & 0xff;
    sk[bodySize + 2] = (p >>> 8) & 0xff;
    sk[bodySize + 3] = p & 0xff;
}

/** Append 4 zero period bytes to a Shelley-format SK (no period). */
export function withPeriodZero(skBody: Uint8Array): Uint8Array {
    const out = new Uint8Array(skBody.length + PERIOD_SIZE);
    out.set(skBody, 0);
    return out;
}

export function assertLen(buf: Uint8Array, n: number, label: string): void {
    if (buf.length !== n) {
        throw new Error(`${label}: expected ${n} bytes, got ${buf.length}`);
    }
}
