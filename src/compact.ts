/**
 * Recursive SumCompact KES — port of IOHK `sum_compact_kes!` macro.
 * Compact sig size at depth d: 64 + (d+1)*32 (Sum6 = 288).
 * SK layout matches non-compact Sum (same keygen/update).
 */
import {
    PUBLIC_KEY_SIZE,
    SEED_SIZE,
    SIGMA_SIZE,
    assertLen,
    bytesEq,
    compactSigSize,
    depthHalf,
    depthTotal,
    hashPair,
    readPeriod,
    skBodySize,
    skWithPeriodSize,
    writePeriod,
} from "./common";
import {
    sumKeygen,
    sumKeygenSlice,
    sumToPk,
    sumUpdate,
    sumUpdateSlice,
    sumGetPeriod,
    sumSkBodySize,
} from "./sum";
import {
    SUM0_COMPACT_SIG_SIZE,
    sum0CompactRecompute,
    sum0CompactSignFromSlice,
    sum0Keygen,
} from "./sum0";

export function compactSignatureSize(depth: number): number {
    return compactSigSize(depth);
}

/** Same SK sizes as non-compact */
export function compactSkBodySize(depth: number): number {
    return skBodySize(depth);
}

export function compactSkSize(depth: number): number {
    return skWithPeriodSize(depth);
}

export function compactKeygen(
    depth: number,
    keyBuffer: Uint8Array,
    masterSeed: Uint8Array,
): Uint8Array {
    return sumKeygen(depth, keyBuffer, masterSeed);
}

export function compactUpdate(depth: number, sk: Uint8Array): void {
    sumUpdate(depth, sk);
}

export function compactToPk(depth: number, sk: Uint8Array): Uint8Array {
    return sumToPk(depth, sk);
}

export function compactGetPeriod(depth: number, sk: Uint8Array): number {
    return sumGetPeriod(depth, sk);
}

/**
 * Compact sign: sigma || sibling_pk
 * If period < half: sibling = rhs_pk; else sibling = lhs_pk
 */
export function compactSignFromSlice(
    depth: number,
    sk: Uint8Array,
    message: Uint8Array,
    period: number,
): Uint8Array {
    if (depth === 0) {
        return sum0CompactSignFromSlice(sk, message, period);
    }

    const half = depthHalf(depth);
    const lowerSize = sumSkBodySize(depth - 1);
    let sigma: Uint8Array;
    let sibling: Uint8Array;

    if (period < half) {
        sibling = sk.subarray(
            lowerSize + SEED_SIZE + PUBLIC_KEY_SIZE,
            lowerSize + SEED_SIZE + PUBLIC_KEY_SIZE * 2,
        );
        sigma = compactSignFromSlice(
            depth - 1,
            sk.subarray(0, lowerSize),
            message,
            period,
        );
    } else {
        sibling = sk.subarray(lowerSize + SEED_SIZE, lowerSize + SEED_SIZE + PUBLIC_KEY_SIZE);
        sigma = compactSignFromSlice(
            depth - 1,
            sk.subarray(0, lowerSize),
            message,
            period - half,
        );
    }

    const out = new Uint8Array(compactSigSize(depth));
    out.set(sigma, 0);
    out.set(sibling, sigma.length);
    return out;
}

export function compactSign(
    depth: number,
    sk: Uint8Array,
    message: Uint8Array,
): Uint8Array {
    const body = sumSkBodySize(depth);
    const period = readPeriod(sk, body);
    return compactSignFromSlice(depth, sk.subarray(0, body), message, period);
}

/**
 * Recompute root public key from compact signature + message.
 * Returns null on verification failure.
 */
export function compactRecompute(
    depth: number,
    signature: Uint8Array,
    period: number,
    message: Uint8Array,
): Uint8Array | null {
    if (signature.length !== compactSigSize(depth)) return null;
    if (period < 0 || period >= depthTotal(depth)) return null;

    if (depth === 0) {
        return sum0CompactRecompute(signature, period, message);
    }

    const childSize = compactSigSize(depth - 1);
    const sigma = signature.subarray(0, childSize);
    const siblingPk = signature.subarray(childSize, childSize + PUBLIC_KEY_SIZE);
    const half = depthHalf(depth);

    if (period < half) {
        const recomputed = compactRecompute(depth - 1, sigma, period, message);
        if (recomputed === null) return null;
        return hashPair(recomputed, siblingPk);
    }

    const recomputed = compactRecompute(depth - 1, sigma, period - half, message);
    if (recomputed === null) return null;
    return hashPair(siblingPk, recomputed);
}

export function compactVerify(
    depth: number,
    signature: Uint8Array,
    period: number,
    publicKey: Uint8Array,
    message: Uint8Array,
): boolean {
    if (publicKey.length !== PUBLIC_KEY_SIZE) return false;
    const root = compactRecompute(depth, signature, period, message);
    if (root === null) return false;
    return bytesEq(root, publicKey);
}

// --- Sum6 compact conveniences ---

export const SUM6_COMPACT_SIG_SIZE = compactSigSize(6); // 288
export const SUM6_COMPACT_SK_BODY = skBodySize(6); // 608
export const SUM6_COMPACT_SK_SIZE = skWithPeriodSize(6); // 612

export function keygenSum6Compact(seed: Uint8Array): { sk: Uint8Array; pk: Uint8Array } {
    const sk = new Uint8Array(SUM6_COMPACT_SK_SIZE);
    const seedCopy = seed.slice();
    const pk = compactKeygen(6, sk, seedCopy);
    return { sk, pk };
}

export function verifySum6Compact(
    signature: Uint8Array,
    period: number,
    publicKey: Uint8Array,
    message: Uint8Array,
): boolean {
    return compactVerify(6, signature, period, publicKey, message);
}

export function signSum6Compact(sk: Uint8Array, message: Uint8Array): Uint8Array {
    return compactSign(6, sk, message);
}

export function updateSum6Compact(sk: Uint8Array): void {
    compactUpdate(6, sk);
}
