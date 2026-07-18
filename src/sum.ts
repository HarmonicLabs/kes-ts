/**
 * Recursive Sum KES (non-compact) — port of IOHK `sum_kes!` macro in kes.rs.
 * Depth d can evolve 2^d periods. Cardano headers use Sum6 (448-byte sig).
 */
import {
    PUBLIC_KEY_SIZE,
    SEED_SIZE,
    assertLen,
    bytesEq,
    depthHalf,
    depthTotal,
    hashPair,
    readPeriod,
    skBodySize,
    skWithPeriodSize,
    splitSeed,
    sumSigSize,
    writePeriod,
} from "./common.ts";
import {
    SUM0_SK_BODY,
    sum0Keygen,
    sum0KeygenSlice,
    sum0SignFromSlice,
    sum0ToPk,
    sum0Verify,
} from "./sum0.ts";

/** SK body size (no period) at depth d */
export function sumSkBodySize(depth: number): number {
    return skBodySize(depth);
}

export function sumSkSize(depth: number): number {
    return skWithPeriodSize(depth);
}

export function sumSignatureSize(depth: number): number {
    return sumSigSize(depth);
}

/**
 * Recursive keygen into keySlice of length skBodySize(depth).
 * When optSeed is provided, seed is consumed/zeroed.
 * When optSeed is null, seed lives at keySlice[SIZE..SIZE+32] (SIZE+32 buffer).
 */
export function sumKeygenSlice(
    depth: number,
    inSlice: Uint8Array,
    optSeed: Uint8Array | null,
): Uint8Array {
    if (depth === 0) {
        return sum0KeygenSlice(inSlice, optSeed);
    }

    const size = sumSkBodySize(depth);
    const lowerSize = sumSkBodySize(depth - 1);

    let r0: Uint8Array;
    let seed: Uint8Array;

    if (optSeed !== null) {
        assertLen(inSlice, size, `sumKeygenSlice d=${depth} inSlice`);
        assertLen(optSeed, SEED_SIZE, `sumKeygenSlice d=${depth} seed`);
        ({ left: r0, right: seed } = splitSeed(optSeed));
    } else {
        assertLen(inSlice, size + SEED_SIZE, `sumKeygenSlice d=${depth} inSlice+seed`);
        const seedSlot = inSlice.subarray(size, size + SEED_SIZE);
        ({ left: r0, right: seed } = splitSeed(seedSlot));
    }

    // Save right seed before lower keygen zeros it via recursive path
    inSlice.set(seed, lowerSize);

    // Left child keygen into prefix
    const pk0 = sumKeygenSlice(depth - 1, inSlice.subarray(0, lowerSize), r0);

    // Right child: full keygen into temp (body + period)
    const temp = new Uint8Array(sumSkSize(depth - 1));
    const seedCopy = seed.slice();
    const pk1 = sumKeygen(depth - 1, temp, seedCopy);
    temp.fill(0);
    seed.fill(0);

    const pk = hashPair(pk0, pk1);

    // Write lhs/rhs public keys after lower SK + seed slot
    inSlice.set(pk0, lowerSize + SEED_SIZE);
    inSlice.set(pk1, lowerSize + SEED_SIZE + PUBLIC_KEY_SIZE);

    return pk;
}

/**
 * Full keygen: keyBuffer length = skBody + 4 (period).
 * Zeros masterSeed. Returns root public key.
 */
export function sumKeygen(
    depth: number,
    keyBuffer: Uint8Array,
    masterSeed: Uint8Array,
): Uint8Array {
    const body = sumSkBodySize(depth);
    assertLen(keyBuffer, body + 4, `sumKeygen d=${depth} keyBuffer`);
    assertLen(masterSeed, SEED_SIZE, "sumKeygen seed");

    if (depth === 0) {
        return sum0Keygen(keyBuffer, masterSeed);
    }

    const pk = sumKeygenSlice(depth, keyBuffer.subarray(0, body), masterSeed);
    writePeriod(keyBuffer, body, 0);
    return pk;
}

/**
 * Update SK in-place (body only for recursive; period bumped at top).
 * period is current period before update.
 */
export function sumUpdateSlice(
    depth: number,
    keySlice: Uint8Array,
    period: number,
): void {
    if (depth === 0) {
        throw new Error("KeyCannotBeUpdatedMore");
    }

    const total = depthTotal(depth);
    if (period + 1 === total) {
        throw new Error("KeyCannotBeUpdatedMore");
    }

    const half = depthHalf(depth);
    const lowerSize = sumSkBodySize(depth - 1);
    const next = period + 1;

    if (next < half) {
        sumUpdateSlice(depth - 1, keySlice.subarray(0, lowerSize), period);
    } else if (next === half) {
        // Materialize right half from stored seed at [lowerSize .. lowerSize+32]
        // keygen_slice into [0 .. lowerSize+32] with opt_seed=None
        sumKeygenSlice(
            depth - 1,
            keySlice.subarray(0, lowerSize + SEED_SIZE),
            null,
        );
    } else {
        sumUpdateSlice(
            depth - 1,
            keySlice.subarray(0, lowerSize),
            period - half,
        );
    }
}

export function sumUpdate(depth: number, sk: Uint8Array): void {
    const body = sumSkBodySize(depth);
    assertLen(sk, body + 4, `sumUpdate d=${depth}`);
    const period = readPeriod(sk, body);
    sumUpdateSlice(depth, sk.subarray(0, body), period);
    writePeriod(sk, body, period + 1);
}

export function sumGetPeriod(depth: number, sk: Uint8Array): number {
    const body = sumSkBodySize(depth);
    return readPeriod(sk, body);
}

/**
 * Derive root public key from SK: hash_pair of top-level lhs/rhs pks.
 */
export function sumToPk(depth: number, sk: Uint8Array): Uint8Array {
    if (depth === 0) {
        return sum0ToPk(sk);
    }
    const body = sumSkBodySize(depth);
    const lhs = sk.subarray(body - PUBLIC_KEY_SIZE * 2, body - PUBLIC_KEY_SIZE);
    const rhs = sk.subarray(body - PUBLIC_KEY_SIZE, body);
    return hashPair(lhs, rhs);
}

/**
 * Sign message. Signature size = sumSigSize(depth).
 * For depth>0 Sum (non-compact), period is not needed for sign_from_slice
 * (always signs with active lower SK + both pks).
 */
export function sumSignFromSlice(
    depth: number,
    sk: Uint8Array,
    message: Uint8Array,
): Uint8Array {
    if (depth === 0) {
        return sum0SignFromSlice(sk, message);
    }

    const lowerSize = sumSkBodySize(depth - 1);
    const sigma = sumSignFromSlice(depth - 1, sk.subarray(0, lowerSize), message);
    const lhsPk = sk.subarray(lowerSize + SEED_SIZE, lowerSize + SEED_SIZE + PUBLIC_KEY_SIZE);
    const rhsPk = sk.subarray(
        lowerSize + SEED_SIZE + PUBLIC_KEY_SIZE,
        lowerSize + SEED_SIZE + PUBLIC_KEY_SIZE * 2,
    );

    const out = new Uint8Array(sumSigSize(depth));
    out.set(sigma, 0);
    out.set(lhsPk, sigma.length);
    out.set(rhsPk, sigma.length + PUBLIC_KEY_SIZE);
    return out;
}

export function sumSign(depth: number, sk: Uint8Array, message: Uint8Array): Uint8Array {
    // Full SK includes period at end; body is enough for signing
    const body = sumSkBodySize(depth);
    return sumSignFromSlice(depth, sk.subarray(0, body), message);
}

/**
 * Verify Sum signature at given period against root public key.
 */
export function sumVerify(
    depth: number,
    signature: Uint8Array,
    period: number,
    publicKey: Uint8Array,
    message: Uint8Array,
): boolean {
    if (signature.length !== sumSigSize(depth)) return false;
    if (publicKey.length !== PUBLIC_KEY_SIZE) return false;
    if (period < 0 || period >= depthTotal(depth)) return false;

    if (depth === 0) {
        return sum0Verify(signature, period, publicKey, message);
    }

    const childSigSize = sumSigSize(depth - 1);
    const sigma = signature.subarray(0, childSigSize);
    const lhs = signature.subarray(childSigSize, childSigSize + PUBLIC_KEY_SIZE);
    const rhs = signature.subarray(
        childSigSize + PUBLIC_KEY_SIZE,
        childSigSize + PUBLIC_KEY_SIZE * 2,
    );

    if (!bytesEq(hashPair(lhs, rhs), publicKey)) return false;

    const half = depthHalf(depth);
    if (period < half) {
        return sumVerify(depth - 1, sigma, period, lhs, message);
    }
    return sumVerify(depth - 1, sigma, period - half, rhs, message);
}

// --- Convenience Sum6 (Cardano) ---

export const SUM6_DEPTH = 6;
export const SUM6_SIG_SIZE = sumSigSize(6); // 448
export const SUM6_SK_BODY = sumSkBodySize(6); // 608
export const SUM6_SK_SIZE = sumSkSize(6); // 612

export function keygenSum6(seed: Uint8Array): { sk: Uint8Array; pk: Uint8Array } {
    const sk = new Uint8Array(SUM6_SK_SIZE);
    const seedCopy = seed.slice();
    const pk = sumKeygen(6, sk, seedCopy);
    return { sk, pk };
}

export function verifySum6(
    signature: Uint8Array,
    period: number,
    publicKey: Uint8Array,
    message: Uint8Array,
): boolean {
    return sumVerify(6, signature, period, publicKey, message);
}

export function signSum6(sk: Uint8Array, message: Uint8Array): Uint8Array {
    return sumSign(6, sk, message);
}

export function updateSum6(sk: Uint8Array): void {
    sumUpdate(6, sk);
}

export function toPkSum6(sk: Uint8Array): Uint8Array {
    return sumToPk(6, sk);
}

export function getPeriodSum6(sk: Uint8Array): number {
    return sumGetPeriod(6, sk);
}
