/**
 * @harmoniclabs/kes — pure TypeScript Cardano KES
 *
 * Default surface matches wasm-kes (Sum6 non-compact) for Gerolamo drop-in.
 * Also exports compact Sum6 and depth-generic helpers.
 *
 * Design: IOHK kes-summed-ed25519 (Apache-2.0) / MMM Sum composition.
 */

export {
    INDIVIDUAL_SECRET_SIZE,
    SIGMA_SIZE,
    PUBLIC_KEY_SIZE,
    SEED_SIZE,
    PERIOD_SIZE,
    hashPair,
    splitSeed,
    bytesEq,
    depthTotal,
    depthHalf,
    sumSigSize,
    compactSigSize,
    skBodySize,
    skWithPeriodSize,
    withPeriodZero,
    readPeriod,
    writePeriod,
} from "./common";

export {
    SUM0_SK_BODY,
    SUM0_SK_SIZE,
    SUM0_SIG_SIZE,
    SUM0_COMPACT_SIG_SIZE,
    sum0Keygen,
    sum0Sign,
    sum0Verify,
    sum0ToPk,
    sum0CompactSign,
    sum0CompactVerify,
    sum0CompactRecompute,
} from "./sum0";

export {
    sumKeygen,
    sumUpdate,
    sumSign,
    sumVerify,
    sumToPk,
    sumGetPeriod,
    sumSkBodySize,
    sumSkSize,
    sumSignatureSize,
    SUM6_DEPTH,
    SUM6_SIG_SIZE,
    SUM6_SK_BODY,
    SUM6_SK_SIZE,
    keygenSum6,
    verifySum6,
    signSum6,
    updateSum6,
    toPkSum6,
    getPeriodSum6,
} from "./sum";

export {
    compactKeygen,
    compactUpdate,
    compactSign,
    compactVerify,
    compactRecompute,
    compactToPk,
    compactGetPeriod,
    compactSignatureSize,
    SUM6_COMPACT_SIG_SIZE,
    SUM6_COMPACT_SK_BODY,
    SUM6_COMPACT_SK_SIZE,
    keygenSum6Compact,
    verifySum6Compact,
    signSum6Compact,
    updateSum6Compact,
} from "./compact";

// ---------------------------------------------------------------------------
// Pluggable raw ed25519 verifier for the KES leaf (see sum0.ts).
export { setEd25519Verify, getEd25519Verify, type Ed25519Verify } from "./sum0";

// wasm-kes compatible API (Sum6 non-compact — Cardano headers)
// ---------------------------------------------------------------------------

import {
    getPeriodSum6,
    keygenSum6,
    signSum6,
    toPkSum6,
    updateSum6,
    verifySum6,
    SUM6_SIG_SIZE as _SUM6_SIG,
    SUM6_SK_BODY as _SUM6_SK_BODY,
    SUM6_SK_SIZE as _SUM6_SK_SIZE,
} from "./sum";

/**
 * Verify a Sum6 KES signature (448 bytes) — drop-in for wasm-kes `verify`.
 */
export function verify(
    sig: Uint8Array,
    period: number,
    pk: Uint8Array,
    msg: Uint8Array,
): boolean {
    return verifySum6(sig, period, pk, msg);
}

/**
 * Sign with Sum6 secret key (body 608 or with period 612).
 */
export function sign(skey: Uint8Array, msg: Uint8Array): Uint8Array {
    return signSum6(skey, msg);
}

/**
 * Generate Sum6 keypair from 32-byte seed (seed is zeroed).
 */
export function kes_keygen(seed: Uint8Array): { sk: Uint8Array; pk: Uint8Array } {
    return keygenSum6(seed);
}

/**
 * Evolve Sum6 secret key to next period (mutates in place).
 */
export function kes_update(sk_buffer: Uint8Array): void {
    updateSum6(sk_buffer);
}

/**
 * Derive Sum6 public key from secret key buffer.
 */
export function kes_to_pk(sk_buffer: Uint8Array): Uint8Array {
    return toPkSum6(sk_buffer);
}

/**
 * Read current period from Sum6 secret key (last 4 BE bytes).
 */
export function kes_get_period(sk_buffer: Uint8Array): number {
    return getPeriodSum6(sk_buffer);
}

export { _SUM6_SIG as SUM6_SIGNATURE_SIZE };
export { _SUM6_SK_BODY as SUM6_SECRET_KEY_BODY_SIZE };
export { _SUM6_SK_SIZE as SUM6_SECRET_KEY_SIZE };
