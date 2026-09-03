/**
 * Depth-0 KES leaf — single-period Ed25519.
 * Port of IOHK `single_kes.rs` Sum0Kes / Sum0CompactKes.
 */
import {
    deriveEd25519PublicKey_sync,
    getEd25519Signature_sync,
    verifyEd25519Signature_sync,
} from "@harmoniclabs/crypto";
import {
    INDIVIDUAL_SECRET_SIZE,
    PERIOD_SIZE,
    PUBLIC_KEY_SIZE,
    SEED_SIZE,
    SIGMA_SIZE,
    assertLen,
    bytesEq,
} from "./common";

export const SUM0_SK_BODY = INDIVIDUAL_SECRET_SIZE; // 32
export const SUM0_SK_SIZE = SUM0_SK_BODY + PERIOD_SIZE; // 36
export const SUM0_SIG_SIZE = SIGMA_SIZE; // 64
export const SUM0_COMPACT_SIG_SIZE = SIGMA_SIZE + PUBLIC_KEY_SIZE; // 96

/**
 * Keygen Sum0 into keyBuffer of length 36 (32 sk + 4 period).
 * Zeros masterSeed after use.
 * Returns public key (32).
 */
export function sum0Keygen(keyBuffer: Uint8Array, masterSeed: Uint8Array): Uint8Array {
    assertLen(keyBuffer, SUM0_SK_SIZE, "sum0Keygen keyBuffer");
    assertLen(masterSeed, SEED_SIZE, "sum0Keygen seed");
    const sk32 = masterSeed.slice();
    const pk = deriveEd25519PublicKey_sync(sk32);
    keyBuffer.set(sk32, 0);
    keyBuffer.fill(0, SUM0_SK_BODY); // period = 0
    masterSeed.fill(0);
    sk32.fill(0);
    return pk;
}

/**
 * Recursive keygen helper: write 32-byte sk into inSlice[0..32], zero seed.
 * When optSeed provided: inSlice length = 32.
 * When not: inSlice length = 32+32 (sk || seed), seed at [32..64].
 */
export function sum0KeygenSlice(
    inSlice: Uint8Array,
    optSeed: Uint8Array | null,
): Uint8Array {
    let secret: Uint8Array;
    if (optSeed !== null) {
        assertLen(inSlice, SUM0_SK_BODY, "sum0KeygenSlice inSlice");
        assertLen(optSeed, SEED_SIZE, "sum0KeygenSlice seed");
        secret = optSeed.slice();
        optSeed.fill(0);
    } else {
        assertLen(inSlice, SUM0_SK_BODY + SEED_SIZE, "sum0KeygenSlice inSlice+seed");
        secret = inSlice.subarray(SUM0_SK_BODY).slice();
        inSlice.fill(0, SUM0_SK_BODY);
    }
    const pk = deriveEd25519PublicKey_sync(secret);
    inSlice.set(secret, 0);
    secret.fill(0);
    return pk;
}

export function sum0Sign(skBodyOrFull: Uint8Array, message: Uint8Array): Uint8Array {
    const sk32 = skBodyOrFull.subarray(0, SUM0_SK_BODY);
    return getEd25519Signature_sync(message, sk32);
}

export function sum0SignFromSlice(sk: Uint8Array, message: Uint8Array): Uint8Array {
    assertLen(sk.subarray(0, SUM0_SK_BODY), SUM0_SK_BODY, "sum0SignFromSlice");
    return getEd25519Signature_sync(message, sk.subarray(0, SUM0_SK_BODY));
}

/** Raw ed25519 verify used at the KES leaf. Pluggable so a host can supply a
 *  faster implementation (e.g. noble's pure-TS ed25519, ~30x faster than the
 *  textbook BigInt one in @harmoniclabs/crypto's `_sync` variant). */
export type Ed25519Verify = (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => boolean;

let ed25519Verify: Ed25519Verify = verifyEd25519Signature_sync;

export function setEd25519Verify(fn: Ed25519Verify | null | undefined): void {
    ed25519Verify = typeof fn === "function" ? fn : verifyEd25519Signature_sync;
}

export function getEd25519Verify(): Ed25519Verify {
    return ed25519Verify;
}

export function sum0Verify(
    signature: Uint8Array,
    _period: number,
    publicKey: Uint8Array,
    message: Uint8Array,
): boolean {
    if (signature.length !== SUM0_SIG_SIZE) return false;
    if (publicKey.length !== PUBLIC_KEY_SIZE) return false;
    try {
        return ed25519Verify(signature, message, publicKey);
    } catch {
        return false;
    }
}

export function sum0Update(_sk: Uint8Array): never {
    throw new Error("KeyCannotBeUpdatedMore");
}

export function sum0ToPk(sk: Uint8Array): Uint8Array {
    return deriveEd25519PublicKey_sync(sk.subarray(0, SUM0_SK_BODY));
}

// --- Compact leaf: sig = ed25519_sig(64) || leaf_pk(32) ---

export function sum0CompactSign(skBodyOrFull: Uint8Array, message: Uint8Array): Uint8Array {
    const sk32 = skBodyOrFull.subarray(0, SUM0_SK_BODY);
    const sig = getEd25519Signature_sync(message, sk32);
    const pk = deriveEd25519PublicKey_sync(sk32);
    const out = new Uint8Array(SUM0_COMPACT_SIG_SIZE);
    out.set(sig, 0);
    out.set(pk, SIGMA_SIZE);
    return out;
}

export function sum0CompactSignFromSlice(
    sk: Uint8Array,
    message: Uint8Array,
    _period: number,
): Uint8Array {
    return sum0CompactSign(sk, message);
}

/**
 * Compact recompute at leaf: verify ed25519, return leaf pk.
 */
export function sum0CompactRecompute(
    signature: Uint8Array,
    _period: number,
    message: Uint8Array,
): Uint8Array | null {
    if (signature.length !== SUM0_COMPACT_SIG_SIZE) return null;
    const edSig = signature.subarray(0, SIGMA_SIZE);
    const leafPk = signature.subarray(SIGMA_SIZE, SIGMA_SIZE + PUBLIC_KEY_SIZE);
    try {
        if (!ed25519Verify(edSig, message, leafPk)) return null;
    } catch {
        return null;
    }
    return leafPk.slice();
}

export function sum0CompactVerify(
    signature: Uint8Array,
    period: number,
    publicKey: Uint8Array,
    message: Uint8Array,
): boolean {
    const recomputed = sum0CompactRecompute(signature, period, message);
    if (recomputed === null) return false;
    return bytesEq(recomputed, publicKey);
}
