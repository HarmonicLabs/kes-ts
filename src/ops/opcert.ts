/**
 * Operational certificates (`node.cert`) and the cold key's issue counter (`node.counter`), in the
 * exact byte layout cardano-cli writes, plus the checks cardano-node applies in the header rules
 * (OCERT: cold signature, KES period window, counter progression m ≤ n ≤ m + 1).
 */
import { deriveEd25519PublicKey_sync, getEd25519Signature_sync, verifyEd25519Signature_sync } from "@harmoniclabs/crypto";
import { cborDecode, cborEncode, fromHex, toHex, type MiniCbor } from "./cbor";
import { EnvelopeType, type TextEnvelope } from "./envelope";

export interface OpcertFields { kesVkey: Uint8Array; counter: bigint; kesPeriod: bigint; signature: Uint8Array }
export interface OperationalCert { cert: OpcertFields; coldVkey: Uint8Array }
export interface IssueCounter { next: bigint; coldVkey: Uint8Array }
export interface ColdKey { skey: Uint8Array; vkey: Uint8Array }

const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
function u64(n: bigint): Uint8Array { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n, false); return b; }

/** Cold key from its 32-byte secret (the `cold.skey` payload). */
export function coldKeyFromSecret(skey: Uint8Array): ColdKey {
    if (skey.length !== 32) throw new Error("cold signing key must be 32 bytes");
    return { skey, vkey: deriveEd25519PublicKey_sync(skey) };
}

/** Bytes the cold key signs: kes_vkey ‖ counter (u64 BE) ‖ kes_period (u64 BE). */
export function opcertSigningBytes(kesVkey: Uint8Array, counter: bigint, kesPeriod: bigint): Uint8Array {
    const out = new Uint8Array(48); out.set(kesVkey, 0); out.set(u64(counter), 32); out.set(u64(kesPeriod), 40);
    return out;
}

export function opcertFieldsToCbor(c: OpcertFields): MiniCbor { return [c.kesVkey, c.counter, c.kesPeriod, c.signature]; }

function opcertFieldsFromCbor(v: MiniCbor): OpcertFields {
    if (!Array.isArray(v) || v.length !== 4) throw new Error("opcert is not a 4-element array");
    const [k, n, p, s] = v;
    if (!(k instanceof Uint8Array) || typeof n !== "bigint" || typeof p !== "bigint" || !(s instanceof Uint8Array)) throw new Error("opcert element types");
    if (k.length !== 32 || s.length !== 64) throw new Error("opcert key/signature sizes");
    return { kesVkey: k, counter: n, kesPeriod: p, signature: s };
}

/** `node.cert`: `[[kes_vkey, counter, kes_period, cold_signature], cold_vkey]`. */
export function decodeOperationalCert(env: TextEnvelope): OperationalCert {
    if (env.type !== EnvelopeType.operationalCert) throw new Error(`TextEnvelope type ${env.type}, expected ${EnvelopeType.operationalCert}`);
    const v = cborDecode(fromHex(env.cborHex));
    if (!Array.isArray(v) || v.length !== 2 || !(v[1] instanceof Uint8Array)) throw new Error("opcert envelope is not [cert, bytes]");
    return { cert: opcertFieldsFromCbor(v[0]!), coldVkey: v[1] };
}

export function encodeOperationalCert(oc: OperationalCert): TextEnvelope {
    return { type: EnvelopeType.operationalCert, description: "", cborHex: toHex(cborEncode([opcertFieldsToCbor(oc.cert), oc.coldVkey])) };
}

/** `node.counter`: `[next_counter, cold_vkey]`. */
export function decodeIssueCounter(env: TextEnvelope): IssueCounter {
    if (env.type !== EnvelopeType.counter) throw new Error(`TextEnvelope type ${env.type}, expected ${EnvelopeType.counter}`);
    const v = cborDecode(fromHex(env.cborHex));
    if (!Array.isArray(v) || v.length !== 2 || typeof v[0] !== "bigint" || !(v[1] instanceof Uint8Array)) throw new Error("counter envelope is not [uint, bytes]");
    return { next: v[0], coldVkey: v[1] };
}

export function encodeIssueCounter(c: IssueCounter): TextEnvelope {
    return { type: EnvelopeType.counter, description: `Next certificate issue number: ${c.next}`, cborHex: toHex(cborEncode([c.next, c.coldVkey])) };
}

/** `cardano-cli node issue-op-cert`: sign with the cold key; returns the certificate and the bumped counter. */
export function issueOperationalCert(kesVkey: Uint8Array, counter: IssueCounter, kesPeriod: bigint, cold: ColdKey): { opcert: OperationalCert; nextCounter: IssueCounter } {
    if (!eq(counter.coldVkey, cold.vkey)) throw new Error("counter file belongs to a different cold key");
    if (kesVkey.length !== 32) throw new Error("KES vkey must be 32 bytes");
    const signature = getEd25519Signature_sync(opcertSigningBytes(kesVkey, counter.next, kesPeriod), cold.skey);
    const cert: OpcertFields = { kesVkey: Uint8Array.from(kesVkey), counter: counter.next, kesPeriod, signature: Uint8Array.from(signature) };
    return { opcert: { cert, coldVkey: Uint8Array.from(cold.vkey) }, nextCounter: { next: counter.next + 1n, coldVkey: counter.coldVkey } };
}

export function verifyOpcertSignature(oc: OperationalCert): boolean {
    return verifyEd25519Signature_sync(oc.cert.signature, opcertSigningBytes(oc.cert.kesVkey, oc.cert.counter, oc.cert.kesPeriod), oc.coldVkey);
}

export interface OpcertCheckInput {
    /** KES period of the current slot: floor(slot / slotsPerKESPeriod). */
    currentKesPeriod: bigint;
    /** Genesis `maxKESEvolutions` (62 on every public network). */
    maxKesEvolutions: bigint;
    /** Last counter this pool put on chain, null when it has never produced a block. */
    lastOnChainCounter: bigint | null;
    /** The KES verification key the certificate must be about. */
    kesVkey: Uint8Array;
}
export type OpcertCheck = { ok: true; evolution: number } | { ok: false; reason: string };

/**
 * What cardano-node checks before accepting a header signed under this certificate. On success
 * returns the KES evolution the signing key must be at for the current period.
 */
export function checkOperationalCert(oc: OperationalCert, input: OpcertCheckInput): OpcertCheck {
    const { cert } = oc;
    if (!verifyOpcertSignature(oc)) return { ok: false, reason: "cold signature invalid" };
    if (!eq(cert.kesVkey, input.kesVkey)) return { ok: false, reason: "certificate is for a different KES key" };
    if (input.currentKesPeriod < cert.kesPeriod) return { ok: false, reason: `KES period ${cert.kesPeriod} starts after the current period ${input.currentKesPeriod}` };
    if (input.currentKesPeriod >= cert.kesPeriod + input.maxKesEvolutions) return { ok: false, reason: `KES key expired: period ${cert.kesPeriod} + ${input.maxKesEvolutions} evolutions ≤ current ${input.currentKesPeriod}` };
    const r = checkCounterProgression(cert.counter, input.lastOnChainCounter);
    if (!r.ok) return r;
    return { ok: true, evolution: Number(input.currentKesPeriod - cert.kesPeriod) };
}

/** OCERT counter rule: at least the last on-chain counter, at most one above it. */
export function checkCounterProgression(counter: bigint, lastOnChain: bigint | null): { ok: true } | { ok: false; reason: string } {
    if (lastOnChain == null) return { ok: true };
    if (counter < lastOnChain) return { ok: false, reason: `counter ${counter} below last on-chain counter ${lastOnChain}` };
    if (counter > lastOnChain + 1n) return { ok: false, reason: `counter ${counter} skips ahead of last on-chain counter ${lastOnChain} (at most +1)` };
    return { ok: true };
}
