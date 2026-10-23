/**
 * KES key lifecycle for a stake pool: load / store the cardano-cli `kes.skey` form, evolve a key to
 * the current period, compute how long the operational certificate has left, and rotate (new KES
 * key + new operational certificate + bumped counter) — `cardano-cli node key-gen-KES` +
 * `node issue-op-cert` in one step, with the counter rule checked against the chain.
 *
 * Periods: the KES period of slot s is floor(s / slotsPerKESPeriod); a certificate issued at period
 * p is valid for periods p … p + maxKESEvolutions − 1, and the key signs period c with evolution
 * c − p. Sum6 has 64 evolutions; Cardano genesis caps it at 62.
 */
import { getPeriodSum6, keygenSum6, toPkSum6, updateSum6, SUM6_SK_BODY, SUM6_SK_SIZE } from "../sum";
import { envelopeBytes, envelopeOfBytes, EnvelopeType, type TextEnvelope } from "./envelope";
import { checkCounterProgression, issueOperationalCert, type ColdKey, type IssueCounter, type OperationalCert } from "./opcert";

export const KES_MAX_EVOLUTIONS = 62;

export interface KesKey {
    /** Sum6 secret with its period suffix (612 bytes), at its current evolution. Keep in memory only. */
    skey: Uint8Array;
    vkey: Uint8Array;
}

/** Overwrite secret key buffers (on rotation, shutdown, error paths). */
export function zeroise(...keys: Array<Uint8Array | null | undefined>): void { for (const k of keys) k?.fill(0); }

function withPeriod(body: Uint8Array, period = 0): Uint8Array {
    if (body.length === SUM6_SK_SIZE) return body;
    if (body.length !== SUM6_SK_BODY) throw new Error(`KES secret: ${body.length} bytes, expected ${SUM6_SK_BODY} or ${SUM6_SK_SIZE}`);
    const out = new Uint8Array(SUM6_SK_SIZE); out.set(body, 0);
    new DataView(out.buffer).setUint32(SUM6_SK_BODY, period, false);
    return out;
}

export function generateKesKey(seed: Uint8Array = crypto.getRandomValues(new Uint8Array(32))): KesKey {
    if (seed.length !== 32) throw new Error("KES seed must be 32 bytes");
    const { sk, pk } = keygenSum6(Uint8Array.from(seed)); // keygen zeroes its seed copy
    return { skey: withPeriod(sk), vkey: pk };
}

/** From the cardano-cli envelopes (the vkey envelope, when given, must match). */
export function kesKeyFromEnvelopes(skeyEnv: TextEnvelope, vkeyEnv?: TextEnvelope): KesKey {
    if (skeyEnv.type !== EnvelopeType.kesSigningKey) throw new Error(`TextEnvelope type ${skeyEnv.type}, expected ${EnvelopeType.kesSigningKey}`);
    const skey = withPeriod(envelopeBytes(skeyEnv, SUM6_SK_BODY));
    const vkey = toPkSum6(skey);
    if (vkeyEnv) {
        const declared = envelopeBytes(vkeyEnv, 32);
        if (declared.length !== vkey.length || !declared.every((x, i) => x === vkey[i])) throw new Error("kes.vkey does not match kes.skey");
    }
    return { skey, vkey };
}

/** The envelopes cardano-cli writes. Only evolution 0 is representable: the file format carries no period. */
export function kesKeyToEnvelopes(key: KesKey): { skey: TextEnvelope; vkey: TextEnvelope } {
    if (kesEvolution(key) !== 0) throw new Error("kes.skey files hold evolution 0 only; evolved keys are not written back");
    return {
        skey: envelopeOfBytes(EnvelopeType.kesSigningKey, "KES Signing Key", key.skey.subarray(0, SUM6_SK_BODY)),
        vkey: envelopeOfBytes(EnvelopeType.kesVerificationKey, "KES Verification Key", key.vkey),
    };
}

export function kesEvolution(key: KesKey): number { return getPeriodSum6(key.skey); }

/** Evolve in place to `target` evolutions (relative to the certificate). Irreversible; forward only. */
export function evolveKesTo(key: KesKey, target: number, maxEvolutions = KES_MAX_EVOLUTIONS): void {
    if (target < 0 || target > maxEvolutions) throw new Error(`KES evolution ${target} out of range 0..${maxEvolutions}`);
    let cur = kesEvolution(key);
    if (target < cur) throw new Error(`KES key already at evolution ${cur}, cannot go back to ${target}`);
    while (cur < target) { updateSum6(key.skey); cur++; }
}

export const kesPeriodOfSlot = (slot: bigint, slotsPerKESPeriod: bigint): bigint => slot / slotsPerKESPeriod;

export interface KesGenesis {
    slotsPerKESPeriod: number | bigint;
    maxKESEvolutions: number | bigint;
    /** For wall-clock dates: POSIX seconds of `timeOfSlot0` and the slot length (Shelley-era arithmetic). */
    slotZeroTimeSec?: number;
    slotLengthSec?: number;
}

export type KesHealth = "ok" | "rotate-soon" | "rotate-now" | "expired" | "not-yet-valid";

export interface KesStatus {
    currentPeriod: bigint;
    opcertPeriod: bigint;
    /** Evolution the key must be at now. */
    evolution: number;
    maxEvolutions: number;
    /** Periods left before the certificate stops being valid (0 when expired). */
    remainingPeriods: number;
    /** First slot at which blocks can no longer be signed under this certificate. */
    expiresSlot: bigint;
    /** Seconds from `currentSlot` to `expiresSlot`. */
    remainingSec: number;
    /** When `slotZeroTimeSec` was given. */
    expiresAt?: Date;
    health: KesHealth;
}

/**
 * How long a certificate has left. Thresholds (default): `rotate-soon` below 14 periods (~3 weeks on
 * 36-hour periods), `rotate-now` below 4 periods (~6 days).
 */
export function kesStatus(opcertKesPeriod: bigint, currentSlot: bigint, g: KesGenesis, thresholds = { soonPeriods: 14, nowPeriods: 4 }): KesStatus {
    const spk = BigInt(g.slotsPerKESPeriod), maxEvo = Number(g.maxKESEvolutions);
    const currentPeriod = kesPeriodOfSlot(currentSlot, spk);
    const expiresSlot = (opcertKesPeriod + BigInt(maxEvo)) * spk;
    const evolution = Number(currentPeriod - opcertKesPeriod);
    const remainingPeriods = Math.max(0, maxEvo - evolution);
    const slotLen = g.slotLengthSec ?? 1;
    const remainingSec = Math.max(0, Number(expiresSlot - currentSlot) * slotLen);
    let health: KesHealth = "ok";
    if (currentPeriod < opcertKesPeriod) health = "not-yet-valid";
    else if (remainingPeriods <= 0) health = "expired";
    else if (remainingPeriods < thresholds.nowPeriods) health = "rotate-now";
    else if (remainingPeriods < thresholds.soonPeriods) health = "rotate-soon";
    const expiresAt = g.slotZeroTimeSec != null ? new Date((g.slotZeroTimeSec + Number(expiresSlot) * slotLen) * 1000) : undefined;
    return { currentPeriod, opcertPeriod: opcertKesPeriod, evolution, maxEvolutions: maxEvo, remainingPeriods, expiresSlot, remainingSec, expiresAt, health };
}

export interface RotationInput {
    cold: ColdKey;
    counter: IssueCounter;
    currentSlot: bigint;
    genesis: KesGenesis;
    /** The pool's last counter on chain (null if it never produced a block). Rotation is refused if the new counter would break the OCERT rule. */
    lastOnChainCounter: bigint | null;
    /** 32-byte seed for the new KES key (default: crypto.getRandomValues). */
    seed?: Uint8Array;
}

export interface RotationResult {
    kes: KesKey;
    envelopes: { kesSkey: TextEnvelope; kesVkey: TextEnvelope };
    opcert: OperationalCert;
    nextCounter: IssueCounter;
    status: KesStatus;
}

/** New KES key + operational certificate at the current period; the caller writes the files and restarts the producer. */
export function rotateKes(input: RotationInput): RotationResult {
    const r = checkCounterProgression(input.counter.next, input.lastOnChainCounter);
    if (!r.ok) throw new Error(`rotation refused: the new certificate would carry counter ${input.counter.next}: ${r.reason}`);
    const period = kesPeriodOfSlot(input.currentSlot, BigInt(input.genesis.slotsPerKESPeriod));
    const kes = generateKesKey(input.seed);
    const { opcert, nextCounter } = issueOperationalCert(kes.vkey, input.counter, period, input.cold);
    const env = kesKeyToEnvelopes(kes);
    return { kes, envelopes: { kesSkey: env.skey, kesVkey: env.vkey }, opcert, nextCounter, status: kesStatus(period, input.currentSlot, input.genesis) };
}
