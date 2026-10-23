import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { blake2b_224 } from "@harmoniclabs/crypto";
import {
    checkOperationalCert, coldKeyFromSecret, decodeIssueCounter, decodeOperationalCert, encodeIssueCounter, encodeOperationalCert, envelopeBytes,
    evolveKesTo, generateKesKey, issueOperationalCert, kesEvolution, kesKeyFromEnvelopes, kesKeyToEnvelopes, kesPeriodOfSlot, kesStatus,
    parseTextEnvelope, rotateKes, serializeTextEnvelope, sign, verify, verifyOpcertSignature, EnvelopeType, cborDecode, cborEncode, toHex,
} from "../src/index";

// Throwaway keys made with cardano-cli 11.0 (node key-gen, key-gen-KES, issue-op-cert --kes-period 123).
const V = (n: string) => readFileSync(new URL(`./vectors/cardano-cli/${n}`, import.meta.url), "utf8");
const env = (n: string) => parseTextEnvelope(V(n));
const PREVIEW = { slotsPerKESPeriod: 129600, maxKESEvolutions: 62, slotZeroTimeSec: 1666656000, slotLengthSec: 1 };

describe("mini CBOR", () => {
    test("round-trips the key-file shapes canonically", () => {
        for (const v of [0n, 23n, 24n, 255n, 256n, 65535n, 65536n, 2n ** 32n, 2n ** 63n]) expect(cborDecode(cborEncode(v))).toBe(v);
        const nested = [[new Uint8Array(32).fill(7), 5n, 123n, new Uint8Array(64).fill(9)], new Uint8Array(32).fill(1)];
        expect(toHex(cborEncode(cborDecode(cborEncode(nested))))).toBe(toHex(cborEncode(nested)));
        expect(() => cborDecode(Uint8Array.of(0x01, 0x02))).toThrow(/trailing/);
    }, 120_000);
});

describe("cardano-cli interop", () => {
    test("counter, KES key and operational certificate decode and re-encode byte-identically", () => {
        const counter = decodeIssueCounter(env("cold.counter"));
        expect(counter.next).toBe(1n);
        expect(encodeIssueCounter(counter)).toEqual(env("cold.counter"));
        const cold = coldKeyFromSecret(envelopeBytes(env("cold.skey"), 32));
        expect(toHex(cold.vkey)).toBe(toHex(envelopeBytes(env("cold.vkey"), 32)));
        expect(toHex(blake2b_224(cold.vkey))).toBe(V("pool.id").trim());
        const kes = kesKeyFromEnvelopes(env("kes.skey"), env("kes.vkey"));
        expect(kesEvolution(kes)).toBe(0);
        expect(kesKeyToEnvelopes(kes).skey.cborHex).toBe(env("kes.skey").cborHex);
        expect(kesKeyToEnvelopes(kes).vkey.cborHex).toBe(env("kes.vkey").cborHex);
        const oc = decodeOperationalCert(env("node.cert"));
        expect(oc.cert.counter).toBe(0n);
        expect(oc.cert.kesPeriod).toBe(123n);
        expect(verifyOpcertSignature(oc)).toBe(true);
        expect(encodeOperationalCert(oc).cborHex).toBe(env("node.cert").cborHex);
        // re-issuing with the same inputs reproduces cardano-cli's certificate (ed25519 is deterministic)
        const again = issueOperationalCert(kes.vkey, { next: 0n, coldVkey: cold.vkey }, 123n, cold);
        expect(encodeOperationalCert(again.opcert).cborHex).toBe(env("node.cert").cborHex);
        expect(again.nextCounter.next).toBe(1n);
        expect(serializeTextEnvelope(env("node.cert"))).toBe(V("node.cert").endsWith("\n") ? V("node.cert") : V("node.cert") + "\n");
    }, 120_000);

    test("header-rule checks: signature, KES key, period window, counter progression", () => {
        const oc = decodeOperationalCert(env("node.cert"));
        const kes = kesKeyFromEnvelopes(env("kes.skey"));
        const base = { currentKesPeriod: 130n, maxKesEvolutions: 62n, lastOnChainCounter: null, kesVkey: kes.vkey };
        expect(checkOperationalCert(oc, base)).toEqual({ ok: true, evolution: 7 });
        expect(checkOperationalCert(oc, { ...base, currentKesPeriod: 122n })).toMatchObject({ ok: false });
        expect(checkOperationalCert(oc, { ...base, currentKesPeriod: 185n })).toMatchObject({ ok: false, reason: expect.stringMatching(/expired/) });
        expect(checkOperationalCert(oc, { ...base, lastOnChainCounter: 0n })).toMatchObject({ ok: true });
        expect(checkOperationalCert(oc, { ...base, lastOnChainCounter: 1n })).toMatchObject({ ok: false, reason: expect.stringMatching(/below/) });
        expect(checkOperationalCert(oc, { ...base, kesVkey: generateKesKey(new Uint8Array(32).fill(3)).vkey })).toMatchObject({ ok: false, reason: expect.stringMatching(/different KES key/) });
        const tampered = { ...oc, cert: { ...oc.cert, counter: 5n } };
        expect(checkOperationalCert(tampered, base)).toMatchObject({ ok: false, reason: expect.stringMatching(/signature/) });
    }, 120_000);
});

describe("lifecycle", () => {
    test("evolve forward only; signatures verify at the evolved period", () => {
        const kes = generateKesKey(new Uint8Array(32).fill(1));
        const msg = new TextEncoder().encode("header");
        evolveKesTo(kes, 10);
        expect(kesEvolution(kes)).toBe(10);
        expect(verify(sign(kes.skey, msg), 10, kes.vkey, msg)).toBe(true);
        expect(() => evolveKesTo(kes, 9)).toThrow(/cannot go back/);
        expect(() => evolveKesTo(kes, 63)).toThrow(/out of range/);
        expect(() => kesKeyToEnvelopes(kes)).toThrow(/evolution 0/);
    }, 120_000);

    test("status: remaining periods, expiry slot and date, health thresholds", () => {
        // the Gerolamo preview pool's certificate: period 944, at slot 123 693 225 (period 954)
        const s = kesStatus(944n, 123_693_225n, PREVIEW);
        expect(s.currentPeriod).toBe(954n);
        expect(s.evolution).toBe(10);
        expect(s.remainingPeriods).toBe(52);
        expect(s.expiresSlot).toBe(130_377_600n);
        expect(s.expiresAt!.toISOString()).toBe("2026-12-12T00:00:00.000Z");
        expect(s.health).toBe("ok");
        expect(kesStatus(944n, (944n + 50n) * 129600n, PREVIEW).health).toBe("rotate-soon");
        expect(kesStatus(944n, (944n + 60n) * 129600n, PREVIEW).health).toBe("rotate-now");
        expect(kesStatus(944n, (944n + 62n) * 129600n, PREVIEW).health).toBe("expired");
        expect(kesStatus(944n, 900n * 129600n, PREVIEW).health).toBe("not-yet-valid");
        expect(kesPeriodOfSlot(129599n, 129600n)).toBe(0n);
    }, 120_000);

    test("rotation: new key + certificate the header rules accept; counter rule enforced", () => {
        const cold = coldKeyFromSecret(envelopeBytes(env("cold.skey"), 32));
        const counter = decodeIssueCounter(env("cold.counter")); // next = 1
        const slot = 954n * 129600n + 5n;
        const r = rotateKes({ cold, counter, currentSlot: slot, genesis: PREVIEW, lastOnChainCounter: 0n, seed: new Uint8Array(32).fill(4) });
        expect(r.opcert.cert.counter).toBe(1n);
        expect(r.opcert.cert.kesPeriod).toBe(954n);
        expect(r.nextCounter.next).toBe(2n);
        expect(r.status.remainingPeriods).toBe(62);
        expect(r.envelopes.kesSkey.type).toBe(EnvelopeType.kesSigningKey);
        const reloaded = kesKeyFromEnvelopes(r.envelopes.kesSkey, r.envelopes.kesVkey);
        expect(checkOperationalCert(r.opcert, { currentKesPeriod: 954n, maxKesEvolutions: 62n, lastOnChainCounter: 0n, kesVkey: reloaded.vkey })).toEqual({ ok: true, evolution: 0 });
        // a counter two ahead of the chain would get every block rejected: refused
        expect(() => rotateKes({ cold, counter: { ...counter, next: 3n }, currentSlot: slot, genesis: PREVIEW, lastOnChainCounter: 0n })).toThrow(/rotation refused/);
        // the counter file must belong to this cold key
        expect(() => rotateKes({ cold, counter: { next: 1n, coldVkey: new Uint8Array(32) }, currentSlot: slot, genesis: PREVIEW, lastOnChainCounter: 0n })).toThrow(/different cold key/);
    }, 120_000);
});
