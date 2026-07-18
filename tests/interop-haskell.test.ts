/**
 * Interoperability tests against Cardano/Haskell-generated vectors
 * (IOHK kes-summed-ed25519 tests/data).
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { bytesEq, withPeriodZero } from "../src/common.ts";
import {
    keygenSum6,
    signSum6,
    updateSum6,
    verifySum6,
    getPeriodSum6,
    toPkSum6,
    sumKeygen,
    sumSign,
    sumUpdate,
    sumVerify,
    sumToPk,
    SUM6_SK_BODY,
    SUM6_SK_SIZE,
    SUM6_SIG_SIZE,
} from "../src/sum.ts";
import {
    keygenSum6Compact,
    signSum6Compact,
    updateSum6Compact,
    verifySum6Compact,
    SUM6_COMPACT_SIG_SIZE,
} from "../src/compact.ts";

const VEC = join(import.meta.dir, "vectors");
const SEED = new TextEncoder().encode("test string of 32 byte of lenght");
const MSG = new TextEncoder().encode("test message");

function load(name: string): Uint8Array {
    return new Uint8Array(readFileSync(join(VEC, name)));
}

describe("Haskell interop — Sum (non-compact)", () => {
    test("depth-1 keygen matches key1.bin", () => {
        const sk = new Uint8Array(sumSkSizeLocal(1));
        const seed = SEED.slice();
        sumKeygen(1, sk, seed);
        const h = load("key1.bin");
        expect(sk.subarray(0, h.length)).toEqual(h);
    });

    test("depth-6 keygen matches key6.bin", () => {
        const { sk } = keygenSum6(SEED.slice());
        const h = load("key6.bin");
        expect(h.length).toBe(SUM6_SK_BODY);
        expect(sk.subarray(0, SUM6_SK_BODY)).toEqual(h);
        expect(getPeriodSum6(sk)).toBe(0);
    });

    test("depth-6 update once matches key6update1.bin", () => {
        const { sk } = keygenSum6(SEED.slice());
        updateSum6(sk);
        expect(getPeriodSum6(sk)).toBe(1);
        expect(sk.subarray(0, SUM6_SK_BODY)).toEqual(load("key6update1.bin"));
    });

    test("depth-6 update five times matches key6update5.bin", () => {
        const { sk } = keygenSum6(SEED.slice());
        for (let i = 0; i < 5; i++) updateSum6(sk);
        expect(getPeriodSum6(sk)).toBe(5);
        expect(sk.subarray(0, SUM6_SK_BODY)).toEqual(load("key6update5.bin"));
    });

    test("depth-6 sign period 0 matches key6Sig.bin", () => {
        const { sk, pk } = keygenSum6(SEED.slice());
        const sig = signSum6(sk, MSG);
        expect(sig.length).toBe(SUM6_SIG_SIZE);
        expect(sig).toEqual(load("key6Sig.bin"));
        expect(verifySum6(sig, 0, pk, MSG)).toBe(true);
        expect(verifySum6(sig, 1, pk, MSG)).toBe(false);
        expect(verifySum6(sig, 0, pk, new TextEncoder().encode("no"))).toBe(false);
    });

    test("depth-6 sign after 5 updates matches key6Sig5.bin", () => {
        const { sk, pk } = keygenSum6(SEED.slice());
        for (let i = 0; i < 5; i++) updateSum6(sk);
        const sig = signSum6(sk, MSG);
        expect(sig).toEqual(load("key6Sig5.bin"));
        expect(verifySum6(sig, 5, pk, MSG)).toBe(true);
        expect(verifySum6(sig, 0, pk, MSG)).toBe(false);
        // root pk stable across updates
        expect(bytesEq(toPkSum6(sk), pk)).toBe(true);
    });

    test("verify vector sig with pk from vector key", () => {
        // Build pk from keygen (vector SK is shelley format without period)
        const { pk } = keygenSum6(SEED.slice());
        const sig0 = load("key6Sig.bin");
        const sig5 = load("key6Sig5.bin");
        expect(verifySum6(sig0, 0, pk, MSG)).toBe(true);
        expect(verifySum6(sig5, 5, pk, MSG)).toBe(true);
    });
});

describe("Haskell interop — SumCompact", () => {
    test("compact depth-1 keygen matches compactkey1.bin", () => {
        const sk = new Uint8Array(sumSkSizeLocal(1));
        sumKeygen(1, sk, SEED.slice());
        expect(sk.subarray(0, 128)).toEqual(load("compactkey1.bin"));
    });

    test("compact depth-6 keygen matches compactkey6.bin", () => {
        const { sk } = keygenSum6Compact(SEED.slice());
        expect(sk.subarray(0, 608)).toEqual(load("compactkey6.bin"));
    });

    test("compact update once matches compactkey6update1.bin", () => {
        const { sk } = keygenSum6Compact(SEED.slice());
        updateSum6Compact(sk);
        expect(sk.subarray(0, 608)).toEqual(load("compactkey6update1.bin"));
    });

    test("compact sign period 0 matches compactkey6Sig.bin", () => {
        const { sk, pk } = keygenSum6Compact(SEED.slice());
        const sig = signSum6Compact(sk, MSG);
        expect(sig.length).toBe(SUM6_COMPACT_SIG_SIZE);
        expect(sig).toEqual(load("compactkey6Sig.bin"));
        expect(verifySum6Compact(sig, 0, pk, MSG)).toBe(true);
        expect(verifySum6Compact(sig, 1, pk, MSG)).toBe(false);
    });

    test("compact sign after 5 updates matches compactkey6Sig5.bin", () => {
        const { sk, pk } = keygenSum6Compact(SEED.slice());
        for (let i = 0; i < 5; i++) updateSum6Compact(sk);
        const sig = signSum6Compact(sk, MSG);
        expect(sig).toEqual(load("compactkey6Sig5.bin"));
        expect(verifySum6Compact(sig, 5, pk, MSG)).toBe(true);
    });
});

describe("wasm-kes compatible API", () => {
    test("verify/sign/keygen surface", async () => {
        const { verify, sign, kes_keygen, kes_update, kes_to_pk, kes_get_period } =
            await import("../src/index.ts");
        const { sk, pk } = kes_keygen(SEED.slice());
        expect(kes_get_period(sk)).toBe(0);
        expect(bytesEq(kes_to_pk(sk), pk)).toBe(true);
        const sig = sign(sk, MSG);
        expect(verify(sig, 0, pk, MSG)).toBe(true);
        kes_update(sk);
        expect(kes_get_period(sk)).toBe(1);
        const sig1 = sign(sk, MSG);
        expect(verify(sig1, 1, pk, MSG)).toBe(true);
    });
});

function sumSkSizeLocal(depth: number): number {
    // 32 + d*96 + 4
    return 32 + depth * 96 + 4;
}
