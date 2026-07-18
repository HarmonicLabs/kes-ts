import { describe, expect, test } from "bun:test";
import {
    sum0Keygen,
    sum0Sign,
    sum0Verify,
    sum0ToPk,
    sum0CompactSign,
    sum0CompactVerify,
    SUM0_SK_SIZE,
    SUM0_SIG_SIZE,
    SUM0_COMPACT_SIG_SIZE,
} from "../src/sum0";
import { bytesEq } from "../src/common";

const MSG = new TextEncoder().encode("test message");
const SEED = new TextEncoder().encode("test string of 32 byte of lenght");

describe("Sum0", () => {
    test("keygen/sign/verify roundtrip", () => {
        const sk = new Uint8Array(SUM0_SK_SIZE);
        const seed = SEED.slice();
        const pk = sum0Keygen(sk, seed);
        expect(pk.length).toBe(32);
        expect(seed.every((b) => b === 0)).toBe(true);
        expect(bytesEq(sum0ToPk(sk), pk)).toBe(true);

        const sig = sum0Sign(sk, MSG);
        expect(sig.length).toBe(SUM0_SIG_SIZE);
        expect(sum0Verify(sig, 0, pk, MSG)).toBe(true);
        expect(sum0Verify(sig, 0, pk, new TextEncoder().encode("wrong"))).toBe(false);
    });

    test("compact leaf sign/verify", () => {
        const sk = new Uint8Array(SUM0_SK_SIZE);
        const pk = sum0Keygen(sk, SEED.slice());
        const sig = sum0CompactSign(sk, MSG);
        expect(sig.length).toBe(SUM0_COMPACT_SIG_SIZE);
        expect(sum0CompactVerify(sig, 0, pk, MSG)).toBe(true);
        expect(sum0CompactVerify(sig, 0, pk, new TextEncoder().encode("nope"))).toBe(false);
    });
});
