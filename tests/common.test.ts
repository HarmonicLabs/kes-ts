import { describe, expect, test } from "bun:test";
import { blake2b_256 } from "@harmoniclabs/crypto";
import {
    hashPair,
    splitSeed,
    sumSigSize,
    compactSigSize,
    skBodySize,
    bytesEq,
} from "../src/common.ts";

const SEED = new TextEncoder().encode("test string of 32 byte of lenght");

describe("common", () => {
    test("interop seed is 32 bytes", () => {
        expect(SEED.length).toBe(32);
    });

    test("hashPair is blake2b-256 of concat, no domain prefix", () => {
        const a = new Uint8Array(32).fill(1);
        const b = new Uint8Array(32).fill(2);
        const got = hashPair(a, b);
        const buf = new Uint8Array(64);
        buf.set(a, 0);
        buf.set(b, 32);
        const expected = blake2b_256(buf);
        expect(bytesEq(got, expected)).toBe(true);
    });

    test("splitSeed left=H(1||seed) right=H(2||seed) and zeros parent", () => {
        const s = SEED.slice();
        const orig = s.slice();
        const { left, right } = splitSeed(s);
        expect(left.length).toBe(32);
        expect(right.length).toBe(32);
        expect(s.every((b) => b === 0)).toBe(true);
        expect(bytesEq(left, right)).toBe(false);

        const leftIn = new Uint8Array(33);
        leftIn[0] = 1;
        leftIn.set(orig, 1);
        const rightIn = new Uint8Array(33);
        rightIn[0] = 2;
        rightIn.set(orig, 1);
        expect(bytesEq(left, blake2b_256(leftIn))).toBe(true);
        expect(bytesEq(right, blake2b_256(rightIn))).toBe(true);
    });

    test("size formulas match Cardano Sum6", () => {
        expect(sumSigSize(6)).toBe(448);
        expect(compactSigSize(6)).toBe(288);
        expect(skBodySize(6)).toBe(608);
        expect(sumSigSize(0)).toBe(64);
        expect(compactSigSize(0)).toBe(96);
        expect(skBodySize(0)).toBe(32);
        expect(skBodySize(1)).toBe(128);
    });
});
