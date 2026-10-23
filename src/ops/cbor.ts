/**
 * Minimal CBOR for the fixed shapes cardano-cli key files use (unsigned ints, byte strings,
 * definite arrays). Canonical (shortest) encoding, like cardano-cli. Not a general CBOR codec.
 */

export type MiniCbor = bigint | Uint8Array | MiniCbor[];

function head(major: number, n: bigint): Uint8Array {
    const m = major << 5;
    if (n < 24n) return Uint8Array.of(m | Number(n));
    if (n < 0x100n) return Uint8Array.of(m | 24, Number(n));
    if (n < 0x10000n) return Uint8Array.of(m | 25, Number(n >> 8n), Number(n & 0xffn));
    if (n < 0x100000000n) { const b = new Uint8Array(5); b[0] = m | 26; new DataView(b.buffer).setUint32(1, Number(n), false); return b; }
    const b = new Uint8Array(9); b[0] = m | 27; new DataView(b.buffer).setBigUint64(1, n, false); return b;
}

export function cborEncode(v: MiniCbor): Uint8Array {
    const parts: Uint8Array[] = [];
    const walk = (x: MiniCbor) => {
        if (typeof x === "bigint") { if (x < 0n) throw new Error("cbor: negative ints unsupported"); parts.push(head(0, x)); }
        else if (x instanceof Uint8Array) { parts.push(head(2, BigInt(x.length)), x); }
        else { parts.push(head(4, BigInt(x.length))); for (const e of x) walk(e); }
    };
    walk(v);
    let n = 0; for (const p of parts) n += p.length;
    const out = new Uint8Array(n); let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
}

export function cborDecode(b: Uint8Array): MiniCbor {
    let o = 0;
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const arg = (info: number): bigint => {
        if (info < 24) return BigInt(info);
        if (info === 24) return BigInt(b[o++]!);
        if (info === 25) { const v = dv.getUint16(o, false); o += 2; return BigInt(v); }
        if (info === 26) { const v = dv.getUint32(o, false); o += 4; return BigInt(v); }
        if (info === 27) { const v = dv.getBigUint64(o, false); o += 8; return v; }
        throw new Error(`cbor: unsupported length encoding ${info}`);
    };
    const item = (): MiniCbor => {
        if (o >= b.length) throw new Error("cbor: truncated");
        const ib = b[o++]!, major = ib >> 5, info = ib & 31;
        if (major === 0) return arg(info);
        if (major === 2) { const n = Number(arg(info)); if (o + n > b.length) throw new Error("cbor: truncated bytes"); const v = b.slice(o, o + n); o += n; return v; }
        if (major === 4) { const n = Number(arg(info)); const out: MiniCbor[] = []; for (let i = 0; i < n; i++) out.push(item()); return out; }
        throw new Error(`cbor: unsupported major type ${major}`);
    };
    const v = item();
    if (o !== b.length) throw new Error("cbor: trailing bytes");
    return v;
}

export const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function fromHex(h: string): Uint8Array {
    if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error("invalid hex");
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    return out;
}
