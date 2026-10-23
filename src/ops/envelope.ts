/**
 * cardano-cli TextEnvelope files (`{ type, description, cborHex }`) for the key material a stake
 * pool rotates: KES keys, operational certificates and the cold key's issue counter. Pure
 * string/bytes functions — reading and writing files is the caller's business (Bun, Node, browser).
 */
import { cborDecode, cborEncode, fromHex, toHex } from "./cbor";

export interface TextEnvelope { type: string; description: string; cborHex: string }

/** TextEnvelope `type` strings written by cardano-cli 10/11. */
export const EnvelopeType = {
    coldSigningKey: "StakePoolSigningKey_ed25519",
    coldVerificationKey: "StakePoolVerificationKey_ed25519",
    counter: "NodeOperationalCertificateIssueCounter",
    kesSigningKey: "KesSigningKey_ed25519_kes_2^6",
    kesVerificationKey: "KesVerificationKey_ed25519_kes_2^6",
    operationalCert: "NodeOperationalCertificate",
} as const;

export function parseTextEnvelope(json: string, expectedType?: string): TextEnvelope {
    const d = JSON.parse(json);
    if (typeof d?.type !== "string" || typeof d?.cborHex !== "string") throw new Error("Not a TextEnvelope (type/cborHex missing)");
    if (expectedType && d.type !== expectedType) throw new Error(`TextEnvelope type ${d.type}, expected ${expectedType}`);
    return { type: d.type, description: typeof d.description === "string" ? d.description : "", cborHex: d.cborHex };
}

/** cardano-cli's layout: 4-space indent, keys type/description/cborHex, trailing newline. */
export function serializeTextEnvelope(env: TextEnvelope): string {
    return JSON.stringify({ type: env.type, description: env.description, cborHex: env.cborHex }, null, 4) + "\n";
}

/** The payload of a bytestring envelope. */
export function envelopeBytes(env: TextEnvelope, expectedLength?: number): Uint8Array {
    const v = cborDecode(fromHex(env.cborHex));
    if (!(v instanceof Uint8Array)) throw new Error(`${env.type}: cborHex is not a CBOR bytestring`);
    if (expectedLength != null && v.length !== expectedLength) throw new Error(`${env.type}: ${v.length} bytes, expected ${expectedLength}`);
    return v;
}

export function envelopeOfBytes(type: string, description: string, bytes: Uint8Array): TextEnvelope {
    return { type, description, cborHex: toHex(cborEncode(bytes)) };
}
