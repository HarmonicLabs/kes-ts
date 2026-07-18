# @harmoniclabs/kes

Pure TypeScript Cardano **KES** (Key Evolving Signatures) — MMM Sum composition of Ed25519.

Port of [IOHK `kes-summed-ed25519`](https://github.com/input-output-hk/kes) (Apache-2.0).  
Paper: [Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures](https://eprint.iacr.org/2001/034).

## Status

- **Sum6 non-compact** (448-byte sig) — Cardano header format — full keygen / update / sign / verify
- **Sum6 compact** (288-byte sig) — full lifecycle
- IOHK/Haskell interop vectors: **19/19 pass**
- Not security-audited (same disclaimer as upstream)

## Install

```bash
# sibling monorepo style
"@harmoniclabs/kes": "file:../kes-ts"
```

Depends on `@harmoniclabs/crypto` (`blake2b_256`, strict Ed25519).

## API (wasm-kes compatible — Sum6)

```ts
import {
  verify, sign, kes_keygen, kes_update, kes_to_pk, kes_get_period,
  SUM6_SIGNATURE_SIZE, // 448
} from "@harmoniclabs/kes";

const { sk, pk } = kes_keygen(seed32);
const sig = sign(sk, message);
verify(sig, 0, pk, message); // true
kes_update(sk);
```

Also exports depth-generic `sumVerify` / `compactVerify` and helpers.

## Sizes (depth 6)

| | Size |
|--|--|
| Public key | 32 |
| Sum sig (Cardano headers) | **448** |
| Compact sig | 288 |
| SK body (Shelley wire) | 608 |
| SK + period (this crate) | 612 |

## Crypto notes

- `hashPair(a,b) = Blake2b-256(a || b)` — **no** domain prefixes
- `splitSeed`: left=`H(1||seed)`, right=`H(2||seed)`, parent zeroed
- Leaf: Ed25519 strict verify via `@harmoniclabs/crypto`
- Period: `u32` BE last 4 bytes of SK (not in cardano-node SK wire format)

## Tests

```bash
bun test
```

Vectors under `tests/vectors/` from IOHK `kes` interop suite.

## License

Apache-2.0. TypeScript implementation by Harmonic Labs.
