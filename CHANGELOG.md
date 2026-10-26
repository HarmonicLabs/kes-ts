# Changelog

## 0.1.0

First npm release. Published as CommonJS in `dist/` with type declarations (works in Node, Bun and bundlers).

### Added
- Sum6 KES: key generation, evolution, signing and verification in pure TypeScript.
- `setEd25519Verify`: plug a fast raw ed25519 verifier into the KES leaf check.
- `src/ops/`, what a stake pool's KES agent needs, compatible with cardano-cli 11.0: text envelopes for `kes.skey` /
  `kes.vkey`, `node.cert` and `cold.counter`; evolving a key to the current period; the operational certificate's
  remaining life; rotation in one step (new KES key, new operational certificate, bumped counter, checked against
  the counter the chain last saw).

Tested against cardano-cli vectors made with throwaway keys (`tests/vectors/cardano-cli/`).
