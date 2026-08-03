# Cross-implementation harness

The key derivation in `src/derivation/` is a compatibility contract: the LSP node derives the public halves of the same keys with
fiber's Rust code, so a one-byte divergence makes every channel unusable. This folder holds the second implementation that contract
is checked against, plus the vectors it produces.

`test/tests/derivation/interop-vectors.spec.ts` runs against `vectors/vectors.json` on every `pnpm test`, so the contract is
checked without a Rust toolchain. Rust is only needed to regenerate the vectors.

For the scheme those vectors pin, see [`docs/derivation.md`](../docs/derivation.md).

## The two halves

| Half           | What it is                                                                                                                                                                                                                                |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fiber_scheme` | Verbatim ports of the pure derivation functions of `nervosnetwork/fiber` @ `b71a61c3` (v0.9.0-rc7), `crates/fiber-types/src/channel.rs`                                                                                                   |
| `sdk_scheme`   | The SDK-owned derivations (wallet identity key, per-channel seed, musig2 nonce seed), written from their definition rather than ported, so the TypeScript side is checked against an independent implementation instead of against itself |

The `musig2` crate is the exact crate and version fiber depends on (`musig2 = 0.2.4`, features `["secp256k1"]`), so a partial
signature the SDK produces is verified by the same code that will receive it.

All seeds are fixed public constants: the keys in `vectors/vectors.json` are test keys and nothing else.

## Regenerating the vectors

```bash
cd interop/rust
cargo run --release -- gen-vectors ../vectors/vectors.json
cd ../.. && pnpm test
```

Never hand-edit `vectors/vectors.json`: CI regenerates it and fails on any diff, which is what turns "someone changed a
derivation" into a red build.

## Re-validating against a new fiber release

1. Diff `crates/fiber-types/src/channel.rs` between `b71a61c3` and the new tag.
2. Port any change into the `fiber scheme` section of `rust/src/main.rs` and bump `FIBER_REF`.
3. Regenerate the vectors and run `pnpm test`.

A green suite means upstream did not move. A red one is the decision point: fiber changed its scheme, and existing channels derived
under the old one stay on it (`DERIVATION_SCHEME_VERSION` is additive only).

## Verifying a partial signature

```bash
cargo run --release -- verify-ts ../vectors/vectors.json <ts-out.json>
```

Checks that a BIP-327 partial signature produced by the SDK verifies under fiber's musig2 crate and aggregates into a valid Schnorr
signature. It reads a `{ "local_pubnonce": "...", "partial_signature": "..." }` file, which the musig2 signing engine emits; that
engine is not implemented yet, so this subcommand has no producer in the repo today.
