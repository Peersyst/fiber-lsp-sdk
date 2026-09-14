# Cross-implementation harness

The key derivation in `src/derivation/` is a compatibility contract: the LSP node derives the public halves of the same keys with
fiber's Rust code, so a one-byte divergence makes every channel unusable. This folder holds the second implementation that contract
is checked against, plus the vectors it produces.

`test/tests/derivation/interop-vectors.spec.ts` runs against `vectors/vectors.json` on every `pnpm test`, so the contract is
checked without a Rust toolchain. Rust is only needed to regenerate the vectors and to verify the SDK's partial signature under
fiber's own crate, and the interop workflow does both on every pull request that touches the harness, the derivation, the signing
engine or the tests.

For the scheme those vectors pin, see [`docs/derivation.md`](../docs/derivation.md).

## The three halves

| Half           | What it is                                                                                                                                                                                                                                                                                                        |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fiber_scheme` | Verbatim ports of the pure derivation functions of `nervosnetwork/fiber` @ `b71a61c3` (v0.9.0-rc7), `crates/fiber-types/src/channel.rs`                                                                                                                                                                           |
| `sdk_scheme`   | The SDK-owned derivations (master seed path, wallet identity key, per-channel seed, musig2 nonce seed), written from their definition rather than ported, so the TypeScript side is checked against an independent implementation instead of against itself                                                       |
| `digest`       | Verbatim ports of fiber's signed-message reconstruction (`crates/fiber-lib/src/fiber/channel.rs` and `fee.rs`): fixture channels through settlement witness, lock args, fee mocks, and the four digests, with per-case intermediates so a divergence localizes itself (see [`docs/digest.md`](../docs/digest.md)) |

The master seed half needs BIP32, and the harness implements hardened derivation from the spec (`hmac` + `sha2`) rather than
pulling a BIP32 crate: a second implementation is the whole point, and agreeing with `@scure/bip32` only means something if the
two were written apart.

The `musig2` crate is the exact crate and version fiber depends on (`musig2 = 0.2.4`, features `["secp256k1"]`), so a partial
signature the SDK produces is verified by the same code that will receive it.

The digest half leans the other way on purpose: where the TS side implements molecule serialization from scratch, the harness
serializes with CKB's own `ckb-types`, and the unsigned channel announcement is built and hashed by `fiber-types` itself,
pinned by git rev to the reference commit. The TS fragment is thereby checked against the canonical implementations, not
against a second hand-rolled one.

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
INTEROP_TS_OUT=/tmp/ts-out.json pnpm test -- test/tests/signer/interop-vectors.spec.ts
cd interop/rust
cargo run --release -- verify-ts ../vectors/vectors.json /tmp/ts-out.json
```

Checks that a BIP-327 partial signature produced by the SDK verifies under fiber's musig2 crate and aggregates into a valid Schnorr
signature. `INTEROP_TS_OUT` makes `test/tests/signer/interop-vectors.spec.ts` write the `{ "local_pubnonce": "...",
"partial_signature": "..." }` the subcommand reads, for the loop's canonical slot, (0, `COMMITMENT`); unset, the spec writes
nothing, so a plain `pnpm test` has no side effects. The interop workflow sets it for its own `pnpm test` and runs `verify-ts`
right after, so a signature fiber's crate rejects fails the build the same way a changed vector does. For the engine under test,
see [`docs/signing.md`](../docs/signing.md).
