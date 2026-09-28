# Cross-implementation harness

The key derivation in `src/derivation/` is a compatibility contract: the LSP node derives the public halves of the same keys with
fiber's Rust code, so a one-byte divergence makes every channel unusable. This folder holds the second implementation that contract
is checked against, plus the vectors it produces. The `rpc` module has a contract of the same kind, fiber's JSON forms, and the
same harness pins it in `vectors/rpc.json`: params and results serialized by fiber's own JSON types, and the envelopes as the
jsonrpsee version fiber serves writes them.

`test/tests/derivation/interop-vectors.spec.ts` runs against `vectors/vectors.json` on every `pnpm test`, so the contract is
checked without a Rust toolchain. Rust is only needed to regenerate the vectors and to verify the SDK's partial signature under
fiber's own crate, and the interop workflow does both on every pull request that touches the harness, the derivation, the signing
engine or the tests.

For the scheme those vectors pin, see [`docs/derivation.md`](../docs/derivation.md).

## The four parts

| Part           | What it is                                                                                                                                                                                                                                                                                                                                                                  |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fiber_scheme` | Verbatim ports of the pure derivation functions of `nervosnetwork/fiber` @ `b71a61c3` (v0.9.0-rc7), `crates/fiber-types/src/channel.rs`                                                                                                                                                                                                                                     |
| `sdk_scheme`   | The SDK-owned derivations (master seed path, wallet identity key, per-channel seed, musig2 nonce seed), written from their definition rather than ported, so the TypeScript side is checked against an independent implementation instead of against itself                                                                                                                 |
| `digest`       | Verbatim ports of fiber's signed-message reconstruction (`crates/fiber-lib/src/fiber/channel.rs` and `fee.rs`): fixture channels through settlement witness, lock args, fee mocks, and the four digests, with per-case intermediates so a divergence localizes itself (see [`docs/digest.md`](../docs/digest.md))                                                           |
| `rpc`          | Nothing ported: fiber's RPC forms for the ten methods the client speaks, built from fixed values and serialized by `fiber-json-types` (fiber's serde-only crate, pinned by git rev), plus the request, result and error envelopes as `jsonrpsee-types 0.25.1` writes them; and the other direction, the params the TS client encodes read back by fiber's own deserializers |

The master seed half needs BIP32, and the harness implements hardened derivation from the spec (`hmac` + `sha2`) rather than
pulling a BIP32 crate: a second implementation is the whole point, and agreeing with `@scure/bip32` only means something if the
two were written apart.

The `musig2` crate is the exact crate and version fiber depends on (`musig2 = 0.2.4`, features `["secp256k1"]`), so a partial
signature the SDK produces is verified by the same code that will receive it.

The digest half leans the other way on purpose: where the TS side implements molecule serialization from scratch, the harness
serializes with CKB's own `ckb-types`, and the unsigned channel announcement is built and hashed by `fiber-types` itself,
pinned by git rev to the reference commit. The TS fragment is thereby checked against the canonical implementations, not
against a second hand-rolled one.

All seeds are fixed public constants: the keys in `vectors/` are test keys and nothing else.

## Regenerating the vectors

```bash
cd interop/rust
cargo run --release -- gen-vectors ../vectors/vectors.json
cargo run --release -- gen-rpc-vectors ../vectors/rpc.json
cd ../.. && pnpm test
```

Never hand-edit a file under `vectors/`: CI regenerates both and fails on any diff, which is what turns "someone changed a
derivation" or "someone changed a fixture" into a red build. `gen-rpc-vectors` refuses a debug build: fiber's
`GetPaymentCommandResult` carries a field that exists only under `debug_assertions`, so the forms a release node writes are the
ones pinned.

## The RPC forms

`vectors/rpc.json` holds, per method, `params` and `results` cases of `{name, values, json}`: `values` is the fixed input in the
harness's own forms (bare hex, decimal integers, names, a flag set as the list of names fiber emits for it), `json` is what
fiber's serde writes for the struct built from it. The cases cover every `ChannelState` name and every close flag, the flag sets
that leak a composite name (`OUR_INIT_SENT` alone serializes as `OUR_INIT_SENT|INIT_SENT`) and the empty set, every invoice
and payment status, options present and absent, `u128::MAX` amounts, and funding transactions with cell deps of both types, a
header dep, typed and untyped outputs and witnesses, the submit's signed tx being the open's unsigned one with only its
witnesses changed. The envelopes are one request and, as jsonrpsee writes them, an object, an empty object and a `null`
result, and the errors a client meets: `-32000` (every handler failure), `-32999` (a refused token, twice: its message is
`"Unauthorized"` or that word followed by the Biscuit run limit hit, so only the code identifies it), `-32602` (params fiber's
deserializer refuses, the only one that carries `data`: serde's message), `-32601` and `-32600` with a `null` id.
`test/tests/rpc/interop-vectors.spec.ts` pins that coverage on every `pnpm test`.

"Every" is checked against fiber, not against a copied list: `gen-rpc-vectors` fails unless the cases carry every channel
state, close flag, invoice status, payment status, currency and hash algorithm fiber has. The enums are listed next to an
exhaustive `match`, so a variant a new release adds fails to compile until it is listed, and the close flags are read from
fiber's serializer with every bit set.

The `invoice_address` strings are fixture strings, not decodable invoices: fiber's invoice encoding is pinned by vectors of its
own when the SDK decodes it. The attributes inside an invoice are in fiber's forms: `udt_script` is the molecule `Script`
bytes, and `feature` the bit names fiber's `enabled_features_names` lists, checked against it at generation. The signature
is a real recoverable one, written by fiber's `InvoiceSignature`: the 65 bytes regrouped into 104 five-bit values, as hex.

## Verifying the RPC params

Nothing writes `INTEROP_RPC_OUT` until the first encoder of the `rpc` module lands; from then on the loop runs as:

```bash
INTEROP_RPC_OUT=/tmp/ts-rpc-out.json pnpm test -- test/tests/rpc
cd interop/rust
cargo run --release -- verify-rpc-params ../vectors/rpc.json /tmp/ts-rpc-out.json
```

The TS side writes `{ "<method>": [ { "name": "<case>", "params": {...} } ] }`, the params its encoders produced for each
`params` case of the vectors, once the client's encoders exist. `verify-rpc-params` deserializes each into fiber's params
struct and serializes it back, and requires the round trip to return what was sent, an absent option and a `null` counting as
one, and to equal the vector's own `json`. No fiber params struct denies unknown fields, so a misspelt optional field is
dropped by the node in silence; the round trip is what catches it, along with a wrong form: a decimal amount, a hex with
leading zeros and a field CKB's transaction does not know are refused, and a `0x` on a pubkey is accepted and written back
bare. A method the TS side writes must be one of the ten and carry every case the vectors hold for it; methods it does not
write yet are not checked, so the loop closes method by method as the encoders land, but an output with no method at all is
refused. `cargo test --release` pins each of those outcomes against the vectors, and the interop workflow runs it.

## Re-validating against a new fiber release

1. Diff `crates/fiber-types/src/channel.rs` between `b71a61c3` and the new tag.
2. Port any change into the `fiber scheme` section of `rust/src/main.rs` and bump `FIBER_REF`.
3. Bump the `rev` of both fiber crates in `rust/Cargo.toml`. Read the `jsonrpsee-types` version in fiber's own `Cargo.lock`, and
   set it in `rust/Cargo.toml` and in `JSONRPSEE_VERSION` in `rust/src/rpc.rs`.
4. Re-read the refused-token path at the `file:line` the comment on `UNAUTHORIZED_CODE` in `rust/src/rpc.rs` cites: its code and its
   messages are literals there, so a change reaches the vectors only through the harness.
5. Regenerate both vector files, then run `cargo test --release` and `pnpm test`.

A green suite means upstream did not move. A red derivation is the decision point: fiber changed its scheme, and existing
channels derived under the old one stay on it (`DERIVATION_SCHEME_VERSION` is additive only). A red RPC form, or a generation
that fails its coverage check, means the client's codecs follow the new forms.

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
