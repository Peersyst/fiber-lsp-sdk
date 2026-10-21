# Cross-implementation harness

The key derivation in `src/derivation/` is a compatibility contract: the LSP node derives the public halves of the same keys with
fiber's Rust code, so a one-byte divergence makes every channel unusable. This folder holds the second implementation that contract
is checked against, plus the vectors it produces. The `rpc` module has a contract of the same kind, fiber's JSON forms, and the
same harness pins it in `vectors/rpc.json`: params and results serialized by fiber's own JSON types, and the envelopes as the
jsonrpsee version fiber serves writes them. The `invoice` module reads and writes fiber's invoice string, which the harness
pins in `vectors/invoice.json` from fiber's own encoder and decoder. And the signer answers fiber's signing requests, which the
harness pins in `vectors/signing.json`: one request per transition as a node writes it, with what the device must answer.

`test/tests/derivation/interop-vectors.spec.ts` runs against `vectors/vectors.json` on every `pnpm test`, and
`test/tests/signer/tenant-identity.spec.ts` against its `tenant_registry` section, so the contract is
checked without a Rust toolchain. Rust is only needed to regenerate the vectors and to verify, under fiber's own crates, the
SDK's partial signatures and the RPC params it encodes; the interop workflow does all of it on every pull request that touches
the harness, the modules the vectors pin (`common`, `derivation`, `digest`, `invoice`, `protocol`, `policy`, `signer`, `wire`,
`rpc`), the tests or the lockfile.

For the scheme those vectors pin, see [`docs/derivation.md`](../docs/derivation.md).

## The seven parts

| Part              | What it is                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fiber_scheme`    | Verbatim ports of the pure derivation functions of `nervosnetwork/fiber` @ `8db6a117`, the head of nervosnetwork/fiber#1623, `crates/fiber-types/src/channel.rs`; the derivation there is byte for byte that of `b71a61c3` (v0.9.0-rc7), which the regeneration proved                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `sdk_scheme`      | The SDK-owned derivations (master seed path, wallet identity key, per-channel seed, musig2 nonce seed), written from their definition rather than ported, so the TypeScript side is checked against an independent implementation instead of against itself                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `digest`          | Fixture channels through the four digests, with per-case intermediates so a divergence localizes itself. The settlement witness, its hash, the transaction message, the lock layouts (`CommitmentContractFeatures`) and the check that a settlement is the one a commitment's lock args commit are `fiber-types`' own, pinned by git rev; what `fiber-lib` keeps private is ported and cited at its `file:line`: the TLC order and flip of `get_active_tlcs`, the lock args, the fee mocks, and the reserve `reserved_capacity` sizes over a shutdown script with `ckb-types`' own `occupied_capacity` (see [`docs/digest.md`](../docs/digest.md)). Each case carries the plaintext its digest is computed from, as a signing request hands it over, and each commitment case the settlement snapshot fiber's `to_rpc_signing_settlement` states for it |
| `rpc`             | Nothing ported: fiber's RPC forms for the eighteen methods the client speaks, built from fixed values and serialized by `fiber-json-types` (fiber's serde-only crate, pinned by git rev), plus the request, result and error envelopes as `jsonrpsee-types 0.25.1` writes them; and the other direction, the params the TS client encodes read back by fiber's own deserializers                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `invoice`         | Nothing ported but the coder: invoices built from fixed values and written by `fiber-types`' own `CkbInvoice`, pinned by git rev, with each layer beside the string; the `arcode` coder, ported verbatim because fiber keeps it private, checked against those strings; UTF-8 as Rust reads it; variants of one invoice with fiber's verdict on each; and the other direction, fiber's decoder over the strings the TS encoder writes                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `signing`         | Fiber's six signing requests on one channel, written by `fiber-json-types` and checked through `fiber-lsp-sdk`'s own JSON codec, fiber's client crate pinned by git rev: the plaintexts built by the `digest` section, the key contexts, nonces and the peer's partial signatures by fiber's `musig2` and `InMemorySigner`; ported, cited, only `to_rpc_signing_settlement`, which `fiber-lib` keeps private. Beside each request, what the device answers; and variants of one request with the verdict of fiber's codec                                                                                                                                                                                                                                                                                                                               |
| `tenant_registry` | Nothing ported: one tenant registration, the RootSigner being the `sdk_scheme` wallet identity key and the LSP's node key and nonce fixed. The payload's canonical bytes, its digest and the tenant id are `fiber-types`' own `TenantRegistryPayload` and `TenantId`, pinned by git rev; the signature is the `sign_ecdsa` of fiber's agent (`crates/fiber-lsp-sdk/src/root_key.rs:53-64`, private there), deterministic, so the vector pins it byte for byte, and it is written only after fiber's `TenantRegistrySignature::from_slice` and `verify_signature` accept it                                                                                                                                                                                                                                                                              |

The master seed half needs BIP32, and the harness implements hardened derivation from the spec (`hmac` + `sha2`) rather than
pulling a BIP32 crate: a second implementation is the whole point, and agreeing with `@scure/bip32` only means something if the
two were written apart.

The `musig2` crate is the exact crate and version fiber depends on (`musig2 = 0.2.4`, features `["secp256k1"]`), so a partial
signature the SDK produces is verified by the same code that will receive it.

The digest half leans the other way on purpose: where the TS side implements molecule serialization from scratch, the harness
serializes with CKB's own `ckb-types`, and the settlement witness, the transaction message and the unsigned channel
announcement are built and hashed by `fiber-types` itself, pinned by git rev to the reference commit; a commitment case is
written only after fiber's own `settlement_matches_commitment_tx` reads its settlement back from the lock args the harness
built, so the one piece of the commitment that stays ported is checked by the crate. The TS fragment is thereby checked
against the canonical implementations, not against a second hand-rolled one.

All seeds are fixed public constants: the keys in `vectors/` are test keys and nothing else.

## Regenerating the vectors

```bash
cd interop/rust
cargo run --release -- gen-vectors ../vectors/vectors.json
cargo run --release -- gen-rpc-vectors ../vectors/rpc.json
cargo run --release -- gen-invoice-vectors ../vectors/invoice.json
cargo run --release -- gen-signing-vectors ../vectors/signing.json
cd ../.. && pnpm test
```

Never hand-edit a file under `vectors/`: CI regenerates all four and fails on any diff, which is what turns "someone changed a
derivation" or "someone changed a fixture" into a red build. `gen-rpc-vectors` refuses a debug build: fiber's
`GetPaymentCommandResult` carries a field that exists only under `debug_assertions`, so the forms a release node writes are the
ones pinned.

## The lock layouts

Every commitment and revocation case carries `lock_layout`, `legacy` or `full_payment_hash`: the two values of fiber's
`CommitmentContractFeatures` at the pin. Under `legacy` the commitment lock args are 57 bytes and each TLC record of the
settlement witness carries the first 20 bytes of the payment hash, 85 bytes a record; under `full_payment_hash` the args are
58, the features byte `0x01` after the `0x00`, and the record carries the whole 32-byte hash, 97 bytes. The layout reaches
the fee and the reserve: fiber sizes its fee mock with `lock_args_len()` zero bytes of args, so a commitment or a revocation
under `full_payment_hash` pays for one byte more (`tx_size` 457 against 456 on the CKB cases), and the device's reserve counts
a close script's args at no less than that length, so `reserve_cases[].reserved` holds a value under each layout, the six
scripts crossing both floors. The `legacy` cases are the ones the vectors held before the pin moved, byte for byte; each
`full_payment_hash` case mirrors a legacy twin, with the reserve its layout fixes. The revoked commitment's 36-byte args
know no layout, which is why a revocation case still carries one: its fee does.

## The plaintexts

A signing request carries the plaintext and the device computes the digest from it, so every digest case carries its
plaintext beside the digest. A commitment or shutdown case carries `transaction`, the unsigned transaction in fiber's JSON
(`ckb-jsonrpc-types`, `0x` hex), with no cell deps and no witnesses: `compute_tx_message` hashes the raw transaction with its
cell deps emptied, so that form is the digest's whole input. A revocation case carries, bare hex, the three parts fiber's
`Musig2SignableContent::Revocation` holds and hashes in this order: `output`, the molecule `CellOutput`; `output_data`, the
molecule `Bytes` with its 4-byte length header (`00000000` for a CKB channel), since fiber's builders hand over
`output_data.as_slice()` and hash it as it is; and `commitment_lock_script_args`, the revoked commitment's 36 bytes. A TLC
carries what a signing snapshot does: `local_key_commitment_number`, the number the device's TLC key is derived at, and
`remote_tlc_pubkey`, the peer's TLC key, both as fiber's `get_tlc_keys` derives them.

## The RPC forms

`vectors/rpc.json` holds, per method, `params` and `results` cases of `{name, values, json}`: `values` is the fixed input in the
harness's own forms (bare hex, decimal integers, names, `null` for an absent option, a flag set as the list of names fiber
emits for it), `json` is what fiber's serde writes for the struct built from it. The file holds eighteen methods. For the ten
the client has spoken since the first pin, the cases cover every `ChannelState` name and every close flag, the flag sets
that leak a composite name (`OUR_INIT_SENT` alone serializes as `OUR_INIT_SENT|INIT_SENT`) and the empty set, every invoice
and payment status, options present and absent, `u128::MAX` amounts, and funding transactions with cell deps of both types, a
header dep, typed and untyped outputs and witnesses, the submit's signed tx being the open's unsigned one with only its
witnesses changed. The eight of the tenant's API, at the head of nervosnetwork/fiber#1623, follow: `open_tenant_channel`
is the external-funding open with the signer's opening block (real musig2 public nonces, the announcement nonce present and
absent, the delay and fee rate options present and absent) and a result whose `opening_context` is pinned at ordinary values
and at `u128::MAX` amounts, `u64::MAX` reserves and fee rate and an epoch with every field set; `shutdown_channel` by channel
id alone and with the close script, fee rate and `force`, its result `null`; `get_channel_signing_status` and
`get_watchtower_signing_status` with `NoSignatureRequired` only, a channel's `SignatureRequired` requests being pinned whole
in `vectors/signing.json` (see "The signing requests") and the watchtower's not yet;
`submit_channel_signature` with and without `next_material` and `submit_watchtower_signature` with a recoverable signature,
each with both outcomes, `Applied` and `AlreadyApplied`; and `lsp_get_tenant_registry_nonce` and `lsp_register_tenant`, the
latter's `signature` the bare hex of the 64-byte compact form as fiber's own agent writes it, with a tenant under each runtime
status, `cold` without a channel or a root signer and `active` with its private channel online. Outside the methods,
`channel_state_flags` holds, for each `ChannelState`, the names fiber's serializer
writes with every bit set: the state's whole flag list in declaration order, so the client's per-state lists are pinned
whole and not only through the names the cases carry. The envelopes are one request and, as jsonrpsee writes them, an
object, an empty object and a `null` result, and the errors a client meets: `-32000` (every handler failure), `-32999` (a
refused token, twice: its message is `"Unauthorized"` or that word followed by the Biscuit run limit hit, so only the code
identifies it), `-32602` (params fiber's deserializer refuses, the only one that carries `data`: serde's message), `-32601`
and `-32600` with a `null` id.
`test/tests/rpc/interop-vectors.spec.ts` pins that coverage on every `pnpm test`.

"Every" is checked against fiber, not against a copied list: `gen-rpc-vectors` fails unless the cases carry every channel
state, close flag, invoice status, payment status, currency, hash algorithm, tenant runtime status and submission outcome
fiber has. The enums are listed next to an exhaustive `match`, so a variant a new release adds fails to compile until it is
listed, and the close flags are read from fiber's serializer with every bit set.

The `invoice_address` strings are fixture strings, not decodable invoices: fiber's invoice encoding is pinned by vectors of its
own, `vectors/invoice.json` (see below). The attributes inside an invoice are in fiber's forms: `udt_script` is the molecule `Script`
bytes, and `feature` the bit names fiber's `enabled_features_names` lists, checked against it at generation. The signature
is a real recoverable one, written by fiber's `InvoiceSignature`: the 65 bytes regrouped into 104 five-bit values, as hex.

## Verifying the RPC params

```bash
INTEROP_RPC_OUT=/tmp/ts-rpc-out.json pnpm test -- test/tests/rpc
cd interop/rust
cargo run --release -- verify-rpc-params ../vectors/rpc.json /tmp/ts-rpc-out.json
```

`INTEROP_RPC_OUT` makes `test/tests/rpc/interop-vectors.spec.ts` write `{ "<method>": [ { "name": "<case>", "params": {...} } ] }`,
the params the client's encoders produced for each `params` case of the vectors; unset, the spec writes nothing. It is the one
writer, and the file holds the eighteen methods: the map of encoders the spec runs is total over them by type, so a method
without an encoder does not compile. The interop workflow sets it and runs the verifier right after `pnpm test`.

`verify-rpc-params` deserializes each case into fiber's params struct and serializes it back, and requires the round trip to
return what was sent, an absent option and a `null` counting as one, and to equal the vector's own `json`. No fiber params
struct denies unknown fields, so a misspelt optional field is dropped by the node in silence; the round trip is what catches it,
along with a wrong form: a decimal amount, a hex with leading zeros and a field CKB's transaction does not know are refused, and a
`0x` on a pubkey is accepted and written back bare. A method the TS side writes must be one of the eighteen and carry every case
the vectors hold for it; a method it does not write is not checked, which is why the completeness is held on the TS side, and
an output with no method at all is refused. `cargo test --release` pins each of those outcomes against the vectors, and the
interop workflow runs it.

## Re-validating against a new fiber release

1. Diff `crates/fiber-types/src/channel.rs` between `8db6a117` and the new tag.
2. Port any change into the `fiber scheme` section of `rust/src/main.rs` and bump `FIBER_REF`.
3. Bump the `rev` of the three fiber crates in `rust/Cargo.toml`. Read the `jsonrpsee-types` version in fiber's own `Cargo.lock`, and
   set it in `rust/Cargo.toml` and in `JSONRPSEE_VERSION` in `rust/src/rpc.rs`. The witness, the transaction message, the lock
   layouts and the settlement check follow the bump on their own, being the crate's; re-read the private pieces the `digest`
   section of `rust/src/main.rs` ports at the `file:line` each comment cites (`get_active_tlcs`, the lock args of
   `build_commitment_transaction_output`, `commitment_tx_size`, `occupied_capacity`). A lock args port that no longer commits
   what the crate's witness says stops `gen-vectors` on the case's name. Re-read, at the `file:line` `rust/src/signing.rs`
   cites, `to_rpc_signing_settlement` (the one port there), the slot, counter and key order each request builder of
   `channel.rs` gives its transition, and the peer's nonce derivations.
   Re-read the tenant registration's signing at the `file:line` `tenant_registry_vector` in `rust/src/main.rs` cites.
4. Re-read the refused-token path at the `file:line` the comment on `UNAUTHORIZED_CODE` in `rust/src/rpc.rs` cites: its code and its
   messages are literals there, so a change reaches the vectors only through the harness.
5. Diff `crates/fiber-types/src/invoice.rs` and `schema/invoice.mol`, and read the `arcode` and `bech32` versions in fiber's own
   `Cargo.lock`: the harness pins both crates and ports fiber's two coder functions verbatim into `rust/src/invoice.rs`.
6. Regenerate the four vector files, then run `cargo test --release` and `pnpm test`.

A green suite means upstream did not move. A red derivation is the decision point: fiber changed its scheme, and existing
channels derived under the old one stay on it (`DERIVATION_SCHEME_VERSION` is additive only). A red RPC form, or a generation
that fails its coverage check, means the client's codecs follow the new forms; a flag a release adds to a state shows as a
diff in `channel_state_flags` and fails the interop spec until `RPC_CHANNEL_STATE_FLAGS` follows. A red invoice layer names
where the format moved; an attribute a release adds fails to compile in the harness until it is listed, and then fails the
TS reader, which refuses an item id it does not know.

## The invoice string

`vectors/invoice.json` holds `invoices`, each built from fixed values by fiber's `CkbInvoice`, signed with a fixed test key by
its `update_signature` and written by its `Display`, with the molecule, the compressed stream, the signed digest and the
signature beside the string: each attribute alone and all together, the three currencies, no amount and `u128::MAX`, signed
and unsigned, the hold, multi-path and tenant invoices as `new_invoice` shapes them, and data at the decoder's 16384-byte limit. The
harness writes each one again from its own parts and requires fiber's string, which pins its coder port. `coder` holds streams
compressed and decompressed past what an invoice reaches, `utf8` byte sequences with what `String::from_utf8` reads, and
`variants` 74 malformed or malleated strings, each with the verdict of fiber's signed-only decoder: `accepted`, `rewritten`
(read, but written back as another string), `refused` with its message, or `panicked`. The variants are generated, so every
verdict is fiber's and none is copied from a document. `test/tests/invoice/interop-vectors.spec.ts` holds the SDK to them,
and [`docs/invoice.md`](../docs/invoice.md) states the rule.

## Verifying the invoice strings

```bash
INTEROP_INVOICE_OUT=/tmp/ts-invoice-out.json pnpm test -- test/tests/invoice/interop-vectors.spec.ts
cd interop/rust
cargo run --release -- verify-invoices ../vectors/invoice.json /tmp/ts-invoice-out.json
```

`INTEROP_INVOICE_OUT` makes the spec write `{ "cases": [ { "name", "values", "signature", "string" } ] }`: every signed
invoice of the vectors encoded again by the SDK, and 64 invoices it generates from a fixed seed. `verify-invoices` requires the
vectors' strings unchanged and at least one string beyond them, and parses each string with fiber's decoder, which must read
the values the SDK wrote it from and write the string back unchanged. `cargo test --release` pins each of those outcomes, and
the interop workflow runs the verifier right after `pnpm test`.

## The signing requests

`vectors/signing.json` holds one channel between the device and a fiber node and, on it, one `SignatureRequired` request per
`ChannelSigningTransition`, each the result of `get_channel_signing_status` as `fiber-json-types` writes it:

- `device`: the SDK's master seed and the channel's index (a time of open in seconds), with the funding and TLC base public
  keys they derive. `peer`: the node's seed, a fiber `InMemorySigner`, and its keys. `channel`: the channel in the harness's
  own forms (bare hex, decimal strings): the terms a signer pins (the commitment fee rate, the peer's reserve, the liquid
  capacity `to_local + to_remote`), the commitment lock and the funding lock's cell deps, the two close scripts, the shutdown
  fee rates, and the three TLCs both commitments carry.
- `cases[]`: `name`, `transition`, `result` in fiber's JSON, and `expected`, bare hex: `key_order` (whose key `key_agg_ctx`
  aggregates first), `message`, the device's `public_nonce` and `partial_signature`, `next_material` for the slot's number
  plus one (the commitment point and the commitment and revocation nonces) on the four transitions that advance a
  commitment and `null` on the other two, and `signature`, the aggregated Schnorr signature, on `CompleteReceivedRevokeAndAck`
  alone, the one whose evidence the device keeps.
- `variants[]`: the `SendCommitmentSigned` result with `key_agg_ctx` or `agg_nonce` malformed, and the verdict of
  `fiber-lsp-sdk`'s `musig2_from_rpc` on it: `accepted`, or refused with its message. fiber's codec takes a context with the
  parity bit, a tweaked one and a three-key one as well formed: refusing them is the signer's job.

| Transition                     | Slot                    | Counter  | Key order         | Plaintext                                           | Peer's partial signature |
| ------------------------------ | ----------------------- | -------- | ----------------- | --------------------------------------------------- | ------------------------ |
| `SendCommitmentSigned`         | `Commitment` 4          | `Local`  | ascending         | commitment, lock args at 4, snapshot for the remote | no                       |
| `CompleteReceivedCommitment`   | `Commitment` 3          | `Local`  | ascending         | commitment, lock args at 2, snapshot for the local  | yes                      |
| `SendRevokeAndAck`             | `Revocation` 3          | `Remote` | `[remote, local]` | revocation of 2, paying the peer's close script     | no                       |
| `CompleteReceivedRevokeAndAck` | `Revocation` 4          | `Local`  | `[local, remote]` | revocation of 3, paying the device's close script   | yes                      |
| `SendClosingSigned`            | `Commitment` 5          | `Local`  | ascending         | closing transaction                                 | no                       |
| `SignChannelAnnouncement`      | `ChannelAnnouncement` 0 | none     | ascending         | unsigned announcement, molecule                     | no                       |

The slots, counters and key orders are those fiber's channel actor gives each transition, cited in `rust/src/signing.rs`: the
spends of the funding cell and the announcement sort the two funding keys ascending, each revocation keeps the role order of
the lock it revokes. Every case is a snapshot of its own; no two share a slot, so no two share a device nonce. With this
channel's keys the peer's funding key sorts first, so `SendRevokeAndAck`'s role order coincides with the ascending one, and
only `CompleteReceivedRevokeAndAck` puts the device first.

The device's nonce is the one the SDK's engine generates: BIP-327 `NonceGen` over the slot's nonce seed (`sdk_scheme`), with
the funding key, its public key and an empty extra input, under the context of the slot's purpose; a close signs under
`COMMITMENT` at its own number, fiber's nonce purposes having no close. The peer's nonce is the one a fiber node derives for
the slot, and `agg_nonce` is `AggNonce::sum` of the two. The settlement snapshot is fiber's `to_rpc_signing_settlement`, the
one port of the part (crates/fiber-lib/src/rpc/channel.rs:913-945): the balances with the reserves added and the pending TLCs
taken out, `inbound` relative to the device.

A case is written only after the generator has checked that fiber's `signing_message()` of its plaintext equals the digest
the `digest` section's builders give it; that the result, read back through `fiber-lsp-sdk`'s `musig2_from_rpc`,
`session_evidence_from_rpc` and `settlement_from_rpc`, returns what it was written from, and that fiber's
`settlement_matches_commitment_tx` reads the snapshot in the commitment's lock args; that the aggregated key is the revoked
lock's or the announced one; and that the device's and the peer's partial signatures verify and aggregate into a Schnorr
signature valid under the aggregated key.

## Verifying the signing requests

```bash
INTEROP_SIGNING_OUT=/tmp/ts-signing-out.json pnpm test -- test/tests/signer/interop-vectors.spec.ts
cd interop/rust
cargo run --release -- verify-signing ../vectors/signing.json /tmp/ts-signing-out.json
```

`INTEROP_SIGNING_OUT` makes `test/tests/signer/interop-vectors.spec.ts` write
`{ "cases": [ { "name": "<case>", "public_nonce": "<hex>", "partial_signature": "<hex>" } ] }`, bare hex: the device's half
of every case of `signing.json` as the SDK computes it, the announcement's included, which the dispatch refuses but the
engine still signs. Unset, the spec writes nothing. `verify-signing` requires every case once and no other; the public nonce
to be the device's half of the case's `agg_nonce`; fiber's musig2 crate to verify the partial signature (`verify_partial`);
and the two halves, the peer's taken from the request or signed by the harness with the peer's nonce, to aggregate into a
Schnorr signature valid under the case's aggregated key. `cargo test --release` pins each of those outcomes, and the interop
workflow runs the verifier right after `pnpm test`.

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
