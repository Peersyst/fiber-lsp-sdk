# Digest reconstruction

The no-blind-signing half of the policy design: before the device signs a 32-byte message, the `digest` module rebuilds that
message from the channel state the node attached, so a signature can only ever bind what the device was actually shown. It
also computes the message of the plaintext the node sent, so the two can be compared. The policy layer compares and refuses
on mismatch ([policy.md](./policy.md)); this module only reconstructs. For what the signature then does with the digest see
[signing.md](./signing.md).

## Four messages, not one

Fiber does not sign one kind of message. Each signing context rebuilds differently, ported from `nervosnetwork/fiber` @
`8db6a117`:

| Builder                            | Message                                                                                                 |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `computeCommitmentTxDigest`        | CKB blake2b-256 of the commitment tx's `RawTransaction`, cell deps emptied (`compute_tx_message`)       |
| `computeClosingTxDigest`           | Same hash over the cooperative-close tx, rebuilt from what that tx states                               |
| `computeShutdownTxDigest`          | Same hash over the cooperative-close tx, rebuilt from the two fee rates                                 |
| `computeRevocationDigest`          | blake2b-256 of a synthetic punishment output, its data, and the revoked cell's 36-byte lock args; no tx |
| `computeChannelAnnouncementDigest` | blake2b-256 of the molecule gossip announcement with its three signature fields zeroed                  |

All of them are pure: typed inputs in, digest out. They throw `TypeError`/`RangeError` only for structurally impossible
inputs (wrong lengths, out-of-range amounts, fees no capacity covers); "digest does not match" is the policy layer's
verdict, not theirs. The commitment and the revocation also take the channel's lock layout (see "Two lock layouts" below):
it shapes the lock args, the settlement witness and the fee mock of the first, and the fee alone of the second. The closing
and the shutdown builders produce the same transaction (see "The cooperative close, from its tx").

## The input model: the device receives, it does not re-filter

TLC selection, settlement amounts, fee rates, close scripts and the peer's per-TLC keys arrive as inputs. The device does
not run fiber's TLC state machine to derive them; it binds the signature to exactly what it was shown, and judging those
values (balance rule, monotonicity) is the policy record's job. The only parts recomputed from secrets are the device's own
key material: base key hashes and per-TLC keys, derived through the `derivation` module.

## From fiber's snapshot to the commitment input

A commitment request carries fiber's `SigningSettlement` (`to_rpc_signing_settlement`, `rpc/channel.rs:915-947`) next to
the transaction. `settlementToCommitmentInput(keys, settlement, terms, commitmentNumber)` turns it into the
`CommitmentTxInput` the digest rebuilds, taking from `CommitmentSettlementTerms` what no snapshot states: the channel's pins
(out point, the peer's funding key, delay, layout, reserves, fee rate, liquid capacity) and the network's constants
(commitment lock, cell-dep count). The commitment number is the version the lock args carry (`readCommitmentLockVersion`).

- **Amounts.** The snapshot's `local_amount` and `remote_amount` are the settlement witness amounts: adjusted by the TLCs and,
  on a CKB channel, with each side's reserve already added (`build_settlement_data`, `channel.rs:11409-11530`). The
  converter takes the reserve back out, since `CommitmentTxInput` keeps the amounts before it; on a UDT channel fiber adds
  nothing and the amounts pass whole. An amount below its side's reserve cannot be one fiber wrote, and is refused.
- **Settlement keys.** Fiber settles on the TLC base keys (`get_settlement_keys`, `channel.rs:8621-8638`): the local one must
  be the device's TLC base pubkey, refused otherwise as fiber's own signer refuses it
  (`fiber-lsp-sdk/src/commitment.rs:319-325`). The remote one is the peer's TLC base key the witness binds, and the
  converter takes it as stated: the device derives no key to compare it with, so the check is the policy's, which pins it
  at the first signed commitment and refuses any other after ([policy.md](./policy.md)).
- **TLC keys.** Each TLC states the number its device key derives at (`local_key_commitment_number`) and that key
  (`local_key_pubkey`). The converter derives the key at the stated number and refuses the TLC unless it matches. More than
  255 TLCs are refused before any key is derived.
- **Direction and order.** `forRemote` comes from the snapshot, and the TLCs keep the snapshot's order: fiber's `inbound`
  is relative to the device in both views, so it maps onto `SettlementTlc.direction` with no flip. Fiber lists them in
  witness order, so the converted list can differ in order alone from the one the commitment was built from; the digest
  is the same, since the witness sorts the TLCs itself.

Every refusal is a `TypeError` or a `RangeError`, the errors the module throws for state that cannot exist, which the policy
maps to `malformed`.

## The liquid capacity

Fiber only ever reads the two channel balances summed: `to_local + to_remote` (`checked_liquid_capacity`,
`get_total_ckb_amount`, `channel.rs:7868-7906`) sizes the commitment output's capacity, and on a UDT channel it is the
output's data. A commitment and a revocation take that sum, `liquidCapacityShannons`, rather than the pair: the device pins
it at the opening, and it stays constant for the channel's life, since a TLC only moves value from one side to the other.
`ShutdownTxInput` keeps the pair, because a UDT close writes each side's amount into its own output.

## TLC keys as stated

The settlement witness hashes two keys per TLC (fiber's `get_tlc_keys`, `channel.rs:8588-8618`):

- the device's, derived from its TLC base key at the TLC's `localKeyCommitmentNumber` (the remote commitment number the TLC
  was created at), recomputed by the device;
- the peer's, which fiber derives from the peer's commitment point at the local number the TLC was created at. The device
  never sees the peer's commitment points, so `SettlementTlc.remoteTlcPubkey` carries the key as the node derived it, and
  the witness hashes it as given, a valid point being all it checks.

## Two key orderings

Fiber aggregates the two funding pubkeys in two different orders, and both appear here:

- **Sorted** (lexicographic byte compare): the cooperative close's output order and the announcement's `ckb_key`. The node
  ids of the announcement are also sorted, so the caller's order never matters.
- **Role order** (`forRemote ? [local, remote] : [remote, local]`): the x-only key hashed into commitment and revocation
  lock args, which must equal the key baked into the cell being spent or punished.

The signing engine itself never orders keys (see [signing.md](./signing.md)); these orderings exist only inside the
reconstructed bytes.

## Fees are part of the digest

The output capacities subtract a fee computed over a **mock** transaction (fiber's `commitment_tx_size` /
`shutdown_tx_size`): zeroed cell deps, a zeroed input, placeholder outputs, one 112-byte zeroed witness, measured as
serialized size plus 4. The commitment mock's output carries the commitment lock with its args zeroed at the layout's
length (`COMMITMENT_LOCK_ARGS_LENGTHS`, 57 or 58 bytes, fiber's `lock_args_len`), so the commitment fee, and with it the
revocation's, is one byte's worth larger under `fullPaymentHash`. The mock's cell-dep count is an input (it depends on the
node's contract config), the division truncates, and one shannon of divergence changes the digest, so the mock is rebuilt
byte for byte with the same molecule serializer rather than approximated.

The cell-dep count is fiber's `get_cell_deps_count(vec![FundingLock], udt)` (`fee.rs:27-35`): the funding lock's deps,
plus the UDT's on a UDT channel. No transaction states it, since the digest blanks the deps, so it is a network constant:
`fundingLockCellDepsCount` is 2 on the mainnet and testnet presets, and a dev network declares its own
([sdk.md](./sdk.md)), as fiber's own signer reads it from the network (`fiber-lsp-sdk/src/opening.rs:24`).

The two fees are exported on their own, `calculateCommitmentTxFee` (a commitment and a revocation take the same one) and
`calculateShutdownTxFee` (one side's), because the policy bounds them: the digest binds the signature to whatever fee the
node's rate produces, and judging how large it may be is the gate's ([policy.md](./policy.md)).

## Two lock layouts

Fiber's `CommitmentContractFeatures` gives the commitment lock two layouts, named here `CommitmentLockLayout`:

- `legacy`: the 57-byte lock args (key hash, delay, version, settlement hash, a trailing zero), and each TLC record of the
  settlement witness binds the first 20 bytes of its payment hash, an 85-byte record.
- `fullPaymentHash`: the feature byte `0x01` (`ONCHAIN_FULL_PAYMENT_HASH`) appended as a 58th byte, and each record binds
  the whole 32-byte hash, 97 bytes.

The fee mock follows the args (see "Fees are part of the digest"), so a commitment and a revocation under the two layouts
digest apart even on equal inputs. Nothing else moves: the revocation's 36-byte args carry no feature byte, the close mock
sizes over the close scripts, and the announcement has no fee.

`CommitmentTxInput` and `RevocationInput` carry the layout as a required `lockLayout`. Neither the channel's opening
context nor a settlement states it, so it is read from the args of the commitment lock the node attaches, with
`readCommitmentLockLayout`, the port of fiber's `from_lock_args`: 57 bytes is `legacy`, 58 ending in `0x01` is
`fullPaymentHash`, anything else is refused. Fiber also reads 58 bytes ending in `0x00` as `legacy` but never writes them,
and the device rebuilds the args itself, so the strict reader leaves nothing signable out. Which layout a channel stays on
is the policy's pin ([policy.md](./policy.md)).

Two more readers take the fields fiber reads out of the args, written by `channel.rs:11352-11357` and read back by its
device SDK (`fiber-lsp-sdk/src/commitment.rs:623,641-645`) and its watchtower (`watchtower/actor.rs:1267-1269`):
`readCommitmentLockDelay` (bytes 20 to 28, the little-endian since of a relative epoch delay, returned with its `0xa0` flags
stripped, any other flags refused) and `readCommitmentLockVersion` (bytes 28 to 36, the big-endian commitment number,
refused above `MAX_COMMITMENT_NUMBER`). Both take the 57 and 58 bytes of a commitment lock and the 36 bytes a revocation
signs, which are their prefix, and refuse any other length; the layout is `readCommitmentLockLayout`'s to check.

## The cooperative close, from its tx

A close request carries the transaction but not the two fee rates it was built from, so `ShutdownTxInput` cannot be filled
from it. `ClosingTxInput` instead takes what the tx states: the funding out point, the two close scripts and the two output
capacities, and `computeClosingTxDigest` rebuilds fiber's `build_shutdown_tx` (`channel.rs:11175-11308`) from them: one
input, no cell deps, and the two outputs in the funding-pubkey order (`order_things_for_musig2`, local first when its key
sorts first), each with empty data. Judging the capacities, the local one against the channel's exposure, is the policy's
([policy.md](./policy.md)).

`readClosingTx(keys, remoteFundingPubkey, tx)` reads that input out of the node's tx: the out point of its single input, and
each side's script and capacity by the same funding-pubkey order. It refuses a tx with other than one input and two outputs,
or an output with a type script, and leaves the rest (cell deps, data, witnesses) to the digest comparison. The order alone
says which output is whose, so a tx with the two swapped reads as the peer's script on the device's side, and the digest
still matches: the policy's check that the local output pays to the pinned close script is what refuses it.

`ClosingTxInput` is CKB only, as the channel pins are. `computeShutdownTxDigest` computes the two capacities from the rates
and hands them to the same builder, adding the UDT's type script and each side's amount as data on a UDT channel, so the
shutdown vectors, UDT case included, pin the closing construction too.

## The message of what the node sent

The other half of the comparison: fiber's `Musig2SignableContent::signing_message` (`fiber-types/src/channel_signer.rs:102-121`)
over the plaintext a request carries.

- `computeTxMessage(tx)` is `compute_tx_message` (`channel_signer.rs:650-662`): the molecule `RawTransaction` with its cell
  deps emptied, hashed, so a script upgrade that moves the deps never invalidates a signature. The witnesses never reach it
  either. Every transaction construction above ends in it, so the rebuilt digest and the message of the node's tx come out
  of one serializer.
- `computeRevocationContentMessage(output, outputData, args)` is the revocation's: the blake2b of the molecule `CellOutput`,
  the output data and the revoked cell's args, concatenated in that order. Fiber hands over the data as the molecule `Bytes`
  slice, its 4-byte length header included (`channel.rs:7999-8003`), and the function hashes it as given;
  `computeRevocationDigest` wraps the data it rebuilds the same way.

The message is not the transaction's on-chain hash: the transaction fiber broadcasts adds the funding lock's cell deps back
(`get_latest_commitment_transaction`, `channel.rs:11567-11581`).

## The content before its message

Three constructions are exported beside their digests, so the content a message is computed over can be built on its own:

- `buildCommitmentTx(keys, input)`, the tx of fiber's `build_commitment_tx_and_settlement_data`: the funding cell into the
  commitment cell, unsigned and without cell deps. `computeCommitmentTxDigest` is `computeTxMessage` over it.
- `buildClosingTx(keys, input, udt)`, the cooperative close of `build_shutdown_tx`, with the UDT's type script and each
  side's amount or `null` on a CKB channel. Both close digests are `computeTxMessage` over it.
- `buildRevocationContent(keys, input)`, fiber's `Musig2SignableContent::Revocation`: the punishment `output`, its
  `outputData` as the molecule `Bytes` the message hashes, header included, and the revoked cell's 36 bytes of args,
  `commitmentLockArgs`, fiber's `commitment_lock_script_args` under the name the protocol codecs read them by.
  `computeRevocationDigest` is `computeRevocationContentMessage` over the three.

None of them is in the barrel's list: the SDK only ever needs their messages. The tests' node double, which sends the
device the content fiber would, imports them by file, as the module's specs do.

## Network pinning

The commitment lock's code hash decides which script guards the funds after a force close, and on mainnet and testnet it
comes from fiber's shipped node config, not from the chain. The SDK therefore pins both as constants
(`COMMITMENT_LOCK_MAINNET`, `COMMITMENT_LOCK_TESTNET`) and never accepts them from the node: a node able to choose the code
hash could redirect the commitment output and still pass the digest check. Dev chains pass an explicit template instead.

## Molecule, from scratch

The reconstruction needs CKB's molecule serialization (tables, fixed and dynamic vectors, options) for exactly seven
blockchain types plus the gossip announcement table. The SDK implements that subset rather than adding a dependency: the
runtime dependency set is a hard constraint, and the full molecule machinery is far larger than the fragment needed. The
writers of the primitives (integers, tables, vectors, `Bytes`, `Script`) live in `common`, since the invoice module writes
the same ones ([invoice.md](./invoice.md)); the transaction serializers stay in `utils/molecule.utils.ts`. The layout is pinned
by unit fixtures and, end to end, by the interop vectors.

## What the vectors guarantee

The `digest` section of [`interop/vectors/vectors.json`](../interop/README.md) is generated by Rust ports of the same fiber
functions, serialized with CKB's own `ckb-types` (and the announcement built by `fiber-types` itself, pinned to the
reference commit). Every case carries its intermediates (settlement witness, lock args, mock size, fee) besides the final
digest, so a divergence points at the exact stage that moved; the commitment and revocation cases also carry their lock
layout, and cover both layouts by name. The suite also recomputes each shutdown and announcement case from the peer's side
of the fixture channel, which exercises both branches of the sorted orderings against the same Rust digest, rebuilds each
CKB close from what its tx states, and each commitment from the settlement snapshot fiber's `to_rpc_signing_settlement`
writes for it, through the converter. The builders are pinned to fiber's constructions themselves, not only to their
digests (`test/tests/digest/interop-vectors.spec.ts`): the tx of each of the nine commitment cases and of the CKB close,
and the output, data and args of each of the three revocations, come out equal to the ones the vectors carry.

## What the tests guarantee

Coverage of the module is 100% on all four metrics. The transaction and revocation messages are also pinned by hand
fixtures whose digests were computed apart from the SDK, over hand-written molecule bytes. The assertions were checked by
breaking the code on purpose:

| Mutation                                                                 | Tests that failed |
| ------------------------------------------------------------------------ | ----------------- |
| The local settlement key is held to the funding key                      | 54                |
| The mock size leaves out the block overhead                              | 45                |
| The witness count byte is left out                                       | 31                |
| The delay sits one byte later                                            | 31                |
| A snapshot TLC key is checked one number up                              | 27                |
| The cell's reserve leaves the peer's out                                 | 26                |
| The delay is read big-endian                                             | 24                |
| The witness derives the device's TLC key one number up                   | 22                |
| The witness hashes the device's TLC key for the peer's                   | 21                |
| A CKB cell leaves the reserves out                                       | 20                |
| The fee mock keeps 57 bytes of args under the full hash                  | 19                |
| The fee rounds up instead of truncating                                  | 18                |
| The delay keeps its flags                                                | 18                |
| The cell deps reach the message                                          | 16                |
| The version is read little-endian                                        | 16                |
| The TLC expiry is written in milliseconds                                | 14                |
| The TLC record binds the whole hash under legacy too                     | 14                |
| The lock args version is written little-endian                           | 13                |
| The commitment's capacity ignores the fee                                | 12                |
| The input's version is one up                                            | 11                |
| The snapshot's view is inverted                                          | 11                |
| The peer's TLC base key is the device's                                  | 11                |
| The revocation content's args leave out the revoked number               | 11                |
| A CKB snapshot keeps the reserves                                        | 10                |
| The feature byte is left out under the full-hash layout                  | 10                |
| The feature byte is written as 0x00                                      | 10                |
| The args reader takes any length                                         | 10                |
| The input's cell dep count is one up                                     | 10                |
| The commitment tx carries a witness the message leaves out               | 10                |
| The remote amount loses the local reserve                                | 9                 |
| The TLC groups are ordered offered first on both variants                | 9                 |
| The TLC record binds the first 20 bytes under the full hash too          | 9                 |
| The TLCs are not sorted by id inside their group                         | 9                 |
| The revocation content's data loses its molecule header                  | 9                 |
| A UDT cell counts its liquid amount as capacity                          | 8                 |
| A snapshot TLC is always offered                                         | 7                 |
| A snapshot TLC's peer key is the device's                                | 7                 |
| The args reader refuses a revocation's 36 bytes                          | 7                 |
| The outputs data are hashed in reverse                                   | 7                 |
| The revocation content hashes the args before the data                   | 7                 |
| The revocation content leaves out the data                               | 7                 |
| The commitment tx's output drops the UDT type                            | 7                 |
| The direction bit is not flipped on the local variant                    | 6                 |
| A UDT cell writes no amount                                              | 6                 |
| A close's outputs are read in reverse                                    | 6                 |
| A delay with any flags passes                                            | 6                 |
| The local amount is not bounded                                          | 6                 |
| The remote amount is not bounded                                         | 6                 |
| The revocation content names its args lockArgs                           | 6                 |
| The per-TLC key hashes keep one order on both variants                   | 5                 |
| The witness side blocks keep one order on both variants                  | 5                 |
| The revocation's fee ignores the layout                                  | 4                 |
| A close's remote capacity is the local one                               | 4                 |
| A close's remote script is the local one                                 | 4                 |
| A snapshot TLC key is not checked                                        | 4                 |
| The header deps are emptied too                                          | 4                 |
| A UDT snapshot loses the reserves                                        | 4                 |
| The lock args reader takes any length but 58 as legacy                   | 3                 |
| The revocation's args carry the trailing byte                            | 3                 |
| The shutdown outputs keep role order instead of the funding-pubkey sort  | 3                 |
| A typed close output is read                                             | 3                 |
| The version bound refuses its own edge                                   | 3                 |
| A reserve is not bounded                                                 | 3                 |
| The commitment aggregates the funding keys in one order on both variants | 2                 |
| A close's out point is not checked                                       | 2                 |
| A close's outputs are read in tx order                                   | 2                 |
| A message output's capacity takes 128 bits                               | 2                 |
| A message output's type is not checked                                   | 2                 |
| The local settlement key is not checked                                  | 2                 |
| A cell's total capacity may pass a u64 by one                            | 2                 |
| The close's funding out point is left to the message to check            | 2                 |
| The lock args reader takes 58 bytes ending in 0x00 as the full hash      | 1                 |
| A close output is not checked to be an object                            | 1                 |
| A close with more inputs is read                                         | 1                 |
| A close with more outputs is read                                        | 1                 |
| A tx list is not checked to be an array                                  | 1                 |
| An amount below its reserve is taken                                     | 1                 |
| An amount equal to its reserve is refused                                | 1                 |
| An input's since is not bounded                                          | 1                 |
| The commitment's liquid capacity is not bounded                          | 1                 |
| The peer's TLC key is not checked on the curve                           | 1                 |
| The revocation's liquid capacity is not bounded                          | 1                 |
| The settlement's TLC cap is one lower                                    | 1                 |
| The version is not bounded                                               | 1                 |
| A header dep is left to the serializer to check                          | 1                 |
| A header dep is named without the transaction's path                     | 1                 |
| The commitment's funding out point is left to the message to check       | 1                 |
