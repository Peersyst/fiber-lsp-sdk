# Digest reconstruction

The no-blind-signing half of the policy design: before the device signs a 32-byte message, the `digest` module rebuilds that
message from the channel state the node attached, so a signature can only ever bind what the device was actually shown. The
policy layer compares and refuses on mismatch ([policy.md](./policy.md)); this module only reconstructs. For what the
signature then does with the digest see [signing.md](./signing.md).

## Four constructions, not one

Fiber does not sign one kind of message. Each signing context rebuilds differently, ported from `nervosnetwork/fiber` @
`8db6a117`:

| Builder                            | Message                                                                                                 |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `computeCommitmentTxDigest`        | CKB blake2b-256 of the commitment tx's `RawTransaction`, cell deps emptied (`compute_tx_message`)       |
| `computeShutdownTxDigest`          | Same hash over the cooperative-close tx                                                                 |
| `computeRevocationDigest`          | blake2b-256 of a synthetic punishment output, its data, and the revoked cell's 36-byte lock args; no tx |
| `computeChannelAnnouncementDigest` | blake2b-256 of the molecule gossip announcement with its three signature fields zeroed                  |

All four are pure: typed inputs in, digest out. They throw `TypeError`/`RangeError` only for structurally impossible inputs
(wrong lengths, out-of-range amounts, fees no capacity covers); "digest does not match" is the policy layer's verdict, not
theirs. The commitment and the revocation also take the channel's lock layout (see "Two lock layouts" below): it shapes
the lock args, the settlement witness and the fee mock of the first, and the fee alone of the second.

## The input model: the device receives, it does not re-filter

TLC selection, settlement amounts, fee rates, close scripts and commitment points arrive as inputs. The device does not run
fiber's TLC state machine to derive them; it binds the signature to exactly what it was shown, and judging those values
(balance rule, monotonicity) is the policy record's job. The only parts recomputed from secrets are the device's own key
material: base key hashes and per-TLC keys, derived through the `derivation` module.

## Two key orderings

Fiber aggregates the two funding pubkeys in two different orders, and both appear here:

- **Sorted** (lexicographic byte compare): the shutdown tx's output order and the announcement's `ckb_key`. The node ids of
  the announcement are also sorted, so the caller's order never matters.
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
of the fixture channel, which exercises both branches of the sorted orderings against the same Rust digest.

## What the tests guarantee

Coverage of the module is 100% on all four metrics, and the assertions were checked by breaking the code on purpose:

| Mutation                                                                 | Tests that failed |
| ------------------------------------------------------------------------ | ----------------- |
| The mock size leaves out the block overhead                              | 45                |
| The witness count byte is left out                                       | 31                |
| The fee mock keeps 57 bytes of args under the full hash                  | 19                |
| The fee rounds up instead of truncating                                  | 18                |
| The TLC expiry is written in milliseconds                                | 14                |
| The TLC record binds the whole hash under legacy too                     | 14                |
| The lock args version is written little-endian                           | 13                |
| The commitment's capacity ignores the fee                                | 12                |
| The feature byte is left out under the full-hash layout                  | 10                |
| The feature byte is written as 0x00                                      | 10                |
| The TLC groups are ordered offered first on both variants                | 9                 |
| The TLC record binds the first 20 bytes under the full hash too          | 9                 |
| The TLCs are not sorted by id inside their group                         | 9                 |
| The direction bit is not flipped on the local variant                    | 6                 |
| The per-TLC key hashes keep one order on both variants                   | 5                 |
| The witness side blocks keep one order on both variants                  | 5                 |
| The revocation's fee ignores the layout                                  | 4                 |
| The lock args reader takes any length but 58 as legacy                   | 3                 |
| The revocation's args carry the trailing byte                            | 3                 |
| The shutdown outputs keep role order instead of the funding-pubkey sort  | 3                 |
| The commitment aggregates the funding keys in one order on both variants | 2                 |
| The lock args reader takes 58 bytes ending in 0x00 as the full hash      | 1                 |
