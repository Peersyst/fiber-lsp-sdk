# Protocol

How the device reads a signing request. Fiber has two statuses, read by two decoders: the channel's, the `status` of
`get_channel_signing_status`, a musig2 session over one of six transitions; and the watchtower's, the `status` of
`get_watchtower_signing_status`, a spend of a force-closed commitment ([The watchtower's status](#the-watchtowers-status)).
The RPC client hands each on as the field it arrived in ([rpc.md](./rpc.md)), and the decoder turns it into a typed request
with every value in the one form fiber writes and every transition held to what it must carry. What the device then does
with the request, the key order, the aggregate nonce, the peer's signature and the message, is the dispatch of
[signing.md](./signing.md); the gate it passes is [policy.md](./policy.md); the message it rebuilds from the content is
[digest.md](./digest.md).

The protocol is fiber's, not the SDK's: the types are `fiber-json-types/src/channel.rs:650-870` and `:948-1027` at the
hosted-LSP PR, and nothing here proposes a form of its own.

## The status

The status is a union fiber tags with `type`:

- `NoSignatureRequired`, with no other member, decodes to `{ kind: "none" }`;
- `SignatureRequired` decodes to the request below.

| Member             | Form                                                                                        | Decoded                                                    |
| ------------------ | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `request_id`       | `Hash256`: `0x` and 64 lowercase hex digits                                                 | `requestId`, 32 bytes                                      |
| `transition`       | One of the six names of the rules table below                                               | `transition`                                               |
| `content`          | `Musig2SigningContent`: `slot`, `commitment_counter`, `key_agg_ctx`, `agg_nonce`, `content` | `slot`, `counter`, `keyAggregation`, `aggNonce`, `content` |
| `session_evidence` | `{ peer_public_nonce, peer_partial_signature }`                                             | `evidence`                                                 |
| `settlement`       | `SigningSettlement`, `null`, or absent                                                      | `settlement`, or `null`                                    |

`slot` is `{ purpose, commitment_number }`. The purpose is mapped onto the nonce context the device derives under
(`Commitment` to `COMMITMENT`, `Revocation` to `REVOKE`, `ChannelAnnouncement` to `ANNOUNCEMENT`): a cooperative close has no
purpose of its own and signs in the commitment slot of its number. The number is at most `2^48 - 2`, one below the
derivation's bound, because the answer publishes the material of the next number, which must still be derivable. The
announcement's slot is always `0`, as fiber's own `validate_nonce_slot` requires. `commitment_counter` is `Local` or `Remote`,
decoded to `"local"` or `"remote"`, and `null` only for the announcement.

## The forms

Exactly one form per value, the one fiber's serde writes; fiber's reader is laxer in places (it takes `0X`, uppercase digits,
or a missing prefix on bytes), the device is not, because a value with two spellings is two names for one thing.

| Fiber's type             | Form                                                                            | Where                                                          |
| ------------------------ | ------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `U64Hex`, `U128Hex`      | `0x` hex, lowercase, no leading zeros, within the width                         | slot number, TLC ids, numbers, amounts, expiries               |
| `Hash256`                | `0x` and exactly 32 bytes                                                       | `request_id`, `payment_hash`                                   |
| `Pubkey`                 | 33 bytes of lowercase hex **without** `0x`, on the curve                        | the settlement's four kinds of key                             |
| `SliceHex`               | `0x` hex of whole bytes                                                         | `key_agg_ctx`, `agg_nonce`, the nonce, the signature, the data |
| `EntityHex`              | `0x` hex of a molecule entity                                                   | the revocation's `output`                                      |
| CKB's JSON `Transaction` | `{ version, cell_deps, header_deps, inputs, outputs, outputs_data, witnesses }` | the two transaction contents                                   |
| `Option<T>`              | `null`; a missing member is refused                                             | `commitment_counter`, `peer_partial_signature`                 |

`settlement` is the one exception to the last row: fiber reads it with `serde(default)`, so an absent settlement is `null` to
fiber and to the device alike. Members the device does not know are ignored, so fiber can add one without breaking a device
already in the field; a member the device does not read is a member it does not sign.

## The contents

The content is a second union tagged with `type`, and each variant is the plaintext the device computes the message from
([digest.md](./digest.md)):

| `type`                        | Members                                                           | Decoded                                                          |
| ----------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------- |
| `CommitmentTransaction`       | `transaction`                                                     | `{ kind: "commitmentTx", transaction }`                          |
| `CooperativeCloseTransaction` | `transaction`                                                     | `{ kind: "closingTx", transaction }`                             |
| `Revocation`                  | `output` (molecule), `output_data`, `commitment_lock_script_args` | `{ kind: "revocation", output, outputData, commitmentLockArgs }` |
| `ChannelAnnouncement`         | `unsigned_announcement` (molecule, signatures zeroed)             | `{ kind: "announcement", unsignedAnnouncement }`                 |

The revocation's `output` is read by a canonical molecule decoder, so the cell output it yields serializes back to the bytes
the node hashed. Its `output_data` is kept as fiber hashes it: the molecule `Bytes`, its 4-byte length header included
(`0x00000000` for a CKB channel). The lock args are exactly 36 bytes, the revoked cell's key hash, delay and version. The
announcement bytes are kept whole; the dispatch refuses an announcement anyway, every channel of the SDK being private.

## The key aggregation and the nonces

`key_agg_ctx` is musig2 0.2.4's `KeyAggContext::to_bytes`: a header byte (bit 0 negates the aggregate's parity, bit 1
announces a 32-byte tweak that follows), a big-endian `u32` count, then the compressed keys in the order they were
aggregated. Fiber aggregates the two funding keys untweaked, so the device reads exactly that and nothing else: 71 bytes,
header `0x00`, count `2`, two points on the curve, distinct. It returns the two keys in their order; whether that order is
fiber's for the transition is the dispatch's check.

Fiber's own reader is musig2's `from_bytes`, which takes any context it can rebuild, and the vectors record its verdict on
each variant the device refuses:

| Variant                       | Fiber   | Device                     |
| ----------------------------- | ------- | -------------------------- |
| The parity bit set            | accepts | refuses: header            |
| The tweak bit without a tweak | refuses | refuses: header            |
| The tweak bit and its tweak   | accepts | refuses: 103 bytes, not 71 |
| A count of 3 and three keys   | accepts | refuses: 104 bytes, not 71 |
| A count of 3 and two keys     | refuses | refuses: count             |
| A key off the curve           | refuses | refuses: the key           |

The three fiber accepts are contexts it never writes for a channel: a parity flag and a tweak come from taproot tweaking,
which a funding lock does not use, and a third key is not a 2-of-2. Reading them would let a context aggregate to a key that
is not the funding cell's, and the device would only burn a slot on a signature nothing can spend with.

`agg_nonce` is musig2's `AggNonce`: 66 bytes, two compressed points, either of which may be at infinity, which musig2 and
BIP-327 write as 33 zero bytes. `session_evidence.peer_public_nonce` is the peer's own `PubNonce`, never at infinity, so both
of its halves must be points. `peer_partial_signature` is 32 bytes and a scalar below the curve order, as musig2's
`PartialSignature` reads it.

## The settlement

`SigningSettlement` is the public snapshot behind a commitment, untrusted until the commitment rebuilt from it hashes to the
transaction the node sent ([digest.md](./digest.md)):

| Member                                                  | Decoded                                                 |
| ------------------------------------------------------- | ------------------------------------------------------- |
| `local_amount`, `remote_amount` (u128)                  | `localAmountShannons`, `remoteAmountShannons`, `bigint` |
| `local_settlement_pubkey`, `remote_settlement_pubkey`   | `localSettlementPubkey`, `remoteSettlementPubkey`       |
| `for_remote`                                            | `forRemote`                                             |
| `tlcs`, at most 255 (the witness counts them in a byte) | `tlcs`                                                  |

Each TLC:

| Member                        | Decoded                                                       |
| ----------------------------- | ------------------------------------------------------------- |
| `tlc_id` (u64)                | `tlcId`, at most `Number.MAX_SAFE_INTEGER`                    |
| `local_key_commitment_number` | `localKeyCommitmentNumber`, at most `2^48 - 1`                |
| `inbound`                     | `direction`: `"received"` when inbound, `"offered"` otherwise |
| `payment_hash`                | `paymentHash`                                                 |
| `payment_amount` (u128)       | `amountShannons`                                              |
| `hash_algorithm`              | `hashAlgorithm`: `ckb_hash` to `ckb-hash`, `sha256`           |
| `expiry` (u64, milliseconds)  | `expiryMs`                                                    |
| `local_key_pubkey`            | `localKeyPubkey`                                              |
| `remote_key`                  | `remoteTlcPubkey`                                             |

`inbound` is relative to the device in both views, so the direction is too.

## The transition rules

What each transition must carry, as the node builds it and fiber's own device SDK checks it
(`fiber-lsp-sdk/src/lifecycle.rs:118-180`): the slot, counter and content of a revocation or a close
(`fiber-lib/src/fiber/channel.rs:7999-8018,9200-9213,10194-10216`), the peer's evidence (`:11040-11080`), the settlement
and the next material (`fiber-types/src/channel_signer.rs:348-358,380-388`). The decoder enforces every column but the last before anything
reads the content; `CHANNEL_SIGNING_RULES` is the table, and the dispatch reads its last column.

| Transition                     | Purpose               | Counter  | Content                       | Settlement          | Peer signature | Next material |
| ------------------------------ | --------------------- | -------- | ----------------------------- | ------------------- | -------------- | ------------- |
| `SendCommitmentSigned`         | `Commitment`          | `Local`  | `CommitmentTransaction`       | `for_remote: true`  | `null`         | yes           |
| `CompleteReceivedCommitment`   | `Commitment`          | `Local`  | `CommitmentTransaction`       | `for_remote: false` | required       | yes           |
| `SendRevokeAndAck`             | `Revocation`          | `Remote` | `Revocation`                  | `null`              | `null`         | yes           |
| `CompleteReceivedRevokeAndAck` | `Revocation`          | `Local`  | `Revocation`                  | `null`              | required       | yes           |
| `SendClosingSigned`            | `Commitment`          | `Local`  | `CooperativeCloseTransaction` | `null`              | `null`         | no            |
| `SignChannelAnnouncement`      | `ChannelAnnouncement` | `null`   | `ChannelAnnouncement`         | `null`              | `null`         | no            |

Fiber's device SDK verifies a peer signature where one is present on a sending transition; the node never writes one there,
so the device refuses it instead, and a settlement on a transition that builds no commitment likewise.

## The watchtower's status

`decodeWatchtowerSigningStatus` reads the second status, the same union under the same two tags, which the two decoders
share (`SIGNING_STATUS_TYPES`): `NoSignatureRequired` decodes to `{ kind: "none" }`, and `SignatureRequired` to the spend
the watchtower waits on:

| Member                | Form                                                            | Decoded                                                                    |
| --------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `request_id`          | `Hash256`                                                       | `requestId`, 32 bytes                                                      |
| `content.key_purpose` | `OnchainKeyPurpose`, tagged with `type`: `Settlement`, or `Tlc` | `purpose`: `{ kind: "settlement" }` or `{ kind: "tlc", commitmentNumber }` |
| `content.transaction` | CKB's JSON `Transaction`                                        | `transaction`                                                              |

`Tlc` carries `commitment_number`, a `U64Hex` at most `2^48 - 1`, the derivation's bound, decoded to the purpose's
`commitmentNumber`: the number of the TLC key the spend needs. A `type` of either union that fiber does not write is
refused. The request id is fiber's hash of the molecule transaction, and the decoder takes it as an opaque name: what the
device signs is the message it computes from the transaction ([signing.md](./signing.md)). The transaction is read as any
other, and judged by the watchtower's rules ([policy.md](./policy.md)).

## What a refusal looks like

Every refusal is a `ProtocolError`, code `malformed`, naming the field by its path from the field the decoder was given
(`response.result.status.content.slot.purpose`) and what it had to be (`must be Revocation for SendRevokeAndAck`). It never
names the value: a refusal reaches the host's logs, and a value can be a key. The decoder refuses at the first field that
fails, reading in the order of the wire: the envelope, the slot, the counter, the key aggregation, the aggregate nonce, the
content, the evidence, the settlement; inside the settlement and each TLC too, member by member as the tables above list
them, the view held to the transition where `for_remote` is read and the TLC count checked before any TLC. The
watchtower's decoder reads the envelope, the request id, the purpose and the transaction, in that order.

The decoder checks what a status says on its own. What needs the channel, its keys, its nonces, its pins, is the dispatch's:
that the keys are fiber's order of the channel's funding keys, that the aggregate is the device's nonce plus the peer's, that
the peer's signature verifies, that the message rebuilt from the content matches. Those refusals are `malformed` too, and
the codes beyond it are policy's ([signing.md](./signing.md), [policy.md](./policy.md)).

## Where it lives

| File                                        | Contents                                                                                                                                                   |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/protocol/protocol.constants.ts`        | The status types, the transitions, fiber's purposes and counters mapped to the SDK's, the content kinds, the rules table, the slot bound, the key purposes |
| `src/protocol/protocol.types.ts`            | The two statuses in their wire forms (`*Wire`), the rule, and the decoded requests                                                                         |
| `src/protocol/protocol.error.ts`            | `ProtocolError`: a wire refusal restated as `malformed`                                                                                                    |
| `src/protocol/channel-signing-status.ts`    | `decodeChannelSigningStatus`, the channel's entry point                                                                                                    |
| `src/protocol/watchtower-signing-status.ts` | `decodeWatchtowerSigningStatus`, the watchtower's                                                                                                          |
| `src/protocol/key-agg-context.ts`           | The `KeyAggContext` reader, kept out of the barrel                                                                                                         |
| `src/wire/`                                 | The forms of the table above, and the field reader whose paths the refusals are written in                                                                 |

Two of the wire readers exist for the channel's decoder: `readTagged`, which reads serde's internally tagged unions (the
statuses, the content and the key purpose) and narrows the members a variant can be read for, and
`decodeMoleculeCellOutput`, the strict molecule table reader behind `EntityHex`. The wire readers refuse with a
`WireError`; the entry point restates it as the `ProtocolError`.

## What the tests guarantee

- **Every case of the signing vectors decodes** into a typed request written out literally in the spec, one per transition,
  and into the key order the vectors name for it (`test/tests/protocol/interop-vectors.spec.ts`).
- **Every variant of the vectors is refused**, with fiber's verdict on it asserted next to the device's, so a regenerated
  vector that changes fiber's mind fails the spec.
- **A refusal per field and per form**, absent included, on every transition where the rules differ: a purpose, a counter,
  a content type, a settlement and a peer signature of another transition are each refused on each transition. Every bound
  is read at its last accepted value and refused at the first one past it: the slot at `2^48 - 2`, the TLC key number at
  `2^48 - 1`, the TLC id at `Number.MAX_SAFE_INTEGER`, the amounts and expiries at their widths, 255 TLCs, 36 bytes of lock
  args, the peer signature one below the curve order, an aggregate nonce half at infinity.
- **The `KeyAggContext` reader** on its own: every length, header, count and key it refuses, and both key orders.
- **The watchtower's status** (`test/tests/protocol/watchtower-signing-status.spec.ts`): both purposes read into the
  typed request, written out literally; every case of `rpc.json` and the status of every spend of `signing.json`'s
  `watchtower` section, which carry both purposes; a refusal per field, in each form and absent, the envelope, the request
  id, the purpose's tag and its number (absent, `null`, a number, bare, padded, uppercase, empty) read at `0` and at
  `2^48 - 1` and refused past it and past a u64, and the transaction field by field; and the refusal at the first field
  that fails, in the wire's order.

Coverage of the module is 100% on all four metrics, and the assertions were checked by breaking the code on purpose
(`test/tests/protocol`):

| Mutation                                              | Tests that failed |
| ----------------------------------------------------- | ----------------- |
| NoSignatureRequired is read as a request              | 181               |
| A refusal escapes as the wire's error                 | 158               |
| The counters are swapped                              | 132               |
| The key count is read little-endian                   | 130               |
| The rule's peer signature column is inverted          | 87                |
| A settlement key takes the 0x prefix                  | 50                |
| The revocation purpose maps to the commitment context | 37                |
| The sent revocation reads the local counter           | 14                |
| The keys come back swapped                            | 13                |
| The counter is not held to the transition             | 12                |
| The nonce halves are named in reverse                 | 10                |
| The close is a commitment content                     | 9                 |
| The content type is not held to the transition        | 7                 |
| The purpose is not held to the transition             | 7                 |
| The local settlement key reads the remote one         | 7                 |
| The remote amount reads the local one                 | 7                 |
| An absent settlement is not read as null              | 6                 |
| The key count is not checked                          | 6                 |
| The peer nonce halves are not checked                 | 6                 |
| A settlement key off the curve passes                 | 5                 |
| The key aggregation takes any longer length           | 5                 |
| The received commitment is the remote view            | 5                 |
| The request id takes any length                       | 5                 |
| The second key is not checked on the curve            | 5                 |
| The slot bound is the derivation's, not one below     | 5                 |
| A peer signature on a sending transition passes       | 4                 |
| A settlement on an unsettled transition passes        | 4                 |
| The TLC direction is inverted                         | 4                 |
| The aggregate nonce halves are not checked            | 4                 |
| The first key is not checked on the curve             | 4                 |
| An aggregate nonce half at infinity is refused        | 3                 |
| The parity bit passes the header check                | 3                 |
| The settlement's view is not held to the transition   | 3                 |
| A commitment without a settlement passes              | 2                 |
| A missing peer signature is refused only by its form  | 2                 |
| The TLC id bound is one lower                         | 2                 |
| The TLC key number bound is one lower                 | 2                 |
| The curve order itself is a valid signature           | 2                 |
| The revocation lock args take any length              | 2                 |
| A close decodes as a commitment content               | 1                 |
| A half with any zero byte reads as infinity           | 1                 |
| A protocol refusal is coded policy_refusal            | 1                 |
| The TLC amount is held to 64 bits                     | 1                 |
| The TLC cap is one lower                              | 1                 |
| The TLC expiry takes 128 bits                         | 1                 |
| The announcement slot may be any number               | 1                 |
| The local amount is held to 64 bits                   | 1                 |
| The same key twice passes                             | 1                 |
| The settlement is read before the evidence            | 1                 |
| The TLC list is read before the amounts               | 1                 |
| The view is checked after the TLC list is read        | 1                 |
| The TLCs are read before their count is checked       | 1                 |
| A TLC's inbound flag is read before its key number    | 1                 |
| A TLC's amount is read before its payment hash        | 1                 |

The refusal order was the one gap the sweep found: reading the settlement before the evidence failed no test, so a spec now
breaks every member of the wire at once and repairs them from the front, asserting the refusal at each step. A review found
the same gap one level down, the settlement read with its TLC count first and each TLC out of the wire's order, so two
more specs do the same over the settlement's members and over a TLC's, and a third refuses at the count an oversized list
whose TLCs would refuse too.

The watchtower's decoder, `decodeWatchtowerSigningStatus`, was broken the same way (`test/tests/protocol`, still 100% on all
four metrics):

| Mutation                                   | Tests that failed |
| ------------------------------------------ | ----------------- |
| The request id is read at 31 bytes         | 64                |
| A refusal escapes as the wire's error      | 55                |
| A TLC purpose is refused by its tag        | 41                |
| A settlement purpose is read as a TLC's    | 8                 |
| Any purpose tag reads as a TLC's           | 7                 |
| The TLC key number bound is one lower      | 4                 |
| NoSignatureRequired is read as a request   | 3                 |
| The TLC key number bound is one higher     | 3                 |
| The transaction is read before the purpose | 1                 |
| The content is read before the request id  | 1                 |

### The readers it relies on

The wire readers written for this decoder, swept against `test/tests/wire` (100% on all four metrics there):

| Mutation                                     | Tests that failed |
| -------------------------------------------- | ----------------- |
| The cell output reads four fields            | 78                |
| The capacity is read as a u32                | 68                |
| The type is refused under the lock's path    | 25                |
| The script fields are named in camelCase     | 20                |
| An empty type reads as a script              | 10                |
| The tag is not checked against the variants  | 10                |
| The offsets refusal is worded with a bound   | 10                |
| A broken header is worded as the field count | 3                 |

The strict molecule reader they share with the invoice codec, `src/common/utils/molecule-reader.utils.ts`, swept against
`test/tests/common`, at 100% on all four metrics:

| Mutation                                            | Tests that failed |
| --------------------------------------------------- | ----------------- |
| A u32 is read big-endian                            | 35                |
| A fixed value may be any length                     | 8                 |
| The field count is not checked                      | 5                 |
| An unknown hash type passes                         | 4                 |
| An empty table is refused                           | 3                 |
| Offsets out of order pass                           | 3                 |
| The size is not checked                             | 3                 |
| A union without an id is not refused by name        | 2                 |
| Bytes may be shorter than their length says         | 2                 |
| The field count reason drops its plural             | 2                 |
| The first offset may point past the end             | 2                 |
| A union id past the items reads as the first        | 1                 |
| The code hash is a view over the input              | 1                 |
| The first offset may be unaligned                   | 1                 |
| The first offset may point inside the header        | 1                 |
| The fixed size reason keeps its plural for one byte | 1                 |
| The integer is read big-endian                      | 1                 |
| The union id reason counts one more item            | 1                 |
