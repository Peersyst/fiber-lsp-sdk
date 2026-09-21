# Protocol

The wire between the device and the LSP's signer bridge: what a frame looks like, how every value is spelled, and what a frame
that does not decode is answered with. The gate the decoded requests then pass is [policy.md](./policy.md); the inputs the
operation objects carry are the typed structs of [digest.md](./digest.md); the signature at the end is
[signing.md](./signing.md).

## Status: a proposal

Protocol v1 is co-designed with the Fiber team, and this document is the artifact that review works on. Nothing here is
frozen. Everything the review may rename lives in the codecs (`src/protocol`, with the value forms in `src/wire`), so a
rename stays local: the compiler carries it from the wire type to its decoder. Everything the review may reshape is called
out below as a position taken, not a decision. Until the wire freezes, the tests pin no wire fixtures: a pin would only
catch the change the review is expected to make. They are pinned with the freeze, the way the stored record format is
pinned today ([persistence.md](./persistence.md)).

## Encodings

Every frame is one JSON text message with a `type` field. Binary frames are refused. Names are snake_case. Values follow
fiber's own JSON conventions wherever fiber has one, with exactly one accepted form per value:

| Value                       | Form                                                                                                              | Example                                           |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Bytes, public keys included | `0x`-prefixed lowercase hex of an exact length                                                                    | `0x02ab…` (33 bytes)                              |
| Integers                    | `0x` hex without leading zeros, fiber's `U64Hex` and `U128Hex`: `state_version` and every integer inside `params` | `0x0`, `0xff`, `0xe6f8b1600`                      |
| The two session numbers     | A JSON number, and only for `protocol_version` and `pending_requests`                                             | `1`, `3`                                          |
| Scripts                     | CKB's JSON shape: `{code_hash, hash_type, args}`, `args` of any length                                            | `hash_type` is `data`, `type`, `data1` or `data2` |
| Outpoints                   | CKB's JSON shape: `{tx_hash, index}`, the index a u32 in hex                                                      | `{tx_hash: "0x…", index: "0x0"}`                  |
| An absent option            | `null`, never a missing field                                                                                     | `udt_type_script: null`                           |
| Enumerations                | snake_case, fiber's own spelling where fiber has one                                                              | `ckb_hash` (fiber's), `offered` (this protocol's) |

The one form per value is strict on purpose: uppercase hex, a missing `0x`, a leading zero in an integer, or a public key
without its prefix are all refused. A value with two accepted spellings would be two aliases for one channel or two keys for
one hash. Fields the device does not know are ignored, so the wire can grow additively without breaking devices already in
the field; a field the device does not read is a field it does not sign, so ignoring it is also safe.

Three strings carry no length bound, on purpose: a script's `args`, whose length the lock defines, and the `code` and
`message` of an `error` frame, which the device only reports to the host. None of them enters a signature except through
the digest reconstruction, which binds the signature to what the device rebuilt. Every other string is bounded, the
`request_id` included, so that no field can carry a payload.

An integer the SDK keeps as a JavaScript number rather than a `bigint` is bounded below its wire width, as the field tables
give, and a value beyond the bound is refused rather than rounded.

## Session frames

| Direction | Frame                                                                                                          | Notes                                                                                                                                                       |
| --------- | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| bridge    | `{type: "challenge", challenge}`                                                                               | Random, sent right after the socket opens                                                                                                                   |
| device    | `{type: "signed_challenge", protocol_version, public_key, signature}`                                          | BIP-340 over `ckbBlake2b("fiber-lsp-sdk session challenge v1" ‖ challenge)` with the wallet identity key, whose public half the bridge pins across sessions |
| bridge    | `{type: "session_established", protocol_version, pending_requests}`                                            | Resume point: the count is informational, the drain is ordinary delivery                                                                                    |
| either    | `{type: "ping"}` / `{type: "pong"}`                                                                            | App-level heartbeat, device-driven; a bridge may also ping and the device answers `pong`                                                                    |
| device    | `{type: "register_channel", request_id, funding_pubkey, tlc_base_pubkey, local_settlement_key}`                | The channel-open handshake: the base public keys plus the delegated settlement key, nothing derived by number (below)                                       |
| bridge    | `{type: "channel_registered", request_id, channel_id}`                                                         | The node names the channel: the temporary id it will use in `OpenChannel`, which the device files as the channel's first name                               |
| bridge    | `{type: "error", request_id, code, message}`                                                                   | Failure of a device-initiated request; the codes are the bridge's to define                                                                                 |
| bridge    | `{type: "sign_request", request_id, channel_id, method, params, state_version}`                                | Below                                                                                                                                                       |
| device    | `{type: "sign_response", request_id, result}` or `{type: "sign_response", request_id, error: {code, message}}` | `code` is one of the four of [policy.md](./policy.md)                                                                                                       |

| Field                               | Frames                                                                             | Form                                                  |
| ----------------------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `challenge`                         | `challenge`                                                                        | 32 bytes                                              |
| `protocol_version`                  | `signed_challenge`, `session_established`                                          | JSON number                                           |
| `public_key`                        | `signed_challenge`                                                                 | 32 bytes, the x-only identity key                     |
| `signature`                         | `signed_challenge`                                                                 | 64 bytes                                              |
| `pending_requests`                  | `session_established`                                                              | JSON number                                           |
| `request_id`                        | `register_channel`, `channel_registered`, `error`, `sign_request`, `sign_response` | String of 1 to 64 printable ASCII characters          |
| `funding_pubkey`, `tlc_base_pubkey` | `register_channel`                                                                 | 33 bytes                                              |
| `local_settlement_key`              | `register_channel`                                                                 | 32 bytes, a private key                               |
| `channel_id`                        | `channel_registered`, `sign_request`                                               | 32 bytes, fiber's `Hash256`                           |
| `code`, `message`                   | `error`                                                                            | Strings, `code` not empty                             |
| `method`, `params`                  | `sign_request`                                                                     | One of the ten methods, and its params object (below) |
| `state_version`                     | `sign_request`                                                                     | `U64Hex`, at most `2^53 − 1`                          |
| `result`                            | `sign_response`                                                                    | The method's result object (below)                    |

`request_id` is opaque and echoed verbatim. It is ASCII so that a character and a byte count the same on both ends, and a
`U64Hex` fits as well as any other printable id. Device-initiated requests use their own ids, and the two namespaces never
mix because each direction correlates its own. The device keeps a `channel_id` in its wire form, as the name the policy
record is aliased by ([persistence.md](./persistence.md)).

The signed challenge is domain-separated so the identity key never signs a bare 32-byte digest the bridge chose; the bridge
computes the same hash to verify. `ckbBlake2b` is CKB's blake2b-256, personalized with `ckb-default-hash`, over the label's
UTF-8 bytes followed by the 32 challenge bytes; `sessionChallengeDigest` is that hash, and the device side that signs it is
the wallet identity of [signing.md](./signing.md). Whether `protocol_version` in `session_established` matches the device's
own is the session's decision, not a decode refusal: the codec reads any version.

The bridge has no frame to refuse a handshake with, so the device reads it from the socket: a close after the signature
went out and before `session_established` is a refused handshake, on which the device does not reconnect, while a close
before the challenge is answered, or after a signature the socket would not take, is a lost socket, on which it does
([session.md](./session.md)). When the device closes a socket itself it does so with code `1000`, the one code a browser
lets a client send outside the private range, and a reason string that says why: `disconnect`, `connect timeout`,
`heartbeat timeout`, `protocol violation`, `protocol version mismatch`, `authentication failed` or `send failed`. During
establishment a frame that does not decode or arrives out of the sequence ends the session; once established it is
dropped and reported, and the session goes on.

**Position taken**: the handshake carries no public data at all, only the base public keys and the delegated settlement
key. The node fetches commitment points and public nonces by number through the public-data methods, which it needs for
every later round anyway. The alternative, points and nonces inline in the registration, would make the device encode
numbers that are fiber's own bookkeeping, one of which is hardcoded upstream and may move between releases.

## Sign requests

| Method                               | `params`                                            | `result`                                    |
| ------------------------------------ | --------------------------------------------------- | ------------------------------------------- |
| `get_base_public_keys`               | `{}`                                                | `{funding_pubkey, tlc_base_pubkey}`         |
| `get_commitment_point`               | `{commitment_number}`                               | `{commitment_point}`                        |
| `get_commitment_pub_nonce`           | `{commitment_number}`                               | `{pub_nonce}`                               |
| `get_revocation_pub_nonce`           | `{commitment_number}`                               | `{pub_nonce}`                               |
| `get_channel_announcement_pub_nonce` | `{}`                                                | `{pub_nonce}`                               |
| `get_settlement_keys`                | `{commitment_number}`                               | `{local_settlement_key, tlc_key}` (private) |
| `partial_sign_commitment_tx`         | `{session, nonce_commitment_number, commitment_tx}` | `{partial_signature}`                       |
| `partial_sign_closing_tx`            | `{session, nonce_commitment_number, shutdown_tx}`   | `{partial_signature}`                       |
| `partial_sign_revocation`            | `{session, nonce_commitment_number, revocation}`    | `{partial_signature}`                       |
| `partial_sign_channel_announcement`  | `{session, channel_announcement}`                   | `{partial_signature}`                       |

| Field                                                   | Form                         |
| ------------------------------------------------------- | ---------------------------- |
| `commitment_number`, `nonce_commitment_number`          | `U64Hex`, at most `2^48 − 1` |
| `session.ordered_pubkeys`                               | Exactly two 33-byte keys     |
| `session.aggregated_nonce`                              | 66 bytes                     |
| `session.message`                                       | 32 bytes                     |
| `funding_pubkey`, `tlc_base_pubkey`, `commitment_point` | 33 bytes                     |
| `pub_nonce`                                             | 66 bytes                     |
| `local_settlement_key`, `tlc_key`                       | 32 bytes each, private keys  |
| `partial_signature`                                     | 32 bytes                     |

`session` is `{ordered_pubkeys, aggregated_nonce, message}`: the key list exactly as the node aggregates it, which the
engine never sorts, the aggregated public nonce, and the message to sign. `nonce_commitment_number` is the number the
device's nonce is derived at, named apart from any number inside the operation because the two differ: a commitment tx
versions its lock with the local or the remote number depending on its direction, and a revocation signs at the current
remote number while its message commits to the one before. The announcement carries no nonce number, since its slot is
fixed ([policy.md](./policy.md)); one sent anyway is ignored. `get_settlement_keys` is the one method whose result is
private material, the scoped keys a watchtower settles with, and it never includes the funding key.

Once its params decode, every request resolves its channel before anything is derived, the public-data ones included: an
unregistered `channel_id` is `unknown_channel` whatever the method, since there are no keys to derive without an index. A
signing request decodes into exactly the policy engine's input, so the dispatch passes it through untouched, and the digest
is then rebuilt from the operation object and compared with `message` before anything is signed.

## Operation objects

Each operation object is the wire form of one typed input of the `digest` module, field for field. Nothing is added and
nothing is dropped except the network-pinned commitment lock, which the device supplies from its own preset and never reads
from the wire ([digest.md](./digest.md)): a `commitment_lock` on the wire is ignored.

### `commitment_tx`

| Field                                   | Typed input                                             | Form                         |
| --------------------------------------- | ------------------------------------------------------- | ---------------------------- |
| `for_remote`                            | `forRemote`                                             | boolean                      |
| `funding_out_point`                     | `fundingOutPoint`                                       | outpoint                     |
| `remote_funding_pubkey`                 | `remoteFundingPubkey`                                   | 33 bytes                     |
| `remote_tlc_base_pubkey`                | `remoteTlcBasePubkey`                                   | 33 bytes                     |
| `commitment_number`                     | `commitmentNumber`                                      | `U64Hex`, at most `2^48 − 1` |
| `commitment_delay_epoch`                | `commitmentDelayEpoch`                                  | `U64Hex`                     |
| `commitment_fee_rate`                   | `commitmentFeeRate`                                     | `U64Hex`                     |
| `cell_deps_count`                       | `cellDepsCount`                                         | `U64Hex`, at most `255`      |
| `udt_type_script`                       | `udtTypeScript`                                         | script or `null`             |
| `to_local`, `to_remote`                 | `toLocalShannons`, `toRemoteShannons`                   | `U128Hex`                    |
| `settlement_local`, `settlement_remote` | `settlementLocalShannons`, `settlementRemoteShannons`   | `U128Hex`                    |
| `local_reserved`, `remote_reserved`     | `localReservedCkbShannons`, `remoteReservedCkbShannons` | `U64Hex`                     |
| `tlcs`                                  | `tlcs`                                                  | array of at most 255, below  |

| `tlcs[]` field                        | Typed input                       | Form                         |
| ------------------------------------- | --------------------------------- | ---------------------------- |
| `id`                                  | `id`                              | `U64Hex`, at most `2^53 − 1` |
| `direction`                           | `direction`                       | `offered` or `received`      |
| `hash_algorithm`                      | `hashAlgorithm`                   | `ckb_hash` or `sha256`       |
| `amount`                              | `amountShannons`                  | `U128Hex`                    |
| `payment_hash`                        | `paymentHash`                     | 32 bytes                     |
| `expiry_ms`                           | `expiryMs`                        | `U64Hex`                     |
| `created_at_remote_commitment_number` | `createdAtRemoteCommitmentNumber` | `U64Hex`, at most `2^48 − 1` |
| `remote_commitment_point`             | `remoteCommitmentPoint`           | 33 bytes                     |

**Position taken**: a TLC's id and its direction are two fields here, where fiber has one. Fiber's `TLCId` is an externally
tagged enum, `{"Offered": "0x1"}`, and its `SettlementTlc` spells the amount `payment_amount` and the expiry `expiry`. The
device reads a TLC only to rebuild a settlement witness whose flag byte is a function of the direction, so splitting the two
keeps every decoder a field-for-field image of its typed input and every refusal keyed to one field. The cost is that a
bridge cannot forward fiber's own `SettlementTlc` untouched, which is the trade the review should settle. The same question
covers the names: `offered` and `received` are this protocol's spelling, not fiber's, while `ckb_hash` and `sha256` are
fiber's `HashAlgorithm` verbatim.

### `shutdown_tx`

| Field                               | Typed input                                             | Form                    |
| ----------------------------------- | ------------------------------------------------------- | ----------------------- |
| `funding_out_point`                 | `fundingOutPoint`                                       | outpoint                |
| `remote_funding_pubkey`             | `remoteFundingPubkey`                                   | 33 bytes                |
| `local_close_script`                | `localCloseScript`                                      | script                  |
| `remote_close_script`               | `remoteCloseScript`                                     | script                  |
| `local_fee_rate`, `remote_fee_rate` | `localFeeRate`, `remoteFeeRate`                         | `U64Hex`                |
| `cell_deps_count`                   | `cellDepsCount`                                         | `U64Hex`, at most `255` |
| `udt_type_script`                   | `udtTypeScript`                                         | script or `null`        |
| `to_local`, `to_remote`             | `toLocalShannons`, `toRemoteShannons`                   | `U128Hex`               |
| `local_reserved`, `remote_reserved` | `localReservedCkbShannons`, `remoteReservedCkbShannons` | `U64Hex`                |

### `revocation`

| Field                               | Typed input                                             | Form                         |
| ----------------------------------- | ------------------------------------------------------- | ---------------------------- |
| `for_remote`                        | `forRemote`                                             | boolean                      |
| `revoked_commitment_number`         | `revokedCommitmentNumber`                               | `U64Hex`, at most `2^48 − 1` |
| `payout_script`                     | `payoutScript`                                          | script                       |
| `remote_funding_pubkey`             | `remoteFundingPubkey`                                   | 33 bytes                     |
| `commitment_delay_epoch`            | `commitmentDelayEpoch`                                  | `U64Hex`                     |
| `commitment_fee_rate`               | `commitmentFeeRate`                                     | `U64Hex`                     |
| `cell_deps_count`                   | `cellDepsCount`                                         | `U64Hex`, at most `255`      |
| `udt_type_script`                   | `udtTypeScript`                                         | script or `null`             |
| `to_local`, `to_remote`             | `toLocalShannons`, `toRemoteShannons`                   | `U128Hex`                    |
| `local_reserved`, `remote_reserved` | `localReservedCkbShannons`, `remoteReservedCkbShannons` | `U64Hex`                     |

### `channel_announcement`

| Field                   | Typed input           | Form                                      |
| ----------------------- | --------------------- | ----------------------------------------- |
| `chain_hash`            | `chainHash`           | 32 bytes                                  |
| `funding_out_point`     | `fundingOutPoint`     | outpoint                                  |
| `node_ids`              | `nodeIds`             | exactly two 33-byte keys, in either order |
| `remote_funding_pubkey` | `remoteFundingPubkey` | 33 bytes                                  |
| `capacity`              | `capacityShannons`    | `U128Hex`                                 |
| `udt_type_script`       | `udtTypeScript`       | script or `null`                          |

What keeps these tables in step with the code is that every decoder is typed against the digest module's input: a field
added to a typed input without its decoder does not compile.

## What a refusal looks like

Every field is validated before anything is derived: type, hex prefix and length, integer form and bound, enumeration
membership, array shape, and that the `method` is one of the ten. A failure anywhere is answered `malformed`, with the
echoed `request_id` and a message naming the **field**, as a path such as `sign_request.params.commitment_tx.tlcs[0].amount`,
and what it had to be. A decode refusal never names the value: it reaches the node's logs, and a value can be a preimage or
a key. A decode refusal precedes the channel lookup, so a request the codec refuses is answered `malformed` even for an
unknown channel.

A `sign_request` whose `request_id` cannot be read is unanswerable: answering without an id would correlate with nothing,
so the frame is dropped and the host is told. The same goes for any other frame that does not decode, a challenge of the
wrong length or an acknowledgement with a bad channel id, since none of those is answered on the wire. The two cases are
told apart by the refusal itself: the answerable one carries the request id, the unanswerable one is the bare wire refusal.

The codec is the first of two shape checks and the only one that knows the wire. The policy engine repeats the part it
depends on over the typed input, because it is callable without the wire, and adds that the session's keys are points on
the curve and the nonce's halves too, or at infinity ([policy.md](./policy.md)); it is also the engine that issues the
other three codes. It takes the channel's keys, so it runs after the lookup: for an unknown channel, what only the engine
refuses, a point off the curve or a message that does not match, is answered `unknown_channel`. Its refusals explain the
state they judged, so they may cite what the request carried or what the channel's record holds (a commitment number, a
state version, an amount), though never key material:

| Code              | Meaning                                                                                         |
| ----------------- | ----------------------------------------------------------------------------------------------- |
| `unknown_channel` | The channel's name resolves to no channel index on this device                                  |
| `malformed`       | A field of the wrong shape, state that cannot produce a digest, or a digest that does not match |
| `stale_state`     | A commitment number or state version older than the last one served                             |
| `policy_refusal`  | The sign-once rule or the balance rule                                                          |

A failure that is the device's own, its storage throwing or a record it refuses to read, is none of the four: such a request
is left unanswered and reported to the host, so the node never reads a device fault as a security event. The dispatch
returns it as a fault, apart from the refusals ([signing.md](./signing.md)).

## Where it lives

| File                                   | Contents                                                                                                           |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `src/protocol/protocol.constants.ts`   | The method and frame names, the challenge label, and the challenge and request id bounds                           |
| `src/protocol/protocol.types.ts`       | Every frame and operation object in its wire form (`*Wire`), and the decoded forms the SDK uses                    |
| `src/protocol/protocol.error.ts`       | `ProtocolError`: a wire refusal restated with the code and the request id it is answered with                      |
| `src/protocol/frame.ts`                | Text in, typed inbound frame out; typed outbound frame in, text out                                                |
| `src/protocol/sign-request.ts`         | The sign request's envelope, its params per method, and the response                                               |
| `src/protocol/operation-params.ts`     | The four operation objects and the musig2 session                                                                  |
| `src/protocol/channel-registration.ts` | The registration and its acknowledgement                                                                           |
| `src/protocol/utils/`                  | The request id it echoes, the channel id it names a record by, and the digest the session challenge is signed over |
| `src/wire/`                            | The forms of the Encodings table, and the field reader whose paths the refusals are written in                     |
| `src/common/`                          | The four error codes, and the chain and channel vocabulary the codecs, the digest module and the engine share      |

The encodings are fiber's, not this protocol's, so the readers that enforce them are a module of their own, shared with the
JSON-RPC client that reads the same values from the same node. They refuse with a `WireError` naming the field; the two entry
points of the protocol module, the frame decoder and the params decoder, restate it as the `ProtocolError` that is answerable.
The types those readers decode into, a script, an outpoint, a TLC direction, are CKB's and fiber's rather than any one
module's, so they live in `common` and `wire` stays below the modules that consume it.

The sign request is decoded in two steps on purpose. The frame decoder reads the envelope and leaves `params` as the node's
JSON; the params are decoded by whoever holds the network's commitment lock, which the session does not, so that the session
speaks frames and nothing else. A `ProtocolError` raised past the request id carries that id, which is what lets either step
answer it.

## What the tests guarantee

The specs mirror the two modules one to one, and beyond a happy path per frame and per method:

- **Round trips through fiber's digests.** Every operation object is built from the cross-implementation vectors by a twin
  written apart from the SDK's encoders (`test/utils/wire-requests.ts`), decoded, compared with the typed input the digest
  specs already validate, and rebuilt into the digest fiber's Rust code generated. A signing request decodes into an input
  the policy gate accepts as fresh.
- **A refusal per field and per form.** Missing, wrong type, wrong length, uppercase hex, a missing `0x`, a leading zero,
  an integer past its bound, an unknown enumeration value or method or frame type, a third public key, a 256th TLC, a
  binary frame, invalid JSON, an unreadable request id. Each refusal names its path, is answerable exactly when the request
  id was read, and never contains the value. Every bounded field is also read at its exact bound, so a bound that drifts
  either way fails.
- **The device's own encodings**, compared field by field with literal wire objects, and the wire sizes asserted on the
  way out, since a wrong size there is a device bug rather than a refusal. A refusal is written as exactly its code and
  message whatever object carries it, and a code outside the four is a device bug too.

Coverage of both modules is 100% on all four metrics, and coverage only proves there is no dead code, so the assertions were
checked by breaking the code on purpose:

| Mutation                                                                     | Tests that failed |
| ---------------------------------------------------------------------------- | ----------------- |
| Uppercase hex is accepted                                                    | 8                 |
| A leading zero in an integer is accepted                                     | 15                |
| The integer bound is dropped                                                 | 32                |
| The refusal is not correlated with the request id                            | 42                |
| An absent option reads as `null`                                             | 5                 |
| A sparse array is read with `map`, skipping holes                            | 1                 |
| The key list is sorted on the way in                                         | 1                 |
| The announcement reads a nonce number from the wire                          | 3                 |
| The channel id is any non-empty string                                       | 13                |
| A binary frame is stringified instead of refused                             | 6                 |
| The digest module's spelling of the hash algorithm is accepted               | 1                 |
| The TLC count bound is dropped                                               | 1                 |
| The state version is read as a u64 and rounded                               | 1                 |
| The commitment lock is read from the wire when present                       | 1                 |
| A refusal names the value it refused                                         | 89                |
| One field's bound is lowered by one, or widened (58 mutants, one field each) | 1 to 4 each       |
| The params decoder fixes the commitment lock instead of taking the caller's  | 1 per operation   |
| A refusal is written as the object that carries it                           | 2                 |
| A refusal code outside the four is written                                   | 1                 |
| A request id may hold any character                                          | 12                |
| `channel_registered` or `error` reads its id as any non-empty string         | 2 each            |
