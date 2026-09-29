# RPC

The client of the fiber node's JSON-RPC: one HTTP POST per call, over a `fetch` the host injects. This document covers its
transport (how a call is written, how the answer is read, and the three ways a call fails) and the methods built on it, one
subject at a time: the four channel methods today, the invoice and payment methods next.

Every claim about fiber refers to `nervosnetwork/fiber` @ `b71a61c3`, and the forms it rests on are pinned by
`interop/vectors/rpc.json`, written by fiber's own serde and jsonrpsee `0.25.1` (see [interop/README.md](../interop/README.md)).

## The host's fetch

The client performs no platform call. It is given, at construction:

| Option  | What it is                                                                               |
| ------- | ---------------------------------------------------------------------------------------- |
| `url`   | The node's RPC address. jsonrpsee serves at the bare origin, so it is posted to as it is |
| `token` | The Biscuit token, base64, when the node's RPC has auth on; absent otherwise             |
| `fetch` | The host's `fetch`, as `IFetchLike`                                                      |

`IFetchLike` is `(url, { method: "POST", headers, body }) => Promise<{ status, text() }>`: what Node's, the browsers' and
React Native's `fetch` agree on, and nothing wider, since `src/` compiles against ES2022 alone and neither the DOM's nor
Node's `fetch` type is in reach. A host passes its own `fetch` unchanged; the spec checks under `tsc` that Node's
satisfies the interface. The client calls it without a receiver, because a browser's `fetch` called as a method of
another object throws.

The token is checked once, at construction, to be printable ASCII without spaces, so a token no runtime would put in a
header fails there and not on every call. No error the client throws carries it.

## A call

`call(method, params, decode)` posts:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "get_payment", "params": [{ "payment_hash": "0x…" }] }
```

- **Params are positional**: one object, the only item of an array. It is the only form fiber's callers use, and the
  auth middleware reads `params[0]`; the named form would change its outer key per method.
- **Headers**: `content-type: application/json` and, with a token, `authorization: Bearer <token>`, the prefix matched
  case-sensitively by fiber. Each call gets its own copy, so a `fetch` that alters them cannot reach the next call.
- **Ids** are a counter per client, from 1, one per call and never reused, a failed call included. A notification (no
  id) is always refused by fiber, so there is none.

The answer is read strictly, as `response`:

1. The status must be 2xx; the body is not read otherwise.
2. The body must be JSON, an object, with `jsonrpc` exactly `"2.0"`.
3. It must carry exactly one of `result` and `error`, by presence: a `null` result is a result (`abandon_channel`
   answers one), and a `null` error beside a result is refused.
4. `id` must be the one the request was sent with. The one exception is an error with a `null` id, which JSON-RPC
   answers when the request itself could not be read, so it had no id to echo.
5. An error must have an integer `code` and a string `message`; its `data` is ignored. Only a params refusal by
   jsonrpsee carries one, serde's message, and nothing reads it.
6. A result goes to the method's decoder, as the field `response.result`. Unknown members are ignored at every level.

## Three errors, by what the caller can conclude

A caller of a write has to know what it can conclude about the outcome, so the errors split by that, not by where they
were thrown:

| Error               | When                                                                             | What the caller knows                         |
| ------------------- | -------------------------------------------------------------------------------- | --------------------------------------------- |
| `RpcTransportError` | `fetch` rejected or threw, the status was not 2xx, or the body could not be read | Nothing: the call may or may not have run     |
| `RpcError`          | The node answered an error: `method`, `code`, and its `message` verbatim         | The node refused                              |
| `RpcResponseError`  | The node answered something the client cannot read: `method`, `path`, `reason`   | The node answered, the client cannot say what |

- `RpcTransportError` carries the `status` when a response arrived, and the runtime's error as its `cause`.
- `RpcError` is told apart by `code` alone. Fiber answers every handler failure as `-32000` (`RPC_CALL_FAILED_CODE`) with
  free text, and an auth refusal as `-32999` (`RPC_UNAUTHORIZED_CODE`) with one of five messages; with auth on, an
  unknown method is `-32999` too. Nothing machine-readable tells two `-32000` failures apart, so the client never
  parses a message.
- `RpcResponseError` wraps the `WireError` of the field that failed, so `path` says whether the envelope or the result
  was unreadable (`response.id`, `response.result.channel_id`). A decoder that throws anything but a `WireError` is a bug,
  and it propagates as it is.

A non-2xx status is a transport error even when the body would hold a JSON-RPC error: the status is what says the
exchange did not complete, and how jsonrpsee maps its own failures to statuses is only visible against a node.

## What the client deliberately does not do

- **Retry.** No write is idempotent: a second `send_payment` for one hash restarts a failed payment, and a repeated open
  is a second channel. Reconciling an unknown outcome means reading state, which is the caller's.
- **Time out.** The timeout is the host's `fetch`'s, where TLS, proxies and abort already live, and it has to allow
  `open_channel_with_external_funding`, which blocks until the funding transaction is built.
- **Parse messages**, for the reason above.
- **Batch, or speak WebSocket.** One request per POST; fiber's pubsub is not a device surface.

## Channel methods

Four methods carry an externally funded channel from its open to its listing. Each sends a closed subset of fiber's params,
what the SDK decides, and leaves every other option to the node's default; each reads only the members the SDK uses, ignoring
the rest even when they are malformed.

| Method                               | Client method                    | Sends                                                                          | Reads                               |
| ------------------------------------ | -------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------- |
| `open_channel_with_external_funding` | `openChannelWithExternalFunding` | `pubkey`, `funding_amount`, `public`, `shutdown_script`, `funding_lock_script` | `channel_id`, `unsigned_funding_tx` |
| `submit_signed_funding_tx`           | `submitSignedFundingTx`          | `channel_id`, `signed_funding_tx`                                              | `channel_id`, `funding_tx_hash`     |
| `abandon_channel`                    | `abandonChannel`                 | `channel_id`                                                                   | `null`                              |
| `list_channels`                      | `listChannels`                   | nothing, or one of `include_closed` and `only_pending`                         | per channel, the fields below       |

- **The open blocks** until the peer has accepted and the funding transaction is built, and answers with the channel's
  **final** id, not the temporary one. Its answer is the only copy of the unsigned transaction: no other method returns it.
- **`public` is always sent**, true included, and the peer's key is required: fiber defaults `public` to `true`, and whether a
  channel is announced is the SDK's decision, not an inherited default.
- **Left to the node on the open**: `funding_udt_type_script` (the client opens CKB channels only until the SDK's multi-asset
  shape is settled; adding it is additive), `funding_lock_script_cell_deps` (needed only by a lock whose deps are not among
  the node's defaults, and additive when a host has one), and the commitment delay, both fee rates and the four TLC
  settings, which are the node's policy.
- **The submit is checked byte for byte by fiber**, which refuses a transaction that differs from the unsigned one in
  anything but the witnesses; it answers before broadcast, and verifies no signature.
- **The abandon answers `null`**, read as such; anything else is an answer the client cannot read.
- **The listing has three modes**, which fiber refuses to combine, so the client takes one `filter` rather than two flags. The
  default hides closed channels, and with them a `ShuttingDown` whose only flag is `WAITING_COMMITMENT_CONFIRMATION`, which
  fiber counts as closed, so a close polled in the default mode vanishes before it reads `Closed`; `include_closed` shows
  them; `only_pending` shows the openings, failed ones included, as synthetic entries fiber builds from its open records: a
  failed opening always reads `Closed` with `FUNDING_ABORTED`, an abandon included, told apart only by `failure_detail`. The
  `pubkey` filter is never sent.

A channel is read as:

| Field                                                         | From                        | Form                                                 |
| ------------------------------------------------------------- | --------------------------- | ---------------------------------------------------- |
| `channelId`                                                   | `channel_id`                | The wire string, `0x` hex, the policy record's alias |
| `peerPubkey`                                                  | `pubkey`                    | 33 bytes, read bare                                  |
| `fundingUdtTypeScript`                                        | `funding_udt_type_script`   | A script or `null`                                   |
| `state`                                                       | `state`                     | Below                                                |
| `local`/`remote`/`offeredTlc`/`receivedTlc` `BalanceShannons` | the four balances           | Decimal shannons                                     |
| `createdAtMs`                                                 | `created_at`                | A `bigint` of milliseconds, a u64                    |
| `shutdownTransactionHash`                                     | `shutdown_transaction_hash` | 32 bytes or `null`, set once the close confirmed     |
| `failureDetail`                                               | `failure_detail`            | Fiber's free text or `null`                          |

## Channel state

Fiber writes a state adjacently tagged: `{"state_name": "Closed", "state_flags": "COOPERATIVE"}`, and for the two states
without flags, `ChannelReady` and `Stale`, the name alone. The client reads it as the name and the list of flag names, typed
per state, and never turns the names back into bits:

- **A name is written whenever its bits overlap**, so composites leak: `OUR_INIT_SENT` alone reads
  `OUR_INIT_SENT|INIT_SENT`. The client keeps what fiber wrote rather than normalizing it, and its lists are pinned whole:
  the vectors carry, per state, the names fiber's serializer writes with every bit set, composites included, and the
  interop spec holds `CHANNEL_STATE_FLAGS` equal to them.
- **`""` is the empty set**, which fiber writes for a state with flags when none is set.
- **Each state accepts only its own names**, in `CHANNEL_STATE_FLAGS`; a name of another state, an unknown one, a name twice,
  an empty segment or padding around `|` is refused, since none can come out of fiber's serializer.
- **`ChannelReady` and `Stale` refuse any `state_flags`**, `""` included: fiber writes no member at all for them.

A channel is ready at `ChannelReady`, and closed at `Closed` with `COOPERATIVE`, `UNCOOPERATIVE_LOCAL` or
`UNCOOPERATIVE_REMOTE`, plus `WAITING_ONCHAIN_SETTLEMENT` until settled.

## Forms only the RPC uses

The `wire` module holds these next to the forms the signing protocol shares:

- **A public key is bare hex**: fiber writes `Pubkey` without `0x`, unlike every hash, which keeps it. The client writes it
  bare and refuses a prefixed one on read; fiber accepts both on input and writes back bare, so the params loop of
  [interop/README.md](../interop/README.md) is what pins the choice.
- **A flag set is one string**, read by `decodeFlags` against the names a state has.
- **A transaction is CKB's JSON**: `version`, `cell_deps` with `dep_type` `code` or `dep_group`, `header_deps`, `inputs` with
  a u64 `since`, `outputs` with a u64 `capacity`, a lock and a type script or `null`, `outputs_data` and `witnesses`, and no
  `hash`. It is read into the SDK's `Transaction` (bytes, `bigint`) and written back exactly, the seven fields in CKB's
  order and nothing else, since CKB's deserializer refuses a member it does not know. A member the client does not know is
  ignored on read, as everywhere else.

The typed inputs are checked before anything is written: a key, hash or id of the wrong length, bytes that are not a
`Uint8Array` (a witness given as hex), an amount that is not canonical decimal, a hash type or dep type outside CKB's, or
a filter fiber has no flag for throws a `TypeError` or `RangeError` naming the field, and nothing is sent.

## Amounts

Amounts on the SDK's surface are integer strings of shannons; fiber's are `U128Hex`, `0x` hex without leading zeros.
`encodeShannons` and `decodeShannons` in `src/rpc/utils/amount.utils.ts` are the only place one becomes the other, over
the wire module's `encodeUintHex` and `decodeUintHex`. An amount that is not canonical decimal within a u128 is refused
before it is written, naming the amount and not its value.

The one exception is a funding transaction's `capacity`: `Transaction` is CKB's own structure, read and written by `wire`
below the conversion, so a `CellOutput` keeps `capacityShannons` as a `bigint`, next to an input's `since` and as `digest`'s
inputs do, and the host hands it to its CKB signer as it is.

## Where it lives

| File                            | Contents                                                                                                                            |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `src/rpc/fiber-rpc-client.ts`   | `FiberRpcClient`: the request, the status, the three errors, the methods                                                            |
| `src/rpc/channels.ts`           | The codecs of the four channel methods, the channel and its state                                                                   |
| `src/rpc/json-rpc.ts`           | The pure envelope codec: the request text, the response read against its id                                                         |
| `src/rpc/rpc.error.ts`          | `RpcTransportError`, `RpcError`, `RpcResponseError`                                                                                 |
| `src/rpc/rpc.constants.ts`      | The ten methods, the version, the Bearer prefix, fiber's two error codes, the channel states and their flags, the listing's filters |
| `src/rpc/interfaces/i-fetch.ts` | `IFetchLike`                                                                                                                        |
| `src/rpc/utils/amount.utils.ts` | Decimal shannons to and from `U128Hex`                                                                                              |
| `src/wire/flags.ts`             | Fiber's flag sets                                                                                                                   |
| `src/wire/transaction.ts`       | CKB's transaction JSON, read and written                                                                                            |
| `test/mocks/rpc/fetch.mock.ts`  | `FetchMock`: records every request and its receiver, answers from a script                                                          |
| `test/utils/rpc-typed.ts`       | The vectors' values projected into the client's typed params and results                                                            |

## What the tests guarantee

- **The envelope against jsonrpsee**: the request text equal byte for byte to the vector's; every result and error
  envelope of the vectors read as written, `data` ignored; the two codes the client names equal to the ones fiber answers
  with.
- **One refusal per rule**: a body that is not JSON, not an object, a batch, no or another version, neither or both of
  `result` and `error`, another or a string id, a missing id on a result or on an error, a `null` id on a result, an
  error that is not an object, a code missing, a string, fractional or unsafe, a message missing or not a string; each
  with its path and reason, and none echoing the body.
- **The request**: the url, the method, the headers with and without a token, a token at the bounds of printable ASCII
  sent as it is, the exact body, the call without a receiver, headers a `fetch` alters not reaching the next call, ids
  from 1, distinct across concurrent calls, never reused after a failure, and counted per client.
- **The errors**: a `fetch` that rejects and one that throws before returning a promise; every non-2xx boundary
  (100, 199, 300) and common status, without reading the body; a status that is not an integer; 200, 201, 204 and 299
  read; a body that cannot be read; every error envelope as an `RpcError` without calling the decoder; an unreadable
  envelope and a decoder's refusal as an `RpcResponseError` naming the field; a decoder's own bug passing through; the
  token absent from every error.
- **The channel methods against fiber**: every params case of the four methods, encoded from its typed input, equal to what
  fiber's serde wrote, and read back unchanged by fiber's own deserializers through `verify-rpc-params`; every result case
  decoded and compared with the vector's input values, not with the JSON it read: both opens, the submit, the abandon's
  `null`, and the three listings and the empty one, which carry every state and every close flag.
- **The flag names per state against fiber**: `CHANNEL_STATE_FLAGS` equal, state by state, to what fiber's serializer writes
  with every bit set, so a flag a release adds fails the interop spec instead of a listing in production.
- **One refusal per field read**, with its full path from `response.result` (`response.result.channels[1].state.state_flags`):
  a hash or id bare or short, a key prefixed, short or uppercase, each balance and `created_at` in decimal, with a leading zero
  or past its width, a state name unknown, flags on a state without any, missing or `null` on one with them, a flag of another
  state, twice, or with an empty segment; and the members not read accepted however malformed.
- **The forms**: the flag set against every rule above; the transaction read field by field from a literal, written back
  equal, one refusal per field with its path, a `hash` ignored on read and never written; the bare key, the new encoders and
  their refusals of typed input, which send nothing.
- **Amounts**: every amount of the params vectors, `u128::MAX` included, written as fiber's serde wrote it and read back;
  the bounds; one refusal per malformed form.

Coverage of the module and of `wire` is 100% on all four metrics, and the assertions were checked by breaking the code on purpose:

| Mutation                                                     | Tests that failed |
| ------------------------------------------------------------ | ----------------- |
| The envelope's version is not checked                        | 54                |
| A response with both or neither of result and error is read  | 51                |
| Ids start at 0                                               | 23                |
| An amount is written without checking its form               | 10                |
| The token is not checked at construction                     | 8                 |
| The params are sent as the object, not as a positional array | 4                 |
| A `null` id is never accepted                                | 3                 |
| `encodeUintHex` writes a value past its bound                | 3                 |
| Every call is sent with the same id                          | 2                 |
| An error code only has to be a number                        | 2                 |
| The Bearer prefix is lowercase                               | 2                 |
| A `null` id is accepted on a result too                      | 1                 |
| Status 300 is read as success                                | 1                 |
| Status 199 is read as success                                | 1                 |
| A status that is not an integer is read as success           | 1                 |
| `fetch` is called with the client as its receiver            | 1                 |
| Every call shares one headers object                         | 1                 |
| Any error of a decoder is reported as an unreadable answer   | 1                 |
| A body that cannot be read escapes as the runtime's error    | 1                 |
| An empty url is accepted                                     | 1                 |
| An error without an id is read as the node's refusal         | 1                 |
| The token pattern admits DEL                                 | 1                 |
| The token pattern excludes `!` and `~`                       | 1                 |
| `created_at` is bounded to a u32                             | 19                |
| A pubkey is read with a `0x` prefix too                      | 12                |
| An empty string is not the empty flag set                    | 11                |
| The transaction encoder writes the members it read           | 7                 |
| A missing shutdown hash is read as no hash                   | 6                 |
| A state without flags may carry `state_flags`                | 5                 |
| The remote balance is read from the local one                | 5                 |
| An untyped output's `type` is omitted, not `null`            | 4                 |
| The filter writes `false` for the other flag                 | 4                 |
| The abandon's `null` is not checked                          | 4                 |
| A pubkey is written with a `0x` prefix                       | 3                 |
| A channel id is not checked before it is written             | 3                 |
| Any state's flag is accepted in any state                    | 2                 |
| A flag named twice is accepted                               | 2                 |
| Flags are split with their padding trimmed                   | 2                 |
| `public` is omitted when true                                | 2                 |
| A `since` is read as a u128                                  | 1                 |
| A `capacity` is read as a u128                               | 1                 |
| The dep type is not checked before it is written             | 1                 |
| A header dep of any length is written                        | 1                 |
| An unknown filter is written                                 | 1                 |
| An outpoint index past a u32 is written                      | 1                 |
| Script args are not checked to be bytes                      | 1                 |
| A transaction's byte lists are written unchecked             | 2                 |
| A flag missing from a state's list                           | 1                 |
