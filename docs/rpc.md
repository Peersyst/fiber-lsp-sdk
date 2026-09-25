# RPC

The client of the fiber node's JSON-RPC: one HTTP POST per call, over a `fetch` the host injects. This document covers its
transport: how a call is written, how the answer is read, and the three ways a call fails. The methods, their params and
results, arrive on top of it one subject at a time.

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

## Amounts

Amounts on the SDK's surface are integer strings of shannons; fiber's are `U128Hex`, `0x` hex without leading zeros.
`encodeShannons` and `decodeShannons` in `src/rpc/utils/amount.utils.ts` are the only place one becomes the other, over
the wire module's `encodeUintHex` and `decodeUintHex`. An amount that is not canonical decimal within a u128 is refused
before it is written, naming the amount and not its value.

## Where it lives

| File                            | Contents                                                                    |
| ------------------------------- | --------------------------------------------------------------------------- |
| `src/rpc/fiber-rpc-client.ts`   | `FiberRpcClient`: the request, the status, the three errors                 |
| `src/rpc/json-rpc.ts`           | The pure envelope codec: the request text, the response read against its id |
| `src/rpc/rpc.error.ts`          | `RpcTransportError`, `RpcError`, `RpcResponseError`                         |
| `src/rpc/rpc.constants.ts`      | The ten methods, the version, the Bearer prefix, fiber's two error codes    |
| `src/rpc/interfaces/i-fetch.ts` | `IFetchLike`                                                                |
| `src/rpc/utils/amount.utils.ts` | Decimal shannons to and from `U128Hex`                                      |
| `test/mocks/rpc/fetch.mock.ts`  | `FetchMock`: records every request and its receiver, answers from a script  |

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
- **Amounts**: every amount of the params vectors, `u128::MAX` included, written as fiber's serde wrote it and read back;
  the bounds; one refusal per malformed form.

Coverage of the module is 100% on all four metrics, and the assertions were checked by breaking the code on purpose:

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
