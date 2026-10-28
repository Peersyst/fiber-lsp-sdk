# RPC

The client of the fiber node's JSON-RPC: one HTTP POST per call, over the host's `fetch` or the runtime's. This document
covers its transport (how a call is written, how the answer is read, and the three ways a call fails) and the eighteen
methods built on it, by subject: channels, invoices, payments, the tenant's channels, the signing requests and the
registration.

Every claim about fiber refers to `nervosnetwork/fiber` @ `8db6a117`, and the forms it rests on are pinned by
`interop/vectors/rpc.json`, written by fiber's own serde and jsonrpsee `0.25.1` (see [interop/README.md](../interop/README.md)).

## The host's fetch

The client makes no platform call except reading the runtime's `fetch` when the host passes none. It is given, at
construction:

| Option  | What it is                                                                               |
| ------- | ---------------------------------------------------------------------------------------- |
| `url`   | The node's RPC address. jsonrpsee serves at the bare origin, so it is posted to as it is |
| `token` | The Biscuit token, base64, when the node's RPC has auth on; absent otherwise             |
| `fetch` | The host's `fetch`, as `IFetchLike`; optional                                            |

`IFetchLike` is `(url, { method: "POST", headers, body }) => Promise<{ status, text() }>`: what Node's, the browsers' and
React Native's `fetch` agree on, and nothing wider, since `src/` compiles against ES2022 alone and neither the DOM's nor
Node's `fetch` type is in reach. A host passes its own `fetch` unchanged; the spec checks under `tsc` that Node's
satisfies the interface. The client calls it without a receiver, because a browser's `fetch` called as a method of
another object throws.

Without one, the client takes the runtime's global `fetch`, which Node, the browsers and React Native all have. It reads
it once, at construction, so a runtime without one fails there with a `TypeError` and not on the first call. A host still
passes its own when it needs another: a timeout, a proxy, a double in tests.

The token is checked to be printable ASCII without spaces, so a token no runtime would put in a header fails when it is
given and not on every call. It is given at construction or, later, through `setToken(token)`, which replaces it from the
next call on under the same check; a refused token leaves the previous one, and nothing removes it. A device learns its
tenant token only after it registers, which is why it can arrive after construction. No error the client throws carries
it.

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
- **The params are typed per method** by `RpcParamsWireByMethod`, which names all eighteen, so `call` cannot be handed
  the params of another method. The typed method of each RPC is what a caller uses; `call` is what they share. Each of the
  eight methods of the tenant API has its client method: the four the poller's two steps call
  (`getChannelSigningStatus`, `submitChannelSignature`, `getWatchtowerSigningStatus`, `submitWatchtowerSignature`), the
  two registration methods (`getTenantRegistryNonce`, `registerTenant`), and the tenant channel's two,
  `openTenantChannel`, which the facade's opening calls, and `shutdownChannel`, which its close calls ([sdk.md](./sdk.md)).

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

- **Retry.** No write is idempotent: a second `send_payment` for one hash restarts a failed payment, and a repeated
  external-funding open is a second channel. The tenant open is the exception fiber makes, one opening per tenant whose
  identical repeat gets the same answer, and the facade's opening is what retries it ([sdk.md](./sdk.md)). Reconciling an
  unknown outcome means reading state, which is the caller's.
- **Time out.** The timeout is the host's `fetch`'s, where TLS, proxies and abort already live, and it has to allow
  both opens, which block until the funding transaction is built.
- **Parse messages**, for the reason above.
- **Batch, or speak WebSocket.** One request per POST; fiber's pubsub is not a device surface.

## Channel methods

Four methods carry an externally funded channel from its open to its listing. Each sends a closed subset of fiber's params,
what the SDK decides, and leaves every other option to the node's default; each reads only the members the SDK uses, ignoring
the rest even when they are malformed.

| Method                               | Client method                    | Sends                                                                                                                    | Reads                               |
| ------------------------------------ | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------- |
| `open_channel_with_external_funding` | `openChannelWithExternalFunding` | `pubkey`, `funding_amount`, `public`, `shutdown_script`, `funding_lock_script`; `funding_lock_script_cell_deps` if given | `channel_id`, `unsigned_funding_tx` |
| `submit_signed_funding_tx`           | `submitSignedFundingTx`          | `channel_id`, `signed_funding_tx`                                                                                        | `channel_id`, `funding_tx_hash`     |
| `abandon_channel`                    | `abandonChannel`                 | `channel_id`                                                                                                             | `null`                              |
| `list_channels`                      | `listChannels`                   | nothing, or one of `include_closed` and `only_pending`                                                                   | per channel, the fields below       |
| `list_channels`                      | `listChannelIds`                 | the same as `listChannels`                                                                                               | each channel's `channel_id` alone   |
| `list_channels`                      | `listChannelStates`              | the same as `listChannels`                                                                                               | each channel's id and state alone   |

- **The open blocks** until the peer has accepted and the funding transaction is built, and answers with the channel's
  **final** id, not the temporary one. Its answer is the only copy of the unsigned transaction: no other method returns it.
- **`public` is always sent**, true included, and the peer's key is required: fiber defaults `public` to `true`, and whether a
  channel is announced is the SDK's decision, not an inherited default.
- **The funding lock's cell deps are sent only when given**, as `fundingLockScriptCellDeps`: without them fiber resolves
  the funding lock's deps among the chain's genesis scripts alone (`funding_tx.rs:223-238`), so a user's lock outside
  them cannot fund the channel. Each is checked as a cell dep by `common`'s `assertCellDeps` (an out point and `code` or
  `dep_group`), refused by its index before anything is sent, and written as CKB's JSON writes one. An empty list is sent
  as `[]`, which fiber reads as none.
- **Left to the node on the open**: `funding_udt_type_script` (the client opens CKB channels only until the SDK's multi-asset
  shape is settled; adding it is additive), and the commitment delay, both fee rates and the four TLC settings, which are
  the node's policy.
- **The submit is checked byte for byte by fiber**, which refuses a transaction that differs from the unsigned one in
  anything but the witnesses; it answers before broadcast, and verifies no signature.
- **The abandon answers `null`**, read as such; anything else is an answer the client cannot read.
- **The listing has three modes**, which fiber refuses to combine, so the client takes one `filter` rather than two flags. The
  default hides closed channels, and with them a `ShuttingDown` whose only flag is `WAITING_COMMITMENT_CONFIRMATION`, which
  fiber counts as closed, so a close polled in the default mode vanishes before it reads `Closed`; `include_closed` shows
  them; `only_pending` shows the openings, failed ones included, as synthetic entries fiber builds from its open records: a
  failed opening always reads `Closed` with `FUNDING_ABORTED`, an abandon included, told apart only by `failure_detail`. The
  `pubkey` filter is never sent.
- **The listing can be read for its ids alone**: `listChannelIds` reads `channels[].channel_id`, strict in it (an
  array of objects, each id 32 bytes of `0x` lowercase hex) and blind to every other field, so a state or a flag a newer
  fiber adds cannot stop a caller that needs only the ids, which is the signing step ([sdk.md](./sdk.md)).
- **Or for its ids and states, read tolerantly**: `listChannelStates` reads the id as strictly, and the state as fiber's
  strings, `{ channelId, stateName, stateFlags }`: `state` an object, `state_name` a string, and `state_flags` a string
  split on `|`, `""` and an absent member both read as none. A name or a flag the client does not know reads as it is,
  where `listChannels` refuses it, so the watchtower step, which must keep polling a channel whatever state a newer fiber
  gives it, is the one that calls it ([sdk.md](./sdk.md)). Every other field is ignored.

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
  interop spec holds `RPC_CHANNEL_STATE_FLAGS` equal to them.
- **`""` is the empty set**, which fiber writes for a state with flags when none is set.
- **Each state accepts only its own names**, in `RPC_CHANNEL_STATE_FLAGS`; a name of another state, an unknown one, a name twice,
  an empty segment or padding around `|` is refused, since none can come out of fiber's serializer.
- **`ChannelReady` and `Stale` refuse any `state_flags`**, `""` included: fiber writes no member at all for them.

A channel is ready at `ChannelReady`, and closed at `Closed` with `COOPERATIVE`, `UNCOOPERATIVE_LOCAL` or
`UNCOOPERATIVE_REMOTE`, plus `WAITING_ONCHAIN_SETTLEMENT` until settled.

## Invoice methods

Four methods carry an invoice from its creation to its settlement. The client can only create a **hold invoice**: it sends
the payment hash and has no member for a preimage, so the node holds the payment it receives until `settle_invoice` hands it
the preimage, the one call that carries one.

| Method           | Client method   | Sends                                                                                                        | Reads                       |
| ---------------- | --------------- | ------------------------------------------------------------------------------------------------------------ | --------------------------- |
| `new_invoice`    | `newInvoice`    | `amount`, `currency`, `payment_hash`, `expiry`, `final_expiry_delta`, `hash_algorithm`, `description` if any | `invoice_address`           |
| `get_invoice`    | `getInvoice`    | `payment_hash`                                                                                               | `invoice_address`, `status` |
| `settle_invoice` | `settleInvoice` | `payment_hash`, `payment_preimage`                                                                           | `{}`                        |
| `cancel_invoice` | `cancelInvoice` | `payment_hash`                                                                                               | `invoice_address`, `status` |

- **`expiry` is required**, a u64 of seconds: fiber has no default, and an invoice created without one never expires.
- **`final_expiry_delta` is required**, milliseconds above zero and at most 14 days (`RPC_MAX_FINAL_EXPIRY_DELTA_MS`,
  fiber's `MAX_PAYMENT_TLC_EXPIRY_LIMIT`, `rpc/invoice.rs:374-387`), the least time a TLC paying the invoice must have
  left. Fiber writes its minimum when it is absent, two thirds of its default commitment delay, which leaves a held
  payment no margin to settle ([sdk.md](./sdk.md)). The client bounds it below at 1 and not at that minimum, because
  the minimum is the build's (9,600,000 ms in release, 1,333 ms in debug): the node refuses one below its own.
- **`hash_algorithm` is always sent**, because the caller computed the hash and has to name how. The SDK's `ckb-hash` is
  written `ckb_hash`, fiber's spelling, through the one map `wire` also reads it with.
- **`currency` is fiber's name**, `Fibb`, `Fibt` or `Fibd` for mainnet, testnet and any other chain. Fiber refuses one that
  is not the node's. The list is `invoice`'s `INVOICE_CURRENCIES`, shared with the invoice reader, which knows the same three by
  the prefix of the string ([invoice.md](./invoice.md)).
- **`description` is optional**, and an empty one is sent as it is: fiber stores it as a description, which is not the
  invoice it builds without one. It is at most 639 bytes of well-formed UTF-8 (`RPC_MAX_INVOICE_DESCRIPTION_BYTES`,
  fiber's `MAX_DESCRIPTION_LENGTH` held to the string's UTF-8 length, `invoice/invoice_impl.rs:214-219`), checked by the
  client before anything is sent: more is a `RangeError`, and a lone surrogate a `TypeError`, since serde_json refuses
  one in a string and the platform's encoders would replace it in silence. The guard, `assertRpcInvoiceDescription`,
  counts the bytes with the writer the invoice codec uses (`encodeWellFormedUtf8`, [invoice.md](./invoice.md)), and the
  facade calls it before it allocates an invoice's index ([sdk.md](./sdk.md)).
- **Left to the node on the creation**: `fallback_address`, `udt_type_script` (CKB invoices only, as the open), `allow_mpp` and `allow_trampoline_routing`. `payment_preimage` is not
  left to the node: the client cannot send it.
- **Only the encoded invoice is read**, a non-empty string: it is what a payer is given. Fiber also answers the invoice
  parsed, which the client ignores, since what is worth checking is the string itself.
- **`get_invoice` reads the encoded invoice too**, not only the status: it is how a caller that lost the answer of
  `new_invoice` recovers the invoice the node did create.
- **The status is one of fiber's five**, `Open`, `Cancelled`, `Expired`, `Received` and `Paid`. `Expired` is derived on read
  from an `Open` invoice past its expiry. `Received` means a payment that fulfils the invoice is held; nothing takes it back
  if the hold runs out, so it is not a promise that the funds can still be claimed.
- **A settle answers `{}` once the preimage is stored**, which is not the funds claimed: that is `Paid`, read with
  `get_invoice`. Fiber refuses it unless the invoice is `Received` and the preimage hashes to its payment hash.
- **A cancel answers the invoice as `Cancelled`**, failing the payment it held when it was `Received`. Fiber refuses it on a
  `Paid` or already `Cancelled` invoice.

## Payment methods

| Method         | Client method | Sends                                                     | Reads                 |
| -------------- | ------------- | --------------------------------------------------------- | --------------------- |
| `send_payment` | `sendPayment` | `invoice`, `max_fee_amount`, `dry_run`, `trampoline_hops` | the payment, as below |
| `get_payment`  | `getPayment`  | `payment_hash`                                            | the payment, as below |

- **The invoice is all a payment is described by**: the node takes the amount, the hash and the target from it, so the
  client sends none of the three.
- **`max_fee_amount` is always sent**: with the invoice's amount it is the most the payment can debit. Fiber caps it further
  by its `max_fee_rate`, and only the sending node's route finding enforces either.
- **`dry_run` is always sent**, false included. A dry run finds the route and answers the payment it would send, its fee
  included, and stores nothing.
- **`trampoline_hops` is required of the caller and sent only when not empty**: `trampolineHops` is a list of at most
  five compressed keys (`RPC_MAX_TRAMPOLINE_HOPS`, fiber's `MAX_TRAMPOLINE_HOPS_LIMIT`, `fiber/payment.rs:49`), in route
  order, each a point on the curve, written as bare hex as fiber's `Pubkey` serde reads it. Fiber refuses an empty list
  ("trampoline_hops must be non-empty when provided", `fiber/payment.rs:263-266`), so an empty one is left out, and the
  node then takes the invoice's trampoline hint when it carries one, or routes on its own graph
  (`fiber/payment.rs:401-408`). The list is read by index, so a hole in a sparse array is refused as the `undefined` it is.
- **Left to the node on the send**: `target_pubkey`, `amount` and `payment_hash` (the invoice's), `final_tlc_expiry_delta`,
  `tlc_expiry_limit`, `timeout`, `max_fee_rate`, `max_parts`, `keysend`, `udt_type_script`, `allow_self_payment`,
  `custom_records` and `hop_hints`.
- **The send answers once the first hop is dispatched**, normally as `Created`: how the payment ends is read with
  `get_payment`.

A payment is read as:

| Field             | From              | Form                                                             |
| ----------------- | ----------------- | ---------------------------------------------------------------- |
| `paymentHash`     | `payment_hash`    | 32 bytes                                                         |
| `status`          | `status`          | `Created`, `Inflight`, `Success` or `Failed`, the last two final |
| `createdAtMs`     | `created_at`      | A `bigint` of milliseconds, a u64                                |
| `lastUpdatedAtMs` | `last_updated_at` | A `bigint` of milliseconds, a u64                                |
| `failedError`     | `failed_error`    | Fiber's free text or `null`, read whatever the status            |
| `feeShannons`     | `fee`             | Decimal shannons: the fee of the attempts that have not failed   |

`custom_records` is not read, nor `routers`, which only a debug build of fiber writes.

## Tenant channel methods

Two methods open and close a tenant's channel on the hosted node, which holds no channel key: the device supplies the
public signer material at the open, and signs on request afterwards ([Signing request methods](#signing-request-methods)).

| Method                | Sends                                                                                                                                                                                                                           | Reads                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `open_tenant_channel` | the open's `pubkey`, `funding_amount`, `public`, `shutdown_script`, `funding_lock_script`, and `funding_lock_script_cell_deps` if given; `commitment_delay_epoch` and `commitment_fee_rate` if given; `external_channel_signer` | `channel_id`, `unsigned_funding_tx`, `opening_context` |
| `shutdown_channel`    | `channel_id`; `close_script`, `fee_rate` and `force` if given                                                                                                                                                                   | `null`                                                 |

- **The open is the external-funding open plus the signer material**, on the client as `openTenantChannel`, which the
  facade's opening calls ([sdk.md](./sdk.md)): the same members, the funding lock's cell deps included, written by the
  same encoder, with `public` always `false`. A tenant channel is private, fiber refuses to announce one, and the choice is the SDK's,
  not an inherited default; an input that carries `public: true` still sends `false`.
- **`external_channel_signer` is the device's public material**: `base_public_keys` (`funding_pubkey`, `tlc_base_key`),
  `first_commitment_point`, `second_commitment_point`, each a 33-byte point written bare, and `commitment_nonce`,
  `next_commitment_nonce`, `revocation_nonce`, each a 66-byte musig2 public nonce written with its `0x`.
  `channel_announcement_nonce` is written only when the input has one; the SDK's input is `null` for the private channel
  it opens, since fiber refuses the nonce on one.
- **The two options are sent only when given**, as `U64Hex`: the delay as the full `EpochNumberWithFraction` value, the
  rate in shannons per kilobyte; absent, the node's defaults apply. Left to the node, as on the external-funding open:
  `funding_udt_type_script`, `funding_fee_rate` and the four TLC settings.
- **The answer is the channel's final id**, derived from both TLC base keys, the unsigned funding transaction (the only
  copy of it) and the `opening_context`: the terms the node froze. The client reads their forms only; holding them to
  what was asked, the id and the funding output included, is the facade's ([sdk.md](./sdk.md)). It is read field by
  field, each refusal naming its path:

| Field                                  | From                                    | Form                                    |
| -------------------------------------- | --------------------------------------- | --------------------------------------- |
| `remoteFundingKey`                     | `remote_funding_key`                    | 33 bytes, read bare                     |
| `remoteSettlementKey`                  | `remote_settlement_key`                 | 33 bytes, read bare                     |
| `remoteShutdownScript`                 | `remote_shutdown_script`                | A script                                |
| `commitmentDelayEpoch`                 | `commitment_delay_epoch`                | A `bigint`, the full epoch value, a u64 |
| `commitmentFeeRate`                    | `commitment_fee_rate`                   | A `bigint`, a u64                       |
| `localAmountShannons`                  | `local_amount`                          | Decimal shannons, the reserve included  |
| `remoteAmountShannons`                 | `remote_amount`                         | Decimal shannons                        |
| `local`/`remote` `ReservedCkbShannons` | `local`/`remote` `_reserved_ckb_amount` | Decimal shannons, a u64                 |

- **The shutdown sends the id alone for a cooperative close on the node's defaults**, on the client as `shutdownChannel`,
  which the facade's close calls ([sdk.md](./sdk.md)): `close_script` (by default the shutdown script of the open, the
  device's for a tenant), `fee_rate` (by default the channel's commitment fee rate, `fiber/channel.rs:2759-2765`) and
  `force` (`false`) are written only when given, never as `null`. Fiber refuses `force` beside either of the other two
  (`rpc/channel.rs:723-729`), which the client leaves to it. It answers `null`, read as such.

## Signing request methods

Four methods carry the polled signing protocol: the device reads whether the node waits on a signature, and submits one.
Two getters and two submissions, one pair for the channel and one for the watchtower, with the same forms. The channel
pair is on the client as `getChannelSigningStatus({ channelId })` and `submitChannelSignature({ channelId, requestId,
partialSignature, nextMaterial })`, which the facade's signing step calls; the watchtower pair as
`getWatchtowerSigningStatus({ channelId })` and `submitWatchtowerSignature({ channelId, requestId, signature })`, which its
watchtower step calls ([sdk.md](./sdk.md)).

| Method                          | Sends                                                                   | Reads                  |
| ------------------------------- | ----------------------------------------------------------------------- | ---------------------- |
| `get_channel_signing_status`    | `channel_id`                                                            | `channel_id`, `status` |
| `submit_channel_signature`      | `channel_id`, `request_id`, `partial_signature`; `next_material` if any | `type`                 |
| `get_watchtower_signing_status` | `channel_id`                                                            | `channel_id`, `status` |
| `submit_watchtower_signature`   | `channel_id`, `request_id`, `signature`                                 | `type`                 |

- **The status is the signing protocol's**, a tagged object: `{ "type": "NoSignatureRequired" }` or
  `{ "type": "SignatureRequired", ... }` with the request's id and what to sign: the transition and its plaintext for a
  channel, the key purpose and the transaction for the watchtower ([protocol.md](./protocol.md)). The client reads
  the `channel_id` and hands `status` over as the `WireField` it arrived in, positioned at `response.result.status`, so
  the protocol's decoder refuses with the full path; `rpc` never reads inside it, and does not import `protocol`.
- **A channel signature is a 32-byte musig2 partial signature** for the request it names, with `next_material`: the next
  commitment point (bare) and the next commitment and revocation nonces (`0x`), all three always written, or left out
  when the request takes none, never sent as `null`, as every absent option of the client is.
- **A watchtower signature is recoverable ECDSA**, 65 bytes with the recovery id, written with its `0x`.
- **A submission answers one of two outcomes**, read from the `type` tag against `RPC_SUBMISSION_RESULTS`: `Applied`, the
  signature verified and the node resumed, or `AlreadyApplied`, the same signature already taken for this request. Both
  are success: a device that lost the answer resubmits and reads the second without reconciling anything.

## Registration methods

Two methods register a device's root signer as a tenant of the hosted LSP, under the operator's token: the registration
is the one exchange a tenant cannot make with its own token, which it does not have yet. The client's `getTenantRegistryNonce` and
`registerTenant` call them, on a client built with the operator's token: the host's backend or an agent makes them, never
the facade, and the device only signs, through `TenantIdentity` ([signing.md](./signing.md)). `FiberRpcClient` is not
published yet, so the two methods are within reach of the repo's code alone until the facade's operations settle
what the package exports.

| Method                          | Sends                                      | Reads                                        |
| ------------------------------- | ------------------------------------------ | -------------------------------------------- |
| `lsp_get_tenant_registry_nonce` | `root_signer_pubkey`                       | `lsp_node_id`, `root_signer_pubkey`, `nonce` |
| `lsp_register_tenant`           | `root_signer_pubkey`, `nonce`, `signature` | `tenant`, `access_token`                     |

- **The nonce is single-use and bound to the root signer** it was issued to; the answer also names the LSP's node id,
  which the registry payload the device signs covers.
- **The signature is compact ECDSA**, 64 bytes, over fiber's `TenantRegistryPayload`, and is written as **bare hex**, 128
  characters without `0x`, as fiber's own agent writes it. Fiber reads a prefixed one too, so the params loop of
  [interop/README.md](../interop/README.md) is what pins the spelling.
- **The answer is the tenant and its access token**, a non-empty string, the Biscuit the device calls everything else
  with. The tenant is read field by field:

| Field              | From                 | Form                                                                          |
| ------------------ | -------------------- | ----------------------------------------------------------------------------- |
| `tenantId`         | `tenant_id`          | 32 bytes of bare hex, the digest of the root signer's key, kept as the string |
| `rootSignerPubkey` | `root_signer_pubkey` | 33 bytes bare, or `null` for a tenant fiber's operator registered another way |
| `invoicePubkey`    | `invoice_pubkey`     | 33 bytes bare, the tenant's protocol key                                      |
| `privateChannelId` | `private_channel_id` | The wire string, `0x` hex, or `null` before the channel is bound              |
| `createdAtMs`      | `created_at`         | A `bigint` of milliseconds, a u64                                             |
| `runtimeStatus`    | `runtime_status`     | `cold` or `active`, from `RPC_TENANT_RUNTIME_STATUSES`                        |
| `channelOnline`    | `channel_online`     | A boolean                                                                     |

## What a tenant's token allows

Fiber's middleware checks a tenant token against an allowlist after the Biscuit's own checks (`TENANT_ALLOWED_METHODS`),
and every method outside it is refused. Of the eighteen methods of the client, a tenant may call all but five: the two
registration methods, which take the operator's token, as above, and `open_channel_with_external_funding`,
`abandon_channel` and `cancel_invoice`, which stay in the client because a node that is not a hosted LSP has them.

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

The typed inputs are checked before anything is written: a key, hash, preimage or id of the wrong length, bytes that are not
a `Uint8Array` (a witness given as hex), an amount that is not canonical decimal, an expiry that is not a `bigint` within a
u64, a hash type, dep type, currency or hash algorithm outside the names the SDK has, an empty invoice, or a filter fiber has
no flag for throws a `TypeError` or `RangeError` naming the field, and nothing is sent. The refusal of a preimage never
carries it.

## Amounts

Amounts on the SDK's surface are integer strings of shannons; fiber's are `U128Hex`, `0x` hex without leading zeros.
`encodeRpcShannons` and `decodeRpcShannons` in `src/rpc/utils/amount.utils.ts` are the only place one becomes the other, over
the wire module's `encodeUintHex` and `decodeUintHex`. An amount that is not canonical decimal within a u128 is refused
before it is written, naming the amount and not its value.

The one exception is a funding transaction's `capacity`: `Transaction` is CKB's own structure, read and written by `wire`
below the conversion, so a `CellOutput` keeps `capacityShannons` as a `bigint`, next to an input's `since` and as `digest`'s
inputs do, and the host hands it to its CKB signer as it is.

## Where it lives

| File                                  | Contents                                                                                                                                                                                                                                                                                  |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/rpc/fiber-rpc-client.ts`         | `FiberRpcClient`: the token and `setToken`, the request, the status, the three errors, the methods                                                                                                                                                                                        |
| `src/rpc/channels.ts`                 | The codecs of the four channel methods and the two tenant channel methods, the channel, its state, the listing read for its ids or its states, and the opening context                                                                                                                    |
| `src/rpc/invoices.ts`                 | The codecs of the four invoice methods, and the description's guard                                                                                                                                                                                                                       |
| `src/rpc/payments.ts`                 | The codecs of the two payment methods                                                                                                                                                                                                                                                     |
| `src/rpc/signing.ts`                  | The codecs of the four signing request methods: the status handed over as a field, the two signatures, the two outcomes                                                                                                                                                                   |
| `src/rpc/tenants.ts`                  | The codecs of the two registration methods, the tenant's status                                                                                                                                                                                                                           |
| `src/rpc/json-rpc.ts`                 | The pure envelope codec: the request text, the response read against its id                                                                                                                                                                                                               |
| `src/rpc/rpc.error.ts`                | `RpcTransportError`, `RpcError`, `RpcResponseError`                                                                                                                                                                                                                                       |
| `src/rpc/rpc.constants.ts`            | The eighteen methods, the version, the Bearer prefix, fiber's two error codes, the channel states and their flags, the listing's filters, the invoice, payment, submission and tenant runtime statuses, the final expiry delta's and the description's bounds, the trampoline hops' bound |
| `src/rpc/interfaces/i-fetch.ts`       | `IFetchLike`                                                                                                                                                                                                                                                                              |
| `src/rpc/utils/amount.utils.ts`       | Decimal shannons to and from `U128Hex`                                                                                                                                                                                                                                                    |
| `src/rpc/utils/payment-hash.utils.ts` | The params of the three methods that take a payment hash and nothing else                                                                                                                                                                                                                 |
| `src/rpc/utils/channel-id.utils.ts`   | The params of the three methods that take a channel id and nothing else: the abandon and the two signing status getters                                                                                                                                                                   |
| `src/wire/flags.ts`                   | Fiber's flag sets                                                                                                                                                                                                                                                                         |
| `src/wire/transaction.ts`             | CKB's transaction JSON, read and written                                                                                                                                                                                                                                                  |
| `test/mocks/rpc/fetch.mock.ts`        | `FetchMock`: records every request and its receiver, answers from a script                                                                                                                                                                                                                |
| `test/utils/rpc-typed.ts`             | The vectors' values projected into the client's typed params and results                                                                                                                                                                                                                  |
| `test/utils/rpc-answers.ts`           | The result field and the scripted answers the method specs share                                                                                                                                                                                                                          |

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
- **The runtime's fetch**: taken when the host passes none, read at construction and called without a receiver; the host's
  preferred over it; a runtime without one, or with one that is not a function, refused at construction.
- **The errors**: a `fetch` that rejects and one that throws before returning a promise; every non-2xx boundary
  (100, 199, 300) and common status, without reading the body; a status that is not an integer; 200, 201, 204 and 299
  read; a body that cannot be read; every error envelope as an `RpcError` without calling the decoder; an unreadable
  envelope and a decoder's refusal as an `RpcResponseError` naming the field; a decoder's own bug passing through; the
  token absent from every error.
- **The channel methods against fiber**: every params case of the four methods, the open with its funding lock's cell deps
  of both dep types and without them, encoded from its typed input, equal to what fiber's serde wrote, and read back unchanged by fiber's own deserializers through `verify-rpc-params`; every result case
  decoded and compared with the vector's input values, not with the JSON it read: both opens, the submit, the abandon's
  `null`, and the three listings and the empty one, which carry every state and every close flag, read by
  `listChannelStates` too, each state as fiber's strings. That reading has its own refusals and acceptances: a literal
  listing in the node's order, the flags split and none for a state without them, `""` as none, an entry carrying its id
  and state alone, a state or a flag no release has yet, and one refusal per field it reads, with its path; the client
  method lists in the default mode and with the filter's flag, and refuses a filter it cannot write before any fetch.
- **The flag names per state against fiber**: `RPC_CHANNEL_STATE_FLAGS` equal, state by state, to what fiber's serializer writes
  with every bit set, so a flag a release adds fails the interop spec instead of a listing in production.
- **One refusal per field read**, with its full path from `response.result` (`response.result.channels[1].state.state_flags`):
  a hash or id bare or short, a key prefixed, short or uppercase, each balance and `created_at` in decimal, with a leading zero
  or past its width, a state name unknown, flags on a state without any, missing or `null` on one with them, a flag of another
  state, twice, or with an empty segment; and the members not read accepted however malformed.
- **The invoice and payment methods against fiber**: every params case of the six methods written as fiber's serde wrote it
  and read back unchanged by its deserializers, so the loop covers the ten methods, which the map of encoders the interop
  spec runs is total over by type; every result case decoded and compared with the vector's input values: the created
  invoice, the five invoice statuses, the settle's `{}`, the cancelled invoice, and the four payment statuses with the
  largest fee and timestamps. `send_payment` has three params cases: a dry run and the largest fee bound, both with no hops and
  written without `trampoline_hops`, and a real one with two hops, in order, as fiber's `SendPaymentCommandParams`
  serializes them.
- **The names against fiber**: the currencies, the invoice and payment statuses and the hash algorithms the client names
  equal to the ones the vectors carry, which the harness cannot generate without every variant fiber has.
- **The trampoline hops**: five written and a sixth refused; two written in order as bare hex; and the hops not a list
  or missing, a hop of 32 or 34 bytes, as a string, `null`, a hole in the list, and 33 bytes off the curve, each refused
  by its position with nothing sent.
- **One refusal per field, written and read**: each typed input of the six methods in every wrong form, with nothing sent;
  each member read missing, `null`, in another form or past its width, with its path; an unknown status, a lowercase one and
  one padded; a result that is not an object; a `null` answer to a settle. The members not read are accepted missing or
  malformed.
- **The hold invoice by construction**: no input makes `new_invoice` carry a preimage, a description is omitted rather than
  sent as `null` and sent when empty, and no refusal of a preimage carries its bytes.
- **The creation's bounds**: `final_expiry_delta` written at fiber's 14 days and at one millisecond, and refused at zero,
  negative, one past 14 days, absent and as a number, with nothing sent; a description of exactly 639 bytes sent in one-, three- and
  four-byte characters, a surrogate pair taken as the one point it encodes, and 640 bytes, a lone surrogate of either
  half and anything not a string refused, the guard on its own and through `newInvoice`.
- **The funding lock's cell deps**: written after the funding lock when given and never otherwise, an empty list as `[]`,
  the highest index an out point can name, and one refusal per field of a list or an entry (not a list, an entry not an
  object, its out point missing, a short hash, an index past a u32, a dep type missing or unknown), with nothing sent.
- **The forms**: the flag set against every rule above; the transaction read field by field from a literal, written back
  equal, one refusal per field with its path, a `hash` ignored on read and never written; the bare key, the new encoders and
  their refusals of typed input, which send nothing.
- **The tenant channel methods against fiber**: every params case of the two methods (the open without options, with the
  delay and the fee rate, with the announcement nonce, and with the funding lock's cell deps; the shutdown by id alone and
  with its three options) written as fiber's serde wrote it and read back by its deserializers; both opening contexts
  decoded and compared with the vector's values; a literal context read field by field with the amounts and reserves in
  decimal; the largest amounts, reserves, delay and rate; `public` false even when the input says true; each option
  written on its own and never as `null`; the exact body of a shutdown through `call`, and through `shutdownChannel` with
  every option and with none, resolving with nothing, a result that is not `null` refused by its path and params it
  cannot write refused before any fetch; and `openTenantChannel` sending
  every params case and reading every result through the client, a bad param refused before any fetch, the node's refusal
  as an `RpcError`, and a result without its opening context named by its path.
- **The signing request methods against fiber**: every params case of the four (a submit with and without next material,
  the 65-byte watchtower signature) written as fiber's serde wrote it; `NoSignatureRequired` of both getters decoded and
  compared with the vector's values, which pins that fiber writes the unit variant as its tag alone; both outcomes of both
  submissions; `SignatureRequired` of the watchtower's getter under both key purposes, `Settlement` and `Tlc`, handed
  over as fiber wrote it; the status handed over untouched, the same value with its path, whatever it holds; a null next
  material left out and never sent as `null`; the exact body of all four methods through the client's own methods,
  `Applied` and `AlreadyApplied` both resolved as results, a result it cannot read named by its path, and a bad param
  refused before any fetch.
- **The registration methods against fiber**: both params cases written as fiber's serde wrote them, the signature bare;
  both tenants decoded and compared with the vector's values, which carry both runtime statuses, a tenant without a root
  signer or a channel and one with both; a literal cold and a literal active tenant read field by field; the exact body
  of both methods through the client's own methods, every registration result, the node's refusal passed through, a
  result it cannot read named by its path, and a bad param refused before any fetch.
- **One refusal per field of the eight methods, written and read**: a point of the wrong length or given as hex, a nonce
  of 65 or 67 bytes, a partial signature of 31, 33 or 64 bytes, a registration signature of 63 or 65 and a watchtower
  signature of 64 or 66, a delay or a fee rate negative, past a u64, as a number or a string, an option given as `null`
  where the type says absent, a `force` that is not a boolean, a material missing or given as a string, an announcement
  nonce or a next material left `undefined` where the type says `null`, with nothing sent; each member read missing,
  `null`, in another form, past its width or in the other spelling (a key prefixed, a hash bare, a tenant id prefixed,
  short, uppercase or empty), an unknown `type` or `runtime_status`, a lowercase or padded one, an empty access token,
  each with its full path; a result that is not an object; the members not read accepted however malformed.
- **Amounts**: every amount of the params vectors, `u128::MAX` included, written as fiber's serde wrote it and read back;
  the bounds; one refusal per malformed form.

Coverage of the module and of `wire` is 100% on all four metrics, and the assertions were checked by breaking the code on purpose:

| Mutation                                                     | Tests that failed |
| ------------------------------------------------------------ | ----------------- |
| The envelope's version is not checked                        | 54                |
| A response with both or neither of result and error is read  | 51                |
| The ids reader takes the channels from another field         | 32                |
| A payment's `created_at` is bounded to a u32                 | 28                |
| Ids start at 0                                               | 23                |
| The partial signature is checked at 64 bytes                 | 21                |
| `created_at` is bounded to a u32                             | 19                |
| The ids reader takes ids of 33 bytes                         | 19                |
| A payment hash is written without its `0x`                   | 15                |
| `encodeMapped` does not check the spelling                   | 15                |
| The fee bound is written in decimal                          | 13                |
| `get_invoice` does not read the invoice address              | 13                |
| A pubkey is read with a `0x` prefix too                      | 12                |
| The settle writes the hash in the preimage's place           | 12                |
| An empty string is not the empty flag set                    | 11                |
| A payment hash of any length is written                      | 11                |
| `assertString` accepts anything                              | 11                |
| An amount is written without checking its form               | 10                |
| The status is read as the result's `type`, not handed over   | 10                |
| The hash algorithm is written in the SDK's spelling          | 10                |
| `last_updated_at` is read from `created_at`                  | 10                |
| A submission outcome is read without checking its tag        | 9                 |
| The ids reader reads each channel whole                      | 9                 |
| The ids reader skips the hex check                           | 9                 |
| The token is not checked at construction                     | 8                 |
| The registration signature is checked at 65 bytes            | 8                 |
| The runtime status is read without checking its name         | 8                 |
| A preimage of any length is written                          | 8                 |
| `encodeMapped` writes the SDK's spelling                     | 8                 |
| The transaction encoder writes the members it read           | 7                 |
| An invoice's expiry is bounded to a u32                      | 7                 |
| The settle's answer is not checked to be an object           | 7                 |
| A missing shutdown hash is read as no hash                   | 6                 |
| A tenant id of any string is accepted                        | 6                 |
| The getter's channel id is written without checking its form | 6                 |
| The watchtower signature is checked at 64 bytes              | 6                 |
| An empty invoice address is read                             | 6                 |
| An invoice's status is not checked against fiber's           | 6                 |
| A currency missing from the client's list                    | 6                 |
| The description is not checked                               | 6                 |
| An empty hop list is written                                 | 6                 |
| A state without flags may carry `state_flags`                | 5                 |
| The remote balance is read from the local one                | 5                 |
| The registry nonce is read as bare hex                       | 5                 |
| The shutdown's `null` is not checked                         | 5                 |
| `dry_run` is omitted when false                              | 5                 |
| An invoice status missing from the client's list             | 5                 |
| A channel signature is submitted as the watchtower's         | 5                 |
| The registration is sent under the nonce's method            | 4                 |
| The params are sent as the object, not as a positional array | 4                 |
| An untyped output's `type` is omitted, not `null`            | 4                 |
| The filter writes `false` for the other flag                 | 4                 |
| The abandon's `null` is not checked                          | 4                 |
| An absent delay is sent as `null`                            | 4                 |
| The access token may be empty                                | 4                 |
| The registration signature is written with a `0x` prefix     | 4                 |
| The preimage is written without its `0x`                     | 4                 |
| An empty invoice is sent to be paid                          | 4                 |
| A payment's status is not checked against fiber's            | 4                 |
| The hops are never written                                   | 4                 |
| The registration's answer is handed over unread              | 3                 |
| The registration params are sent unwritten                   | 3                 |
| A `null` id is never accepted                                | 3                 |
| `encodeUintHex` writes a value past its bound                | 3                 |
| A pubkey is written with a `0x` prefix                       | 3                 |
| A channel id is not checked before it is written             | 3                 |
| The announcement nonce is sent as `null` when there is none  | 3                 |
| The opening context's amounts are read as u64                | 3                 |
| The shutdown's `force` is sent without checking it           | 3                 |
| The shutdown's absent close script is sent as `null`         | 3                 |
| An empty description is dropped                              | 3                 |
| The currency is not checked before it is written             | 3                 |
| A payment status fiber does not have                         | 3                 |
| A channel signature is sent unchecked                        | 3                 |
| The channel signing status is asked of the watchtower        | 3                 |
| The hops are written reversed                                | 3                 |
| The nonce is asked for under the registration's method       | 2                 |
| Every call is sent with the same id                          | 2                 |
| An error code only has to be a number                        | 2                 |
| The Bearer prefix is lowercase                               | 2                 |
| Any state's flag is accepted in any state                    | 2                 |
| A flag named twice is accepted                               | 2                 |
| Flags are split with their padding trimmed                   | 2                 |
| A `null` next material is sent as `null`                     | 2                 |
| `public` is omitted when true                                | 2                 |
| A transaction's byte lists are written unchecked             | 2                 |
| A missing description is sent as `null`                      | 2                 |
| `dryRun` is not checked to be a boolean                      | 2                 |
| A payment's fee is read as a u64                             | 2                 |
| `cancelInvoice` calls `get_invoice`                          | 2                 |
| `getPayment` calls `send_payment`                            | 2                 |
| Any submission result is read as Applied                     | 2                 |
| The ids method ignores the filter                            | 2                 |
| The hops are not checked as an array                         | 2                 |
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
| A missing root signer on the tenant status is read as `null` | 1                 |
| The opening context's reserves are read as u128              | 1                 |
| A `since` is read as a u128                                  | 1                 |
| A `capacity` is read as a u128                               | 1                 |
| The dep type is not checked before it is written             | 1                 |
| A header dep of any length is written                        | 1                 |
| An unknown filter is written                                 | 1                 |
| An outpoint index past a u32 is written                      | 1                 |
| Script args are not checked to be bytes                      | 1                 |
| A flag missing from a state's list                           | 1                 |
| A missing `failed_error` is read as no error                 | 1                 |
| `settleInvoice` does not read the answer                     | 1                 |
| `newInvoice` reads the answer as an invoice with a status    | 1                 |
| The ids method reads the full listing                        | 1                 |
| The signing status params are sent unchecked                 | 1                 |
| The signing status result is not read                        | 1                 |
| The nonce's answer is handed over unread                     | 1                 |
| A hop off the curve is written                               | 1                 |
| Five hops are refused                                        | 1                 |
| Six hops are written                                         | 1                 |

One mutant changes nothing observable and is left out: dropping the `public: false` the tenant's open writes after the
spread, since the encoder it spreads already writes it; the member stays for the literal type the wire form states.

The watchtower pair, `getWatchtowerSigningStatus` and `submitWatchtowerSignature`, and the tolerant listing,
`listChannelStates` over `decodeListChannelStatesResult`, were broken the same way (`test/tests/rpc`, still 100% on all
four metrics):

| Mutation                                                      | Tests that failed |
| ------------------------------------------------------------- | ----------------- |
| Absent flags are refused                                      | 17                |
| A listed channel id is not checked                            | 14                |
| The listing is read in reverse                                | 10                |
| Empty flags read as one empty flag                            | 8                 |
| The flags are not split                                       | 6                 |
| The watchtower signature is submitted to the channel's method | 5                 |
| The watchtower signature is written as a channel signature    | 5                 |
| The watchtower status is read from the channel's method       | 5                 |
| The watchtower status is asked with the params unwritten      | 4                 |
| An absent state reads as an empty one                         | 3                 |
| The state name is not checked to be a string                  | 3                 |
| The states are listed under another method                    | 3                 |
| The watchtower status is not read                             | 3                 |
| An entry is not checked to be an object                       | 2                 |
| The states are listed without the filter                      | 2                 |
| Null flags read as none                                       | 1                 |
| The states are read by the full reader                        | 1                 |
| The watchtower submission's result is not read                | 1                 |

`setToken`, the token replaced after construction under the same check, was broken the same way (`test/tests/rpc`,
still 100% on all four metrics):

| Mutation                                | Tests that failed |
| --------------------------------------- | ----------------- |
| The header has no Bearer prefix         | 16                |
| The token's characters are not checked  | 15                |
| A token set later is not validated      | 10                |
| A refused token clears the previous one | 9                 |
| The token's type is not checked         | 6                 |
| A token set later is ignored            | 4                 |
| The printable range admits the space    | 3                 |
| The printable range admits DEL          | 2                 |

`openTenantChannel`, the client method over the tenant opening's codec, was broken the same way (`test/tests/rpc`, still
100% on all four metrics):

| Mutation                                                  | Tests that failed |
| --------------------------------------------------------- | ----------------- |
| The opening is sent as open_channel_with_external_funding | 5                 |
| The opening's params go out unencoded                     | 4                 |
| The opening's result is handed back undecoded             | 3                 |
| The opening's result is read as an external funding's     | 3                 |

`final_expiry_delta` in `encodeNewInvoiceParams`, above zero and at most 14 days, and `assertRpcInvoiceDescription`, fiber's
639 bytes of well-formed UTF-8, were broken the same way (`test/tests/rpc`, still 100% on all four metrics). The description
left unchecked is a row of the first table, which carries this sweep's count; the guard's own string check is no row, since
`encodeWellFormedUtf8` makes the same one with the same message:

| Mutation                                                           | Tests that failed |
| ------------------------------------------------------------------ | ----------------- |
| The final expiry delta's bound is in seconds                       | 45                |
| The final expiry delta is not sent                                 | 9                 |
| The final expiry delta is sent as the invoice's expiry             | 8                 |
| The final expiry delta's bound is one millisecond short of 14 days | 7                 |
| A zero final expiry delta is sent                                  | 6                 |
| The final expiry delta is bounded to a u64                         | 6                 |
| The final expiry delta's bound is one millisecond past 14 days     | 6                 |
| A description of exactly 639 bytes is refused                      | 4                 |
| The description's bound is 640 bytes                               | 4                 |
| The description's bytes are not checked                            | 4                 |
| A lone surrogate in the description is written                     | 3                 |
| The description is measured in UTF-16 units                        | 3                 |
| The final expiry delta is written after the hash algorithm         | 2                 |
| A final expiry delta of 1 ms is refused as zero                    | 1                 |

`shutdownChannel`, the client method over the close's codec, was broken the same way (`test/tests/rpc`, still 100% on
all four metrics):

| Mutation                                               | Tests that failed |
| ------------------------------------------------------ | ----------------- |
| The shutdown is sent as abandon_channel                | 3                 |
| The shutdown's params go out unencoded                 | 3                 |
| The shutdown's answer is not read                      | 1                 |
| The shutdown's params are written as a bare channel id | 1                 |
