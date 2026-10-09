# SDK

The facade: `FiberLspSdk`, the one object a wallet talks to. It is built once from the master seed and the host's
effects, wires every other module behind it, and owns what none of them could: the lifecycle the host drives, the events
the host listens to, the clock the device's indexes come from, and the list of what the device still has to ask the node
about. This document covers that core. The four operations a wallet calls, opening a channel, listing channels, creating
an invoice and paying one, are not built yet; each lands with its own section here.

## The effects it is given

The facade performs no platform call of its own. Everything that touches the outside world is injected at construction,
or defaults to what every runtime the SDK targets has:

| Option             | Interface                                | Default                                                             |
| ------------------ | ---------------------------------------- | ------------------------------------------------------------------- |
| `storage`          | `ISignerStorage` / `IAsyncSignerStorage` | None: no key-value store is shared by Node, the browsers and Hermes |
| `webSocketFactory` | `WebSocketFactory`                       | None: the three runtimes construct a socket differently             |
| `fetch`            | `IFetchLike`                             | The runtime's global `fetch` ([rpc.md](./rpc.md))                   |
| `timer`            | `ITimer`                                 | The runtime's `setTimeout` and `clearTimeout`                       |
| `now`              | `() => number`                           | `Date.now`                                                          |

The test for a default is whether all three runtimes agree on it. `fetch`, `setTimeout` and `clearTimeout` pass it; the
storage and the socket do not. The timer's two functions are read from `globalThis` once, at construction, so a runtime
without them fails there with a `TypeError` and not on the first tick, and they are called without a receiver, since a
browser's `setTimeout` throws when called on anything but its window. `Date.now` is the language's and not the
platform's, so it needs no reading. No source of randomness is injected: nothing in the facade draws one, by design
(the indexes below), and the session's backoff jitter stays on `Math.random`, which is ECMAScript too.

`ITimer`, `IWebSocketLike` and `WebSocketFactory` are the session's ([session.md](./session.md)); `IFetchLike` is the
rpc client's; the two storage interfaces are the store's ([persistence.md](./persistence.md)). The facade publishes all
of them, since it is the first thing that lets a host construct any of the modules behind them.

## The options

| Option             | What it is                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `network`          | `"mainnet"`, `"testnet"`, or `{ commitmentLock, invoiceCurrency }` for a development chain                         |
| `rpcUrl`           | The node's JSON-RPC address                                                                                        |
| `signerSessionUrl` | The LSP's signer bridge, a WebSocket url                                                                           |
| `biscuitToken`     | The RPC's Biscuit token; omitted when the node's RPC has no auth on, as a development chain's may                  |
| `lspPubkey`        | The LSP node's key, the peer every channel opens to, as a compressed point on the curve; copied                    |
| `pollIntervalMs`   | How often the node is asked about what is watched; five seconds by default, at least one millisecond               |
| `session`          | The session's timings: connect timeout, heartbeat interval and timeout, reconnect policy; the jitter stays its own |

A network preset is the commitment lock fiber ships in its node config for that chain ([digest.md](./digest.md)) and the
currency its invoices carry there, `Fibb` on mainnet and `Fibt` on testnet; a development chain passes both, and its
code hash is copied so the host's bytes cannot move under the device. The token is optional for the same reason the rpc
client's is: a hosted node without one fails at the first call, loudly, while a required one would make a development
chain unreachable. Every value option (the network, the two urls, the token, the key, the poll interval and the
session's timings) is checked at construction, with the error naming the field as the module that takes it calls it
(`token`, `connectTimeoutMs`), and the master seed must be exactly 32 bytes, checked first; of the effects, what can be
checked before a call is checked (the storage's `get` and `set`, the socket factory, `fetch`, the clock and the timer's
`schedule` are functions), so a missing one is refused here rather than as a session that reconnects forever. The
session's options are passed field by field, so its jitter's draw stays its own, and every effect that is a bare
function (the socket factory, `fetch`, the clock, the runtime's timer functions) is called without a receiver, the
storage and the timer as methods of the host's own object, so none sees an SDK object as `this`. Nothing connects,
schedules or reads the storage until `connect()`.

## What gets wired

Construction builds, in order, the typed store over the storage, the policy engine over the store, the signer dispatch
over the seed, the network's commitment lock and the engine ([signing.md](./signing.md)), the wallet identity over the
seed, the session over the socket factory, the timer, the identity as its authenticator and the dispatch as its handler,
the rpc client over the url, the token and `fetch`, and the three pieces this document describes: the allocator and the
activity tracker over the store, and the poller over the timer. The dispatch copies the seed and the identity derives
its key from it; the facade itself keeps nothing of the seed.

Everything built is held in one context the facade's operations will share: the network, the LSP's key, the clock, the
rpc client, the engine, the dispatch, the session, the allocator, the tracker, the poller and the facade's own `emit`.
The operations are thin entry points over that context, which is what keeps each flow a function of what it needs.

## `connect()` and `disconnect()`

`connect()` is the host's foreground and `disconnect()` its background, the mapping the session was designed for
([session.md](./session.md)). `connect()` starts the poller and asks the session to connect; it resolves once the session
is established and rejects with a `connect_failed` error, the `SessionError` underneath as its cause, when it cannot be:
a refused handshake, a protocol version the device does not speak, an authenticator that cannot answer, or a
`disconnect()` that came first. Called while established it resolves at once; called while the session is
reconnecting it cuts the backoff short, which is what a host calling it on every foreground gets.

The poller runs between `connect()` and `disconnect()` whatever becomes of the session. The two links are independent:
the RPC needs no signer bridge, and a bridge that is down keeps the session reconnecting and `connect()` pending, which
must not stop a wallet from seeing its channels and payments move. So a rejected `connect()` leaves the poller running
too, until `disconnect()`, and a host that wants everything stopped calls that.

`disconnect()` never throws: it stops the poller, abandoning the step in flight so nothing of it is acted on and no tick
follows, and closes the session, which rejects whoever was waiting on it. The instance stays usable: the next
`connect()` starts both again. `sessionState` reads the session's state at any time, for a wallet's first render before
any event arrived.

## Events

`onEvent(listener)` subscribes to every event and returns the function that unsubscribes. Eight events exist:

| Event              | Payload                    | When                                                                                 |
| ------------------ | -------------------------- | ------------------------------------------------------------------------------------ |
| `SESSION`          | `state`                    | Each transition of the signer session, as it is announced                            |
| `CHANNEL_READY`    | `channelId`                | A channel the device opened is ready; read by the poller (not built yet)             |
| `CHANNEL_CLOSED`   | `channelId`                | A channel the device watched is closed, by any of fiber's three ways (not built yet) |
| `PAYMENT_SENT`     | `paymentHashHex`           | A payment the device started succeeded (not built yet)                               |
| `PAYMENT_FAILED`   | `paymentHashHex`, `reason` | A payment the device started failed, with fiber's text (not built yet)               |
| `PAYMENT_PENDING`  | `paymentHashHex`           | An invoice of the device has a payment held on it (not built yet)                    |
| `PAYMENT_RECEIVED` | `paymentHashHex`           | An invoice of the device was paid (not built yet)                                    |
| `ERROR`            | `error`                    | The session's errors, fatal ones too (which also reject `connect()`), a failed step  |

The six polled events are **at least once**: the poller emits the event and then records, in the activity list below,
the status it was emitted for, so a crash between the two repeats it on the next tick. A host deduplicates on the
event's type and id. `SESSION` and `ERROR` are neither recorded nor repeated: one is state, read again from
`sessionState`, the other a diagnostic.

`ERROR` exists because two kinds of failure have no caller to reach. The session reports errors that end nothing, a
frame that does not decode, a socket error, a lost connection on its way to reconnecting, the device's own fault while
answering a sign request (the storage's error, a corrupt record), which leaves that request unanswered, and the fatal
ones besides, which also reject the `connect()` that was waiting; the facade forwards each as a `session_error`, with
the session's cause underneath. And a poll tick that fails, a node that cannot be reached or an answer that cannot be
read, is reported as a `poll_failed` and retried at the next tick, since the alternative is a node outage invisible
until an operation fails. The state is announced before the error on a lost socket, so a listener always reads the new
state when it learns why.

A listener that throws never breaks the facade or the other listeners; an event reaches the listeners subscribed when it
was raised, so one added on hearing it takes the next event and not that one, and one removed during it still hears that
event and nothing after.

## Errors

Every failure of the device's own is one `SdkError`, with a `code` a wallet can branch on and the module's own error
underneath as its `cause`; a host's programming error, such as an option out of range, is a `TypeError` or a
`RangeError`:

| Code                 | When                                                              | Cause                                            |
| -------------------- | ----------------------------------------------------------------- | ------------------------------------------------ |
| `connect_failed`     | `connect()` could not establish the session                       | `SessionError`                                   |
| `session_error`      | The session reported an error, fatal or not, as an `ERROR` event  | `SessionError`, the socket's, the device's fault |
| `poll_failed`        | A step of a poll tick failed, as an `ERROR` event                 | What the step threw                              |
| `clock_before_floor` | An index was asked of a clock reading before the allocation floor | None                                             |

A message says what failed and then the cause's own words, with a `SessionError`'s kind between the two. The codes grow
with the operations; a wrong argument at construction is a `TypeError` or a `RangeError` naming the field, as everywhere
in the SDK, since it is the host's programming error and not a condition of the device's.

## Indexes that a wipe cannot reset

Every channel's secrets derive from its index ([derivation.md](./derivation.md)), and nothing the node holds can re-seed
it. A persisted counter would read zero after a wipe, hand index 0 to the next channel, and sign its first commitment
with the nonce the old channel 0 used for another message: both partial signatures reach the same peer, and the funding
key of both channels is recovered. So **the index is the time**: a channel index is the clock in whole seconds, never
below one past the last index handed out, `max(floor(now / 1000), last + 1)`, and a hold invoice's index the same in
milliseconds, under a sequence of its own. Within one installation `last` makes each sequence strictly increasing
whatever the clock does; after a wipe the clock has moved on, so a new index is above every one the old installation
handed out, with nothing recorded and nothing asked of the node, which is who would gain from an index looking free.

`last` is written before the index is returned, in the key's own lane of the store, so two concurrent allocations never
share one and the registration that follows never leaves the device ahead of the record of its index. The one way to
land twice on a value is a clock that restarts from a fixed date after a wipe, so a reading before `ALLOCATION_FLOOR_MS`,
2026-10-01T00:00:00Z until the release sets it, is refused as `clock_before_floor`: that is the device's clock being
wrong, a condition a wallet shows. A reading that is not a whole number of milliseconds is the host's `now` being wrong,
a `TypeError`. A stored `last` that does not read as an index throws rather than starting over from the clock, as every
record of the store does. The alternatives, a random index (a fourth effect, and an index no recovery could ever search
for) and a counter floored by the node's listing (the node decides), were rejected on purpose; a time index keeps the
door to a recovery by search open without walking through it, since fiber reports each channel's `created_at`.

A burst of opens within one second runs `last` ahead of the clock by as many seconds as there were opens, and a wipe
inside that window would collide; every open is a blocking RPC of seconds, so the window does not exist in practice. It
is stated, not defended against.

## What is watched, and the poller

The storage cannot be enumerated, so whatever the poller still has to ask about is listed under one key: the channels
not yet closed, the payments not yet final and the invoices not yet paid, cancelled or expired, each by the id the node
knows it under (the channel id; the payment hash in hex) and with the last status an event was emitted for, `null` until
the first. An entry is added when the operation that creates it starts watching, marked each time an event goes out, and
dropped when it is final; a channel id is 32 bytes of 0x-prefixed lowercase hex, the one form `list_channels` is read
in, so no entry can sit unmatched for good, a payment hash exactly 32 bytes of lowercase hex, and a status one of
fiber's for that kind, which the record's guard pairs at every write. Marking something not watched is a programming
error and throws; watching something again keeps its entry, status included; dropping what is not there writes nothing.

The poller walks that list. `start()` ticks at once, then arms the next tick for the interval after each tick completes,
so a slow node never overlaps two ticks while its steps keep their deadline, and never shortens the pause between them.
A tick runs its steps in order, one at a time, and runs every one of them even when another fails: each failure is
reported as a `poll_failed` error and the rest still run, since a channel read that keeps failing must not starve the
invoice step that settles held payments. Each step has thirty seconds (`POLL_STEP_TIMEOUT_MS`): one that has not settled
by then is reported as a `poll_failed` and the tick moves on, since the default `fetch` has no timeout of its own and a
request hung across a trip to the background would otherwise hold every later tick, and a `stop()` and `start()` with
it. The call itself cannot be stopped and may still answer, so each step is handed its run, whose `abandoned` turns true
at the deadline or on a `stop()`: a step reads it before every `emit` and every `mark`, and an answer that outlived its
run acts on nothing. `stop()` cancels the armed tick and abandons the step in flight, whose tick ends at once, runs no
further step and arms nothing; a `start()` right after begins a fresh tick rather than wait on the stopped one. An extra
tick can be asked for at once, which the operations do after a `send_payment` or a `settle_invoice` rather than wait out
the interval; asked during a tick, it queues exactly one more, and a host cancel that throws does not stop it. A timer
whose cancel does nothing cannot fire a stale tick, for the reason the session's timers cannot
([session.md](./session.md)). A host timer that throws when arming is reported as a `poll_failed` too, and ends the loop
until the next `start()`, rather than rejecting a promise nobody awaits. The steps themselves, one `list_channels` for
the channels, one `get_payment` per payment and one `get_invoice` per invoice, land with the operations; today the list
is empty and a tick does nothing but arm the next.

## What is published

`src/index.ts` exports the facade, `FiberLspSdk`, with its options, network and event types, `SdkError` with its codes,
the event type list, the network names and the default poll interval; the injection interfaces of the modules behind it,
`ISignerStorage`, `IAsyncSignerStorage`, `IWebSocketLike`, `WebSocketFactory`, `ITimer`, `IFetchLike` and their event
and response types; the session's state, reconnect policy and two errors, and the rpc client's three with the
`RpcMethod` they name, which a wallet meets as causes; `decodeInvoice` with the invoice types and `InvoiceError`, since
a wallet has to show what it is about to pay; and the `Script` types the options and the operations take. Nothing else
of the modules: the store, the engine, the dispatch, the session and the rpc client are reached through the facade
alone.

## What the facade deliberately does not do

- **No operation yet.** Opening a channel, listing channels, creating an invoice and paying one are not built yet.
- **No app state.** The host calls `connect()` and `disconnect()`; the facade does not know whether the app is open.
- **No retry of a call.** Whether a lost answer is read back from the node is each operation's decision, with the
  rpc client's three errors telling it what it may conclude ([rpc.md](./rpc.md)).
- **No public poll.** The extra tick is the operations' to ask for; whether a wallet's pull-to-refresh gets a method is
  for the API review.
- **No history.** The facade reports what it is tracking; past payments are the node's.

## Where it lives

| File                                     | Contents                                                                                                  |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `src/sdk/fiber-lsp-sdk.ts`               | `FiberLspSdk`: the options checked, the wiring, `connect`, `disconnect`, `sessionState`, the events       |
| `src/sdk/sdk.types.ts`                   | The options, the network, the events, the error codes, the activity record, the shared context            |
| `src/sdk/sdk.constants.ts`               | The network presets, the poll interval, the allocation floor, the storage keys, the event and error lists |
| `src/sdk/sdk.error.ts`                   | `SdkError`                                                                                                |
| `src/sdk/allocator.ts`                   | `IndexAllocator`: the channel and invoice indexes from the clock, the last one persisted                  |
| `src/sdk/activity.ts`                    | `ActivityTracker`: the persisted list of what is watched, and the status each event was emitted for       |
| `src/sdk/poller.ts`                      | `ActivityPoller`: the tick, its steps and their runs and deadline, the interval, `start`, `stop`          |
| `src/sdk/utils/runtime-timer.utils.ts`   | The timer over the runtime's `setTimeout` and `clearTimeout`                                              |
| `src/sdk/utils/network.utils.ts`         | The network option resolved to its two constants                                                          |
| `src/sdk/utils/activity-record.utils.ts` | The activity record's guard, ids and statuses per kind                                                    |
| `src/sdk/utils/failure.utils.ts`         | An `SdkError`'s message from what failed and its cause                                                    |
| `src/policy/signer-store.ts`             | `getRecord` and `updateRecord`, the store's records of another module's format, used by the two above     |
| `src/common/utils/assert.utils.ts`       | `assertTimerDelayMs`, `assertScriptTemplate`, `assertCompressedPoint` and `assertFunction`                |
| `src/common/utils/validate.utils.ts`     | `isCompressedPoint`, shared with the invoice codec and the session guard                                  |
| `src/common/listener-set.ts`             | `ListenerSet`: the events' fan-out, shared with the session                                               |

## What the tests guarantee

`test/tests/sdk/fiber-lsp-sdk.spec.ts` pins the construction and the wiring over a socket double, and
`fiber-lsp-sdk.flow.spec.ts` drives the facade against the real `InMemorySignerBridge` of the session flows, over a
timer double advanced by hand, an in-memory storage and a `fetch` double, with the wallet identity of the vectors.
Beyond a happy path per feature:

- **Construction**: every option refused with the error naming the field (the seed's length and type, the two urls, the
  LSP key's length and type, the poll interval below one, fractional and past the timer ceiling, an unknown network, a
  development chain with a short code hash or an unknown currency, a token with a space, a session timing of zero); the
  edges accepted (the default interval, the ceiling, no token, both presets, a development chain, no session options, no
  clock); nothing connected, scheduled or read before `connect()`; the timer defaulting to the runtime's, read once,
  and refused when the runtime has none; `fetch` the same.
- **`connect()`**: the session established under the identity the bridge verifies and pins, with the state sequence
  announced; the node's request answered through the dispatch over the policy, an unknown channel refused as such;
  another seed being another identity; resolving at once when established; `connect_failed` with the session's kind
  and message on a refused identity, on another protocol version, and on a `disconnect()` that comes first; the fatal
  failure reaching the listeners too; connecting again after `disconnect()` and after a refusal; a `connect()` from
  reconnecting cutting the backoff short.
- **The poller**: ticking at the call of `connect()`, before the session is established, then at the interval; ticking
  while the session reconnects and after a rejected `connect()`; stopping at `disconnect()` with no timer left behind,
  and starting over at the next `connect()`.
- **`disconnect()`**: the session closed with its reason and announced; a no-op before any `connect()`; idempotent.
- **Events**: the session's non-fatal error forwarded as `session_error` with its cause and the session left up; a socket
  error with and without words; the state before the error on a lost socket; a throwing listener leaving the others
  reached, an unsubscribe honoured, a listener added on hearing an event taking the next one; `sessionState` following
  the session.

`allocator.spec.ts` pins the floor to 2026-10-01T00:00:00Z and the key prefix, the first index as the clock in seconds
and in milliseconds, one past the last index while the clock stands still, goes back, or stands at the floor, the clock
followed once past the last index, the two sequences apart, the last index picked up by a later instance, the write
landing before the promise resolves on both storages, three readings before the floor refused as `clock_before_floor`
and eight readings that are not whole milliseconds refused as the host's error, all writing nothing, the clock read on
every allocation, eight corrupt stored values throwing with the value kept, the bound reached and then refused, a
storage failure propagated, and concurrent allocations distinct under an asynchronous storage without the two kinds
waiting on each other.

`activity.spec.ts` pins the key, the empty record read without a write, the record's JSON literally, the entry kept with
its status on a repeated watch, the kinds apart for one id, a repeated status writing nothing, marking something not
watched or watched under another kind refused, each kind's id and status refused before the storage is touched, the
removal keeping the others, idempotent, and writing nothing for what is not there, seven corrupt stored records throwing
on a read and on an update alike with the value kept, unknown fields kept, a storage failure propagated, and concurrent
updates losing nothing. `poller.spec.ts` pins the tick at start and the steps in order, the next tick at the exact
interval measured from the end of a held step, one step at a time, no step at all, a failing step reported as
`poll_failed` with its cause and the next step and tick still run, a step that throws synchronously and a cause that is
not an error, an emitter that throws leaving the loop, `stop()` cancelling the interval, abandoning the step in flight
and running no further step, idempotent, and immune to a timer whose cancel does nothing, `start()` after `stop()`
ticking again at once, the stopped tick reporting and arming nothing, and the extra tick now, queued once during a tick,
dropped by a `stop()` and never carried across one. The utils specs pin the presets' code hashes, the network refusals
field by field, the runtime timer's functions read once and called without a receiver, and the record guard's refusals
one field at a time. `signer-store.spec.ts` covers the store's generic records the same way as its typed ones.

Coverage of the module is 100% on all four metrics, and the assertions were checked by breaking the code on purpose:

| Mutation                                                                    | Tests that failed |
| --------------------------------------------------------------------------- | ----------------- |
| Steps run concurrently, not one at a time                                   | 8                 |
| A stop() mid-tick lets the remaining steps run                              | 1                 |
| The interval is armed after a stop()                                        | 2                 |
| A pollNow() during a tick is forgotten                                      | 1                 |
| The next tick is armed a millisecond after the tick, not after the interval | 18                |
| A second start() ticks again                                                | 1                 |
| A start() after a stop() waits on the stopped tick                          | 4                 |
| A stopped tick clears the flag of the fresh one                             | 1                 |
| A host cancel that throws escapes stop() or pollNow()                       | 3                 |
| A host cancel that throws escapes disconnect() and leaves it half done      | 4                 |
| A null effect falls back to the runtime's default                           | 5                 |
| A null session timing is taken as the default                               | 3                 |
| mark() drops an entry's unknown fields                                      | 1                 |
| A failure settled just before a stop() is reported                          | 1                 |
| disconnect() closes the session before stopping the poller                  | 1                 |
| A null poll interval is taken as the default                                | 1                 |
| A listener that is not a function is accepted                               | 2                 |
| A stop() leaves the interval armed                                          | 6                 |
| A stop() keeps the tick a pollNow() queued                                  | 1                 |
| pollNow() ticks when stopped                                                | 1                 |
| pollNow() leaves the interval armed beside the tick it starts               | 1                 |
| A failed step is reported under another code                                | 1                 |
| An emitter that throws breaks the loop                                      | 1                 |
| A failing step ends the tick                                                | 5                 |
| Watching again resets the status                                            | 1                 |
| Marking something not watched creates it                                    | 3                 |
| A repeated status is written again                                          | 1                 |
| forget() removes nothing                                                    | 3                 |
| An unchanged record is written anyway                                       | 3                 |
| Every kind shares one field                                                 | 22                |
| An id is not checked before the write                                       | 3                 |
| The last index is handed out again when the clock stands still              | 9                 |
| The last index is ignored                                                   | 9                 |
| The channel index is the clock in milliseconds                              | 10                |
| A clock before the floor is accepted                                        | 3                 |
| A fractional clock is accepted                                              | 6                 |
| A corrupt stored last index is read as valid                                | 4                 |
| connect() does not start the poller                                         | 8                 |
| connect() rethrows the session's error bare                                 | 3                 |
| disconnect() leaves the poller running                                      | 4                 |
| disconnect() leaves the session up                                          | 7                 |
| The session's state is never announced                                      | 9                 |
| The session's errors are dropped                                            | 4                 |
| A listener that throws breaks delivery                                      | 1                 |
| An event reaches a listener subscribed while it is raised                   | 1                 |
| A poll interval of 0 is accepted                                            | 1                 |
| The LSP key is held by reference                                            | 1                 |
| The poller reports to nobody                                                | 1                 |
| The clock defaults to a frozen one                                          | 1                 |
| The dispatch gets another commitment lock than the network's                | 2                 |
| The rpc client gets another url                                             | 1                 |
| The host's fetch is ignored for the runtime's                               | 2                 |
| The token is not passed to the rpc client                                   | 2                 |
| The host's timer is ignored for the runtime's                               | 7                 |
| The session options are not passed through                                  | 3                 |
| The master seed is not checked                                              | 1                 |
| The session gets the host's whole object, its jitter included               | 1                 |
| A host timer that throws rejects a promise nobody awaits                    | 1                 |
| A step that never settles holds the loop                                    | 2                 |
| A step's deadline outlives the step                                         | 2                 |
| A run past its deadline is not abandoned                                    | 1                 |
| A stop() does not abandon the run in flight                                 | 1                 |
| A host cancel that throws breaks the step's settlement                      | 1                 |
| A run settling late clears the one in flight, which stop() then misses      | 1                 |
| A host cancel that throws is called again on the next clear                 | 2                 |
| A null token is sent as `Bearer null`                                       | 4                 |
| A development chain's code hash is held by reference                        | 1                 |
| The presets' currencies are swapped                                         | 1                 |
| A runtime without clearTimeout is accepted                                  | 2                 |
| The record's version is not checked                                         | 4                 |
| An entry's id is not checked                                                | 2                 |
| A null status is refused                                                    | 22                |

The wiring no operation reads yet (the dispatch's commitment lock, the rpc client, the LSP's key, the clock) is read
where it lands, in the facade's internal context, until the operations, once built, observe it through what they
send and sign.
