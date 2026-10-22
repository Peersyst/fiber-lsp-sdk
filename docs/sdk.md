# SDK

The facade: `FiberLspSdk`, the one object a wallet talks to. It is built once from the master seed and the host's
effects, wires every other module behind it, and owns what none of them could: the lifecycle the host drives, the events
the host listens to, the clock the device's indexes come from, and the list of what the device still has to ask the node
about. This document covers that core. The four operations a wallet calls, opening a channel, listing channels, creating
an invoice and paying one, are not built yet; each lands with its own section here.

## The effects it is given

The facade performs no platform call of its own. Everything that touches the outside world is injected at construction,
or defaults to what every runtime the SDK targets has:

| Option    | Interface                                | Default                                                             |
| --------- | ---------------------------------------- | ------------------------------------------------------------------- |
| `storage` | `ISignerStorage` / `IAsyncSignerStorage` | None: no key-value store is shared by Node, the browsers and Hermes |
| `fetch`   | `IFetchLike`                             | The runtime's global `fetch` ([rpc.md](./rpc.md))                   |
| `timer`   | `ITimer`                                 | The runtime's `setTimeout` and `clearTimeout`                       |
| `now`     | `() => number`                           | `Date.now`                                                          |

The test for a default is whether all three runtimes agree on it. `fetch`, `setTimeout` and `clearTimeout` pass it; the
storage does not. The timer's two functions are read from `globalThis` once, at construction, so a runtime
without them fails there with a `TypeError` and not on the first tick, and they are called without a receiver, since a
browser's `setTimeout` throws when called on anything but its window. `Date.now` is the language's and not the
platform's, so it needs no reading. No source of randomness is injected: nothing in the facade draws one, by design
(the indexes below).

`ITimer` belongs to `common`; `IFetchLike` is the rpc client's; the two storage interfaces are the store's ([persistence.md](./persistence.md)). The facade publishes all
of them, since it is the first thing that lets a host construct any of the modules behind them.

## The options

| Option           | What it is                                                                                                           |
| ---------------- | -------------------------------------------------------------------------------------------------------------------- |
| `network`        | `"mainnet"`, `"testnet"`, or `{ commitmentLock, invoiceCurrency, fundingLockCellDepsCount }` for a development chain |
| `rpcUrl`         | The node's JSON-RPC address                                                                                          |
| `biscuitToken`   | The RPC's Biscuit token; omitted when the node's RPC has no auth on, as a development chain's may                    |
| `lspPubkey`      | The LSP node's key, the peer every channel opens to, as a compressed point on the curve; copied                      |
| `pollIntervalMs` | How often the node is asked about what is watched; five seconds by default, at least one millisecond                 |
| `nonceReuse`     | `"refuse"` by default, or `"allow"`: whether a slot already served may serve a second session, never a third         |

A network preset is the commitment lock fiber ships in its node config for that chain ([digest.md](./digest.md)), the
currency its invoices carry there, `Fibb` on mainnet and `Fibt` on testnet, and the number of cell deps of the funding
lock, 2 on both. That last one is a network constant because the commitment tx carries no cell deps while fiber sizes
its fee as if it carried the funding lock's, so the device cannot read it from anything it signs; a development chain
passes all three, the count a positive integer up to `MAX_CELL_DEPS_COUNT` (255), and its code hash is copied so the
host's bytes cannot move under the device. The token is optional for the same reason the rpc client's is: a hosted node
without one fails at the first call, loudly, while a required one would make a development chain unreachable. Every
value option (the network, the url, the token, the key, the poll interval and the nonce reuse mode) is checked at
construction, with the error naming the field as the module that takes it calls it (`token`), and the master seed must
be exactly 32 bytes, checked first; of the effects, what can be checked before a call is checked (the storage's `get`
and `set`, `fetch`, the clock and the timer's `schedule` are functions). The nonce reuse mode is the policy engine's
([policy.md](./policy.md)), which checks it and names it `options.nonceReuse`. `"allow"` exists because Fiber's current
nonce lifecycle asks for a second session on the slots of a channel's opening, of each round the peer starts and of
each revocation round: under the default no channel opens against Fiber today, so a host that must work with it now sets
`"allow"`, and the mode goes once Fiber's nonces are strict. Even under `"allow"`, a round the peer starts after one of
the device's own asks for a third session on one slot, which is refused, so a channel stalls at the fulfil of a payment
it sent or at a payment received after one it fulfilled ([policy.md](./policy.md), "The known cost"). Every effect
that is a bare function (`fetch`, the clock, the runtime's timer functions) is called without a receiver, the storage
and the timer as methods of the host's own object, so none sees an SDK object as `this`. Nothing schedules or reads the storage until `connect()`.

## What gets wired

Construction builds, in order, the typed store over the storage, the policy engine over the store, the signer dispatch
over the seed, the network's commitment lock and funding lock cell deps count, and the engine ([signing.md](./signing.md)),
the rpc client over the url, the token and `fetch`, and the three pieces this document describes: the allocator and the
activity tracker over the store, and the poller over the timer. The dispatch copies the seed; the facade itself keeps
nothing of it.

Everything built is held in one context the facade's operations will share: the network, the LSP's key, the clock, the
rpc client, the engine, the dispatch, the allocator, the tracker, the poller and the facade's own `emit`. The operations
are thin entry points over that context, which is what keeps each flow a function of what it needs.

## `connect()` and `disconnect()`

`connect()` is the host's foreground and `disconnect()` its background. `connect()` starts the poller and returns: there
is no link to establish, so it cannot fail, and calling it while polling changes nothing. The device reaches the node
only through the RPC, and what the node asks of the device is read by the poller's signing step, below.

`disconnect()` never throws: it stops the poller, abandoning the step in flight so nothing of it is acted on and no tick
follows. The instance stays usable: the next `connect()` starts polling again.

## Events

`onEvent(listener)` subscribes to every event and returns the function that unsubscribes. Eight events exist:

| Event              | Payload                    | When                                                                                 |
| ------------------ | -------------------------- | ------------------------------------------------------------------------------------ |
| `CHANNEL_READY`    | `channelId`                | A channel the device opened is ready; read by the poller (not built yet)             |
| `CHANNEL_CLOSED`   | `channelId`                | A channel the device watched is closed, by any of fiber's three ways (not built yet) |
| `PAYMENT_SENT`     | `paymentHashHex`           | A payment the device started succeeded (not built yet)                               |
| `PAYMENT_FAILED`   | `paymentHashHex`, `reason` | A payment the device started failed, with fiber's text (not built yet)               |
| `PAYMENT_PENDING`  | `paymentHashHex`           | An invoice of the device has a payment held on it (not built yet)                    |
| `PAYMENT_RECEIVED` | `paymentHashHex`           | An invoice of the device was paid (not built yet)                                    |
| `SIGNING`          | see below                  | A signing request was answered or refused by the poller's signing step               |
| `ERROR`            | `error`                    | A failed poll step, or one channel's failure inside the signing step                 |

The six activity events are **at least once**: the poller emits the event and then records, in the activity list below,
the status it was emitted for, so a crash between the two repeats it on the next tick. A host deduplicates on the
event's type and id. `ERROR` is neither recorded nor repeated: it is a diagnostic.

`SIGNING` carries `channelId`, `requestId` (the node's request id, `0x`-prefixed hex as fiber writes it, so it can be
matched against the node's logs as it is; `null` when the status could not be read or answered for another channel),
`transition` (fiber's name for it, `null` in the same case) and `outcome`: `"signed"` once the node took the signature,
`"warning"` when it was signed under `nonceReuse: "allow"` as a slot's second session, or `"refused"`, which alone
carries `error`, the signer's `{ code, message }` ([signing.md](./signing.md)). Like `ERROR`, it is neither recorded nor
deduplicated: a refused request stays pending on the node and is refused again, and reported again, on every tick until
the node drops it. The same holds for a signed one: while fiber keeps offering a request it already took, or after a
submission whose answer was lost, it is signed again with the same bytes, resubmitted and announced again, so a host
that shows one notification per signature deduplicates on `requestId`.

`ERROR` exists because a poll tick that fails, a node that cannot be reached or an answer that cannot be read, has no
caller to reach. It is reported as a `poll_failed` and retried at the next tick, since the alternative is a node outage
invisible until an operation fails.

A listener that throws never breaks the facade or the other listeners; an event reaches the listeners subscribed when it
was raised, so one added on hearing it takes the next event and not that one, and one removed during it still hears that
event and nothing after.

## Errors

Every failure of the device's own is one `SdkError`, with a `code` a wallet can branch on and the module's own error
underneath as its `cause`; a host's programming error, such as an option out of range, is a `TypeError` or a
`RangeError`:

| Code                 | When                                                              | Cause       |
| -------------------- | ----------------------------------------------------------------- | ----------- |
| `poll_failed`        | A step of a poll tick, or one channel of the signing step, failed | What failed |
| `clock_before_floor` | An index was asked of a clock reading before the allocation floor | None        |

A message says what failed and then the cause's own words. The codes grow
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
whose cancel does nothing cannot fire a stale tick, since the slot that holds the armed tick ignores a callback armed
before the last clear. A host timer that throws when arming is reported as a `poll_failed` too, and ends the loop until
the next `start()`, rather than rejecting a promise nobody awaits. Today a tick runs one step, the signing step below;
the event steps, one `list_channels` for the channels, one `get_payment` per payment and one `get_invoice` per invoice,
land with the operations.

## The signing step

The node never calls the device: a request for a signature waits on the node until the device reads it. Each tick, the
signing step asks `list_channels` with no filter, which in fiber is every channel not closed, the ones still opening
included, and keeps those the policy has registered: the storage cannot list its keys, and a channel the node does not
list is one it cannot be waiting on a signature for, so hiding one only stalls the node's own channel. For each, in the
order listed, one at a time:

1. `get_channel_signing_status`. An answer for another channel than the one asked is refused as `malformed` and never
   reaches the dispatch: a status is signed only under the name it was read for.
2. The dispatch's `handle`, which decodes the status, runs every check and the claim, and signs or refuses
   ([signing.md](./signing.md)). Nothing pending is nothing done.
3. A signature goes back through `submit_channel_signature`, with the next round's material when the transition carries
   it; `Applied` and `AlreadyApplied` are both success (fiber answers the first again while the request is still
   pending, the second once it completed), and `SIGNING` is emitted after the node took it, never before. A refusal is
   emitted as `SIGNING` at once, and nothing is submitted: the request stays pending, which is the right side to fail
   on, since nothing was signed; while a TLC is pending on the channel, the node force-closes it once the earliest TLC
   nears its expiry, and a request with none stays pending until it is answered.

A channel whose status read or submission fails, or whose dispatch faults (a store failure, a bug), is reported as a
`poll_failed` naming it, and the step goes on to the next channel. Only a `list_channels` that fails fails the step,
which the poller reports as any other. The listing is read for its channel ids alone: a field the step does not use,
such as a state or a flag a newer fiber adds, cannot stop the signing. A request is answered within one interval of
being posted, against a deadline, when there is one, of TLC expiries; the step does not try to compute it. A call that
never answers holds the whole step until its deadline, and the next tick starts from the same channel: the channels
listed after it wait as long, which with fiber's one channel per tenant is no channel at all.

The run's `abandoned` is read before the dispatch, before the submission and before every event: an answer that outlived
its run acts on nothing, and the next channel is not polled. A signature abandoned before it was submitted is not lost:
the claim was persisted, so the next tick signs the same slot again, which the sign-once registry answers with the same
bytes (`already-signed`), and submits them. The same holds for a submission whose answer was lost: it is sent again and
taken as success. Under `allow`, a slot's second session resent after a cut is still a reuse to the policy, so it is
announced as a `warning` again.

## What is published

`src/index.ts` exports the facade, `FiberLspSdk`, with its options, network and event types, `SdkError` with its codes,
the event type list, the network names and the default poll interval, the nonce reuse mode, and what `SIGNING` names
(`SigningEventOutcome`, `ChannelSigningTransition`, `SignerRefusal`); the injection interfaces of the modules behind it,
`ISignerStorage`, `IAsyncSignerStorage`, `ITimer`, `IFetchLike` and their event and response types; the rpc client's
three with the `RpcMethod` they name, which a wallet meets as causes; `decodeInvoice` with the invoice types and
`InvoiceError`, since a wallet has to show what it is about to pay; and the `Script` types the options and the
operations take. Nothing else of the modules: the store, the engine, the dispatch and the rpc client are reached through
the facade alone.

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
| `src/sdk/fiber-lsp-sdk.ts`               | `FiberLspSdk`: the options checked, the wiring, `connect`, `disconnect`, the events                       |
| `src/sdk/sdk.types.ts`                   | The options, the network, the events, the error codes, the activity record, the shared context            |
| `src/sdk/sdk.constants.ts`               | The network presets, the poll interval, the allocation floor, the storage keys, the event and error lists |
| `src/sdk/sdk.error.ts`                   | `SdkError`                                                                                                |
| `src/sdk/allocator.ts`                   | `IndexAllocator`: the channel and invoice indexes from the clock, the last one persisted                  |
| `src/sdk/activity.ts`                    | `ActivityTracker`: the persisted list of what is watched, and the status each event was emitted for       |
| `src/sdk/poller.ts`                      | `ActivityPoller`: the tick, its steps and their runs and deadline, the interval, `start`, `stop`          |
| `src/sdk/signing-step.ts`                | `buildChannelSigningStep`: the channels polled, the status read, the dispatch, the submission, `SIGNING`  |
| `src/sdk/utils/runtime-timer.utils.ts`   | The timer over the runtime's `setTimeout` and `clearTimeout`                                              |
| `src/sdk/utils/network.utils.ts`         | The network option resolved to its three constants                                                        |
| `src/sdk/utils/activity-record.utils.ts` | The activity record's guard, ids and statuses per kind                                                    |
| `src/sdk/utils/failure.utils.ts`         | An `SdkError`'s message from what failed and its cause; the guarded emit and the `poll_failed` report     |
| `src/policy/signer-store.ts`             | `getRecord` and `updateRecord`, the store's records of another module's format, used by the two above     |
| `src/common/utils/assert.utils.ts`       | `assertTimerDelayMs`, `assertScriptTemplate`, `assertCompressedPoint` and `assertFunction`                |
| `src/common/utils/validate.utils.ts`     | `isCompressedPoint`, shared with the invoice codec                                                        |
| `src/common/timer-slot.ts`               | `TimerSlot`: the one armed callback the poller holds                                                      |
| `src/common/listener-set.ts`             | `ListenerSet`: the events' fan-out                                                                        |

## What the tests guarantee

`test/tests/sdk/fiber-lsp-sdk.spec.ts` pins the construction and the wiring over a timer double advanced by hand, an
in-memory storage and a `fetch` double. Beyond a happy path per feature:

- **Construction**: every option refused with the error naming the field (the seed's length and type, the url, the LSP
  key's length and type, the poll interval below one, fractional and past the timer ceiling, an unknown network, a
  development chain with a short code hash, an unknown currency or no funding lock cell deps count, a token with a
  space); the edges accepted (the default interval, the ceiling, no token, both presets, a development chain, no clock);
  nothing scheduled or read before `connect()`; the timer defaulting to the runtime's, read once, and refused when the
  runtime has none; `fetch` the same.
- **`connect()` and the poller**: ticking at the call, then at the interval; starting nothing twice; stopping at
  `disconnect()` with no timer left behind, and starting over at the next `connect()`; `disconnect()` a no-op before any
  `connect()`, idempotent, and not throwing when the host's cancel does.
- **Events**: a throwing listener leaving the others reached, an unsubscribe honoured, a listener added on hearing an
  event taking the next one.
- **Signing through the facade**, over a channel registered from the signing vectors and one tick of `connect()`: the
  testnet preset, whose commitment lock and cell deps the vectors were built under, signs with the exact submission
  body; so does the same network given as a development chain, and one whose code hash bytes the host zeroes after
  construction; mainnet and a cell deps count of 3 are refused as `malformed` with nothing submitted; a slot's second
  session is a `warning` under `allow` and refused by default and under `refuse`; `"ALLOW"`, `null` and `1` refused as
  the nonce reuse mode.

`signing-step.spec.ts` pins the step with the real dispatch over the signing vectors and a scripted node
(`test/mocks/rpc/scripted-node.mock.ts`): each of the five signable transitions submitted with the vectors' request id,
partial signature and next material (absent on the close) and announced as `signed`; the already-signed resubmission of
the same bytes, writing nothing, with `AlreadyApplied` as success; the channels in listing order and an unregistered one
skipped without a status read; a channel in a state and one with a flag no release has yet listed beside the registered
one, whose signature still goes out; the announcement and an unreadable status refused (the latter with `null` request
id and transition); a status for another channel refused as `malformed` without reaching the dispatch; a refusal
repeated on every tick; the second session a `warning` under `allow` and a third refused; nothing pending, nothing
listed; a status refused by the node, a status read that fails in transport, a submission refused, a submission result
it cannot read, a dispatch fault and a corrupt alias, each a `poll_failed` naming the channel with the next channel
still answered; a failed submission sent again with the same bytes on the next tick; a `list_channels` failure failing
the step; the run abandoned during the status read, the signature, the submission, a refusal, a mismatched answer and a
failing read, acting on nothing and polling no further channel, with the next tick submitting the same bytes; and an
emitter that throws leaving the step running. `utils/failure.utils.spec.ts` pins the guarded emit and the `poll_failed`
report with its cause.

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
field by field (the cell deps count at 1 and 255 accepted, and 0, 256, fractional, negative, absent, null, a string and a
bigint refused), the runtime timer's functions read once and called without a receiver, and the record guard's refusals
one field at a time. `signer-store.spec.ts` covers the store's generic records the same way as its typed ones.

Coverage of the module is 100% on all four metrics, and the assertions were checked by breaking the code on purpose:

| Mutation                                                                    | Tests that failed |
| --------------------------------------------------------------------------- | ----------------- |
| The channel ids are read off the full listing                               | 40                |
| Closed channels are listed too                                              | 34                |
| The next tick is armed a millisecond after the tick, not after the interval | 24                |
| Every kind shares one field                                                 | 22                |
| A null status is refused                                                    | 22                |
| A signed request's id is announced bare                                     | 20                |
| Every signature is announced as a warning                                   | 19                |
| The next material is never sent                                             | 15                |
| Steps run concurrently, not one at a time                                   | 14                |
| A poll failure carries no cause                                             | 12                |
| The cell deps bound is one lower                                            | 11                |
| A poll failure is reported under another code                               | 11                |
| The channel index is the clock in milliseconds                              | 10                |
| A development chain's cell deps count is not checked                        | 10                |
| The channels are answered in reverse order                                  | 10                |
| The facade's poller has no signing step                                     | 10                |
| The last index is handed out again when the clock stands still              | 9                 |
| The last index is ignored                                                   | 9                 |
| A failing step ends the tick                                                | 8                 |
| A failing channel fails the whole step                                      | 8                 |
| A step's deadline outlives the step                                         | 7                 |
| A refusal's request id is dropped                                           | 7                 |
| A refusal's transition is dropped                                           | 7                 |
| A stop() leaves the interval armed                                          | 6                 |
| A fractional clock is accepted                                              | 6                 |
| connect() does not start the poller                                         | 6                 |
| A failing channel ends the step                                             | 6                 |
| The interval is armed after a stop()                                        | 5                 |
| A start() after a stop() waits on the stopped tick                          | 5                 |
| The host's timer is ignored for the runtime's                               | 5                 |
| A refusal's code is reported as malformed                                   | 5                 |
| A corrupt stored last index is read as valid                                | 4                 |
| A poll interval of 0 is accepted                                            | 4                 |
| A step that never settles holds the loop                                    | 4                 |
| The record's version is not checked                                         | 4                 |
| A development chain's cell deps count is the presets'                       | 4                 |
| An emitter that throws breaks the step                                      | 4                 |
| The nonce reuse mode is not passed to the engine                            | 4                 |
| A host cancel that throws escapes stop() or pollNow()                       | 3                 |
| pollNow() ticks when stopped                                                | 3                 |
| A failed step is reported under another code                                | 3                 |
| Marking something not watched creates it                                    | 3                 |
| forget() removes nothing                                                    | 3                 |
| An unchanged record is written anyway                                       | 3                 |
| An id is not checked before the write                                       | 3                 |
| A clock before the floor is accepted                                        | 3                 |
| disconnect() leaves the poller running                                      | 3                 |
| The dispatch gets another commitment lock than the network's                | 3                 |
| The token is not passed to the rpc client                                   | 3                 |
| The presets state one cell dep                                              | 3                 |
| The dispatch gets another cell deps count than the network's                | 3                 |
| A channel the policy never registered is polled too                         | 3                 |
| An abandoned run still emits                                                | 3                 |
| A stop() mid-tick lets the remaining steps run                              | 2                 |
| A pollNow() during a tick is forgotten                                      | 2                 |
| A second start() ticks again                                                | 2                 |
| A listener that is not a function is accepted                               | 2                 |
| The host's fetch is ignored for the runtime's                               | 2                 |
| A stop() does not abandon the run in flight                                 | 2                 |
| A runtime without clearTimeout is accepted                                  | 2                 |
| An entry's id is not checked                                                | 2                 |
| A reused session is announced as signed                                     | 2                 |
| The submission is not awaited                                               | 2                 |
| A stopped tick clears the flag of the fresh one                             | 1                 |
| A null effect falls back to the runtime's default                           | 1                 |
| mark() drops an entry's unknown fields                                      | 1                 |
| A failure settled just before a stop() is reported                          | 1                 |
| A null poll interval is taken as the default                                | 1                 |
| A stop() keeps the tick a pollNow() queued                                  | 1                 |
| pollNow() leaves the interval armed beside the tick it starts               | 1                 |
| An emitter that throws breaks the loop                                      | 1                 |
| Watching again resets the status                                            | 1                 |
| A repeated status is written again                                          | 1                 |
| A listener that throws breaks delivery                                      | 1                 |
| An event reaches a listener subscribed while it is raised                   | 1                 |
| The LSP key is held by reference                                            | 1                 |
| The poller reports to nobody                                                | 1                 |
| The clock defaults to a frozen one                                          | 1                 |
| The rpc client gets another url                                             | 1                 |
| The master seed is not checked                                              | 1                 |
| A host timer that throws rejects a promise nobody awaits                    | 1                 |
| A run past its deadline is not abandoned                                    | 1                 |
| A host cancel that throws breaks the step's settlement                      | 1                 |
| A run settling late clears the one in flight, which stop() then misses      | 1                 |
| A null token is sent as `Bearer null`                                       | 1                 |
| A development chain's code hash is held by reference                        | 1                 |
| The presets' currencies are swapped                                         | 1                 |
| A development chain may state no cell deps                                  | 1                 |
| A dispatch fault is reported to nobody                                      | 1                 |
| A status for another channel is not checked                                 | 1                 |
| A status for another channel is refused and still signed                    | 1                 |
| An abandoned run polls the next channel                                     | 1                 |
| An abandoned run still reaches the dispatch                                 | 1                 |
| An abandoned run still reports a channel's failure                          | 1                 |
| An abandoned run still submits                                              | 1                 |

The `TimerSlot` the poller holds lives in `common` (`src/common/timer-slot.ts`), at 100% on all four metrics, and was swept
against `test/tests/common`. The two rows the facade's `disconnect()` once had, a throwing cancel escaping it and the
cancel called again on the next clear, are the slot's now; its other refusals stay above, read through the poller:

| Mutation                                         | Tests that failed |
| ------------------------------------------------ | ----------------- |
| A re-arm leaves the held callback scheduled      | 2                 |
| A stale callback runs when its cancel is ignored | 2                 |
| Clearing does not move the arming number         | 2                 |
| A fired callback keeps its cancel                | 1                 |
| A throwing cancel escapes                        | 1                 |
| Clearing keeps the cancel                        | 1                 |

The network's cell deps count and the dispatch's share one floor, `common`'s `assertPositiveInteger`, swept against
`test/tests/common`:

| Mutation                                | Tests that failed |
| --------------------------------------- | ----------------- |
| A positive integer may be 0             | 1                 |
| A positive integer's bound is exclusive | 1                 |

The wiring no operation reads yet (the dispatch's commitment lock, the rpc client, the LSP's key, the clock) is read
where it lands, in the facade's internal context, until the operations, once built, observe it through what they
send and sign.

The rows of the facade, the network, the runtime timer, the listener set and the poller were measured again once the
signer session and its socket left the facade, with the rows only the session exercised gone; the allocator's and the
activity's, whose code and specs that change did not touch, keep their counts.
