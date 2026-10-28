# SDK

The facade: `FiberLspSdk`, the one object a wallet talks to. It is built once from the master seed and the host's
effects, wires every other module behind it, and owns what none of them could: the lifecycle the host drives, the events
the host listens to, the clock the device's indexes come from, and the list of what the device still has to ask the node
about. This document covers that core, the tenant's registration and token, the opening of a channel and the events that
follow it, the listing of the channels, the evidence of a channel, and a payment received on a hold invoice, from its
creation to its settlement. Of the four operations a wallet calls, opening a channel, listing channels and creating an
invoice are built; paying one is not yet, and lands with its own section here.

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

| Option           | What it is                                                                                                                      |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `network`        | `"mainnet"`, `"testnet"`, or `{ commitmentLock, fundingLock, invoiceCurrency, fundingLockCellDepsCount, millisecondsPerEpoch }` |
| `rpcUrl`         | The node's JSON-RPC address                                                                                                     |
| `biscuitToken`   | The RPC's Biscuit token; omitted when the node's RPC has no auth on, or until the tenant registers                              |
| `lspPubkey`      | The LSP node's key, the peer every channel opens to, as a compressed point on the curve; copied                                 |
| `pollIntervalMs` | How often the node is asked about what is watched; five seconds by default, at least one millisecond                            |
| `nonceReuse`     | `"refuse"` by default, or `"allow"`: whether a slot already served may serve a second session, never a third                    |
| `watchtower`     | `{ destination, maxFeeShannons }`, what the watchtower's spends may pay; omitted, every spend is refused                        |

A network preset is the commitment lock and the funding lock fiber ships in its node config for that chain
([digest.md](./digest.md)), the currency its invoices carry there, `Fibb` on mainnet and `Fibt` on testnet, and the
number of cell deps of the funding lock, 2 on both. The funding lock is a template, a code hash and a hash type: its args
are each channel's own, computed from the two funding keys, and the opening holds the node's funding cell to it (below). That count is a network constant because the commitment tx carries no cell deps while fiber sizes its
fee as if it carried the funding lock's, so the device cannot read it from anything it signs. So is the length of an
epoch in milliseconds, fiber's `MILLI_SECONDS_PER_EPOCH`, which the signing deadline ([signing.md](./signing.md)) and the
margin of a hold invoice's release ([The invoice step](#the-invoice-step)) are computed with: fiber's build sets it, 4 hours in release (14,400,000, both presets) and 2 seconds in
debug, which is what a development chain run from a debug build passes, and nothing the device reads states it. A
development chain passes all five, both locks templates of any of CKB's four hash types, the count a positive integer up
to `MAX_CELL_DEPS_COUNT` (255), the epoch's length a positive integer up to `Number.MAX_SAFE_INTEGER`, and both code
hashes are copied so the host's bytes cannot move under the device. The token is optional for the same reason the rpc client's is: a hosted node without one fails at the first
call, loudly, while a required one would make a development chain unreachable; and a device only gets its tenant token
once it registers, which it may do after construction (`setBiscuitToken`, below). Every value option (the network, the
url, the token, the key, the poll interval and the nonce reuse mode) is checked at construction, with the error naming
the field as the module that takes it calls it (`token`), and the master seed must be exactly 32 bytes, checked first;
of the effects, what can be checked before a call is checked (the storage's `get` and `set`, `fetch`, the clock and the
timer's `schedule` are functions). The nonce reuse mode is the policy engine's ([policy.md](./policy.md)), which checks
it and names it `options.nonceReuse`. `"allow"` exists because Fiber's current nonce lifecycle asks for a second session
on the slots of a channel's opening, of each round the peer starts and of each revocation round: under the default no
channel opens against Fiber today, so a host that must work with it now sets `"allow"`, and the mode goes once Fiber's
nonces are strict. Even under `"allow"`, a round the peer starts after one of the device's own asks for a third session
on one slot, which is refused, so a channel stalls at the fulfil of a payment it sent or at a payment received after one
it fulfilled ([policy.md](./policy.md), "The known cost"). Every effect that is a bare function (`fetch`, the clock, the
runtime's timer functions) is called without a receiver, the storage and the timer as methods of the host's own object,
so none sees an SDK object as `this`. Nothing schedules or reads the storage until `connect()`.

The `watchtower` option, `SdkWatchtowerOptions`, is what the host approves a watchtower's spends for after a force close:
`destination`, the `Script` every spend must pay, and `maxFeeShannons`, decimal shannons within a u64, how far below what
an unlock releases the destination may be paid ([policy.md](./policy.md)). It is the policy engine's, which checks it,
naming each field `options.watchtower.destination` and `options.watchtower.maxFeeShannons`, and copies it. Without it every
spend the node's watchtower asks for is refused, and the funds stay in the commitment lock's cell; the only destination
fiber's watchtower pays today is the LSP node's own lock, and approving it is trusting the LSP after a force close
([signing.md](./signing.md)).

## What gets wired

Construction builds, in order, the typed store over the storage, the policy engine over the store, the nonce reuse mode
and the watchtower's approval, the signer dispatch over the seed, the network's commitment lock, funding lock cell deps
count and epoch length, and the engine ([signing.md](./signing.md)), the rpc client over the url, the token and `fetch`,
the tenant identity over the seed ([signing.md](./signing.md)), and the pieces this document describes: the allocator,
the activity tracker and the pending opening's store (`PendingOpeningStore`) over the store, the hold invoices' preimages
(`HoldInvoicePreimages`, [signing.md](./signing.md)) over the seed, and the poller over the timer and its four steps, the
channel step first, then the signing step, the watchtower step and the invoice step. The dispatch and the preimages each
copy the seed, and the identity keeps only the key it derives from it; the facade holds the seed through nothing else.

Everything built is held in one context the facade's operations share: the network, the LSP's key, the clock, the
store, the rpc client, the engine, the dispatch, the identity, the preimages (`preimages`), the allocator, the tracker,
the pending opening's store (`openings`), the poller and the facade's own `emit`. The operations are thin entry points over that context, which is what keeps each flow a function of what it
needs.

## `connect()` and `disconnect()`

`connect()` is the host's foreground and `disconnect()` its background. `connect()` starts the poller and returns: there
is no link to establish, so it cannot fail, and calling it while polling changes nothing. The device reaches the node
only through the RPC, and what the node asks of the device and what became of its channels and its invoices are read by
the poller's four steps, below.

`disconnect()` never throws: it stops the poller, abandoning the step in flight so nothing of it is acted on and no tick
follows. The instance stays usable: the next `connect()` starts polling again.

## Events

`onEvent(listener)` subscribes to every event and returns the function that unsubscribes. Ten events exist:

| Event                | Payload                    | When                                                                                 |
| -------------------- | -------------------------- | ------------------------------------------------------------------------------------ |
| `CHANNEL_READY`      | `channelId`                | A channel the device opened is ready; read by the poller's channel step              |
| `CHANNEL_CLOSED`     | `channelId`                | A channel the device watched is closed, under any flag, an aborted opening included  |
| `PAYMENT_SENT`       | `paymentHashHex`           | A payment the device started succeeded (not built yet)                               |
| `PAYMENT_FAILED`     | `paymentHashHex`, `reason` | A payment the device started failed, with fiber's text (not built yet)               |
| `PAYMENT_PENDING`    | `paymentHashHex`           | An invoice of the device has a payment held on it; read by the poller's invoice step |
| `PAYMENT_RECEIVED`   | `paymentHashHex`           | An invoice of the device was paid with the preimage it released                      |
| `PAYMENT_EXPIRED`    | `paymentHashHex`           | An invoice of the device ended unpaid, its preimage never released                   |
| `SIGNING`            | see below                  | A signing request was answered or refused by the poller's signing step               |
| `WATCHTOWER_SIGNING` | see below                  | A watchtower spend was signed or refused by the poller's watchtower step             |
| `ERROR`              | `error`                    | A failed poll step, or the failure of one channel or one invoice inside a step       |

The three payment events of an invoice name it by its payment hash as `createInvoice` returned it, `0x` lowercase hex, and
are the invoice step's ([The invoice step](#the-invoice-step) says when each goes out). The seven activity events are
**at least once**: the poller emits the event and then records, in the activity list below,
the status it was emitted for, so a crash between the two repeats it on the next tick. A host deduplicates on the
event's type and id. `ERROR` is neither recorded nor repeated: it is a diagnostic.

`CHANNEL_READY` is fiber's `ChannelReady`, seen once: a channel that leaves it for `ShuttingDown` is not announced again
until it closes. `CHANNEL_CLOSED` is fiber's `Closed` under any flag, a cooperative close, either force close, an
abandon, and an opening fiber aborted unfunded (`FUNDING_ABORTED`), which only the listing of the pending channels
still shows; it may follow a `CHANNEL_READY` or come without one. Both are the channel step's (below).

`SIGNING` carries `channelId`, `requestId` (the node's request id, `0x`-prefixed hex as fiber writes it, so it can be
matched against the node's logs as it is; `null` when the status could not be read or answered for another channel),
`transition` (fiber's name for it, `null` in the same case), `outcome`: `"signed"` once the node took the signature,
`"warning"` when it was signed under `nonceReuse: "allow"` as a slot's second session, or `"refused"`, which alone
carries `error`, the signer's `{ code, message }` ([signing.md](./signing.md)), and, on any of the three, `deadlineMs`
when there is one. `deadlineMs` is the moment, in milliseconds since the epoch and comparable with `now()`, from which
fiber force-closes the channel if the request is still unanswered: present only on the two commitment transitions whose
snapshot lists at least one TLC, with the channel's delay pinned. Its absence means the device cannot compute one, not
that fiber has none: a revocation, the close, or a fulfil's commitment (which no longer lists the TLC it removes) still
falls under fiber's deadline while a TLC's removal is unconfirmed. It is an upper bound, since fiber counts every TLC
not confirmed removed and the request only the commitment's, so fiber may force-close earlier, never later; on a refused
request the expiries are the node's own statement, which nothing checked, so the bound holds only as far as the node is
honest. It is reported for a wallet to show, never acted on, and the dispatch computes it ([signing.md](./signing.md)).
Past `Number.MAX_SAFE_INTEGER` it is the nearest number, a date some 285,000 years away. `SIGNING` is, like `ERROR`,
neither recorded nor deduplicated: a refused request stays pending on the node and is refused again, and reported again,
on every tick until the node drops it. The same holds for a signed one: while fiber keeps offering a request it already
took, or after a submission whose answer was lost, it is signed again with the same bytes, resubmitted and announced
again, so a host that shows one notification per signature deduplicates on `requestId`.

`WATCHTOWER_SIGNING` carries `channelId`, `requestId` (in the same form, `null` in the same case), `purpose` (the key the
spend needs, `{ kind: "settlement" }` or `{ kind: "tlc", commitmentNumber }`, `null` in the same case) and `outcome`:
`"signed"` once the node took the signature, or `"refused"`, which alone carries `error` ([policy.md](./policy.md) lists
the watchtower's refusals). It follows `SIGNING`'s rules: neither recorded nor deduplicated, a refused spend reported on
every tick while it waits, and a signed one announced again when its submission is sent again, or when fiber rebuilds a
spend of an unlock already signed under a new request id, so a host deduplicates on `requestId`.

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

| Code                 | When                                                                                                      | Cause                       |
| -------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------- |
| `poll_failed`        | A step of a poll tick, or one channel or invoice of a step, failed                                        | What failed                 |
| `clock_before_floor` | An index was asked of a clock reading before the allocation floor                                         | None                        |
| `unknown_channel`    | An operation named a channel this device never registered                                                 | None                        |
| `opening_rejected`   | The node's answer to an opening is not what the device asked; the message names the field                 | None                        |
| `opening_conflict`   | The node's answer contradicts the device's record: a registration or a pin the policy refuses             | The policy's error          |
| `funding_tx_altered` | The signed funding tx is not the one the opening froze, or the channel pins no funding cell to compare to | The pin's conflict, or none |
| `invoice_rejected`   | The node's invoice string is not the invoice the device asked for; the message names the field            | The decoder's, or none      |

A message says what failed and then the cause's own words. The codes grow with the operations; a wrong argument is a
`TypeError` or a `RangeError` naming the field, as everywhere in the SDK, since it is the host's programming error and
not a condition of the device's. The amount of an opening is the policy's to bound, so one out of range is its
`RangeError`, naming `fundedShannons`.

What is not a condition of the device's comes through as its own error, unwrapped: the node's answers, through the rpc
client's three errors ([rpc.md](./rpc.md)), on an opening, a submission, a listing and an invoice's creation; the
policy's own refusal of an invoice record it cannot take; the host's own effects, a storage
that throws or a record or alias it holds that the store refuses to read, wherever one is read, `channelEvidence`
included; on an opening, whatever the host's signer throws; and on a submission, a signed tx that does not read as a
transaction, a `TypeError` naming `signedTx`. An opening the device refuses drops its pending opening first, and when that
drop fails the refusal keeps its code and its cause, its message ending with "the pending opening could not be dropped"
and the drop's own words ([Opening a channel](#opening-a-channel)).

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
in, so no entry sits unmatched for its form (a channel neither of the node's listings shows still stays watched, below),
a payment hash exactly 32 bytes of lowercase hex, and a status one of
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
tick can be asked for at once, which the invoice step does after a `settle_invoice` rather than wait out the interval,
and a payment will after its `send_payment`; asked during a tick, it queues exactly one more, and a host cancel that throws does not stop it. A timer
whose cancel does nothing cannot fire a stale tick, since the slot that holds the armed tick ignores a callback armed
before the last clear. A host timer that throws when arming is reported as a `poll_failed` too, and ends the loop until
the next `start()`, rather than rejecting a promise nobody awaits. Today a tick runs four steps, in this order: the
channel step, the signing step, the watchtower step and the invoice step, below, each with its own listing and its own
thirty seconds, so a slow read in one cannot spend another's. Each step answers what it polls one at a time through
`answerEachPolled`, which stops at an abandoned run and reports one item's failure as a `poll_failed` naming it before it
goes on to the next. The payment step, one `get_payment` per payment, lands with its operation.

## The channel step

The channel step turns what the node lists into `CHANNEL_READY` and `CHANNEL_CLOSED` for the channels the activity list
watches, which the opening adds (below). It reads that list first and, when no channel is watched, calls nothing. Otherwise
it asks `list_channels` once with `include_closed`, read through `listChannelStates` for the ids and states alone, any
state name or flag accepted ([rpc.md](./rpc.md)), and settles each watched channel the listing shows, in the node's
order, one at a time:

- `ChannelReady`, unless that is the status last announced: `CHANNEL_READY`, then the pending opening that names the
  channel dropped, then the status recorded.
- `Closed`, under any flag or none: `CHANNEL_CLOSED`, then the pending opening that names it dropped, then the channel
  no longer watched.
- Any other state, one a newer fiber adds included: nothing, and the channel stays watched.

Fiber deletes an opening it aborted unfunded and leaves it out of that listing; it shows it, `Closed` with
`FUNDING_ABORTED`, only to `only_pending` ([rpc.md](./rpc.md)). So when a watched channel is missing from the first
listing, the step asks `only_pending` once in the tick, for every channel missing at once and not after its run was
abandoned, and settles what it shows the same way. A channel neither listing shows emits nothing and stays watched, so
it costs that second read on every tick: no answer of the node's says the channel is gone, and dropping it on a
silence would lose its close.

The events are at least once, as everywhere: each is emitted only while the run stands and before anything is written,
and the run's `abandoned` is read again after it, so an event whose run was cut while it went out (a listener that calls
`disconnect()`, say) is not recorded and goes out again on the next tick; no channel is settled once the run is
abandoned. A watched channel whose drop or record fails is reported as a `poll_failed` naming it, its event repeated on
the next tick, and the next channel is settled; only a watched list that cannot be read, or a listing that fails, fails
the step.

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
being posted, against a deadline, when there is one, of TLC expiries; the step reports it on `SIGNING` and never waits
on it or hurries for it. A call that
never answers holds the whole step until its deadline, and the next tick starts from the same channel: the channels
listed after it wait as long, which with fiber's one channel per tenant is no channel at all.

The run's `abandoned` is read before the dispatch, before the submission and before every event: an answer that outlived
its run acts on nothing, and the next channel is not polled. A signature abandoned before it was submitted is not lost:
the claim was persisted, so the next tick signs the same slot again, which the sign-once registry answers with the same
bytes (`already-signed`), and submits them. The same holds for a submission whose answer was lost: it is sent again and
taken as success. Under `allow`, a slot's second session resent after a cut is still a reuse to the policy, so it is
announced as a `warning` again.

## The watchtower step

After a force close the node's watchtower spends the commitment cell one unlock at a time, each spend waiting on the
device's signature ([signing.md](./signing.md)). The step runs after the signing step, in the same tick, and lists the
channels itself with `include_closed`: a force-closed channel is the one the watchtower spends from, and fiber's default
listing hides it once closed. The listing is `listChannelStates`, read for the ids and the states alone, any state name or
flag accepted ([rpc.md](./rpc.md)). It skips only a `Closed` channel flagged `COOPERATIVE`, `ABANDONED` or
`FUNDING_ABORTED` (`WATCHTOWER_UNWATCHED_CLOSE_FLAGS`): fiber deletes the watch row on a cooperative close and on a failed
opening, which may hold one since its collaboration. A state or a flag the SDK does not know is polled, since polling
costs a read and skipping might leave a spend unsigned. For each channel the policy has registered, in the order listed,
one at a time:

1. `get_watchtower_signing_status`. Before `RemoteTxComplete` fiber holds no watch row for the channel, and answers
   `-32000` with "watched channel not found" (`WATCHTOWER_UNWATCHED_ERROR`, `rpc/watchtower.rs:386-391`); on a channel
   that is not `Closed` that answer is read as nothing pending, rather than a `poll_failed` on every tick of an opening.
   On a closed one it is a failure. An answer for another channel than the one asked is refused as `malformed`, with
   neither request id nor purpose, and never reaches the dispatch.
2. The dispatch's `handleWatchtower`, which decodes the status, runs the watchtower's rules and the claim, and signs or
   refuses ([signing.md](./signing.md)). Nothing pending is nothing done.
3. A signature goes back through `submit_watchtower_signature`; `Applied` and `AlreadyApplied` are both success. Then
   the spend is marked applied, `PolicyEngine.markWatchtowerSpendApplied`, unless the dispatch signed it unclaimed, and
   `WATCHTOWER_SIGNING` is emitted. A refusal is emitted at once and nothing is submitted: the spend stays pending, and
   the funds where they are.

A channel whose registration, status read, submission or mark fails, or whose dispatch faults, is reported as a
`poll_failed` naming it, and the step goes on to the next channel; only a listing that fails, or that the client cannot
read, fails the step. The run's `abandoned` is read before the dispatch, before the submission and before every event, as
in the signing step, with one exception: the mark after a submission is written even once the run is abandoned, because
fiber never serves an applied request again, so a mark skipped there would never come. A signature abandoned before its
submission is not lost: the claim was written, and the next tick answers the same request with the signature recorded.

## The tenant's registration

A device is a tenant of the hosted LSP once its RootSigner, the key the master seed derives as the wallet identity
([signing.md](./signing.md)), is registered there. The facade signs and the host calls: the two registration methods take
the operator's token, so the host or its backend makes them ([rpc.md](./rpc.md)), never the facade.

- `rootSignerPubkey`, the RootSigner's 33-byte compressed key, a copy on every read: the key the host asks
  `lsp_get_tenant_registry_nonce` for.
- `tenantId`, fiber's tenant id of that key (`TenantId::from_root_signer_pubkey`), 64 lowercase hex characters.
- `signTenantRegistration(challenge)` takes the nonce's result decoded to bytes, `SdkTenantChallenge`
  (`{ lspNodeId, rootSignerPubkey, nonce }`), and returns `SdkTenantRegistration`, the params of `lsp_register_tenant`
  (`{ rootSignerPubkey, nonce, signature }`, the signature 64 bytes of compact ECDSA) plus `tenantId`, bytes of its own.
  It is synchronous, calls nothing and writes nothing. It refuses, with a `TypeError` naming the field, a challenge that
  is not an object; a `lspNodeId` absent, not bytes, not 33 bytes, not a point, or not the `lspPubkey` the facade was
  built with (compared with its own copy), since a nonce another LSP issued is no registration with this one; then, as
  the identity does, a `rootSignerPubkey` that is not this device's, and a nonce that is not 32 bytes. The LSP is checked
  first, so a challenge wrong on both names the LSP.

`setBiscuitToken(token)` hands the token `lsp_register_tenant` returned to the rpc client, which puts it on the next call
on, the poller's included; a token the client refuses (not printable ASCII without spaces) throws its `TypeError` and
leaves the previous one ([rpc.md](./rpc.md)). It takes no `null`: the token is replaced, never removed. Before handing it
over, the host checks that the `tenant.tenant_id` the registration returned is the facade's `tenantId`, as fiber's own
client does (`finish_registration`): the facade sees only the token, so it cannot tell a token issued to another tenant.

## Opening a channel

On fiber's side a tenant channel opens in two calls: `open_tenant_channel` blocks while the node agrees the channel with
the LSP and answers with the funding tx it froze, and `submit_signed_funding_tx` takes that tx signed
([rpc.md](./rpc.md)). The facade has three methods over them:

- `prepareChannelOpen(amountShannons, userLock, userLockCellDeps?)` asks the node for a channel to the LSP, checks and
  pins its answer, and returns `SdkChannelOpening`, `{ channelId, unsignedFundingTx, openingContext }`: the node's answer
  as just read, which the device does not hold, so writing to it changes nothing the device keeps.
- `submitFundingTx(channelId, signedTx)` hands the node the funding tx the host signed, once it is the one the opening
  froze. It settles once the node took the tx; `CHANNEL_READY` tells when the channel is ready.
- `openChannel(amountShannons, userLock, signFundingInputs, userLockCellDeps?)` is the two joined, the host's signer in
  between, and returns the channel id once the node took the signed tx.

The first two serve a host that signs outside the call (a hardware wallet, a backend, a user who confirms later).
`amountShannons` is what the user pays in, in decimal shannons, the device's reserve included, as fiber's `local_amount`
counts it. `userLock` is the lock whose cells fund the channel and also the device's shutdown script, so every close pays
the device's side back to the lock that funded it, and the registration pins it as the close script
([policy.md](./policy.md)). Both are checked before anything is allocated, written or sent, the amount as decimal
shannons and the lock as a script, then as an opening the policy accepts (`assertChannelOpening`: from the device's
least reserve over that lock to below a u64), and copied, so nothing the host changes during the call reaches the node
or the pins.

### What the device asks

The request names the LSP's key as the peer and carries the amount, the user's lock as both `shutdown_script` and
`funding_lock_script`, the lock's cell deps when given, the commitment delay and fee rate, and the device's signer
material for the channel's index ([signing.md](./signing.md), "The public material"); the channel is private, as every
tenant channel is ([rpc.md](./rpc.md)).

The delay and the fee rate are fiber's own defaults, sent explicitly: one epoch (`DEFAULT_COMMITMENT_DELAY_EPOCH`,
`0x10000000001` as fiber's `EpochNumberWithFraction`) and 1000 shannons per kilobyte (`DEFAULT_COMMITMENT_FEE_RATE`).
Left to the node, the answer would state values the device has nothing to hold to; sent, the answer must repeat them.

`userLockCellDeps` are the cell deps the node needs to spend the user's lock. Fiber builds the funding tx over the
user's cells, and without them it resolves only the chain's genesis scripts, so a lock outside them cannot fund the
channel ([rpc.md](./rpc.md)). Each is checked as a cell dep and refused by its position before anything is written. An
empty list is none, as fiber reads it, so it is neither sent nor recorded; their order is part of the request.

### The check of the answer

The node answers with the channel's id, the unsigned funding tx and the opening context, the terms it froze, each read
for its form by the rpc client ([rpc.md](./rpc.md)). `checkTenantOpening` then holds them to what was asked, before
anything of them is written; every failure is `opening_rejected`, naming the field. In order:

1. The peer's TLC base key, the context's `remoteSettlementKey`, is a point on the curve and not the device's own, and
   the channel id is fiber's id of the two TLC base keys, `tenantChannelId` ([digest.md](./digest.md)).
2. The commitment delay and the fee rate are the ones sent.
3. `localAmountShannons` is the amount funded.
4. The device's reserve is `reservedCkbShannons` over the user's lock under one of the two lock layouts, and the peer's
   is the same over its `remoteShutdownScript` under a layout the device's matched: one layout for both
   ([policy.md](./policy.md)).
5. The local amount is at least the device's reserve, and the remote amount at least the peer's.
6. Output 0 of the funding tx (`FUNDING_OUTPUT_INDEX`) exists, with no type script and empty data.
7. The peer's funding key, the context's `remoteFundingKey`, is a point on the curve and not the device's own, and
   output 0's lock is the network's funding lock over the args of the two funding keys, `fundingLockArgs`
   ([digest.md](./digest.md)).
8. The two amounts together fit a u64, and output 0's capacity is exactly them.

Every other output and every input is left alone: the tx carries both parties' inputs and their change, which the device
cannot judge without the chain, so they are the host signer's to check (below). The check returns what the policy pins:
the terms and the funding cell's capacity.

### The pins, before the tx is handed out

Fiber may ask for the device's signature of the peer's first commitment before the funding tx is signed, so everything
the signing gate holds the channel to is written before the tx leaves the device, in this order:

1. The pending opening is named with the channel id (below).
2. `registerChannel`, with the opening's index, the amount and the user's lock as the close script.
3. `pinChannelTerms`: the fee rate, the peer's reserve, the liquid capacity (the two amounts less both reserves), and the
   peer's funding key, its TLC base key and the delay, the values the check held ([policy.md](./policy.md)).
4. `pinFundingCell`: output 0 of the unsigned tx, by CKB's hash of the tx, and its capacity. The hash covers the raw tx
   and not the witnesses, so it is the hash of the tx signed as well.
5. The channel is watched, so the channel step announces it.

Once registered, the channel is served by the signing step, so its first commitments are signed while the host holds the
tx. A registration or a pin the policy refuses, a `ChannelRegistrationError` (the id already another index's, the index
another channel's, a lost race for the name) or a `ChannelPinError`, is `opening_conflict` with the policy's error as its
cause: the node's answer contradicts what the device recorded. Any other failure, a storage that throws or a record it
cannot read, passes through as itself.

### The pending opening

Fiber keeps one opening per tenant: it answers the identical request, signer material and nonces included, with the
result it froze, and refuses another while the first is open ("tenant already has a different channel opening"). An
opening whose answer never reached the device is therefore recovered only by sending the same request again, which
takes the same index. So the device records the opening, under `fiber-lsp-sdk:opening`, before it asks
([persistence.md](./persistence.md)):

- **Fresh.** With no pending opening asked with the same amount, lock and cell deps, a fresh index is allocated and the
  opening written under it with no channel yet, replacing any other; while fiber still holds that other one, it
  refuses the fresh request as "a different channel opening" until it aborts it.
- **Resumed.** A pending opening asked with the same three, the cell deps compared in order, is resumed under its index,
  and the request sent again is identical, since the material is a function of the index. When it already names a
  channel, the node is first asked `only_pending`: a channel it shows `Closed` was aborted, so the opening is dropped and
  a fresh one starts; any other answer resumes it, and a listing that fails passes through and keeps it.
- **Named** right after the check passes and before the registration, so an opening that fails past that point carries
  the id that lets the next same call find it aborted.
- **Dropped** when the device refuses the answer, `opening_rejected` or `opening_conflict`, by its index, so an opening
  another call wrote meanwhile survives; and by the channel step, by its id, once the channel is ready or closed.
- **Kept** on every failure of the request itself. Fiber answers an open interrupted after 30 seconds with "tenant opening
  interrupted; retry the same request" (`rpc/channel.rs:345-370`) and a stopped one with "tenant channel opening
  stopped" (`network.rs:8366-8370`), both keeping the opening on its side; neither can be told from a lost answer or any
  other error, and a final refusal retried only meets the refusal again.

An opening given up for good is not the device's to cancel: fiber aborts one left unfunded once its external funding
timeout passes (`external_funding_timeout_seconds`, 300 by default), the channel step announces `CHANNEL_CLOSED` for it
if it was watched, and the next same call opens afresh under a new index.

| Failure                                               | Error                                                             | The pending opening                               |
| ----------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------- |
| An argument, the signer included                      | `TypeError`, or the policy's `RangeError` naming `fundedShannons` | Untouched: nothing written or sent                |
| The index's allocation                                | `clock_before_floor`                                              | Untouched                                         |
| `only_pending`, resuming a named one                  | The rpc client's                                                  | Kept                                              |
| `open_tenant_channel`, its answer unreadable included | The rpc client's                                                  | Kept                                              |
| The check                                             | `opening_rejected`                                                | Dropped                                           |
| A registration or pin the policy refuses              | `opening_conflict`                                                | Dropped                                           |
| The storage                                           | Its own                                                           | Kept as last written                              |
| The host's signer, in `openChannel`                   | Its own                                                           | Kept, named; the channel registered and watched   |
| The submission                                        | Below                                                             | Kept, until the channel step sees ready or closed |

A drop that fails leaves the refusal its code and its cause, its message saying the opening could not be dropped and why;
the next same call drops the leftover again, or finds it aborted.

### The host's signer

`SdkSignFundingInputs`, `(unsignedFundingTx: Transaction) => Promise<Transaction>`, is checked to be a function with
the other arguments, before anything is written or sent, called without a receiver, and handed a copy of the tx as the
node froze it, each input's witness the 65 zero bytes a secp256k1 signature takes. The device judged the funding cell alone: it cannot read the chain, so it
knows neither the cells the inputs spend nor what they hold, and the change outputs, the user's and the LSP's, are what
those amounts decide. Resolving each input and checking what it pays, that what the user's inputs hold, less the amount
funded and the fee, comes back to the user, and that the fee is one the user accepts, is therefore the signer's duty,
before it signs. It returns the tx with its witnesses signed and nothing else changed: a tx changed anywhere but its
witnesses is refused at submission, since the funding cell is pinned by the tx's hash. What it throws comes through as itself, with
the opening kept, so the identical call resumes it.

### The submission

`submitFundingTx(channelId, signedTx)` checks, in order: the channel id's form, 32 bytes of `0x` lowercase hex, a
`TypeError`; the signed tx's form, an object whose witnesses are a list of byte arrays and which hashes as a CKB
transaction, each a `TypeError` naming `signedTx`, with the hash's own refusal as its cause; the channel's record,
`unknown_channel` for one this device never registered; a funding cell pinned with its capacity, else
`funding_tx_altered`; and the tx's hash against the pinned out point, through the same `pinFundingCell`, so the frozen
hash writes nothing and another is `funding_tx_altered`, the pin's conflict naming both cells as its cause. The tx is
copied in the step it is hashed, so the node receives what was compared. Then `submit_signed_funding_tx`, whose errors
pass through unwrapped, fiber's "Repeated processing message: Signed funding tx has already been submitted" to a second
submission included. `openChannel` submits through the same path.

## Listing the channels

`listChannels()` asks `list_channels` with `include_closed` and returns one `SdkChannelInfo` per channel, in the node's
order: `channelId`, `state`, the four balances in decimal shannons as the rpc client reads them
(`localBalanceShannons`, `remoteBalanceShannons`, `offeredTlcBalanceShannons`, `receivedTlcBalanceShannons`), and
`hasRecord`, whether this device registered the channel, read from its store. A channel without a record is one the node
holds for the tenant that the device never filed, such as an opening whose answer was lost before it reached the
device. The state is one of five, `SDK_CHANNEL_STATES`:

| State     | Fiber's states                                                                                                      |
| --------- | ------------------------------------------------------------------------------------------------------------------- |
| `opening` | `NegotiatingFunding`, `CollaboratingFundingTx`, `SigningCommitment`, `AwaitingTxSignatures`, `AwaitingChannelReady` |
| `ready`   | `ChannelReady`                                                                                                      |
| `closing` | `ShuttingDown`                                                                                                      |
| `closed`  | `Closed`, under any flag                                                                                            |
| `stale`   | `Stale`: a channel fiber restored from an old database, audited with the peer before it resumes                     |

The map is keyed by every state the rpc client knows, so one added there fails to compile until it is mapped; a state
the client does not know is refused by its listing ([rpc.md](./rpc.md)) rather than guessed. An opening fiber aborted is
not listed, since fiber deleted it: `CHANNEL_CLOSED` is what reported it. The node's errors and the store's pass through
unwrapped, and nothing is written.

## A channel's evidence

`channelEvidence(channelId)` reads, from the device's own store, what the record keeps of a channel for a wallet to show
or an agent to write out, `SdkChannelEvidence`, every hex value `0x`-prefixed and lowercase as fiber's JSON writes it:

- `revocations`, the complete revocation signatures of the peer's commitments, `{ version, forRemote, signature }`,
  ascending by version ([signing.md](./signing.md), "The revocation evidence"); `forRemote` is a `boolean` in the
  published type though the record keeps only `true`, so the type survives a revocation of the device's own;
- `commitments`, `{ local, remote }`, each view's last signed commitment as `{ commitmentNumber, txHash }` or `null`,
  `txHash` being fiber's `compute_tx_message` of the tx as signed, not the hash the chain shows;
- `watchtowerSignatures`, the watchtower's spends the device signed, `{ requestId, purpose, signature, applied }`, in the
  order it claimed them, `applied` once fiber took the signature; a spend claimed and never signed is left out.

The channel is named under any id the node gave it, as lowercase `0x` hex of 32 bytes; anything else is a `TypeError`. A
channel the device never registered is an `SdkError` `unknown_channel`, and a name that resolves to an index holding no
record, which only a broken store leaves, the policy's own `TypeError` for it. A storage that throws, or a record or
alias the store refuses to read, comes through as its own error, not wrapped in an `SdkError`. Nothing is written, and
the evidence is a copy: writing to it changes neither the record nor the next read.

## Receiving a payment

A payment reaches the device on a hold invoice: the node holds the payment it receives until the device hands it the
preimage, and the device hands it over only once its channels hold the payment ([policy.md](./policy.md), "The hold
invoice's release"). The preimage of the invoice of index `k` derives from the master seed ([derivation.md](./derivation.md)),
so no secret is stored: the policy's record of the invoice keeps `k` ([persistence.md](./persistence.md)).

### Creating an invoice

`createInvoice(amountShannons, options?)` returns `SdkInvoice`, `{ invoice, paymentHashHex }`: the node's string, checked,
the one to show the payer, and the payment hash in `0x` lowercase hex, the form the payment events carry. The options,
`SdkInvoiceOptions`, are `{ description?, expirySeconds? }`.

The arguments are checked before anything is allocated, written or sent, each option read once so the value checked is the
value sent: the amount decimal shannons above zero, as the policy's record requires (zero is a `RangeError`); the options an object; the description a string of at most 639 bytes of
well-formed UTF-8, fiber's bound, through the rpc client's guard ([rpc.md](./rpc.md)), so a description fiber would refuse
never costs an index; the expiry a whole number of seconds from 1 to `Number.MAX_SAFE_INTEGER`, which keeps the invoice's
end within the u64 of milliseconds fiber's registration of it demands, and one hour (`DEFAULT_SDK_INVOICE_EXPIRY_SECONDS`)
when omitted: fiber has no default, and a tenant's invoice without an expiry fails after its row is stored. Then, in order:

1. An invoice index is allocated, the clock in milliseconds ([Indexes that a wipe cannot reset](#indexes-that-a-wipe-cannot-reset)).
2. The payment hash is the ckb-hash of that index's preimage, from the preimages ([signing.md](./signing.md)).
3. `recordHoldInvoice` records the hash, the amount, ckb-hash and the index in the policy, before the node hears of the
   hash ([policy.md](./policy.md)).
4. `new_invoice` with the amount, the network's currency, the hash, `hash_algorithm` sent as ckb-hash so the string's
   attribute is held to it, the expiry, the description when there is one, and a `final_expiry_delta` of 24 hours
   (`SDK_INVOICE_FINAL_EXPIRY_DELTA_MS`).
5. The host's clock is read once the node answered, without a receiver, and must be a whole number of milliseconds up to
   `Number.MAX_SAFE_INTEGER` (a `RangeError` otherwise): the timestamp the node wrote is judged against a later reading.
6. `checkTenantInvoice` holds the string to what was asked (below).
7. The invoice is watched under its hash, so the invoice step follows it.

The final delta is fiber's `DEFAULT_FINAL_TLC_EXPIRY_DELTA`, the one its own suite sends. Left out, fiber's `new_invoice`
writes its minimum, two thirds of its default commitment delay (160 minutes in a release build), and fiber fails a
received TLC once its expiry is within two thirds of the channel's delay and 60 seconds of now (`channel.rs:3474-3507`):
a payment under that delta would arrive with no margin left to release it. It is not an option: a delta shorter than the
release's margin ([The invoice step](#the-invoice-step)) would leave every payment of the invoice unreleasable.

| Failure                                       | Error                                    | What is left                           |
| --------------------------------------------- | ---------------------------------------- | -------------------------------------- |
| An argument                                   | `TypeError` or `RangeError`, by its name | Nothing: nothing read, written or sent |
| The index's allocation                        | `clock_before_floor`                     | Nothing                                |
| The record                                    | The policy's or the storage's own        | The index spent                        |
| `new_invoice`, its answer unreadable included | The rpc client's                         | The record, unwatched                  |
| The clock after the answer                    | `RangeError`                             | The record, unwatched                  |
| The check                                     | `invoice_rejected`                       | The record, unwatched                  |
| The watch                                     | The storage's own                        | The record, unwatched                  |

The record stays on every failure after it is written. It is harmless: nobody pays an invoice the host never received,
and one never watched is never released. A retry allocates another index, so another hash and another record.

### The check of the string

Fiber signs a tenant's invoice with a key of the tenant's that the LSP generated and keeps (`tenant_pubkey`,
`rpc/invoice.rs:107-118`), not with the LSP's, and writes a trampoline route hint to the LSP, its feature bit and the
final delta on every tenant invoice (`rpc/invoice.rs:184-197`). `checkTenantInvoice` holds the string to that shape and to
what the device asked, before the host is handed it; every failure is `invoice_rejected`, naming the field or the
attribute, in this order:

1. The string decodes ([invoice.md](./invoice.md)). The decoder refuses every string fiber's encoder would not have written
   for what it carries, and a signature not by the payee key the invoice carries, so it is the canonicity check; its
   refusal is the cause.
2. The currency is the network's.
3. The amount is the one asked.
4. The timestamp is no later than the device's clock plus 10 minutes (`SDK_INVOICE_TIMESTAMP_SKEW_MS`). Fiber measures
   the expiry from the timestamp, so a later one stretches the invoice past the expiry asked; the tolerance is for the
   two clocks differing. An earlier one passes, since it only shortens the invoice.
5. The payment hash is the one derived.
6. `hashAlgorithm` is present and ckb-hash.
7. `expiryTime` is the expiry asked.
8. `finalHtlcMinimumExpiryDelta` is the 24 hours sent.
9. The description is the one asked, an empty one included, and absent when none was.
10. `feature` is exactly `0x20`, trampoline routing's optional bit, the one fiber's hint sets
    (`invoice/invoice_impl.rs:103-106`): another bit changes what the payer does.
11. `trampolineRouteHint` names the facade's `lspPubkey`.
12. `payeePublicKey` is present; the decoder already held the signature to it.
13. No attribute of another type: the accepted types are the seven fiber writes for a tenant, the description only when
    asked. They are judged as a set and not by their order, which fiber does not promise to keep, and the decoder already
    refuses a type twice.

The payee key is not pinned: it is the tenant key the LSP holds, which reaches the device in no answer the facade reads.
It need not be, because only the device's preimage opens a TLC of the hash, and the release requires the device's own
channels to hold the payment.

### The invoice step

The invoice step runs fourth in the tick, after the signing and watchtower steps, since the release reads the commitments
they just signed. It reads the activity list and, when no invoice is watched, calls nothing. Otherwise it asks
`get_invoice` for each watched invoice in turn and answers its status:

- **`Open`**: nothing, and the invoice stays watched. Fiber itself answers an `Open` invoice past its expiry as `Expired`.
- **`Received`**: fiber's word that a payment of the invoice is committed in both of the tenant's commitments
  (`channel.rs:1323-1352`). `PAYMENT_PENDING` goes out the first time, then the status is recorded, and the release is
  tried on every tick the invoice stays `Received`:
  1. The record is read (`readHoldInvoice`), and the index it keeps must derive the watched hash, before anything is marked
     or settled: a record whose index derives another hash is a `TypeError`, a `poll_failed`, and is never released.
  2. A record already released is settled again, nothing judged and no tick asked: fiber takes a settlement again while
     the invoice is `Received`, which repairs a stop between the mark and the settlement.
  3. Otherwise `markHoldInvoiceReleased` judges the release ([policy.md](./policy.md)), with the host's clock, read at
     most once for the invoice in the tick, and the margin a held TLC's expiry must clear past it:
     `tlcExpiryDelay(the channel's pinned delay, millisecondsPerEpoch)` ([signing.md](./signing.md)), two thirds of the
     delay as fiber computes it, plus `SDK_RELEASE_EXPIRY_SLACK_MS`, 10 minutes, which covers fiber's 60-second check of
     its channels and the ticks the poller takes to sign the fulfil before fiber would fail the TLC.
  4. Once marked, `settle_invoice` hands the node the preimage. Fiber stores it, gives it to its watchtower and queues the
     fulfil, whose requests the device then signs, so the step asks the poller for a tick at once (`pollNow`).
- **`Paid`**: fiber's word that the fulfil was applied. `PAYMENT_RECEIVED`, then the invoice is no longer watched.
- **`Expired`** or **`Cancelled`**: `PAYMENT_EXPIRED`, then the invoice is no longer watched. A tenant has no
  `cancel_invoice` (`rpc/tenant.rs:22-44`), so a cancelled one is the operator's doing.

A release that waits, `not_held`, `expiry_too_close` or `offered_in_flight`, is no failure: no event, and the release is
tried again on the next tick, while a payment still arrives in one view or an offered TLC beside it resolves. Any other
refusal, `algorithm_mismatch` among them, never resolves on its own and is a `poll_failed`. A waiting release ends the
invoice when it can no longer be paid: past its expiry and with no view of any channel it lists still showing a TLC of it
(`listsHoldInvoiceTlc`), it is `PAYMENT_EXPIRED` and no longer watched. Fiber keeps an invoice whose TLC failed
`Received` for good (`network.rs:4432-4437`), so nothing else would end it. The expiry is fiber's `is_expired`, read off
the string `get_invoice` returns, decoded and held to the watched hash: past it once the timestamp plus the expiry is
strictly below the clock's reading the release took, so the exact millisecond is not past it, and an invoice without an
expiry never is.

`PAYMENT_EXPIRED` therefore comes three ways: fiber reports the invoice `Expired`, an `Open` one past its expiry; fiber
reports it `Cancelled`; or it stays `Received` past its expiry with no TLC of it left. In all three the preimage never left
the device. Two statuses contradict the record, and each is a `poll_failed` naming the invoice on every tick, with no
event and the invoice still watched: a `Paid` invoice whose preimage the device never released, since only that preimage
pays it, and an `Expired` or `Cancelled` one whose preimage it released, since the preimage may still pay it, and it is
settled again should fiber report it `Received`.

A settlement fiber answers with `-32000` and "Invoice is already paid" (`SDK_INVOICE_ALREADY_PAID_ERROR`,
`network.rs:4854`), which it does once the fulfil is applied, is the settlement done: `Paid` confirms it on the next tick.
Any other refusal, under that code with another message included, is a `poll_failed`.

The events are at least once, as everywhere: each is emitted only while the run stands and before its mark or its drop,
so one whose run was cut goes out again on the next tick. The run's `abandoned` is read before every event, mark,
release, settlement and `pollNow`. A failure of one invoice, its read, a status the client does not know, its record, the
release, its settlement or its mark, is a `poll_failed` naming it by its `0x` hash, and the next invoice is answered; only
an activity list that cannot be read fails the step.

## What is published

`src/index.ts` exports the facade, `FiberLspSdk`, with its options, network and event types, `SdkError` with its codes,
the event type list, the network names and the default poll interval, the nonce reuse mode, the watchtower option
(`SdkWatchtowerOptions`), the registration's two forms (`SdkTenantChallenge`, `SdkTenantRegistration`), the opening's
forms (`SdkChannelOpening`, `SdkSignFundingInputs`, and the rpc client's `TenantChannelOpeningContext` the opening hands
back), the listing's (`SdkChannelInfo`, `SdkChannelState`, `SDK_CHANNEL_STATES`), the evidence
(`SdkChannelEvidence`), the invoice's (`SdkInvoice`, `SdkInvoiceOptions`, which `createInvoice` takes and returns through
the class), and what `SIGNING` and `WATCHTOWER_SIGNING` name (`SigningEventOutcome`,
`ChannelSigningTransition`, `WatchtowerKeyPurpose`, `SignerRefusal`); the injection interfaces of the modules behind it,
`ISignerStorage`, `IAsyncSignerStorage`, `ITimer`, `IFetchLike` and their event and response types; the rpc client's
three with the `RpcMethod` they name, which a wallet meets as causes; `decodeInvoice` with the invoice types and
`InvoiceError`, since a wallet has to show what it is about to pay; and the chain's types the options and the operations
take and return, `Script` with its template and hash type, and `Transaction` with `CellDep`, `CellInput`, `CellOutput`,
`DepType` and `OutPoint`. Nothing else of the modules: the store, the engine, the dispatch and the rpc client are reached
through the facade alone.

## What the facade deliberately does not do

- **No payments yet.** Paying an invoice is not built yet.
- **No invoice cancelled.** Fiber gives a tenant no `cancel_invoice`; an invoice never paid ends at its expiry, as
  `PAYMENT_EXPIRED`.
- **No check of the funding inputs.** The device holds the funding cell to what it asked; what the inputs spend, the
  change and the fee are the host signer's, which can read the chain.
- **No operator call.** The facade signs the registration and takes the token; the two calls that need the operator's
  token are the host's.
- **No deadline acted on.** `SIGNING`'s `deadlineMs` is reported, and every request is answered when it is seen.
- **No app state.** The host calls `connect()` and `disconnect()`; the facade does not know whether the app is open.
- **No automatic retry.** Whether a lost answer is read back from the node is each operation's decision, with the rpc
  client's three errors telling it what it may conclude ([rpc.md](./rpc.md)). An opening whose request failed stays
  pending, and its resume is the host's identical call: the facade never resends on its own, nor cancels an opening,
  which fiber aborts when left unfunded.
- **No public poll.** The extra tick is the operations' to ask for; whether a wallet's pull-to-refresh gets a method is
  for the API review.
- **No history.** The facade reports what it is tracking; past payments are the node's.

## Where it lives

| File                                     | Contents                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/sdk/fiber-lsp-sdk.ts`               | `FiberLspSdk`: the options checked, the wiring, `connect`, `disconnect`, the events, the registration, the token, the opening's three methods, the listing, the evidence, `createInvoice`                                                                                                                                        |
| `src/sdk/channel-opening.ts`             | `prepareSdkChannelOpen`, `submitSdkFundingTx` and `openSdkChannel`: the arguments, the request, the resume, the check's verdict, the pins, the refusals and the drop, the submission's checks                                                                                                                                    |
| `src/sdk/utils/opening-check.utils.ts`   | `checkTenantOpening`: the node's answer held to what was asked, each failure `opening_rejected`                                                                                                                                                                                                                                  |
| `src/sdk/pending-opening.ts`             | `PendingOpeningStore`: the pending opening's record, read, matched, written, named and dropped; `assertUserLockCellDeps`                                                                                                                                                                                                         |
| `src/sdk/channel-step.ts`                | `buildChannelStep`: the watched channels settled from both listings, `CHANNEL_READY`, `CHANNEL_CLOSED`                                                                                                                                                                                                                           |
| `src/sdk/channel-listing.ts`             | `listSdkChannels`: the node's channels as a wallet shows them, the five states, `hasRecord`                                                                                                                                                                                                                                      |
| `src/sdk/invoice-creation.ts`            | `createSdkInvoice`: the arguments, the index, the record, `new_invoice`, the clock, the check and the watch                                                                                                                                                                                                                      |
| `src/sdk/utils/invoice-check.utils.ts`   | `checkTenantInvoice`: the node's string held to what was asked, each failure `invoice_rejected`                                                                                                                                                                                                                                  |
| `src/sdk/invoice-step.ts`                | `buildInvoiceStep`: each status answered, the index held to the hash, the release and its margin, the settlement, `pollNow`, `PAYMENT_PENDING`, `PAYMENT_RECEIVED`, `PAYMENT_EXPIRED`                                                                                                                                            |
| `src/sdk/channel-evidence.ts`            | `readSdkChannelRecord`, a registered channel's record or `unknown_channel`, which the submission reads too; `readSdkChannelEvidence`: the record projected onto its evidence                                                                                                                                                     |
| `src/sdk/sdk.types.ts`                   | The options, the network, the events, the error codes, the registration's forms, the opening's and the listing's, the pending opening, the evidence, the invoice's, the activity record, the context                                                                                                                             |
| `src/sdk/sdk.constants.ts`               | The network presets, the poll interval, the allocation floor, the storage keys, the event, error and state lists, the opening's output index and defaults, the watchtower step's skipped flags and unwatched answer, the invoice's expiry, final delta and timestamp tolerance, the release's slack, fiber's already-paid answer |
| `src/sdk/sdk.error.ts`                   | `SdkError`                                                                                                                                                                                                                                                                                                                       |
| `src/sdk/allocator.ts`                   | `IndexAllocator`: the channel and invoice indexes from the clock, the last one persisted                                                                                                                                                                                                                                         |
| `src/sdk/activity.ts`                    | `ActivityTracker`: the persisted list of what is watched, and the status each event was emitted for                                                                                                                                                                                                                              |
| `src/sdk/poller.ts`                      | `ActivityPoller`: the tick, its steps and their runs and deadline, the interval, `start`, `stop`                                                                                                                                                                                                                                 |
| `src/sdk/signing-step.ts`                | `buildChannelSigningStep`: the channels polled, the status read, the dispatch, the submission, `SIGNING`                                                                                                                                                                                                                         |
| `src/sdk/watchtower-step.ts`             | `buildWatchtowerSigningStep`: the channels it may still watch, the unwatched answer, the dispatch, the submission, the mark, `WATCHTOWER_SIGNING`                                                                                                                                                                                |
| `src/sdk/utils/poll-step.utils.ts`       | What the steps share under their run: each channel or invoice in turn (`answerEachPolled`), the guarded event, the `poll_failed` report, the refusal of another channel's status                                                                                                                                                 |
| `src/sdk/utils/request-id.utils.ts`      | `encodeSdkRequestId`, a request id as both signing events carry it                                                                                                                                                                                                                                                               |
| `src/sdk/utils/runtime-timer.utils.ts`   | The timer over the runtime's `setTimeout` and `clearTimeout`                                                                                                                                                                                                                                                                     |
| `src/sdk/utils/network.utils.ts`         | The network option resolved to its five values                                                                                                                                                                                                                                                                                   |
| `src/sdk/utils/activity-record.utils.ts` | The activity record's guard, ids and statuses per kind                                                                                                                                                                                                                                                                           |
| `src/sdk/utils/failure.utils.ts`         | An `SdkError`'s message from what failed and its cause; the guarded emit and the `poll_failed` report                                                                                                                                                                                                                            |
| `src/policy/signer-store.ts`             | `getRecord` and `updateRecord`, the store's records of another module's format, used by the allocator, the activity and the pending opening                                                                                                                                                                                      |
| `src/common/utils/assert.utils.ts`       | `assertTimerDelayMs`, `assertScriptTemplate`, `assertCompressedPoint`, `assertFunction`, `assertCellDep`, `assertCellDeps` and `assertPositiveDecimalShannons`                                                                                                                                                                   |
| `src/common/utils/copy.utils.ts`         | The copies of a script, a template, an out point, a cell dep and a transaction, which the network and the opening take                                                                                                                                                                                                           |
| `src/common/utils/validate.utils.ts`     | `isCompressedPoint`, shared with the invoice codec; `isPositiveDecimalShannons`, shared with the policy's invoice record                                                                                                                                                                                                         |
| `src/common/timer-slot.ts`               | `TimerSlot`: the one armed callback the poller holds                                                                                                                                                                                                                                                                             |
| `src/common/listener-set.ts`             | `ListenerSet`: the events' fan-out                                                                                                                                                                                                                                                                                               |

## What the tests guarantee

`test/tests/sdk/fiber-lsp-sdk.spec.ts` pins the construction and the wiring over a timer double advanced by hand, an
in-memory storage and a `fetch` double. Beyond a happy path per feature:

- **Construction**: every option refused with the error naming the field (the seed's length and type, the url, the LSP
  key's length and type, the poll interval below one, fractional and past the timer ceiling, an unknown network, a
  development chain with no funding lock or a short code hash on either lock, an unknown currency, no funding lock cell
  deps count or no epoch length, a token with a space); the edges accepted (the default interval, the ceiling, no token,
  both presets, each with its own funding lock, a development chain, its two locks copied, no clock); nothing scheduled or read before `connect()`; the timer defaulting to the runtime's, read once, and
  refused when the runtime has none; `fetch` the same.
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
- **The watchtower through the facade**: the approval refused when it is not an object, and handed to the policy engine
  as a copy, or none; the watchtower step run after the signing step in the same tick, after one that signed with each
  step's event in the steps' order, and after one that failed; every spend refused without an approval, nothing
  submitted, and judged by the approval when there is one.
- **The opening and the listing through the facade**: an opening asked under the clock's index with what the node froze
  handed back; the funding cell refused as `opening_rejected` under the mainnet preset and under a development chain's
  other funding lock, and accepted on one that names testnet's; the signed tx submitted, and refused for an unregistered
  channel as `unknown_channel`; the one-call opening through the host's signer; the cell deps passed from both entry
  points, and cell deps that are not a list and a missing signer refused with nothing written or sent; the listing with
  `hasRecord`; and the channel step polled before the signing steps, announcing the opened channel ready and dropping
  its pending opening.
- **The invoice through the facade**: a hold invoice of the seed's preimage hash under the network's currency, checked,
  recorded and watched; the string held to the facade's own LSP key and network; and an amount of zero refused with
  nothing read, written or sent.

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

`watchtower-step.spec.ts` pins the watchtower step the same way, with the real dispatch and policy over the vectors'
spends and the scripted node: each spend of the device submitted with the vectors' signature, marked applied before its
event and announced as `signed`; a spend of an unlock already signed submitted unclaimed, marking nothing; a repeat
resubmitted with the same bytes, writing nothing, `AlreadyApplied` as success; the channels in listing order, listed with
`include_closed`, and an unregistered one skipped without a status read. Each of the three skipped flags is skipped, and
every other state is polled and signed: closed by either commitment, waiting for the settlement, shutting down with the
commitment broadcast, closed with no flag, with a flag or in a state no release has yet, a skipped flag's name under
another state, and `Stale`. The unwatched answer is nothing pending on a channel still opening and on a ready one, and a
`poll_failed` under another message, another code or on a closed channel. A refusal without an approval, by a rule and of
an unreadable status (with neither request id nor purpose), another channel's status refused as `malformed` without
reaching the dispatch, a refusal repeated on every tick; a status read that fails, a submission refused or unreadable, a
mark that fails with the signature already out, a dispatch fault and a registration it cannot read, each a `poll_failed`
naming the channel with the next channel answered, and a failed submission sent again on the next tick with the same
signature, marked on either answer; a listing that fails or that it cannot read failing the step; and the
run abandoned during the status read, the signature and the submission, acting on nothing but the mark after a
submission, emitting no refusal, failure or fault, polling no further channel, and answering the same request on the next
tick. `utils/poll-step.utils.spec.ts` pins what the steps share, each helper silent once its run is abandoned and
`answerEachPolled` naming each failure by the id it is handed, and
`utils/request-id.utils.spec.ts` the request id as the events write it. The flows over the tenant node double run both
steps together ([signing.md](./signing.md)).

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
dropped by a `stop()` and never carried across one. The utils specs pin the presets' code hashes, the funding locks' included, the network refusals
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
| A step's deadline outlives the step                                         | 7                 |
| A refusal's request id is dropped                                           | 7                 |
| A refusal's transition is dropped                                           | 7                 |
| A stop() leaves the interval armed                                          | 6                 |
| A fractional clock is accepted                                              | 6                 |
| connect() does not start the poller                                         | 6                 |
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
| An abandoned run still reaches the dispatch                                 | 1                 |
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

The network's cell deps count and epoch length and the dispatch's share one floor, `common`'s `assertPositiveInteger`,
swept against `test/tests/common`:

| Mutation                                | Tests that failed |
| --------------------------------------- | ----------------- |
| A positive integer may be 0             | 1                 |
| A positive integer's bound is exclusive | 1                 |

Four helpers of `common` serve the hold invoices, tabled here with its others: `isPositiveDecimalShannons` and
`assertPositiveDecimalShannons`, the amount above zero the facade and the policy's record and its stored guard require;
`assertPositiveBigInt`, the rpc's floor on the final expiry delta, over the one range check it shares with
`assertUnsignedBigInt`; and `encodeWellFormedUtf8`, the UTF-8 writer the invoice codec and the rpc's description guard
share. Swept against `test/tests/common`, the three files at 100% of statements, functions and lines; the one branch left
is the writer's `?? 0` fallback on a code point that is always there:

| Mutation                                          | Tests that failed |
| ------------------------------------------------- | ----------------- |
| A positive bigint must be at least 2              | 7                 |
| A positive bigint may be 0                        | 6                 |
| The positive amount guard skips the amount's form | 6                 |
| A lone surrogate written                          | 5                 |
| The positive amount skips the amount's form       | 5                 |
| A number in range passes as a bigint              | 4                 |
| A bigint's bound is exclusive                     | 2                 |
| A bigint's floor is exclusive                     | 2                 |
| A two-byte character is written in one            | 2                 |
| One shannon is not a positive amount              | 2                 |
| Zero is a positive amount                         | 2                 |
| A continuation byte keeps 7 bits                  | 1                 |
| A zero amount is refused as a TypeError           | 1                 |
| A zero amount passes the positive amount guard    | 1                 |
| The surrogate range ends one short                | 1                 |
| The surrogate range starts one late               | 1                 |
| The text is not checked to be a string            | 1                 |
| U+07FF is written in three bytes                  | 1                 |
| U+FFFF is written in four bytes                   | 1                 |

The wiring the operations do not yet observe whole (the network as resolved, the step's deadline, the records kept in
the host's storage) is read where it lands, in the facade's internal context, until the payments observe it through
what they send and sign; the clock is observed through the opening's and the invoice's indexes and the release, the
network's currency and epoch length through the invoice and its release, the preimages through the invoice's hash and
its settlement, the network's funding lock through the funding cell the opening accepts, the LSP's key through the registration and the opening's peer, the
identity through the registration, the store through the evidence and the listing, and the rpc client's token through
`setBiscuitToken` and the headers of the poller's calls.

The rows of the facade, the network, the runtime timer, the listener set and the poller were measured again once the
signer session and its socket left the facade, with the rows only the session exercised gone; the allocator's and the
activity's, whose code and specs that change did not touch, keep their counts.

The watchtower step, `buildWatchtowerSigningStep` with `WATCHTOWER_UNWATCHED_CLOSE_FLAGS` and the mark of the spend fiber
applied, its wiring and the `watchtower` option in the facade, `encodeSdkRequestId`, and the run-guarded helpers both steps
share (`utils/poll-step.utils.ts`), were broken the same way (`test/tests/sdk`, its flow spec included, still 100% on all
four metrics). A helper's row counts the failures of both steps' specs and its own, and stands for the signing step's copy
it replaced; the four rows on `answerEachPolled` carry the count of the hold invoices'
sweep below, the invoice step's specs included:

| Mutation                                                             | Tests that failed |
| -------------------------------------------------------------------- | ----------------- |
| The request id is written without its prefix                         | 91                |
| The listing leaves the closed channels out                           | 70                |
| A channel's failure fails the step                                   | 56                |
| The signed event is a channel SIGNING event                          | 36                |
| The signed event carries no purpose                                  | 35                |
| The spend is not marked applied                                      | 27                |
| Every closed channel is skipped                                      | 21                |
| A channel's failure ends the step                                    | 16                |
| A channel's failure names neither the poll nor the channel           | 15                |
| A refusal is not announced                                           | 13                |
| The watchtower step is not wired                                     | 13                |
| The watchtower step runs first                                       | 13                |
| A refusal's event names no purpose                                   | 10                |
| A channel's failure names the signing poll whichever step failed     | 9                 |
| A listed channel's failure names its listing, not its id             | 9                 |
| The watchtower step's failures name the signing poll                 | 8                 |
| A step's event is emitted after abandonment                          | 7                 |
| The signing step's failures name the watchtower poll                 | 7                 |
| The spend is marked before the submission                            | 7                 |
| A channel's failure is reported after abandonment                    | 6                 |
| Any failed read of an open channel is nothing pending                | 5                 |
| The channels are answered on after abandonment                       | 5                 |
| A refusal's event names no request                                   | 4                 |
| An unwatched channel is polled                                       | 4                 |
| A failed submission is still announced as signed                     | 3                 |
| A misanswered status is refused as a policy refusal                  | 3                 |
| A misanswered status names neither channel                           | 3                 |
| A signature signed unclaimed is marked too                           | 3                 |
| An unregistered channel's status is read                             | 3                 |
| An unwatched channel's status is read on                             | 3                 |
| Fiber's unwatched answer is a poll failure                           | 3                 |
| Fiber's unwatched code is nothing pending under any message          | 3                 |
| The event is emitted before the mark                                 | 3                 |
| The watchtower approval is not handed to the policy                  | 3                 |
| A cooperative close is polled                                        | 2                 |
| A failed mark is swallowed                                           | 2                 |
| The request id's length is not checked                               | 2                 |
| A channel is skipped only when all its flags are                     | 1                 |
| A fault is not reported                                              | 1                 |
| A refusal's event carries another code                               | 1                 |
| A signature is submitted after abandonment                           | 1                 |
| A skipped flag skips a channel in any state                          | 1                 |
| A status read after abandonment is still signed                      | 1                 |
| An abandoned channel is polled                                       | 1                 |
| An aborted funding is polled                                         | 1                 |
| Another channel's status is handed to the dispatch                   | 1                 |
| Fiber's unwatched answer is nothing pending for a closed channel too | 1                 |
| Fiber's unwatched message is nothing pending under any code          | 1                 |
| The mark is skipped once the run is abandoned                        | 1                 |

`fiber-lsp-sdk.spec.ts` pins the tenant's surface as well. The presets take the release epoch of 4 hours and a
development chain its own, under which the deadline reported changes; the context keeps the store the engine writes and
the identity of the seed. `tenantId` is fiber's of the seed's RootSigner and another seed's differs; `rootSignerPubkey`
is a copy on every read. `signTenantRegistration` signs fiber's `tenant_registry` vector byte for byte, returns bytes of
its own, checks the LSP against its own copy of `lspPubkey`, calls nothing and writes nothing, and refuses each field of
the challenge (the challenge not an object, then each key absent, in hex, short or long, the LSP's node id not a point,
another LSP's or the other parity of its x, the root signer another's, the nonce short or long), the LSP named first
when both are wrong. `setBiscuitToken` puts the token on the poller's next calls, on an instance built with one and
without, and a refused token keeps the previous one. `channelEvidence` reads a signed channel's evidence from the host's
storage and refuses an unknown channel, and a bare hex id before reading anything. `utils/network.utils.spec.ts` adds
the epoch to the network's refusals field by field (1, 2,000, 14,400,000 and `Number.MAX_SAFE_INTEGER` accepted; absent,
`undefined`, `null`, 0, negative, fractional, one past the bound, the infinities, NaN, a string and a bigint refused). It
pins the funding lock the same way: each preset's code hash and hash type, a development chain's copied with any of the
four hash types kept and nothing else of the object, and one absent or null, a code hash short, long or in hex, and an
unknown hash type refused.

`channel-evidence.spec.ts` pins the projection over records written literally: a channel that signed nothing read as
empty, every hash and signature as `0x` hex with the revocations' and the claims' order kept, a spend claimed and never
signed left out, one view's commitment without the other's, the channel read under its old and its new name, copies
that change neither the record nor the next read, nothing written; and the refusals: an unknown channel as
`unknown_channel`, a name resolving to no record, a store failure passed through, and every malformed id.
`channel-evidence.flow.spec.ts` reads it over the tenant node double: after the open, the two commitments and nothing
else; after a payment received and fulfilled, the peer's two revocations, each verified as BIP-340 under the aggregate
key and the message the node served, and each view's last commitment, its hash the message signed; after a force close
with a TLC each way in flight, every spend the watchtower took in the device's claim order, signed as submitted, and a
signature whose answer was lost kept as not applied until the restarted device hears fiber took it.

`signing-step.spec.ts` carries the dispatch's deadline on the two commitment transitions and none on the revocations
and the close, the field present on a signature, a warned second session and a refusal and absent from each without
one, 0 as 0 and `u64::MAX` as the nearest number. `signing-step.flow.spec.ts` follows a payment received through its
fulfil and the close, with fiber's deadline, the double's TLC expiry less two thirds of the pinned delay, on the add
round's two commitments and on nothing else.

The tenant's surface (the registration, the token, the evidence, the network's epoch length and the `SIGNING` event's
`deadlineMs`) was broken the same way (`test/tests/sdk`, still 100% on all four metrics):

| Mutation                                              | Tests that failed |
| ----------------------------------------------------- | ----------------- |
| The deadline is never reported                        | 24                |
| The deadline is reported as a bigint                  | 23                |
| A missing deadline is reported as null                | 15                |
| A development chain's epoch is not checked            | 13                |
| The channel id is not checked                         | 9                 |
| The commitment number is lost                         | 9                 |
| The hex carries no prefix                             | 9                 |
| The views are swapped                                 | 9                 |
| A development chain's epoch is not copied             | 7                 |
| The presets use a debug build's epoch                 | 7                 |
| No spends reads as a failure                          | 6                 |
| The token is not handed to the client                 | 6                 |
| A refusal carries no deadline                         | 5                 |
| The LSP's node id is not checked as a point           | 5                 |
| The revocations come out in reverse                   | 5                 |
| A challenge that is not an object reaches the fields  | 4                 |
| A spend's applied flag is always true                 | 4                 |
| An unsigned spend is listed                           | 4                 |
| The root signer's key is the LSP's                    | 4                 |
| A challenge from another LSP is signed                | 3                 |
| An unknown channel reads as empty evidence            | 2                 |
| A lost record reads as an unknown channel             | 1                 |
| The dispatch reads the release epoch on every network | 1                 |
| The registration carries no tenant id                 | 1                 |

`channel-opening.spec.ts` pins the three operations over a scripted node, an in-memory storage and the real policy and
dispatch. The preparation: the request with the device's material, the user's lock as both scripts and fiber's default
delay and fee rate, and an answer at another delay or fee rate refused with nothing registered; the node's id, tx and
context handed back; the opening recorded under a fresh index before the node is asked, then named, registered, pinned
and watched before the tx is handed out, and the channel served by the signing step from then on and not before. The
pending opening: resumed under its index with the identical request after a lost answer, an answer the client cannot
read and fiber's interruption; kept through fiber's refusals (an opening stopped, a different opening, a channel already
there, a channel already open); a named one resumed while the node lists it opening, lists nothing pending or another
channel aborted, and dropped once its own is aborted, opening under a fresh index, dropped even when no fresh index can
be allocated, and leaving an opening another call wrote; another amount or lock opening under a fresh index without a listing; kept
when the pending channels cannot be listed; dropped on a failed check, pinning nothing; kept, named, when pinning fails
short of a conflict, the same call then pinning the rest; and one that failed past its pins dropped once aborted and
reopened without a conflict. The cell deps sent as fiber writes them and recorded, resumed with the same, and sent from
the one-call opening too; the caller's lock and cell deps copied. Each conflict (other terms, another funding cell, a
channel registered under another index, a resumed index holding another amount or serving another channel) is
`opening_conflict` with the policy's refusal as cause; a drop the store refuses keeps `opening_rejected` and
`opening_conflict`, cause included, telling the failure in the message; a corrupt channel record or alias comes through
as itself with the opening kept, named. Each argument is refused with nothing written or sent (the amount absent, a
number, a bigint, empty, negative, fractional or hex, below the least reserve and at a u64's whole capacity as the
policy's `RangeError`; the lock absent, null, with a short code hash, an unknown hash type, or args absent or in hex),
and the edges are asked (the least reserve, one below a u64). The submission: the tx submitted when its raw part is the
frozen one, writing nothing; a refusal naming both funding cells; `unknown_channel`; no funding cell pinned, or an out
point without its capacity, as `funding_tx_altered`; a pin failure short of a conflict as itself; its own copy submitted
however the caller writes to its object during the checks; the node's refusal and a lost answer through unwrapped, the
opening kept; each argument refused, the channel id first, the hash's refusal kept as the cause. The one-call opening:
the host signing a copy, unbound, and its tx submitted; a tx the host wrote to before signing refused; the host's
refusal through, with the opening kept and resumed; and a signer's answer that is not a transaction refused, nothing
submitted.

`utils/opening-check.utils.spec.ts` pins the check over a literal answer: accepted, with the terms and the capacity it
returns and keys of its own; both reserves under the legacy layout, and either layout on a script whose args are as
long as both layouts' lock args; each amount at exactly its reserve; a funding cell of a u64's whole capacity; outputs of
any kind after it; and the funding lock's args whichever key sorts first. Then one refusal per field: another channel id
and the id of the device's funding key; the settlement key off the curve, under the uncompressed prefix and the device's
own; the delay, the fee rate and the local amount one either side; each reserve one either side, the device's at
nothing, and the two under different layouts either way; the peer below its reserve and the device below its own; output
0 missing, typed, without data and with data; the funding key off the curve and the device's own; output 0's lock under
the mainnet funding lock, the commitment lock, another hash type, other args, longer args and none; the capacity past a
u64 and one either side; and an answer for another network's funding lock. An answer wrong everywhere names each field
in order as the ones before it are put right.

`pending-opening.spec.ts` pins the record's key and JSON literally, the lock as molecule hex and the cell deps in their
record form; a read of nothing, of a cleared opening, of another instance's write and of a named one, extra fields
tolerated; every corrupt field refused on a read (the version, the opening, the index, the amount, the lock, each cell
dep's field, the channel id), the cell deps' index bounds accepted, a record that is not JSON refused, and a format that
refuses to write what it would refuse to read; the write replacing any other opening, over a cleared one, written before
it resolves on an asynchronous storage, returning an opening the store does not hold, each argument refused by name, an
empty list of cell deps kept as given; the match on the amount, the lock and the cell deps, none with none and an empty
list with an empty list, and no match on fewer, more or reordered ones; the naming of the channel under its index alone,
writing nothing when it is already named; and both drops, by the channel and by the index, leaving any other opening and
writing nothing when there is none.

`channel-step.spec.ts` pins the step over the scripted node: nothing called with no channel watched, with only payments
and invoices watched, or once the last channel closed; `CHANNEL_READY` once, nothing for a channel still ready, the
event before the drop of the pending opening before the record; `CHANNEL_CLOSED` under each of fiber's close flags and a
pair of them, for an opening and for a ready channel, the event before the drop before the channel is forgotten; nothing
for every other state (each opening state, `ShuttingDown` after ready, `Stale`, a state fiber may add), the channel still
watched. A channel the listing leaves out: looked for among the pending channels once per tick, after the listed ones,
and settled there as a listed one (an aborted opening closed, one still opening left); kept watched when neither listing
shows it; no pending read when every watched channel is listed, and one settled once when both list it. Channels nobody
watches are ignored in both, and the pending opening is kept when another channel turns ready or closed, when its own is
in another state, and while it names none. A listing refused, unreachable or unreadable fails the step with nothing
emitted or written, a failed pending listing after the listed ones are settled, and an unreadable activity list before
any call; a mark or a pending opening that fails is a `poll_failed` naming the channel, the next one settled and the
event emitted again on the next tick; a throwing listener changes nothing; and a run abandoned during either listing,
during its own event or while settling emits, records and reads no further, the event going out again on the next tick.

`channel-listing.spec.ts` pins the five states, every fiber state mapped as the table says, the listing asked with
`include_closed`, each channel's own balances in the node's order and the largest u128 whole, `hasRecord` telling the
registered channels from the others, an empty listing, and the node's error, an unknown state and a store failure
rejected as themselves.

`channel-opening.flow.spec.ts` runs the facade over the tenant node double ([signing.md](./signing.md), "The opening over
the double"): the one-call opening up to `CHANNEL_READY`, signing the open's two commitments, and the force close
announced after; a preparation and a submission, the listing showing the channel opening, ready, closing and closed; the
peer's commitment signed while the funding tx waits for the host, the device's after the submission; an opening fiber
aborts after the device signed the peer's commitment announced closed, dropped and gone from the listing; a lost answer
resumed under the same index with the identical request, the listing showing the channel without a record meanwhile; an
opening the host declined kept, announced closed once fiber aborts it, then reopened under a fresh index; one aborted
while the device was away found through `only_pending` and reopened; the node's tampered answers (another delay, either
reserve, another channel id, output 0 under another lock) refused as `opening_rejected` naming the field; a signed tx
that is not the frozen one refused as `funding_tx_altered`, nothing sent; a submission whose answer was lost, its retry
meeting fiber's repeated-submission refusal and `CHANNEL_READY` confirming it; an LSP the node is not, refused by the
node; the node refusing what the facade never asks (a public channel, no signer, its open channel again) and a fresh
opening while it holds one; and the user lock's cell deps handed to the node, which adds them to the funding tx unless
it carries them already.

The channel opening, `channel-opening.ts` with `utils/opening-check.utils.ts` and `pending-opening.ts`, the channel step and
the listing, their wiring in the facade, the network's funding lock and the presets and defaults they read, were broken the
same way (`test/tests/sdk`, its flow specs included, still 100% on all four metrics):

| Mutation                                                          | Tests that failed |
| ----------------------------------------------------------------- | ----------------- |
| The pending opening's key is another                              | 115               |
| The channel id is computed over the funding key                   | 112               |
| The pending opening's version is 2                                | 97                |
| The funding output is output 1                                    | 85                |
| The material is prepared at another index                         | 82                |
| The funding lock args take the TLC base key                       | 71                |
| The funding cell's capacity leaves the remote amount out          | 70                |
| The default delay is one more                                     | 62                |
| The default fee rate is one more                                  | 58                |
| The testnet preset takes the mainnet funding lock                 | 57                |
| The funding output is checked against the commitment lock         | 56                |
| The channel is not registered                                     | 55                |
| A fresh opening is not recorded                                   | 48                |
| A refusal does not name the field                                 | 48                |
| A record with no opening is refused                               | 45                |
| A rejected answer is opening_conflict                             | 40                |
| The listed channels count as left out                             | 40                |
| The step lists only the pending channels                          | 36                |
| The pending channels are read with nothing left out               | 34                |
| The funding cell is not pinned                                    | 33                |
| The funding cell is pinned at output 1                            | 33                |
| The user's lock is not sent as the shutdown script                | 31                |
| The delay is left to the node                                     | 30                |
| The fee rate is left to the node                                  | 30                |
| The liquid capacity keeps the device's reserve                    | 30                |
| The liquid capacity keeps the peer's reserve                      | 30                |
| A failure of the request drops the pending opening                | 29                |
| A pending opening is never resumed                                | 28                |
| The pinned funding capacity is the local amount                   | 28                |
| The pinned TLC base key is the funding key                        | 27                |
| The node is asked with nothing watched                            | 25                |
| The local balance is the remote one                               | 24                |
| The pending opening never names its channel                       | 24                |
| The remote balance is the local one                               | 24                |
| hasRecord is inverted                                             | 24                |
| The terms are not pinned                                          | 23                |
| A closed channel is not announced                                 | 21                |
| Every channel has a record                                        | 21                |
| The cell deps check takes anything                                | 21                |
| The opening returns the pending opening's channel id              | 20                |
| The signed tx is checked at output 1                              | 20                |
| A closed channel is announced as ready                            | 19                |
| A ready channel is announced as closed                            | 19                |
| The signed tx is never submitted                                  | 18                |
| A closed channel stays watched                                    | 17                |
| The facade's one-call opening opens nothing                       | 17                |
| The stored cell deps are not checked                              | 16                |
| An aborted opening is resumed                                     | 15                |
| A retry with other cell deps resumes                              | 14                |
| The channel is not watched                                        | 14                |
| The preparation skips the argument checks                         | 14                |
| The offered TLC balance is the received one                       | 13                |
| The received TLC balance is the offered one                       | 13                |
| The signed tx is not checked against the frozen one               | 13                |
| The submission's pin conflict goes through unwrapped              | 12                |
| The facade's listing is empty                                     | 11                |
| The funding output's lock is not compared                         | 11                |
| The stored index is not checked                                   | 11                |
| A cell dep's tx hash is stored with a prefix                      | 10                |
| A ready channel is not recorded                                   | 10                |
| The channel step is not wired                                     | 10                |
| A channel negotiating funding is listed as stale                  | 9                 |
| A drop takes the opening it does not seek                         | 9                 |
| The amount is not checked as decimal shannons                     | 9                 |
| The facade's preparation is the one-call opening                  | 9                 |
| The network's funding lock is not checked                         | 9                 |
| The resumption reads every channel instead of the pending ones    | 9                 |
| funding_tx_altered carries no cause                               | 9                 |
| A channel the listing leaves out is never looked for              | 8                 |
| A pending opening with no channel yet lists the pending channels  | 8                 |
| The delay is not checked against the request                      | 8                 |
| The opening returns no context                                    | 8                 |
| The stored lock is not checked                                    | 8                 |
| A ready channel is listed as opening                              | 7                 |
| A ready channel keeps its pending opening                         | 7                 |
| A rejected answer keeps the pending opening                       | 7                 |
| A write keeps the opening it should replace                       | 7                 |
| Naming the channel returns a value                                | 7                 |
| The channel id is not checked                                     | 7                 |
| The channels left out are looked for among all channels           | 7                 |
| The facade's submission sends nothing                             | 7                 |
| The network's funding lock is the commitment lock                 | 7                 |
| The user's lock is not checked as a script                        | 7                 |
| The write checks no cell deps                                     | 7                 |
| A cell dep's index is stored as 0                                 | 6                 |
| A cell dep's type is stored as code                               | 6                 |
| A closed channel keeps its pending opening                        | 6                 |
| A conflict keeps the pending opening                              | 6                 |
| Any pending channel the node lists counts as aborted              | 6                 |
| The drop by index returns a value                                 | 6                 |
| The listing leaves the closed channels out                        | 6                 |
| The write records no cell deps                                    | 6                 |
| opening_conflict carries no cause                                 | 6                 |
| A retry with another lock resumes                                 | 5                 |
| A stored cell dep's index is not checked                          | 5                 |
| A stored cell dep's tx hash is not checked                        | 5                 |
| An aborted opening is dropped and resumed anyway                  | 5                 |
| The cell deps are not sent to the node                            | 5                 |
| The channel is named after the pins                               | 5                 |
| The delay is checked against the node's own                       | 5                 |
| The device's reserve is taken under no layout                     | 5                 |
| The drop ignores the channel it names                             | 5                 |
| The drop returns a value                                          | 5                 |
| The host's signer is not checked to be a function                 | 5                 |
| The preparation skips the cell deps check                         | 5                 |
| The stored amount is not checked                                  | 5                 |
| The stored channel id is not checked                              | 5                 |
| A closed channel is listed as closing                             | 4                 |
| A fresh opening is recorded without its cell deps                 | 4                 |
| A peer key off the curve passes                                   | 4                 |
| A ready channel is recorded before it is announced                | 4                 |
| A signed tx the hash refuses is thrown unwrapped                  | 4                 |
| The channel id is not compared                                    | 4                 |
| The drop by index ignores the index                               | 4                 |
| The drop by index takes any index                                 | 4                 |
| The fee rate is not checked against the request                   | 4                 |
| The network's commitment lock is not copied                       | 4                 |
| The signed tx is not checked to be an object                      | 4                 |
| The stored version is not checked                                 | 4                 |
| A pin conflict is not opening_conflict                            | 3                 |
| A registration conflict is not opening_conflict                   | 3                 |
| An unwatched channel is settled                                   | 3                 |
| The facade's one-call opening drops the cell deps                 | 3                 |
| The funding output's capacity is not compared                     | 3                 |
| The funding output's lock args are not compared                   | 3                 |
| The local amount is not checked                                   | 3                 |
| The mainnet preset takes the testnet funding lock                 | 3                 |
| The network's funding lock is not copied                          | 3                 |
| The one-call opening skips the argument checks                    | 3                 |
| The one-call opening skips the cell deps check                    | 3                 |
| The one-call opening submits the unsigned tx                      | 3                 |
| The opening's floor is not checked                                | 3                 |
| The peer's funding key is not checked                             | 3                 |
| The settlement key is not checked before the id                   | 3                 |
| The write takes any index                                         | 3                 |
| A channel with no funding cell pinned is submitted                | 2                 |
| A drop takes whichever opening is pending                         | 2                 |
| A drop with nothing stored writes a record                        | 2                 |
| A failed drop replaces the refusal                                | 2                 |
| A failed drop's refusal does not tell why                         | 2                 |
| A retry is matched without its cell deps                          | 2                 |
| A retry with another amount resumes                               | 2                 |
| A shutting down channel is listed as closed                       | 2                 |
| A stored cell dep's type is not checked                           | 2                 |
| A typed funding output passes                                     | 2                 |
| An abandoned run reads the pending channels                       | 2                 |
| An empty list of cell deps is kept as one                         | 2                 |
| Any failure to pin is opening_conflict                            | 2                 |
| Funding output data passes                                        | 2                 |
| Naming the channel takes any id                                   | 2                 |
| Naming the channel writes it again                                | 2                 |
| None and an empty list compare equal                              | 2                 |
| Null cell deps count as none                                      | 2                 |
| The device's reserve is computed over the peer's script           | 2                 |
| The drop takes any channel id                                     | 2                 |
| The host's signed tx is submitted, not the copy                   | 2                 |
| The local amount may exceed what was funded                       | 2                 |
| The peer may state the device's own key                           | 2                 |
| The peer's reserve bound is not checked                           | 2                 |
| The peer's reserve is computed over the user's lock               | 2                 |
| The peer's reserve may take the other layout                      | 2                 |
| The pinned remote reserve is the device's                         | 2                 |
| The stored cell deps need not be a list                           | 2                 |
| The stored lock is not read as a script                           | 2                 |
| The submission returns the node's answer                          | 2                 |
| A channel awaiting ready is listed as ready                       | 1                 |
| A channel with no funding capacity pinned is submitted            | 1                 |
| A failed drop's refusal loses its cause                           | 1                 |
| A failed drop's refusal sets an undefined cause                   | 1                 |
| A failed drop's refusal takes another code                        | 1                 |
| A missing funding output is not refused                           | 1                 |
| A ready channel is announced again                                | 1                 |
| A ready channel is recorded before its pending opening is dropped | 1                 |
| A refused channel is watched                                      | 1                 |
| A stale channel is listed as opening                              | 1                 |
| A stored cell dep need not be an object                           | 1                 |
| An abandoned run forgets a closed channel                         | 1                 |
| An abandoned run records a ready channel                          | 1                 |
| An aborted opening is not dropped                                 | 1                 |
| Any closed pending channel counts as the aborted one              | 1                 |
| Any failure of the submission's pin is funding_tx_altered         | 1                 |
| Cell deps compare without the dep type                            | 1                 |
| Cell deps compare without the index                               | 1                 |
| Cell deps compare without the length                              | 1                 |
| Cell deps compare without the tx hash                             | 1                 |
| Missing funding output data is not refused                        | 1                 |
| Naming the channel ignores the index                              | 1                 |
| Naming the channel takes any index                                | 1                 |
| The capacity bound admits a u64 plus one                          | 1                 |
| The capacity bound refuses its own edge                           | 1                 |
| The cell deps are held by reference                               | 1                 |
| The channel step runs after the signing step                      | 1                 |
| The device's reserve bound is not checked                         | 1                 |
| The device's reserve bound refuses its own edge                   | 1                 |
| The facade's preparation drops the cell deps                      | 1                 |
| The fee rate is checked against the node's own                    | 1                 |
| The funding output may hold more than the two amounts             | 1                 |
| The host's signer is called with a receiver                       | 1                 |
| The mainnet funding lock's code hash is another                   | 1                 |
| The match checks no cell deps                                     | 1                 |
| The peer's reserve bound refuses its own edge                     | 1                 |
| The pending listing settles every watched channel                 | 1                 |
| The pinned TLC base key is the answer's own bytes                 | 1                 |
| The pinned funding key is the answer's own bytes                  | 1                 |
| The signed tx is copied after the record is read                  | 1                 |
| The signed tx's witnesses are not checked to be a list            | 1                 |
| The signed tx's witnesses are not checked to be bytes             | 1                 |
| The stored lock's hex is not checked                              | 1                 |
| The submission checks the channel id after the tx                 | 1                 |
| The user's lock is held by reference                              | 1                 |
| The write records an empty list as none                           | 1                 |
| The write takes any amount                                        | 1                 |

The opening's copies and its cell deps' guards live in `common`: `src/common/utils/copy.utils.ts` and `assertCellDep` and
`assertCellDeps` in `src/common/utils/assert.utils.ts`, at 100% on all four metrics, swept against `test/tests/common`.
`copy.utils.spec.ts` pins each copy down to every byte array, so writing to the source changes nothing, a template keeping
nothing else of its object and a transaction with empty lists; `assert.utils.spec.ts` pins a cell dep of either dep
type accepted and one that is not an object, has no out point, no dep type or one in camel case refused, and a list of
none, one or two accepted, a single cell dep or `null` refused, and a bad entry named by its position:

| Mutation                                     | Tests that failed |
| -------------------------------------------- | ----------------- |
| A cell dep need not be an object             | 3                 |
| A cell dep's out point is not checked        | 3                 |
| A cell dep's type is named as its out point  | 3                 |
| A cell dep's type is not checked             | 3                 |
| A template's code hash is held by reference  | 3                 |
| An out point's tx hash is held by reference  | 3                 |
| A cell dep's out point is held by reference  | 2                 |
| A cell dep's type is always code             | 2                 |
| A list's cell deps are not checked           | 2                 |
| A list's cell deps are not named by position | 2                 |
| A script's args are held by reference        | 2                 |
| A script's code hash is held by reference    | 2                 |
| A template's hash type is always type        | 2                 |
| An out point's index is 0                    | 2                 |
| Cell deps need not be a list                 | 2                 |
| A tx input's out point is held by reference  | 1                 |
| A tx input's since is 0                      | 1                 |
| A tx output's capacity is 0                  | 1                 |
| A tx output's lock is held by reference      | 1                 |
| A tx output's type is always dropped         | 1                 |
| A tx output's type is held by reference      | 1                 |
| A tx's cell deps are held by reference       | 1                 |
| A tx's header deps are held by reference     | 1                 |
| A tx's outputs data are held by reference    | 1                 |
| A tx's version is 0                          | 1                 |
| A tx's witnesses are held by reference       | 1                 |

`invoice-creation.spec.ts` pins `createSdkInvoice` over a scripted node, an in-memory storage and the real policy,
allocator and preimages: the request with the derived hash under ckb-hash, the network's currency, an hour's expiry and
a day's final delta, the description and the expiry asked sent and checked, an empty description sent and required, a
development chain's currency; the string and the `0x` hash handed back; the record under a freshly allocated index
before the node hears the hash, and nothing asked when the record cannot be written; the allocation, the record and the
watch in that order, the watch once the string passed; the clock read once, after the answer, without a receiver; each
option read once. A string that is not the invoice asked (another currency, amount, timestamp past the tolerance, hash,
algorithm, expiry or final delta, an unasked description, another hint, and one the decoder refuses) is
`invoice_rejected` with the record kept and nothing watched; a lost answer and one the client cannot read pass through
the same way; a retry takes another index and another hash, both records kept and only the second watched; and each
argument is refused with nothing read, written or sent (the amount absent, a number, a bigint, empty, negative,
fractional, hex, with a leading zero, past a u128 and zero; the options `null`, a list or a string; the description
`null`, a number, 640 bytes or with a lone surrogate; the expiry `null`, zero, negative, fractional, a string, a bigint,
NaN, infinite or past the safe integers).

`utils/invoice-check.utils.spec.ts` pins the check against the tenant invoice of `invoice.json`, as fiber's `new_invoice`
shapes it, and re-signs it to its own string first, so each refusal differs from it only where it says. It accepts the
attributes in reverse order, a past timestamp and one exactly the tolerance ahead (one millisecond more refused), any
payee key the signature is by, no description when none was asked and an empty one when one was. It refuses each field
on its own: the currency of the other two networks, no amount and one shannon either side, another hash, no or another
algorithm, no expiry and one second either side, no final delta and one millisecond either side, no, another or a
padded description, each wrong feature (none, empty, zero, the required bit, MPP's bit beside it, a zero byte after it),
no or another hint, no payee key, each attribute fiber does not write for a tenant, and a string the decoder refuses
(none at all, a broken checksum, upper case, a signature by another key). An invoice wrong everywhere names each field
in order as the ones before it are put right.

`invoice-step.spec.ts` pins the step over the scripted node, the real policy over literal channel records and the real
preimages: nothing called with no invoice watched, with only channels and payments, or once the last invoice is paid;
`Open` answered with nothing, its expiry not read; `PAYMENT_PENDING` once across ticks, emitted before it is recorded,
then the release tried on every tick; the release settled with the preimage of the invoice's own index, then a tick
asked, its clock the host's first reading and its margin following the channel's delay; the already-paid answer taken
as settled, and one that only looks like it a `poll_failed`; a released record settled again on every tick it stays
`Received` without a judgment or a tick, never ended unpaid; each waiting code silent and `algorithm_mismatch`, a
refusal that only looks like a wait, any other release failure and a clock the release refuses each a `poll_failed`;
`PAYMENT_EXPIRED` past the expiry with no TLC left, and nothing at the expiry's exact millisecond, while a TLC is still
listed, or for an invoice without an expiry; a string of another invoice or one that does not decode a `poll_failed`;
`PAYMENT_RECEIVED` for a released invoice, a `Paid` one never released or unrecorded a `poll_failed` on every tick,
still watched; `PAYMENT_EXPIRED` for `Expired` and `Cancelled`, and both a `poll_failed` on a released record, settled
again once fiber reports it `Received`; an invoice the node cannot answer, a status the client does not know and a
record missing each a `poll_failed` with the next invoice answered, and an unreadable activity list failing the step; an
event emitted again after a mark or a drop that failed; a throwing listener changing nothing; and the run abandoned
during each call, acting on nothing further and asking no tick, the event going out again on the next tick.

`invoice-step.flow.spec.ts` runs the facade over the tenant node double, which serves `new_invoice`, `get_invoice` and
`settle_invoice` as fiber does for a tenant: it signs each invoice with a tenant key of its own beside the hint, the
feature and the delta, reports `Received` once the TLC is committed in both views and `Expired` as an `Open` invoice
past its expiry, asks for the preimage the settlement stored before it fulfils a held TLC, fails a held TLC near its
expiry as fiber's maintenance does (`failHeldTlc`), and can tamper with the next invoice it writes (`tamperInvoice`).
Over it: a payment received with the app open, from `createInvoice` through the TLC signed in, the preimage released and
the fulfil signed to `PAYMENT_RECEIVED`; a record whose index derives another hash, never marked and no preimage handed
over; a payment that waits on the node while the app is closed and settles once it connects; an overpay received whole;
a TLC the clock brought too close to its expiry never released, failed back by the node and ended `PAYMENT_EXPIRED`;
the release judged under the network's own epoch, a debug build's two seconds clearing a TLC the release build's holds
back; an `Open` invoice announced expired; a settlement the node never heard and one whose answer was lost, both settled
again; the node's fail of a released TLC refused, nothing signed and the TLC kept in the commitments; and each tampered
invoice (another hash, amount or forward timestamp, no or another hint, an extra attribute or an unasked description,
another feature, another signer, upper case) refused as `invoice_rejected` naming the field, and never polled.

The hold invoices, `createInvoice` over `createSdkInvoice` (its arguments checked before the index is allocated, the
record before `new_invoice`, the clock read and checked once the node answered, the check, then the watch),
`checkTenantInvoice` field by field and its timestamp against the clock and its skew, the invoice step (`buildInvoiceStep`:
each status, `PAYMENT_PENDING` once, the recorded index held to the watched hash before the mark, the release with its
settlement and `pollNow`, the waits against `poll_failed`, the paid answer, the settlement again, a paid invoice never
released and a released one reported expired or cancelled, the three ways to `PAYMENT_EXPIRED` and the strict expiry, the
abandoned run up to `pollNow`), `answerEachPolled` and the fourth step's wiring, were broken the same way (`test/tests/sdk`,
its flow specs included, still 100% on all four metrics):

| Mutation                                                      | Tests that failed |
| ------------------------------------------------------------- | ----------------- |
| The feature expected is another bit                           | 47                |
| The invoice is asked under sha256                             | 39                |
| PAYMENT_PENDING is not recorded                               | 34                |
| The final expiry delta is one millisecond longer              | 28                |
| The string is checked against another LSP key                 | 26                |
| The timestamp is held to the clock without the skew           | 25                |
| The node's string is not checked                              | 24                |
| A release that waits is a poll failure                        | 23                |
| The default expiry is one second longer                       | 22                |
| The invoice is watched before its string is checked           | 22                |
| A finished invoice is still watched                           | 20                |
| An invoice's failure is named without its prefix              | 20                |
| The invoice is recorded under the next index                  | 20                |
| The settlement hands the next index's preimage                | 19                |
| The accepted attributes leave the description out             | 17                |
| A final event names the hash without its prefix               | 16                |
| PAYMENT_PENDING is emitted on every tick                      | 15                |
| A received invoice ends expired before its expiry             | 13                |
| An open invoice ends expired                                  | 12                |
| The preimages derive from another seed                        | 12                |
| A missing attribute is not refused by name                    | 11                |
| A released invoice is not settled again                       | 11                |
| The invoice is recorded after new_invoice                     | 11                |
| The invoice's amount is not checked before the allocation     | 11                |
| The release reads a clock at zero                             | 11                |
| The expiry's bound refuses its own edge                       | 10                |
| The invoice step is not wired                                 | 10                |
| The invoice's expiry is read in milliseconds                  | 10                |
| The expiry is not checked                                     | 9                 |
| The invoice step runs first                                   | 8                 |
| A string that does not decode is not invoice_rejected         | 7                 |
| Any settlement failure is taken as paid                       | 7                 |
| The feature bits are not checked                              | 7                 |
| The payment hash is handed back without its prefix            | 7                 |
| An attribute not asked for is accepted                        | 6                 |
| No tick is asked after the settlement                         | 6                 |
| The amount is not checked                                     | 6                 |
| The currency is not checked                                   | 5                 |
| The expiry is not checked against the one asked               | 5                 |
| The signing step names a failure by no channel                | 5                 |
| The trampoline hint is not held to the LSP's key              | 5                 |
| A description without an expiry is dropped                    | 4                 |
| A forward-dated timestamp is accepted                         | 4                 |
| The description is not checked before the allocation          | 4                 |
| The final expiry delta is not checked                         | 4                 |
| The payment hash is not checked                               | 4                 |
| The release clock is read again for the expiry                | 4                 |
| The release margin has no slack                               | 4                 |
| The timestamp skew is a millisecond longer                    | 4                 |
| A cancelled invoice is not ended                              | 3                 |
| A description is accepted when none was asked                 | 3                 |
| A finished invoice is forgotten after abandonment             | 3                 |
| A paid invoice never released is received                     | 3                 |
| A released invoice reported expired or cancelled ends unpaid  | 3                 |
| A timestamp at the skew's edge is refused                     | 3                 |
| The creation clock is not checked                             | 3                 |
| The description's text is not checked                         | 3                 |
| The hash algorithm is not checked                             | 3                 |
| The options are not checked to be an object                   | 3                 |
| The recorded index is not checked against the watched hash    | 3                 |
| The release margin's slack is a millisecond short             | 3                 |
| createInvoice drops the options                               | 3                 |
| A past timestamp is refused                                   | 2                 |
| A received invoice ends expired with a TLC still listed       | 2                 |
| A zero amount is asked of the node                            | 2                 |
| An already-paid answer fails the settlement                   | 2                 |
| An invoice at its expiry's exact millisecond is past it       | 2                 |
| An offered TLC in flight is a poll failure                    | 2                 |
| Fiber's already-paid code is taken as paid under any message  | 2                 |
| PAYMENT_PENDING is recorded after abandonment                 | 2                 |
| The channel step names a failure by its listing, not its id   | 2                 |
| The index check runs after the mark                           | 2                 |
| The invoice step's pollNow is not wired                       | 2                 |
| The payee attribute is not required                           | 2                 |
| The release is tried after abandonment during the record read | 2                 |
| A released invoice is judged again and asks a tick            | 1                 |
| A released invoice reported cancelled ends unpaid             | 1                 |
| A tick is asked after abandonment during the settlement       | 1                 |
| An algorithm mismatch waits silently                          | 1                 |
| An invoice without an expiry is past it                       | 1                 |
| Another invoice's string is read as the watched one's         | 1                 |
| The creation clock is read before new_invoice                 | 1                 |
| The invoice step takes the default epoch                      | 1                 |
| The options are read again after the check                    | 1                 |
| The settlement runs after abandonment during the release      | 1                 |

"A released invoice is judged again and asks a tick" fails one test of the invoice step and never ends the flows: every
settlement asks for a tick at once, so the sweep stops it at its timeout; the row counts the step's test alone.
