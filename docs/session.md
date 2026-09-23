# Session

The signer session: the device's outbound WebSocket to the LSP's signer bridge, the challenge that authenticates it, and
the order in which what arrives on it is answered. It speaks the frames of [protocol.md](./protocol.md), keeps order, and
hands every request to the dispatch of [signing.md](./signing.md); it knows nothing of keys, policy or digests, and it
keeps nothing across restarts.

## The effects it is given

The session performs no platform call of its own. Everything that touches the outside world is injected at construction:

| Option            | Interface               | What the session does with it                                                                             |
| ----------------- | ----------------------- | --------------------------------------------------------------------------------------------------------- |
| `createWebSocket` | `WebSocketFactory`      | Opens one socket per attempt at the `url`; the socket is the `IWebSocketLike` below                       |
| `timer`           | `ITimer`                | Schedules the connect timeout, the heartbeat and the reconnect backoff                                    |
| `authenticator`   | `ISessionAuthenticator` | Answers the challenge: the wallet identity, or whatever holds its key                                     |
| `handler`         | `ISessionHandler`       | Answers sign requests and files registered channels: the signer dispatch, or a double of it               |
| `random`          | `() => number`          | Jitters the backoff; `Math.random` unless the host pins it, since it is ECMAScript and not a platform API |

`IWebSocketLike` is the intersection of the WebSocket objects of Node, browsers and React Native that the session touches:
`send(text)`, `close(code, reason)`, and the `onmessage`, `onclose` and `onerror` handler properties. `addEventListener`
is not uniformly available across the three, the properties are, and `onopen` is not needed because the bridge speaks
first. The handler properties are typed through a method signature so that a runtime's own event types, which carry more
than the session reads, assign to it under strict function types: `new WebSocket(url)` satisfies the interface as it is.
Only text frames are spoken; a binary message is refused by the codec like any other unreadable frame.

`ITimer` is one method, `schedule(callback, delayMs)` returning a cancel function, which avoids the handle type that
differs per runtime. The session arms each of its three timers through a `TimerSlot`, which numbers every arming and lets
a callback run only if it belongs to the latest one, so a host timer whose cancel does nothing cannot fire a stale connect
timeout into an established session: cancelling is an optimisation, never what correctness rests on.

## States

```text
idle ──connect()──▶ connecting ──challenge answered──▶ authenticating ──session_established──▶ established
                        │                                   │                                      │
                        │ socket lost, timeout,             │ socket closed: refused               │ socket lost, heartbeat timeout
                        │ factory threw, answer refused     │ version mismatch                     ▼
                        ▼                                   │                                 reconnecting
                   reconnecting ◀───────────────────────────┼──────────────────────────────────────┘
                        │ backoff elapsed, or connect()     ▼
                        ▼                                closed ◀── disconnect(), from anywhere
                    connecting                              ▲
                                                            └── a frame that does not decode or arrives out of the
                                                                sequence, and an authenticator that cannot answer:
                                                                from connecting as much as from authenticating
```

`connect()` asks to be connected as soon as possible: from `idle` or `closed` it starts a session, while one is being
established it joins it, in `established` it resolves at once, and in `reconnecting` it cuts the backoff short and opens
now. It resolves when the session is established and rejects when it cannot be, or when `disconnect()` comes first.
`disconnect()` closes the socket, cancels every timer, drops the queued requests, rejects whoever was waiting, and moves
to `closed`; it is the only way out of reconnecting. Reconnection therefore runs only between `connect()` and
`disconnect()`: the host maps foreground to the first and background to the second, which is how the SDK does not fight
the OS without knowing the app's state.

## Establishment

The bridge speaks first with a `challenge`; the session signs it through the authenticator, sends `signed_challenge`, and
waits for `session_established`, whose `protocol_version` must be its own. The connect timeout covers the whole sequence.
Each way it can fail is either the end of this attempt or the end of the session:

| What happened                                                | Outcome                                                           |
| ------------------------------------------------------------ | ----------------------------------------------------------------- |
| The socket closes or errors before the challenge is answered | Attempt failed: `reconnecting`, with the backoff below            |
| Nothing arrives within the connect timeout                   | Attempt failed: the device closes the socket, `reconnecting`      |
| The factory throws                                           | Attempt failed: `reconnecting`, so a bad url reports on every try |
| The socket will not take the answer to the challenge         | Attempt failed: the device gives the socket up, `reconnecting`    |
| The socket closes after the signature went out               | `handshake_refused`: the bridge saw the signature and hung up     |
| `session_established` carries another protocol version       | `version_mismatch`                                                |
| A frame that does not decode, or arrives out of the sequence | `protocol_violation`                                              |
| The authenticator cannot sign, or answers with other bytes   | `authentication_failed`, with the cause                           |

The last four are fatal: the session closes the socket, moves to `closed`, rejects `connect()` with the `SessionError`
of that kind, and does not reconnect, since retrying would not change the answer. The refused handshake is read from the
timing alone, a close while `authenticating`, because the bridge has no frame to refuse with: a bridge that rejects the
identity or the version does it by closing, and a network blip in that window comes out the same way, so the host that
wants to retry calls `connect()` again. What the bridge actually does there is an open question with the Fiber team, and
this is the position taken meanwhile. The timing is only read that way once the signature is on the wire: a socket that
refuses the frame never showed the bridge anything, so the session gives that socket up as lost and reconnects instead of
reading the close that follows as a refusal. What the authenticator answers is checked for its lengths before the frame
is built, so an authenticator that returns what is not a 64-byte signature, or whose public key is not 32 bytes, ends the
session like one that throws: left to the encoder it would come out as a frame the socket would not take, and the device
would reconnect forever on an answer no attempt can improve.

## One request at a time

Every message is decoded as it arrives, which is also what resets the heartbeat. The session frames are handled on the
spot: a bridge `ping` is answered `pong` at once, ahead of whatever is being processed, and a `pong` counts as life and
nothing else. The request-shaped frames, `sign_request`, `channel_registered` and `error`, join one FIFO that is processed
one item at a time in arrival order, and the next item never starts until the current one has been answered or failed.
The order matters because `state_version` is non-decreasing per channel ([policy.md](./policy.md)): a version 6 processed
before a version 5 would refuse the second as `stale_state`, and it was legitimate. The same FIFO carries the
acknowledgement of a registration, so the record is written before a sign request the node sends right behind it.

A `sign_request` is handed to the handler and answered on the socket that delivered it with the result or the refusal the
handler returned. If that socket is gone by then, the answer is dropped: the bridge re-delivers on the next session and
the answer is deterministic, so nothing is lost. A request whose envelope does not decode but whose `request_id` was read
is answered `malformed` in its turn; one whose id cannot be read is dropped and reported, since nothing could correlate
the answer. When the socket is lost, the requests queued behind the current item are dropped too, for the same reason: the
bridge re-delivers, and a re-delivered request finds the sign-once registry and answers with the same bytes. An
acknowledgement is not dropped, since nothing would deliver it again: it keeps its place and is settled in its turn, ahead
of whatever the next socket delivers.

A fault, the handler saying the failure was the device's own (its storage throwing, a record it refuses to read) or the
handler throwing outright, leaves the request unanswered and reaches the host as an `error` event. Answering one of the
four codes would make the node treat a device fault as a security event, so the bridge's own timeout and re-delivery
decide what happens next, and the session keeps the socket so that other channels proceed. Whether the bridge would
rather have a code for a device fault than no answer at all is an open question with the Fiber team.

## Heartbeat

On mobile networks a dead socket is only detected by traffic. After `heartbeatIntervalMs` of inbound silence the session
sends `ping` and waits `heartbeatTimeoutMs` for anything at all; if nothing arrives it closes the socket with the reason
`heartbeat timeout` and reconnects. A socket that will not take the `ping` is given up there and then, since waiting out
a timeout on a socket that already refused a frame only delays the reconnect. Any inbound frame resets the clock, the
device's own sends do not, and an interval of `0` disables the heartbeat. The defaults, twenty seconds and ten, are the
position taken while the bridge's own idle policy is an open question with the Fiber team; they are options so the
answer is a configuration change.

## Reconnection

A lost socket is reported as a `connection_lost` error carrying the close code and reason, or the timeout that gave it up,
then the session moves to `reconnecting` and waits `backoffDelayMs`: the initial delay doubled per failed attempt, capped,
and multiplied by one draw of `random`, which is full jitter, so a fleet of devices losing one bridge does not come back
in lockstep. The defaults are one second, a factor of two and a cap of thirty seconds. The attempt count resets when a
session is established and not before, so a `connect()` that cuts a backoff short opens now but leaves the count where it
was, and a host that calls it on every foreground does not walk the bridge back down to the initial delay. There is no
attempt limit: the session keeps trying at the cap until `disconnect()`, which is the host's foreground-to-background
signal. Whether to give up earlier is the facade's decision, not the session's. A
reconnect is never scheduled once the session is closed, so a `disconnect()` that lands while a loss is being reported
ends it for good all the same.

## Device-initiated requests

`registerChannel(pending)` sends the registration the dispatch prepared, under a request id of the session's own that is
never reused within the instance, and resolves with the channel id the acknowledgement carried once the handler has filed
the channel under it. It rejects with a `BridgeError` carrying the bridge's own code and message on an `error` frame, with
`connection_lost` when the socket goes before the answer arrives, with `disconnected` on a `disconnect()` that comes
before it, with `not_connected` when there is no established session to send on, and with whatever the handler threw when
the channel could not be filed. A registration is taken out of correlation the moment its acknowledgement or error
arrives, and that frame is settled in its turn whatever becomes of the socket: the node has already answered and will not
answer again, so neither a close while the frame waits in the FIFO nor one during the filing turns an answer received into
`connection_lost`. An acknowledgement or error that matches no pending request is reported as it arrives and ignored. A
rejected registration leaves no record; whether the node considers the channel registered is an open question with the
Fiber team.

## Events, and what a listener may do

`onEvent` delivers two kinds of event synchronously: `{type: "state", state}` on every transition and
`{type: "error", cause}` for everything that goes wrong without ending the session, plus the fatal errors themselves. The
state is announced before the cause, so a listener always reads the new state when it learns why. A listener that throws
never breaks the session, and a listener may call `connect()` or `disconnect()` from inside an event: whoever was waiting
is taken out of the session before the transition is announced, and settled after it, so what a listener adds on hearing
the transition is no longer among them; every timer is armed before the state that a listener could react to,
so a `disconnect()` from the `reconnecting` event finds the backoff to cancel and a `connect()` from the `closed` event
starts a session that the closing does not reject. The same holds of an error reported on the way out of a socket, which
is the one event a listener sees before the state that follows it: a `disconnect()` there is not undone by the reconnect
the loss was about to schedule, and a `connect()` there is answered by the session the device ends up with, never by the
one it is letting go of. A listener that ends the session and starts another in the same breath is answered by the one it
asked for: the session being let go of neither opens a socket once a new one holds it, nor resolves a `connect()` that
belongs to its successor, since every step that resumes after an event checks that the session is still the one it began.
An event reaches the listeners subscribed when it was raised, so one a listener adds on hearing it takes the next event
and not that one, and one a listener removes hears nothing further.

The event surface is deliberately this small. A refusal per request, the pending count `session_established` carries, or
a richer error taxonomy are decided with the facade, which is what consumes them.

## What the session deliberately does not do

- **No app state.** It does not know whether the app is foregrounded; the host calls `connect()` and `disconnect()`.
- **No response cache.** A re-delivered request is answered by the dispatch again; the sign-once registry and the
  deterministic nonce make the answer identical ([signing.md](./signing.md)).
- **No keys, no policy, no digests.** The challenge is signed by the authenticator, the requests by the handler.
- **No attempt limit, no close codes of its own.** The device closes with `1000` and a reason string, the one code a
  browser lets a client send outside the private range: `disconnect`, `connect timeout`, `heartbeat timeout`,
  `protocol violation`, `protocol version mismatch`, `authentication failed`, `send failed`.
- **Nothing published.** `src/index.ts` does not export the session yet: the injection interfaces and the event types go
  out with the facade, which is the first thing that lets a host construct a session at all.

## Where it lives

| File                                             | Contents                                                                                        |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| `src/session/signer-session.ts`                  | `SignerSession`: the state machine, the FIFO, the heartbeat, the reconnect, the correlation     |
| `src/session/session.types.ts`                   | The states, the events, the options and the reconnect policy                                    |
| `src/session/session.error.ts`                   | `SessionError`, with its seven kinds, and `BridgeError`                                         |
| `src/session/session.constants.ts`               | The defaults, the timer ceiling, the close code and reasons                                     |
| `src/session/interfaces/`                        | `IWebSocketLike`, `WebSocketFactory`, `ITimer`, `ISessionAuthenticator`, `ISessionHandler`      |
| `src/session/utils/backoff.utils.ts`             | The delay before a reconnect attempt                                                            |
| `src/session/utils/timer-slot.ts`                | One armed timer at a time, immune to a cancel that does nothing                                 |
| `test/mocks/session/`                            | The socket, timer and handler doubles the specs drive                                           |
| `test/utils/signer-bridge.ts`                    | `InMemorySignerBridge`: the LSP end of the protocol over the socket double, verifying node-side |
| `test/tests/session/signer-session.flow.spec.ts` | The flows: session, dispatch, policy and engine together against the bridge                     |

## What the tests guarantee

`test/tests/session/signer-session.spec.ts` drives the session through a socket double whose delivery is asynchronous, a
timer double advanced by hand, and a handler double whose answers can be held. The authenticator is the real wallet
identity of the vectors, and the `signed_challenge` it sends is verified with BIP-340 over the domain-separated digest,
and shown not to verify over the bare challenge. Beyond a happy path per feature:

- **Establishment**: the state sequence and the frame sent; each fatal failure with its kind, its message, the close
  reason and no reconnect; each transient failure reconnecting after the pinned delay; the refused handshake read from a
  close while authenticating, and a close before the challenge, and a challenge answer the socket refuses, both read as
  transient; an authenticator that throws and one that answers with a short signature, a long public key or no byte
  array at all, all fatal before anything is sent; `connect()` joining, resolving at once, cutting a backoff short,
  starting over after `disconnect()` and after a fatal failure, and rejecting on `disconnect()`.
- **Order**: three requests answered in order with the decoded envelope the handler saw; a held answer letting nothing
  overtake it; a refusal written as exactly its code and message; a fault and a throwing handler leaving the request
  unanswered and the next one answered; a malformed envelope answered in its turn and an unreadable one dropped; an
  answer dropped when its socket is gone, a queue dropped on loss, and a re-delivery answered on the new socket; the
  bridge's ping answered ahead of a held request; unexpected session frames and unreadable frames dropped and reported
  without closing.
- **Heartbeat**: the ping at the interval and the close at the timeout, both at their exact boundary; a ping the socket
  refuses giving it up at once instead of arming the timeout; the reset by an inbound frame, by one that does not decode
  as much as by one that does, and not by an outbound one; the pong keeping the socket; the interval of zero leaving no
  timer; the heartbeat moving to the new socket and stopping with the session.
- **Reconnection**: the delay sequence pinned under a stubbed `random`, the jitter, a custom policy, the reset after an
  established session and the count kept across a `connect()` that cuts a backoff short, nothing but waiting during the
  backoff, registrations rejected, and twenty failures not exhausting it.
- **`disconnect()`**: from every state, idempotent, a no-op when idle, leaving no timer, ignoring what the old socket
  still delivers, dropping an answer in flight, and reporting a socket whose close throws.
- **Registration**: the frame sent, the filing ahead of the sign request that follows, ids never reused across sockets,
  the bridge's refusal, the unknown acknowledgement reported as it arrives, every state without a session, the handler's
  failure, the socket refusing the frame, and a filing that outlives a `disconnect()`; an acknowledgement or refusal still
  queued behind a request when the socket is lost or `disconnect()` is called, settled in its turn with what the bridge
  answered, and ahead of what the next socket delivers.
- **Robustness**: events a runtime had already dequeued when the session let go of the socket, and a host timer whose
  cancel does nothing, neither reaching the next socket.
- **Reentrancy**: `connect()` and `disconnect()` called from inside each state event, from the error event of a lost
  socket and from the error of a close that throws, leaving no timer and no socket behind that the state does not account
  for, and reporting no session that is being let go of; a listener that ends the session and starts another from the
  `connecting` and from the `established` event, whose second session is the only one that opens a socket and the only
  one that answers its `connect()`.
- **Events**: a listener that throws still leaving the others reached, one that unsubscribes itself while being called,
  one another listener adds mid-event taking the next event and not that one, and the state the last event announced.
- **Options**: every timing refused below its floor, non-integer, or above the timer ceiling; the reconnect policy
  refused with a cap under the initial delay or a factor under one; the defaults pinned.

Coverage of the module is 100% on all four metrics, and the assertions were checked by breaking the code on purpose:

| Mutation                                                                     | Tests that failed |
| ---------------------------------------------------------------------------- | ----------------- |
| Requests are processed concurrently, not one at a time                       | 8                 |
| A fault is answered as a malformed refusal                                   | 2                 |
| An answer goes to the current socket, not the one that delivered the request | 2                 |
| The queued requests survive the loss of the socket                           | 3                 |
| A queued acknowledgement is dropped with the requests when the socket goes   | 4                 |
| A request delivered on a later socket is dropped                             | 3                 |
| The protocol version is not checked                                          | 1                 |
| A close while authenticating reconnects instead of failing                   | 2                 |
| The backoff attempt count never resets                                       | 1                 |
| A `connect()` that cuts a backoff short resets the attempt count             | 1                 |
| The attempt count is not reset by a `connect()` after `disconnect()`         | 1                 |
| The backoff attempt count never grows                                        | 6                 |
| Outbound frames reset the heartbeat                                          | 1                 |
| Inbound frames do not reset the heartbeat                                    | 3                 |
| A bridge ping is answered in the FIFO's turn                                 | 1                 |
| The state is announced before the signed challenge is sent                   | 2                 |
| Registrations are not rejected when the socket is lost                       | 1                 |
| The waiting are taken after the closed state is announced                    | 1                 |
| The backoff is armed after the reconnecting state is announced               | 1                 |
| `connect()` during a backoff leaves the backoff armed                        | 1                 |
| Registration ids start over on every socket                                  | 1                 |
| A violation while established is fatal                                       | 7                 |
| A registration resolves before the channel is filed                          | 1                 |
| The connect timeout outlives the establishment                               | 13                |
| The socket is opened after a listener's `disconnect()`                       | 1                 |
| An answered registration stays in correlation, so a close rejects it         | 6                 |
| A challenge answer the socket refused counts as sent                         | 1                 |
| A ping the socket refused arms the heartbeat timeout                         | 1                 |
| A reconnect is scheduled on a session a listener has closed                  | 1                 |
| The factory's failure is reported before the reconnect is armed              | 1                 |
| `connect()` reports a session whose socket is already gone                   | 1                 |
| A session a listener ended opens its socket all the same                     | 1                 |
| A session a listener ended resolves the `connect()` of the next one          | 1                 |
| The authenticator's answer is left to the encoder to refuse                  | 3                 |
| A frame that does not decode does not reset the heartbeat                    | 1                 |
| The heartbeat is armed whatever the state                                    | 1                 |
| An event reaches a listener subscribed while it is raised                    | 1                 |
| A re-armed `TimerSlot` lets the arming it replaced run                       | 5                 |

## What the flows guarantee

`test/tests/session/signer-session.flow.spec.ts` runs the real session, dispatch, policy engine and musig2 engine over an
in-memory storage against `InMemorySignerBridge` (`test/utils/signer-bridge.ts`), the LSP end of the protocol over the server
side of the socket double. The bridge challenges every socket, verifies the signature over the domain-separated digest and
pins the identity, announces the pending count and re-delivers every unanswered request on each new session, names a
registered channel the way fiber names a temporary one, and runs signing rounds the way the node will: it fetches the
device's nonce by number, aggregates it with a peer nonce derived from the vectors' remote seed, sends the operation object
the wire twin builds from a vector case, verifies the partial signature with scure under that aggregate, and aggregates it
with the peer's half into a Schnorr signature the 2-of-2 key must accept. A frame the node would not take (an answer to a
request it is not waiting on, a frame out of place or unreadable, a delegated settlement key that is not the TLC base key)
is a violation: the bridge records it, hangs up and rejects whatever it is waiting on, and every flow ends by checking that
it recorded none. A result the node cannot use (a partial signature that does not verify, a result without the bytes asked
for) rejects only the round or the fetch that asked for it, with the bridge's diagnosis, and leaves the session up. The
flows:

- **Session**: establishment with the identity verified and pinned, a device restored from the same seed accepted, another
  identity refused by the bridge hanging up and read as `handshake_refused`, another protocol version ending the session,
  requests queued while offline drained in order with the pending count announced, and the heartbeat answered in both
  directions.
- **Channel open**: registration under the name the bridge gives it, the TLC base key delegated and the funding key never,
  the public data `OpenChannel` needs fetched by number, the first commitment aggregated into a signature the 2-of-2 key
  accepts, and a registration the bridge refuses rejecting with the bridge's code and filing nothing.
- **The life of a channel**: the four signing methods over the wire, the send covered by a debit intent, each verified and
  aggregated by the node, with the whole record pinned at the end.
- **Re-delivery**: a socket lost right after a sign request is delivered, whose re-delivered request, same id and same
  envelope, answers the same bytes and writes nothing; and a device fault left unanswered, the next request answered, the
  faulted one answered on re-delivery once the cause is gone.
- **Refusals**: a refusal stalling neither the other channel nor the next request on the same one, both queued behind it,
  and a field the device cannot read answered `malformed`, naming the field and not the value.
- **A wiped device**: the same seed over an empty storage, accepted under the pinned identity and refusing all ten methods
  for the channel as `unknown_channel`, writing nothing.
- **The bridge's own checks**: a signature over the bare challenge refused, a partial signature that does not verify
  rejecting only its round with the session left up, an answer to a request the bridge never sent recorded as a
  violation, hung up on and rejecting what it waits on, and a delegated settlement key that is not the TLC base key
  recorded as a violation, the registration failing with the hang-up. They keep the checks above from passing vacuously:
  a bridge that stopped verifying or recording would still see every other flow green.

The digests bind the vectors' channel keys, so only the channel at the vectors' index can sign; a second channel on the
device is exercised through public data. The flows were checked the same way, by breaking the code of the modules they
cross; what only the session's own ordering decides (which socket an answer goes to, whether a queue survives a loss, one
request at a time) is invisible to them under a synchronous storage and stays pinned by the spec above:

| Mutation                                                          | Tests that failed |
| ----------------------------------------------------------------- | ----------------- |
| The identity signs the bare challenge                             | 19                |
| The registration delegates the funding key                        | 12                |
| The gate is skipped and the request signed anyway                 | 4                 |
| The balance rule reads the raw balance, not the settlement amount | 3                 |
| A refusal is reported as a fault                                  | 3                 |
| The record opens at zero exposure whatever was prepared           | 2                 |
| The already-signed path applies the balance rule again            | 1                 |
| The key list is sorted before the engine signs                    | 1                 |
| The registration is filed at a fixed index, not the prepared one  | 1                 |
| A fault is answered as a malformed refusal                        | 1                 |
| The announcement signs at a slot other than the one it published  | 1                 |

The bridge was broken the same way: disabling its challenge check, its partial signature check or its settlement key check
fails exactly one of its own checks each, and disabling its record of a violation or its hang-up on one fails the two that
record one.
