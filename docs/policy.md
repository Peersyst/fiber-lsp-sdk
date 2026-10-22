# Policy

The gate every signing request passes before the musig2 engine runs. It is the half of the design that makes deterministic
nonces safe and blind signing impossible: the engine signs whatever it is handed ([signing.md](./signing.md)), the digest
module rebuilds messages but judges nothing ([digest.md](./digest.md)), and this layer decides. The state it decides over is
the per-channel record ([persistence.md](./persistence.md)).

## The six checks, in order

Ahead of them, `PolicyEngine.checkAndClaim` validates the request's own **shape** and refuses it as `malformed`: two
distinct 33-byte public keys on the curve, one of which is this channel's funding key, a 66-byte aggregated nonce whose two
halves are points on the curve or at infinity, a 32-byte message, a known operation, and a slot fiber could have named: a
commitment number in range and the counter fiber reads that operation's slot from (below). On the wire the lengths are
checked once more, and earlier, by the protocol codecs ([protocol.md](./protocol.md)), which is where a field's spelling and
encoding are judged; the engine repeats the part it depends on because it is callable without the wire. The points are not
the codecs' to check but the gate's, before the claim: the musig2 engine would refuse them too, but with the slot already
served and nothing ever signed in it. Everything in a request is node-supplied, so a bad field has to be a wire refusal
rather than an exception escaping into the caller, and the same mapping covers the digest builders, whose rejections of
structurally impossible state (a fee no capacity covers, more than 255 TLCs, a public key off the curve) become `malformed`
rather than a crash. Inside the engine it precedes the channel lookup. Through the signer dispatch the channel is resolved
first, since the keys the gate takes derive from it, so a request for an unknown channel answers `unknown_channel` unless
the codecs have already refused it ([signing.md](./signing.md)).

The six then resolve the channel's name to its index and run as one step inside `SignerStore.updateChannelRecord`, so the
record they read is the record they write and no concurrent request can interleave with the decision. Every claim also
runs inside the store's balance lane, one at a time across every channel: the rule reads records other channels share, and
nothing may move a record between the decision that files a channel on a payment record and the claim it was filed for
(below).

| #   | Check                | Refusal           | What it means                                                                                                       |
| --- | -------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------- |
| 1   | Known channel        | `unknown_channel` | The channel's name resolves to no channel index. Corrupt state throws instead, it never reads as absence            |
| 2   | Digest recomputation | `malformed`       | The message must equal what the `digest` module rebuilds from the attached state: the no-blind-signing rule         |
| 3   | Sign-once            | `policy_refusal`  | The slot must be free, or already served for this exact session; under `allow`, one more session (below)            |
| 4   | Lanes and versions   | `stale_state`     | A fresh slot above its lane's last, a commitment's version after its view's, a revocation after its replacement     |
| 5   | Pins and bounds      | `policy_refusal`  | The channel's constant values, the terms the host pinned among them, and what a message takes from the funding cell |
| 6   | Balance rule         | `policy_refusal`  | Per commitment view and per payment hash: growth needs an open intent, a fall a TLC that took it                    |

## One channel, one registry

Check 1 asks whether a **name** resolves to a channel index, and everything after it works on the index. That indirection is
load-bearing rather than convenience: fiber names a channel twice, a temporary id while the open handshake runs and the id
derived from both sides' TLC base keys once it completes (`fill_in_channel_id`), and the device's secrets all derive from
the index, not from either name.

A registry keyed by the name would therefore split in two the moment the name changed, leaving two sign-once registries over
one nonce space, which is precisely the state that leaks the funding key. Keyed by the index it cannot: every name a channel
ever had resolves to the same record, the critical section runs on the index, and a request under the old name meets the
slots claimed under the new one. The bookkeeping lives in [persistence.md](./persistence.md).

Registration is what may add a name, and it may only rename a record that has **served nothing**. A record with a claimed
slot or a moved counter belongs to a live channel, and handing it another name would be handing away its slots; that is a
host error, not a node one, so it throws rather than refusing on the wire.

A name is claimed, not written: the alias is read and set inside one critical section, and a name already resolving
elsewhere throws. The check the engine runs before creating the record is the same rule stated early, so an ordinary
mistake writes nothing at all; the claim is what settles two registrations racing for one name, since only one of them can
read the alias free. The loser leaves an unreferenced record at its own index, which no name resolves to and which the
winner's slots are unaffected by.

## The slot model

A slot is claimed by the commitment number **the nonce is derived at**, which is not always the number inside the message.
That is what the sign-once registry has to protect, since nonce reuse is what leaks the funding key. The request names the
slot as fiber does, by its number and the counter fiber read the number from, and the counter has to be the one fiber uses
for the operation; any other is `malformed`.

| Operation                      | Slot                        | Counter  | Lane               | Number inside the message                                          |
| ------------------------------ | --------------------------- | -------- | ------------------ | ------------------------------------------------------------------ |
| Commitment tx                  | `COMMITMENT:<local number>` | `local`  | `COMMITMENT:local` | the version: local number when for remote, remote number otherwise |
| Cooperative close              | `COMMITMENT:<local number>` | `local`  | `COMMITMENT:local` | no commitment number                                               |
| Revocation the device sends    | `REVOKE:<remote number>`    | `remote` | `REVOKE:remote`    | the remote number minus one                                        |
| Revocation the device receives | `REVOKE:<local number>`     | `local`  | `REVOKE:local`     | the local number minus one                                         |
| Channel announcement           | `ANNOUNCEMENT:0`            | none     | `ANNOUNCEMENT`     | no commitment number                                               |

A revocation's counter is the one the revoked commitment's version counts: the device's own commitment carries the peer's
number, the peer's commitment the device's. Three consequences follow, all of them fiber's behavior rather than our choice:

- **A commitment slot serves a commitment tx or a close, never both** under the default mode. Fiber derives no closing
  nonce: a cooperative close signs with the commitment slot of the current local number (`get_funding_sign_context`).
- **The announcement slot is fixed and latched.** Its nonce never rotates, so a slot that followed the request would be a
  second nonce space under one nonce; a request naming another number than 0 is `malformed`. The signer dispatch refuses
  every announcement before it reaches the gate (a tenant channel is private), and the slot logic stays for the
  construction the vectors pin.
- **A revocation claims the slot of its nonce**, one above the number its message revokes. The off-by-one is fiber's.

## Lanes

Check 4 orders slots per **lane**, one per counter fiber reads a number from: `COMMITMENT:local` (commitments and closes),
`REVOKE:remote`, `REVOKE:local` and `ANNOUNCEMENT`, kept in the record's `lastSignedCommitmentNumbers`. The two revocation
lanes advance on different events, the remote number after a `SendRevokeAndAck` and the local one after a
`CompleteReceivedRevokeAndAck`, so they drift apart in the normal course of a channel. One counter for both would read a
fresh slot of the lane that lags as a rollback.

A slot the registry has not served must be strictly above the last number of its own lane, whatever the other lanes signed;
at or below it is `stale_state` (anti-rollback, the VLS pattern). A served slot goes to sign-once instead, which answers its
exact repeat whatever the lane signed since and refuses anything else, but for the one more session `allow` serves, which
may not sit below its lane's last (below). The sign-once key stays `<context>:<number>` and names no lane, because the nonce
does not depend on the lane: both sides of one revocation round derive the same nonce at the same number, so the second of
them meets a served slot, which is a second session (below).

## Versions per view

A commitment carries its own number, the **version** in its lock args, and check 4 holds it to the last version signed in
the same view: strictly above it in the device's own view, exactly one above it in the peer's, behind a revocation (below).
The two views carry different counters (the local number in the peer's commitment, the remote one in the device's own),
so neither the slot nor the other view orders them. The record keeps, per view, the last
commitment signed in it in `commitmentHashes`: its version, the view's floor, and the hash of its transaction, fiber's
`compute_tx_message` (the raw transaction with its cell deps emptied). That hash is the digest the gate recomputed, which is
the message of the transaction the node sent once the two match, so it costs nothing to keep. The transaction fiber
broadcasts adds the funding lock's cell deps, so its on-chain hash is another one: whatever reads this hash compares it
with the signed transaction rebuilt, not with a chain lookup.

### The peer's view, one version at a time

A remote commitment at version `v`, when the view's last is `w`, is signed only if `v` is `w + 1` and, unless `w` is the
first commitment of the view, the lane `REVOKE:local` stands at `w` and the revocation evidence (below) holds version
`w - 1`: the revocation of `w - 1`, which claims the slot `REVOKE:w`, has been served and its complete signature kept.
Anything else is `stale_state`. The view's first commitment is exempt, signed at any
version since nothing comes before it, and the one right after it waits on no revocation, since the one it would wait on
is of a commitment the view never had. Whether `w` is the first is deduced from the registry: the dispatch holds a sent
commitment's version to its slot's number ([signing.md](./signing.md)), so `w` follows another commitment of the view
only if the slot `COMMITMENT:(w-1)` was served. A slot served by something else (the device's own commitment, a close)
reads the same, so if the deduction errs it asks for one revocation too many, never one too few. The rule reads both
the lane and the evidence. The lane alone is not enough: the claim is written before anything is signed and the evidence
only after, so a crash between the two would leave the lane at `w` with no signature of the revocation, and a node that
moved on to `w + 1` instead of asking for the revocation again would have it signed with nothing to punish `w - 1` with.
The evidence alone is not enough either, since the evidence's own check only asks for the slot above it to be served,
which the device's revocation of its own commitment also does. An honest fiber never meets the refusal: it holds one
request at a time, so the revocation stays pending until it is applied, and the dispatch keeps the evidence before it
answers.

Without the rule, a peer's commitment could supersede its predecessor before that one's revocation was served. The
replacement rule (below) would then refuse that revocation as `stale_state` for good, since its view has moved past it, and
the older commitment, never revoked, would stay one the LSP could publish. An honest fiber never asks for it: it sends no
`commitment_signed` while it waits for the peer's `revoke_and_ack` (`waiting_ack`, `channel.rs:2032`, cleared at `:6468`).
The device's own view keeps the looser rule, `v` above `w`.

### A revocation follows its replacement

A revocation gives up the commitment one below its slot, and check 4 signs it only while the commitment replacing it is
the last one signed in the revoked one's view, at the slot's number: `commitmentHashes.local` at the slot for a revocation
the device sends (`SendRevokeAndAck`, which revokes the device's own commitment and is slotted by the remote number its
commitments carry), `commitmentHashes.remote` for one it receives (`CompleteReceivedRevokeAndAck`, the peer's commitment,
slotted by the local number). Fiber's device SDK holds a revocation to the same replacement
(`fiber-lsp-sdk/src/commitment.rs:671-689`). No replacement yet, one below the slot or one above it is `stale_state`: the
request is out of order with the record, not a content the device refuses, so the code of the rest of check 4 fits it,
and one whose replacement is not signed yet is answerable once it is. A repeat leaves at check 3 as ever, so a
revocation already served is answered after the view moved past it; a second session under `allow` is held to the
replacement like a first.

Fiber's SDK also requires, when sending, that the replacement hold a complete signature, so the device could publish it.
That check is not ported: the device keeps no complete signature of its own commitment. Through the dispatch, the
replacement reaches `commitmentHashes.local` only by `CompleteReceivedCommitment`, whose peer half the dispatch verified
before the claim ([signing.md](./signing.md)), but the claim writes the hash before `partialSign` runs: the node, which
publishes the device's commitment, holds the complete signature only once the device's answer lands. Until then the
replacement is recorded with no complete signature anywhere, which costs nothing, since the slot is served and a
redelivery of `CompleteReceivedCommitment` gets the device's half again. Keeping one on the device would serve a
recovery path the device does not have yet.

## Sign-once claims a session, not a message

The registry stores a commitment to the whole triple a signature answers: the ordered key list, the aggregated nonce and
the message, hashed under a versioned label. Counting messages would not be enough. A partial signature is
`s = σ·(k1 + b·k2) + e·a·g·d`, and `σ`, `b` and `e` all come from the aggregated nonce the node chose, so one slot and one
message under three different aggregates are three linear equations that solve for the funding key
([signing.md](./signing.md)).

A repeat that matches the stored commitment byte for byte is the idempotent resume path: the gate answers `already-signed`
and the caller re-signs, which is deterministic and therefore identical. That path leaves the pipeline at check 3, so a
re-delivery charges nothing, files nothing and moves no counter, and the stale numbers it would otherwise carry never matter.

## Nonce reuse under `allow`

Fiber's lifecycle, as it stands, asks for more than one signature per slot: at the open both commitment transitions land
on one commitment slot, each round the peer starts puts its two commitments on one commitment slot (three messages
when it follows a round of the device's: the known cost, below), and the two sides of a revocation round share the
revocation slot at one number. Under the default rule the second message of each is refused,
and no channel can open. `new PolicyEngine(store, { nonceReuse })` takes the mode: `refuse`, the default and the rule
above, or `allow`, a compatibility mode for fiber's current nonces that goes once fiber fixes them. An absent mode is
the default; any other value, `null` included, is a `TypeError` naming `options.nonceReuse`. The facade takes it as its
`nonceReuse` option ([sdk.md](./sdk.md)).

Under `allow` a served slot serves **one** more session, never two. With a deterministic nonce, each partial signature on
one slot is one equation `s_i = σ_i·(k1 + b_i·k2) + e_i·a·g·d` in the same three unknowns `k1`, `k2` and `d`: two of them
leave a nonce pair that answers both for every candidate key, which hides it, and a third solves the system for `d`
([signing.md](./signing.md)). So:

- A second distinct session on a served slot is claimed, logged in the record's `nonceReuse` under the slot (its session
  commitment and its message), and answered `reused`, which the dispatch reports as a warning.
- A third distinct session is `policy_refusal`, in either mode.
- A byte-identical repeat is idempotent and writes nothing: the first session answers `already-signed`, the second
  `reused` again, so every delivery of a signature made under a reused nonce carries its warning. Both are answered in
  either mode, so a host that turns `allow` off keeps answering what was already served and refuses the rest.
- The second session runs every check a first one does: the digest, its view's version, the pins and bounds, the balance
  rule, and it updates the view and the commitment hash a first one would. It also moves its own lane up to its number,
  as a first session does. In the round the peer starts, `SendRevokeAndAck` takes `REVOKE:2` fresh on `REVOKE:remote` and
  `CompleteReceivedRevokeAndAck` arrives at `REVOKE:2` as its second session: that is the peer's revocation, the one the
  peer's view waits on in `REVOKE:local` (above), and a lane left below it would refuse the peer's next commitment for
  good. Lanes still only rise: a second session may sit at its lane's last number but never below it, since reuse serves
  fiber's lifecycle, never a rollback to a slot the lane has left (`stale_state`).
- The claim is written before anything is signed, as for a first session.

The known cost: a round the device starts leaves its own completed commitment on `Commitment@L`, after its
`CompleteReceivedRevokeAndAck` moved L, and the peer's next round puts its two commitments on that same slot. That is a
third message on one slot, which `allow` refuses, so after any round of the device's the peer's next round stalls: the
fulfil of a payment the device sent, and a payment received after one it fulfilled. It lasts until fiber gives each message its own
nonce ([signing.md](./signing.md) runs both sequences).

## The claim is written before anything is signed

The gate persists the claim and only then does the caller sign. The reverse order loses: a crash between producing a
signature and recording it would leave the slot free with its nonce already exposed, and the next request could take it
with a different session. Claiming first is safe precisely because the nonce is deterministic, so the interrupted request
is answered identically when it comes back.

## The channel's pins

Every request states values that are constant for the channel's life: the funding output, the peer's funding and TLC base
keys, the commitment delay and fee rate, both reserves, the asset, the commitment lock's layout, and on a close the
script the device's side pays to. They all enter the digest, so check 2 binds the signature to them, but nothing in the
request says they are the channel's: a node could state a longer delay, a higher fee rate or a funding output the user
never paid into, and sign a digest of it. Check 5 holds each of them to one value per channel, kept in the record's
`pins` ([persistence.md](./persistence.md)).

| Pin                         | Fixed by                                     | Stated by                                     |
| --------------------------- | -------------------------------------------- | --------------------------------------------- |
| `fundedShannons`            | the registration                             | (the opening, below)                          |
| `localCloseScript`          | the registration                             | a close, and a revocation the device receives |
| `localReservedCkbShannons`  | the registration, under both layouts (below) | a commitment, a revocation                    |
| `udtTypeScript`             | the registration, as `null`                  | all four                                      |
| `liquidCapacityShannons`    | the host's terms                             | a commitment, a revocation, an announcement   |
| `commitmentFeeRate`         | the host's terms                             | a commitment, a revocation                    |
| `remoteReservedCkbShannons` | the host's terms                             | a commitment, a revocation                    |
| `fundingOutPoint`           | the host, or the first sight                 | a commitment, a close, an announcement        |
| `fundingCapacityShannons`   | the host, or the first sight                 | a commitment, a revocation                    |
| `remoteFundingPubkey`       | the first sight                              | all four                                      |
| `remoteTlcBasePubkey`       | the first sight                              | a commitment                                  |
| `commitmentDelayEpoch`      | the first sight                              | a commitment, a revocation                    |
| `lockLayout`                | the first sight                              | a commitment, a revocation                    |

What the device knows before the node states anything is fixed when the channel is registered: the amount the user
funded and the close script the open passed as the device's shutdown script, both given by the facade, the device's
reserve, which fiber sizes over that script, computed under both lock layouts, and the asset. Registration refuses what
fiber would not open: a funded amount below the lower of the two reserves, the `legacy` one, which comes out of it, or
not below `u64::MAX`, the most a CKB channel's capacity holds. The floor is the lower one on purpose: registration exists
so as not to refuse what a node would open, a legacy node opens in that 1 CKB window, and what a full-hash node refuses it
refuses itself, with nothing signed.
`SignerDispatch.prepareChannelOpen` runs the same check (`assertChannelOpening`) before the open is sent, since a
channel the node opens and the device then refuses to file is left open and unfiled.

**The terms** are three values a request states but nothing in it vouches for, so a first sight of them would be a value the
node chose: the commitment fee rate, the peer's reserve and the liquid capacity. `PolicyEngine.pinChannelTerms` takes them
from the host, which reads them from the node's `opening_context` once the open is accepted and checks them against what the
device asked. A commitment, a revocation or an announcement on a channel whose terms the host has not pinned is refused
(`policy_refusal`), naming the first term that is missing; a close states none of them and needs none.

`PolicyEngine.pinFundingCell` takes what the host knows from the funding tx it is to sign, the out point and the
capacity of the funding output. Neither order is assumed, since fiber can ask for the device's own first commitment
before the signed tx is back: whichever states the cell first pins it, and a message that then states another is refused.
Both host pins share one path: a value that conflicts with the one pinned throws a `ChannelPinError` carrying the
conflict, so the host can tell a cell or terms other than the channel's (the open is not to be funded) from a malformed
argument, which throws a `TypeError` or, out of range, a `RangeError`, or a channel it never registered, which throws a
`TypeError`. Pinning the same values again writes nothing. Both run in the balance lane, so neither moves a record between
a claim's decision and its write.
The rest is pinned by the first signed message that states it, in the same write as its claim; a refused message pins
nothing, and no message ever pins a term. A value that differs from the one pinned is refused, naming the field and both
values.
`PolicyEngine.readChannelPins(channelId)` hands out a copy of them, resolving the name as a claim does (`unknown_channel`
for a name never registered, a thrown `TypeError` for one whose index holds no record). The signer dispatch calls it at its
step 8 to build a request's input from the terms, the device's reserve and the layout a commitment pinned, since no request
states them ([signing.md](./signing.md)). The read takes no lane, so a pin may move before the claim; the claim holds the
input to the pins as they stand when it runs, so a value pinned in between that differs refuses the request rather than
being signed over.

Five choices sit in that table:

- **The asset is fixed, not seen.** A channel the device opens is a CKB channel until the multi-asset shape is decided,
  so a request that states a UDT script is refused. Pinned at first sight, a node could present a CKB channel as a UDT
  one, whose amounts are not shannons, and read the funded amount in another unit. The asset is read ahead of every
  other pin, so that is the refusal such a request gets, whatever else it states. A close states it as `null` always: it
  is read off outputs that carry no type script ([digest.md](./digest.md)).
- **The device's reserve is computed, not seen.** Fiber sizes it over the shutdown script of the open
  (`reserved_capacity`, over `occupied_capacity`): the capacity a cell locked by that script occupies, its args counted
  at no less than the commitment lock's, plus the 1 CKB kept for the close fee. The commitment lock's args are 57 bytes
  under the `legacy` layout and 58 under `fullPaymentHash` ([digest.md](./digest.md)), so on a typical lock the reserve
  is 99 CKB under one and 100 under the other, and the node never declares the layout: it is read from the lock args of
  the first commitment. Registration therefore computes the reserve under both layouts, and the layout a message states
  picks the value it is held to: only a commitment and a revocation state the reserve, and both state the layout beside
  it. "Computed, not seen" stays true: the node only ever chooses between two values the device computed, and choosing
  one pins the layout with it. Pinned at first sight instead, a node could open with the whole funding as the device's
  reserve: the opening would still pay the funded amount, and none of it could be spent.
- **The lock layout is pinned at first sight**, declared by a commitment and by a revocation (both size their fee over
  the commitment lock's mock, so both carry it), never by a close or an announcement, which do not depend on it. A
  message under the other layout is refused as any pin conflict, and it is read right after the asset, so a legacy
  message on a full-hash channel is refused by its layout before its reserve.
- **A close and a revocation the device receives pay the device's own close script** (fiber's `local_shutdown_script`),
  so they state that pin. A close is read by output position, in fiber's funding-pubkey order, so a close whose two
  outputs the node swapped reads with the peer's output as the device's and still hashes to its message: this pin is what
  refuses it. A revocation the device sends sweeps to the peer's script, which the device has no reason to fix: a wrong
  one harms the peer only.
- **The capacities are pinned as sums.** The liquid capacity, `to_local + to_remote`, is what the funding cell holds
  beyond the reserves and does not move while the channel lives; the funding cell's capacity is that plus both reserves
  (on a UDT channel the liquid amount is the cell's data, and its capacity the reserves alone). The pair is what ties
  what a commitment states, which sizes its cell and nothing the balance rule reads, to the cell the user paid into.

## Bounds on what a message takes

The pins fix the cell; check 5 then bounds what a message takes out of it beyond the amounts the balance rule judges.

- **The commitment fee**, which a commitment and a revocation both take from the funding cell, is at most 0.5 CKB:
  half of the 1 CKB fiber keeps in each reserve for the close fee, which is fiber's own bound at open
  (`check_commitment_reserved_fee`). The device runs it on every request, even at the rate the host pinned, and bounds
  the fee rather than the rate because the cell dep count that sizes it is not a channel constant and is not pinned.
- **The device's fee on a close** is at most 1 CKB, the part of the reserve fiber sets aside for it
  (`DEFAULT_MIN_SHUTDOWN_FEE`). The close's tx states no fee rate, so the bound is read on what it pays the device, and
  the balance rule applies it (below). Fiber bounds it by the whole balance only. The peer's output is the peer's.
- **What a commitment pays out**, both settlement amounts and every TLC it lists, is at most the liquid capacity. Fiber
  pays out exactly that in every state but one: the device's own commitment while a removal waits on the previous ack
  lists the TLC nowhere and still deducts its amount, so it pays out less.

At fiber's default rates both fees are a few hundred shannons, five orders below their bounds. The bounds exist so that
the most a fee can take is the reserve's margin, never the balance.

## The balance rule

The device signs two commitments for every change of state, the peer's (`forRemote`) and its own, and they do not list the
same TLCs at the same time: an offered TLC reaches the peer's commitment first and the device's own only after the peer's
`RevokeAndAck`, and a `commitment_signed` that crosses one of the device's adds is signed over a commitment without it. The
record therefore keeps one **view** per commitment, and each view is judged against its own previous message only. One
number compared across both would read the crossing as an increase followed by an unexplained decrease.

A view's snapshot is what the last message signed in it stated: the **exposure**, what the settlement witness pays the
device, which is fiber's TLC-adjusted settlement amount (`to_local + received_fulfilled - offered_pending -
offered_fulfilled`) plus the device's reserve, and the TLCs it listed. The reserve is pinned, so it moves the exposure of
no message; it is in it so that the state a channel opens at is the funded amount, which the facade knows before the node
states anything. A TLC is kept as what the
settlement witness binds of it: its direction, its hash algorithm (in the entry's flag byte), the payment hash as the
witness binds it, its amount and its expiry in whole seconds, never by its id. The id only orders the witness. How much
of the hash the witness binds is the lock layout's ([digest.md](./digest.md)): the first 20 bytes under `legacy`, where
the remaining 12 are bound by nothing, and all 32 under `fullPaymentHash`. The snapshot keeps the first 20 as
`boundPaymentHash` under both, and the whole hash as `fullPaymentHash` under the full-hash layout, `null` under the
other. Snapshots are compared as multisets of those values, the full hash included, so under the full-hash layout two
TLCs apart in their unbound bytes alone are two entries. Next to them each view keeps, per bound hash, what it has
**charged** and what it has **credited** (below).

Two kinds of records sit beside the channel's, device-wide and keyed by the same 20 bytes, because the node and not the
device chooses which channel a payment leaves through:

- a **debit intent**: the most the user approved for a payment, amount and fee budget together, and whether it is still open;
- a **hold invoice**: its amount, and whether the device has released its preimage.

The records are keyed by the 20 bound bytes under both layouts, so the sums below add up across channels whatever
layout each is on: a legacy channel and a full-hash channel drawing on one intent draw on one budget. Which TLCs count as
a record's is the layout's to say. Under `fullPaymentHash` a TLC is the record's only when the whole hash agrees: an
offered TLC whose full hash is not the one of the intent under its key is refused outright, since it draws on no budget
the user approved, and a received TLC whose full hash is not the one of the invoice under its key is nobody's invoice:
it is not credited, it is not held to the release or to the algorithm, and it does not make the mix below. Under
`legacy` the device cannot tell, so it matches the prefix, as before: a TLC that binds no full hash is the record's by
its key alone.

Write `holdings = exposure + the offered TLCs listed`, what the device has if every offered TLC comes back. A fulfilled
offered TLC lowers it by its amount; a failed one leaves it where it was; a received TLC fulfilled raises it. For a commitment
`M` of a view whose previous message was `P`:

1. **A channel may draw more under a hash only against an open intent.** What a view draws under a hash is what it shows
   offered under it plus what it has charged to it, so a fulfilment only moves an amount from one to the other, while a
   TLC that replaces one gone with the money draws again. When a view draws past what the channel already drew in either
   of its views, the hash needs an open intent: a view catching up with an add its other view already showed draws
   nothing new, and is signed even once the intent has closed, since that TLC was shown against an open one. Then and
   the most every channel can draw under it stays within the intent's maximum: each channel at whichever of its two
   views draws more, this one included. A retry, a second part of a multi-path payment and the routing fee are all this
   one case, and the bound is the one fiber keeps for itself (`amount + max_fee_amount`).
2. **Holdings may fall only by what offered TLCs took with them.**
   `shortfall = holdings(P) + credit - holdings(M)`. Every offered TLC that left `P` and could have been paid is charged to
   its hash: one that belongs to some set of those that left whose sum, less what received TLCs that left may have added
   unasked, is the shortfall, so a set summing to anything in `[max(shortfall, 0), shortfall + uncredited received]`. A
   received TLC counts there unless it belongs to an invoice whose preimage the device has not released: the node does not
   know that preimage, so such a TLC can only have failed. A received TLC with no invoice (a keysend) and the part of a
   released invoice past what it owes do count, since the node may have collected them on its own. That holds with nothing
   fallen too: a paid offered TLC and a keysend the node fulfilled on its own leave the exposure exactly
   where both failing would, and leaving the TLC uncharged would let a retry draw its budget again. The empty set fits
   whenever nothing fell, so only a positive shortfall that no set accounts for is a refusal, since no outcome fiber can
   produce explains it. The search is exact up to twelve departing TLCs; past that every one of them is charged, which is
   the conservative side.
3. **A released preimage must be paid for.** `credit` is, for every invoice whose preimage the device released and whose
   received TLCs left the view, their amount up to what the invoice still owes: its amount less this view's credit and,
   for every other channel, the credit of whichever of its two views was paid less. A commitment that drops such a TLC as
   failed has a shortfall nothing covers, and is refused.

Both bounds count every other channel at its worst view, not at the view being judged, because the node can choose. It
aggregates both partial signatures of every channel, so it holds both commitments of each and may broadcast the peer's one
here and the device's own there. Summed per view, two channels each showing a payment in a different view would each pass
a budget of one payment while the node collects two; and an invoice credited by one channel's peer commitment and another
channel's own commitment would let the node broadcast the two that never paid. The worst case per channel is the bound
that holds whatever pair it broadcasts.

Nothing but a fulfilled offered TLC can lower the holdings, so a message that pays the node under a hash no user
approved finds no intent at step 1, and a node that takes a released preimage and fails the TLC anyway is refused at
step 3, unless an offered TLC leaving in the same message can account for the credit. A released TLC and an offered TLC
of the same amount failing together leave the exposure where both being paid would, and the node sets the split and the
fee of the outgoing payments, so it can match the amounts. There the device loses the held amount, bounded by that
offered intent, and the offered hash is burnt. The engine keeps a channel from ever reaching that state:
`markHoldInvoiceReleased` refuses with a `HoldInvoiceError` (`offered_in_flight`) while any channel that lists a TLC of
the invoice also lists an offered TLC, in either view (a channel that no longer lists one cannot take a new one beside
an offered TLC once the preimage is released, so it does not hold the release back), and a commitment after which a
channel would list an offered TLC beside a received TLC of a released invoice, in either view, is refused, unless the
channel already did and the message only retires TLCs: a mixed channel may resolve, never grow, since a new offered TLC
there could cover for the released one again. Both checks run in the balance lane, so nothing can slip an offered TLC in
between the check and the release. A hold invoice also records its hash algorithm, since a preimage opens a TLC only
under its own: the release is refused with `algorithm_mismatch` while a channel lists a TLC of the invoice under another
algorithm, and once released a commitment that adds one is refused. Such a TLC could never be paid and would time out on
chain back to the node, which already collected upstream with the preimage.

What the rule cannot know it charges conservatively. Which of two departing TLCs was fulfilled is not in the message: when
both could account for the shortfall both are charged, because charging one would let the other's budget pay twice. The
cost is not a refused retry: a false charge costs the user that payment hash, since with the intent open the charge already
takes the budget, and once it is closed `intent_charged` refuses it for good, so the hash can no longer be paid from the
device. A paid pair and a failed pair leave the same exposure, so an offered TLC leaving beside a released
one is charged rather than read as the released one failing. A preimage in the request would make both exact.

An intent is never deleted. The host closes it when the payment is final, which only stops growth: TLCs already shown
stay signable until they resolve. Recording an open intent again with the same maximum changes nothing, so a host unsure
whether its first call landed may repeat it; another maximum is refused. A closed intent opens again with a fresh budget
only if nothing was ever charged to it, which is fiber's own rule for sending a hash again after a failure. Those two
refusals are state the user can cause, by paying one invoice twice, so they throw a `DebitIntentError` whose code says
which (`intent_open`, `intent_charged`), and the facade can tell them from a malformed argument, which stays a
`TypeError`. They are the host's and never reach the wire, so they are not `PolicyRefusalError`s. A third code,
`own_invoice`, refuses an intent under the bound hash of one of this device's hold invoices: paying one's own invoice
would have the rule read one hash as money out and money owed in at once. The reverse, an invoice under the hash of an
authorised payment, is a host bug, since every preimage is derived anew, and stays a `TypeError`. The host records an
intent before the operation that causes the TLC, never after: `transfer` records it and then issues `send_payment`. An
invoice is recorded before the node hears of its hash, and marked released before the preimage leaves the device.

A **cooperative close** is judged against both views at once: it lists no TLC, so neither view may still list one (fiber
builds a close only once none is pending), and what its output pays the device may fall short of neither view's
exposure by more than the 1 CKB its fee may take, check 5's bound read on the payout, since the close's tx states no fee
rate: `local capacity >= max(exposure) - 1 CKB`. Its payout is read off the tx itself, the output fiber's funding-pubkey
order gives the device, held to the device's close script by check 5. It spends no intent, having no hash to name one.

**The opening.** Both views start at the funded amount with no TLC. The channel's first commitment, the first message that
claims a slot on the commitment lane, must list no TLC and pay the device exactly the funded amount, whichever view it
belongs to; the first message of the other view is then judged against the opening state by the rule above. A channel whose
first message is a close (fiber builds none that early, but the device does not assume it) is judged by its views alone from
then on, which stand at the opening state. The funded amount comes from the facade, so a node that opens a channel with less
in it than the user paid is refused at its first signature.

Each device-wide record lists the channels that have shown a TLC under its hash, written before the claim that shows it,
since a claim may only write its own channel's record. That list is how a claim finds the other channels drawing on one
budget or crediting one invoice, and a channel too many on it costs a read. The engine decides each commitment once before
writing anything and again inside the record's critical section, so a refused request leaves the device-wide records
untouched too, and the balance lane keeps two channels from drawing on one budget at once.

## Revocation evidence

Once the device has signed the revocation of a peer commitment and holds the peer's partial signature too, the signer
dispatch aggregates the two, verifies the complete schnorr signature under the aggregated key, and hands it to
`PolicyEngine.recordRevocation(channelId, { version, signature })` ([signing.md](./signing.md)). The record keeps it in
`revocations` as `{ version, forRemote: true, signature }`: the evidence that the peer's commitment at that version is
revoked, which a superseded peer commitment published on chain would be swept with.

The write is an upsert by version, kept in ascending version order: recording the same signature again writes nothing,
and another signature of the same version replaces it. The dispatch records again on the already-signed path, so a crash
between signing and recording heals on the next delivery. The engine verifies nothing cryptographic here, the caller has;
it refuses, as a host error, evidence for a version whose revocation slot (one above it) the channel never served, since
evidence of a revocation the device never signed is none. The write runs in the record's own lane and not in the balance
lane: a claim only ever asks for evidence to be there, no write of the evidence takes any away, and a claim that lands
beside it writes the record it read, evidence included.

## What this layer deliberately does not do

- **It does not verify the aggregated nonce or the peer's partial signature.** Both are the signer dispatch's, before it
  calls the gate ([signing.md](./signing.md)). The gate's guarantee does not rest on them: whatever aggregate the node
  sends, a slot serves at most the sessions its nonce can safely answer.
- **It does not re-derive the state it is shown.** TLC selection, settlement amounts and close outputs arrive as inputs.
  The digest binds the signature to them and the record judges them; re-running fiber's TLC state machine would be a
  second source of truth with its own bugs.
- **It does not sign.** Nothing in the pipeline forces the caller to sign what it claimed. The gate and the engine are
  one path in the signer dispatch, at one call site that signs exactly the slot the verdict names
  ([signing.md](./signing.md)).
- **It cannot check a value the first time it sees it.** A pin taken from a request is a value the node chose once: the
  commitment delay and the peer's keys are held to their first value, not to a right one. The funded amount, the close
  script, the device's reserve, the asset and, through the host, the funding cell and the terms are the exceptions, being
  the device's own or checked by the host against the open it asked for.
- **It does not check the funding output's lock.** The funding cell's out point and capacity are pinned, but whether its
  lock is the 2-of-2 the device holds half of needs the peer's funding key before the host signs, which nothing gives it
  (an open question with the Fiber team).
- **It judges the latest commitment of each view, never the ones it supersedes.** A commitment the device signed stays
  publishable until it is revoked. The device keeps the complete revocation of every superseded peer commitment as
  evidence (above), but its own superseded commitments are revoked by a signature only the node holds, and the gate has no
  signal it can check that one is no longer publishable. A budget is therefore bounded at the latest state only: a TLC
  that failed under a hash in one channel frees its budget, and an operator that withholds its `RevokeAndAck` could
  publish the superseded commitment still listing it after a retry elsewhere was paid. The device rests on the operator of
  its node not publishing superseded state; nothing device-side closes this, and it is an open question with the Fiber
  team (I8).
- **It cannot tell a fulfilled TLC from a failed one except by the amounts.** The request carries no preimage, so step 2
  charges every TLC that could have been paid, as described above.
- **It never prunes the record.** A slot per signed commitment, a log entry per reused slot and an evidence entry per
  revoked peer commitment stay forever. Pruning the registry is only safe behind the lanes, which refuse a number already
  served even when its slot is gone, and it would cost the idempotent replay of an old request.

## Where it lives

| File                                     | Contents                                                                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `src/policy/policy-engine.ts`            | The six checks, sign-once and reuse, the claim, channel registration, the host's pins, the evidence, intents and hold invoices |
| `src/policy/channel-opening.ts`          | What a channel opens with: the funded amount and close script checked, and the registration's pins                             |
| `src/policy/channel-pins.ts`             | Check 5's pins, pure: what each operation and the host's terms state, in the pins' forms, and the first conflict               |
| `src/policy/capacity-bounds.ts`          | Check 5's bounds, pure: the commitment fee and what a commitment pays out                                                      |
| `src/policy/balance-rule.ts`             | Check 6 itself, pure: the opening, the three steps over two snapshots, and the close with its fee bound                        |
| `src/policy/policy.constants.ts`         | The keyspace prefixes and the balance lane, the pins by who fixes them, the reuse modes and the lanes, the record versions     |
| `src/policy/policy.error.ts`             | `PolicyRefusalError`, carrying the wire error code; the host's `DebitIntentError`, `HoldInvoiceError` and `ChannelPinError`    |
| `src/policy/utils/payment-hash.utils.ts` | The bound payment hash a payment record is keyed by, and whether a TLC under that key is the record's                          |
| `src/policy/utils/slot.utils.ts`         | Operation and counter to slot and lane, where the shared close slot and the fixed announcement live                            |
| `src/policy/utils/session.utils.ts`      | The session commitment and the shape a signable session must have                                                              |
| `src/policy/signer-store.ts`             | The persistence underneath ([persistence.md](./persistence.md))                                                                |

## What the tests guarantee

`test/tests/policy/policy-engine.spec.ts` builds its requests out of the cross-implementation vectors, so check 2 runs
against digests generated by fiber's own Rust code rather than by the code under test. Around that: a refusal per check and
per malformed field, both sign-once refusals the spec demands (a served slot re-requested with another message, and with
the same message under another aggregated nonce or another key list), the two directions of the shared commitment slot, the
latched announcement, the already-signed path leaving the record untouched and costing no write, and two concurrent
sessions racing for one slot where exactly one wins. The slot is refused per field: a number past the chain or not an
integer, no slot, every counter fiber does not use for the operation (a commitment, a close, either revocation and the
announcement each read from the wrong one), and an announcement at another number. The lanes: a fresh slot at and below
its lane's last refused, a revocation below the other lane's last accepted, both lanes and the announcement's kept apart,
a close ordered on the commitment lane, the second side of a revocation round refused under the default mode, and a
repeat answered whatever the other lane signed since. The replacement, for each direction: a revocation signed once its
view's last commitment is at the slot's number, refused as stale with no commitment in the view, one below and one above,
writing nothing, refused when only the other view is at the number, its repeat answered once the view moved past, and a
second session under `allow` held to its own. The views: a version equal to and below its view's last refused,
each view ordered apart from the slot and from the other view, and the hash of each view's last commitment kept, checked
against `compute_tx_message` of the transactions fiber built. The peer's view, one version at a time: its first
commitment signed at any version and the one after it with no revocation signed, a version two above the last refused,
the next one refused while its revocation slot is unsigned and signed once it is, refused while the lane stands one
below and while only the device's own revocation took the slot, signed once the peer's took it as a second session, a
second session on the view held to the rule like a first, the repeats of a version the view moved past answered as
already signed and as reused, the one after the first asked for a revocation when a slot below the first was served
(the deduction asking one too many), and the device's own view left free to skip versions, each refusal writing nothing.
Under `allow`: the second session served, logged and reported as reused, the same one refused by default, a third
refused, both repeats idempotent with no write, a logged session still answered once the mode is off and a third still
refused, the other lane's revocation served on the slot one lane served, moving its own lane to the slot, a second
session at its lane's last served and below it refused as stale, a second session held to its
view's version, the pins, the balance rule and the close rule, its channel filed on its intents, and an unknown mode
refused. The terms: pinned, at u64's maximum, repeated with no write under either name, each one conflicting with a
`ChannelPinError` naming both values, each malformed argument refused by name, an unregistered channel and an alias with
no record thrown, every operation but the close refused on a channel whose terms are unpinned, naming the first missing,
and the close signed there. The evidence: kept, repeated with no write under either name, replaced by another signature
of its version, kept in ascending order, the record otherwise untouched, refused for a version whose revocation slot was
never served, each malformed argument refused, the highest version the chain holds recorded, and an unregistered channel
and an alias with no record thrown. The pins read back: the registration's, then with the terms, then with what the first
message stated, under either name, as a copy the caller's writes do not reach, and an unregistered channel refused and an
alias with no record thrown.

The balance rule has a spec of its own, `test/tests/policy/balance-rule.spec.ts`, over snapshots written by hand: a refusal
per step and per bound (no intent, a closed one, one shannon over the maximum, other channels' TLCs and charges, this view's
charges, every channel counted at its worst view), a view catching up with its other view under a closed intent and one
drawing past it, the retry after a failure, the replacement inside one message, the parts of a multi-path payment, every
charging case (exact, none, ambiguous, widened by a received TLC and never by a held one, with nothing fallen, the
twelve-TLC boundary on both), every credit case (failed, fulfilled, unreleased, unknown, a part, the cap across channels,
another channel at its less paid view), the offered TLC refused beside a released held one in either view and a mixed
channel refused a new offered or released held TLC and allowed to retire TLCs, a TLC of a released invoice refused under
another algorithm (added, or changed between two messages) and allowed before the release, the close against each view at
the exact edge of the 1 CKB its fee may take and one shannon past it, and the full-hash layout: an offered TLC under a twin
of its intent's hash refused (first, even where the other view already shows the intent's TLC), a received twin of a
released invoice neither credited nor asked for nor held to the release or the algorithm, a twin under `legacy` matched by
its prefix as before, the multiset identity telling two TLCs apart by the full hash alone, and growth summed under one
intent across a legacy channel and a full-hash channel. The engine's spec drives it through real requests, whose digests the
SDK computes for the states the vectors do not cover: the crossing views, one budget drawn from two channels, a second
channel's other view refused against it, an invoice two channels paid in different views, a revocation fired between a
commitment's decision and its claim, a release refused while an offered TLC is listed beside a TLC of the invoice (in either
view) and allowed on a channel that no longer lists one, an offered TLC refused beside a released TLC listed only in the
other view, a charge found in the local view alone, a hash refused as both payment and invoice, an offered TLC refused on a
channel holding a released one, two channels racing for it, a released preimage dropped and paid, the intent and invoice
records' own rules, and on a channel driven with the full-hash cases of the vectors: the layout pinned at first sight by the
opening or by a revocation, a legacy commitment and a legacy revocation then refused by their layout (and the reverse on a
legacy channel), the revocation sized under the pinned layout signed, a twin offered TLC refused through a real request, the
whole hashes kept in the view, and a release held back by the invoice's own TLC beside an offered one but not by a twin. A
malformed request for an unregistered channel pins that the shape check answers first. Renaming has its own set: both names
of a channel reaching one record, a repeat under the other name answered `already-signed`, a rename refused once the record
has served, two names racing for the same slot, and two registrations racing for one name where the loser's index never
takes it.

Check 5 is pinned three ways. `test/tests/policy/channel-pins.spec.ts` reads what each operation of the vectors states,
field for field, under both layouts, a close stating no capacity, reserve or layout, and the host's terms in their pin
forms; it contrasts the reserve under the layout a statement declares, each conflict naming the computed value, throws on a
reserve stated without its layout, and pins a term only from the host's statement, never from a message's.
`test/tests/policy/channel-opening.spec.ts` checks both reserves against the ones fiber's own `occupied_capacity` sizes in
the vectors, over scripts on both sides of the 57-byte and 58-byte edges, and puts the funded amount at each edge of what
registration accepts, the `legacy` floor. `test/tests/policy/capacity-bounds.spec.ts` puts each bound at its exact edge and
one shannon past it, the fees sized over the mock transactions fiber's own fees are pinned against, the commitment fee bound
reached one byte sooner under the full-hash layout, and a close bounded by nothing there. The engine's spec refuses, per
operation, every pin that operation states, moved by one field (the out point, its hash, the liquid capacity, a reserve, a
reserve moved between the sides, the peer's keys, the delay, the rate, the asset, the close script, and a close whose two
outputs the node swapped, read as fiber orders them and matching its message), and checks the refusal writes nothing; it
signs a sent revocation whatever its payout, pins what a close, a revocation or an announcement states when it comes first,
refuses an opening that turns the whole funding into the device's reserve, refuses every UDT operation on a channel
registered as CKB, by its asset even once the capacities are pinned, refuses the opening under either layout with the other
layout's reserve, signs a close on a full-hash channel without reading its layout, puts the commitment fee bound at its edge
at the rate the host pinned and reaches it through the cell dep count alone, puts the close at its exact 1 CKB edge whatever
the peer is paid, and runs the host's pin of the funding cell both ways, each malformed argument refused by name and the pin
held behind a commitment that is being decided. The opening has its own set: TLCs in the first commitment and a shannon more
and less than funded, each in both views, a funded amount the node's opening does not match, an opening on the device's own
commitment with the peer's first one judged against it, the first commitment after an announcement or a revocation still
judged as the opening, and a commitment after a close; a close is refused below either view, the local one included. The
engine's other specs build every channel on the "ckb" cases, which share one funding output and fee rate, pin their terms as
the host does, and open it before its first TLC.

Coverage of the module is 100% on all four metrics. Coverage only proves there is no dead code, so the assertions were
checked by breaking the code on purpose:

| Mutation                                                           | Tests that failed |
| ------------------------------------------------------------------ | ----------------- |
| The session commitment drops the aggregated nonce                  | 4                 |
| The session commitment sorts the key list                          | 2                 |
| The keys are not checked to be on the curve                        | 3                 |
| The nonce is not checked to be on the curve                        | 4                 |
| A nonce half at infinity is refused                                | 3                 |
| A zero-prefixed nonce half is read as infinity                     | 1                 |
| A key at infinity is accepted                                      | 1                 |
| Monotonicity accepts an equal number                               | 1                 |
| A closed intent still lets a TLC grow                              | 3                 |
| The budget ignores other channels                                  | 7                 |
| Other channels count at the judged view                            | 2                 |
| Growth is read against this view alone                             | 2                 |
| The budget ignores what was charged                                | 4                 |
| Growth is read on the shown amounts alone                          | 3                 |
| A fulfilment counts as growth                                      | 9                 |
| A channel may show an offered TLC beside a released held one       | 8                 |
| The mix guard reads the judged view alone                          | 2                 |
| A channel that already shows the mix is refused too                | 3                 |
| A mixed channel may grow                                           | 2                 |
| Growth of a mixed channel reads offered TLCs alone                 | 1                 |
| Growth of a mixed channel reads released held TLCs alone           | 1                 |
| The mix guard counts unreleased held TLCs                          | 34                |
| The release ignores offered TLCs in flight                         | 2                 |
| The release ignores whether the channel still lists the invoice    | 1                 |
| A payment may take the hash of an own invoice                      | 1                 |
| An invoice may take the hash of an authorised payment              | 1                 |
| The release reads the remote view alone                            | 1                 |
| A charge is looked for in the remote view alone                    | 1                 |
| The context reads the judged view's TLCs alone                     | 1                 |
| A mix before is read without the other view                        | 1                 |
| The budget refuses its own maximum                                 | 54                |
| A non-positive shortfall does not search                           | 4                 |
| Nothing fallen and no set fitting is a refusal                     | 2                 |
| Received TLCs that left widen nothing                              | 5                 |
| An unreleased invoice's TLC widens the window                      | 1                 |
| Only received TLCs with no invoice widen the window                | 1                 |
| Every departed TLC is charged                                      | 6                 |
| No departed TLC is charged                                         | 14                |
| The exact search stops one TLC early                               | 2                 |
| An unreleased invoice is credited                                  | 3                 |
| The credit is not capped by what is owed                           | 2                 |
| The cap ignores other channels' credits                            | 1                 |
| Another channel's credit counts at its more paid view              | 2                 |
| Holdings count received TLCs too                                   | 18                |
| TLCs are compared without their expiry                             | 1                 |
| The snapshot keeps the whole hash                                  | 58                |
| Both commitments share one view                                    | 4                 |
| A close ignores listed TLCs                                        | 3                 |
| A close is judged against one view                                 | 2                 |
| The channel is not filed on the intents                            | 9                 |
| The channel is not filed on the invoices                           | 5                 |
| The channel is filed before the decision                           | 2                 |
| Revocations claim outside the balance lane                         | 2                 |
| Commitment claims skip the balance lane                            | 3                 |
| A charged intent opens again                                       | 3                 |
| A legacy TLC is never the record's                                 | 64                |
| The reserve under the full hash counts the args at 57 bytes        | 31                |
| The reserve is held to the legacy value whatever the layout        | 23                |
| A commitment states no layout                                      | 19                |
| A TLC with another whole hash is the record's                      | 10                |
| The registration floor is the full-hash reserve                    | 9                 |
| A revocation states no layout                                      | 8                 |
| The snapshot drops the whole hash under the full-hash layout       | 5                 |
| An offered twin is let through to the budget                       | 4                 |
| The claim's TLCs are read under legacy whatever the input          | 3                 |
| The record guard accepts any string as the layout                  | 3                 |
| The snapshot keeps the whole hash under legacy too                 | 3                 |
| A received twin is credited to the invoice                         | 2                 |
| The record guard accepts a whole hash with another prefix          | 2                 |
| The record guard accepts the reserve as a string                   | 2                 |
| A received twin is refused like an offered one                     | 1                 |
| The algorithm guard reads a twin as the invoice's                  | 1                 |
| The mix guard reads a received twin as a released one              | 1                 |
| The record guard accepts a reserve map with an extra key           | 1                 |
| The release's held filter ignores the whole hash                   | 1                 |
| TLCs are compared without their whole hash                         | 1                 |
| An open intent is replaced                                         | 1                 |
| A repeat of an open intent is refused                              | 1                 |
| An open intent repeated with another maximum is a no-op            | 1                 |
| A twin hash answers for the recorded one                           | 2                 |
| A record may sit under another hash's key                          | 2                 |
| An intent record is read without its version                       | 3                 |
| An invoice record is read without its version                      | 3                 |
| TLCs are compared without their algorithm                          | 1                 |
| The snapshot drops the algorithm                                   | 12                |
| A view TLC is read without its algorithm                           | 2                 |
| An invoice record is read without its algorithm                    | 1                 |
| An invoice may be recorded again with another algorithm            | 1                 |
| The release ignores the algorithm of a held TLC                    | 1                 |
| A released invoice takes a TLC under another algorithm             | 2                 |
| The algorithm guard ignores the release                            | 2                 |
| The already-signed path keeps running                              | 2                 |
| The digest comparison is dropped                                   | 5                 |
| The channel lookup runs before the shape check                     | 2                 |
| A record that has served may take a new name                       | 2                 |
| A rename starts a fresh record                                     | 1                 |
| A name may be re-registered at another index                       | 1                 |
| The name is written instead of claimed                             | 6                 |
| The alias is written before the record                             | 1                 |
| A no-op update still writes the record                             | 3                 |
| A first-sight value conflicts while unpinned                       | 144               |
| Nothing is pinned at first sight                                   | 36                |
| A received revocation states no close script                       | 2                 |
| A sent revocation states its payout as the close script            | 13                |
| The funding capacity leaves the reserves out                       | 19                |
| The funding capacity leaves the remote reserve out                 | 22                |
| A UDT cell's funding capacity counts its liquid amount             | 2                 |
| An announcement states no capacity                                 | 3                 |
| A commitment states no TLC base key                                | 11                |
| A revocation states no fee rate                                    | 4                 |
| A close states no out point                                        | 3                 |
| The out point pin drops its index                                  | 133               |
| The asset is not fixed at registration                             | 205               |
| The asset is stated after the capacities                           | 3                 |
| The commitment fee bound admits its own edge plus one              | 3                 |
| The commitment fee bound refuses its own edge                      | 5                 |
| A revocation's fee is not bounded                                  | 2                 |
| Conservation ignores the TLCs                                      | 4                 |
| Conservation ignores the peer's settlement                         | 5                 |
| Conservation demands equality                                      | 3                 |
| Conservation refuses its own edge                                  | 121               |
| The opening is never judged                                        | 5                 |
| The opening may list TLCs                                          | 4                 |
| The opening may pay any amount                                     | 5                 |
| The opening may pay more                                           | 2                 |
| The exposure leaves the reserve out                                | 116               |
| The device's reserve is left to the first sight                    | 211               |
| The reserve drops the commitment lock's 57-byte floor              | 142               |
| The reserve leaves the close fee out                               | 145               |
| The reserve leaves the capacity field out                          | 145               |
| The reserve leaves the hash type out                               | 145               |
| The record guard ignores the device's reserve                      | 3                 |
| The pins are not checked                                           | 30                |
| The bounds are not judged                                          | 5                 |
| The pins are not written with the claim                            | 33                |
| A re-registration may change the funded amount                     | 1                 |
| A re-registration may change the close script                      | 1                 |
| The host's pin overrides a conflict                                | 7                 |
| A repeated host pin writes again                                   | 2                 |
| The host's pin skips the balance lane                              | 1                 |
| The host's pin checks no tx hash                                   | 1                 |
| The host's pin checks no index                                     | 2                 |
| The host's pin checks no capacity                                  | 1                 |
| The record guard ignores the asset                                 | 3                 |
| The record guard ignores the pins' forms                           | 11                |
| The record guard reads no pins                                     | 27                |
| The registration checks no close script                            | 3                 |
| The registration checks no funded amount                           | 3                 |
| The funded amount may equal u64's maximum                          | 2                 |
| The funded amount may not equal the reserve                        | 9                 |
| The registration skips the opening check                           | 6                 |
| The preparation skips the opening check                            | 10                |
| The preparation files the caller's code hash                       | 1                 |
| The preparation files the caller's args                            | 1                 |
| The preparation copies a Buffer's bytes by view                    | 1                 |
| The opening is judged on the peer's commitment alone               | 3                 |
| Any first signed slot opens the channel                            | 2                 |
| A new pin overwrites one already held                              | 2                 |
| A pin is written as absent                                         | 1                 |
| The host's conflict throws a plain TypeError                       | 7                 |
| The host's error drops what it stated                              | 2                 |
| The script check ignores the args                                  | 3                 |
| The liquid capacity term reads the peer's reserve                  | 173               |
| The stated liquid capacity is one higher                           | 171               |
| The host's terms pin nothing                                       | 169               |
| The fee rate term is pinned one higher                             | 165               |
| The revocation counters are swapped                                | 64                |
| Every commitment is judged as the opening                          | 41                |
| The counter is not checked                                         | 15                |
| A close may take no fee                                            | 14                |
| The allow mode refuses a second session                            | 13                |
| The record guard reads no evidence                                 | 12                |
| A reused slot may not equal its lane's last                        | 10                |
| The record guard reads no commitment hashes                        | 10                |
| The record guard reads no reuse log                                | 10                |
| Both views share one version                                       | 9                 |
| A revocation is signed without its replacement                     | 9                 |
| The replacement is read from the other view                        | 56                |
| The replacement is held to the revoked version                     | 56                |
| The replacement may sit below the slot                             | 7                 |
| The replacement may sit above the slot                             | 2                 |
| A revocation out of order with its replacement is a policy refusal | 7                 |
| A second session skips the replacement                             | 1                 |
| The exemption reads the slot of the last instead of the one below  | 70                |
| The first of the view is never exempt                              | 70                |
| A fresh slot moves no lane                                         | 57                |
| The rule reads the device's own revocation lane                    | 15                |
| The evidence of the last version satisfies the rule                | 14                |
| The remote view goes back to the local view's rule                 | 11                |
| The revocation of the version before the last is never required    | 7                 |
| The lane is never read                                             | 5                 |
| A remote commitment at its view's last is signed                   | 2                 |
| A reused slot moves no lane                                        | 2                 |
| The evidence is never required                                     | 2                 |
| The local view takes the remote view's rule                        | 2                 |
| A remote commitment two versions above its view's last is signed   | 1                 |
| A revocation one below the last satisfies the lane                 | 1                 |
| Any evidence satisfies the rule                                    | 1                 |
| Any revocation at or above the last satisfies the lane             | 0                 |
| The evidence's slot is read at the version itself                  | 8                 |
| The slot bound is one lower                                        | 8                 |
| The verdict carries the lane                                       | 9                 |
| An unpinned term is not refused                                    | 6                 |
| The evidence is filed for the device's view                        | 6                 |
| The mode defaults to allow                                         | 6                 |
| The refuse mode serves a second session                            | 6                 |
| A close may take twice the fee bound                               | 5                 |
| A repeat files the channel again                                   | 5                 |
| A repeat of the first session is answered as reused                | 7                 |
| Both revocation lanes are one                                      | 5                 |
| The close refuses its own fee edge                                 | 5                 |
| The fee bound reads a liquid capacity one higher                   | 5                 |
| A close orders on a lane apart from the commitment's               | 4                 |
| A reused session is answered fresh                                 | 4                 |
| A reused session is not logged                                     | 4                 |
| The announcement slot may be any number                            | 4                 |
| The fee rate term may not be u64's maximum                         | 4                 |
| The record guard ignores the terms' forms                          | 4                 |
| The slot is not checked to be an object                            | 4                 |
| A close states no close script                                     | 3                 |
| A close states no funding key                                      | 3                 |
| A commitment's version may equal its view's last                   | 3                 |
| The commitment hash is not checked                                 | 3                 |
| The commitment hash kept is another                                | 3                 |
| The evidence may revoke the chain's last version                   | 3                 |
| The lane map may name any lane                                     | 3                 |
| The liquid capacity term is not checked                            | 3                 |
| A host amount may not be u64's maximum                             | 2                 |
| A repeat of the reused session is refused                          | 2                 |
| A third session is served                                          | 2                 |
| Evidence for an unserved revocation is kept                        | 2                 |
| The evidence may be of the device's view                           | 2                 |
| The evidence signature is not checked by the guard                 | 2                 |
| The evidence signature takes any length                            | 2                 |
| The peer's reserve term is not checked                             | 2                 |
| The reuse log's message is not checked                             | 2                 |
| A fresh slot may equal its lane's last                             | 1                 |
| A repeated evidence writes again                                   | 1                 |
| A reused session skips the balance rule                            | 1                 |
| A reused slot may sit below its lane's last                        | 1                 |
| An unknown mode is accepted                                        | 1                 |
| Another signature of a version is added beside the first           | 1                 |
| The commitment hashes may name any view                            | 1                 |
| The evidence is kept unsorted                                      | 1                 |
| The evidence is not checked to be an object                        | 1                 |
| The evidence list may repeat a version                             | 1                 |
| The options are not checked to be an object                        | 1                 |
| The reuse log may name a slot never served                         | 1                 |
| The reuse log may repeat the first session                         | 1                 |
| The terms are not checked to be an object                          | 1                 |
| A null nonce reuse mode is taken as the default                    | 1                 |

Four mutants fail no test, and cannot. Letting any revocation at or above the remote view's last satisfy its rule is
equivalent: `REVOKE:local` never passes that last, since the replacement rule holds a revocation at slot `n` to the view's
commitment at `n`. The host's pin of the funding cell given the terms' fields as well pins nothing
more, because the funding cell states none of them. Handing out the pins `readChannelPins` read without copying them, the
reserve map or the whole object, changes nothing a caller sees: the store parses the stored string afresh on every read, so the
copy is redundant behind it and only keeps the method's contract if the store ever caches.
