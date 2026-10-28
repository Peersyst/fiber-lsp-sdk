# Policy

The gate every musig2 signing request passes before the engine runs. It is the half of the design that makes deterministic
nonces safe and blind signing impossible: the engine signs whatever it is handed ([signing.md](./signing.md)), the digest
module rebuilds messages but judges nothing ([digest.md](./digest.md)), and this layer decides. The state it decides over is
the per-channel record ([persistence.md](./persistence.md)). Not every request passes the gate: a watchtower's spend of a
force-closed commitment is no musig2 session, and passes the watchtower's own rules instead (below).

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

Each contradiction registration finds in the records throws a `ChannelRegistrationError`, a `TypeError` carrying the
`channelId` and `channelIndex` the host registered: the name already resolving to another index, the index registered
with another funded amount or close script, a rename of a record that has served. A store that cannot be read throws a
plain `TypeError` instead ([persistence.md](./persistence.md)), so a caller tells a registration the records refuse from
a storage it cannot trust; the facade's opening turns only the first into `opening_conflict` ([sdk.md](./sdk.md)).

A name is claimed, not written: the alias is read and set inside one critical section, and a name already resolving
elsewhere throws the same error. The check the engine runs before creating the record is the same rule stated early, so an ordinary
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
with the signed transaction rebuilt, not with a chain lookup. Beside it the record keeps the commitment's cell and the
settlement body its lock args commit, which the watchtower's rules tell a spend's source by, and, for the peer's view,
the commitment before the last one (below).

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
scripts each side is paid to. They all enter the digest, so check 2 binds the signature to them, but nothing in the
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
| `remoteCloseScript`         | the host's terms                             | a close                                       |
| `fundingOutPoint`           | the host, or the first sight                 | a commitment, a close, an announcement        |
| `fundingCapacityShannons`   | the host, or the first sight                 | a commitment, a revocation                    |
| `remoteFundingPubkey`       | the host's terms                             | all four                                      |
| `remoteTlcBasePubkey`       | the host's terms                             | a commitment                                  |
| `commitmentDelayEpoch`      | the host's terms                             | a commitment, a revocation                    |
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

**The terms** are four values a request states but nothing in it vouches for, so a first sight of them would be a value the
node chose: the commitment fee rate, the peer's reserve, the liquid capacity and the peer's close script (fiber's
`remote_shutdown_script`, kept as its molecule bytes). `PolicyEngine.pinChannelTerms` takes them from the host, which reads
them from the node's `opening_context` once the open is accepted and checks them against what the device asked; the
facade's opening does both ([sdk.md](./sdk.md)). A message never pins a term: one that states a term the host has not
pinned is refused (`policy_refusal`), naming the first such term, so a commitment, a revocation or an announcement on a
channel whose terms are unpinned names one of the three numeric terms, and a close, which states the peer's close script
and none of the others, names that script. A term a message does not state is not asked of it: a channel pinned with every
term but the peer's close script signs everything but its close.

The same context states three first-sight values, and `pinChannelTerms` pins them beside the terms (`HOST_TERMS_PINS`):
the peer's funding key, its TLC base key (fiber's `remote_settlement_key`) and the commitment delay, the full
`EpochNumberWithFraction` value. Pinned by the host, they are the values the opening was checked with rather than the
first a request states, and a request that states others is refused like any pin conflict. No message pins them first:
every operation states a term, and a channel the host pins no terms for signs nothing. Each key must be a compressed
point on the curve and the delay a u64, or the call throws a `TypeError` or a `RangeError` naming the field.

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
  one pins the layout with it. The computation is exported as `reservedCkbShannons(closeScript, layout)`, fiber's
  `reserved_capacity` over either side's close script: the facade sizes the peer's reserve with it over the opening
  context's `remote_shutdown_script` before the host pins that term ([sdk.md](./sdk.md)). Pinned at first sight instead, a node could open with the whole funding as the device's
  reserve: the opening would still pay the funded amount, and none of it could be spent.
- **The lock layout is pinned at first sight**, declared by a commitment and by a revocation (both size their fee over
  the commitment lock's mock, so both carry it), never by a close or an announcement, which do not depend on it. A
  message under the other layout is refused as any pin conflict, and it is read right after the asset, so a legacy
  message on a full-hash channel is refused by its layout before its reserve.
- **A close pays both pinned scripts, and a revocation the device receives the device's own.** Both pay the device's
  close script (fiber's `local_shutdown_script`), so they state that pin. A close also pays the peer's, held to the term the
  host pinned: fiber lets the peer's `Shutdown` replace the script of the open, checking the new script's capacity and fee
  against the peer's balance but never that it is the open's (`channel.rs:1926-1936`), and the
  close's size, which each side's rate is multiplied by for its fee, counts both scripts, so the peer's script moves the
  device's fee. Pinned, a peer that changes it is refused, as fiber's own device SDK refuses it
  (`fiber-lsp-sdk/src/commitment.rs:849-953`), and the fee the facade checks before it asks for a close is the fee the
  close takes ([sdk.md](./sdk.md)). A close is read by output position, in fiber's funding-pubkey order, so a close whose
  two outputs the node swapped reads with the peer's output as the device's and still hashes to its message: the device's
  script is stated before the peer's, so the device's pin is the one that refuses it. A revocation the device sends sweeps
  to the peer's script, which the device has no reason to fix: a wrong one harms the peer only.
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
  the balance rule applies it (below). Fiber bounds it by the whole balance only. The facade runs the same bound before
  it asks for a close, over the fee the two pinned scripts size ([sdk.md](./sdk.md)). The peer's output is held to its
  pinned script (above), never to an amount.
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
- a **hold invoice**: its amount, its hash algorithm, the index its preimage derives from, and whether the device has
  released the preimage ([The hold invoice's release](#the-hold-invoices-release)).

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
the release ([below](#the-hold-invoices-release)) refuses with a `HoldInvoiceError` (`offered_in_flight`) while any channel that lists a TLC of
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

An intent is never deleted. The facade closes it when the payment is final, its payment step on fiber's `Success`,
`Failed` or "not found", and `transfer` itself when the node refuses the send ([sdk.md](./sdk.md)); a close only stops
growth: TLCs already shown stay signable until they resolve. An open intent is never recorded again, whatever its
maximum: a repeat would reach the node as a second payment under the hash, whose refusal would then close the first
payment's intent, so whether a first call landed is read back from the node (`get_payment`), not asked again. The
refusal runs in the balance lane, so of two concurrent records of one intent only one goes through. A closed intent
opens again with a fresh budget only if nothing was ever charged to it, which is fiber's own rule for sending a hash
again after a failure. Those two refusals are state the user can cause, by paying one invoice twice, so they throw a
`DebitIntentError` whose code says which (`intent_open`, `intent_charged`), and the facade can tell them from a malformed
argument, which stays a `TypeError`. They are the host's and never reach the wire, so they are not `PolicyRefusalError`s.
A third code, `own_invoice`, refuses an intent under the bound hash of one of this device's hold invoices: paying one's
own invoice would have the rule read one hash as money out and money owed in at once. A fourth, `hash_twin`, refuses a
hash whose 20 bound bytes are already another payment's, an intent's or a hold invoice's under another full hash: the
records are keyed by those bytes, so the two payments would share one record, and the invoice is the payee's doing, which
the user can cause by paying it. The twin is checked before the record's own rules, so a twin of a hold invoice is
`hash_twin` and not `own_invoice`. The reverse, an invoice under the hash of an authorised payment, is a host bug, since
every preimage is derived anew, and stays a `TypeError`. The facade records an intent before the operation that causes
the TLC, never after: `transfer` watches the hash, records the intent, and only then issues `send_payment`. An invoice is
recorded before the node hears of its hash, and marked released before the preimage leaves the device.

`readDebitIntent(paymentHashHex)` hands the record back by its whole hash, or `null` when none was recorded under it, a
twin's included: a twin's record is another payment's, never this one's. It serves the payment step, which closes an
intent only when one is there.

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

## The hold invoice's release

A hold invoice's record is all the device keeps of it ([persistence.md](./persistence.md)): the full payment hash, the
amount in decimal shannons, above zero since an invoice of nothing would be released before any channel held a shannon of
it, the hash algorithm the payment is locked with, and the invoice index `k` its preimage derives from
([derivation.md](./derivation.md)). The preimage itself is never stored. `recordHoldInvoice(paymentHashHex,
amountShannons, hashAlgorithm, invoiceIndex)` writes it in the balance lane before the node hears of the hash, each
argument refused by name first (the hash 32 bytes of lowercase hex, the amount, the algorithm one of the two, the index an
integer from 0 to `MAX_INVOICE_INDEX`). Recording it again with the same four writes nothing; another amount, algorithm or
index under the same hash and a hash that shares its bound 20 bytes with another invoice are `TypeError`s, as the hash of
an authorised payment is (above): the host's bug, since each invoice derives its preimage from an index of its own.

`markHoldInvoiceReleased(paymentHashHex, { now, releaseMarginMs })` marks the preimage released, from when on every
commitment must pay for it (step 3 of the balance rule), and it is the one gate between a held payment and the preimage
leaving the device: the facade marks before it settles ([sdk.md](./sdk.md), "The invoice step"). The hash is checked and
the two timing fields are checked to be functions, each read once, so the function checked is the function called. Then,
inside the balance lane:

1. The record is read by the whole hash; none, or a twin's under the bound bytes, is a `TypeError`. A record already
   released is answered at once, nothing judged and the clock not read: released once, released for good, since the
   commitments signed since rely on it.
2. The record of every channel the invoice lists is read; a listed channel with no record throws.
3. The clock is read once, after the records and before the judgment, so no wait for the lane or the storage ages the
   reading; one that is not a whole number of milliseconds up to `Number.MAX_SAFE_INTEGER` is a `RangeError`.
4. The judgment, `judgeHoldInvoiceRelease`, reads the TLCs of the invoice each view of each channel lists in its last
   commitment, under the bound hash and, under the full-hash layout, the whole hash, so a twin is nobody's. Channel by
   channel, in the record's order: `algorithm_mismatch` for a TLC of the invoice under another algorithm, then
   `offered_in_flight` for a channel that lists a TLC of the invoice beside an offered TLC in either view (why each, in
   [The balance rule](#the-balance-rule)). Then over all the channels together:
   - `not_held`: the channels hold less than the invoice's amount, each channel counted at its view holding less and the
     channels summed. At least the amount, not exactly it: fiber accepts a TLC of at least the amount, so an overpay is
     held, and what it pays past the amount counts as exposure under the balance rule.
   - `expiry_too_close`: a TLC of the invoice, in either view of any channel, expires at or before
     `now + releaseMarginMs(delay)`, its expiry being its whole seconds times 1000 and the delay the channel's pinned
     `commitmentDelayEpoch`. A channel that lists a TLC of the invoice but pins no delay is a broken record, since a
     signed commitment pins it, and throws a `TypeError`; one that lists none asks no margin. The margin must be a bigint
     within a u64.
5. Only then is the record marked released.

The four codes are `HoldInvoiceError`s, refusals the caller waits out or reports, in that order: the algorithm, the offered
TLC, the amount, the expiry. Each channel counts at its weaker view for the reason the balance rule counts every other
channel at its worst: the node aggregates both partial signatures of every channel, so it may broadcast either
commitment of each, and the sum of the weaker views is what it holds whichever it broadcasts. The expiry is held to a
margin because the preimage, once out, is worth something only if the fulfil it starts is signed before fiber fails the
TLC on its own (`channel.rs:3474-3507`); the margin is the facade's to compute, from fiber's arithmetic and the poller's
pace ([sdk.md](./sdk.md)), and comes in as a function, since `policy` does not import `signer`. The release judges the
latest commitment of each view, as the balance rule does, and rests on the same premise
([What this layer deliberately does not do](#what-this-layer-deliberately-does-not-do)).

Two reads serve the facade's invoice step. `readHoldInvoice(paymentHashHex)` hands the record back by its whole hash, a
`TypeError` when none was recorded under it, a twin's included. `listsHoldInvoiceTlc(paymentHashHex)` tells whether the last commitment of either view
of any channel the invoice lists still shows a TLC of it; it reads outside the balance lane, since its answer is a
snapshot either way, and a channel shows a TLC of the invoice only once it is filed on the record.

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

## The watchtower's spends

A watchtower request names no slot and takes no nonce: its signature is recoverable ECDSA under RFC 6979, which leaks
nothing however many messages one key signs ([signing.md](./signing.md)). So it passes none of the six checks.
`PolicyEngine.checkWatchtowerSpend(keys, channelId, request)` runs the watchtower's rules instead, a port of fiber's device
SDK's `validate` (`fiber-lsp-sdk/src/onchain.rs:61-372`) less what only a chain can tell: which cells are live, the
capacity of the node's cells that pay the fee, and the median time. The rules read the channel's record alone, so they run
in its own lane, outside the balance lane, and a refusal writes nothing.

### The approval

`new PolicyEngine(store, { watchtower })` takes what the host approves the spends for: `destination`, the `Script` every
spend pays, and `maxFeeShannons`, decimal shannons within a u64, how far below what an unlock releases the destination may
be paid. The spend cannot show its fee, since the node's cells that pay it are not the device's to read, so the fee is
bounded from the device's side. Each field is checked at construction, a `TypeError` naming it
(`options.watchtower.destination`), and the approval is copied. Without one, every request is `policy_refusal`, ahead of
the channel's lookup, and the funds stay where they would be with no watchtower ([signing.md](./signing.md), on the trust
the destination takes).

### The rules, in order

| #   | Rule                                                                                                                                          | Refused as                     |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| 1   | An approval                                                                                                                                   | `policy_refusal`               |
| 2   | A non-empty channel name, resolving to a record                                                                                               | `malformed`, `unknown_channel` |
| 3   | Structure: a 32-byte request id and a known purpose, every field the tx hash covers, version 0, no header deps, an input, one data per output | `malformed`                    |
| 4   | Input 0 spends output 0, where every commitment lock cell sits                                                                                | `policy_refusal`               |
| 5   | Witness 0 reads as one settlement unlock under the layout of the commitment it is read against ([digest.md](./digest.md))                     | `malformed`                    |
| 6   | The source: the body is a registered commitment's, or descends from one (below)                                                               | `policy_refusal`               |
| 7   | The key: the unlock is the one the purpose's key signs, settling to that key, and it releases something                                       | `policy_refusal`               |
| 8   | The unlock's signature is the 65 zero bytes of an unsigned spend                                                                              | `malformed`                    |
| 9   | Output 0 is the remainder fiber's watchtower leaves, unless no party is left                                                                  | `policy_refusal`               |
| 10  | The destination: every other output pays it, at least what the unlock releases less the approved fee                                          | `policy_refusal`               |
| 11  | A request already claimed is the same spend                                                                                                   | `policy_refusal`               |

Through the signer dispatch the channel is resolved first, since the keys the rules take derive from it, so an unknown
channel answers `unknown_channel` even without an approval ([signing.md](./signing.md)). A rule's message starts with its
name (`watchtower source:`, `watchtower key:`, `watchtower destination:`) and names the output, the TLC or the amounts at
fault, never a key; a `malformed` one a reader raises carries the reader's own words.

### Where a spend starts

The record keeps the cell and the settlement body of the three commitments fiber's watchtower settles
(`fiber/onchain_tlc_reconcile.rs:128-160`): the last local one, the last remote one, and the remote one before it, which
the peer may still broadcast until it revokes it (`previousRemoteCommitment`, [persistence.md](./persistence.md)). Keeping
that one past its revocation is harmless: a revoked commitment that lands is punished, and fiber's watchtower takes that
path, not this one. A commitment signed before the record kept cells registers nothing.

Input 0's tx hash is not read. The peer broadcasts its commitment with cell deps of its choosing, which no signature covers
(`channel.rs:11567-11581`), so a hash rebuilt over deps the device picked would refuse an honest peer configured otherwise.
The source is told by its content instead, and by its `since`:

- **A since past zero** spends a commitment's own cell, which the lock holds to the delay: the settlement body in witness
  0 must be exactly a registered commitment's. Its capacity is the recorded cell's.
- **A zero since** spends a remainder, which fiber's watchtower spends at once: the body must descend from a registered
  commitment's, each TLC it lists one that commitment lists, and each balance that commitment's or settled (its key hash
  and its amount zeroed). The source may be a cell the device never signed: when the peer spends first, its TLC or its
  balance, the remainder is no spend of the device's, and requiring one would leave the device's funds in it. The lock
  holds the cell to the body it commits, so a source the body does not describe yields a spend the chain refuses, with
  the one exception of the caveat below. A descendant's capacity is whatever the chain holds, which the device does not
  know.

More than one registered commitment can fit: fiber may sign a commitment again with nothing changed but its number (a
nonce rotation, `channel.rs:2473-2478`), and a descendant of one version can descend from the next too. The source is then
the one whose first 36 lock args, which carry the commitment number and which a remainder keeps, equal output 0's. A spend
that leaves no remainder, the final sweep, names none, and is attributed to the first that fits, in the order last remote,
previous remote, last local.

### The key, and what an unlock releases

- **`Tlc { n }`** signs a TLC's unlock, whose entry carries, on the device's side, the `blake160` of the TLC key at `n`.
  The unlock carries the preimage exactly when the device received the TLC; one it offered is claimed by its timeout. It
  releases the TLC's amount.
- **`Settlement`** signs the device's balance, `0xfe` in a local view and `0xff` in a remote one, where the device's
  balance sits second, and the balance must settle to the `blake160` of the TLC base key. The body may still hold TLCs the
  device received, but none it offered, which fiber's watchtower claims first. It releases the balance.
- **The final party.** Once the peer's balance is settled, the device's unlock takes the whole cell: it releases the
  balance and every TLC still in the body, and leaves no remainder.

An unlock that releases nothing is refused, and the device never signs with a key the unlock does not need. What the
clock decides, a delay matured or a TLC expired, is the lock's, which the device cannot read and need not
([signing.md](./signing.md)).

### The remainder and the destination

Output 0 is the remainder exactly as fiber's watchtower writes it: the source's lock, its args committing the next body (the
unlocked TLC dropped, or the device's balance zeroed) and flagged as settled ([digest.md](./digest.md)), with no type and no
data, and, when the source is a commitment's own cell, its capacity less what the unlock releases. Every other output pays
the approved destination with no type and no data, one or two of them as fiber's device SDK bounds it
(`MAX_WATCHTOWER_DESTINATION_OUTPUTS`), and together they are paid at least what the unlock releases less
`maxFeeShannons`.

### The claim

Past every rule, the spend is claimed in the record's `watchtowerSpends` ([persistence.md](./persistence.md)): its request
id, its purpose, the view and the version of the commitment it descends from, the entry of the TLC it unlocks (`null` for
the balance), its CKB tx hash, its remainder's cell, and its signature once the signer records it. A spend is keyed by its
unlock: the view, the version and the entry.

- **A repeat** of a request id is answered `already-signed` with the signature recorded for it, once every rule has passed
  again against the record and the approval as they stand; one whose tx differs is refused. It writes nothing.
- **Only an unsigned claim is replaced.** Fiber rebuilds a spend under a new request id when what it holds changes, the
  node's cells that pay the fee among it, and keeps the old request pending (`watchtower/actor.rs:2151-2155`). A request for
  an unlock whose claim was never signed replaces that claim. One for an unlock whose spend is signed leaves it in place,
  and is answered `unclaimed`: signed and handed over, with nothing written. The record names the first spend signed for
  each unlock, and a lost answer or a lost write cannot let a later request take its place.
- **`applied`** is set by `markWatchtowerSpendApplied` once fiber answered the submission `Applied` or `AlreadyApplied`. It
  means accepted by fiber, not landed: fiber also accepts the signature of an old request whose spend can no longer land.
  It is evidence, which no rule reads.
- **Two identical TLC entries**, the parts of one payment, share a key, so the second's spend goes unclaimed: it is signed
  as any spend is, and the evidence of the first alone is kept.
- **The bound is by construction.** A claim drops the spends of commitments no longer registered, which fiber no longer
  settles. One spend per TLC and one for the balance, in each of three commitments of at most 255 TLCs, is at most
  `3 × (255 + 1) = 768` (`MAX_WATCHTOWER_SPENDS`), which the record guard holds; no cap refuses a spend.

### Where it parts from fiber's `validate`

- **The TLC subset is a multiset.** A body may list an entry as often as its commitment does and no more, so equal entries,
  the parts of one payment among them, stay claimable one by one. Fiber's `validate` checks each entry's membership alone,
  which lets a body list one more often than the commitment did.
- **The source is told by content**, not by a hash rebuilt over cell deps, for the reason above.
- **No chain**: live cells, the fee's sponsors and the median time are the lock's to enforce or the approval's to bound.

UDT channels, the punishment of a revoked commitment and what the lock enforces on chain (the delay's maturity, a TLC's
expiry, a preimage's hash) are out of scope ([signing.md](./signing.md)).

### The caveat

The source rule rests on the lock, which refuses a body its cell does not commit. That holds a spend to the cell, not to
its fee: for a descendant the device knows no capacity, so what the cell holds beyond what the unlock releases and the
remainder keeps is bounded by nothing on the device's side, and a spend over a body that understates the cell can burn
the difference to the fee. It can never redirect it: every output but the remainder pays the approved destination.

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
  commitment delay and the peer's keys are held to their first value, not to a right one. The funded amount, the
  device's close script, the device's reserve, the asset and, through the host, the funding cell, the terms and the three
  first-sight
  values the opening context states are the exceptions, being the device's own or checked by the host against the open it
  asked for.
- **It does not check the funding output's lock.** The funding cell's out point and capacity are pinned, and whether its
  lock is the 2-of-2 the device holds half of is the facade's check at the opening, over the peer's funding key the
  opening context states ([sdk.md](./sdk.md)): a signing request never states the lock, so there is nothing for the gate
  to hold to it.
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
- **It never prunes the registry.** A slot per signed commitment, a log entry per reused slot and an evidence entry per
  revoked peer commitment stay forever. Pruning the registry is only safe behind the lanes, which refuse a number already
  served even when its slot is gone, and it would cost the idempotent replay of an old request. The watchtower's spends
  are the one part that is pruned, by the device's own record rather than by anything the node states: a claim drops
  those of commitments no longer registered, which no signature's safety rests on (above).

## Where it lives

| File                                     | Contents                                                                                                                                                                                                                           |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/policy/policy-engine.ts`            | The six checks, sign-once and reuse, the claim, channel registration, the host's pins, the evidence, intents and hold invoices; the watchtower's approval, its claim, the signature recorded and the mark of a spend fiber applied |
| `src/policy/watchtower-spend.ts`         | The watchtower's rules, pure: the structure, the source, the key, the remainder, the destination, the repeat and the claim                                                                                                         |
| `src/policy/channel-opening.ts`          | What a channel opens with: the funded amount and close script checked, the registration's pins, and the reserve over either side's close script                                                                                    |
| `src/policy/channel-pins.ts`             | Check 5's pins, pure: what each operation and the host's terms state, in the pins' forms, and the first conflict                                                                                                                   |
| `src/policy/hold-invoice-release.ts`     | The hold invoice's release, pure: the invoice's TLCs a view lists, the algorithm, the offered TLC, the amount held and the expiry against the margin                                                                               |
| `src/policy/capacity-bounds.ts`          | Check 5's bounds, pure: the commitment fee and what a commitment pays out                                                                                                                                                          |
| `src/policy/balance-rule.ts`             | Check 6 itself, pure: the opening, the three steps over two snapshots, and the close with its fee bound                                                                                                                            |
| `src/policy/policy.constants.ts`         | The keyspace prefixes and the balance lane, the pins by who fixes them, the reuse modes and the lanes, the record versions, the watchtower's two bounds                                                                            |
| `src/policy/policy.error.ts`             | `PolicyRefusalError`, carrying the wire error code, and `withPolicyRefusal`; the host's `DebitIntentError`, `HoldInvoiceError`, `ChannelPinError` and `ChannelRegistrationError`                                                   |
| `src/policy/utils/payment-hash.utils.ts` | The bound payment hash a payment record is keyed by, and whether a TLC under that key is the record's                                                                                                                              |
| `src/policy/utils/slot.utils.ts`         | Operation and counter to slot and lane, where the shared close slot and the fixed announcement live                                                                                                                                |
| `src/policy/utils/session.utils.ts`      | The session commitment and the shape a signable session must have                                                                                                                                                                  |
| `src/policy/signer-store.ts`             | The persistence underneath ([persistence.md](./persistence.md))                                                                                                                                                                    |

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
refused. The terms: pinned with the three first-sight values, at u64's maximum, repeated with no write under either name,
each one conflicting with a `ChannelPinError` naming both values, a first-sight value a message pinned first restated with
no write and contradicted with that error, each malformed argument refused by name, an unregistered channel and an alias
with no record thrown, every operation refused on a channel whose terms are unpinned, naming the first missing, a close
naming the peer's close script; a close refused on a channel whose host pinned every term but that one, where every other
operation signs, and signed once the host pins it; and the peer's close script as a term: pinned and repeated with no
write, another script, one a byte shorter and one under another hash type each a `ChannelPinError`, and refused absent, in
its molecule hex, and with each field missing, in hex, of the wrong length or under an unknown hash type. The evidence:
kept, repeated with no write under either name, replaced by another signature
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
records' own rules (an open intent refused when recorded again, with the same maximum or another, writing nothing, and
one of two concurrent records let through; a closed one nothing was shown or charged under opened again, a charged one
never; a twin of an intent and of a hold invoice refused as `hash_twin`; `readDebitIntent` reading the record by its
full hash, a copy, and `null` for a hash never recorded and for a twin), and on a channel driven with the full-hash cases of the vectors: the layout pinned at first sight by the
opening or by a revocation, a legacy commitment and a legacy revocation then refused by their layout (and the reverse on a
legacy channel), the revocation sized under the pinned layout signed, a twin offered TLC refused through a real request, the
whole hashes kept in the view, and a release held back by the invoice's own TLC beside an offered one but not by a twin. A
malformed request for an unregistered channel pins that the shape check answers first. Renaming has its own set: both names
of a channel reaching one record, a repeat under the other name answered `already-signed`, a rename refused once the record
has served, two names racing for the same slot, and two registrations racing for one name where the loser's index never
takes it. Each contradicted registration, the lost race included, throws a `ChannelRegistrationError` carrying the
registered name and index, and a record or a name the store holds corrupt a plain `TypeError`, writing nothing.

Check 5 is pinned three ways. `test/tests/policy/channel-pins.spec.ts` reads what each operation of the vectors states,
field for field, under both layouts, a close stating both close scripts, the device's first, and no capacity, reserve or
layout, a close with its outputs swapped naming the device's, and the host's terms in their pin forms, the peer's close
script, empty args included, in the molecule hex a close states it in; a conflict on the peer's close script, and none while
it is unpinned; it contrasts the reserve under the layout a statement declares, each conflict naming the computed value,
throws on a
reserve stated without its layout, and pins a term only from the host's statement, never from a message's.
`test/tests/policy/channel-opening.spec.ts` checks both reserves against the ones fiber's own `occupied_capacity` sizes in
the vectors, over scripts on both sides of the 57-byte and 58-byte edges, refuses a malformed close script or layout by
name, and puts the funded amount at each edge of what registration accepts, the `legacy` floor. `test/tests/policy/capacity-bounds.spec.ts` puts each bound at its exact edge and
one shannon past it, the fees sized over the mock transactions fiber's own fees are pinned against, the commitment fee bound
reached one byte sooner under the full-hash layout, and a close bounded by nothing there. The engine's spec refuses, per
operation, every pin that operation states, moved by one field (the out point, its hash, the liquid capacity, a reserve, a
reserve moved between the sides, the peer's keys, the delay, the rate, the asset, the device's close script, the peer's
paid to another script and to the device's, and a close whose two outputs the node swapped, read as fiber orders them and
matching its message), the funding output named first on a close that also pays the peer elsewhere, and checks the refusal
writes nothing; it
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
| The release ignores offered TLCs in flight                         | 7                 |
| The release ignores whether the channel still lists the invoice    | 4                 |
| A payment may take the hash of an own invoice                      | 1                 |
| An invoice may take the hash of an authorised payment              | 1                 |
| The release reads the remote view alone                            | 2                 |
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
| The release's held filter ignores the whole hash                   | 3                 |
| TLCs are compared without their whole hash                         | 1                 |
| A twin hash answers for the recorded one                           | 2                 |
| A record may sit under another hash's key                          | 2                 |
| An intent record is read without its version                       | 3                 |
| An invoice record is read without its version                      | 3                 |
| TLCs are compared without their algorithm                          | 1                 |
| The snapshot drops the algorithm                                   | 12                |
| A view TLC is read without its algorithm                           | 2                 |
| An invoice record is read without its algorithm                    | 1                 |
| An invoice may be recorded again with another algorithm            | 1                 |
| The release ignores the algorithm of a held TLC                    | 3                 |
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
| An unpinned term is not refused                                    | 8                 |
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
| A close states no device close script                              | 4                 |
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
| An open intent with the same maximum is a no-op again              | 1                 |
| An open intent is reopened                                         | 3                 |
| `readDebitIntent` skips the hash check                             | 3                 |
| `readDebitIntent` returns a twin                                   | 1                 |
| `readDebitIntent` returns nothing                                  | 3                 |

Four mutants fail no test, and cannot. Letting any revocation at or above the remote view's last satisfy its rule is
equivalent: `REVOKE:local` never passes that last, since the replacement rule holds a revocation at slot `n` to the view's
commitment at `n`. The host's pin of the funding cell given the terms' fields as well pins nothing
more, because the funding cell states none of them. Handing out the pins `readChannelPins` read without copying them, the
reserve map or the whole object, changes nothing a caller sees: the store parses the stored string afresh on every read, so the
copy is redundant behind it and only keeps the method's contract if the store ever caches.

`test/tests/policy/watchtower-spend.spec.ts` claims every spend of the vectors' `watchtower` section, the device's own
commitment and the peer's, through the engine and in the watchtower's order, the peer's spends first included, and
refuses each of the vectors' variants with the verdict fiber's `validate` gives it. Around that, a refusal per rule and
per field: each fault of the structure; input 0 on another output; a witness absent or one the unlock reader refuses; a
body no registered commitment has at a since, and at a zero since a TLC the commitment never listed, one listed fewer
times than the body does, a balance moved, each fault named against each commitment, and a channel that signed none;
each key on the other kind of unlock, a TLC key of another number, the preimage on the wrong side, the settlement key on
the peer's balance, on a balance of zero and beside a TLC the device offered; a signed unlock; the remainder with another
lock, flag, body, capacity, a type or data, or missing, and one the final party's unlock leaves no room for; and the
destination by output count, lock, type, data and payment, at the exact edge and a shannon below, summed over two outputs,
with a fee above the release letting anything through. The sources: a commitment's cell under any tx hash and any since
past zero, its body at a zero since read as a descendant with no capacity, a descendant at whatever capacity, the remote
commitment before the last signed and recorded under its own version, two commitments of one body told apart by output
0's args, and a final sweep recorded under the first that fits. The claim: the purpose recorded alone and the entry of the
TLC unlocked, the record given left untouched, a repeat served with its signature after every rule ran again and refused
for another spend, an unsigned claim of the same unlock replaced, a signed one keeping its place while the new request
goes unclaimed, the other unlocks and the other view's kept in order, and the spends of a commitment no longer registered
dropped. The engine's spec reads the approval (none, a fee of zero and at u64's maximum, a copy the host's later writes do
not reach), keeps each commitment's cell and body and moves the previous remote one on, refuses before the channel without
an approval, an empty name and an unregistered one with nothing written, and records the signature and the mark once each,
throwing on a request never claimed or replaced, another signature, a mark with no signature and a channel with no record.
The record guard's spec accepts and refuses each new field one at a time ([persistence.md](./persistence.md)).

The watchtower rules, the engine's `checkWatchtowerSpend`, `recordWatchtowerSignature` and `markWatchtowerSpendApplied`, and
the record guard's new fields were broken the same way (`test/tests/policy`, still 100% on all four metrics):

| Mutation                                                                                      | Tests that failed |
| --------------------------------------------------------------------------------------------- | ----------------- |
| The recorded settlement body drops its last byte                                              | 157               |
| The commitment is recorded without its settlement body                                        | 150               |
| The view is read as local always                                                              | 73                |
| Any purpose kind reads as a TLC's                                                             | 54                |
| The previous is recorded at the new commitment's version                                      | 53                |
| A spend with a since is read as a descendant's, and one without as a commitment's             | 51                |
| A received TLC is read as offered                                                             | 45                |
| A TLC's spend reads as the last party's, leaving no remainder                                 | 43                |
| The spends are not checked                                                                    | 38                |
| The device's balance is placed by the other view                                              | 31                |
| The claim is recorded applied                                                                 | 19                |
| The remainder commits the next body of the other view                                         | 19                |
| A remainder is read as a commitment cell                                                      | 18                |
| An entry may appear one time fewer than the commitment lists it                               | 17                |
| The approved fee is ignored                                                                   | 16                |
| The payment bound is exclusive                                                                | 16                |
| The structure is refused as a policy refusal                                                  | 14                |
| A descendant's remainder is held to the commitment cell's capacity                            | 13                |
| A signed commitment is recorded without its cell                                              | 12                |
| A spend must carry a signature                                                                | 11                |
| The previous remote commitment is not checked                                                 | 11                |
| A descendant may not settle a balance                                                         | 10                |
| The remainder is recorded with data                                                           | 10                |
| Every spend is read as a descendant's                                                         | 9                 |
| A paid output may go elsewhere                                                                | 8                 |
| The last party is read from the device's own balance                                          | 8                 |
| The last party still owes a remainder                                                         | 8                 |
| The new spend replaces every spend recorded                                                   | 8                 |
| The spend records no version                                                                  | 8                 |
| A TLC entry of no layout's length is accepted                                                 | 7                 |
| A descendant's spend records no version                                                       | 7                 |
| Scripts match whatever their args                                                             | 7                 |
| A kept balance may change its amount                                                          | 6                 |
| The last party is owed its TLCs alone                                                         | 6                 |
| A signed spend of any unlock leaves a request unclaimed                                       | 5                 |
| The remainder's lock is not checked                                                           | 5                 |
| The spend key ignores the TLC entry                                                           | 5                 |
| A TLC entry is not checked to be hex                                                          | 4                 |
| A TLC's spend records the balance's key                                                       | 4                 |
| A claim never signed holds its unlock                                                         | 4                 |
| A new spend keeps the one of its unlock                                                       | 4                 |
| A recorded cell's flag is not checked                                                         | 4                 |
| A repeat is decided again as a fresh spend                                                    | 4                 |
| A request never claimed is updated as nothing                                                 | 4                 |
| A spend must carry a remainder                                                                | 4                 |
| Spends of two TLCs share a key                                                                | 4                 |
| The applied flag is not checked to be a boolean                                               | 4                 |
| The destination is not checked                                                                | 4                 |
| The previous's cell is not checked                                                            | 4                 |
| The purpose is not checked                                                                    | 4                 |
| The remote commitment before the last is not registered                                       | 4                 |
| Two destination outputs are refused                                                           | 4                 |
| A TLC key is not checked against the entry                                                    | 3                 |
| A TLC purpose may name a number past the chain                                                | 3                 |
| A commitment cell's remainder is held to no capacity                                          | 3                 |
| A commitment cell's spend records no version                                                  | 3                 |
| A descendant's refusal names the first view's fault alone                                     | 3                 |
| A recorded cell may carry data                                                                | 3                 |
| A recorded spend's purpose is not checked                                                     | 3                 |
| A repeat is answered before the rules run                                                     | 3                 |
| A request left unclaimed reads as fresh                                                       | 3                 |
| A signed spend is replaced by a later request for its unlock                                  | 3                 |
| A spend with a since takes the first commitment whatever its body                             | 3                 |
| A spend's version is not checked                                                              | 3                 |
| The mark leaves the spend unapplied                                                           | 3                 |
| The previous is taken from the new commitment                                                 | 3                 |
| The remainder's capacity is not checked                                                       | 3                 |
| The request id is not checked                                                                 | 3                 |
| The spend key ignores the view                                                                | 3                 |
| A TLC entry of either layout passes a pinned record                                           | 2                 |
| A TLC purpose may lack its number                                                             | 2                 |
| A TLC the device received holds a settlement back                                             | 2                 |
| A TLC's unlock is not held to its preimage flag                                               | 2                 |
| A body is not checked against the args                                                        | 2                 |
| A descendant may list a TLC the commitment never did                                          | 2                 |
| A repeat never carries its recorded signature                                                 | 2                 |
| A spend leaving no remainder is recorded under the last candidate                             | 2                 |
| A zero balance is settled                                                                     | 2                 |
| An entry's copies are counted before it                                                       | 2                 |
| An updated spend replaces every spend                                                         | 2                 |
| Equal entries may appear more often than the commitment lists them                            | 2                 |
| Input 0 may spend any output                                                                  | 2                 |
| No remainder names a source                                                                   | 2                 |
| Only a spend fiber confirmed holds its unlock                                                 | 2                 |
| Outputs and their data may differ in count                                                    | 2                 |
| Scripts match whatever their code hash                                                        | 2                 |
| Scripts match whatever their hash type                                                        | 2                 |
| The approval is not checked to be an object                                                   | 2                 |
| The body is a set, as in fiber's validate                                                     | 2                 |
| The fee is not bounded                                                                        | 2                 |
| The fee is not checked to be a string                                                         | 2                 |
| The last party is owed its balance alone                                                      | 2                 |
| The last party may not sweep a TLC the device offered                                         | 2                 |
| The previous remote commitment is matched before the last                                     | 2                 |
| The previous remote commitment is never recorded                                              | 2                 |
| The settlement key may sign the peer's balance                                                | 2                 |
| The spend key ignores the version                                                             | 2                 |
| The tx hash is not checked                                                                    | 2                 |
| 769 spends are accepted                                                                       | 1                 |
| A TLC entry may go under the settlement key                                                   | 1                 |
| A TLC key may go without its entry                                                            | 1                 |
| A TLC key may sign a balance's unlock                                                         | 1                 |
| A TLC the device offered may carry a preimage                                                 | 1                 |
| A TLC the device received may go without its preimage                                         | 1                 |
| A balance with a zeroed amount alone reads as settled                                         | 1                 |
| A balance with a zeroed key alone reads as settled                                            | 1                 |
| A body its layout does not read is accepted                                                   | 1                 |
| A body without its cell is accepted                                                           | 1                 |
| A cell without its body is accepted                                                           | 1                 |
| A commitment cell's spend takes the first commitment of its body whatever its remainder names | 1                 |
| A descendant takes the first candidate whatever its remainder names                           | 1                 |
| A descendant's balance 1 is not compared                                                      | 1                 |
| A kept balance may change its key                                                             | 1                 |
| A last remote commitment without its cell keeps the old previous                              | 1                 |
| A local commitment drops the previous                                                         | 1                 |
| A missing witness list is accepted                                                            | 1                 |
| A null approval reads as none                                                                 | 1                 |
| A paid output may carry a type                                                                | 1                 |
| A paid output's data is read at its offset                                                    | 1                 |
| A purpose of any kind is accepted                                                             | 1                 |
| A recorded cell may carry a type                                                              | 1                 |
| A recorded signature is overwritten                                                           | 1                 |
| A repeat may carry another tx                                                                 | 1                 |
| A request id of any length is looked up                                                       | 1                 |
| A settlement may leave a TLC the device offered                                               | 1                 |
| A signature of any length is accepted                                                         | 1                 |
| A signature of any length is recorded                                                         | 1                 |
| A signed unlock is accepted                                                                   | 1                 |
| A spend is decided with no approval                                                           | 1                 |
| A spend may name a view with no commitment                                                    | 1                 |
| A spend may name any view                                                                     | 1                 |
| A spend paying no destination output is accepted                                              | 1                 |
| A spend with no signature is marked applied                                                   | 1                 |
| A spend without an input is accepted                                                          | 1                 |
| A spend's registration ignores the version                                                    | 1                 |
| A spend's registration ignores the view                                                       | 1                 |
| A zero release is read from the balance                                                       | 1                 |
| An applied spend may lack its signature                                                       | 1                 |
| An empty channel id is not refused as malformed                                               | 1                 |
| An unchanged spend is written again                                                           | 1                 |
| Any version is accepted                                                                       | 1                 |
| Every party is owed the last party's release                                                  | 1                 |
| Header deps are accepted                                                                      | 1                 |
| Other operations drop the previous                                                            | 1                 |
| Spends of one unlock in two commitments share a key                                           | 1                 |
| Spends of one unlock in two views share a key                                                 | 1                 |
| The destination is paid the last output alone                                                 | 1                 |
| The destination's args are kept by reference                                                  | 1                 |
| The destination's code hash is kept by reference                                              | 1                 |
| The mark writes again over an applied spend                                                   | 1                 |
| The mark's request id is not checked                                                          | 1                 |
| The previous commitment's fault is named as the last one's                                    | 1                 |
| The previous may sit at any version below the last                                            | 1                 |
| The previous needs no remote commitment after it                                              | 1                 |
| The previous's version is not checked                                                         | 1                 |
| The recorded purpose keeps whatever the request carried                                       | 1                 |
| The remainder may carry a type                                                                | 1                 |
| The remainder may carry data                                                                  | 1                 |
| The same signature recorded again is a conflict                                               | 1                 |
| The settlement key is not checked against the balance                                         | 1                 |
| The settlement key may sign a TLC's unlock                                                    | 1                 |
| The spend is recorded under the remote view always                                            | 1                 |
| The spend records the first TLC's entry                                                       | 1                 |
| The spends of a commitment no longer registered are kept                                      | 1                 |
| The verdict is fresh whatever the rules decided                                               | 1                 |
| Two spends may share a commitment's unlock                                                    | 1                 |
| Two spends may share a request                                                                | 1                 |

The record's two accessors, `readRegisteredRecord` and `updateRegisteredRecord`, which every read and update of a
registered channel goes through and which fail on a record a broken storage lost, were broken the same way
(`test/tests/policy`, still 100% on all four metrics):

| Mutation                                         | Tests that failed |
| ------------------------------------------------ | ----------------- |
| The updater's record is never written            | 216               |
| A lost record reaches the updater                | 7                 |
| A lost record reads as absent instead of failing | 3                 |
| The read helper names no channel                 | 3                 |

The opening's part, the three first-sight values `pinChannelTerms` takes from the host, `reservedCkbShannons` over either
side's close script, and the `ChannelRegistrationError` each contradicted registration throws, were broken the same way
(`test/tests/policy`, still 100% on all four metrics):

| Mutation                                                        | Tests that failed |
| --------------------------------------------------------------- | ----------------- |
| The keys are pinned 0x-prefixed                                 | 278               |
| The peer's funding key pin is its TLC base key                  | 221               |
| The delay is pinned in hex                                      | 210               |
| The peer's TLC base key pin is its funding key                  | 182               |
| The host pins the terms alone                                   | 15                |
| The host does not pin the delay                                 | 10                |
| The host does not pin the peer's TLC base key                   | 10                |
| The registration error carries no channel id                    | 7                 |
| The registration error carries no channel index                 | 7                 |
| The host does not pin the peer's funding key                    | 6                 |
| The delay bound refuses its own edge                            | 5                 |
| The peer's TLC base key is not checked                          | 5                 |
| The peer's TLC base key is refused under the funding key's name | 5                 |
| The peer's funding key is not checked                           | 5                 |
| The registration error is not a TypeError                       | 5                 |
| The registration error keeps Error's name                       | 5                 |
| The delay bound admits its edge plus one                        | 4                 |
| The delay is not checked                                        | 4                 |
| The reserve's close script is checked under another name        | 4                 |
| The reserve's close script is not checked                       | 4                 |
| A claimed name reports the index it resolves to                 | 2                 |
| A claimed name throws a plain TypeError                         | 2                 |
| A served record's rename reports the record's name              | 2                 |
| A served record's rename throws a plain TypeError               | 2                 |
| Another funded amount or close script reports the record's name | 2                 |
| Another funded amount or close script throws a plain TypeError  | 2                 |
| The reserve's layout is checked under another name              | 2                 |
| The reserve's layout is not checked                             | 2                 |
| A name at another index reports the index it is at              | 1                 |
| A name at another index throws a plain TypeError                | 1                 |

`test/tests/policy/hold-invoice-release.spec.ts` pins the judgment over records written by hand: the invoice's TLCs
listed in a view's order and nothing under another hash, one binding the whole hash listed and its twin left out; the
amount held in both views passing, one shannon above it too and one short refused, an invoice no channel lists a TLC of
refused, the channels summed and the TLCs of one view summed, two channels holding it in crossed views refused, a twin
not counted, another algorithm refused, an offered TLC refused beside a TLC of the invoice and allowed on a channel that
lists none; the expiry refused exactly at the margin past now, each channel's margin from its own pinned delay, a channel
listing a TLC of the invoice with no delay pinned thrown as a host error and one listing none asked no margin, a margin
outside a u64 refused, its top refusing every TLC and zero taking an unexpired one; and the refusals in order, the
algorithm before the offered TLC, the offered TLC before the amount, a later channel's offered TLC before an earlier
one's short amount, the amount before the expiry, and no margin read before the amount is held. The engine's spec drives
them through the store: the record under the bound 20 bytes with the index at either end of its range, a repeat writing
nothing, another amount, algorithm or index refused, a twin and an authorised payment's hash refused, one refusal per
argument, the zero amount among them; the release marked once and a repeat judging nothing and writing nothing, an
invoice no channel showed and each view alone refused, the exact amount released and one shannon more refused, the
channels summed, the expiry refused at the margin and released a millisecond before it, the margin asked of the pinned
delay, an unrecorded invoice refused, one refusal per argument and per timing field, five clock readings that are no
whole milliseconds refused and a throwing clock passed through, all writing nothing, the clock read once after the
records and before the write, each timing field read once, and a clock at zero taken; `readHoldInvoice` by the whole
hash, refusing an unrecorded or malformed one; and `listsHoldInvoiceTlc` answering for each view and each channel until
both views of every channel dropped the TLC. `utils/validate.utils.spec.ts` holds the stored record to the same: the
index at either end of its range, and a zero amount and an index fractional, negative, past the bound or in a string
refused.

The hold invoice's index and its release, `recordHoldInvoice` with the index, its amount above zero and its conflict, the
stored record's guard, `markHoldInvoiceReleased` (each timing field read once, the clock read once inside the balance lock
after the records it judges) over `judgeHoldInvoiceRelease` (`not_held` at each channel's view holding less, summed,
against the exact amount; `expiry_too_close` at its boundary; a channel without TLCs of the invoice skipped; the pinned
delay required), and the queries `readHoldInvoice` and `listsHoldInvoiceTlc`, were broken the same way (`test/tests/policy`, still 100% on all four
metrics). The first table's six rows on the release and on recording an invoice again carry this sweep's counts:

| Mutation                                                         | Tests that failed |
| ---------------------------------------------------------------- | ----------------- |
| The invoice index is not recorded                                | 65                |
| The exact amount is refused as not held                          | 36                |
| The expiry is read in seconds against a deadline in milliseconds | 34                |
| The amount held is not checked                                   | 15                |
| A TLC expiring a millisecond past the margin is refused          | 12                |
| The deadline is now, without the margin                          | 12                |
| The invoice's TLCs are listed without the bound hash             | 10                |
| Each channel counts at the view holding more                     | 8                 |
| The deadline is the margin, without now                          | 7                 |
| A TLC expiring exactly at the margin is released                 | 6                 |
| The invoice is marked released before it is judged               | 6                 |
| An amount one shannon short is held                              | 5                 |
| Each channel counts at its remote view                           | 5                 |
| The channels' amounts are not summed, the largest one counts     | 5                 |
| The invoice index is not checked                                 | 5                 |
| The invoice record guard ignores the invoice index               | 5                 |
| The release clock is not checked                                 | 5                 |
| Each channel counts at its local view                            | 4                 |
| A listed channel with no record is skipped                       | 3                 |
| The listing query's hash is not checked                          | 3                 |
| The margin is asked of a zero delay                              | 3                 |
| The margin is not checked to be a u64                            | 3                 |
| The read's hash is not checked                                   | 3                 |
| Only the first TLC of a channel is held to the expiry            | 2                 |
| The clock is not checked to be a function                        | 2                 |
| The clock is read before the balance lock                        | 2                 |
| The expiry is judged before the amount                           | 2                 |
| The listing query reads the remote view alone                    | 2                 |
| The margin is not checked to be a function                       | 2                 |
| The timing is not checked to be an object                        | 2                 |
| A channel listing a TLC with no delay pinned is not refused      | 1                 |
| A channel without TLCs of the invoice is held to the expiry too  | 1                 |
| A released invoice is judged again                               | 1                 |
| A twin's record answers for the hash                             | 1                 |
| A view's TLCs are not summed, the first one counts               | 1                 |
| A zero-amount hold invoice is recorded                           | 1                 |
| An invoice may be recorded again with another index              | 1                 |
| The clock is read before the records it judges                   | 1                 |
| The clock is read from the timing again inside the lock          | 1                 |
| The invoice record guard takes a fractional invoice index        | 1                 |
| The invoice record guard takes a zero amount                     | 1                 |
| The listing query answers yes for a listed channel               | 1                 |
| The listing query reads the first channel alone                  | 1                 |
| The margin is read from the timing again for the judgment        | 1                 |
| The release is judged at a clock of zero                         | 1                 |

The peer's close script, a term the host pins from the opening context (`channelTermsPins`, `CHANNEL_TERMS_PINS`, the
check in `pinChannelTerms` and its form in the record guard) and a value every close states after the device's
(`statedChannelPins`), was broken the same way (`test/tests/policy`, still 100% on all four metrics). Two rows of the
first table count this sweep's specs too: "An unpinned term is not refused", which lets a close through on a channel
whose terms the host never pinned, and "A close states no device close script", whose specs tell it from a close that
states no peer's:

| Mutation                                                   | Tests that failed |
| ---------------------------------------------------------- | ----------------- |
| The peer's close script term is pinned as its args alone   | 41                |
| The host's terms pin no peer's close script                | 37                |
| The peer's close script is not a term                      | 32                |
| A close states the device's close script as the peer's     | 18                |
| The peer's close script term is checked under another name | 10                |
| The peer's close script term is not checked                | 10                |
| A close states no peer's close script                      | 6                 |
| The record guard takes any peer's close script             | 4                 |
| A close states the peer's close script before the device's | 2                 |
