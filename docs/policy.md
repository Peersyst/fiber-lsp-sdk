# Policy

The gate every signing request passes before the musig2 engine runs. It is the half of the design that makes deterministic
nonces safe and blind signing impossible: the engine signs whatever it is handed ([signing.md](./signing.md)), the digest
module rebuilds messages but judges nothing ([digest.md](./digest.md)), and this layer decides. The state it decides over is
the per-channel record ([persistence.md](./persistence.md)).

## The five checks, in order

Ahead of them, `PolicyEngine.checkAndClaim` validates the request's own **shape** and refuses it as `malformed`: two
distinct 33-byte public keys on the curve, one of which is this channel's funding key, a 66-byte aggregated nonce whose two
halves are points on the curve or at infinity, a 32-byte message, a known operation, and numbers in range. On the wire the
lengths are checked once more, and earlier, by the protocol codecs ([protocol.md](./protocol.md)), which is where a field's
spelling and encoding are judged; the engine repeats the part it depends on because it is callable without the wire. The
points are not the codecs' to check but the gate's, before the claim: the musig2 engine would refuse them too, but with
the slot already served and nothing ever signed in it. Everything in a request is node-supplied, so a bad field has to be
a wire refusal rather than an exception escaping into the session, and the same mapping covers the digest builders, whose
rejections of structurally impossible state (a fee no capacity covers, more than 255 TLCs, a public key off the curve)
become `malformed` rather than a crash. Inside the engine it precedes the channel lookup. Through the signer dispatch the
channel is resolved first, since the keys the gate takes derive from it, so a request for an unknown channel answers
`unknown_channel` unless the codecs have already refused it ([signing.md](./signing.md)).

The five then resolve the channel's name to its index and run as one step inside `SignerStore.updateChannelRecord`, so the
record they read is the record they write and no concurrent request can interleave with the decision. Every claim also
runs inside the store's balance lane, one at a time across every channel: the rule reads records other channels share, and
nothing may move a record between the decision that files a channel on a payment record and the claim it was filed for
(below).

| #   | Check                | Refusal           | What it means                                                                                               |
| --- | -------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------- |
| 1   | Known channel        | `unknown_channel` | The channel's name resolves to no channel index. Corrupt state throws instead, it never reads as absence    |
| 2   | Digest recomputation | `malformed`       | The message must equal what the `digest` module rebuilds from the attached state: the no-blind-signing rule |
| 3   | Sign-once            | `policy_refusal`  | The slot must be free, or already served for this exact session, which is answered `already-signed`         |
| 4   | Monotonicity         | `stale_state`     | Commitment numbers strictly increase per context, `stateVersion` never decreases                            |
| 5   | Balance rule         | `policy_refusal`  | Per commitment view and per payment hash: growth needs an open intent, a fall a TLC that took it            |

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
That is what the sign-once registry has to protect, since nonce reuse is what leaks the funding key.

| Operation                    | Slot                        | Number inside the message           |
| ---------------------------- | --------------------------- | ----------------------------------- |
| Commitment tx                | `COMMITMENT:<local number>` | `forRemote ? local : remote` number |
| Cooperative close (shutdown) | `COMMITMENT:<local number>` | no commitment number                |
| Revocation                   | `REVOKE:<remote number>`    | the remote number minus one         |
| Channel announcement         | `ANNOUNCEMENT:0`            | no commitment number                |

Three consequences, all of them fiber's behavior rather than our choice:

- **A commitment slot serves a commitment tx or a close, never both.** Fiber derives no closing nonce: a cooperative close
  signs with the commitment slot of the current local number (`get_funding_sign_context`). The device therefore refuses
  whichever of the two arrives second, and the `CLOSE` nonce context of the derivation scheme stays reserved and unused.
- **The announcement slot is fixed and latched.** Its nonce never rotates, so a second distinct announcement session over
  it would leak the funding key. The number a request carries is ignored, never trusted.
- **A revocation claims the slot of its nonce**, one above the number its message revokes. The off-by-one is fiber's.

## Sign-once claims a session, not a message

The registry stores a commitment to the whole triple a signature answers: the ordered key list, the aggregated nonce and
the message, hashed under a versioned label. Counting messages would not be enough. A partial signature is
`s = k1 + b·k2 + e·a·d`, and both `b` and `e` come from the aggregated nonce the node chose, so one slot and one message
under three different aggregates are three linear equations that solve for the funding key ([signing.md](./signing.md)).

A repeat that matches the stored commitment byte for byte is the idempotent resume path: the gate answers `already-signed`
and the caller re-signs, which is deterministic and therefore identical. That path leaves the pipeline at check 3, so a
re-delivery charges nothing, files nothing and moves no counter, and the stale numbers it would otherwise carry never matter.

## The claim is written before anything is signed

The gate persists the claim and only then does the caller sign. The reverse order loses: a crash between producing a
signature and recording it would leave the slot free with its nonce already exposed, and the next request could take it
with a different session. Claiming first is safe precisely because the nonce is deterministic, so the interrupted request
is answered identically when it comes back.

## The balance rule

The device signs two commitments for every change of state, the peer's (`forRemote`) and its own, and they do not list the
same TLCs at the same time: an offered TLC reaches the peer's commitment first and the device's own only after the peer's
`RevokeAndAck`, and a `commitment_signed` that crosses one of the device's adds is signed over a commitment without it. The
record therefore keeps one **view** per commitment, and each view is judged against its own previous message only. One
number compared across both would read the crossing as an increase followed by an unexplained decrease.

A view's snapshot is what the last message signed in it stated: the **exposure**, fiber's TLC-adjusted settlement amount
(`to_local + received_fulfilled - offered_pending - offered_fulfilled`), and the TLCs it listed. A TLC is kept as what the
settlement witness binds of it: its direction, its hash algorithm (in the entry's flag byte), the first 20 bytes of its
payment hash (`boundPaymentHash`), its amount and its expiry in whole seconds, never by its id. The id only orders the
witness, and the remaining 12 bytes of the hash are bound by nothing. Snapshots are compared as multisets of those five
values. Next to them each view keeps, per bound
hash, what it has **charged** and what it has **credited** (below).

Two kinds of records sit beside the channel's, device-wide and keyed by the same 20 bytes, because the node and not the
device chooses which channel a payment leaves through:

- a **debit intent**: the most the user approved for a payment, amount and fee budget together, and whether it is still open;
- a **hold invoice**: its amount, and whether the device has released its preimage.

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
builds a close only once none is pending), and it may not pay the device less than either view's exposure. It spends no
intent, having no hash to name one.

Each device-wide record lists the channels that have shown a TLC under its hash, written before the claim that shows it,
since a claim may only write its own channel's record. That list is how a claim finds the other channels drawing on one
budget or crediting one invoice, and a channel too many on it costs a read. The engine decides each commitment once before
writing anything and again inside the record's critical section, so a refused request leaves the device-wide records
untouched too, and the balance lane keeps two channels from drawing on one budget at once.

## What this layer deliberately does not do

- **It does not verify the aggregated nonce.** Nothing proves the 66 bytes the node sent contain the public nonce the
  device published. The sign-once rule is what makes that safe, and it is why a legitimate node error is indistinguishable
  from an attack here (open question with the Fiber team).
- **It does not re-derive the state it is shown.** TLC selection, settlement amounts, fee rates and close scripts arrive as
  inputs. The digest binds the signature to them and the record judges them; re-running fiber's TLC state machine would be
  a second source of truth with its own bugs.
- **It does not sign.** Nothing in the pipeline forces the caller to sign what it claimed. The gate and the engine are
  one path in the signer dispatch, at one call site that signs exactly the slot the verdict names
  ([signing.md](./signing.md)).
- **It judges the amounts a message states, not the capacity behind them.** The exposure it compares on a cooperative
  close is the amount the message pays the device, while the output that close actually builds is that amount plus the
  reserved capacity minus a fee taken at the rate the node attached, bounded only by the capacity it comes out of. A close
  carrying the right amount and an inflated local fee rate therefore passes. The commitment tx has the same shape one step
  removed: its fee shrinks the cell below the settlement amounts it must pay out, and the settlement amount the rule reads
  is untouched. Closing it is a bound on the fee on its own, out of the reserve, and it lands with the pins of the
  channel's constant values.
- **It judges the latest commitment of each view, never the ones it supersedes.** A commitment the device signed stays
  publishable until it is revoked, and revocation is a musig2 transaction the node completes: the device produces its half
  on request, never sees the peer's `RevokeAndAck`, and holds no completed revocation, so it has no signal it can check that
  a superseded commitment is no longer publishable. A budget is therefore bounded at the latest state only: a TLC that
  failed under a hash in one channel frees its budget, and an operator that withholds its `RevokeAndAck` could publish the
  superseded commitment still listing it after a retry elsewhere was paid. More broadly, a revoked own commitment and the
  revocation that sweeps it both sit with the node, so the device rests on the operator of its node not publishing
  superseded state. Nothing device-side closes this; it is an open question with the Fiber team (I8).
- **It cannot tell a fulfilled TLC from a failed one except by the amounts.** The request carries no preimage, so step 2
  charges every TLC that could have been paid, as described above.
- **It never prunes the registry.** A slot per signed commitment stays forever. Pruning is only safe behind the monotonic
  counter, which refuses a number already served even when its slot is gone, and it would cost the idempotent replay of an
  old request.

## Where it lives

| File                                     | Contents                                                                                           |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `src/policy/policy-engine.ts`            | The five checks, the claim, channel registration, intents and hold invoices                        |
| `src/policy/balance-rule.ts`             | Check 5 itself, pure: the three steps over two snapshots, and the close                            |
| `src/policy/policy.constants.ts`         | The keyspace prefixes and the balance lane, the record formats and their versions, the error codes |
| `src/policy/policy.error.ts`             | `PolicyRefusalError`, carrying the wire error code; `DebitIntentError` and `HoldInvoiceError`      |
| `src/policy/utils/payment-hash.utils.ts` | The bound payment hash a payment record is keyed by                                                |
| `src/policy/utils/slot.utils.ts`         | Operation to slot, where the shared close slot and the fixed announcement live                     |
| `src/policy/utils/session.utils.ts`      | The session commitment and the shape a signable session must have                                  |
| `src/policy/signer-store.ts`             | The persistence underneath ([persistence.md](./persistence.md))                                    |

## What the tests guarantee

`test/tests/policy/policy-engine.spec.ts` builds its requests out of the cross-implementation vectors, so check 2 runs
against digests generated by fiber's own Rust code rather than by the code under test. Around that: a refusal per check and
per malformed field, both sign-once refusals the spec demands (a served slot re-requested with another message, and with
the same message under another aggregated nonce or another key list), the two directions of the shared commitment slot, the
latched announcement, the already-signed path leaving the record untouched and costing no write, and two concurrent
sessions racing for one slot where exactly one wins.

The balance rule has a spec of its own, `test/tests/policy/balance-rule.spec.ts`, over snapshots written by hand: a
refusal per step and per bound (no intent, a closed one, one shannon over the maximum, other channels' TLCs and charges,
this view's charges, every channel counted at its worst view), a view catching up with its other view under a closed
intent and one drawing past it, the retry after a failure, the replacement inside one message, the parts of a multi-path
payment, every charging case (exact, none, ambiguous, widened by a received TLC and never by a held one, with nothing
fallen, the twelve-TLC boundary on both), every credit case (failed, fulfilled, unreleased, unknown, a part, the cap
across channels, another channel at its less paid view), the offered TLC refused beside a released held one in either
view and a mixed channel refused a new offered or released held TLC and allowed to retire TLCs, a TLC of a released
invoice refused under another algorithm (added, or changed between two messages) and allowed before the release, and the
close against each view. The engine's spec drives it through real requests, whose digests the SDK computes for the
states the vectors do not cover: the crossing views, one budget drawn from two channels, a second channel's other view
refused against it, an invoice two channels paid in different views, a revocation fired between a commitment's decision
and its claim, a release refused while an offered TLC is listed beside a TLC of the invoice (in either view) and allowed
on a channel that no longer lists one, an offered TLC refused beside a released TLC listed only in the other view, a
charge found in the local view alone, a hash refused as both payment and invoice, an offered TLC refused on a channel
holding a released one, two channels racing for it, a released preimage dropped and paid, and the intent and invoice
records' own rules. A malformed request for an unregistered channel pins that the shape check answers first. Renaming
has its own set: both names of a channel reaching one record, a repeat under the other name answered `already-signed`, a
rename refused once the record has served, two names racing for the same slot, and two registrations racing for one name
where the loser's index never takes it.

Coverage of the module is 100% on all four metrics. Coverage only proves there is no dead code, so the assertions were
checked by breaking the code on purpose:

| Mutation                                                        | Tests that failed |
| --------------------------------------------------------------- | ----------------- |
| The close gets a `CLOSE` slot of its own                        | 3                 |
| The announcement slot follows the request                       | 3                 |
| The session commitment drops the aggregated nonce               | 4                 |
| The session commitment sorts the key list                       | 2                 |
| The keys are not checked to be on the curve                     | 3                 |
| The nonce is not checked to be on the curve                     | 4                 |
| A nonce half at infinity is refused                             | 3                 |
| A zero-prefixed nonce half is read as infinity                  | 1                 |
| A key at infinity is accepted                                   | 1                 |
| Monotonicity accepts an equal number                            | 1                 |
| The state version may roll back                                 | 1                 |
| A closed intent still lets a TLC grow                           | 3                 |
| The budget ignores other channels                               | 7                 |
| Other channels count at the judged view                         | 2                 |
| Growth is read against this view alone                          | 2                 |
| The budget ignores what was charged                             | 4                 |
| Growth is read on the shown amounts alone                       | 3                 |
| A fulfilment counts as growth                                   | 9                 |
| A channel may show an offered TLC beside a released held one    | 8                 |
| The mix guard reads the judged view alone                       | 2                 |
| A channel that already shows the mix is refused too             | 3                 |
| A mixed channel may grow                                        | 2                 |
| Growth of a mixed channel reads offered TLCs alone              | 1                 |
| Growth of a mixed channel reads released held TLCs alone        | 1                 |
| The mix guard counts unreleased held TLCs                       | 34                |
| The release ignores offered TLCs in flight                      | 2                 |
| The release ignores whether the channel still lists the invoice | 1                 |
| A payment may take the hash of an own invoice                   | 1                 |
| An invoice may take the hash of an authorised payment           | 1                 |
| The release reads the remote view alone                         | 1                 |
| A charge is looked for in the remote view alone                 | 1                 |
| The context reads the judged view's TLCs alone                  | 1                 |
| A mix before is read without the other view                     | 1                 |
| The budget refuses its own maximum                              | 54                |
| A non-positive shortfall does not search                        | 4                 |
| Nothing fallen and no set fitting is a refusal                  | 2                 |
| Received TLCs that left widen nothing                           | 5                 |
| An unreleased invoice's TLC widens the window                   | 1                 |
| Only received TLCs with no invoice widen the window             | 1                 |
| Every departed TLC is charged                                   | 6                 |
| No departed TLC is charged                                      | 14                |
| The exact search stops one TLC early                            | 2                 |
| An unreleased invoice is credited                               | 3                 |
| The credit is not capped by what is owed                        | 2                 |
| The cap ignores other channels' credits                         | 1                 |
| Another channel's credit counts at its more paid view           | 2                 |
| Holdings count received TLCs too                                | 18                |
| TLCs are compared without their expiry                          | 1                 |
| The snapshot keeps the whole hash                               | 58                |
| Both commitments share one view                                 | 4                 |
| A close ignores listed TLCs                                     | 3                 |
| A close is judged against one view                              | 2                 |
| The channel is not filed on the intents                         | 9                 |
| The channel is not filed on the invoices                        | 5                 |
| The channel is filed before the decision                        | 2                 |
| Revocations claim outside the balance lane                      | 2                 |
| Commitment claims skip the balance lane                         | 2                 |
| A charged intent opens again                                    | 3                 |
| An open intent is replaced                                      | 1                 |
| A repeat of an open intent is refused                           | 1                 |
| An open intent repeated with another maximum is a no-op         | 1                 |
| A twin hash answers for the recorded one                        | 2                 |
| A record may sit under another hash's key                       | 2                 |
| An intent record is read without its version                    | 3                 |
| An invoice record is read without its version                   | 3                 |
| TLCs are compared without their algorithm                       | 1                 |
| The snapshot drops the algorithm                                | 12                |
| A view TLC is read without its algorithm                        | 2                 |
| An invoice record is read without its algorithm                 | 1                 |
| An invoice may be recorded again with another algorithm         | 1                 |
| The release ignores the algorithm of a held TLC                 | 1                 |
| A released invoice takes a TLC under another algorithm          | 2                 |
| The algorithm guard ignores the release                         | 2                 |
| The already-signed path keeps running                           | 2                 |
| The digest comparison is dropped                                | 5                 |
| The channel lookup runs before the shape check                  | 2                 |
| A record that has served may take a new name                    | 2                 |
| A rename starts a fresh record                                  | 1                 |
| A name may be re-registered at another index                    | 1                 |
| The name is written instead of claimed                          | 6                 |
| The alias is written before the record                          | 1                 |
| A no-op update still writes the record                          | 3                 |
