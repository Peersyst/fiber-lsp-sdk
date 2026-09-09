# Policy

The gate every signing request passes before the musig2 engine runs. It is the half of the design that makes deterministic
nonces safe and blind signing impossible: the engine signs whatever it is handed ([signing.md](./signing.md)), the digest
module rebuilds messages but judges nothing ([digest.md](./digest.md)), and this layer decides. The state it decides over is
the per-channel record ([persistence.md](./persistence.md)).

## The five checks, in order

Ahead of them, `PolicyEngine.checkAndClaim` validates the request's own **shape** and refuses it as `malformed`: two
distinct 33-byte public keys one of which is this channel's funding key, a 66-byte aggregated nonce, a 32-byte message, a
known operation, and numbers in range. Everything in a request is node-supplied, so a bad field has to be a wire refusal
rather than an exception escaping into the session, and the same mapping covers the digest builders, whose rejections of
structurally impossible state (a fee no capacity covers, more than 255 TLCs, a public key off the curve) become
`malformed` rather than a crash. It precedes the channel lookup, so a malformed request for an unknown channel answers
`malformed`.

The five then resolve the channel's name to its index and run as one step inside `SignerStore.updateChannelRecord`, so the
record they read is the record they write and no concurrent request can interleave with the decision.

| #   | Check                | Refusal           | What it means                                                                                               |
| --- | -------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------- |
| 1   | Known channel        | `unknown_channel` | The channel's name resolves to no channel index. Corrupt state throws instead, it never reads as absence    |
| 2   | Digest recomputation | `malformed`       | The message must equal what the `digest` module rebuilds from the attached state: the no-blind-signing rule |
| 3   | Sign-once            | `policy_refusal`  | The slot must be free, or already served for this exact session, which is answered `already-signed`         |
| 4   | Monotonicity         | `stale_state`     | Commitment numbers strictly increase per context, `stateVersion` never decreases                            |
| 5   | Balance rule         | `policy_refusal`  | A message that lowers the device's share needs a user-initiated debit intent, which it consumes             |

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
re-delivery consumes no debit intent and moves no counter, and the stale numbers it would otherwise carry never matter.

A device that lost its storage keeps that path for the one slot that matters. The watermark it left behind carries the
top slot of each context, so the request a reconnect re-delivers is still answered `already-signed` and re-signed to the
same bytes, while everything at or below the counter refuses with `stale_state`
([persistence.md](./persistence.md#what-a-restored-device-still-refuses)).

## The claim is written before anything is signed

The gate persists the claim and only then does the caller sign. The reverse order loses: a crash between producing a
signature and recording it would leave the slot free with its nonce already exposed, and the next request could take it
with a different session. Claiming first is safe precisely because the nonce is deterministic, so the interrupted request
is answered identically when it comes back.

## The balance rule

The record tracks the device's **exposure**: fiber's TLC-adjusted settlement amount, not the raw balance. An offered TLC
lowers it the moment the commitment is signed, which is the only moment the device can still refuse; the raw balance moves
later, when the TLC settles and the money is already gone.

A message that lowers the exposure is signed only against a recorded debit intent that covers the decrease, and it consumes
the smallest one that does. Intents are authorised maximums, fee budget included, because the decrease a payment causes is
the amount plus whatever routing costs. Increases need no intent. A cooperative close answers to the same rule, since it is
the moment funds leave the 2-of-2 and the digest check alone only binds the signature to some payout, not to the right one.

The intent is recorded by the host before the operation that causes the decrease, never after: `transfer` records it and
then issues `send_payment`.

## What this layer deliberately does not do

- **It does not verify the aggregated nonce.** Nothing proves the 66 bytes the node sent contain the public nonce the
  device published. The sign-once rule is what makes that safe, and it is why a legitimate node error is indistinguishable
  from an attack here (open question with the Fiber team).
- **It does not re-derive the state it is shown.** TLC selection, settlement amounts, fee rates and close scripts arrive as
  inputs. The digest binds the signature to them and the record judges them; re-running fiber's TLC state machine would be
  a second source of truth with its own bugs.
- **It does not sign.** Nothing in the pipeline forces the caller to sign what it claimed. The gate and the engine become
  one path when the signer session dispatch wires them together, at one call site.
- **It does not tie an intent to a payment.** Intents are amounts, so any decrease consumes any intent that covers it: the
  rule bounds how much can be drained, the sum of what was recorded, but not where it goes. Consuming the smallest
  sufficient intent is optimal for that model, since every alternative leaves a residual set this one dominates element by
  element, but the matching only exists because the intent names no payment. Binding intents to their payment hash removes
  both the gap and the matching, and it is device-side: the hash already reaches the device inside the commitment input
  (`SettlementTlc.paymentHash`) and the host holds it before the payment is issued. It lands with the facade that records
  intents.
- **It does not require an increase, only judge decreases.** Fiber's settlement amount is
  `to_local + received_fulfilled - offered_pending - offered_fulfilled`, so an incoming TLC raises the device's side only
  once it is removed as **fulfilled**; removed as failed it goes back to the peer and leaves the exposure where it started.
  A node that takes a released preimage and then removes the TLC as failed therefore produces a commitment this rule has
  nothing to refuse. Closing it needs the released preimages, which are device-held, matched against the payment hashes the
  commitment input already carries, and it lands with the same work that binds intents to payment hashes.
- **It judges the amounts a message states, not the capacity behind them.** The exposure it compares on a cooperative
  close is the amount the message pays the device, while the output that close actually builds is that amount plus the
  reserved capacity minus a fee taken at the rate the node attached, bounded only by the capacity it comes out of. A close
  carrying the right amount and an inflated local fee rate therefore passes. The commitment tx has the same shape one step
  removed: its fee shrinks the cell below the settlement amounts it must pay out, and the settlement amount the rule reads
  is untouched. Closing it is a decision about what exposure is measured in, since the fee is CKB while a UDT channel's
  amounts are not, and it lands with the same work that binds intents to payment hashes.
- **It does not decide where the anti-rollback floor is kept.** The host injects the storage that survives an uninstall,
  and a device without one is told, per channel, that its restored record has no floor
  ([persistence.md](./persistence.md#what-a-reinstall-keeps)).
- **It never prunes the registry.** A slot per signed commitment stays forever. Pruning is only safe behind the monotonic
  counter, which refuses a number already served even when its slot is gone, and it would cost the idempotent replay of an
  old request.

## Where it lives

| File                                  | Contents                                                                       |
| ------------------------------------- | ------------------------------------------------------------------------------ |
| `src/policy/policy-engine.ts`         | The five checks, the claim, channel registration and debit intents             |
| `src/policy/policy.constants.ts`      | The keyspace prefixes, and the three formats a change to would reopen slots    |
| `src/policy/policy.error.ts`          | `PolicyRefusalError`, carrying the wire error code                             |
| `src/policy/utils/slot.utils.ts`      | Operation to slot, where the shared close slot and the fixed announcement live |
| `src/policy/utils/session.utils.ts`   | The session commitment and the shape a signable session must have              |
| `src/policy/channel-recovery.ts`      | Reconciling the node's channels back onto their index, and the index allocator |
| `src/policy/utils/watermark.utils.ts` | The projection between a record and the watermark a reinstall finds            |
| `src/policy/signer-store.ts`          | The persistence underneath ([persistence.md](./persistence.md))                |

## What the tests guarantee

`test/tests/policy/policy-engine.spec.ts` builds its requests out of the cross-implementation vectors, so check 2 runs
against digests generated by fiber's own Rust code rather than by the code under test. Around that: a refusal per check and
per malformed field, both sign-once refusals the spec demands (a served slot re-requested with another message, and with
the same message under another aggregated nonce or another key list), the two directions of the shared commitment slot, the
latched announcement, the already-signed path leaving the record untouched and costing no write, and two concurrent
sessions racing for one slot where exactly one wins. A malformed request for an unregistered channel pins that the shape
check answers first. Renaming has its own set: both names of a channel reaching one record, a repeat under the other name
answered `already-signed`, a rename refused once the record has served, two names racing for the same slot, and two
registrations racing for one name where the loser's index never takes it.

`test/tests/policy/channel-recovery.spec.ts` runs the other half against a wiped storage: a channel matched to its index
by the funding key alone, a record rebuilt from the watermark and one rebuilt without it, a channel of another seed
reported unmatched and left unregistered, both names of a renamed channel reaching one index, the gap the scan stops at,
and a second run that changes nothing. It ends where the signing engine begins: after the wipe, the re-delivered request is
answered `already-signed` and `partialSign` returns the same bytes the device produced before the reinstall, while the slot
below the counter refuses and the same case without a recovery storage is served fresh.

Coverage of the module is 100% on all four metrics. Coverage only proves there is no dead code, so the assertions were
checked by breaking the code on purpose:

| Mutation                                          | Tests that failed |
| ------------------------------------------------- | ----------------- |
| The close gets a `CLOSE` slot of its own          | 3                 |
| The announcement slot follows the request         | 3                 |
| The session commitment drops the aggregated nonce | 4                 |
| The session commitment sorts the key list         | 2                 |
| Monotonicity accepts an equal number              | 1                 |
| The state version may roll back                   | 1                 |
| The balance rule reads the raw balance            | 5                 |
| The balance rule skips the cooperative close      | 2                 |
| The already-signed path keeps running             | 2                 |
| The digest comparison is dropped                  | 5                 |
| The channel lookup runs before the shape check    | 2                 |
| A record that has served may take a new name      | 2                 |
| A rename starts a fresh record                    | 1                 |
| A name may be re-registered at another index      | 1                 |
| The name is written instead of claimed            | 6                 |
| The alias is written before the record            | 1                 |
| A no-op update still writes the record            | 3                 |
| The watermark is written after the record         | 1                 |
| The watermark is never written                    | 10                |
| The watermark keeps the whole registry            | 2                 |
| A restore takes the node's exposure               | 2                 |
| A restore starts the counters empty               | 4                 |
| A restore drops the pruned registry               | 5                 |
| Registration ignores the watermark                | 1                 |
| The allocator does not step over used indexes     | 3                 |
| Allocation needs no reconciliation                | 2                 |
| The counter is not mirrored, or not read back     | 3                 |
| Reconciliation overwrites the record it finds     | 3                 |
| Reconciliation does not raise the counter         | 2                 |
| The scan does not extend past a match             | 1                 |
