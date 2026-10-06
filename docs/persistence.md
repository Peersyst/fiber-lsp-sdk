# Persistence

What the device persists, and the guarantees `SignerStore` gives the policy engine on top of the host's storage.

## Keyspace

The host injects an `ISignerStorage` (or its async form): a string-keyed, string-valued store the SDK never introspects. All
keys carry the `fiber-lsp-sdk:` namespace, because the host may back that storage with a store it also uses for its own keys.

| Key                                 | Value                                                                |
| ----------------------------------- | -------------------------------------------------------------------- |
| `fiber-lsp-sdk:channel:<index>`     | The channel's policy record, JSON                                    |
| `fiber-lsp-sdk:alias:<id>`          | The channel index that channel id resolves to, an integer in base 10 |
| `fiber-lsp-sdk:intent:<boundHash>`  | The debit intent of a payment, JSON                                  |
| `fiber-lsp-sdk:invoice:<boundHash>` | A hold invoice whose preimage the device holds, JSON                 |
| `fiber-lsp-sdk:preimage:<hash>`     | The device-held preimage of a hold invoice, 32 bytes hex             |

The prefixes are fixed and disjoint, so a channel id and a payment hash can be the same string without colliding.
`<boundHash>` is the bound payment hash: the first 20 bytes of the payment hash, the part a commitment binds. A record
keyed by all 32 would let a node that changes the other 12 find no invoice to pay for ([policy.md](./policy.md)). The
record holds the whole hash, and a record whose hash does not start with its key's reads as corruption.

## Identity: the index, not the name

A record is keyed by the **channel index**, and the channel id is an alias pointing at it. The two are not interchangeable:
the index is what every channel secret derives from ([derivation.md](./derivation.md)), while the id is a name fiber assigns
twice, a temporary one at open and the final one once the handshake knows both sides' TLC base keys.

Keying by the name would split the record the moment the name changed: two records, two sign-once registries, one nonce
space, which is the exact condition that leaks the funding key ([policy.md](./policy.md)). Aliases are therefore many to
one and never removed, so every name a channel ever had keeps resolving to the one record, and the critical section runs on
the index, so two names cannot interleave on it.

`registerChannel` writes the record first and the alias second: the reverse order could leave a name resolving to an index
that holds nothing. A record may take a new name only while it has served nothing at all, since renaming one that has
served would hand a live channel's slots to another name.

The alias is **claimed**, not written: `claimChannelAlias` reads and sets the key inside one critical section, and a name
already resolving to another index throws instead of moving. Many names may point at one index, which is the whole point of
the map, but a name never moves between indexes, so the two registrations of a channel cannot end up with the record at one
index and its name at another.

## The channel record

One record per channel, holding what the policy checks need. Everything else about a channel lives on the node, which stays
the durable store for channel state.

| Field                         | What it holds                                                                             |
| ----------------------------- | ----------------------------------------------------------------------------------------- |
| `version`                     | Format version of the record itself                                                       |
| `channelId`                   | The channel's current name, which the open handshake may still change                     |
| `lastSignedCommitmentNumbers` | Last commitment number signed per context, strictly increasing                            |
| `signedSessions`              | Sign-once registry: the session served in each `<context>:<number>` slot                  |
| `lastStateVersion`            | Last state version seen from the node, non-decreasing                                     |
| `views`                       | One snapshot per commitment the device signs, `remote` (the peer's) and `local` (its own) |

A view's snapshot holds:

| Field              | What it holds                                                                                                 |
| ------------------ | ------------------------------------------------------------------------------------------------------------- |
| `exposureShannons` | The device's TLC-adjusted share after the last message signed in the view, integer shannons in base 10        |
| `tlcs`             | The TLCs that message listed: direction, hash algorithm, `boundPaymentHash`, amount, expiry in seconds; no id |
| `chargedShannons`  | Per `<boundHash>`, what offered TLCs that left the view took with them                                        |
| `creditedShannons` | Per `<boundHash>`, what received TLCs of a released invoice had to pay the view                               |

Two fields carry more than their name suggests, and [policy.md](./policy.md) is where the reasoning lives:

- `signedSessions` stores a commitment to the whole triple a signature answers (the ordered key list, the aggregated nonce
  and the message), not to the message alone. Storing only the message would let a node re-ask one slot under three
  aggregated nonces of its choosing and recover the funding key.
- `exposureShannons` is fiber's settlement amount, not the raw balance: it drops the moment an offered TLC is committed,
  which is while the device can still refuse, rather than later when the TLC settles. It is kept per view because the two
  commitments do not list the same TLCs at the same time.

Two rules keep the sign-once registry trustworthy:

- **Corruption throws; it never reads as absence.** A record or an alias that fails to parse or fails its shape guard raises a
  `TypeError` naming the key. Reading it as "no record" would re-register the channel with empty sign-once slots, and a slot
  that reopens turns a legitimate refusal into a second signature over the same nonce. An alias resolving to an index that
  holds no record throws for the same reason, rather than reading as a channel the device never knew.
- **The record carries a format version.** A future format change migrates old records rather than rejecting them, for the same
  reason: a rejected record is a lost registry. Unknown extra fields are tolerated on read; a version from the future is not.

## The payment records

A debit intent holds the full payment hash, `maxShannons` (amount plus fee budget), `open`, and `channelIndexes`; a hold
invoice holds the full payment hash, `amountShannons`, `hashAlgorithm`, `released`, and `channelIndexes`. Both are device-wide because
the node, not the device, picks the channel a payment uses, and both carry `version` (`PAYMENT_RECORD_VERSION`), as the
channel record does. Until the SDK's first release every format changes in place without bumping its version; from then
on a change is a new version and a migration.

`channelIndexes` lists every channel that has shown a TLC under the hash, so a claim can find the other channels drawing on
one budget or crediting one invoice, since the storage cannot be enumerated. It is written before the claim that shows the
TLC, and only once that claim has been decided: a crash in between leaves a channel listed that shows nothing, which costs
a read, while the reverse order could leave a charge nobody finds. What a view has charged and credited lives in the channel
record, written in the same step as the claim, so no amount is kept twice.

Neither kind is ever deleted. A closed intent stays, since what was charged to it is what keeps it from opening again.

## What growth this costs

Nothing here is ever deleted, so it is worth stating what that costs. An alias is about 90 bytes (a 20-character prefix, a
64-character channel id, and an index), and a channel has at most the two names fiber gives it, so every channel the device
ever opened costs under 200 bytes of names for good: a thousand channels is under 200 KB.

The registry inside the record is the half that grows without a bound, at about 85 bytes per slot ever served, in a value
re-serialized on every claim. A channel a thousand commitments deep therefore rewrites an 85 KB record on each signature, and
that write amplification, not the alias map, is the cost to watch on a device.

The views grow the same way, more slowly: each keeps one entry of about 60 bytes per payment hash it has ever charged or
credited, so the record also carries every payment that ever crossed the channel. A payment record is about 200 bytes and
one exists per payment and per invoice the device ever made, so ten thousand of them is about 2 MB, read only when a
commitment names their hash.

Neither is pruned, and the reason is the same for both: the device never learns from a source it trusts that a channel is
finished, since closure is node-supplied state, and deleting on it would hand the node a way to clear the names and slots that
refuse it. Pruning the registry is additionally bounded by what would still be safe without it, the monotonic counter, and it
would cost the idempotent replay of an old request ([policy.md](./policy.md)).

## Concurrency

`SignerStore` serializes every operation per storage key. Operations on one key run in call order, one at a time, and each
`updateChannelRecord` holds its key for the whole read-modify-write, which is the record's key and therefore the channel
index: two names of one channel share the lane. Different keys never wait on each other. Claims are the exception: they
all run in the balance lane below, one at a time across every channel, so a slow claim does stall the next one.

One lane is no key at all: `withBalanceLock` runs an operation after every earlier one in a lane named
`fiber-lsp-sdk:balance`, which nothing is ever stored under. The policy engine runs every claim in it, and every write of
an intent or an invoice, because the balance rule reads records several channels share: the per-key lanes alone would let
two channels draw on one budget at once, and a revocation landing between a commitment's decision and its claim could fail
the claim after its channel was filed on a payment record.

This is what makes the sign-once registry hold under concurrent sign requests. Without it, two requests for the same slot both
read the record before either writes, and the second write drops the first one's claim on the slot: exactly the double signature
the registry exists to prevent. The policy engine must therefore do its read-decide-write inside `updateChannelRecord`, never as
a separate `getChannelRecord` plus `setChannelRecord`. The updater is synchronous by design: it runs while the key is held, so
it decides and returns, and anything slower belongs outside the critical section.

Refusals throw out of the updater before the write, which leaves the stored record untouched and the key immediately usable by
the next operation. So does a decision that changes nothing: an updater that hands back the record it was given skips the
write, so the idempotent replay of an already-served request and the re-registration of a known channel cost the device's
storage nothing.

**The guarantee is per `SignerStore` instance.** Two stores over the same underlying storage (a second tab, a second process, a
second SDK instance) can still lose an update to each other, because `ISignerStorage` has no compare-and-swap to build on. A
host must give the SDK a single instance, or keep its storage private to one.

## Recovery

From the mnemonic alone the host re-derives the master seed, and the SDK re-derives every channel key (see
[derivation.md](./derivation.md)). What does not come back is the record: counters, the sign-once registry and the view
snapshots all start empty, and so do the intents and the invoices. Losing the storage is therefore not losing funds, with
one exception: hold-invoice preimages exist only on the device, so unclaimed held payments need the storage intact. They
are refundable to the payer otherwise.

**Rebuilding that state is not something the SDK does today.** What a restore would have to rebuild before anything else is
the alias map: which channel index each of the node's channels belongs to. `ISignerStorage` is `get` and `set` with no
enumeration, so that mapping cannot be read back from the storage itself, and while it is missing every channel the node
holds reads as unregistered. That is where a reinstalled device stands, and it is the safe side to fail on: it refuses
everything rather than signing under an empty registry.

The reason it stays open is that whatever rebuilds the map still owes an answer for the sign-once registry, which cannot come
back with it. A record rebuilt from what the node reports takes its counters from a number the node chooses, and a node
reporting one below the truth gets a slot served twice under a session of its choosing, which is the condition that recovers
the funding key ([policy.md](./policy.md)). Once the storage is gone the device holds nothing of its own to check that number
against. Until that is settled, re-registering a channel this device has already signed for is a decision the host takes on
its own: `registerChannel` will build a record with an empty registry, and every check downstream trusts it.
