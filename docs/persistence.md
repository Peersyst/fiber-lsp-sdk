# Persistence

What the device persists, and the guarantees `SignerStore` gives the policy engine on top of the host's storage.

## Keyspace

The host injects an `ISignerStorage` (or its async form): a string-keyed, string-valued store the SDK never introspects. All
keys carry the `fiber-lsp-sdk:` namespace, because the host may back that storage with a store it also uses for its own keys.

| Key                             | Value                                                                |
| ------------------------------- | -------------------------------------------------------------------- |
| `fiber-lsp-sdk:channel:<index>` | The channel's policy record, JSON                                    |
| `fiber-lsp-sdk:alias:<id>`      | The channel index that channel id resolves to, an integer in base 10 |
| `fiber-lsp-sdk:preimage:<hash>` | The device-held preimage of a hold invoice, 32 bytes hex             |

The three prefixes are fixed and disjoint, so a channel id and a payment hash can be the same string without colliding.

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

| Field                         | What it holds                                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------------ |
| `version`                     | Format version of the record itself                                                        |
| `channelId`                   | The channel's current name, which the open handshake may still change                      |
| `lastSignedCommitmentNumbers` | Last commitment number signed per context, strictly increasing                             |
| `signedSessions`              | Sign-once registry: the session served in each `<context>:<number>` slot                   |
| `lastStateVersion`            | Last state version seen from the node, non-decreasing                                      |
| `localExposureShannons`       | The device's TLC-adjusted share after the last signed message, integer shannons in base 10 |
| `pendingDebitsShannons`       | User-initiated debits not yet consumed by an exposure-lowering message                     |

Two fields carry more than their name suggests, and [policy.md](./policy.md) is where the reasoning lives:

- `signedSessions` stores a commitment to the whole triple a signature answers (the ordered key list, the aggregated nonce
  and the message), not to the message alone. Storing only the message would let a node re-ask one slot under three
  aggregated nonces of its choosing and recover the funding key.
- `localExposureShannons` is fiber's settlement amount, not the raw balance: it drops the moment an offered TLC is
  committed, which is while the device can still refuse, rather than later when the TLC settles.

Two rules keep the sign-once registry trustworthy:

- **Corruption throws; it never reads as absence.** A record or an alias that fails to parse or fails its shape guard raises a
  `TypeError` naming the key. Reading it as "no record" would re-register the channel with empty sign-once slots, and a slot
  that reopens turns a legitimate refusal into a second signature over the same nonce. An alias resolving to an index that
  holds no record throws for the same reason, rather than reading as a channel the device never knew.
- **The record carries a format version.** A future format change migrates old records rather than rejecting them, for the same
  reason: a rejected record is a lost registry. Unknown extra fields are tolerated on read; a version from the future is not.

## What growth this costs

Nothing here is ever deleted, so it is worth stating what that costs. An alias is about 90 bytes (a 20-character prefix, a
64-character channel id, and an index), and a channel has at most the two names fiber gives it, so every channel the device
ever opened costs under 200 bytes of names for good: a thousand channels is under 200 KB.

The registry inside the record is the half that grows without a bound, at about 85 bytes per slot ever served, in a value
re-serialized on every claim. A channel a thousand commitments deep therefore rewrites an 85 KB record on each signature, and
that write amplification, not the alias map, is the cost to watch on a device.

Neither is pruned, and the reason is the same for both: the device never learns from a source it trusts that a channel is
finished, since closure is node-supplied state, and deleting on it would hand the node a way to clear the names and slots that
refuse it. Pruning the registry is additionally bounded by what would still be safe without it, the monotonic counter, and it
would cost the idempotent replay of an old request ([policy.md](./policy.md)).

## Concurrency

`SignerStore` serializes every operation per storage key. Operations on one key run in call order, one at a time, and each
`updateChannelRecord` holds its key for the whole read-modify-write, which is the record's key and therefore the channel
index: two names of one channel share the lane. Different keys never wait on each other, so a slow channel does not stall
the rest.

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
[derivation.md](./derivation.md)). What does not come back is the record: counters, the sign-once registry and the exposure
snapshot all start empty. Losing the storage is therefore not losing funds, with one exception: hold-invoice preimages exist
only on the device, so unclaimed held payments need the storage intact. They are refundable to the payer otherwise.

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
