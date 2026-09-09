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

The SDK takes a **second storage** for the little that a reinstall must not erase, and its keys never appear in the first one:

| Key                                | Value                                                         |
| ---------------------------------- | ------------------------------------------------------------- |
| `fiber-lsp-sdk:watermark:<index>`  | The channel's anti-rollback watermark, JSON                   |
| `fiber-lsp-sdk:next-channel-index` | The next index the allocator hands out, an integer in base 10 |

The counter is written to **both** storages and read as the higher of the two, because either one alone can be lost. The
second storage is optional, and [what a reinstall keeps](#what-a-reinstall-keeps) is what a device without one gives up.

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

One record per channel, holding what the policy checks and recovery need. Everything else about a channel lives on the node,
which stays the durable store for channel state.

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

A watermark is about 400 bytes and does not grow with the channel: it holds one slot per context, whatever the depth.

Neither of the first two is pruned, and the reason is the same for both: the device never learns from a source it trusts that a channel is
finished, since closure is node-supplied state, and deleting on it would hand the node a way to clear the names and slots that
refuse it. Pruning the registry is additionally bounded by what would still be safe without it, the monotonic counter, and it
would cost the idempotent replay of an old request ([policy.md](./policy.md)).

## What a reinstall keeps

The sign-once registry is what makes deterministic nonces safe, and it is the one thing the node cannot hand back: counters
re-seeded from a number the node states are counters an under-reporting node moves backwards, and a slot served twice under
two sessions of its choosing recovers the funding key ([policy.md](./policy.md)). So the device keeps its own floor in a
storage the host places where an uninstall does not reach: an iOS keychain item survives one, Android needs an explicit
backup. The SDK does not choose the place, it takes the storage.

The watermark is the record minus everything a restore can rebuild from elsewhere:

| Dropped                                         | Where it comes back from                                                        |
| ----------------------------------------------- | ------------------------------------------------------------------------------- |
| The channel name                                | The node's channel list, matched to the index by public key                     |
| The debit intents                               | Nowhere: they are user authorisations, and they die with the app that took them |
| The registry below the top slot of each context | Nowhere: the counter refuses every number at or below it anyway                 |

The top slot of each context is kept because it is the one a reconnect re-delivers, and answering that re-delivery
`already-signed` is what keeps a restored device from stalling the channel at its first request.

The watermark is written **before** the record it projects from, so a crash between the two writes can only leave the floor
ahead of the claim, never behind it. A write whose projection matches the one this run of the app already wrote is skipped, so
recording a debit intent costs the slow store one write per run at most, while a claim that moves a counter always costs one.

A recovery storage that throws takes the record write down with it, and with it the signature: the device refuses rather than
claim a slot whose floor it could not persist. That is a real case on a phone, where a keychain item readable only while the
device is unlocked is unreadable to a signer answering in the background, so the host has to place the watermark where the
signer can reach it whenever it can be asked to sign.

Without the second storage a restore still works, and every channel it rebuilds is reported `unguarded`: the device is then
trusting the node's commitment numbers, and its first request may reopen a slot it already served.

## The channel index allocator

The index is the one piece of a channel that recovery cannot take from the node, since every secret derives from it, so the
SDK owns the counter that hands indexes out. It reads the higher of the two storages, spends an index before returning it,
and steps over any index that still holds a record or a watermark.

None of that is enough on its own: after a wipe the counter reads `0`, and an index handed out twice signs two channels
under one nonce space. So the allocator refuses to hand out anything until the session has reconciled with the node's
channels, and it refuses again in the next run of the app, since the flag is in memory and the counter alone cannot prove
what it survived.

The gate is only as strong as the list it reconciles against. With the second storage the mirrored counter survives the wipe,
so the allocator resumes past every index it ever handed out even when the node's list is short. Without it, a wiped device
has nothing to check the node's answer against: reconciliation restores exactly the channels the node reports, and a channel
the node omits, pruned or withheld, leaves its index looking free. Handing that index out again is the nonce reuse above, so
a host that skips the second storage is trusting the node's completeness, not just its commitment numbers.

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
[derivation.md](./derivation.md)). Losing the storage is therefore not losing funds, with one exception: hold-invoice
preimages exist only on the device, so unclaimed held payments need the storage intact. They are refundable to the payer
otherwise.

What no re-derivation gives back is **which index each of the node's channels belongs to**. `ISignerStorage` is `get` and
`set` with no enumeration, so that mapping cannot come from the storage, and until it exists every channel reads as
unregistered, which is the safe side to fail on: the device refuses everything rather than signing under an empty registry.

`ChannelRecovery.reconcile` is what rebuilds it, and it is what a session runs before anything else. It takes the node's
channels, closed ones included, and a function from channel index to funding public key, and it matches a channel to an
index by **that key**: the device compares the node's answer against its own derivation, so no name and no index the node
states is ever taken on trust, and recovery only ever sees public keys. Then, per matched channel:

| What it finds          | What it does                                                  | Reported    |
| ---------------------- | ------------------------------------------------------------- | ----------- |
| A record               | Leaves it exactly as it is, and adds the name as an alias     | `known`     |
| No record, a watermark | Rebuilds the record from the watermark                        | `restored`  |
| Neither                | Rebuilds it from the exposure the node reports, with no floor | `unguarded` |

A channel no index owns is reported apart and stays unregistered. The scan runs a gap of twenty indexes past the counter and
past every match, which is enough because indexes are handed out in sequence: a gap is an index whose channel the node never
came to know. Finally the counter is raised above the highest index matched, and the allocator is allowed to run.

Reconciliation is idempotent, so a device that never lost anything runs it on every connect and changes nothing.

### What a restored device still refuses

The record that comes back from a watermark is thinner than the one that was lost, and the difference is what the counter
has to cover:

- A repeat of the top slot's exact session is answered `already-signed`, and the deterministic nonce re-signs it to the same
  bytes it signed before the reinstall.
- Any other session on that slot refuses with `policy_refusal`, as it would have before.
- A slot at or below the counter refuses with `stale_state`, even though the pruned registry no longer names it. That is the
  counter standing in for the slots the watermark dropped.
- Above the counter everything is fresh, which is correct: those slots were never served.

Without a watermark none of that holds. The channel comes back `unguarded` with no counters at all, and the first request the
node sends is served whatever it asks for.
