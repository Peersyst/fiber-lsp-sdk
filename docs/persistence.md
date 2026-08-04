# Persistence

What the device persists, and the guarantees `SignerStore` gives the policy engine on top of the host's storage.

## Keyspace

The host injects an `ISignerStorage` (or its async form): a string-keyed, string-valued store the SDK never introspects. All
keys carry the `fiber-lsp-sdk:` namespace, because the host may back that storage with a store it also uses for its own keys.

| Key                             | Value                                                    |
| ------------------------------- | -------------------------------------------------------- |
| `fiber-lsp-sdk:channel:<id>`    | The channel's policy record, JSON                        |
| `fiber-lsp-sdk:preimage:<hash>` | The device-held preimage of a hold invoice, 32 bytes hex |

The two prefixes are fixed and disjoint, so a channel id and a payment hash can be the same string without colliding.

## The channel record

One record per channel, holding what the policy checks and recovery need. Everything else about a channel lives on the node,
which stays the durable store for channel state.

| Field                         | What it holds                                                             |
| ----------------------------- | ------------------------------------------------------------------------- |
| `version`                     | Format version of the record itself                                       |
| `channelIndex`                | The index the channel seed derives from                                   |
| `lastSignedCommitmentNumbers` | Last commitment number signed per context, strictly increasing            |
| `signedDigests`               | Sign-once registry: the digest signed in each `<context>:<number>` slot   |
| `lastStateVersion`            | Last state version seen from the node, non-decreasing                     |
| `localBalanceShannons`        | Local balance after the last signed commitment, decimal shannons          |
| `pendingDebitsShannons`       | User-initiated debits not yet consumed by a balance-decreasing commitment |

Two rules keep the sign-once registry trustworthy:

- **Corruption throws; it never reads as absence.** A record that fails to parse or fails the shape guard raises a `TypeError`
  naming the key. Reading it as "no record" would re-register the channel with empty sign-once slots, and a slot that reopens
  turns a legitimate refusal into a second signature over the same nonce.
- **The record carries a format version.** A future format change migrates old records rather than rejecting them, for the same
  reason: a rejected record is a lost registry. Unknown extra fields are tolerated on read; a version from the future is not.

## Concurrency

`SignerStore` serializes every operation per storage key. Operations on one key run in call order, one at a time, and each
`updateChannelRecord` holds its key for the whole read-modify-write. Different keys never wait on each other, so a slow channel
does not stall the rest.

This is what makes the sign-once registry hold under concurrent sign requests. Without it, two requests for the same slot both
read the record before either writes, and the second write drops the first one's claim on the slot: exactly the double signature
the registry exists to prevent. The policy engine must therefore do its read-decide-write inside `updateChannelRecord`, never as
a separate `getChannelRecord` plus `setChannelRecord`. The updater is synchronous by design: it runs while the key is held, so
it decides and returns, and anything slower belongs outside the critical section.

Refusals throw out of the updater before the write, which leaves the stored record untouched and the key immediately usable by
the next operation.

**The guarantee is per `SignerStore` instance.** Two stores over the same underlying storage (a second tab, a second process, a
second SDK instance) can still lose an update to each other, because `ISignerStorage` has no compare-and-swap to build on. A
host must give the SDK a single instance, or keep its storage private to one.

## Recovery

From the mnemonic alone the host re-derives the master seed, and the SDK re-derives every channel key (see
[derivation.md](./derivation.md)). Counters and balances re-seed from the node's state on the next session, under the
monotonicity check. Losing the storage is therefore not losing funds, with one exception: hold-invoice preimages exist only on
the device, so unclaimed held payments need the storage intact. They are refundable to the payer otherwise.
