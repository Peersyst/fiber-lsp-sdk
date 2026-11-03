# Signing

The entry of a signing request and the musig2 (BIP-327) engine behind it: what the device checks before it claims a slot,
the order fiber aggregates the keys in, how the device computes the message itself, why its nonces are deterministic and
how many sessions one of them can answer, the public material it hands the node, and the two signatures outside musig2:
the tenant identity the device registers with, and the watchtower's spends of a force-closed commitment. For how the
statuses are read see [protocol.md](./protocol.md); for the gate a request passes, and the rules a watchtower spend
passes, see [policy.md](./policy.md); for the four constructions the messages are rebuilt with see
[digest.md](./digest.md); for the keys see [derivation.md](./derivation.md).

## The entry: `SignerDispatch.handle`

`handle(channelId, status)` takes the `status` member of `get_channel_signing_status`, as the rpc client hands it over,
and answers it in twelve steps. Up to the eighth, everything refuses before anything is claimed: a refused request leaves
the store as it was, byte for byte, and costs no write. The order is fiber's own device SDK's
(`fiber-lsp-sdk/src/lifecycle.rs:105-207`, `validate_session`) followed by the gate.

| #   | Step                                                                                         | Refused as                                         |
| --- | -------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| 1   | Decode the status, each transition held to what it must carry ([protocol.md](./protocol.md)) | `malformed`, with no request id to name            |
| 2   | Resolve the channel's name to its index, and derive its keys                                 | `unknown_channel`                                  |
| 3   | Refuse `SignChannelAnnouncement`                                                             | `policy_refusal`                                   |
| 4   | The key order fiber gives the transition, holding the device's funding key                   | `malformed`                                        |
| 5   | The aggregated nonce is the device's nonce for the slot plus the peer's                      | `malformed`                                        |
| 6   | The message, computed from the plaintext the request carries                                 | `malformed`                                        |
| 7   | The peer's partial signature, on the two `CompleteReceived*` transitions                     | `malformed`                                        |
| 8   | The operation's input, from the content, the snapshot, `readChannelPins` and the network     | `malformed`; `policy_refusal` for an unpinned term |
| 9   | `PolicyEngine.checkAndClaim`: the digest, sign-once and reuse, lanes, views, pins, balance   | the gate's codes ([policy.md](./policy.md))        |
| 10  | `partialSign` at the slot the verdict names, which must be the request's                     | a fault otherwise                                  |
| 11  | On `CompleteReceivedRevokeAndAck`, the complete revocation signature kept as evidence        |                                                    |
| 12  | `next_material` for the slot's number plus one, on the four commitment and revocation steps  |                                                    |

Step 3 comes once the channel resolves: every channel this device opens is a tenant channel, private by construction
(`open_tenant_channel` requires `public: false`), so an announcement is never signed. Its construction stays in `digest`
for the vectors that pin it, and the engine still signs one, which the interop loop uses.

At step 9 the gate also holds a revocation to its replacement: the last commitment signed in the revoked one's view must be
the one at the slot's number, as fiber's device SDK requires (`fiber-lsp-sdk/src/commitment.rs:671-689`), or the request
is `stale_state`. Fiber's SDK further wants the replacement of a sent revocation to hold a complete signature; the device
keeps none, and why that suffices is in [policy.md](./policy.md).

Nothing on this path throws. A status is answered with one of four outcomes:

- **idle**, for `NoSignatureRequired`, before the channel is even looked up;
- **signed**, with the request id and transition, the slot, the number the message carries and its view (below), the
  32-byte partial signature, the next material or `null`, the verdict (`fresh`, `already-signed` or `reused`), the
  warnings (a `reused` verdict carries `{ kind: "nonce-reused", slot }`) and the deadline (below);
- **refused**, with the request id and transition once the status decoded, the deadline, and one of the four codes with
  its message: a `ProtocolError` of the decoder, a `PolicyRefusalError` of the gate or of the dispatch's own steps, and
  the type and range errors the digest and the input builders throw over what the node sent, which are `malformed`;
- **fault**, carrying the cause: the storage throwing, a record or an alias the store refuses to read, a name resolving
  to an index with no record, a value whose reading throws for a reason no codec names, a bug. None of those is the
  node's, and answering one as a refusal would make the node treat a device fault as a security event; a fault after the
  claim leaves the slot claimed with its nonce unexposed, and the next delivery answers it.

The number and the view a signed outcome reports: a commitment's version and its view (`remote` for
`SendCommitmentSigned`, the peer's commitment; `local` for `CompleteReceivedCommitment`); for a revocation, the number it
revokes and the view of the commitment it revokes (`local` when sending, `remote` when receiving); `null` and `null` for a
close. Fiber's requests carry no state version: the request id correlates, and the lanes and the per-view versions of the
gate order ([policy.md](./policy.md)).

Channel keys are derived per request and never cached. The master seed, copied at construction so the host may discard
its own buffer, is the only secret the dispatch holds.

## The deadline

A channel whose request fiber is still waiting on, in `ChannelReady` or in `ShuttingDown` without
`WAITING_COMMITMENT_CONFIRMATION`, is force-closed once any unresolved TLC reaches its expiry less two thirds of the
commitment delay (`pending_tlc_signature_deadline` and `tlc_expiry_delay`, `fiber-lib/src/fiber/channel.rs:6532-6553`
and `:5894-5899`); nothing of it travels in the status. The dispatch computes it and reports it as `deadlineMs`, a
`bigint` of milliseconds since the epoch, on a signed outcome and on a refusal after decoding, and never acts on it:
every request is answered when it is seen. It is `null` unless the request carries a settlement with at least one TLC,
which only the two commitment transitions do, and the channel's delay is pinned; a refusal before decoding has none
either. The pins are read after the claim, so the first commitment, whose claim pins the delay, already reports it, and
a pin read that fails leaves the deadline `null` and the outcome as it was: a diagnostic never turns a signature or a
refusal into a fault. The delay is the pinned one, not the transaction's, since a refused request's content may state
another.

It is an upper bound. Fiber takes every TLC whose removal is not confirmed (`all_tlcs()`), the snapshot only the
commitment's, so fiber's deadline may come earlier, never later. On a refusal the expiries are the node's own statement,
which nothing checked (they are bound to the message only once the transaction is rebuilt), so there the bound holds only
as far as the node is honest. And `null` means the device cannot compute one, not that fiber has none: a revocation, the
close, or a fulfil's commitment, which no longer lists the TLC it removes, still falls under fiber's deadline while a
TLC's removal is unconfirmed.

The port (`src/signer/signing-deadline.ts`, `tlcExpiryDelay` and `pendingTlcSignatureDeadline`) follows fiber's
arithmetic to the bit. The delay is read as CKB's `EpochNumberWithFraction::from_full_value` reads it, the number in
bits 0 to 23, the index in 24 to 39 and the length in 40 to 55, a zero length rewritten to the fraction 0/1 by its
`normalize` (ckb-types 1.1.3, `core/extras.rs:468-489`). The sum `number + index / length` is multiplied by the epoch's
length and by 2 and divided by 3 in that order, in f64, and cast as Rust's `as u64` casts: truncated, NaN and below zero
to 0, from 2^64 up to `u64::MAX`. Each expiry less the result saturates at 0, and the earliest is the deadline. The
epoch's length, fiber's `MILLI_SECONDS_PER_EPOCH`, is set by the node's build, 4 hours in release and 2 seconds in debug
(`fiber-lib/src/fiber/config.rs:44-50`), so the device cannot deduce it: it comes in as the dispatch's
`millisecondsPerEpoch`, a positive integer up to `Number.MAX_SAFE_INTEGER`, from the facade's network
([sdk.md](./sdk.md)). Both functions are exported through the module's barrel: the facade builds the margin a held
payment's release must clear on `tlcExpiryDelay` ([sdk.md](./sdk.md), "The invoice step").

## Key orders

Key aggregation is order-sensitive (`KeyAgg([A, B]) ≠ KeyAgg([B, A])`), and the aggregate is what the funding cell or the
revoked lock is locked under: a signature under any other order is useless to the node and only burns a slot. The
dispatch holds the request's `key_agg_ctx` to the order fiber builds for the transition, and the engine then signs that
list as it stands, never sorting it itself.

| Transition                     | Order            | Fiber                                                                   |
| ------------------------------ | ---------------- | ----------------------------------------------------------------------- |
| `SendCommitmentSigned`         | ascending        | `order_things_for_musig2`, `fiber-lib/src/fiber/channel.rs:11028-11041` |
| `CompleteReceivedCommitment`   | ascending        | the same                                                                |
| `SendClosingSigned`            | ascending        | the same                                                                |
| `SignChannelAnnouncement`      | ascending        | the same                                                                |
| `SendRevokeAndAck`             | `[peer, device]` | `get_musig2_agg_context(false)`, `:11119-11128`                         |
| `CompleteReceivedRevokeAndAck` | `[device, peer]` | `get_musig2_agg_context(true)`                                          |

Ascending is fiber's `should_local_go_first_in_musig2`: the device first when its compressed key sorts first or equal,
compared byte by byte, prefix included. A list without the device's funding key is refused before its order is read. The
peer's key is the other one; the gate holds it to the one the channel pinned.

## The aggregated nonce and the peer's half

The node sends the aggregated nonce and, beside it, the peer's own public nonce. The device sums its nonce for the slot
with the peer's (BIP-327 `NonceAgg`) and requires the result to be the aggregate: a session over any other aggregate is
one the node can use against the deterministic nonce (below) and never to complete a signature.

On `CompleteReceivedCommitment` and `CompleteReceivedRevokeAndAck` the request also carries the peer's partial signature,
exactly there (fiber's `external_signing_peer_evidence`, `channel.rs:11054-11079`). The dispatch verifies it with
`Session.partialSigVerify`, under the key list, the aggregate and the message it computed, the two nonces placed by the
position of their keys. The node verified it already; the device verifies so that it never completes a signature the peer
did not produce, and so that the evidence it keeps (below) is a signature the revoked lock accepts. A type or range error
the verification throws is `malformed` like a half that does not verify: whatever it read is what the node sent.

## The message and the operation's input

The request carries the plaintext, never a digest to trust: the device computes the message itself, fiber's
`signing_message` (`computeTxMessage` for the commitment and the close, `blake2b(output || output_data || args)` for the
revocation, [digest.md](./digest.md)). Then it builds the operation the gate rebuilds the digest from and compares
against that message.

| Input                                   | Commitment                                              | Revocation                                      | Close               |
| --------------------------------------- | ------------------------------------------------------- | ----------------------------------------------- | ------------------- |
| Funding out point                       | the tx's input                                          |                                                 | the tx's input      |
| Peer's funding key                      | the key aggregation                                     | the key aggregation                             | the key aggregation |
| Peer's TLC base key                     | the snapshot                                            |                                                 |                     |
| Version, delay, layout                  | the commitment cell's lock args                         | the revoked args; the layout the channel pinned |                     |
| Fee rate, peer reserve, liquid capacity | the host's terms                                        | the host's terms                                |                     |
| Device's reserve                        | the pins, under the layout                              | the pins, under the layout                      |                     |
| Commitment lock, cell deps              | the network                                             | the network                                     |                     |
| Amounts and TLCs                        | the snapshot, converted (`settlementToCommitmentInput`) |                                                 | the tx's outputs    |

Every source but the pins is something the request states; the gate holds each stated value to the one the channel
pinned. The pins are read with `PolicyEngine.readChannelPins`, a copy taken outside the balance lane: the claim holds the
input to the pins as they stand when it runs, so a value pinned in between that differs from the one read refuses the
request instead of being signed over ([policy.md](./policy.md)). The channel resolved at step 2, so the read answers no refusal of its own; a record gone
since is a fault. A commitment or a revocation on a channel whose terms the host has not pinned is `policy_refusal`,
naming the first missing term, and so is a revocation before any commitment has pinned the lock layout: the revoked
36-byte args carry none, though the fee is sized over the commitment mock that does. A close needs neither here; the
gate refuses one on a channel whose peer's close script the host has not pinned ([policy.md](./policy.md)).

The checks of this step, each `malformed`:

- **The commitment the device sends** carries, in its lock args (bytes 28..36, big-endian), the slot's own number:
  `SendCommitmentSigned` names the device's local number for both. The commitment it receives carries the remote number
  instead, which the gate keeps increasing per view.
- **A revocation revokes the number one below its slot**, the args fiber builds at the counter minus one
  (`channel.rs:7987`, `:10182`).
- **A revocation the device receives pays the device's close script**, the one pinned at registration; one it sends pays
  the peer's, which the device has no reason to fix.
- **No output carries a type script**: every channel of the device is a CKB channel.
- **The snapshot's device keys are the device's**: the converter refuses a local settlement key or a per-TLC key the
  device does not derive at the stated number ([digest.md](./digest.md)). The peer's settlement key, its TLC base key, is
  taken as stated and held by the gate's pin, which the facade's opening sets from the opening context it checked
  ([policy.md](./policy.md)).

## Deterministic nonces

Every signature consumes a musig2 secret nonce, and reusing one across two different challenges leaks the signing key.
The engine derives its nonces deterministically anyway: BIP-327 `NonceGen` seeded only through its `rand` input with the
slot's `nonceSeed(channel, commitmentNumber, context)` ([derivation.md](./derivation.md)), with the aggregate key, the
message and the extra input left out of the hash. That buys two properties:

- **The public nonce exists before the message does**, so the device publishes it in the material below, ahead of the
  transaction it will sign.
- **Re-delivery is idempotent.** A request delivered again regenerates the identical nonce and answers the byte-identical
  partial signature, so a crash between signing and submitting costs nothing.

Determinism is only safe under the sign-once rule, and that rule counts **sessions**, not messages: the ordered key list,
the aggregated nonce and the message, a repeat answered only when all three match ([policy.md](./policy.md)). The engine
itself checks no policy and stores nothing, so on its own it would sign a slot for whatever it is handed; the dispatch is
the one call site where the gate and the engine are one path, and it signs exactly the slot the verdict names. That slot
must be the request's own, the one the aggregated nonce was checked at in step 5: a verdict for any other is the device's
own bug, answered as a fault with nothing signed.

### Two sessions, and why not three

A BIP-327 partial signature is `s = σ·(k1 + b·k2) + e·a·g·d` over the slot's two secret nonces `k1`, `k2` and the funding
key `d`: `σ` is the sign the aggregate nonce point's parity gives the nonces, `g` the one the aggregate key's gives the
key, `a` the key's aggregation coefficient. Every coefficient is public: the node computes `b` and `e` from the
aggregate, the key and the message it sent. Under one deterministic nonce, each session on a slot is one more linear
equation in the same three unknowns.

- **One session** is one equation: safe, as for any musig2 signer.
- **Two sessions** are two equations in three unknowns. The two nonce columns are independent whenever the two `b`
  differ, so for every candidate `d` there are nonces that answer both: the key stays hidden.
- **Three sessions** solve the system, and the funding key falls out.

Fiber's lifecycle, as it stands, asks for more than one session per slot (both commitment transitions of an open land on
one slot, and so do the two sides of a revocation round). `PolicyEngine`'s `nonceReuse: "allow"` serves one second
session, logs it and answers it `reused`, which the dispatch reports as a `nonce-reused` warning on every delivery of it;
a third is refused in either mode ([policy.md](./policy.md)). `test/tests/signer/musig2-engine.spec.ts` proves the bound
rather than asserting it: it reads the three equations off three partial signatures of one slot, checks they hold at the
device's own nonces and key, shows that under two of them a wrong key has nonces answering both, and recovers the funding
key from the third by Cramer's rule.

## The revocation evidence

After `CompleteReceivedRevokeAndAck` the device holds both halves of the revocation of the peer's commitment at the
slot's number minus one. The dispatch aggregates them (`partialSigAgg`, a sum, so the order is immaterial), verifies the
64-byte BIP-340 signature under the x-only aggregate of the key list, which is the key the revoked lock commits, and
records it with `PolicyEngine.recordRevocation(channelId, { version, signature })` ([policy.md](./policy.md)). It does so
on every delivery, `fresh`, `already-signed` and `reused` alike, so a crash between the claim and the record heals on the
next delivery. An aggregate that does not verify cannot come of two halves that each did, so it is a fault, not a refusal.

## The public material

The node never asks for a point or a nonce; the device hands them over twice, and keeps no memory of what it published,
since all of it derives from the seed and the node checks each value against the one it holds at its slot.

- **At the open**, `prepareChannelOpen(channelIndex, fundedShannons, localCloseScript)` returns `buildChannelOpenMaterial`:
  the funding and TLC base public keys, the commitment points of numbers 1 and 2, and the nonces of `Commitment@0`,
  `Commitment@1` and `Revocation@2`, the slots fiber installs them at (`channel.rs:5975-6005`), with the announcement nonce
  always `null`, which fiber requires of a private channel. Beside it, what the channel is registered with once the node
  names it: the index, the funded amount and a copy of the close script, both checked first against what fiber opens with
  ([policy.md](./policy.md)). The facade's opening sends the material as `external_channel_signer` ([sdk.md](./sdk.md)).
- **With every signature** on the four commitment and revocation transitions, `buildNextMaterial(keys, slot + 1)`: the
  commitment point and the commitment and revocation nonces of the number after the slot, fiber's `next_material`
  (`fiber-lsp-sdk/src/signer.rs:363-385`). The decoder bounds the slot one below the derivation's top, so `slot + 1` is
  always derivable.

## The tenant identity

A tenant of the hosted LSP is one RootSigner, and the device's is `walletIdentityKey`
([derivation.md](./derivation.md)): the same on every device restored from the seed, so a restored wallet lands on the
same tenant. `TenantIdentity` holds it in a private field, out of every property, enumeration and serialization, and
gives out three things:

- **`publicKey`**, the 33-byte compressed key the LSP issues registry nonces to.
- **`tenantId`**, fiber's `TenantId::from_root_signer_pubkey`: the lowercase hex of
  `blake2b_hash_with_salt(publicKey, "fiber-hosted-lsp-tenant-id/v1")`, the salt hashed before the data.
- **`signRegistration(challenge)`**, which takes the result of `lsp_get_tenant_registry_nonce` as it comes and returns
  the params of `lsp_register_tenant`. It signs fiber's `TenantRegistryPayload`: the bytes
  `"fiber-hosted-lsp-tenant-registry/v1" ‖ lsp_node_id (33) ‖ root_signer_pubkey (33) ‖ nonce (32)`, their digest
  `blake2b_hash_with_salt(bytes, [])` (the plain CKB blake2b-256), and a compact ECDSA signature of 64 bytes over it.
  The signature is RFC 6979 with low S and no added entropy, which is what rust-secp256k1's `sign_ecdsa` produces, so it
  matches fiber's own signer to the byte; noble signs the digest as given only with `prehash: false`.

A nonce issued to another root signer is refused (`TypeError` naming `challenge.rootSignerPubkey`), as fiber's own
`begin_registration` refuses it: signing it serves no one and hides a fault of the LSP or the host. The LSP's node id
must be a point and the nonce 32 bytes. Which LSP the node id should be is the facade's to check against its options
([sdk.md](./sdk.md), "The tenant's registration").

The SDK signs and never calls: both registration methods need the operator's token ([rpc.md](./rpc.md)), which a phone
does not hold, so the host's backend (or an agent) asks for the nonce, has the device sign it, registers, and hands the
tenant's token back to the device.

The private field is ES2022 syntax the build emits as is; under React Native, Metro's Babel preset transpiles it, as it
does the bundle's other ES2022 syntax.

## The hold invoice preimages

`HoldInvoicePreimages` is the custodian of the preimages of the device's hold invoices, so that, as with the dispatch and
the identity, no part of the SDK outside `signer` keeps the master seed. It copies the seed at construction, checked to
be 32 bytes, into a private field, so the host may change or discard its own buffer, and gives out three things:

- **`preimage(k)`**, the preimage of the invoice of index `k`, `deriveHoldInvoicePreimage` ([derivation.md](./derivation.md)),
  derived on every call and handed out as a fresh copy.
- **`paymentHash(k)`**, its payment hash: the preimage under `hashAlgorithm`, CKB's blake2b-256, also a fresh copy.
- **`hashAlgorithm`**, `ckb-hash`, the algorithm `paymentHash` hashes with, which the facade states to the node and to the
  policy's record.

An index outside `[0, MAX_INVOICE_INDEX]` is the derivation's `RangeError`. The facade builds one at construction, and its
invoice creation and its invoice step are its only readers ([sdk.md](./sdk.md), "Receiving a payment").

## What the engine signs

The message is always an opaque 32-byte digest, handed to the session raw: BIP-327 applies its own tagged challenge hash,
so the engine never pre-hashes or tags. Wire sizes: 33-byte compressed public keys, 66-byte public and aggregated nonces,
32-byte messages and partial signatures, 64-byte complete signatures. The partial signature's size is checked on the way
out, since the dependency floats on a caret range and the size is a protocol commitment.

## The watchtower

After a force close, the device's funds sit in the commitment lock's cell, and the node's watchtower takes them out one
unlock per transaction: each TLC, then the device's balance, every spend but the last leaving the rest of the cell at its
output 0, the remainder the next spend starts from. Each spend waits on a signature of the device, read through a second
status, `get_watchtower_signing_status`, and handed back through `submit_watchtower_signature` ([rpc.md](./rpc.md),
[protocol.md](./protocol.md)). The request carries the unsigned transaction and the key it needs, its `key_purpose`:

| Purpose                     | Key                                                 | What it unlocks                                      |
| --------------------------- | --------------------------------------------------- | ---------------------------------------------------- |
| `Settlement`                | the TLC base key, `tlcBaseKey`                      | the device's balance, which settles to its hash      |
| `Tlc { commitment_number }` | `deriveTlcKey(keys, n)`, the TLC key at that number | a TLC whose entry carries that key's hash as its own |

### The signature

`signOnchain(keys, purpose, tx)` signs as fiber does (`sign_onchain_request`, `watchtower/signer.rs:95-147`, and the
on-chain arm of its device SDK's `sign_content`, `fiber-lsp-sdk/src/signer.rs:1237-1252`): recoverable ECDSA over
`computeTxMessage(tx)`, the message of every transaction fiber signs ([digest.md](./digest.md)), which leaves the
witnesses out, so the 65 zero bytes the unlock holds in their place never reach it. It is RFC 6979 with low S and no
added entropy over the message as given (`prehash: false`), which is rust-secp256k1's `sign_ecdsa_recoverable`, so it
matches fiber's own signer to the byte. Noble writes the recovery id first; the device hands over the 65 bytes as fiber
serializes them, `r ‖ s ‖ recid`. Fiber's `submit_watchtower_signature` checks the length, reads the recovery id, and
requires the key it recovers over its own message to be the one the purpose names (`verify_onchain_signature`).

Signing again is not the hazard here that it is for musig2: RFC 6979 derives each nonce from the key and the message,
so two messages never share one, and no number of signatures under one key leaks it. That is why the watchtower keeps no sign-once registry: a spend fiber rebuilds for an unlock already signed is
signed again, and a spend the chain refuses costs nothing.

### The entry: `SignerDispatch.handleWatchtower`

`handleWatchtower(channelId, status)` takes the `status` member of `get_watchtower_signing_status` and, like `handle`,
answers it without throwing. Its steps: the decoder ([protocol.md](./protocol.md)); a non-empty channel id; the channel
resolved to its index and its keys derived; `PolicyEngine.checkWatchtowerSpend`, which runs the watchtower rules and claims
the spend ([policy.md](./policy.md)); `signOnchain`; and the signature recorded on the claim before it leaves the
dispatch, so a write that fails leaves a fault that hands nothing over. The outcomes:

- **idle**, for `NoSignatureRequired`, before the channel is looked up;
- **signed**, with the request id, the purpose, the 65-byte signature and `claimed`. `claimed` is false when the record
  already holds another signed spend of the same unlock, which leaves this one unclaimed ([policy.md](./policy.md)): it
  is signed and handed over, nothing is written, and there is no claim to mark applied once fiber takes it;
- **refused**, with the request id and the purpose once the status decoded, `null` and `null` before, and the code with
  its message: `malformed` from the decoder, an empty channel id or a spend the policy reads as malformed,
  `unknown_channel`, and the rules' `policy_refusal`;
- **fault**, carrying the cause: the storage throwing, a corrupt record, a value whose reading throws for a reason no
  codec names, a bug. As for `handle`, none of those is the node's.

A request delivered again is answered with the signature recorded for it, signing and writing nothing; every rule still
runs on it first, against the record and the approval as they stand. A claim whose signature was never recorded, a crash
between the claim and the record, is signed again, to the same bytes, and recorded then.

### The destination, and the trust it takes

Fiber's watchtower pays every spend to the secp256k1 lock of the node it runs on, and takes the fee from that node's own
cells (`watchtower/actor.rs:1303-1306`, `:1808-1826`); `create_watch_channel` has no member for another destination.
Fiber's own device SDK plans the same answer the SDK gives: the wallet approves a destination and a fee bound, and signs
only spends that pay them (`fiber-lsp-sdk/src/onchain.rs:45-59`). The facade takes them as its `watchtower` option
([sdk.md](./sdk.md)), and the policy holds every spend to them. Without the option every request is refused as
`policy_refusal`, and the funds stay in the commitment lock's cell, where they would be with no watchtower at all.

The only destination fiber's watchtower produces today is the LSP node's lock. Approving it is trusting the LSP after a
force close: the funds the commitment lock releases to the device are paid to the LSP's wallet, and reach the user only if
the LSP pays them on. A destination the user chooses, which `create_watch_channel` would take, closes that gap; it is a
proposal to Fiber, and neither side implements it.

### What the chain enforces, and the device does not check

The commitment lock holds a spend to more than the device checks: the commitment cell to its delay through the input's
`since`, a TLC to its expiry or its preimage, and the settlement body to the hash the cell's args commit, besides the
remainder, which the device checks too. The device checks none of the clock's part (whether a delay has matured, a TLC
has expired) and not a preimage's hash: a spend that fails one of them is refused by the chain, and its signature costs
nothing (above). Nor does
it check the hash of the transaction input 0 spends: the peer broadcasts its commitment with the cell deps it picks, which
no signature covers, so the device names the source by its content instead ([policy.md](./policy.md)).

UDT channels, which the device does not open, and the punishment of a revoked commitment, which fiber's watchtower spends
with the revocation signed in its musig2 round (`watchtower/actor.rs:331-394`), never reach this path.

## The interop loops

Two loops verify the signer against fiber's exact stack, each with a jest half and a Rust half
([`interop/`](../interop/README.md)):

- **The signing requests**: `test/tests/signer/interop-vectors.spec.ts` answers every request of `signing.json`, each on
  a channel at the state before it, through the dispatch, the announcement through the engine, and requires fiber's
  expected public nonce and partial signature to the byte. It also signs every watchtower spend of the file's
  `watchtower` section, decoded by the protocol's decoder and signed with `signOnchain` under the purpose fiber names.
  Under `INTEROP_SIGNING_OUT` it writes both for `verify-signing`, which verifies each partial signature under fiber's
  `musig2` crate and aggregates it with the peer's half, and requires each on-chain signature to recover the spend's
  expected key over fiber's message, as `submit_watchtower_signature` checks it.
- **The canonical slot**: the same spec signs the musig vector at (0, `COMMITMENT`) and, under `INTEROP_TS_OUT`, writes
  it for `verify-ts`.

`test/tests/signer/musig2-engine.spec.ts` also pins the public nonce and the partial signature of a literal request.
Those pins, like the vectors, are the idempotent re-delivery contract, not snapshots: a dependency bump that changed
`NonceGen`'s output would break every in-flight signing round. A failing pin is investigated, never repinned.

## The node double and the flows

`InMemoryTenantNode` (`test/utils/tenant-node.ts`) is the node end of the tenant RPC. It answers the injected `fetch`
for the thirteen methods the facade calls, `open_tenant_channel` and `submit_signed_funding_tx` (below), `list_channels`,
`get_channel_signing_status`, `submit_channel_signature`, `get_watchtower_signing_status`,
`submit_watchtower_signature`, `new_invoice`, `get_invoice`, `settle_invoice`, `send_payment`, `get_payment` and
`shutdown_channel`, in fiber's shapes, and holds what fiber holds: the
counters L and R (`CommitmentNumbers`, both 0 before the open), the sites that issue a request off them, the points and
nonces the device published, and the peer's musig2 half. It issues one request at a time and queues the movements that
arrive while one is pending, as fiber buffers them. A submission first meets the conversions of fiber's RPC layer, ahead
of the channel lookup (`rpc/channel.rs:840-847`): the partial signature as a scalar and the next nonces as musig2
nonces. Then fiber's checks (`channel.rs:2208-2285`): `replay_or_pending`, which answers the exact receipt again
`AlreadyApplied`; the partial signature, verified against the nonce the device published for the slot; and
`next_material`, required on the four advancing transitions and installed at the slot's number plus one
(`channel.rs:6009-6139`). The content it sends is built with digest's own builders ([digest.md](./digest.md)), from
device keys the test derives from the seed: a shortcut, since a real node holds only the public parts, with the same
result. The double takes the keys of each channel index a test may open under, and a channel is built with the ones
whose funding key its open's material carries. The channel opens through the RPC or through a method of the double, and
moves through the RPC the facade calls (`send_payment`, `shutdown_channel`) or through methods of the double (send,
receive, fulfil, a shutdown, the peer's shutdown, a force close). Beside them, it can tamper with its next request, go
past one as if the device had answered it, keep a
submission in the network until the next one, or drop the answer to a method's next call after handling it. Its
opening and its watchtower halves are below; its invoice half is with the flows that drive it ([sdk.md](./sdk.md)).

The flows, `test/tests/sdk/signing-step.flow.spec.ts`, run the poller's signing step over the double with the real
dispatch, policy and rpc client and a mock timer, on the harness both flow specs share (`test/utils/tenant-flow.ts`: the
device wired with one step or both, as the facade wires them, the open, the ticks and the calls the node received).
Under `nonceReuse: "allow"` the sequences run as below, each request named by its transition and fiber's nonce slot, and
answered `signed`, or `warning` as a second session on its slot:

- **The open**: `CompleteReceivedCommitment` and `SendCommitmentSigned`, both at `Commitment@1`: the first of the two
  is signed and the second is a warning. Fiber may issue them in either order, and the flows run both; fiber's devnet
  issues `SendCommitmentSigned` first. Under `refuse` the second is refused as `policy_refusal`, on every tick.
- **A payment received**, the peer's round: `CompleteReceivedCommitment` at `Commitment@2` signed, `SendRevokeAndAck` at
  `Revocation@2` signed, `SendCommitmentSigned` at `Commitment@2` warning, `CompleteReceivedRevokeAndAck` at
  `Revocation@2` warning. Then the tenant's round to fulfil it: `SendCommitmentSigned` at `Commitment@3` signed,
  `CompleteReceivedRevokeAndAck` at `Revocation@3` signed, `CompleteReceivedCommitment` at `Commitment@4` (version 3)
  signed, `SendRevokeAndAck` at `Revocation@3` warning. It ends at L = 4 and R = 4, with the revocation evidence of
  versions 1 and 2.
- **A payment sent**, the tenant's round: `SendCommitmentSigned` at `Commitment@2` signed, `CompleteReceivedRevokeAndAck`
  at `Revocation@2` signed, `CompleteReceivedCommitment` at `Commitment@3` (version 2) signed, `SendRevokeAndAck` at
  `Revocation@2` warning. Then the peer's round to fulfil it: `CompleteReceivedCommitment` at `Commitment@3` warning,
  `SendRevokeAndAck` at `Revocation@3` signed, and `SendCommitmentSigned` at `Commitment@3` refused as `policy_refusal`,
  a third session on one slot, on every tick, with nothing written.
- **The cooperative close**: `SendClosingSigned` at `Commitment@L`, with no `next_material`. After the open it signs
  `Commitment@2`; after a full payment received it lands on `Commitment@4`, which the device's own last commitment
  (`CompleteReceivedCommitment`, version 3) already took, so it is a second session, served with a warning under
  `allow`.

What the sequences show:

- **Revocation slots are shared too.** The slot key names no lane ([policy.md](./policy.md)), so `Revocation@n` serves
  both `SendRevokeAndAck` and `CompleteReceivedRevokeAndAck` under one nonce, and the second of them is a second session.
- **A commitment's version is not always its slot.** For `SendCommitmentSigned` the two are equal; for
  `CompleteReceivedCommitment` the version is R, one below its slot when it follows a `CompleteReceivedRevokeAndAck` in
  the tenant's own round (`Commitment@3` carries version 2 in the send flow) and equal to it otherwise.
- **After any round the tenant starts, the peer's next round stalls**, even under `allow`, under fiber's current nonce
  lifecycle. The tenant's round leaves its `CompleteReceivedCommitment` on `Commitment@L` once its
  `CompleteReceivedRevokeAndAck` moved L, and the peer's next round asks for its two commitments on that slot: a third
  session. So the fulfil of a payment sent stalls, and so does a second payment received, after the first's fulfil:
  `CompleteReceivedCommitment` at `Commitment@4` warning, `SendRevokeAndAck` at `Revocation@4` signed,
  `SendCommitmentSigned` at `Commitment@4` refused as `policy_refusal`. The cap stays: three signatures under one
  deterministic nonce solve for the funding key (above).

### Past the stall, under a test-only bypass

To exercise what comes after the stall, four flows run past it: the payment sent completed and then a close, the second
payment received completed, and a third payment sent after it. Before each third session the double calls
`forgetSecondSession` (`test/utils/nonce-cap-bypass.ts`), which drops the slot's entry from the stored record's
`nonceReuse` log so the policy serves the third as a second session. With the cap out of the way every later step is
signed or warned: the peer's view rule, the replacement rule, the lanes and the balance rule accept each round, so the
third session on `Commitment@L` is the only obstacle in fiber's current lifecycle. The bypass lives in `test/` alone and
never in `src/`, where the cap stays: three signatures under one nonce solve for the funding key. **It goes when Fiber's
nonces are strict, before the release**: the helper is deleted and the double moves to Fiber's new nonce lifecycle, so
the flows run the real sequence end to end with the cap in force.

Three more flows cover the host's effects. With the app closed, the requests wait on the node, and once the poller
starts they are served in order. After a crash between signing and submitting, the restarted device signs the same bytes
again with no write; the node answers `AlreadyApplied` only when the first submission lands after the restarted device
read the status, since otherwise the status already names the next request. When the write of a revocation's evidence
fails, the outcome is a fault and nothing is submitted; the node asks for the same revocation again, the device signs it
and keeps the evidence, and the peer's next commitment is signed after it.

The opening's sequence is asserted by fiber's own test (`fiber-lib/src/fiber/tests/external_signer_restart.rs:685-740`).
The payments' are derived from fiber's counter rules, since no fiber test fixes them: R moves by one when the device's
`revoke_and_ack` is sent (`channel.rs:6313`), L when the peer's is received (`channel.rs:6462`), and a `commitment_signed`
moves neither, which is where the shared slots come from. Fiber's devnet runs them in this order, with these outcomes
([e2e-agent.md](./e2e-agent.md), "Scenarios"): a payment received and its fulfil, and a payment sent up to the third session
refused on its fulfil.

The controls each end refused, on two ticks, with no submission and the record unchanged:

| Control                                                                         | Refused as                              |
| ------------------------------------------------------------------------------- | --------------------------------------- |
| An aggregated nonce that is not the device's at the slot                        | `malformed`                             |
| The peer's partial signature over another message than the content's            | `malformed`                             |
| A settlement amount moved by one shannon                                        | `malformed`: the message does not match |
| An offered TLC under a twin hash, the same 20 bytes as the debit intent's       | `policy_refusal`                        |
| The delay epoch moved from its pin                                              | `policy_refusal`                        |
| A close paying the device's side to another script                              | `policy_refusal`                        |
| A skipped `CompleteReceivedRevokeAndAck` before the next `SendCommitmentSigned` | `stale_state`: the peer's view rule     |
| A node that moves past a revocation whose evidence write failed                 | `stale_state`: the evidence is missing  |

The double also reproduces fiber's own refusals of a submission, with fiber's messages, each leaving the request pending: a
partial signature that does not verify or is no scalar, a next nonce of another length, another request id, an unknown
channel, no next material on an advancing transition or a member of it missing, one nonce for both purposes, a point or a
nonce that conflicts with the one already published, another signature for a request already applied, and a submission
while nothing is pending; and jsonrpsee's answers to a method the node does not serve and to params it cannot read.

### The watchtower over the double

`forceClose(view, options)` puts a commitment on chain, the view's last or one before it, with the funding lock's cell deps
fiber adds when it broadcasts, and the double turns into fiber's watchtower for it. `test/utils/tenant-watchtower.ts` ports
its `build_settlement_tx` (`watchtower/actor.rs:1308-1840`): the unlock it picks on a cell, by the chain's median time and
the preimages it holds; the spend it builds, the remainder at output 0 unless no party is left and the node's output paid
what the unlock releases and its own cell brings, less the fee; the request id, the blake2b of the molecule transaction
(`watchtower/signer.rs:95`); and `verify_onchain_signature`. The double serves the lowest pending request id, as fiber's
`first_pending` does, and once it applies a signature the spend lands and the next one is built from its remainder. A
submission meets fiber's checks: the length, the recovery id, the key recovered over fiber's message, a pending request,
`AlreadyApplied` for the signature applied and a mismatch for another. Both methods answer "watched channel not found"
before the watch row exists, which fiber creates at `RemoteTxComplete` (`event_handler.rs:41-67`), and once a cooperative
close deletes it. Beside them, the peer can spend first, the median time can move on, the node can fund its spends from
another of its cells, which rebuilds the spend waiting under a new request id and leaves the old one pending, as fiber does
(`watchtower/actor.rs:2151-2155`), and a spend can be tampered with.

The flows, `test/tests/sdk/watchtower-step.flow.spec.ts`, run both steps as the facade polls them, under `allow` and the
vectors' approval, over a channel with a TLC each way in flight: an inbound one whose preimage the node holds and an
outbound one past its expiry. Each spend is named by its purpose, `Tlc@n` being the TLC key at number `n`:

- **The device's own commitment**: `Tlc@3` the outbound TLC by timeout, `Tlc@2` the inbound one by preimage, then
  `Settlement`, each applied and landed, each next spend built from the remainder.
- **The peer's commitment**: the inbound TLC, the outbound one, then the settlement; the same when the peer broadcast it
  with funding lock cell deps of its own, which changes its on-chain hash and nothing the device checks.
- **The clock and the preimages**: the inbound TLC claimed at once and the outbound one only once the node asks for it
  past its expiry; without the preimage, the inbound TLC never claimed and the balance settled once it expired.
- **The peer first**: the peer times the inbound TLC out and settles its own balance, and the device claims its outbound
  TLC from the peer's remainder, a cell it never signed, then settles as the last party, taking the whole cell with no
  remainder.
- **The remote commitment before the last**, which the peer may still broadcast, its spends signed under it; and a
  commitment with no TLC, settled in one spend.
- **The watch row**: an open channel fiber does not watch yet read as nothing pending, then its spend signed once
  watched; a channel closed cooperatively no longer polled.
- **The host's effects**: with no approval, every spend refused and the node still waiting for the first; after a lost
  answer, the same bytes again and `AlreadyApplied` taken as success; a spend fiber rebuilds for an unlock already signed,
  its fee moved to another cell, signed unclaimed, the record keeping the first, which fiber confirms after when the
  first's submission was lost and which stays unconfirmed when its mark was.

Each pins the calls, the spends the node served with its answers, the transactions that landed, the events and the
record's spends. The controls each end refused, on two ticks, with nothing signed or written and the node still waiting:

| Control                                                                  | Refused as                        |
| ------------------------------------------------------------------------ | --------------------------------- |
| A spend of the device's own commitment before its last, which it revoked | `policy_refusal`: the source      |
| A spend of the peer's commitment two before its last, which it revoked   | `policy_refusal`: the source      |
| A spend paying another lock than the approved destination                | `policy_refusal`: the destination |
| A remainder keeping less than the cell less what the unlock releases     | `policy_refusal`: the remainder   |
| A purpose naming the TLC key of another commitment number than the TLC's | `policy_refusal`: the key         |

The double reproduces fiber's refusals of a watchtower submission too, with fiber's messages, each leaving the request
pending: a recovery id above 3, an `r` at or above the curve order or zero, the other recovery id, which recovers another
key, another request id, another length than 65 bytes, a TLC key no commitment it watches holds, and a submission while
nothing is pending; and jsonrpsee's answers to params it cannot read. Its listing shows a force-closed channel only to a
call that asks for closed ones, and a cooperative close as `ShuttingDown` and then as `Closed` to that call alone.

### The opening over the double

`open_tenant_channel` meets fiber's checks of the params (`rpc/channel.rs:1110-1124`): the LSP's own key as the peer,
`public: false` and the signer material present. Then the tenant's single opening slot (`network.rs:3679-3790`): the
identical command, nonces included, answers the result it froze; another answers "tenant already has a different channel
opening", and the identical one once the channel is ready "tenant channel is already open". Absent, `null` and empty
`funding_lock_script_cell_deps` compare alike, as fiber's conversion reads them (`rpc/channel.rs:1130-1136`). The open
never parks: within the call the double freezes the funding tx, output 0 the funding cell under the testnet funding lock
over the two funding keys, then the tenant's change and the LSP's (`funding_tx.rs:552-600`), each input's witness the
65-zero-byte placeholder, and the user lock's cell deps after the tx's own, each once (`:714-726`); and the opening
context, the tenant's reserve sized over the open's shutdown script, the LSP's being the vectors'.

`submit_signed_funding_tx` answers a second submission "Repeated processing message: Signed funding tx has already been
submitted" and a tx whose raw part differs from the frozen one fiber's mismatch, the witnesses alone being free, then
resumes the open's commitments and shows the channel `ChannelReady` once both are signed. The listing is fiber's whole:
the four balances, the closed channels to a call that asks for them, and to an `only_pending` call the opening while it
opens and each failed one, made up as fiber makes it (`rpc/channel.rs:601-680`). Beside them, the next opening's answer
can be tampered with (the delay, either reserve, the channel id, output 0's lock), the peer can send its commitment
before the funding tx is signed, which leaves the channel `SigningCommitment` with `THEIR_COMMITMENT_SIGNED_SENT` as
fiber's does (`channel.rs:2525-2550`), and the opening can expire as fiber's external funding timeout fires
(`channel.rs:4374-4395`): `Closed` with `FUNDING_ABORTED`, its state deleted and listed among the pending ones alone. The
flows that run the facade's opening over it are [sdk.md](./sdk.md)'s.

## Where it lives

| File                                      | Contents                                                                                                                      |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `src/signer/signer-dispatch.ts`           | The twelve steps, the four outcomes, the deadline of two, and the opening; `handleWatchtower` and its four outcomes           |
| `src/signer/musig2-engine.ts`             | The public keys, points and nonces, the nonce sum, the partial signature, the peer's half verified, the aggregate             |
| `src/signer/signer-material.ts`           | The opening block and the next material                                                                                       |
| `src/signer/signing-deadline.ts`          | `tlcExpiryDelay` and `pendingTlcSignatureDeadline`: fiber's deadline for a pending request, its f64 arithmetic and casts      |
| `src/signer/hold-invoice-preimages.ts`    | `HoldInvoicePreimages`: the seed's copy, each invoice's preimage and payment hash, the algorithm                              |
| `src/signer/tenant-identity.ts`           | The RootSigner: its public key, the tenant id, the registry payload, its digest and the registration signature                |
| `src/signer/onchain-signature.ts`         | `signOnchain`: the watchtower's recoverable signature under the key its purpose names                                         |
| `src/signer/signer.constants.ts`          | The key order per transition, fiber's two tenant domains                                                                      |
| `src/signer/utils/key-order.utils.ts`     | The order of the two funding keys, and the peer's key read out of a request held to it                                        |
| `src/signer/utils/signing-terms.utils.ts` | The message from the plaintext, and the operation built from the content, the pins and the network                            |
| `src/signer/signer.types.ts`              | The options, the cosigned session, the prepared operation, the two outcomes and the pending open                              |
| `src/common/utils/musig.utils.ts`         | The musig2 shapes `policy` and `protocol` hold a session to as well: the nonce halves, an aggregate's half, two distinct keys |

## What the tests guarantee

`test/tests/signer/signer-dispatch.spec.ts` drives every transition of `signing.json` through the dispatch, each on a
channel of its own at the state before it (`test/utils/signing-channel.ts`), and requires fiber's partial signature and
next material to the byte, a half that verifies under the nonce the device published, the slot claimed, each
commitment's hash recorded in its view, and the complete revocation signature fiber expects kept as evidence. Every
refusal is driven at its step, with the store asserted unchanged and unwritten for every one before the claim: each
decoder refusal (the seven variants of `signing.json` among them) answered without a request id and ahead of the channel
lookup; an unknown channel for every transition, the announcement included; the announcement refused ahead of its key
order; each wrong key order (a sorted transition with the device first, the sent revocation with the device first, the
received one sorted) and a list without the device's key; an aggregate over another peer nonce or another slot's device
nonce; the peer's half absent, over another message, under another aggregate, or of a commitment the node changed after;
a foreign settlement key and a foreign TLC key; the sent commitment's version one above and one below its slot; each
revocation one above and one below the number it must revoke; a received revocation paying the peer's script; a type
script on a commitment cell and on either revocation; each of the three numeric terms unpinned on a commitment and a
revocation while a close, which states none of them, still signs; and the unpinned layout. Behind the claim, the gate's
refusals surface with their codes: a digest mismatch
per content kind (a snapshot amount, a re-signed commitment tx, a revocation output and its data, a close input's since),
a slot not above its lane, a conflicting peer key, an offered TLC no intent covers, and a close that pays too little. A
status delivered twice is answered with the same bytes and no write; the revocation evidence is rewritten after it was
lost, and a crash between the claim and the evidence heals on the next delivery. Each revocation of the vectors signs
with its replacement in place and leaves it there, and is refused as `stale_state` with no replacement, one below the
slot and one above. A verdict for another context or number than the request's slot is a fault that signs nothing, and a
type error out of the peer half's verification is `malformed`. A second session on a served slot is refused by default,
signed under `allow` with its warning and a valid half, and a third refused; both served sessions answer again with
their bytes, the reused one with its warning, and a received revocation reused after the sent one of its round keeps its
complete signature, byte for byte fiber's. The storage throwing, a corrupt record, a value whose reading throws and an
alias with no record are faults that claim nothing, and no refusal names a secret.

The flows over the node double (above) pin the sequences end to end: for each, the order of the RPC calls, the requests
the node served with its answers, the host's `SIGNING` events, the counters and the material published, and the final
record, its lanes, commitment hashes, reuse log, evidence and views.

`test/tests/signer/utils/` pins the key orders with keys of both sort orders, since with the vectors' keys the sent
revocation's role order coincides with the ascending one, and the input builder field by field. The engine's spec covers
the nonce sum, the peer's half (accepted at either position, refused over another message, order, nonce, aggregate or
scalar), the aggregate (accepted in either order, refused when it does not verify) and the three-session algebra above;
`signer-material.spec.ts` pins the material against fiber's expected `next_material`. Coverage of the module is 100% on
all four metrics, and the assertions were checked by breaking the code on purpose:

| Mutation                                                  | Tests that failed |
| --------------------------------------------------------- | ----------------- |
| The ascending sort is descending                          | 60                |
| The revoked number is held to the slot                    | 48                |
| The revocation's direction is inverted                    | 41                |
| The peer's signature is verified at the device's index    | 35                |
| The received revocation sorts its keys                    | 26                |
| A sent revocation must pay the device's script            | 25                |
| A malformed step is refused as `policy_refusal`           | 23                |
| The key order is not checked                              | 19                |
| The received commitment's version is held to its slot too | 16                |
| A decode refusal is a fault                               | 13                |
| The engine signs under a fixed context, not the verdict's | 12                |
| A reused verdict carries no warning                       | 11                |
| An unpinned term reads as zero                            | 10                |
| The next material swaps its nonces                        | 10                |
| The evidence is recorded at the slot's number             | 9                 |
| The aggregated nonce is not checked                       | 7                 |
| The commitment's view is inverted                         | 7                 |
| A fault is answered as `malformed`                        | 6                 |
| A typed output passes                                     | 6                 |
| The peer's signature is not verified                      | 6                 |
| The next material is at the slot's number                 | 4                 |
| The announcement is signed                                | 3                 |
| The opening carries an announcement nonce                 | 3                 |
| The revocation layout is read as `legacy` when unpinned   | 3                 |
| The sent commitment's version is not held to its slot     | 3                 |
| The sent revocation sorts its keys                        | 3                 |
| A received revocation may pay any script                  | 2                 |
| The evidence is recorded only on a fresh claim            | 2                 |
| The verdict's slot is not held to the request's           | 2                 |
| A reused revocation keeps no evidence                     | 1                 |
| A type error in the peer half's verification is a fault   | 1                 |
| The aggregate is not verified                             | 1                 |
| The close script is held by reference                     | 1                 |
| The dispatch takes no cell deps                           | 1                 |
| The opening is not checked                                | 1                 |
| The opening revocation nonce is at 1                      | 1                 |
| The seed is held by reference                             | 1                 |
| The verdict's context is not held to the request's        | 1                 |
| The verdict's number is not held to the request's         | 1                 |

`test/tests/signer/tenant-identity.spec.ts` pins the identity against fiber's `tenant_registry` vector (the key, the
tenant id, the payload, the digest and the signature to the byte) and against literal values of its own, refuses each
field of the challenge (a foreign root signer, the other parity of its x, each wrong length, an LSP node id that is not a
point, the absent ones), and checks that no property, enumeration or serialization reaches the secret:

| Mutation                                              | Tests that failed |
| ----------------------------------------------------- | ----------------- |
| The public key is handed out by reference             | 23                |
| The answer carries the identity's key by reference    | 18                |
| The payload omits the protocol prefix                 | 11                |
| The payload puts the root signer before the LSP       | 11                |
| The LSP's node id is not checked as a point           | 8                 |
| The digest is prehashed again before signing          | 8                 |
| The signature takes added entropy                     | 7                 |
| The signature may be high-S                           | 6                 |
| The nonce's length is not checked                     | 5                 |
| A challenge that is not an object reaches the fields  | 4                 |
| The tenant id is hashed without its salt              | 3                 |
| A nonce issued to another root signer is signed       | 2                 |
| The secret is a public property                       | 2                 |
| The answer carries the challenge's nonce by reference | 2                 |
| The nonce is copied with a Buffer's slice             | 1                 |

Reading the pins before the channel resolves fails no test, and cannot: the reader resolves the name itself, with the same
refusal, so the outcome is the same for every status.

`test/tests/signer/onchain-signature.spec.ts` signs every spend of the vectors' `watchtower` section to fiber's bytes and
recovers from each the key fiber expects; it signs the settlement under the TLC base key and a TLC under the number its
purpose names, at 0 and at the derivation's last, pins a literal spend's signature and key, hands each call bytes of its
own, and refuses a purpose that is no object, a kind it does not know, a number absent, negative, fractional, past the
derivation or a string, and a transaction it cannot serialize. The
dispatch's spec drives every spend of the device through `handleWatchtower` to fiber's signature, with the claim written
before the signature and the signature recorded on it, and every refusal at its step, the store unwritten: each decoder
refusal without a request to name, ahead of the channel, even an unregistered one; an unregistered channel and an empty
channel id, naming the request; no approval; each variant of the vectors with the code fiber's verdict calls for; and a
spend the policy reads as malformed. A repeat is answered with the recorded signature, signing and writing nothing; a
claim whose signature was lost is signed again to the same bytes and recorded; a spend of an unlock already signed is
signed unclaimed, writing nothing. A failed record hands nothing over and the next delivery heals it; a status whose
reading throws for no codec's reason and a corrupt record are faults; and no refusal names a key. The watchtower's flows
over the node double (above) pin the step end to end.

The watchtower signer, `signOnchain` and `SignerDispatch.handleWatchtower` with the spend it signs unclaimed, was broken the
same way (`test/tests/signer`, still 100% on all four metrics):

| Mutation                                             | Tests that failed |
| ---------------------------------------------------- | ----------------- |
| The recovery id is dropped                           | 41                |
| The signature is compact, without its recovery id    | 41                |
| The size check expects 64 bytes                      | 41                |
| The purpose's kind is read inverted                  | 40                |
| The message is prehashed                             | 39                |
| The recovery id stays first, as noble writes it      | 39                |
| The signature takes added entropy                    | 24                |
| A TLC signs under the TLC base key                   | 22                |
| A TLC signs under the next commitment's key          | 22                |
| The settlement signs under the funding key           | 17                |
| The keys derive from the next channel index          | 15                |
| A failed record write still hands the signature over | 13                |
| The signature is not recorded                        | 13                |
| The signature may be high-S                          | 13                |
| The purpose is not checked                           | 12                |
| A fresh signature reads as unclaimed                 | 11                |
| A policy refusal is a fault                          | 11                |
| A refusal names no request                           | 10                |
| A refusal names no purpose                           | 9                 |
| Every spend signs under the settlement key           | 7                 |
| Every refusal is a policy refusal                    | 6                 |
| The signed outcome names the settlement purpose      | 6                 |
| A decode refusal is a fault                          | 4                 |
| A claim without its signature is answered as signed  | 2                 |
| A signing fault is answered as malformed             | 2                 |
| A decode fault is answered as malformed              | 1                 |
| A repeat is signed again                             | 1                 |
| A repeat's signature reads as unclaimed              | 1                 |
| A spend signed unclaimed has its signature recorded  | 1                 |
| A spend signed unclaimed reads as claimed            | 1                 |
| An empty channel id is a fault                       | 1                 |
| No request is read as a spend                        | 1                 |

Dropping the size check on the recovered signature fails no test, and cannot: noble's `recovered` format always writes 65
bytes, so the check only guards a change of the library, whose frozen export no spec can stand in for.

`test/tests/signer/signing-deadline.spec.ts` pins the port of fiber's `tlc_expiry_delay` and
`pending_tlc_signature_deadline` with values computed by hand and checked against fiber's f64 arithmetic: one epoch at
each build's `MILLI_SECONDS_PER_EPOCH`, fractions where f64 rounding departs from the exact value, a zero length read as
CKB's `normalize` reads it, the cast's truncation and saturation, an expiry below, at and above the reserve, and the
earliest of several TLCs. The dispatch's spec reads the deadline on both commitment transitions, signed and refused, from
the pinned delay rather than the transaction's, and requires `null` on revocations, the close, a refusal before decoding,
no TLC, no pin, and pins that fail to read, the outcome otherwise identical (`test/tests/signer`, still 100% on all four
metrics):

| Mutation                                                | Tests that failed |
| ------------------------------------------------------- | ----------------- |
| The delay is the whole commitment delay, not two thirds | 20                |
| The index is read at the length's offset                | 19                |
| The epoch length is not validated                       | 9                 |
| The latest TLC is taken, not the earliest               | 8                 |
| Only the first TLC counts                               | 7                 |
| A failed pin read faults the outcome                    | 6                 |
| The delay is taken from the default epoch, not the pin  | 6                 |
| The fraction is dropped from the delay                  | 5                 |
| The number mask keeps a bit of the index                | 5                 |
| An expiry equal to the reserve is not zero              | 4                 |
| A refusal after decoding carries no deadline            | 3                 |
| A signature carries no deadline                         | 3                 |
| The cast does not saturate                              | 3                 |
| The deadline is read with no TLC                        | 3                 |
| The thirds are taken before the epochs are summed       | 3                 |
| A zero length is not normalized                         | 2                 |
| The cast rounds instead of truncating                   | 2                 |
| The subtraction wraps below zero                        | 2                 |
| A zero length keeps its index                           | 1                 |
| NaN is cast to u64::MAX                                 | 1                 |
| No TLC gives a zero deadline                            | 1                 |
| The network's epoch length is ignored                   | 1                 |
| The saturation starts one ulp late                      | 1                 |

`test/tests/signer/hold-invoice-preimages.spec.ts` pins the custodian of the hold invoice preimages against the device
scheme's pinned preimage and a literal payment hash at index 0 and at the last index, requires a fresh copy from every call,
refuses each malformed index and master seed, changes the host's seed array after construction to no effect, and states
ckb-hash as `hashAlgorithm` (`test/tests/signer`, still 100% on all four metrics):

| Mutation                                                    | Tests that failed |
| ----------------------------------------------------------- | ----------------- |
| The preimage ignores the index                              | 8                 |
| The payment hash is of the next index's preimage            | 5                 |
| A preimage is handed out by reference, cached per index     | 3                 |
| The preimages' seed is not checked at construction          | 3                 |
| The payment hash is salted with the master seed             | 2                 |
| The payment hash is the preimage itself                     | 2                 |
| The payment hash is the preimage under sha256               | 2                 |
| A payment hash is handed out by reference, cached per index | 1                 |
| The preimages state sha256 as their algorithm               | 1                 |
| The preimages' seed is held by reference                    | 1                 |
