# Signing

The entry of a signing request and the musig2 (BIP-327) engine behind it: what the device checks before it claims a slot,
the order fiber aggregates the keys in, how the device computes the message itself, why its nonces are deterministic and
how many sessions one of them can answer, and the public material it hands the node. For how the status is read see
[protocol.md](./protocol.md); for the gate a request passes see [policy.md](./policy.md); for the four constructions the
messages are rebuilt with see [digest.md](./digest.md); for the keys see [derivation.md](./derivation.md).

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
  32-byte partial signature, the next material or `null`, the verdict (`fresh`, `already-signed` or `reused`) and the
  warnings: a `reused` verdict carries `{ kind: "nonce-reused", slot }`;
- **refused**, with the request id and transition once the status decoded, and one of the four codes with its message:
  a `ProtocolError` of the decoder, a `PolicyRefusalError` of the gate or of the dispatch's own steps, and the type and
  range errors the digest and the input builders throw over what the node sent, which are `malformed`;
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
36-byte args carry none, though the fee is sized over the commitment mock that does. A close needs neither.

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
  taken as stated and held by the gate's first-sight pin.

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
  ([policy.md](./policy.md)).
- **With every signature** on the four commitment and revocation transitions, `buildNextMaterial(keys, slot + 1)`: the
  commitment point and the commitment and revocation nonces of the number after the slot, fiber's `next_material`
  (`fiber-lsp-sdk/src/signer.rs:363-385`). The decoder bounds the slot one below the derivation's top, so `slot + 1` is
  always derivable.

## What the engine signs

The message is always an opaque 32-byte digest, handed to the session raw: BIP-327 applies its own tagged challenge hash,
so the engine never pre-hashes or tags. Wire sizes: 33-byte compressed public keys, 66-byte public and aggregated nonces,
32-byte messages and partial signatures, 64-byte complete signatures. The partial signature's size is checked on the way
out, since the dependency floats on a caret range and the size is a protocol commitment.

## The interop loops

Two loops verify the engine against fiber's exact stack, each with a jest half and a Rust half
([`interop/`](../interop/README.md)):

- **The signing requests**: `test/tests/signer/interop-vectors.spec.ts` answers every request of `signing.json`, each on
  a channel at the state before it, through the dispatch, the announcement through the engine, and requires fiber's
  expected public nonce and partial signature to the byte. Under `INTEROP_SIGNING_OUT` it writes them for
  `verify-signing`, which verifies each under fiber's `musig2` crate and aggregates it with the peer's half.
- **The canonical slot**: the same spec signs the musig vector at (0, `COMMITMENT`) and, under `INTEROP_TS_OUT`, writes
  it for `verify-ts`.

`test/tests/signer/musig2-engine.spec.ts` also pins the public nonce and the partial signature of a literal request.
Those pins, like the vectors, are the idempotent re-delivery contract, not snapshots: a dependency bump that changed
`NonceGen`'s output would break every in-flight signing round. A failing pin is investigated, never repinned.

## Where it lives

| File                                      | Contents                                                                                                                      |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `src/signer/signer-dispatch.ts`           | The twelve steps, the four outcomes, and the opening                                                                          |
| `src/signer/musig2-engine.ts`             | The public keys, points and nonces, the nonce sum, the partial signature, the peer's half verified, the aggregate             |
| `src/signer/signer-material.ts`           | The opening block and the next material                                                                                       |
| `src/signer/signer.constants.ts`          | The key order per transition                                                                                                  |
| `src/signer/utils/key-order.utils.ts`     | The order of the two funding keys, and the peer's key read out of a request held to it                                        |
| `src/signer/utils/signing-terms.utils.ts` | The message from the plaintext, and the operation built from the content, the pins and the network                            |
| `src/signer/signer.types.ts`              | The options, the cosigned session, the prepared operation, the outcome and the pending open                                   |
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
script on a commitment cell and on either revocation; each unpinned term on a commitment and a revocation while a close
still signs; and the unpinned layout. Behind the claim, the gate's refusals surface with their codes: a digest mismatch
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

Reading the pins before the channel resolves fails no test, and cannot: the reader resolves the name itself, with the same
refusal, so the outcome is the same for every status.
