# Signing

The musig2 (BIP-327) engine: how the device produces partial signatures, why its nonces are deterministic, and the exact
conditions under which that is safe. For the keys everything signs with see [derivation.md](./derivation.md); for the
sign-once registry the safety argument depends on see [persistence.md](./persistence.md).

## Role order

Fiber locks a channel's funds in a 2-of-2 musig2 aggregate of the two funding pubkeys. Key aggregation is
order-sensitive (`KeyAgg([A, B]) ≠ KeyAgg([B, A])`), and fiber uses two orderings: funding-cell spends and the channel
announcement sort the keys lexicographically, while the revocation signature keeps role order (see
[digest.md](./digest.md)). The engine takes no side in that: it signs for exactly the list the node sent, in the order it
sent it, and never sorts, which is correct under both. It validates only that the list has exactly two distinct 33-byte
keys and that its own funding pubkey is one of them.

## Deterministic nonces

Every signature consumes a musig2 secret nonce, and reusing one across two different messages leaks the signing key.
The engine derives its nonces deterministically anyway: BIP-327 `NonceGen` seeded only through its `rand` input with the
slot's `nonceSeed(channel, commitmentNumber, context)` (see [derivation.md](./derivation.md)), with the aggregate key,
message, and extra input deliberately omitted from the hash.

That parameterization buys two properties:

- **The public nonce exists before the message does.** The node can fetch pub nonces (or receive them in the channel
  handshake) ahead of building the transaction they will sign.
- **Re-delivery is idempotent.** A re-sent request regenerates the identical nonce and returns the byte-identical
  partial signature, so a connection lost mid-signature costs nothing.

Determinism is only safe under the sign-once rule, and that rule counts **sessions**, not messages: a slot ever serves
one (ordered key list, aggregated nonce, message) triple, and a repeat is answered only when all three match byte for
byte. The guard lives in the policy layer over the persisted registry ([policy.md](./policy.md)); the engine
itself checks no policy and stores nothing, so on its own it would resign a slot for whatever it is handed. This is why
the engine is internal and every signature must pass through the policy gate: the pair is the design, neither half
stands alone. The four contexts exist so that two different operations on the same commitment number never share a
nonce.

### Why counting messages is not enough

A BIP-327 partial signature is `s = k1 + b·k2 + e·a·d`, over the slot's two secret nonces `k1`, `k2` and the funding key
`d`. Both coefficients the node contributes sit inside: `b` is hashed from the aggregated nonce, and `e` from the
aggregate point that the same aggregated nonce determines. Hold the slot and the message fixed, vary only the aggregated
nonce, and every response is one more linear equation in those three unknowns. Three responses solve the system and the
funding key falls out, which the sign-once rule counted as a single message.

The node therefore never supplies nonces, and the one 66-byte aggregate it does supply is not something the engine can
check: it cannot tell whether that aggregate includes the nonce it published. A wrong aggregate yields a partial
signature the node cannot use, harmless on its own and key recovery by the third one. Nothing in the engine stands
between the two, only the policy gate refusing a slot whose session it has already served.

## What the engine signs

The message is always an opaque 32-byte digest (what fiber's `compute_tx_message` produces), handed to the session raw:
BIP-327 applies its own tagged challenge hash internally, so the engine never pre-hashes or tags. Validating that the
digest matches the attached channel state is the policy layer's no-blind-signing check, not the engine's.

Wire sizes: 33-byte compressed pubkeys, 66-byte public and aggregated nonces (two compressed points), 32-byte messages
and partial signatures.

## One call site: the dispatch

`SignerDispatch.handle` is where the gate and the engine become one path, the promise [policy.md](./policy.md) makes. It
takes a decoded envelope from the protocol layer ([protocol.md](./protocol.md)) with its params still as the node sent
them, and runs, in this order: the params are decoded against the network's commitment lock the dispatch holds
(`malformed`), the channel's name is resolved to its index (`unknown_channel`), the channel's four secrets are derived
from that index, and then the method runs. For a signing method that is `PolicyEngine.checkAndClaim` over the decoded
request and then `partialSign` at exactly the slot the verdict names, never at a number read from the operation: the
announcement signs at its fixed slot, and the other three at the `nonce_commitment_number` the request carries, taken as
sent (fiber's revocation carries one above the number it revokes, and nothing checks that relation). The `already-signed`
verdict takes the same path and re-signs to the same bytes. The gate's own shape checks run after the lookup, since they
take the channel's keys, so for an unknown channel only what the codecs refuse is `malformed`.

Nothing on that path throws. Every request comes out as one of three outcomes: a result, a refusal carrying one of the
four codes and a message, or a fault. A refusal is what the codecs or the gate said no to (`ProtocolError`,
`PolicyRefusalError`) and is answered on the wire. A fault is anything else: the host's storage throwing, a record or an
alias the store refuses to read, a bug. None of those is honestly one of the four codes, and answering `policy_refusal`
would make the node treat a device fault as a security event, so a fault is left unanswered and reported to the host;
nothing is signed and nothing is claimed, and the same request answers normally once the cause is gone.

Channel keys are derived per request and never cached: a few hashes, and no channel secret stays resident between
requests. The master seed, copied at construction so the host may discard its own buffer, is the
only secret the dispatch holds.

The public data methods resolve the channel and answer from the derivation: the base public keys, a commitment point or a
public nonce by number, and the announcement nonce at its fixed slot. They pass the known-channel check and nothing else;
their `state_version` is read but not judged, since nothing is claimed. `get_settlement_keys` is the one method whose
answer is private material: the TLC base key and the TLC key of the number asked, the scoped keys a watchtower settles
with, and never the funding key.

Registration is two halves, because the name a channel is filed under comes from the node. `prepareChannelRegistration`
derives the keys of a channel index the caller allocated and returns the payload of `register_channel`, the base public
keys and the delegated settlement key, together with the exposure the record will open at. `channelRegistered` files the
channel under the name the acknowledgement carried, through `PolicyEngine.registerChannel`; the session calls it while it
processes the acknowledgement, so a request the node sends right after finds the record in place. A registration that is
refused or interrupted leaves no record.

## The wallet identity

The session challenge is answered by `WalletIdentity`, over the wallet identity key of [derivation.md](./derivation.md).
The public half is the 32-byte x-only key of BIP-340, which the bridge pins per account across sessions: two devices
restored from one seed present one key. The signature is BIP-340 over `sessionChallengeDigest(challenge)`, the
domain-separated hash of [protocol.md](./protocol.md), so the identity key never signs bare bytes the bridge chose.

The signature is deterministic. BIP-340 takes optional auxiliary randomness to harden signing against fault attacks, and
the library draws it from the platform's random source when none is given, which `src/` may not touch: the identity
signs with a fixed auxiliary value instead, and BIP-340 still derives the nonce from the key and the message, so two
challenges never share one. The tests pin a signature for a fixed challenge for that reason: a dependency that started
drawing randomness would break the pin.

## The interop loop

Two halves verify the engine against fiber's exact stack:

- **jest**: `test/tests/signer/interop-vectors.spec.ts` signs the committed vector inputs
  ([`interop/`](../interop/README.md)) at the loop's canonical slot, (0, `COMMITMENT`), and verifies the partial
  signature in-session. Full aggregation against the vector remote is impossible in TS: fiber's Rust `SecNonceBuilder`
  omits the public key scure's `nonceGen` requires, so only the public half of the remote's nonce exists here.
- **Rust**: the harness's `verify-ts` subcommand verifies and aggregates that same signature under fiber's own
  `musig2 0.2.4` crate, fed by the same spec under `INTEROP_TS_OUT` ([`interop/`](../interop/README.md)). It needs a
  Rust toolchain that `pnpm test` does not, so it runs in the interop workflow on every pull request that touches the
  engine, the derivation, the tests or the harness, and on demand locally.

`test/tests/signer/musig2-engine.spec.ts` additionally pins the slot's public nonce and partial signature as literal
hex. Those pins are the idempotent re-delivery contract, not snapshots: the SDK's dependencies float on caret ranges,
and a bump that changes `NonceGen`'s output would break every in-flight signing round (the published nonce would no
longer match the one regenerated at sign time). A failing pin is investigated, never repinned.

## Where it lives

| File                                    | Contents                                                                            |
| --------------------------------------- | ----------------------------------------------------------------------------------- |
| `src/signer/musig2-engine.ts`           | The public data providers and the partial signature                                 |
| `src/signer/signer-dispatch.ts`         | The one call site: params, channel, keys, gate, signature, and the three outcomes   |
| `src/signer/wallet-identity.ts`         | The x-only identity key and the deterministic BIP-340 signature of the challenge    |
| `src/signer/signer.types.ts`            | The partial-sign request, the dispatch outcome, and a registration awaiting its ack |
| `src/protocol/utils/challenge.utils.ts` | The digest the challenge is signed over, shared with the bridge                     |

## What the tests guarantee

`test/tests/signer/signer-dispatch.spec.ts` drives every method through the dispatch with requests built from the
cross-implementation vectors, and verifies each of the four partial signatures with scure under an aggregate that
contains the nonce **the dispatch itself published** for that slot, which is what the node will do, and over the key
list in fiber's own order: sorted for the funding spends and the announcement, remote first for the send-side
revocation, so a list the dispatch reordered would not verify; the commitment signature is also aggregated with the
peer's half into a Schnorr signature the 2-of-2 key accepts. Around that: each of the four codes reaching the outcome as
exactly its code and the message the codec or the gate threw, a codec refusal ahead of the channel lookup and a
gate refusal behind it, a session off the curve refused before the claim so that the corrected request still signs, the
re-delivered request answered with identical bytes, no write and no intent consumed, two channels on one dispatch each
filed under and answered from its own index, so the two never share a nonce, the storage that throws (with a `code` of
its own or without), the corrupt record and the alias without a record all coming out as faults that claim nothing and
clear once the cause is gone, the mainnet lock refusing the testnet vectors, public data answering whatever the state
version, the settlement keys and the registration payload never carrying the funding key, and every refusal message
checked against the seed, the identity key, the four channel secrets, a nonce seed and a TLC key.

`test/tests/signer/wallet-identity.spec.ts` pins the x-only key of the vector master seed and the signature of a fixed
challenge, both as literals: the first is the account's name at the bridge, the second the proof that no randomness
enters the signature. Discarding the host's seed buffer changes neither.
`test/tests/protocol/utils/challenge.utils.spec.ts` pins the digest itself.

Coverage of the module is 100% on all four metrics, and the assertions were checked by breaking the code on purpose:

| Mutation                                                             | Tests that failed |
| -------------------------------------------------------------------- | ----------------- |
| A revocation signs at the number it revokes, not at its nonce number | 1                 |
| Every signature uses the `COMMITMENT` nonce context                  | 2                 |
| A refusal of the gate is ignored and the request signed anyway       | 10                |
| The params are decoded under a fixed lock, not the dispatch's        | 18                |
| A fault is answered as a `malformed` refusal                         | 5                 |
| A refusal is reported as a fault                                     | 27                |
| A refusal is told apart by carrying a `code`, not by its class       | 1                 |
| A refusal is written with its stack, not its message                 | 2                 |
| The key list is sorted before the engine signs                       | 1                 |
| The channel is looked up before the params are decoded               | 1                 |
| The keys of the first channel derived are kept for every channel     | 1                 |
| The keys derive from a fixed index, not the resolved one             | 1                 |
| The registration is filed at a fixed index, not the prepared one     | 2                 |
| The prepared registration keeps a fixed index                        | 3                 |
| The announcement nonce is published at another slot                  | 2                 |
| The settlement keys carry the funding key                            | 1                 |
| The registration carries the funding key                             | 3                 |
| The seed is held by reference, not copied                            | 1                 |
| The exposure is not validated before the registration is prepared    | 6                 |
| The record opens at zero exposure whatever was prepared              | 5                 |
| The gate lets a session off the curve reach the claim                | 2                 |
| The identity signs the bare challenge                                | 5                 |
| The identity draws fresh auxiliary randomness                        | 1                 |
| The identity holds the seed by reference, not its derived key        | 1                 |
| The challenge digest drops the label                                 | 4                 |
