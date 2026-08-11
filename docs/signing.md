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
byte. The guard lives in the policy layer over the persisted registry ([persistence.md](./persistence.md)); the engine
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

## The interop loop

Two halves verify the engine against fiber's exact stack:

- **jest**: `test/tests/signer/interop-vectors.spec.ts` signs the committed vector inputs
  ([`interop/`](../interop/README.md)) at the loop's canonical slot, (0, `COMMITMENT`), and verifies the partial
  signature in-session. Full aggregation against the vector remote is impossible in TS: fiber's Rust `SecNonceBuilder`
  omits the public key scure's `nonceGen` requires, so only the public half of the remote's nonce exists here.
- **Rust**: the harness's `verify-ts` subcommand verifies and aggregates that same signature under fiber's own
  `musig2 0.2.4` crate. It runs on demand, fed by the same spec under `INTEROP_TS_OUT`
  ([`interop/`](../interop/README.md)), because it needs a Rust toolchain that `pnpm test` does not.

`test/tests/signer/musig2-engine.spec.ts` additionally pins the slot's public nonce and partial signature as literal
hex. Those pins are the idempotent re-delivery contract, not snapshots: the SDK's dependencies float on caret ranges,
and a bump that changes `NonceGen`'s output would break every in-flight signing round (the published nonce would no
longer match the one regenerated at sign time). A failing pin is investigated, never repinned.
