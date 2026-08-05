# Key derivation

Everything the device signs with descends from one 32-byte master seed the host injects at construction. Nothing is drawn at
random and nothing is stored: given the seed, every key of every channel is a pure function of a channel index and a commitment
number.

Three things have to hold at once, and each fails in its own way:

- **The keys must equal fiber's, byte for byte.** The node builds transactions with the public halves it derives itself. One
  diverging byte and no signature validates, so no channel opens.
- **The keys must be deterministic.** Losing the device would otherwise mean losing the funds: there would be no way to rebuild
  them from the mnemonic.
- **Two different signatures must never share a nonce.** Schnorr leaks the private key from two signatures made with the same
  nonce, so a collision in the nonce derivation is a total-loss bug, not a correctness bug.

This document covers the scheme itself. For the surrounding architecture see the [README](../README.md); for how the scheme is
verified against fiber's Rust implementation see [`interop/README.md`](../interop/README.md).

## What each key protects

fiber's `InMemorySigner` holds four secrets per channel. They are not equally dangerous:

| Secret            | What it is                                                       | If it leaks                                                                                   |
| ----------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `fundingKey`      | The local half of the 2-of-2 that locks the channel's funds      | An attacker holding the other half can sign any state: total loss                             |
| `musig2BaseNonce` | Root of every musig2 nonce in the channel                        | Predictable nonces let `fundingKey` be recovered from signatures: total loss                  |
| `commitmentSeed`  | Root of the per-commitment revocation secret chain               | Old states can be revoked and penalised: the channel can be claimed                           |
| `tlcBaseKey`      | Base key the per-commitment TLC settlement keys are tweaked from | Settlement of in-flight payments after a close can be skewed, but the funding cannot be spent |

That last row is why the split matters. `fundingKey` never leaves the device under any circumstance. `tlcBaseKey` deliberately
can: a watchtower needs it to settle TLCs if the channel is force-closed while the phone is off. It is a scoped delegation —
power over post-close settlement, not over the channel's money.

The SDK adds a fifth key that is not part of fiber's scheme:

| Secret              | What it is                                                                             |
| ------------------- | -------------------------------------------------------------------------------------- |
| `walletIdentityKey` | Wallet identity. Signs the challenge with which the LSP bridge authenticates a session |

It identifies the master seed, not the handset. Two devices restored from the same mnemonic derive the same key and are
indistinguishable to the LSP — which is what makes a restored wallet reauthenticate on its own, and what makes telling two
installations apart impossible with this derivation alone.

## The primitives

### CKB's personalized blake2b-256

CKB does not use SHA-256. It uses blake2b with a 32-byte output and the personalization `ckb-default-hash` — a standard blake2b
parameter (16 bytes max; this string is exactly 16) mixed into the initial state. Hash the same bytes with a different
personalization and every digest differs.

```text
ckbBlake2b("") = 44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e
```

That value is a well-known CKB constant and is pinned as a test. It is the cheapest possible proof that the hash is wired up
correctly.

**The salt trap.** fiber has a helper `blake2b_hash_with_salt(data, salt)` that hashes `salt || data` — the reverse of its own
argument order. It is the perfect silent bug: it compiles, the types line up, determinism tests pass, and every key comes out
wrong. The port keeps the same signature so it reads against upstream, and concentrates the hazard in one function that carries
its own comment and its own test.

### The additive tweak on secp256k1

A private key is a scalar `d`; the public key is the point `P = d·G`, 33 bytes compressed. The group law `(a + b)·G = a·G + b·G`
is the engine of the whole per-commitment scheme:

```text
tweak            t  = ckbBlake2b(commitmentPoint)
derived private  d' = (d + t) mod n
derived public   P' = d'·G = (d + t)·G = d·G + t·G = P + t·G
```

So whoever knows only the public key `P` and the commitment point — which is public — can compute `P'` without knowing `d`. Hence
the two functions: `derivePrivateKey(d, point)` for the device, which holds the secret, and `derivePublicKey(P, point)` for the
node, which does not. The tests pin the invariant that ties them together across many commitment numbers:

```ts
pubkeyOf(derivePrivateKey(d, point)) === derivePublicKey(pubkeyOf(d), point);
```

If that ever breaks, node and device are deriving different keys for the same commitment.

The point is hashed rather than used directly so the tweak is unpredictable and bound to that specific commitment, which rules
out algebraic relations between derived keys.

### The commitment secret chain

Every time the channel advances, the previous state must be revoked: the counterparty receives a secret that lets it punish us if
we ever publish that old state. Storing N independent secrets would be O(N); Lightning solved this with a construction (BOLT3,
"efficient per-commitment secret storage") that keeps every revealed secret in 48 values.

```text
secret(seed, number):
    res = seed
    for bitpos from 47 down to 0:
        if bit bitpos is set in number:
            res[bitpos / 8] ^= 1 << (bitpos % 8)     # flip that bit inside the 32 bytes
            res = ckbBlake2b(res)                     # and rehash
    return res
```

Reading it:

- The walk goes from the **high** bit down. Each set bit triggers one flip-and-hash.
- `number = 0` has no set bits, so **the secret is the seed itself**, untouched. The vectors show it:
  `commitments[0].secret == commitment_seed`.
- Only the **low 48 bits** are read. `number` and `number + 2⁴⁸` produce exactly the same secret.

That last property is the reason `MAX_COMMITMENT_NUMBER` exists. Two different commitments sharing a secret also share the
derived musig2 nonce, which is catastrophic. The code turns it into a `RangeError` instead of letting it through.

**Derivability, and a consequence worth knowing.** Because the walk goes high bit to low, the secret at index `I` lets you derive
the secrets of every index that shares `I`'s high bits and only adds bits _below_ its lowest set bit. Lightning exploits this by
counting **downwards**, so revealing one state's secret never reveals future ones. The corollary matters: `secret(0)` is the seed
itself, so from it every other secret follows. A channel that started at 0 and counted up would hand over the entire chain with
its first revocation. The reference implementation (LDK) maps `real_index = INITIAL_COMMITMENT_NUMBER - n` with
`INITIAL_COMMITMENT_NUMBER = 2⁴⁸ - 1` precisely for this reason. The function here is a pure function of the number it is given
and is correct either way, but the convention is still an open item (see below).

### musig2 nonces

fiber's 2-of-2 is not a multisig script: the two keys are aggregated into a single Schnorr key with musig2 (BIP-327), so the
final signature is indistinguishable from an ordinary one. Two facts drive the design here.

**Aggregation is order-dependent.** `KeyAgg([A, B]) ≠ KeyAgg([B, A])`; each key carries a coefficient derived from the ordered
list. fiber orders by role, `[local, remote]`, not lexicographically. The SDK must never sort on its own.

**Every signature needs a single-use secret nonce.** Sign two different messages with the same nonce `k` and the private key
falls out:

```text
s1 = k + e1·d
s2 = k + e2·d    ⇒    d = (s1 - s2) / (e1 - e2)
```

musig2 uses two nonces per signer to resist adaptive (Wagner/ROS) attacks in concurrent sessions, but that does not make reuse
safe: BIP-327 forbids it outright and the security proof collapses without it. The nonce is generated by whoever holds the key,
and only the public nonce crosses the wire — a node able to choose or influence our nonce could induce reuse.

From which follows the decision that shapes the SDK:

> Nonces are **deterministic**: the same `(channel, commitment number, context)` slot always produces the same nonce.

That reads like a violation of the golden rule, and it is not, provided the other half holds:

> The **sign-once** policy guarantees a slot ever signs **one** message. A repeated request with the same message returns the
> cached signature; a different message for an already-signed slot is refused.

Deterministic nonce + sign-once = single-use nonce _per message_. The payoff on mobile is large: if the connection drops
mid-signature and the bridge redelivers, the device produces the same response byte for byte, so retries are idempotent without
persisting the signature itself. The four contexts (`COMMITMENT`, `REVOKE`, `CLOSE`, `ANNOUNCEMENT`) exist so two different
operations on the same commitment number cannot share a nonce.

This module derives the nonce **seed**. The nonce itself (BIP-327 `nonceGen`) belongs to the signing engine.

## The scheme

### The tree

```text
user mnemonic                       (the SDK never sees it)
   │
   └─ BIP39, done by the host application
      │
      └── bip39Seed (64 bytes) ─────────────────────────── goes in and out of deriveMasterSeed, never retained
            │
            └── masterSeed = BIP32 m/1017'/309'/{a}'  ───── enters once, through the constructor   [a = account]
                  │
                  ├── walletIdentityKey = ckbBlake2b(masterSeed ‖ "wallet identity")
                  │      └─ signs the session challenge
                  │
                  └── channelSeed(i) = ckbBlake2b(masterSeed ‖ "fiber channel {i}")     [i = channel index]
                        │
                        │   ─── from here down it is fiber's scheme, byte for byte ───
                        │
                        └── seed = ckbBlake2b(channelSeed)
                              ├── commitmentSeed  = ckbBlake2b(seed ‖ "commitment seed")
                              │     └── commitmentSecret(n)  = 48-bit BOLT3 chain over commitmentSeed
                              │           └── commitmentPoint(n) = commitmentSecret(n)·G
                              │
                              ├── fundingKey      = ckbBlake2b("funding key"   ‖ seed)
                              │     └── musig2 partial signatures: commitment / revoke / close / announcement
                              │
                              ├── tlcBaseKey      = ckbBlake2b("HTLC base key" ‖ fundingKey)
                              │     └── tlcKey(n) = tlcBaseKey + ckbBlake2b(commitmentPoint(n))   [settlement material]
                              │
                              └── musig2BaseNonce = ckbBlake2b("musig nocne"   ‖ tlcBaseKey)
                                    └── nonceSeckey(n) = musig2BaseNonce + ckbBlake2b(commitmentPoint(n))
                                          └── nonceSeed(n, ctx) = ckbBlake2b(nonceSeckey(n) ‖ ctx)   [SDK-owned]
```

`‖` is byte concatenation; `+` on keys is modular scalar addition.

### Normative table

| Derivation                   | Formula                                                                   | Owner |
| ---------------------------- | ------------------------------------------------------------------------- | ----- |
| `masterSeed(a)`              | BIP32 private key at `m/1017'/309'/{a}'` over the BIP39 seed              | SDK   |
| `walletIdentityKey`          | `ckbBlake2b(masterSeed ‖ "wallet identity")`                              | SDK   |
| `channelSeed(i)`             | `ckbBlake2b(masterSeed ‖ "fiber channel {i}")`                            | SDK   |
| `seed`                       | `ckbBlake2b(channelSeed)`                                                 | fiber |
| `commitmentSeed`             | `ckbBlake2b(seed ‖ "commitment seed")`                                    | fiber |
| `fundingKey`                 | `ckbBlake2b("funding key" ‖ seed)`                                        | fiber |
| `tlcBaseKey`                 | `ckbBlake2b("HTLC base key" ‖ fundingKey)`                                | fiber |
| `musig2BaseNonce`            | `ckbBlake2b("musig nocne" ‖ tlcBaseKey)`                                  | fiber |
| `commitmentSecret(n)`        | 48-bit chain over `commitmentSeed`                                        | fiber |
| `commitmentPoint(n)`         | `commitmentSecret(n)·G`                                                   | fiber |
| `tweak(point)`               | `ckbBlake2b(point)`                                                       | fiber |
| `derivePrivateKey(d, point)` | `(d + tweak(point)) mod n`                                                | fiber |
| `derivePublicKey(P, point)`  | `P + tweak(point)·G`                                                      | fiber |
| `tlcKey(n)`                  | `derivePrivateKey(tlcBaseKey, commitmentPoint(n))`                        | fiber |
| `nonceSeed(n, ctx)`          | `ckbBlake2b(derivePrivateKey(musig2BaseNonce, commitmentPoint(n)) ‖ ctx)` | SDK   |

Note the asymmetric concatenation: `commitmentSeed` hashes `seed ‖ label`, while the three keys hash `label ‖ data`. That is not
a slip on our side, it is how fiber does it, and the code makes it visible by using two different functions — `ckbBlake2b(...)`
against `blake2bHashWithSalt(data, salt)` — instead of hiding it in the order of two arguments.

### Where the master seed comes from

The SDK is constructed with a 32-byte master seed and the mnemonic never reaches it. That leaves one step above the tree, and
`deriveMasterSeed(bip39Seed, account)` is the SDK owning it rather than leaving it to each host:

```text
masterSeed = BIP32 private key at m/1017'/309'/{account}'
```

Every level is hardened, so the branch cannot be walked from any public key the wallet publishes. The two fixed levels are what
matter:

- **Purpose 1017** is the BIP43 purpose lnd uses for its Lightning key tree, and lnd picked the number arbitrarily: nothing
  registers purposes, so the precedent buys legibility rather than any guarantee. Other implementations do not follow it, since
  they do not derive their channel keys this way at all. The argument that does the work is a different one: a wallet spends
  on-chain from BIP44, BIP49 and BIP84, so picking a purpose none of them uses makes it impossible for one private key to serve
  as both a spending key and this master seed, whatever accounts the wallet derives. The impossibility is structural, a different
  purpose is a different hardened subtree; a test demonstrates it against nine paths under those three purposes.
- **Coin type 309** is CKB's SLIP-44 registration.

The function is pure and lives outside the SDK instance: the host calls it, gets 32 bytes, and passes those to the constructor.
The BIP39 seed is an argument and nothing more, so the instance never holds the root of the wallet. A host that derives its own
seed some other way can still do so; what the function buys is that the promise of recoverability now covers the whole chain,
including the step the SDK used to leave undefined. If a host picks its own path and later changes it, the channels derived under
the old one are gone, and no test in this repo would notice.

### Why the channel seed is derived, not random

fiber generates the channel seed **randomly** on the node. The SDK derives it from the master seed instead. The change is
deliberate and cuts both ways.

**For:** full recoverability. Mnemonic plus channel index regenerates every key. Losing the device, or losing the SDK's local
storage, is not losing funds: counters and balances are reseeded from the state the node sends, and monotonicity protects against
being rolled back.

**Against:** the channel index becomes part of the state to recover — you have to know how many channels existed — and all
security rests on the master seed. It also means the scheme is a consensus with our future selves: changing it orphans existing
channels. Hence `DERIVATION_SCHEME_VERSION` and the **additive-only** rule: a new version applies to new channels only, and v1
must keep working forever.

### Inherited quirks

| Quirk                                     | Why it stays                                                                                     |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `"musig nocne"`                           | Upstream typo. It is inside the hash, so it is part of the scheme: "fixing" it changes every key |
| `"HTLC base key"`                         | fiber calls them TLCs, but the derivation string kept Lightning's name                           |
| `ckbBlake2b(seed ‖ "commitment seed")`    | The only case where the label goes last; the other three put it first                            |
| `ckb-default-hash` personalization        | Without it no digest matches anything in CKB                                                     |
| Compressed 33-byte point fed to the tweak | fiber serialises compressed; hashing the uncompressed form yields a different tweak              |

## Where it lives

| File                                     | Contents                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------ |
| `src/derivation/fiber-scheme.ts`         | The literal port of `crates/fiber-types/src/channel.rs`                        |
| `src/derivation/device-scheme.ts`        | The SDK-owned derivations: wallet identity key, channel seed, nonce seed       |
| `src/derivation/master-seed.ts`          | The step above the tree: BIP39 seed to master seed, the boundary with the host |
| `src/derivation/derivation.constants.ts` | Lengths, bounds, scheme version, nonce contexts                                |
| `src/derivation/utils/ckb-hash.utils.ts` | CKB's blake2b-256 and the salted variant                                       |
| `src/common/utils/assert.utils.ts`       | Input guards for lengths and ranges, shared with the rest of the SDK           |
| `src/derivation/index.ts`                | The module surface; scheme internals stay unexported                           |
| `interop/`                               | The Rust harness and the generated vectors ([README](../interop/README.md))    |

Every function in `fiber-scheme.ts` carries the name of its Rust counterpart, so auditing against `channel.rs` is a matter of
reading the two side by side.

## What the tests guarantee

187 tests across the 6 suites of `test/tests/derivation/`, in four layers with different jobs. The input guards the module leans
on are generic and live in `common/`, tested alongside them.

**Cross-implementation vectors** (`test/tests/derivation/interop-vectors.spec.ts`) compare every derivation against
`interop/vectors/vectors.json`. This is _the_ contract: while it is green, the TypeScript produces the same bytes as an
independent implementation. It covers 4 hashing KATs; the 4 channel keys and 2 of their public halves; 9 commitment numbers
(0, 1, 2, 5, 1000, 65535, 2³²−1, 2⁴⁷, 2⁴⁸−1) across secret, point, TLC key by both paths and nonce seckey; 3 master seeds at accounts
0, 1 and 2³¹−1; the wallet identity key; 6 channel seeds including `MAX_SAFE_INTEGER`; the full master seed → channel → keys chain;
and 36 nonce seeds (9 numbers × 4 contexts). The vector file is shape-checked when loaded, and a guard test demands the boundary
cases are present so a regenerated, thinner file fails loudly instead of silently testing less.

The master seed half is worth a note: the Rust side implements BIP32 hardened derivation straight from the spec, so agreement
with `@scure/bip32` is two independent implementations meeting, not one library checked against itself.

**Invariants** hold whatever the input: the private and public derivation paths agree; the first 65 commitment secrets are all
distinct; the first 101 channel seeds are all distinct; the four nonce seeds of one commitment differ; nothing mutates its
inputs; `getCommitmentSecret` returns a copy, accepts a view into a larger buffer, and reaches a later secret from an earlier one
whenever the extra bits are lower — the property that lets the counterparty store every revealed secret in 48 values.

**Refusal paths** get a test each — bad lengths, bad types, a value that is not a number, negative, fractional, `NaN`,
`Infinity`, above the maximum, an uncompressed point, a point off the curve, the zero key, a key at the curve order, a tweak that
cancels the key on either derivation path, malformed channel keys, an unknown context. The first group is exercised directly
against the guards in `test/tests/common/utils/assert.utils.spec.ts`.

**Pinned outputs** hardcode results by hand, deliberately redundant with the vectors, because the vectors live in a generated
file: a change made to the port and to the Rust harness at the same time regenerates them green, and only a hand-written value
survives that. `device-scheme.spec.ts` pins the scheme v1 outputs, the promise that a channel opened today can be recovered
tomorrow; `master-seed.spec.ts` pins three master seeds, which is where a changed path level lands; `fiber-scheme.spec.ts` pins
the four channel keys, two commitment secrets, a commitment point and a TLC key, which is where "fixing" a domain separator or
shortening the chain lands. None of them is a snapshot to update when it fails.

Coverage is 100% on statements, branches, functions and lines, which proves there is no dead code — not that the assertions are
right. For that, silent breakages were introduced deliberately and the reaction measured:

| Mutation                                           | Tests that failed |
| -------------------------------------------------- | ----------------- |
| "Fixing" the `musig nocne` typo to `musig nonce`   | 49                |
| 47-bit chain instead of 48 (`bitpos = 46`)         | 13                |
| Hashing `data ‖ salt` instead of `salt ‖ data`     | 61                |
| `fiber channel {i}` changed to `fiber channel-{i}` | 45                |
| Purpose 1017 changed to 1018                       | 4                 |
| Coin type 309 changed to 310                       | 4                 |
| Any path level left unhardened                     | 4                 |

Every one of them is exactly the kind of change a well-meaning refactor might make.

## Design decisions

| Decision                                    | Rejected alternative                   | Why                                                                                                    |
| ------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `commitmentNumber: number` capped at 2⁴⁸−1  | `bigint`                               | The cap fits exactly in `number`, and the rest of the API already uses `number`                        |
| Reject `n > 2⁴⁸−1`                          | Mask the low 48 bits                   | Masking silently aliases secrets and nonces; throwing turns a crypto disaster into a programming error |
| Master seed of exactly 32 bytes             | Accept any length, the hash absorbs it | Requiring it catches a miswired host immediately                                                       |
| BIP43 purpose 1017 for the master seed path | Reuse BIP44 with CKB's coin type       | A purpose no wallet spends from makes a collision with an on-chain key impossible, not just unlikely   |
| `deriveMasterSeed` as a pure function       | Take the BIP39 seed in the constructor | The instance would then hold the root of the whole wallet, not just the material scoped to Fiber       |
| BIP39 seed of exactly 64 bytes              | Accept 16 to 64 as BIP32 does          | The one wrong argument worth catching is a 32-byte master seed passed in twice, which would look valid |
| Validate in every public function           | Validate only at the SDK boundary      | The module is called from inside; a cheap guard beats debugging wrong keys three layers up             |
| `TypeError` / `RangeError`                  | A dedicated `DerivationError` class    | These are host programming errors, not protocol errors; protocol errors have their own codes           |
| `DataView` in the bit chain                 | `(secret[i] ?? 0) ^ …`                 | Removes an unreachable branch that `noUncheckedIndexedAccess` would otherwise force                    |
| Pinned outputs _and_ vectors                | Vectors only                           | The vectors are a generated file; the pinned values survive someone regenerating them                  |
| SDK half of the harness written, not ported | Port the TypeScript to Rust            | Porting would replicate interpretation errors instead of catching them                                 |

## Open questions

These do not affect the functions, which are pure and correct for the inputs they are given, but the conventions around them must
be fixed before integration against a real node.

1. **Direction of the commitment number.** `secret(0)` is the whole seed, which is why Lightning's reference implementation
   counts down from 2⁴⁸−1. Confirm, against fiber's channel actor, which number arrives in a sign request and whether it is
   already mapped.
2. **Commitment number for the `ANNOUNCEMENT` context.** A channel announcement is signed once, not per commitment. A convention
   has to be frozen along with the wire format.
3. **Account index convention.** `deriveMasterSeed` takes one and defaults to 0. Confirm whether the wallet keeps one Fiber
   account per wallet account, and whether that index is the same one it uses for its on-chain BIP44 accounts, since recovery has
   to know it as surely as it knows the channel index.
4. **Nonce construction on both sides.** Only public nonces cross the wire, so the internal constructions may differ. Confirm
   during integration that fiber assumes nothing about how our secret nonce was built.
5. **Channel index after a restore.** Re-deriving requires knowing how many channels existed. The reseeding logic belongs to the
   persistence layer but depends on this scheme.
6. **Telling two installations apart.** `walletIdentityKey` is a function of the master seed alone, so a wallet installed on two
   devices presents one identity. If the session layer ever needs per-installation identity — revoking one device, warning about
   a second login — it needs a component that is not derived from the seed, and therefore registered with the LSP rather than
   rederived.

## Glossary

| Term                        | Meaning                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| **BIP-327 / musig2**        | Multiparty Schnorr signing: N keys aggregate into one, N partial signatures into one       |
| **BOLT3**                   | The Lightning spec that defines, among other things, the per-commitment secret chain       |
| **Commitment tx**           | The transaction representing the channel's current state                                   |
| **Commitment point/secret** | Per-state pair; the secret is revealed on revocation                                       |
| **CKB**                     | Nervos' blockchain; cells and personalized blake2b-256                                     |
| **Funding**                 | The 2-of-2 output that locks the channel's money                                           |
| **KAT**                     | Known Answer Test: fixed input, fixed expected output                                      |
| **LSP**                     | Lightning Service Provider: hosts the node and provides liquidity                          |
| **Nonce**                   | Single-use secret per signature; reusing one leaks the private key                         |
| **Personalization**         | blake2b parameter altering the initial state; CKB uses `ckb-default-hash`                  |
| **Shannon**                 | CKB's smallest unit: 1 CKB = 10⁸ shannons                                                  |
| **Sign-once**               | Policy rule: a `(channel, number, context)` slot signs exactly one message                 |
| **TLC**                     | Fiber's equivalent of Lightning's HTLC                                                     |
| **Tweak**                   | Scalar added to a key to derive another                                                    |
| **Watchtower**              | Service that watches the channel and punishes fraudulent closes while the owner is offline |
