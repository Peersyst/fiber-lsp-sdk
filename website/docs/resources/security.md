---
title: Security model
sidebar_label: Security
description: What the Fiber LSP SDK trusts, what it checks instead, and the rules your app must keep for it to stay safe.
---

# Security model

The device holds the keys and the LSP node runs everything else. The SDK's job is to make that split safe: the node can ask for signatures, but it cannot make the device sign something it did not agree to, and it never sees a private key.

## What the device trusts, and what it does not

| Party                  | Trusted for                                                                                  | Not trusted for                                                         |
| ---------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **The LSP node**       | Running the channels, routing payments, staying online, broadcasting transactions             | What the device signs: every request is rebuilt and checked             |
| **Your app (the host)** | The master seed, the storage, the funding signer, the watchtower approval, the clock          | Nothing: the host is the device's owner                                 |
| **The operator backend** | Admitting tenants with the operator token                                                   | It never holds device keys and plays no part in signing                 |
| **The CKB chain**      | Final settlement, and the timelocks and hash locks of the commitment scripts                  |                                                                         |

The node is the party that could gain from a bad signature, so everything it sends is treated as untrusted input. If a request does not match what the device can rebuild from its own records, the device refuses it and reports a `SIGNING` event with `outcome: "refused"`.

## Never blind-sign

Fiber signs four kinds of message for a channel. For each signing request, the device rebuilds the message from the state the node attaches and its own records, and refuses unless the rebuilt message is byte for byte the one it was asked to sign. Then a policy checks, in order:

1. the channel is one this device registered;
2. the message is the one the device rebuilt;
3. the signing slot is free (sign-once, below);
4. the channel's state only moves forward;
5. the channel's fixed terms (its peer, its funding cell, its close scripts) and the bounds on fees hold;
6. the balance rule: the device's balance only goes down for a payment it approved, by no more than it approved.

A payment you send with `transfer` is approved up front with its amount and a fee bound; the device then signs nothing that pays out more. See [No blind signing](/docs/concepts/no-blind-signing).

## Sign once, with deterministic nonces

Each signature uses a musig2 nonce, and the device derives each one deterministically from the master seed and the signing slot. That has two benefits: the device can publish its nonces before it knows the messages, and a request delivered twice is answered with the identical signature, so a crash between signing and submitting costs nothing.

The price is a strict rule: **one slot, one signing session**. Each session signed under a nonce is one equation about the funding key, and three of them solve for it. So the device records every session it serves in the storage, writes that record before it signs, and refuses any other session on a served slot.

:::note
Fiber's current nonce lifecycle needs a second session on some slots, so the SDK offers `nonceReuse: "allow"`, which serves one second session and never a third. Two sessions still keep the key hidden. See [Status and known limitations](/docs/resources/status).
:::

## Why the storage must never roll back

The sign-once records live in the storage you provide. That makes the storage part of the security model:

- **Storage lost (empty):** safe. Every channel reads as unknown and the device refuses to sign for it.
- **Storage older than it was:** unsafe. The device would see slots it already served as free, and could sign another message under the same nonce. Enough of those reveal the channel's funding key to the node.

So never restore the storage from a backup over a live device, keep it out of OS backups (Android's Auto Backup, cloud restores), and run a single SDK instance per storage. See [Storage](/docs/concepts/storage).

## Secrets never leave the SDK

- The master seed enters once, through the `FiberLspSdk` constructor, and stays in the SDK's memory.
- No method returns a private key. The one exception is `deriveMasterSeed`, a pure function that returns to your app the seed your app then passes to the constructor. It keeps nothing.
- `deriveTenantId` also reads the seed, keeps nothing and returns only the public tenant id.
- The storage holds no secret: only records, counters and indexes. Losing it does not leak keys.
- The SDK never sees the mnemonic or the BIP39 seed beyond that one call, and draws no randomness of its own.

## The operator token is a backend secret

Registering a tenant takes the LSP's operator token, which can admit any tenant. It belongs on your backend, never in a mobile or web app. The device only signs its registration; the backend checks the signature and the timestamp window with `verifyTenantRegistration`, then registers it with `LspOperatorClient`, which keeps the token in a private field and checks that the node's answer names the right tenant. The device then receives a per-tenant access token (`setBiscuitToken`) that reaches only its own channels. See [Register a tenant](/docs/guides/register-a-tenant).

## The watchtower takes trust

After a force close, the device signs the watchtower's spends only to the destination you approve, and only up to the fee you approve. Without an approval, nothing is signed and the funds stay in the commitment's cell.

Today, Fiber's watchtower pays only the LSP node's own lock. Approving it is trusting the LSP to pay the funds on to your user after a force close. Decide that with your users in mind. See [Watchtower](/docs/concepts/watchtower).

## What the device does not check

- **The funding inputs.** The device cannot read the chain, so it checks the funding cell it asked for, not what the inputs spend or the change. Your funding signer must check those before it signs.
- **Timelocks and preimages in the watchtower's spends.** The chain enforces them; a spend that breaks them is refused by the chain, and its signature costs nothing.
- **Payment proofs.** `PAYMENT_SENT` is the node's report.

## Learn more

- [policy.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/policy.md): every check, in order.
- [signing.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/signing.md): the nonces, the two-session bound and the watchtower's trust.
- [persistence.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/persistence.md): what the storage holds and why it must not roll back.
