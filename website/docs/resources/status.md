---
title: Status and known limitations
sidebar_label: Status
description: Where the Fiber LSP SDK stands today, which upstream Fiber it targets, and the limitations you will hit.
---

# Status and known limitations

The SDK is pre-release and tracks a Fiber feature that is still under review. This page says plainly what works today, what stops, and why, so you can plan around it.

## Version and API

The package is at **version 0.0.0**. The public API is not settled: names, options and behaviors may change between releases without a deprecation period. Pin an exact version if you build on it now.

## The Fiber it targets

The SDK targets the head of Fiber's hosted-LSP pull request, [nervosnetwork/fiber#1623](https://github.com/nervosnetwork/fiber/pull/1623), at commit `d8dd6d28`. That PR is where the tenant API, the polled signing protocol and the watchtower's spends come from. Its key derivation is byte for byte the one of Fiber `v0.9.0-rc7`.

Until the PR is merged and released, a node you talk to must run that code. When it changes, the SDK follows; see [Compatibility](/docs/resources/compatibility).

## Fiber's current nonce lifecycle

This is the limitation you will notice first.

The device uses deterministic nonces: each signing slot of a channel has exactly one nonce. That is safe as long as each slot signs one message. Fiber's current lifecycle asks for **two** signatures on some slots: at the channel's opening, in each round the peer starts, and in each revocation round.

- With the default, `nonceReuse: "refuse"`, the second one is refused, so **no channel can open** against Fiber today.
- With `nonceReuse: "allow"`, a slot serves a second signature and never a third. Two signatures under one nonce still hide the key; three would reveal the channel's funding key, so the device refuses the third in either mode. Each second signature is reported as a `SIGNING` event with `outcome: "warning"`.

Even under `"allow"`, a round the peer starts right after one of the device's own asks for a third signature on one slot. So two flows stop:

| Flow                                                         | What happens                                                                 |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| The settlement of a payment the device sends                 | The device refuses the third signature; the payment stays in flight          |
| A second payment received, after one the device has fulfilled | The device refuses the third signature; the payment is not settled           |

In both cases Fiber's node force-closes the channel once the round has stayed incomplete for 30 seconds (about 30 to 33 seconds in tests on a development chain). Opening a channel and receiving the first payment on it work.

:::info[What changes this]
The fix is on Fiber's side: giving each message its own nonce. When Fiber's nonces are strict, `nonceReuse: "allow"` goes away and both flows complete. Until then, `"allow"` is a compatibility mode you opt into knowingly.
:::

Learn more: [policy.md, "Nonce reuse under allow"](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/policy.md) and the scenarios in [e2e-agent.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/e2e-agent.md).

## The watchtower pays the LSP

After a force close, Fiber's watchtower builds the spends that move the device's funds out of the commitment, and the device signs them only toward a destination you approve (the `watchtower` option, or `setWatchtowerApproval`). Without an approval, every spend is refused and the funds stay in the commitment's cell.

Today the only destination Fiber's watchtower pays is **the LSP node's own lock**. Approving it means trusting the LSP after a force close: the funds go to the LSP's wallet, and reach your user only if the LSP pays them on. A destination the user chooses would close that gap; it is a proposal to Fiber that neither side implements yet. See [Watchtower](/docs/concepts/watchtower).

## What a restore cannot bring back

The keys always come back: every channel key re-derives from the mnemonic. The signing state does not. If the storage is lost:

- Every channel the node holds reads as unregistered, and the device refuses to sign for it. That is the safe side to fail on, but it means the device can no longer cooperate on those channels.
- A payment held on a hold invoice and not yet settled cannot be settled, because the index its preimage derives from was in the storage. The payment times out and goes back to the payer.
- A payment sent and still in flight loses its tracking, so no event reports how it ends. The node still knows it.
- The watchtower's spends of a force-closed channel are no longer signed, since the device no longer has the commitments they start from.
- A channel opening the node still holds blocks a new one until Fiber aborts it unfunded (five minutes by default).

**Rebuilding that state is not implemented.** Restoring a storage from an older backup is worse than losing it, because it can make the device sign twice; see [Security](/docs/resources/security).

Learn more: [persistence.md, "Recovery"](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/persistence.md).

## Polling, not WebSocket

Fiber's node can push signing requests over WebSocket subscriptions. The SDK does not use them: it polls the node's JSON-RPC over plain HTTP `POST`, every two seconds by default (`pollIntervalMs`). Polling only runs while you are connected (`connect()`), so the device answers requests only while your app is in the foreground. See [Poller and events](/docs/concepts/poller-and-events).

## Not supported

These are out of scope today, by design:

- Keysend, UDT (token) channels, multi-path payments and invoices without an amount.
- A proof of payment: `PAYMENT_SENT` is the node's word.
- A payment history: the SDK reports what it is tracking; past payments are the node's.
- Automatic retries of operations: a retry is your identical call.

## See also

- [Security](/docs/resources/security)
- [FAQ](/docs/resources/faq)
