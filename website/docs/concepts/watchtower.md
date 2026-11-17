---
title: The watchtower
description: What Fiber's watchtower does with a force-closed channel, why it needs the device's signature, and how your app approves where the funds go.
---

# The watchtower

When a channel is force-closed, the device's funds land in an on-chain cell that only the device's keys can unlock. Fiber's watchtower, on the LSP's node, does the work of claiming them, but every spend still needs the device's signature, and the SDK signs only spends that pay a destination your app approved.

## What happens after a force close

A force close puts the channel's latest commitment transaction on chain. The device's share is not paid straight to the user: it sits in the commitment lock's cell, behind a delay, with any pending payments (TLCs) next to it.

Fiber's watchtower then takes that cell apart one piece per transaction: each TLC first, then the device's balance. Every spend but the last leaves the rest of the cell at its first output, and the next spend starts from there.

Each of those spends unlocks the device's part with a key only the device has: the per-commitment TLC key for a TLC, the TLC base key for the balance (never the funding key). So the watchtower publishes a request, the SDK's poller reads it in its [watchtower step](/docs/concepts/poller-and-events#the-five-steps-of-a-tick), checks it, signs it and hands the signature back.

These signatures are ordinary ECDSA with deterministic nonces derived from the message (RFC 6979), so, unlike musig2, signing many of them under one key leaks nothing. There is no sign-once rule here: a spend Fiber rebuilds is simply signed again.

## Refused by default

Without an approval, the SDK refuses every watchtower spend. The funds stay in the commitment cell, which is exactly where they would be with no watchtower at all. To let the spends through, give the SDK a destination and a fee bound, with the `watchtower` option:

```ts title="wallet.ts"
import { FiberLspSdk, type SdkWatchtowerOptions } from "@peersyst/fiber-lsp-sdk";

const approval: SdkWatchtowerOptions = {
    destination: lspLock, // every spend must pay this script
    maxFeeShannons: "100000", // at most 0.001 CKB below what each unlock releases
};

const sdk = new FiberLspSdk(masterSeed, {
    network: "testnet",
    storage,
    rpcUrl: "https://lsp.example.com/rpc",
    lspPubkey,
    watchtower: approval,
});

sdk.onEvent((event) => {
    if (event.type !== "WATCHTOWER_SIGNING") return;
    if (event.outcome === "refused") console.warn(event.channelId, event.requestId, event.error.code, event.error.message);
    else console.info("watchtower spend signed", event.channelId, event.purpose);
});

sdk.connect();
```

| Field | What it is |
| --- | --- |
| `destination` | A `Script`: the lock every spend must pay the released funds to |
| `maxFeeShannons` | Decimal shannons (a u64): how far below what an unlock releases the destination may be paid. The spend's fee is paid from the node's cells, which the device cannot see, so the device bounds it from its own side |

You can also set or replace the approval later with [`setWatchtowerApproval`](/docs/api/classes/FiberLspSdk#setwatchtowerapproval):

```ts title="approve.ts"
// In memory only: call it again on every start. It asks for a poll right away.
sdk.setWatchtowerApproval(approval);
```

- **It lives in memory.** Neither the option nor `setWatchtowerApproval` is persisted: set it again every time your app builds the SDK.
- **It can be replaced, not removed.** An invalid approval throws a `TypeError` or `RangeError` naming the field, and the previous one stays in force.
- **It takes effect at once.** Fiber keeps a refused spend pending, so the next tick, which `setWatchtowerApproval` triggers immediately, signs it.

## What the device checks

Before it signs, the SDK holds each spend to the channel's own record and to your approval:

- **It spends from a commitment the device signed**, or from what a previous spend of one left behind.
- **It uses the key the spend asks for**, and that unlock releases something to the device.
- **The remainder is exactly what Fiber's watchtower leaves**, so nothing else of the cell moves.
- **Every other output pays your `destination`**, with no type script and no data, and together they get at least what the unlock releases minus `maxFeeShannons`.
- **A request already signed is the same spend.**

What only the chain can tell (whether the delay has passed, whether a TLC has expired, whether a preimage is right) is left to the commitment lock: a spend that breaks one of those is rejected on chain, and its signature costs nothing.

:::note[A bound on the fee, not on every shannon]
When a spend starts from a remainder, the device does not know that cell's exact capacity. A dishonest node could understate it and burn the difference as fee. It can never redirect it: every output but the remainder pays your destination.
:::

## The trust this takes today

:::warning[Approving the watchtower trusts the LSP]
Fiber's watchtower pays every spend to **the LSP node's own lock**, and today it offers no way to name another destination. So the only destination you can approve and have signed is the LSP's lock: after a force close, the device's funds go to the LSP's wallet, and reach the user only if the LSP pays them on.

Letting the wallet choose the destination is a change on Fiber's side. It is proposed, not implemented. Until then, decide with your users whether to approve the LSP's lock, or to leave the funds in the commitment cell. See [Status](/docs/resources/status).
:::

Get the lock script from your LSP. If you approve any other destination, every spend is refused (`policy_refusal`, a message starting with `watchtower destination:`), and the funds stay where they are.

## The `WATCHTOWER_SIGNING` event

Every spend the step signs or refuses is reported as a `WATCHTOWER_SIGNING` event:

| Field | What it is |
| --- | --- |
| `channelId` | The channel being claimed |
| `requestId` | The node's request id, `0x` hex; `null` when the status could not be read at all |
| `purpose` | `{ kind: "settlement" }` for the device's balance, `{ kind: "tlc", commitmentNumber }` for a TLC; `null` with `requestId` |
| `outcome` | `"signed"` once the node took the signature, or `"refused"` |
| `error` | On `"refused"` only: `{ code, message }`, the same [signer codes](/docs/concepts/no-blind-signing#what-a-refusal-looks-like) as `SIGNING` |

Unlike `SIGNING`, a refusal is reported **on every tick** while the spend waits, and a signed spend can be announced again (when its submission is retried, or Fiber rebuilds it under a new request id). Deduplicate on `requestId`.

## When nothing can sign

The device signs only for channels it has a record of. A channel this device did not open, or one whose record was lost with the storage, is never signed for: its balance stays in the commitment cell, and the SDK has no other way to claim it today. That is also true of [`forceCloseChannel`](/docs/guides/close-a-channel) on a channel without a record: the node closes it, but nothing signs the spends that follow.

## Learn more

- [Close a channel](/docs/guides/close-a-channel): cooperative and forced closes.
- [Keys and recovery](/docs/concepts/keys-and-recovery#what-a-restore-does-not-bring-back): what a lost storage costs.
- The watchtower's rules and their reasoning: [`docs/policy.md`](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/policy.md) and [`docs/signing.md`](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/signing.md).
