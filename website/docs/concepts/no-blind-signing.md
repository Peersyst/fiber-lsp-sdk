---
title: No blind signing
description: How the device rebuilds every message Fiber asks it to sign, the policy checks it runs first, and what a refusal looks like to your app.
---

# No blind signing

The node prepares everything the device signs, and the node is not the device's friend. So the SDK never signs a hash it was handed: it rebuilds each message from its contents, checks it against what the user approved, and refuses anything else.

## What Fiber asks the device to sign

A signing request from the node carries the **plaintext** of what is to be signed, not just a digest: the transaction, the TLCs (pending payments) it lists, the balances, the fee rate, the scripts. Fiber signs four kinds of message, and the SDK rebuilds each one the way Fiber builds it:

| Message | When | What the device rebuilds |
| --- | --- | --- |
| **Commitment** | Every change of a channel's state: a payment added, settled or failed. The device signs both the peer's commitment and its own | The commitment transaction, from the balances, TLCs, keys and fee in the request |
| **Revocation** | After each new commitment, to give up the old one | The punishment output that makes broadcasting the old state costly |
| **Cooperative close** | A close either side asked for | The closing transaction, from what it pays each side |
| **Channel announcement** | Never, in practice | Tenant channels are private, so the device refuses every announcement request |

If the message the node says it wants signed differs from the one the device rebuilt, by a single byte, the request is refused as `malformed`. The device also recomputes its own keys and nonces rather than taking the node's word for them, and checks the peer's half of the signature on the steps that complete a round.

## The checks, in order

Once the message is rebuilt, the policy decides. Every check runs before anything is written, so a refused request leaves storage exactly as it was.

1. **Known channel.** The request names a channel this device opened and keeps a record of. Otherwise: `unknown_channel`.
2. **The message matches.** The rebuilt message equals the one requested. Otherwise: `malformed`.
3. **Sign-once.** This signing slot is free, or was already used for this exact session (then the device answers with the same signature again). Otherwise: `policy_refusal`. See [Sign-once](#sign-once).
4. **No going back.** Each new commitment comes after the last one signed in its view, and a revocation only after its replacement was signed. Otherwise: `stale_state`.
5. **The channel's constants hold.** The values fixed at the opening (the funding output, the peer's keys, the delay, the fee rate, the reserves, the close scripts) are the same as always, and fees stay within their bounds (at most 0.5 CKB for a commitment, 1 CKB for the device's share of a close). Otherwise: `policy_refusal`.
6. **The balance rule.** Money leaves the device's side only under a payment the user approved, up to its amount plus fee budget, and the device's balance only falls by what such a payment actually took. Otherwise: `policy_refusal`.

The balance rule is what ties signing to your app. When the user pays an invoice with [`transfer`](/docs/guides/send-a-payment), the SDK records a budget (the amount plus a fee bound) before it asks the node to pay. A commitment that sends more than that budget, or sends money under a payment hash nobody approved, is refused. A payment the device receives is protected the same way: the preimage of a hold invoice is released only once the device's channels hold the payment, and from then on every commitment must pay it.

:::info[Checked before the node even asks]
The same idea runs through the rest of the SDK. An opening is checked against what you asked for before the funding transaction reaches your signer (`opening_rejected`), an invoice the node created is checked against what you asked (`invoice_rejected`), and a close whose fee would exceed the bound is refused before the node is called (`close_fee_too_high`). See [Errors](/docs/reference/errors).
:::

## Sign-once

The device's musig2 nonces are deterministic: each one is derived from the master seed and a **slot** (the channel, the commitment number and the kind of message). That is what makes the signer recoverable and its answers repeatable, and it comes with one hard rule.

A partial signature is a linear equation in the device's secret nonce and its funding key. Two equations under one nonce still hide the key, but three can be solved for the **funding key**. So the SDK keeps a persisted registry of every slot it has signed, and it follows two rules:

- **The claim is written before the signature is made.** A crash between signing and recording can never leave a slot looking free.
- **A repeat of the same session gets the same bytes.** If the node asks again with the identical keys, aggregated nonce and message (after a lost answer, say), the device signs again and, because the nonce is deterministic, produces the identical signature. Nothing new is revealed.

That registry is the reason your storage must never go back in time. See [Storage](/docs/concepts/storage#never-older-than-it-was).

## The `nonceReuse` mode

Fiber's current nonce handling asks the device for a **second** signature on some slots: on the opening of a channel, on each round the peer starts, and on each revocation round. Under the default, `nonceReuse: "refuse"`, those second requests are refused, and no channel can open against Fiber as it is today.

`nonceReuse: "allow"` is a compatibility mode for that. It lets a slot serve one more session, never two:

- The second session passes every other check, as a first one does.
- It is reported as a `SIGNING` event with `outcome: "warning"`, on every delivery of it.
- A third session on the same slot is refused in either mode, because three signatures under one nonce reveal the funding key.

```ts title="wallet.ts"
import { FiberLspSdk } from "@peersyst/fiber-lsp-sdk";

const sdk = new FiberLspSdk(masterSeed, {
    network: "testnet",
    storage,
    rpcUrl: "https://lsp.example.com/rpc",
    lspPubkey,
    nonceReuse: "allow", // needed against Fiber today; remove it once Fiber's nonces are strict
});
```

:::warning[The known cost]
Even with `"allow"`, a round the peer starts right after one of the device's own asks for a third signature on one slot, and that is refused. In practice the channel cannot complete the settlement of a payment the device **sent**, nor a payment **received** after one it settled, and Fiber force-closes the channel some 30 seconds later. This goes away when Fiber gives each message its own nonce. See [Status](/docs/resources/status).
:::

## What a refusal looks like

A refused request is never submitted. It stays pending on the node, and your app hears about it through a `SIGNING` event with `outcome: "refused"`:

```ts title="signing-events.ts"
sdk.onEvent((event) => {
    if (event.type !== "SIGNING") return;
    switch (event.outcome) {
        case "signed":
            break;
        case "warning":
            // Signed as the second session of a slot, under nonceReuse: "allow".
            console.warn("nonce reused", event.channelId, event.transition);
            break;
        case "refused":
            // event.error is { code, message }: unknown_channel, malformed, stale_state or policy_refusal.
            console.error("refused", event.channelId, event.requestId, event.error.code, event.error.message);
            if (event.deadlineMs !== undefined) {
                console.error("fiber force-closes the channel by", new Date(event.deadlineMs).toISOString());
            }
            break;
    }
});
```

The event's `error` is a [`SignerRefusal`](/docs/api/type-aliases/SignerRefusal): a `code` from [`SIGNER_ERROR_CODES`](/docs/api/variables/SIGNER_ERROR_CODES) and a `message` that names what failed (never a key).

| Code | Meaning |
| --- | --- |
| `unknown_channel` | The request names a channel this device has no record of |
| `malformed` | The request cannot be read, or its message is not the one the device rebuilt |
| `stale_state` | The request would sign an older state than one already signed |
| `policy_refusal` | A slot already used, a constant of the channel changed, a fee out of bounds, a payment nobody approved, or an announcement |

A few things to know when you show these to a user:

- **A refusal is told once** per channel, request id and code, for the life of the SDK instance, although the device refuses it again on every tick while the node keeps it pending. A refusal with `requestId: null` (a status that could not be read at all) is told on every tick.
- **`deadlineMs`**, when present, is when Fiber force-closes the channel if the request stays unanswered. It is an upper bound, for display only: the SDK never acts on it.
- **A refusal is not an outage.** A storage failure or a bug is not a refusal: it surfaces as an `ERROR` event with code `poll_failed` (see [The poller and events](/docs/concepts/poller-and-events#what-error-means)).

The watchtower's spends after a force close follow rules of their own and report through `WATCHTOWER_SIGNING`; see [The watchtower](/docs/concepts/watchtower).

## Learn more

- [Events](/docs/reference/events) lists every event and its payload.
- The message constructions, byte by byte: [`docs/digest.md`](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/digest.md).
- Every check, with its reasoning: [`docs/policy.md`](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/policy.md).
- The signer and the nonce math: [`docs/signing.md`](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/signing.md).
