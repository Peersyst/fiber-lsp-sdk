---
title: Quickstart
description: Run a Fiber LSP SDK wallet end to end, from the master seed to a closed channel, in one page.
---

# Quickstart

This page takes a wallet from nothing to a closed channel: derive the seed, build the SDK, register with the LSP, open a channel, receive, pay and close. Each step is short and links to the guide that covers it in depth.

:::warning[Pre-release, with known limits]
The SDK is at 0.0.0. With Fiber's current nonce lifecycle a channel stops at the settlement of a payment it sends (step 8) and at a second payment received, and the node then force-closes it. Read [Status and known limitations](/docs/resources/status) first.
:::

## Before you start

You need:

- the package installed ([Installation](/docs/get-started/installation));
- the URL of the LSP's Fiber node RPC and the LSP node's 33-byte public key, from the LSP operator;
- a backend endpoint that registers tenants (step 4 shows its code);
- a CKB wallet that can sign the inputs of a funding transaction, and the lock script of its address.

## 1. Derive the master seed

The SDK never sees the mnemonic. Your wallet expands the mnemonic into its 64-byte BIP39 seed as it already does, and `deriveMasterSeed` turns that into the 32 bytes the SDK is built from.

```ts title="seed.ts"
import { deriveMasterSeed } from "@peersyst/fiber-lsp-sdk";

// bip39Seed: the 64-byte seed your wallet already expands from the mnemonic
const masterSeed = deriveMasterSeed(bip39Seed);
```

The same mnemonic always gives the same master seed, so every channel key can be recovered from it. See [Keys and recovery](/docs/concepts/keys-and-recovery).

## 2. Provide a storage

The SDK keeps its signing records in a key-value store you provide. For a first try, an in-memory `Map` is enough:

```ts title="storage.ts"
import type { ISignerStorage } from "@peersyst/fiber-lsp-sdk";

// For trying the SDK only: everything is lost when the process exits.
const memory = new Map<string, string>();
const storage: ISignerStorage = {
    get: (key) => memory.get(key) ?? null,
    set: (key, value) => {
        memory.set(key, value);
    },
};
```

:::danger[For trying only]
Never ship an in-memory storage. The records it holds are what stop the device from signing twice, and a real store must survive restarts and must never be restored to an older state. See [Storage](/docs/concepts/storage).
:::

## 3. Construct the SDK

```ts title="sdk.ts"
import { FiberLspSdk } from "@peersyst/fiber-lsp-sdk";

const sdk = new FiberLspSdk(masterSeed, {
    network: "testnet",
    rpcUrl: "https://lsp.example.com/rpc",
    lspPubkey, // the LSP node's public key, 33 bytes
    storage,
    nonceReuse: "allow", // needed with Fiber's current nonce lifecycle, see Status
});

const unsubscribe = sdk.onEvent((event) => {
    if (event.type === "ERROR") console.error(event.error.code, event.error.message);
    if (event.type === "SIGNING" && event.outcome === "refused") console.warn("refused", event.error.code);
});
```

Construction checks every option and connects nothing. `nonceReuse: "allow"` is required today: without it, no channel can open against Fiber's current nodes. Every option is listed in [Options](/docs/reference/options), and every event in [Events](/docs/reference/events).

## 4. Register as a tenant

The device signs a registration, your backend registers it with the LSP node, and the device gets back its access token.

```ts title="register.ts"
const requestId = crypto.getRandomValues(new Uint8Array(32)); // fresh for every attempt
const signedAtMs = BigInt(Date.now());
const registration = sdk.signTenantRegistration({ requestId, signedAtMs });

// Your own backend endpoint: it holds the operator token, registers the tenant and returns its access token.
const response = await fetch("https://wallet-backend.example.com/register-tenant", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
        rootSignerPubkey: Array.from(registration.rootSignerPubkey),
        requestId: Array.from(registration.requestId),
        signedAtMs: registration.signedAtMs.toString(),
        signature: Array.from(registration.signature),
    }),
});
const { accessToken } = (await response.json()) as { accessToken: string };

sdk.setBiscuitToken(accessToken);
sdk.connect(); // start polling the node
```

On the backend, `LspOperatorClient` makes the call that needs the operator token. Check the timestamp window and the signature first:

```ts title="backend/register-tenant.ts"
import {
    LspOperatorClient,
    TENANT_REGISTRY_MAX_SIGNED_AT_AGE_MS,
    TENANT_REGISTRY_MAX_SIGNED_AT_FUTURE_SKEW_MS,
    verifyTenantRegistration,
} from "@peersyst/fiber-lsp-sdk";

const operator = new LspOperatorClient({
    rpcUrl: "https://lsp.example.com/rpc",
    operatorToken: process.env.LSP_OPERATOR_TOKEN ?? "",
});

const now = BigInt(Date.now());
const { signedAtMs } = registration;
if (signedAtMs < now - TENANT_REGISTRY_MAX_SIGNED_AT_AGE_MS || signedAtMs > now + TENANT_REGISTRY_MAX_SIGNED_AT_FUTURE_SKEW_MS) {
    throw new Error("stale registration");
}
if (!verifyTenantRegistration(lspPubkey, registration)) throw new Error("invalid registration");

const { tenantId, accessToken } = await operator.registerTenant(registration);
// Send accessToken back to the device.
```

`connect()` starts the poller, which reads the node every two seconds by default and answers its signing requests. Call it once the token is set, so the first polls are not refused. Details in [Register a tenant](/docs/guides/register-a-tenant).

## 5. Open a channel

`openChannel` asks the node for a channel to the LSP, checks the node's answer, and calls your funding signer with the unsigned funding transaction. Your wallet checks what its inputs pay and returns the witnesses.

```ts title="open.ts"
const channelReady = new Promise<string>((resolve) => {
    const stop = sdk.onEvent((event) => {
        if (event.type === "CHANNEL_READY") {
            stop();
            resolve(event.channelId);
        }
    });
});

// 1,000 CKB in shannons (1 CKB = 100,000,000 shannons), the reserve included
const channelId = await sdk.openChannel("100000000000", userLock, (unsignedFundingTx) =>
    // Your wallet checks what the inputs pay, then signs them: one witness per position.
    wallet.signFundingWitnesses(unsignedFundingTx),
);
```

`userLock` is a `Script`: the lock whose cells fund the channel, and where your side of every close is paid back. Amounts are always decimal strings of shannons. See [Open a channel](/docs/guides/open-a-channel).

## 6. Wait for the channel to be ready

`openChannel` resolves once the node took the signed funding transaction. The channel is usable once the funding is confirmed on chain, which the poller reports as `CHANNEL_READY`:

```ts title="open.ts"
await channelReady;
console.log("channel ready", channelId);
```

## 7. Receive a payment

`createInvoice` creates a hold invoice that only this device can settle. The poller settles it once the device's channel holds the payment.

```ts title="receive.ts"
const { invoice, paymentHashHex } = await sdk.createInvoice("250000000", { description: "coffee" });
console.log("show this to the payer:", invoice);

sdk.onEvent((event) => {
    if (event.type === "PAYMENT_RECEIVED" && event.paymentHashHex === paymentHashHex) console.log("paid");
});
```

The device must be connected for the payment to settle. See [Receive a payment](/docs/guides/receive-a-payment).

## 8. Send a payment

`transfer` decodes and checks the invoice, records the budget it approves (the amount plus a fee bound, 0.5% by default), and asks the node to pay it through the LSP.

```ts title="send.ts"
sdk.onEvent((event) => {
    if (event.type === "PAYMENT_SENT") console.log("sent", event.paymentHashHex);
    if (event.type === "PAYMENT_FAILED") console.log("failed", event.paymentHashHex, event.reason);
});

const payment = await sdk.transfer(invoiceToPay);
console.log("sending", payment.paymentHashHex, "fee budget", payment.maxFeeShannons);
```

:::warning[Stops under Fiber's current nonces]
Today the settlement of a payment the device sends asks for a third signature under one nonce, which the device always refuses. The payment stays in flight and the node force-closes the channel about 30 seconds later. To try step 9, run it on a channel that has not sent a payment. See [Status and known limitations](/docs/resources/status).
:::

See [Send a payment](/docs/guides/send-a-payment).

## 9. Close the channel and disconnect

`closeChannel` asks the node for a cooperative close that pays your side back to `userLock`. `CHANNEL_CLOSED` follows once the close is confirmed.

```ts title="close.ts"
sdk.onEvent((event) => {
    if (event.type === "CHANNEL_CLOSED" && event.channelId === channelId) console.log("closed");
});
await sdk.closeChannel(channelId);

// Later, when the app goes to the background:
sdk.disconnect();
```

`disconnect()` stops the poller; `connect()` starts it again. Call them when your app goes to the background and comes back. See [Close a channel](/docs/guides/close-a-channel) and [Backgrounding](/docs/guides/backgrounding).

## Next steps

- [Events and errors](/docs/guides/events-and-errors): what to show the user for each event and error code.
- [No blind signing](/docs/concepts/no-blind-signing): what the device checks before it signs.
- [Runtimes](/docs/get-started/runtimes): what changes on React Native and in browsers.
