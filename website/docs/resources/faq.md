---
title: FAQ
description: Short answers to the questions wallet and LSP developers ask most about the Fiber LSP SDK.
---

# FAQ

Short answers to the questions that come up most when integrating the SDK, each with a link to the page that covers it in full.

## Does the LSP ever hold my users' keys?

No. The LSP runs the Fiber node, but every channel key derives on the device from the master seed, and no SDK method returns a private key. The node sends signing requests; the device rebuilds each message, checks it against its policy and answers with a partial signature. See [Security model](/docs/resources/security).

## Do I need to run a Fiber node?

Not as a wallet developer: the LSP runs it. As an LSP operator, you run a Fiber node with the hosted-LSP support of [fiber#1623](https://github.com/nervosnetwork/fiber/pull/1623), and a backend that registers tenants. See [Compatibility](/docs/resources/compatibility).

## Why do I have to set `nonceReuse: "allow"`?

Fiber's current nonce lifecycle asks for two signatures on some signing slots, and the default mode refuses the second, so no channel would open. `"allow"` serves a second signature and never a third, which keeps the key hidden. It is a compatibility mode that goes away once Fiber's nonces are strict. See [Status and known limitations](/docs/resources/status).

## Why was my channel force-closed after a payment?

Under Fiber's current nonces, the settlement of a payment the device sends, and a second payment received after one it fulfilled, each ask for a third signature on one slot. The device always refuses it, and Fiber force-closes the channel about 30 seconds later. This is a known limitation, described in [Status and known limitations](/docs/resources/status). A channel also gets force-closed if the device goes to the background in the middle of a signing round; see [Backgrounding](/docs/guides/backgrounding).

## Can I recover everything from the mnemonic?

The keys, yes: every channel key re-derives from the mnemonic. The signing state, no: it lives only in the storage, and rebuilding it is not implemented. Without it, the device refuses to sign for its old channels, and a payment held and not yet settled goes back to the payer. See [Keys and recovery](/docs/concepts/keys-and-recovery).

## What should I use for storage?

Any durable string key-value store with `get` and `set`, synchronous (`ISignerStorage`) or asynchronous (`IAsyncSignerStorage`): MMKV or SQLite on React Native, IndexedDB in a browser, a database on Node. It must never be restored to an older state, and only one SDK instance may use it at a time. See [Storage](/docs/concepts/storage).

## Can one storage serve several accounts?

No. One storage, or one key prefix of a shared store, serves one master seed. For several accounts, derive a master seed per account with `deriveMasterSeed(bip39Seed, accountIndex)` and give each its own storage. See [Keys and recovery](/docs/concepts/keys-and-recovery).

## Where does the operator token go?

On your backend, never in the app. The device signs its registration with `signTenantRegistration`, your backend checks it with `verifyTenantRegistration` and registers it with `LspOperatorClient`, and the device receives its own access token through `setBiscuitToken`. See [Register a tenant](/docs/guides/register-a-tenant).

## Can a hardware wallet or a backend sign the funding transaction?

Yes. `openChannel` takes a funding signer callback, but you can also split it: `prepareChannelOpen` returns the unsigned funding transaction, and `submitFundingTx` takes it back signed, whenever your signer is done. Either way, your signer must check what the inputs pay, since the device cannot read the chain. See [Open a channel](/docs/guides/open-a-channel).

## Does the SDK work while my app is in the background?

Only while it polls. The device reads the node and answers its requests on a timer between `connect()` and `disconnect()`, and mobile platforms pause or freeze timers in the background. A payment that arrives in the background waits for the next `connect()`, and a round left half done for about 30 seconds gets the channel force-closed. See [Backgrounding](/docs/guides/backgrounding).

## Why polling and not WebSocket?

The device reaches the node only through plain JSON-RPC over HTTP, which works the same in Node, browsers and React Native and needs no open connection. Fiber's WebSocket subscriptions are not used. The interval is `pollIntervalMs`, two seconds by default. See [Poller and events](/docs/concepts/poller-and-events).

## How do I show the user what they are about to pay?

Call `decodeInvoice(invoice)` before `transfer`: it reads the string on the device, with no call to the node, and returns its currency, amount, payment hash and attributes. `transfer` decodes and checks it again before paying. See [Decode an invoice](/docs/guides/decode-an-invoice).

## What units are amounts in?

Decimal strings of shannons, where 1 CKB is 100,000,000 shannons: `"250000000"` is 2.5 CKB. No `number` is used for on-chain amounts. The one exception is a CKB `Transaction`, whose output capacities are `bigint`. See [Options](/docs/reference/options).
