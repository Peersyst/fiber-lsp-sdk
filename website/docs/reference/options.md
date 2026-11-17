---
title: Options
description: Every option of FiberLspSdk and LspOperatorClient, the network presets, the per-call options and the FiberLspSdk method list.
---

# Options

Everything you can pass to `FiberLspSdk`, `LspOperatorClient` and their methods, with the defaults and the error you get when a value is refused. The generated [API reference](/docs/api) has the full signatures.

:::info[Pre-release]
The SDK is version 0.0.0 and its public API is not settled. Names and defaults on this page can change before the first release. See [Project status](/docs/resources/status).
:::

## `FiberLspSdkOptions`

The second argument of `new FiberLspSdk(masterSeed, options)`. The first is the 32-byte master seed (from [`deriveMasterSeed`](/docs/api/functions/deriveMasterSeed)); anything else is a `TypeError` (`masterSeed must be 32 bytes, got N`), checked before the options.

```ts title="wallet.ts"
import { FiberLspSdk, type FiberLspSdkOptions, type ISignerStorage } from "@peersyst/fiber-lsp-sdk";

const options: FiberLspSdkOptions = {
    network: "testnet",
    storage, // your ISignerStorage or IAsyncSignerStorage
    rpcUrl: "https://lsp.example.com/rpc",
    biscuitToken: tenantToken,
    lspPubkey, // the LSP node's 33-byte compressed key
    pollIntervalMs: 2_000,
};

const sdk = new FiberLspSdk(masterSeed, options);
sdk.connect();
```

Every option is checked in the constructor, so a misconfigured instance never gets built. Nothing touches the network or the storage until you call `connect()` (or an operation).

| Option | Type | Required | Default | Refused with |
| --- | --- | --- | --- | --- |
| [`network`](/docs/api/type-aliases/FiberLspSdkOptions#network) | `"mainnet"` \| `"testnet"` \| [`SdkNetworkConfig`](#sdknetworkconfig) | Yes | None | `TypeError`: `network must be one of mainnet, testnet`, or `network must be a network name or an object`; a config's own fields as listed [below](#sdknetworkconfig) |
| [`storage`](/docs/api/type-aliases/FiberLspSdkOptions#storage) | [`ISignerStorage`](/docs/api/interfaces/ISignerStorage) \| [`IAsyncSignerStorage`](/docs/api/interfaces/IAsyncSignerStorage) | Yes | None (no store is shared by every runtime) | `TypeError`: `storage must be an object`, `storage.get must be a function`, `storage.set must be a function` |
| [`rpcUrl`](/docs/api/type-aliases/FiberLspSdkOptions#rpcurl) | `string` | Yes | None | `TypeError`: `rpcUrl must be a non-empty string` |
| [`biscuitToken`](/docs/api/type-aliases/FiberLspSdkOptions#biscuittoken) | `string` | No | No `authorization` header | `TypeError`: `token must be printable ASCII without spaces` |
| [`lspPubkey`](/docs/api/type-aliases/FiberLspSdkOptions#lsppubkey) | `Uint8Array` | Yes | None | `TypeError`: `lspPubkey must be 33 bytes, got N`, or `lspPubkey must be a compressed point on secp256k1` |
| [`fetch`](/docs/api/type-aliases/FiberLspSdkOptions#fetch) | [`IFetchLike`](/docs/api/interfaces/IFetchLike) | No | The runtime's global `fetch`, read once at construction | `TypeError`: `fetch must be a function`; with no global: `this runtime has no fetch: pass one in the options` |
| [`timer`](/docs/api/type-aliases/FiberLspSdkOptions#timer) | [`ITimer`](/docs/api/interfaces/ITimer) | No | The runtime's `setTimeout` and `clearTimeout`, read once at construction | `TypeError`: `timer must be an object`, `timer.schedule must be a function`; with no globals: `this runtime has no timer: pass one in the options` |
| [`now`](/docs/api/type-aliases/FiberLspSdkOptions#now) | `() => number` | No | `Date.now` | `TypeError`: `now must be a function` |
| [`pollIntervalMs`](/docs/api/type-aliases/FiberLspSdkOptions#pollintervalms) | `number` | No | `2000` ([`DEFAULT_POLL_INTERVAL_MS`](/docs/reference/constants#default_poll_interval_ms)) | `RangeError`: `pollIntervalMs must be an integer between 1 and 2147483647, got N` |
| [`nonceReuse`](/docs/api/type-aliases/FiberLspSdkOptions#noncereuse) | `"refuse"` \| `"allow"` | No | `"refuse"` | `TypeError`: `options.nonceReuse must be one of refuse, allow` |
| [`watchtower`](/docs/api/type-aliases/FiberLspSdkOptions#watchtower) | [`SdkWatchtowerOptions`](#sdkwatchtoweroptions) | No | None: every watchtower spend is refused | As listed [below](#sdkwatchtoweroptions), prefixed `options.watchtower.` |

Notes on each option:

- **`network`**: a preset name or a full config for a development chain. The preset values are [below](#the-two-presets).
- **`storage`**: a string key-value store the SDK persists its signing records in. It must persist across app restarts. See [Storage](/docs/concepts/storage).
- **`rpcUrl`**: the JSON-RPC address of the LSP's Fiber node. Any non-empty string is accepted; the URL is not parsed.
- **`biscuitToken`**: the tenant's access token, sent as `authorization: Bearer <token>`. Leave it out until the tenant is registered, then call `setBiscuitToken`. A hosted node with auth on refuses every call without one, so a missing token shows up at the first call, not at construction.
- **`lspPubkey`**: the LSP node's public key, the peer every channel opens to. It is copied, so changing your array afterwards has no effect.
- **`fetch`**, **`timer`**, **`now`**: the injected effects. Bare functions are called without a receiver, and the storage and the timer as methods of your own object. See [Runtimes](/docs/get-started/runtimes).
- **`pollIntervalMs`**: the pause between the end of one poll tick and the start of the next. Ticks never overlap. `null` is refused like any non-integer.
- **`nonceReuse`**: whether a signing slot that already served one session may serve a second (never a third). See the warning below.
- **`watchtower`**: what the device may sign a watchtower's spend for after a force close. Held in memory only, so set it again at every start. See [Watchtower](/docs/concepts/watchtower).

:::warning[`nonceReuse` and Fiber today]
Fiber's current nonce lifecycle asks for a second signing session on some slots. Under the default `"refuse"`, no channel opens against Fiber today; a host that must work with it now sets `"allow"`. Even under `"allow"`, some rounds ask for a third session, which is always refused, and Fiber then force-closes the channel. The mode goes away once Fiber's nonces are strict. See [Project status](/docs/resources/status).
:::

## `SdkNetworkConfig`

Pass an object instead of `"mainnet"` or `"testnet"` to run against a development chain. All five fields are required.

```ts title="devnet.ts"
import type { SdkNetworkConfig } from "@peersyst/fiber-lsp-sdk";

// The two code hashes (32 bytes each) come from your devnet node's config.
const devnet: SdkNetworkConfig = {
    commitmentLock: { codeHash: commitmentLockCodeHash, hashType: "data1" },
    fundingLock: { codeHash: fundingLockCodeHash, hashType: "data1" },
    invoiceCurrency: "Fibd",
    fundingLockCellDepsCount: 2,
    // A node built in debug mode uses 2-second epochs.
    millisecondsPerEpoch: 2_000,
};
```

| Field | Type | Meaning | Refused with |
| --- | --- | --- | --- |
| `commitmentLock` | `ScriptTemplate` (`{ codeHash, hashType }`) | The commitment lock of the chain's Fiber deployment | `TypeError`: `network.commitmentLock must be an object`, `network.commitmentLock.codeHash must be 32 bytes, got N`, `network.commitmentLock.hashType must be one of data, type, data1, data2` |
| `fundingLock` | `ScriptTemplate` | The funding lock. A template only: each channel's args are computed from the two funding keys | The same messages, under `network.fundingLock` |
| `invoiceCurrency` | `"Fibb"` \| `"Fibt"` \| `"Fibd"` | The currency the chain's invoices carry | `TypeError`: `network.invoiceCurrency must be one of Fibb, Fibt, Fibd` |
| `fundingLockCellDepsCount` | `number` | The funding lock's cell deps. Fiber counts them into the commitment fee although the commitment tx carries none, so the device cannot read it from what it signs | `RangeError`: `network.fundingLockCellDepsCount must be an integer between 1 and 255, got N` |
| `millisecondsPerEpoch` | `number` | Fiber's `MILLI_SECONDS_PER_EPOCH`, which the node's build sets: 4 hours in release, 2 seconds in debug. It feeds the signing deadline and the margin of a hold invoice's release | `RangeError`: `network.millisecondsPerEpoch must be an integer between 1 and 9007199254740991, got N` |

Both code hashes are copied, so the bytes cannot change under the SDK afterwards.

## The two presets

`"mainnet"` and `"testnet"` resolve to these values (from `src/sdk/sdk.constants.ts` and `src/digest/digest.constants.ts`):

| Field | `"mainnet"` | `"testnet"` |
| --- | --- | --- |
| `commitmentLock.codeHash` | `0x2d45c4d3ed3e942f1945386ee82a5d1b7e4bb16d7fe1ab015421174ab747406c` | `0x740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8` |
| `commitmentLock.hashType` | `"type"` | `"type"` |
| `fundingLock.codeHash` | `0xe45b1f8f21bff23137035a3ab751d75b36a981deec3e7820194b9c042967f4f1` | `0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c` |
| `fundingLock.hashType` | `"type"` | `"type"` |
| `invoiceCurrency` | `"Fibb"` | `"Fibt"` |
| `fundingLockCellDepsCount` | `2` (the lock's code cell and the auth library's) | `2` |
| `millisecondsPerEpoch` | `14400000` (4 h, a release build) | `14400000` |

The locks are the ones Fiber ships in its node config for each chain. See [Networks](/docs/concepts/networks) for when to use which.

## `SdkWatchtowerOptions`

What you approve the watchtower's spends for, passed as the `watchtower` option or later through [`setWatchtowerApproval`](/docs/api/classes/FiberLspSdk#setwatchtowerapproval).

| Field | Type | Meaning | Refused with |
| --- | --- | --- | --- |
| `destination` | `Script` | The lock every spend must pay | `TypeError` naming `options.watchtower.destination` (or `approval.destination`), e.g. `... must be an object`, `....codeHash must be 32 bytes, got N` |
| `maxFeeShannons` | `string` (decimal shannons) | How far below what an unlock releases the destination may be paid | `TypeError`: `... must be a string` or `... must be an amount in decimal shannons`; `RangeError` above `18446744073709551615`, the most a CKB cell's capacity holds |

The approval is copied. A refused `setWatchtowerApproval` throws and leaves the previous approval in force; nothing removes an approval once given.

:::warning[The only destination Fiber pays today]
Fiber's watchtower pays every spend to the LSP node's own lock. Approving that destination means trusting the LSP to pass the funds on after a force close. Without an approval, the funds stay in the commitment lock's cell. See [Watchtower](/docs/concepts/watchtower).
:::

## `LspOperatorClientOptions`

The options of `new LspOperatorClient(options)`, the operator's backend client that registers tenants. It never runs on a device.

```ts title="backend.ts"
import { LspOperatorClient } from "@peersyst/fiber-lsp-sdk";

const operator = new LspOperatorClient({ rpcUrl: "https://lsp.example.com/rpc", operatorToken });
const { tenantId, accessToken } = await operator.registerTenant(registration);
```

| Option | Type | Required | Default | Refused with |
| --- | --- | --- | --- | --- |
| `rpcUrl` | `string` | Yes | None | `TypeError`: `rpcUrl must be a non-empty string` |
| `operatorToken` | `string` | Yes | None | `TypeError`: `operatorToken must be printable ASCII without spaces` |
| `fetch` | [`IFetchLike`](/docs/api/interfaces/IFetchLike) | No | The runtime's global `fetch` | `TypeError`: `fetch must be a function` |

A non-object `options` is a `TypeError` (`options must be an object`). The operator token grants `lsp_register_tenant`: it is a backend secret and must never reach a device. See [Register a tenant](/docs/guides/register-a-tenant).

## Per-call options

Each is optional, and so is every field. A non-object is a `TypeError` (`options must be an object`).

### `SdkInvoiceOptions`

Second argument of [`createInvoice`](/docs/api/classes/FiberLspSdk#createinvoice).

| Field | Type | Default | Refused with |
| --- | --- | --- | --- |
| `description` | `string` | No description | `TypeError` if not a string or not well-formed Unicode; `RangeError`: `options.description must be at most 639 bytes of UTF-8, got N` |
| `expirySeconds` | `number` (whole seconds) | `3600` (one hour) | `RangeError`: `options.expirySeconds must be an integer between 1 and 9007199254740991, got N` |

The SDK always sends an expiry: Fiber has no default, and a tenant's invoice without one fails after it is stored.

### `SdkTransferOptions`

Second argument of [`transfer`](/docs/api/classes/FiberLspSdk#transfer).

| Field | Type | Default | Refused with |
| --- | --- | --- | --- |
| `maxFeeShannons` | `string` (decimal shannons, `"0"` allowed) | Fiber's 0.5% of the amount, rounded up: `ceil(amount * 5 / 1000)`, which is also Fiber's cap | `TypeError`: `options.maxFeeShannons must be an amount in decimal shannons`; `RangeError` when it adds up with the amount past a u128 |

:::note
Under trampoline routing, to any payee but the LSP itself, a budget below `ceil(amount / 1000)` fails the route.
:::

### `SdkCloseOptions`

Second argument of [`closeChannel`](/docs/api/classes/FiberLspSdk#closechannel).

| Field | Type | Default | Refused with |
| --- | --- | --- | --- |
| `feeRate` | `bigint` (shannons per kilobyte) | The channel's commitment fee rate, which Fiber refuses to go below | `RangeError`: `options.feeRate must be a bigint between 0 and 18446744073709551615, got N` (a non-bigint included) |

A rate whose fee on the close is above 1 CKB is refused as `close_fee_too_high` (see [Errors](/docs/reference/errors#sdk_error_codes)).

## `FiberLspSdk` methods

| Member | What it does | Returns |
| --- | --- | --- |
| [`tenantId`](/docs/api/classes/FiberLspSdk#tenantid) | The tenant id Fiber derives from the device's root signer key (getter) | `string`, 64 lowercase hex characters |
| [`rootSignerPubkey`](/docs/api/classes/FiberLspSdk#rootsignerpubkey) | The root signer's public key, which `lsp_register_tenant` registers (getter) | `Uint8Array`, a copy of the 33-byte key |
| [`signTenantRegistration(request)`](/docs/api/classes/FiberLspSdk#signtenantregistration) | Signs the tenant registration for the LSP of `lspPubkey`, from your 32-byte `requestId` and `signedAtMs` | [`SdkTenantRegistration`](/docs/api/type-aliases/SdkTenantRegistration) |
| [`setBiscuitToken(token)`](/docs/api/classes/FiberLspSdk#setbiscuittoken) | Replaces the token the node's calls carry, from the next call on | `void` |
| [`setWatchtowerApproval(approval)`](/docs/api/classes/FiberLspSdk#setwatchtowerapproval) | Replaces the watchtower approval, then polls at once | `void` |
| [`prepareChannelOpen(amount, userLock, cellDeps?)`](/docs/api/classes/FiberLspSdk#preparechannelopen) | Opens a channel up to the unsigned funding tx, after checking and pinning the node's answer | `Promise<`[`SdkChannelOpening`](/docs/api/type-aliases/SdkChannelOpening)`>` |
| [`submitFundingTx(channelId, signedTx)`](/docs/api/classes/FiberLspSdk#submitfundingtx) | Hands the node the funding tx you signed, refusing one that is not the frozen tx | `Promise<void>` |
| [`openChannel(amount, userLock, signFundingInputs, cellDeps?)`](/docs/api/classes/FiberLspSdk#openchannel) | The two steps above in one call, with your signer in between | `Promise<string>`, the channel id |
| [`closeChannel(channelId, options?)`](/docs/api/classes/FiberLspSdk#closechannel) | Asks for a cooperative close once the device's fee is one it signs | `Promise<void>` |
| [`forceCloseChannel(channelId)`](/docs/api/classes/FiberLspSdk#forceclosechannel) | Asks the node to force-close a channel; needs no record on this device | `Promise<void>` |
| [`listChannels()`](/docs/api/classes/FiberLspSdk#listchannels) | Lists the node's channels, closed ones included | `Promise<`[`SdkChannelInfo`](/docs/api/type-aliases/SdkChannelInfo)`[]>` |
| [`channelEvidence(channelId)`](/docs/api/classes/FiberLspSdk#channelevidence) | Reads what the device keeps of a channel: revocations, last commitments, watchtower signatures | `Promise<`[`SdkChannelEvidence`](/docs/api/type-aliases/SdkChannelEvidence)`>` |
| [`createInvoice(amount, options?)`](/docs/api/classes/FiberLspSdk#createinvoice) | Creates a hold invoice only this device can settle | `Promise<`[`SdkInvoice`](/docs/api/type-aliases/SdkInvoice)`>` |
| [`cancelInvoice(paymentHashHex)`](/docs/api/classes/FiberLspSdk#cancelinvoice) | Cancels one of this device's hold invoices | `Promise<void>` |
| [`transfer(invoice, options?)`](/docs/api/classes/FiberLspSdk#transfer) | Pays an invoice through the LSP after checking it | `Promise<`[`SdkPayment`](/docs/api/type-aliases/SdkPayment)`>` |
| [`onEvent(listener)`](/docs/api/classes/FiberLspSdk#onevent) | Subscribes to every [event](/docs/reference/events) | `() => void`, which unsubscribes |
| [`connect()`](/docs/api/classes/FiberLspSdk#connect) | Starts polling the node (your app's foreground); a no-op while polling | `void` |
| [`disconnect()`](/docs/api/classes/FiberLspSdk#disconnect) | Stops polling (your app's background); never throws | `void` |

Amounts are decimal strings of shannons. Channel ids are 32 bytes of `0x`-prefixed lowercase hex, as the node names them.

## See also

- [Events](/docs/reference/events) and [Errors](/docs/reference/errors)
- [Constants](/docs/reference/constants)
- [Storage](/docs/concepts/storage) and [Runtimes](/docs/get-started/runtimes)
- [`FiberLspSdk` in the API reference](/docs/api/classes/FiberLspSdk)
