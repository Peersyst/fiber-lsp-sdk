---
title: Networks
description: The mainnet and testnet presets the SDK ships, and how to describe a devnet or any other chain with a custom network config.
---

# Networks

The SDK has to know a few facts about the chain it signs for, and none of them can be read from what the node sends: a node that lied about them could make the device sign the wrong thing. You give them once, with the `network` option.

## The presets

For CKB's public chains, pass a name:

```ts title="wallet.ts"
import { FiberLspSdk } from "@peersyst/fiber-lsp-sdk";

const sdk = new FiberLspSdk(masterSeed, { network: "testnet", storage, rpcUrl: "https://lsp.example.com/rpc", lspPubkey });
```

[`SDK_NETWORK_NAMES`](/docs/api/variables/SDK_NETWORK_NAMES) lists the names, `"mainnet"` and `"testnet"`. Each preset holds the values Fiber's own node configuration uses on that chain:

| Field | `mainnet` | `testnet` |
| --- | --- | --- |
| `commitmentLock` | Fiber's commitment lock on mainnet (`hashType: "type"`) | Fiber's commitment lock on testnet (`hashType: "type"`) |
| `fundingLock` | Fiber's funding lock on mainnet (`hashType: "type"`) | Fiber's funding lock on testnet (`hashType: "type"`) |
| `invoiceCurrency` | `"Fibb"` | `"Fibt"` |
| `fundingLockCellDepsCount` | `2` | `2` |
| `millisecondsPerEpoch` | `14_400_000` (4 hours) | `14_400_000` (4 hours) |

The exact code hashes are in the SDK's source, [`src/digest/digest.constants.ts`](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/src/digest/digest.constants.ts). Which Fiber version they match is in [Compatibility](/docs/resources/compatibility).

To pick a preset from configuration, narrow the string first:

```ts title="network.ts"
import { SDK_NETWORK_NAMES, type SdkNetworkName } from "@peersyst/fiber-lsp-sdk";

function isNetworkName(value: string): value is SdkNetworkName {
    return (SDK_NETWORK_NAMES as readonly string[]).includes(value);
}

const network: SdkNetworkName = isNetworkName(fromConfig) ? fromConfig : "testnet";
```

## A custom network

For a devnet, or any chain the presets do not cover, pass an [`SdkNetworkConfig`](/docs/api/type-aliases/SdkNetworkConfig) object instead. This one describes a local devnet run from a debug build of Fiber:

```ts title="devnet.ts"
import { FiberLspSdk, type SdkNetworkConfig } from "@peersyst/fiber-lsp-sdk";

// Your own helper: 64 hex characters to 32 bytes.
const hex = (value: string): Uint8Array => Uint8Array.from(value.match(/../g) ?? [], (byte) => parseInt(byte, 16));

const devnet: SdkNetworkConfig = {
    // The scripts your devnet's Fiber nodes are configured with.
    commitmentLock: { codeHash: hex("<commitment-lock code hash, 64 hex characters>"), hashType: "data2" },
    fundingLock: { codeHash: hex("<funding-lock code hash, 64 hex characters>"), hashType: "data2" },
    invoiceCurrency: "Fibd",
    fundingLockCellDepsCount: 2,
    millisecondsPerEpoch: 2_000, // a debug build of fiber; release builds use 14_400_000 (4 hours)
};

const sdk = new FiberLspSdk(masterSeed, {
    network: devnet,
    storage,
    rpcUrl: "http://127.0.0.1:8227",
    lspPubkey,
    // biscuitToken omitted: a local node may run its RPC without auth
});
```

Every field, and where to find its value:

| Field | Type | What it is |
| --- | --- | --- |
| `commitmentLock` | `ScriptTemplate` (`{ codeHash, hashType }`) | The lock of Fiber's commitment transactions. Take the code hash and hash type from your nodes' Fiber config. A devnet whose genesis deploys the contract binaries usually references them by data hash (`"data2"`) |
| `fundingLock` | `ScriptTemplate` | The lock of the channel's funding cell, the 2-of-2 the device holds a key of. Only the code hash and hash type: each channel's args are computed from the two funding keys |
| `invoiceCurrency` | `"Fibb"`, `"Fibt"` or `"Fibd"` | The currency prefix of the network's invoices: mainnet, testnet, devnet. The SDK asks the node for invoices in it, and `transfer` refuses an invoice in another |
| `fundingLockCellDepsCount` | Integer, 1 to 255 | How many cell deps the funding lock needs (the lock's code and its auth library: `2` on mainnet, testnet and a standard devnet). Fiber sizes the commitment fee as if the commitment carried them, so the device needs the count to rebuild the fee |
| `millisecondsPerEpoch` | Integer, at least 1 | The length of an epoch as Fiber's build defines it: **14,400,000 (4 hours) in a release build, 2,000 (2 seconds) in a debug build**. It must match the build the LSP's node runs |

All five fields are required and checked at construction: a wrong one throws a `TypeError` or `RangeError` naming it (`network.fundingLockCellDepsCount`, for example). The code hashes are copied, so changing your buffers later has no effect.

:::warning[`millisecondsPerEpoch` must match the node's build]
Nothing the node sends states the epoch length; Fiber compiles it in. The SDK uses it to compute when Fiber would force-close a channel waiting on a signature (the `deadlineMs` of `SIGNING` events) and how much time a held payment has left before the device can safely release its preimage. With a debug-build node and the release value, or the reverse, those margins are wrong by a factor of 7,200. Public nodes run release builds, which is what both presets assume.
:::

:::tip[No token on a local node]
`biscuitToken` is optional so that a development node with its RPC auth off is reachable. A hosted node without a token fails loudly at the first call.
:::

## Next steps

- [Options](/docs/reference/options): the other constructor options.
- [Compatibility](/docs/resources/compatibility): which Fiber version the presets match.
- [Quickstart](/docs/get-started/quickstart): build an instance against testnet.
