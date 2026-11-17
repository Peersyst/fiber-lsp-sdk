---
title: Constants
description: Every constant the SDK exports, with its value and what it means, and the five channel states.
---

# Constants

The SDK exports eleven constants. This page gives the value of each and what it is for. The arrays are `as const`, so each has a matching union type (for example `SdkChannelState` for `SDK_CHANNEL_STATES`).

## Summary

| Constant | Type | Value |
| --- | --- | --- |
| [`DEFAULT_POLL_INTERVAL_MS`](#default_poll_interval_ms) | `number` | `2000` |
| [`BIP39_SEED_LENGTH`](#bip39_seed_length) | `number` | `64` |
| [`MAX_ACCOUNT_INDEX`](#max_account_index) | `number` | `2147483647` (`2 ** 31 - 1`) |
| [`DERIVATION_SCHEME_VERSION`](#derivation_scheme_version) | `number` | `1` |
| [`TENANT_REGISTRY_MAX_SIGNED_AT_AGE_MS`](#tenant_registry_max_signed_at_age_ms) | `bigint` | `300000n` (5 minutes) |
| [`TENANT_REGISTRY_MAX_SIGNED_AT_FUTURE_SKEW_MS`](#tenant_registry_max_signed_at_future_skew_ms) | `bigint` | `30000n` (30 seconds) |
| [`SDK_NETWORK_NAMES`](#sdk_network_names) | `readonly string[]` | `["mainnet", "testnet"]` |
| [`SDK_CHANNEL_STATES`](#sdk_channel_states) | `readonly string[]` | `["opening", "ready", "closing", "closed", "stale"]` |
| [`SDK_EVENT_TYPES`](#sdk_event_types) | `readonly string[]` | Eleven event types |
| [`SDK_ERROR_CODES`](#sdk_error_codes) | `readonly string[]` | Fourteen error codes |
| [`SIGNER_ERROR_CODES`](#signer_error_codes) | `readonly string[]` | `["unknown_channel", "malformed", "stale_state", "policy_refusal"]` |

## Polling

### `DEFAULT_POLL_INTERVAL_MS`

`2000`. The default of the [`pollIntervalMs`](/docs/reference/options#fiberlspsdkoptions) option: the pause, in milliseconds, between the end of one poll tick and the start of the next. A tick makes one `list_channels` call (while a channel is watched), one read per payment and invoice in flight, one signing status per channel and one submission per signature. [API](/docs/api/variables/DEFAULT_POLL_INTERVAL_MS).

## Key derivation

### `BIP39_SEED_LENGTH`

`64`. The length in bytes of the BIP39 seed [`deriveMasterSeed`](/docs/api/functions/deriveMasterSeed) takes. BIP39 always expands a mnemonic into exactly 64 bytes, so anything shorter is a wiring mistake in your app, and is refused with a `TypeError`. [API](/docs/api/variables/BIP39_SEED_LENGTH).

### `MAX_ACCOUNT_INDEX`

`2147483647` (`2 ** 31 - 1`). The highest `accountIndex` `deriveMasterSeed` accepts. The account level of the derivation path is hardened, so it has 31 bits. The default index is `0`; above the maximum is a `RangeError`. [API](/docs/api/variables/MAX_ACCOUNT_INDEX).

### `DERIVATION_SCHEME_VERSION`

`1`. The version of the scheme that turns the master seed into every channel key and nonce. The scheme is additive only: changing a derivation would strand existing channels, so any change takes a new version. See [Keys and recovery](/docs/concepts/keys-and-recovery). [API](/docs/api/variables/DERIVATION_SCHEME_VERSION).

## Tenant registration

Both are Fiber's own bounds on a registration's `signedAtMs`, inclusive, measured against the **node's** clock. A registration outside them is refused by the node. See [Register a tenant](/docs/guides/register-a-tenant).

### `TENANT_REGISTRY_MAX_SIGNED_AT_AGE_MS`

`300000n` (5 minutes). How far behind the node's clock `signedAtMs` may be. Send the registration within this window after signing it. [API](/docs/api/variables/TENANT_REGISTRY_MAX_SIGNED_AT_AGE_MS).

### `TENANT_REGISTRY_MAX_SIGNED_AT_FUTURE_SKEW_MS`

`30000n` (30 seconds). How far ahead of the node's clock `signedAtMs` may be. A device clock running fast by more than this gets its registration refused. [API](/docs/api/variables/TENANT_REGISTRY_MAX_SIGNED_AT_FUTURE_SKEW_MS).

## Enumerations

### `SDK_NETWORK_NAMES`

`["mainnet", "testnet"]`. The names the [`network`](/docs/reference/options#fiberlspsdkoptions) option accepts as a preset. Type: [`SdkNetworkName`](/docs/api/type-aliases/SdkNetworkName). The values each preset resolves to are in [Options](/docs/reference/options#the-two-presets). [API](/docs/api/variables/SDK_NETWORK_NAMES).

### `SDK_CHANNEL_STATES`

`["opening", "ready", "closing", "closed", "stale"]`. The `state` of each channel [`listChannels()`](/docs/api/classes/FiberLspSdk#listchannels) returns. Type: [`SdkChannelState`](/docs/api/type-aliases/SdkChannelState). [API](/docs/api/variables/SDK_CHANNEL_STATES).

Each state groups one or more of Fiber's channel states:

| State | Fiber's states | What it means for the user |
| --- | --- | --- |
| `opening` | `NegotiatingFunding`, `CollaboratingFundingTx`, `SigningCommitment`, `AwaitingTxSignatures`, `AwaitingChannelReady` | The channel is being set up and funded. It cannot carry payments yet |
| `ready` | `ChannelReady` | The channel is open and can send and receive |
| `closing` | `ShuttingDown` | A cooperative close is under way |
| `closed` | `Closed`, under any flag | The channel is closed, cooperatively or by force |
| `stale` | `Stale` | Fiber restored the channel from an old database and is auditing it with the peer before it resumes |

An opening Fiber aborted before it was funded is not listed at all, since Fiber deletes it; the [`CHANNEL_CLOSED`](/docs/reference/events#all-events) event is what reports it. A state the SDK does not know is refused rather than guessed. Each listed channel also carries `hasRecord`, whether this device registered it.

```ts title="channels.ts"
import { SDK_CHANNEL_STATES, type SdkChannelState } from "@peersyst/fiber-lsp-sdk";

const labels: Record<SdkChannelState, string> = {
    opening: "Opening",
    ready: "Ready",
    closing: "Closing",
    closed: "Closed",
    stale: "Recovering",
};

const channels = await sdk.listChannels();
for (const state of SDK_CHANNEL_STATES) {
    const count = channels.filter((channel) => channel.state === state).length;
    console.log(labels[state], count);
}
```

### `SDK_EVENT_TYPES`

The eleven values of `SdkEvent["type"]`, in this order: `"CHANNEL_READY"`, `"CHANNEL_CLOSED"`, `"PAYMENT_SENT"`, `"PAYMENT_FAILED"`, `"PAYMENT_PENDING"`, `"PAYMENT_RECEIVED"`, `"PAYMENT_EXPIRED"`, `"PAYMENT_CANCELLED"`, `"SIGNING"`, `"WATCHTOWER_SIGNING"`, `"ERROR"`. Type: [`SdkEventType`](/docs/api/type-aliases/SdkEventType). Payloads and timing are in [Events](/docs/reference/events). [API](/docs/api/variables/SDK_EVENT_TYPES).

### `SDK_ERROR_CODES`

The fourteen values of `SdkError["code"]`, in this order: `"poll_failed"`, `"clock_before_floor"`, `"unknown_channel"`, `"opening_rejected"`, `"opening_conflict"`, `"funding_tx_altered"`, `"invoice_rejected"`, `"invoice_unpayable"`, `"payment_in_flight"`, `"payment_charged"`, `"own_invoice"`, `"close_fee_too_high"`, `"unknown_invoice"`, `"invoice_released"`. Type: [`SdkErrorCode`](/docs/api/type-aliases/SdkErrorCode). What each means is in [Errors](/docs/reference/errors#sdk_error_codes). [API](/docs/api/variables/SDK_ERROR_CODES).

### `SIGNER_ERROR_CODES`

`["unknown_channel", "malformed", "stale_state", "policy_refusal"]`. The codes of a refused signing request, carried by the `error` of a [`SIGNING`](/docs/reference/events#signing) or [`WATCHTOWER_SIGNING`](/docs/reference/events#watchtower_signing) event. Type: [`SignerErrorCode`](/docs/api/type-aliases/SignerErrorCode). What each means is in [Errors](/docs/reference/errors#signer_error_codes). [API](/docs/api/variables/SIGNER_ERROR_CODES).

:::note
`unknown_channel` is both an `SdkError` code and a signer code. As an `SdkError` it is thrown by an operation; as a signer code it only appears in a refused signing event.
:::

## See also

- [Options](/docs/reference/options)
- [Events](/docs/reference/events)
- [Errors](/docs/reference/errors)
- [API reference: variables](/docs/api)
