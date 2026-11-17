---
title: Errors
description: Every error the SDK throws or reports, what each code means and what your app should do about it.
---

# Errors

The SDK splits its failures by who can act on them: `SdkError` for a condition of the device you can branch on, the rpc errors for what the node did, `TypeError` and `RangeError` for a programming error in your code. This page lists them all.

## At a glance

| Error | Thrown when | What you do |
| --- | --- | --- |
| [`SdkError`](#sdkerror) | The device refuses or cannot complete an operation | Branch on `code` ([table below](#sdk_error_codes)) |
| [`RpcTransportError`](#rpc-errors) | The request did not complete | Assume the call may or may not have run |
| [`RpcError`](#rpc-errors) | The node answered with an error | The node refused; read `code` and `message` |
| [`RpcResponseError`](#rpc-errors) | The node answered something the SDK cannot read | The node answered, but nobody can say what |
| [`InvoiceError`](#invoiceerror) | `decodeInvoice` refused a string | Tell the user it is not a valid Fiber invoice |
| `TypeError`, `RangeError` | An argument or option is wrong | Fix the calling code |
| Anything else | Your own effects failed (storage, signer) | Handle as your own error |

```ts title="pay.ts"
import { RpcError, RpcResponseError, RpcTransportError, SdkError } from "@peersyst/fiber-lsp-sdk";

try {
    const payment = await sdk.transfer(invoice);
    show(`Sending ${payment.amountShannons} shannons`);
} catch (error) {
    if (error instanceof SdkError) {
        switch (error.code) {
            case "invoice_unpayable":
            case "own_invoice":
                show("This invoice cannot be paid from this wallet.");
                break;
            case "payment_in_flight":
                show("This invoice is already being paid.");
                break;
            case "payment_charged":
                show("This invoice may already have been paid.");
                break;
            default:
                show(error.message);
        }
    } else if (error instanceof RpcTransportError) {
        show("The node could not be reached. The payment may or may not have been sent.");
    } else if (error instanceof RpcError) {
        show(`The node refused the payment: ${error.message}`);
    } else if (error instanceof RpcResponseError) {
        show("The node answered something the wallet cannot read.");
    } else {
        throw error;
    }
}
```

## `SdkError`

[`SdkError`](/docs/api/classes/SdkError) extends `Error`, with `name` set to `"SdkError"`.

| Property | Type | Meaning |
| --- | --- | --- |
| [`code`](/docs/api/classes/SdkError#code) | [`SdkErrorCode`](/docs/api/type-aliases/SdkErrorCode) | What failed, one of [`SDK_ERROR_CODES`](/docs/api/variables/SDK_ERROR_CODES) |
| `message` | `string` | What failed, then the cause's own words. Safe to log |
| [`cause`](/docs/api/classes/SdkError#cause) | `unknown`, optional | The module's own error underneath, when there is one (column "Cause" below) |

Operations throw it, and the poller reports it through the [`ERROR` event](/docs/reference/events#error) as `poll_failed`.

## `SDK_ERROR_CODES`

| Code | Thrown by | When | Cause | What to do |
| --- | --- | --- | --- | --- |
| `poll_failed` | The poller (`ERROR` event only) | A poll step, or one channel, invoice or payment inside a step, failed or took more than 30 seconds | What failed | Log it. The SDK retries at the next tick. Persistent ones point at the node, the network or your storage |
| `clock_before_floor` | Operations that allocate an index (opening a channel, creating an invoice) | The device clock reads before the SDK's allocation floor, 2026-10-01T00:00:00Z | None | Ask the user to fix the device's date and time, then retry |
| `unknown_channel` | `submitFundingTx`, `closeChannel`, `channelEvidence` | The channel id names a channel this device never registered | None | Check the id; use `forceCloseChannel` for a channel without a record |
| `opening_rejected` | `prepareChannelOpen`, `openChannel` | The node's answer to an opening is not what the device asked for; the message names the field | None | Do not retry blindly: the node (or the LSP) is misbehaving or misconfigured. The pending opening is dropped |
| `opening_conflict` | `prepareChannelOpen`, `openChannel` | The node's answer contradicts the device's records: a registration or a pin the policy refuses | The policy's error | As above. The pending opening is dropped |
| `funding_tx_altered` | `submitFundingTx`, `openChannel` | The signed funding tx is not the one the opening froze, or the channel pins no funding cell to compare it to | The pin's conflict, or none | Sign the exact `unsignedFundingTx` you were given, changing only the witnesses |
| `invoice_rejected` | `createInvoice` | The node's invoice string is not the invoice the device asked for; the message names the field | The decoder's error, or none | Do not show the invoice. The node is misbehaving or misconfigured |
| `invoice_unpayable` | `transfer` | The invoice is not one the device pays (it does not decode, is for another network, has no amount or a zero one, is a UDT invoice, has no payee key, or has expired), or its hash is a twin of another payment's | The decoder's or the policy's error, or none | Tell the user this invoice cannot be paid |
| `payment_in_flight` | `transfer` | A payment under this hash is not settled yet: being sent, being read, watched, open, or held by the node | The policy's error, the node's `RpcError`, or none | Wait for `PAYMENT_SENT` or `PAYMENT_FAILED` |
| `payment_charged` | `transfer` | A payment under this hash was already charged a TLC, so it may have been made. It is never sent again | The policy's error | Treat the invoice as possibly paid; do not offer a retry |
| `own_invoice` | `transfer` | The invoice is one of this device's own hold invoices | The policy's error | Tell the user they cannot pay their own invoice |
| `close_fee_too_high` | `closeChannel` | The device's fee on the close, at your `feeRate` or the channel's commitment fee rate, is above the 1 CKB the policy lets a close take | None | Retry with a lower `feeRate`, or force-close |
| `unknown_invoice` | `cancelInvoice` | This device recorded no invoice under the hash | The policy's error | Check the hash |
| `invoice_released` | `cancelInvoice` | The device already released this invoice's preimage | The policy's error | Too late to cancel: the payment is being settled. Wait for `PAYMENT_RECEIVED` |

When the device refuses an opening, it drops its pending opening first. If that drop fails, the error keeps its code and cause, and its message ends with "the pending opening could not be dropped" and the drop's own words.

:::note
The list of codes grows with the operations, and the SDK is pre-release. Keep a `default` branch in your `switch`. See [Project status](/docs/resources/status).
:::

## `SIGNER_ERROR_CODES`

The refusal codes the device answers a signing request with. You see them in the `error.code` of a refused [`SIGNING`](/docs/reference/events#signing) or [`WATCHTOWER_SIGNING`](/docs/reference/events#watchtower_signing) event, as a [`SignerRefusal`](/docs/api/type-aliases/SignerRefusal) (`{ code, message }`). They are never thrown.

| Code | Meaning |
| --- | --- |
| `unknown_channel` | The request names a channel this device has no record of, so it holds no keys for it |
| `malformed` | The request does not hold together: the status does not decode, the node answered for another channel, the key order, the aggregated nonce, the message or the peer's partial signature is not what it must be, or a watchtower spend the policy reads as malformed |
| `stale_state` | The request is out of order: a slot below its lane's last (a rollback), a commitment after its view's, or a revocation without the replacement commitment it needs |
| `policy_refusal` | The request is well formed but the policy will not sign it: a slot already served (a second session under `"refuse"`, a third in any mode), a value that moved from its pin, a balance change no payment explains, a channel announcement, or a watchtower spend outside the [approval](/docs/reference/options#sdkwatchtoweroptions) (or with no approval at all) |

A refused request stays pending on the node; nothing was signed. The message says which rule refused it. See [No blind signing](/docs/concepts/no-blind-signing), and for the full rule set, [policy.md on GitHub](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/policy.md).

## RPC errors

Every call to the node can fail in three ways. They are split by what you can conclude about the outcome, which matters most for writes like `transfer` or `submitFundingTx`.

| Error | When | What you can conclude | Extra properties |
| --- | --- | --- | --- |
| [`RpcTransportError`](/docs/api/classes/RpcTransportError) | `fetch` rejected or threw, the HTTP status was not 2xx, or the body could not be read | **Nothing**: the call may or may not have run | `method`, `status` (when a response arrived), `cause` (the runtime's error) |
| [`RpcError`](/docs/api/classes/RpcError) | The node answered a JSON-RPC error | **The node refused** | `method`, `code`, and `message` verbatim |
| [`RpcResponseError`](/docs/api/classes/RpcResponseError) | The node answered something the client cannot read | **The node answered**, but nobody can say what | `method`, `path` (the field that failed, like `response.result.channel_id`), `reason` |

Notes:

- A non-2xx status is a transport error even when the body holds a JSON-RPC error.
- Fiber answers every handler failure with `code` `-32000` and free text, and an auth refusal with `-32999`. Nothing machine-readable tells two `-32000` failures apart, so the SDK never parses messages for you (except a few known answers it handles itself, like a payment session that already exists, which becomes `payment_in_flight`).
- [`LspOperatorClient.registerTenant`](/docs/api/classes/LspOperatorClient#registertenant) throws `RpcResponseError` when the node's answer names another tenant than the registered key. The call did run there: the request id is spent and a token was minted for the tenant the answer names.

Learn more in [rpc.md on GitHub](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/rpc.md).

## `InvoiceError`

[`decodeInvoice`](/docs/api/functions/decodeInvoice) throws [`InvoiceError`](/docs/api/classes/InvoiceError) for a string Fiber's encoder would not write.

| Property | Type | Meaning |
| --- | --- | --- |
| `path` | `string` | What was refused: a layer of the string, or a field inside its data |
| `reason` | `string` | What it had to be (never what it was) |

```ts title="scan.ts"
import { InvoiceError, decodeInvoice } from "@peersyst/fiber-lsp-sdk";

try {
    const invoice = decodeInvoice(text);
    console.log(invoice.amountShannons);
} catch (error) {
    if (error instanceof InvoiceError) console.log(`Not a Fiber invoice: ${error.path} ${error.reason}`);
    else throw error;
}
```

Inside `transfer` and `createInvoice`, a decode failure is wrapped instead: `invoice_unpayable` or `invoice_rejected`, with the `InvoiceError` as `cause`. See [Decode an invoice](/docs/guides/decode-an-invoice).

## What passes through unwrapped

What is not a condition of the device comes through as its own error, not as an `SdkError`:

- **The node's answers**: the three rpc errors on an opening, a funding submission, a listing, an invoice's creation or cancel, a payment's send and a close. The one exception is the node saying a payment session already exists for the hash, which becomes `payment_in_flight` with the `RpcError` as its cause.
- **Your storage**: whatever it throws, and a stored record the SDK refuses to read (a corrupt one), wherever a record is read, `channelEvidence` included.
- **Your funding signer**: whatever `signFundingInputs` throws in `openChannel`.
- **A funding tx that is not a transaction**: a `TypeError` naming `signedTx` from `submitFundingTx`.
- **A close without its pins**: a `TypeError` naming the missing pin, from `closeChannel` on a channel whose record lacks them.

## Programming errors

A wrong argument or option is a `TypeError` or a `RangeError` naming the field, thrown before anything is written or sent. `TypeError` is for the wrong shape (`rpcUrl must be a non-empty string`, `channelId must be 32 bytes of 0x-prefixed lowercase hex`); `RangeError` is for a value out of bounds (`pollIntervalMs must be an integer between 1 and 2147483647, got 0`). Some bounds belong to the policy:

- An opening amount out of range is a `RangeError` naming `fundedShannons`: from the device's least reserve over that lock to below a u64.
- A payment's fee budget that, added to the invoice's amount, exceeds a u128 is a `RangeError`.

These are bugs to fix in your code, not conditions to show the user. Every message is listed per option in [Options](/docs/reference/options).

## See also

- [Events](/docs/reference/events)
- [Handle events and errors](/docs/guides/events-and-errors)
- [No blind signing](/docs/concepts/no-blind-signing)
- [`SdkError` in the API reference](/docs/api/classes/SdkError)
