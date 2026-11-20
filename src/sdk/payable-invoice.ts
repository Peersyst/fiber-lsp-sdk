import { bytesToHex } from "@noble/hashes/utils.js";
import { assertOneOf, assertString, assertUnsignedInteger } from "../common";
import { SDK_NETWORK_NAMES, SDK_NETWORK_PRESETS } from "./sdk.constants";
import type { SdkNetworkName, SdkPayableInvoiceDetails } from "./sdk.types";
import { checkPayableInvoice } from "./utils";

/**
 * Reads an invoice the device pays on a network, by the checks `transfer` runs first, touching nothing.
 * @param encodedInvoice The invoice string.
 * @param network The network's name.
 * @param nowMs The host's clock, `Date.now()` by default.
 * @returns The payment hash, amount, description and expiry; an unpayable invoice is `invoice_unpayable`.
 */
export function readSdkPayableInvoice(
    encodedInvoice: string,
    network: SdkNetworkName,
    nowMs: number = Date.now(),
): SdkPayableInvoiceDetails {
    assertString("encodedInvoice", encodedInvoice);
    assertOneOf("network", network, SDK_NETWORK_NAMES);
    assertUnsignedInteger("nowMs", nowMs, Number.MAX_SAFE_INTEGER);
    const { paymentHash, amountShannons, description, expiresAtMs } = checkPayableInvoice(
        encodedInvoice,
        SDK_NETWORK_PRESETS[network].invoiceCurrency,
        nowMs,
    );
    return { paymentHashHex: `0x${bytesToHex(paymentHash)}`, amountShannons, description, expiresAtMs };
}
