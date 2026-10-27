import { bytesToHex } from "@noble/hashes/utils.js";
import { assertPositiveDecimalShannons, assertPositiveInteger, isPlainObject } from "../common";
import type { NewInvoiceParams } from "../rpc";
import { assertRpcInvoiceDescription } from "../rpc";
import { DEFAULT_SDK_INVOICE_EXPIRY_SECONDS, SDK_INVOICE_FINAL_EXPIRY_DELTA_MS } from "./sdk.constants";
import type { SdkContext, SdkInvoice, SdkInvoiceOptions } from "./sdk.types";
import { checkTenantInvoice, readSdkClock } from "./utils";

export type SdkInvoiceCreationContext = Pick<
    SdkContext,
    "network" | "lspPubkey" | "now" | "preimages" | "rpc" | "policy" | "allocator" | "activity"
>;

type InvoiceArguments = { expirySeconds: bigint; description: string | undefined };

/**
 * Creates a hold invoice the device alone can settle: recorded before the node hears its hash, checked, then watched.
 * @param context What the creation reads and writes.
 * @param amountShannons What the payer pays, in decimal shannons.
 * @param options The description and the expiry in whole seconds, if any.
 * @returns The node's string and the payment hash.
 */
export async function createSdkInvoice(
    context: SdkInvoiceCreationContext,
    amountShannons: string,
    options?: SdkInvoiceOptions,
): Promise<SdkInvoice> {
    const { expirySeconds, description } = readInvoiceArguments(amountShannons, options);
    const invoiceIndex = await context.allocator.allocateInvoiceIndex();
    const paymentHash = context.preimages.paymentHash(invoiceIndex);
    const paymentHashHex = bytesToHex(paymentHash);
    const { hashAlgorithm } = context.preimages;
    // Kept whatever follows: nobody pays an invoice the host never received, and one never watched is never released.
    await context.policy.recordHoldInvoice(paymentHashHex, amountShannons, hashAlgorithm, invoiceIndex);
    const params: NewInvoiceParams = {
        amountShannons,
        currency: context.network.invoiceCurrency,
        paymentHash,
        // Sent explicitly so the string's attribute is checked against it.
        hashAlgorithm,
        expirySeconds,
        finalExpiryDeltaMs: SDK_INVOICE_FINAL_EXPIRY_DELTA_MS,
        ...(description === undefined ? {} : { description }),
    };
    const { invoiceAddress } = await context.rpc.newInvoice(params);
    // Read after the node answered, so its timestamp is judged against a later reading.
    const nowMs = readSdkClock(context.now);
    checkTenantInvoice(invoiceAddress, { ...params, lspPubkey: context.lspPubkey }, nowMs);
    await context.activity.watch("invoice", paymentHashHex);
    return { invoice: invoiceAddress, paymentHashHex: `0x${paymentHashHex}` };
}

/**
 * Asserts an invoice's amount and options before anything is allocated or written, reading each option once.
 * @param amountShannons What the payer pays, in decimal shannons.
 * @param options The host's options, if any.
 * @returns The expiry, defaulted, and the description.
 */
function readInvoiceArguments(amountShannons: string, options: SdkInvoiceOptions | undefined): InvoiceArguments {
    assertPositiveDecimalShannons("amountShannons", amountShannons);
    if (options === undefined) return { expirySeconds: DEFAULT_SDK_INVOICE_EXPIRY_SECONDS, description: undefined };
    if (!isPlainObject(options)) throw new TypeError("options must be an object");
    const { description, expirySeconds } = options;
    if (description !== undefined) assertRpcInvoiceDescription("options.description", description);
    if (expirySeconds === undefined) return { expirySeconds: DEFAULT_SDK_INVOICE_EXPIRY_SECONDS, description };
    // A safe integer of seconds keeps the invoice's end within the u64 of milliseconds fiber's registration demands.
    assertPositiveInteger("options.expirySeconds", expirySeconds, Number.MAX_SAFE_INTEGER);
    return { expirySeconds: BigInt(expirySeconds), description };
}
