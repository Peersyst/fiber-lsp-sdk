import {
    PAYMENT_HASH_LENGTH,
    PREIMAGE_LENGTH,
    UINT64_MAX,
    assertOneOf,
    assertPositiveBigInt,
    assertString,
    encodeWellFormedUtf8,
} from "../common";
import { INVOICE_CURRENCIES } from "../invoice";
import type { WireField } from "../wire";
import {
    WIRE_TLC_HASH_ALGORITHMS,
    decodeEnum,
    decodeNonEmptyString,
    encodeHexBytes,
    encodeMapped,
    encodeUintHex,
    readObject,
    requireObject,
} from "../wire";
import { RPC_INVOICE_STATUSES, RPC_MAX_FINAL_EXPIRY_DELTA_MS, RPC_MAX_INVOICE_DESCRIPTION_BYTES } from "./rpc.constants";
import type {
    NewInvoiceParams,
    NewInvoiceParamsWire,
    NewInvoiceResult,
    NewInvoiceResultWire,
    RpcInvoice,
    RpcInvoiceWire,
    SettleInvoiceParams,
    SettleInvoiceParamsWire,
} from "./rpc.types";
import { encodeRpcPaymentHashParams, encodeRpcShannons } from "./utils";

/**
 * Writes the params of `new_invoice`.
 * @param params The invoice to create.
 * @returns The wire params.
 */
export function encodeNewInvoiceParams(params: NewInvoiceParams): NewInvoiceParamsWire {
    const { description } = params;
    if (description !== undefined) assertRpcInvoiceDescription("description", description);
    assertOneOf("currency", params.currency, INVOICE_CURRENCIES);
    // Fiber's own floor depends on the build (9,600,000 ms release, 1,333 ms debug), so only 0 is refused here.
    assertPositiveBigInt("finalExpiryDeltaMs", params.finalExpiryDeltaMs, RPC_MAX_FINAL_EXPIRY_DELTA_MS);
    return {
        amount: encodeRpcShannons("amountShannons", params.amountShannons),
        ...(description === undefined ? {} : { description }),
        currency: params.currency,
        payment_hash: encodeHexBytes("paymentHash", params.paymentHash, PAYMENT_HASH_LENGTH),
        expiry: encodeUintHex("expirySeconds", params.expirySeconds, UINT64_MAX),
        final_expiry_delta: encodeUintHex("finalExpiryDeltaMs", params.finalExpiryDeltaMs, UINT64_MAX),
        hash_algorithm: encodeMapped("hashAlgorithm", params.hashAlgorithm, WIRE_TLC_HASH_ALGORITHMS),
    };
}

/**
 * Asserts that a value is well-formed Unicode within fiber's invoice description limit in UTF-8 bytes.
 * @param name Name for the error message.
 * @param value Value to check.
 */
export function assertRpcInvoiceDescription(name: string, value: unknown): asserts value is string {
    assertString(name, value);
    // serde_json refuses a lone surrogate in a string.
    const bytes = encodeWellFormedUtf8(name, value).length;
    if (bytes > RPC_MAX_INVOICE_DESCRIPTION_BYTES) {
        throw new RangeError(`${name} must be at most ${RPC_MAX_INVOICE_DESCRIPTION_BYTES} bytes of UTF-8, got ${bytes}`);
    }
}

/**
 * Reads the result of `new_invoice`.
 * @param field The result field.
 * @returns The encoded invoice.
 */
export function decodeNewInvoiceResult(field: WireField): NewInvoiceResult {
    return { invoiceAddress: decodeNonEmptyString(readObject<NewInvoiceResultWire>(field)("invoice_address")) };
}

/**
 * Reads the result of `get_invoice` and of `cancel_invoice`.
 * @param field The result field.
 * @returns The encoded invoice and its status.
 */
export function decodeRpcInvoice(field: WireField): RpcInvoice {
    return { ...decodeNewInvoiceResult(field), status: decodeEnum(readObject<RpcInvoiceWire>(field)("status"), RPC_INVOICE_STATUSES) };
}

/**
 * Writes the params of `settle_invoice`.
 * @param params The invoice and its preimage.
 * @returns The wire params.
 */
export function encodeSettleInvoiceParams(params: SettleInvoiceParams): SettleInvoiceParamsWire {
    return {
        ...encodeRpcPaymentHashParams(params),
        payment_preimage: encodeHexBytes("paymentPreimage", params.paymentPreimage, PREIMAGE_LENGTH),
    };
}

/**
 * Reads the result of `settle_invoice`, which is an empty object.
 * @param field The result field.
 */
export function decodeSettleInvoiceResult(field: WireField): void {
    requireObject(field);
}
