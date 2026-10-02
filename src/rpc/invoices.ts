import { PAYMENT_HASH_LENGTH, PREIMAGE_LENGTH, UINT64_MAX, assertOneOf, assertString } from "../common";
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
import { RPC_INVOICE_STATUSES } from "./rpc.constants";
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
    if (description !== undefined) assertString("description", description);
    assertOneOf("currency", params.currency, INVOICE_CURRENCIES);
    return {
        amount: encodeRpcShannons("amountShannons", params.amountShannons),
        ...(description === undefined ? {} : { description }),
        currency: params.currency,
        payment_hash: encodeHexBytes("paymentHash", params.paymentHash, PAYMENT_HASH_LENGTH),
        expiry: encodeUintHex("expirySeconds", params.expirySeconds, UINT64_MAX),
        hash_algorithm: encodeMapped("hashAlgorithm", params.hashAlgorithm, WIRE_TLC_HASH_ALGORITHMS),
    };
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
