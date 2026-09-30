import { PAYMENT_HASH_LENGTH, UINT64_MAX, assertBoolean, assertNonEmptyString } from "../common";
import type { Field } from "../wire";
import { decodeEnum, decodeHexBytes, decodeOrNull, decodeString, decodeUintHex, readObject } from "../wire";
import { PAYMENT_STATUSES } from "./rpc.constants";
import type { RpcPayment, RpcPaymentWire, SendPaymentParams, SendPaymentParamsWire } from "./rpc.types";
import { decodeRpcShannons, encodeRpcShannons } from "./utils";

/**
 * Writes the params of `send_payment`.
 * @param params The invoice to pay and the fee bound.
 * @returns The wire params.
 */
export function encodeSendPaymentParams(params: SendPaymentParams): SendPaymentParamsWire {
    assertNonEmptyString("invoice", params.invoice);
    assertBoolean("dryRun", params.dryRun);
    return {
        invoice: params.invoice,
        max_fee_amount: encodeRpcShannons("maxFeeAmountShannons", params.maxFeeAmountShannons),
        dry_run: params.dryRun,
    };
}

/**
 * Reads the result of `send_payment` and of `get_payment`.
 * @param field The result field.
 * @returns The payment.
 */
export function decodeRpcPayment(field: Field): RpcPayment {
    const at = readObject<RpcPaymentWire>(field);
    return {
        paymentHash: decodeHexBytes(at("payment_hash"), PAYMENT_HASH_LENGTH),
        status: decodeEnum(at("status"), PAYMENT_STATUSES),
        createdAtMs: decodeUintHex(at("created_at"), UINT64_MAX),
        lastUpdatedAtMs: decodeUintHex(at("last_updated_at"), UINT64_MAX),
        failedError: decodeOrNull(at("failed_error"), decodeString),
        feeShannons: decodeRpcShannons(at("fee")),
    };
}
