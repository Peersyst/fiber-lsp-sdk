import {
    COMPRESSED_POINT_LENGTH,
    PAYMENT_HASH_LENGTH,
    UINT64_MAX,
    assertBoolean,
    assertCompressedPoint,
    assertNonEmptyString,
} from "../common";
import type { WireField } from "../wire";
import { decodeEnum, decodeHexBytes, encodeBareHexBytes, decodeOrNull, decodeString, decodeUintHex, readObject } from "../wire";
import { RPC_MAX_TRAMPOLINE_HOPS, RPC_PAYMENT_STATUSES } from "./rpc.constants";
import type { RpcPayment, RpcPaymentWire, SendPaymentParams, SendPaymentParamsWire } from "./rpc.types";
import { decodeRpcShannons, encodeRpcShannons } from "./utils";

/**
 * Writes the params of `send_payment`.
 * @param params The invoice to pay, the fee bound and the trampoline hops.
 * @returns The wire params.
 */
export function encodeSendPaymentParams(params: SendPaymentParams): SendPaymentParamsWire {
    assertNonEmptyString("invoice", params.invoice);
    assertBoolean("dryRun", params.dryRun);
    const { trampolineHops } = params;
    if (!Array.isArray(trampolineHops)) throw new TypeError("trampolineHops must be an array");
    if (trampolineHops.length > RPC_MAX_TRAMPOLINE_HOPS) {
        throw new TypeError(`trampolineHops must have at most ${RPC_MAX_TRAMPOLINE_HOPS} entries`);
    }
    const hops: string[] = [];
    // An index loop, so a sparse array's holes are checked too.
    for (let index = 0; index < trampolineHops.length; index++) {
        const hop: unknown = trampolineHops[index];
        assertCompressedPoint(`trampolineHops[${index}]`, hop);
        hops.push(encodeBareHexBytes(`trampolineHops[${index}]`, hop, COMPRESSED_POINT_LENGTH));
    }
    return {
        invoice: params.invoice,
        max_fee_amount: encodeRpcShannons("maxFeeAmountShannons", params.maxFeeAmountShannons),
        dry_run: params.dryRun,
        // Fiber refuses an empty list (`fiber/payment.rs:263-266`).
        ...(hops.length === 0 ? {} : { trampoline_hops: hops }),
    };
}

/**
 * Reads the result of `send_payment` and of `get_payment`.
 * @param field The result field.
 * @returns The payment.
 */
export function decodeRpcPayment(field: WireField): RpcPayment {
    const at = readObject<RpcPaymentWire>(field);
    return {
        paymentHash: decodeHexBytes(at("payment_hash"), PAYMENT_HASH_LENGTH),
        status: decodeEnum(at("status"), RPC_PAYMENT_STATUSES),
        createdAtMs: decodeUintHex(at("created_at"), UINT64_MAX),
        lastUpdatedAtMs: decodeUintHex(at("last_updated_at"), UINT64_MAX),
        failedError: decodeOrNull(at("failed_error"), decodeString),
        feeShannons: decodeRpcShannons(at("fee")),
    };
}
