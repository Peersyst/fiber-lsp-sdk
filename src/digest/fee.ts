import { assertUnsignedBigInt, assertUnsignedInteger } from "../common";
import {
    CELL_DEP_LENGTH,
    CELL_INPUT_LENGTH,
    COMMITMENT_LOCK_ARGS_LENGTH,
    FEE_RATE_WEIGHT_SCALE,
    FUNDING_CELL_WITNESS_LENGTH,
    MAX_CAPACITY_SHANNONS,
    MAX_CELL_DEPS_COUNT,
} from "./digest.constants";
import type { Script, ScriptTemplate } from "./digest.types";
import { encodeCellOutput, encodeRawTransaction, encodeTransaction } from "./utils";

const UDT_AMOUNT_DATA_LENGTH = 16;

/**
 * The 4 bytes CKB adds on top of a serialized transaction when counting it towards a block (`serialized_size_in_block`).
 */
const BLOCK_SIZE_OVERHEAD = 4;

/**
 * Port of fiber's `commitment_tx_size`: the block size of a mock commitment tx, fee-relevant fields zeroed.
 * @param cellDepsCount Cell deps of the funding lock plus the UDT's; mocked as zeroed deps.
 * @param udtTypeScript The channel's UDT type script, or `null` for a CKB channel.
 * @param commitmentLock The network's commitment lock template.
 * @returns The size in bytes.
 */
export function commitmentTxSize(cellDepsCount: number, udtTypeScript: Script | null, commitmentLock: ScriptTemplate): number {
    const mockLock: Script = { ...commitmentLock, args: new Uint8Array(COMMITMENT_LOCK_ARGS_LENGTH) };
    const outputs = [encodeCellOutput(0n, mockLock, udtTypeScript)];
    const outputsData = [udtTypeScript === null ? new Uint8Array(0) : new Uint8Array(UDT_AMOUNT_DATA_LENGTH)];
    return mockTxSize(cellDepsCount, outputs, outputsData);
}

/**
 * Port of fiber's `shutdown_tx_size`: the block size of a mock shutdown tx with the two real close scripts.
 * @param cellDepsCount Cell deps of the funding lock plus the UDT's; mocked as zeroed deps.
 * @param udtTypeScript The channel's UDT type script, or `null` for a CKB channel.
 * @param closeScripts The two close scripts; only their sizes matter, so their order does not.
 * @returns The size in bytes.
 */
export function shutdownTxSize(cellDepsCount: number, udtTypeScript: Script | null, closeScripts: [Script, Script]): number {
    const outputs = closeScripts.map((script) => encodeCellOutput(0n, script, udtTypeScript));
    const data = udtTypeScript === null ? new Uint8Array(0) : new Uint8Array(UDT_AMOUNT_DATA_LENGTH);
    return mockTxSize(cellDepsCount, outputs, [data, data]);
}

/**
 * Port of fiber's `checked_fee_from_rate`: fee in shannons from a rate over a size, truncating.
 * @param feeRate Rate in shannons per 1000 bytes.
 * @param txSize Transaction size in bytes.
 * @returns The fee in shannons.
 */
export function calculateFee(feeRate: bigint, txSize: number): bigint {
    assertUnsignedBigInt("feeRate", feeRate, MAX_CAPACITY_SHANNONS);
    assertUnsignedInteger("txSize", txSize, Number.MAX_SAFE_INTEGER);
    const fee = (feeRate * BigInt(txSize)) / FEE_RATE_WEIGHT_SCALE;
    assertUnsignedBigInt("fee", fee, MAX_CAPACITY_SHANNONS);
    return fee;
}

/**
 * Measures the mock transaction every fee is sized over: zeroed deps and input, the given outputs, one zeroed witness.
 * @param cellDepsCount Number of zeroed cell deps to mock.
 * @param outputs Serialized outputs of the mock.
 * @param outputsData Raw output data of the mock.
 * @returns The size in bytes, block overhead included.
 */
function mockTxSize(cellDepsCount: number, outputs: Uint8Array[], outputsData: Uint8Array[]): number {
    assertUnsignedInteger("cellDepsCount", cellDepsCount, MAX_CELL_DEPS_COUNT);
    const raw = encodeRawTransaction({
        version: 0,
        cellDeps: Array.from({ length: cellDepsCount }, () => new Uint8Array(CELL_DEP_LENGTH)),
        headerDeps: [],
        inputs: [new Uint8Array(CELL_INPUT_LENGTH)],
        outputs,
        outputsData,
    });
    const transaction = encodeTransaction(raw, [new Uint8Array(FUNDING_CELL_WITNESS_LENGTH)]);
    return transaction.length + BLOCK_SIZE_OVERHEAD;
}
