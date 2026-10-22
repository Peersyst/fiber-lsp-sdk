import type { CellOutput, Script, Transaction } from "../common";
import {
    COMPRESSED_POINT_LENGTH,
    MAX_AMOUNT_SHANNONS,
    assertBytes,
    assertOutPoint,
    assertScript,
    assertUnsignedBigInt,
    compareBytes,
    isPlainObject,
    uint128Le,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { pubkeyOf } from "../derivation";
import { MAX_CAPACITY_SHANNONS } from "./digest.constants";
import type { ClosingTxInput, ShutdownTxInput } from "./digest.types";
import { calculateShutdownTxFee } from "./fee";
import { computeTxMessage } from "./tx-message";
import { subtractTxFee } from "./utils";

const CLOSING_TX_INPUTS = 1;
const CLOSING_TX_OUTPUTS = 2;

type ClosingTxUdt = {
    typeScript: Script;
    localAmountShannons: bigint;
    remoteAmountShannons: bigint;
};

/**
 * Fiber's `compute_tx_message` over `build_shutdown_tx`, from what the close's tx states.
 * @param keys The channel's secrets.
 * @param input What the node's tx states.
 * @returns The 32-byte digest.
 */
export function computeClosingTxDigest(keys: FiberChannelKeys, input: ClosingTxInput): Uint8Array {
    return computeTxMessage(buildClosingTx(keys, input, null));
}

/**
 * Reads a cooperative close's tx, assigning each output to its side by funding-pubkey order.
 * @param keys The channel's secrets.
 * @param remoteFundingPubkey The peer's funding pubkey.
 * @param tx The node's tx; cell deps, witnesses and data are left to the digest comparison.
 * @returns What the tx states.
 */
export function readClosingTx(keys: FiberChannelKeys, remoteFundingPubkey: Uint8Array, tx: Transaction): ClosingTxInput {
    assertBytes("remoteFundingPubkey", remoteFundingPubkey, COMPRESSED_POINT_LENGTH);
    if (!isPlainObject(tx)) throw new TypeError("closing tx must be an object");
    const { inputs, outputs } = tx;
    if (!Array.isArray(inputs) || inputs.length !== CLOSING_TX_INPUTS) {
        throw new TypeError(
            `closing tx must have exactly ${CLOSING_TX_INPUTS} input, got ${Array.isArray(inputs) ? inputs.length : "none"}`,
        );
    }
    if (!Array.isArray(outputs) || outputs.length !== CLOSING_TX_OUTPUTS) {
        throw new TypeError(
            `closing tx must have exactly ${CLOSING_TX_OUTPUTS} outputs, got ${Array.isArray(outputs) ? outputs.length : "none"}`,
        );
    }
    const [input] = inputs;
    if (!isPlainObject(input)) throw new TypeError("closing tx inputs[0] must be an object");
    assertOutPoint("closing tx inputs[0].previousOutput", input.previousOutput);
    const [first, second] = outputs.map((output, index) => readClosingOutput(output, `closing tx outputs[${index}]`)) as [
        CellOutput,
        CellOutput,
    ];
    const [local, remote] = isLocalFirst(keys, remoteFundingPubkey) ? [first, second] : [second, first];
    return {
        fundingOutPoint: input.previousOutput,
        remoteFundingPubkey,
        localCloseScript: local.lock,
        remoteCloseScript: remote.lock,
        localCapacityShannons: local.capacityShannons,
        remoteCapacityShannons: remote.capacityShannons,
    };
}

/**
 * Checks one output of a CKB close: a capacity, a lock, and no type script.
 * @param output The output.
 * @param name Its path, for the refusal.
 * @returns The output.
 */
function readClosingOutput(output: CellOutput, name: string): CellOutput {
    if (!isPlainObject(output)) throw new TypeError(`${name} must be an object`);
    assertUnsignedBigInt(`${name}.capacityShannons`, output.capacityShannons, MAX_CAPACITY_SHANNONS);
    assertScript(`${name}.lock`, output.lock);
    if (output.type !== null) throw new TypeError(`${name} must carry no type script: a closing input is CKB only`);
    return output;
}

/**
 * Port of fiber's `should_local_go_first_in_musig2`.
 * @param keys The channel's secrets.
 * @param remoteFundingPubkey The peer's funding pubkey.
 * @returns `true` when the device's funding pubkey sorts first or equal.
 */
function isLocalFirst(keys: FiberChannelKeys, remoteFundingPubkey: Uint8Array): boolean {
    return compareBytes(pubkeyOf(keys.fundingKey), remoteFundingPubkey) <= 0;
}

/**
 * Fiber's `compute_tx_message` over `build_shutdown_tx`, from the fee rates.
 * @param keys The channel's secrets.
 * @param input What the tx is a function of.
 * @returns The 32-byte digest.
 */
export function computeShutdownTxDigest(keys: FiberChannelKeys, input: ShutdownTxInput): Uint8Array {
    assertBytes("remoteFundingPubkey", input.remoteFundingPubkey, COMPRESSED_POINT_LENGTH);
    assertUnsignedBigInt("toLocalShannons", input.toLocalShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("toRemoteShannons", input.toRemoteShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("localReservedCkbShannons", input.localReservedCkbShannons, MAX_CAPACITY_SHANNONS);
    assertUnsignedBigInt("remoteReservedCkbShannons", input.remoteReservedCkbShannons, MAX_CAPACITY_SHANNONS);

    const localFee = calculateShutdownTxFee(input.localFeeRate, input);
    const remoteFee = calculateShutdownTxFee(input.remoteFeeRate, input);
    const udt = input.udtTypeScript;

    const localTotal = udt === null ? input.toLocalShannons + input.localReservedCkbShannons : input.localReservedCkbShannons;
    const remoteTotal = udt === null ? input.toRemoteShannons + input.remoteReservedCkbShannons : input.remoteReservedCkbShannons;
    // Fiber reads the funding cell's capacity as a u64.
    assertUnsignedBigInt("funding capacity", localTotal + remoteTotal, MAX_CAPACITY_SHANNONS);
    const closing: ClosingTxInput = {
        fundingOutPoint: input.fundingOutPoint,
        remoteFundingPubkey: input.remoteFundingPubkey,
        localCloseScript: input.localCloseScript,
        remoteCloseScript: input.remoteCloseScript,
        localCapacityShannons: subtractTxFee(localTotal, localFee),
        remoteCapacityShannons: subtractTxFee(remoteTotal, remoteFee),
    };
    return computeTxMessage(
        buildClosingTx(
            keys,
            closing,
            udt === null
                ? null
                : { typeScript: udt, localAmountShannons: input.toLocalShannons, remoteAmountShannons: input.toRemoteShannons },
        ),
    );
}

/**
 * Port of fiber's `build_shutdown_tx`: the funding cell into one output per side, in funding-pubkey order.
 * @param keys The channel's secrets.
 * @param input The out point, close scripts and capacities.
 * @param udt The UDT and each side's amount, or `null` on a CKB channel.
 * @returns The unsigned tx, without cell deps.
 */
export function buildClosingTx(keys: FiberChannelKeys, input: ClosingTxInput, udt: ClosingTxUdt | null): Transaction {
    assertOutPoint("fundingOutPoint", input.fundingOutPoint);
    assertBytes("remoteFundingPubkey", input.remoteFundingPubkey, COMPRESSED_POINT_LENGTH);
    assertScript("localCloseScript", input.localCloseScript);
    assertScript("remoteCloseScript", input.remoteCloseScript);
    assertUnsignedBigInt("localCapacityShannons", input.localCapacityShannons, MAX_CAPACITY_SHANNONS);
    assertUnsignedBigInt("remoteCapacityShannons", input.remoteCapacityShannons, MAX_CAPACITY_SHANNONS);
    const type = udt?.typeScript ?? null;
    const localOutput: CellOutput = { capacityShannons: input.localCapacityShannons, lock: input.localCloseScript, type };
    const remoteOutput: CellOutput = { capacityShannons: input.remoteCapacityShannons, lock: input.remoteCloseScript, type };
    const localData = udt === null ? new Uint8Array(0) : uint128Le(udt.localAmountShannons);
    const remoteData = udt === null ? new Uint8Array(0) : uint128Le(udt.remoteAmountShannons);
    const localFirst = isLocalFirst(keys, input.remoteFundingPubkey);
    return {
        version: 0,
        cellDeps: [],
        headerDeps: [],
        inputs: [{ since: 0n, previousOutput: input.fundingOutPoint }],
        outputs: localFirst ? [localOutput, remoteOutput] : [remoteOutput, localOutput],
        outputsData: localFirst ? [localData, remoteData] : [remoteData, localData],
        witnesses: [],
    };
}
