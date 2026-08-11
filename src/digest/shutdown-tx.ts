import { COMPRESSED_POINT_LENGTH, MAX_AMOUNT_SHANNONS, assertBytes, assertUnsignedBigInt, ckbBlake2b, compareBytes } from "../common";
import type { FiberChannelKeys } from "../derivation";
import { pubkeyOf } from "../derivation";
import { MAX_CAPACITY_SHANNONS } from "./digest.constants";
import type { ShutdownTxInput } from "./digest.types";
import { calculateFee, shutdownTxSize } from "./fee";
import { encodeCellInput, encodeCellOutput, encodeRawTransaction, subtractFee, uint128Le } from "./utils";

/**
 * Recomputes the digest of a cooperative-close (shutdown) tx: fiber's `compute_tx_message` over `build_shutdown_tx`.
 * @param keys The channel's four secrets.
 * @param input Everything the tx is a function of, as the node attached it.
 * @returns The 32-byte digest a compliant signing request must carry.
 */
export function computeShutdownTxDigest(keys: FiberChannelKeys, input: ShutdownTxInput): Uint8Array {
    assertBytes("remoteFundingPubkey", input.remoteFundingPubkey, COMPRESSED_POINT_LENGTH);
    assertUnsignedBigInt("toLocalShannons", input.toLocalShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("toRemoteShannons", input.toRemoteShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("localReservedCkbShannons", input.localReservedCkbShannons, MAX_CAPACITY_SHANNONS);
    assertUnsignedBigInt("remoteReservedCkbShannons", input.remoteReservedCkbShannons, MAX_CAPACITY_SHANNONS);

    const txSize = shutdownTxSize(input.cellDepsCount, input.udtTypeScript, [input.localCloseScript, input.remoteCloseScript]);
    const localFee = calculateFee(input.localFeeRate, txSize);
    const remoteFee = calculateFee(input.remoteFeeRate, txSize);
    const isUdt = input.udtTypeScript !== null;

    const localCapacity = subtractFee(
        isUdt ? input.localReservedCkbShannons : input.toLocalShannons + input.localReservedCkbShannons,
        localFee,
    );
    const remoteCapacity = subtractFee(
        isUdt ? input.remoteReservedCkbShannons : input.toRemoteShannons + input.remoteReservedCkbShannons,
        remoteFee,
    );
    const localOutput = encodeCellOutput(localCapacity, input.localCloseScript, input.udtTypeScript);
    const remoteOutput = encodeCellOutput(remoteCapacity, input.remoteCloseScript, input.udtTypeScript);
    const localData = isUdt ? uint128Le(input.toLocalShannons) : new Uint8Array(0);
    const remoteData = isUdt ? uint128Le(input.toRemoteShannons) : new Uint8Array(0);

    // The two outputs are permuted by the funding-pubkey sort, not by role: fiber's order_things_for_musig2.
    const localFirst = compareBytes(pubkeyOf(keys.fundingKey), input.remoteFundingPubkey) <= 0;
    const raw = encodeRawTransaction({
        version: 0,
        cellDeps: [],
        headerDeps: [],
        inputs: [encodeCellInput(0n, input.fundingOutPoint)],
        outputs: localFirst ? [localOutput, remoteOutput] : [remoteOutput, localOutput],
        outputsData: localFirst ? [localData, remoteData] : [remoteData, localData],
    });
    return ckbBlake2b(raw);
}
