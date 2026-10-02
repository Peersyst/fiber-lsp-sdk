import {
    COMPRESSED_POINT_LENGTH,
    MAX_AMOUNT_SHANNONS,
    assertBytes,
    assertUnsignedBigInt,
    ckbBlake2b,
    compareBytes,
    uint128Le,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { pubkeyOf } from "../derivation";
import { MAX_CAPACITY_SHANNONS } from "./digest.constants";
import type { ShutdownTxInput } from "./digest.types";
import { calculateTxFee, shutdownTxSize } from "./fee";
import { moleculeCellInput, moleculeCellOutput, moleculeRawTransaction, subtractTxFee } from "./utils";

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
    const localFee = calculateTxFee(input.localFeeRate, txSize);
    const remoteFee = calculateTxFee(input.remoteFeeRate, txSize);
    const isUdt = input.udtTypeScript !== null;

    const localCapacity = subtractTxFee(
        isUdt ? input.localReservedCkbShannons : input.toLocalShannons + input.localReservedCkbShannons,
        localFee,
    );
    const remoteCapacity = subtractTxFee(
        isUdt ? input.remoteReservedCkbShannons : input.toRemoteShannons + input.remoteReservedCkbShannons,
        remoteFee,
    );
    const localOutput = moleculeCellOutput(localCapacity, input.localCloseScript, input.udtTypeScript);
    const remoteOutput = moleculeCellOutput(remoteCapacity, input.remoteCloseScript, input.udtTypeScript);
    const localData = isUdt ? uint128Le(input.toLocalShannons) : new Uint8Array(0);
    const remoteData = isUdt ? uint128Le(input.toRemoteShannons) : new Uint8Array(0);

    // The two outputs are permuted by the funding-pubkey sort, not by role: fiber's order_things_for_musig2.
    const localFirst = compareBytes(pubkeyOf(keys.fundingKey), input.remoteFundingPubkey) <= 0;
    const raw = moleculeRawTransaction({
        version: 0,
        cellDeps: [],
        headerDeps: [],
        inputs: [moleculeCellInput(0n, input.fundingOutPoint)],
        outputs: localFirst ? [localOutput, remoteOutput] : [remoteOutput, localOutput],
        outputsData: localFirst ? [localData, remoteData] : [remoteData, localData],
    });
    return ckbBlake2b(raw);
}
