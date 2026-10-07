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
import { calculateShutdownTxFee } from "./fee";
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

    const localFee = calculateShutdownTxFee(input.localFeeRate, input);
    const remoteFee = calculateShutdownTxFee(input.remoteFeeRate, input);
    const isUdt = input.udtTypeScript !== null;

    const localTotal = isUdt ? input.localReservedCkbShannons : input.toLocalShannons + input.localReservedCkbShannons;
    const remoteTotal = isUdt ? input.remoteReservedCkbShannons : input.toRemoteShannons + input.remoteReservedCkbShannons;
    // Fiber reads the funding cell's capacity as a u64.
    assertUnsignedBigInt("funding capacity", localTotal + remoteTotal, MAX_CAPACITY_SHANNONS);
    const localCapacity = subtractTxFee(localTotal, localFee);
    const remoteCapacity = subtractTxFee(remoteTotal, remoteFee);
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
