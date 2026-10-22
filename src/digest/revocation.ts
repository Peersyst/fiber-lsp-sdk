import { concatBytes } from "@noble/hashes/utils.js";
import type { CellOutput } from "../common";
import {
    COMPRESSED_POINT_LENGTH,
    MAX_AMOUNT_SHANNONS,
    assertBytes,
    assertUnsignedBigInt,
    assertUnsignedInteger,
    blake160,
    moleculeBytes,
    uint64Le,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_COMMITMENT_NUMBER, pubkeyOf } from "../derivation";
import { MAX_CAPACITY_SHANNONS, MAX_SINCE_PAYLOAD, SINCE_RELATIVE_EPOCH_FLAGS } from "./digest.constants";
import type { RevocationInput } from "./digest.types";
import { calculateCommitmentTxFee } from "./fee";
import { computeRevocationContentMessage } from "./tx-message";
import { aggregateXOnlyPubkey, commitmentCellValue, uint64Be } from "./utils";

/**
 * Fiber's hash over the punishment output, its data and the revoked cell's lock args.
 * @param keys The channel's secrets.
 * @param input What the message is a function of.
 * @returns The 32-byte digest.
 */
export function computeRevocationDigest(keys: FiberChannelKeys, input: RevocationInput): Uint8Array {
    const { output, outputData, commitmentLockArgs } = buildRevocationContent(keys, input);
    return computeRevocationContentMessage(output, outputData, commitmentLockArgs);
}

/**
 * The content of fiber's `Musig2SignableContent::Revocation`.
 * @param keys The channel's secrets.
 * @param input What the content is a function of.
 * @returns The output, its data as molecule `Bytes`, and the revoked cell's lock args.
 */
export function buildRevocationContent(
    keys: FiberChannelKeys,
    input: RevocationInput,
): { output: CellOutput; outputData: Uint8Array; commitmentLockArgs: Uint8Array } {
    assertBytes("remoteFundingPubkey", input.remoteFundingPubkey, COMPRESSED_POINT_LENGTH);
    assertUnsignedInteger("revokedCommitmentNumber", input.revokedCommitmentNumber, MAX_COMMITMENT_NUMBER);
    assertUnsignedBigInt("commitmentDelayEpoch", input.commitmentDelayEpoch, MAX_SINCE_PAYLOAD);
    assertUnsignedBigInt("liquidCapacityShannons", input.liquidCapacityShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("localReservedCkbShannons", input.localReservedCkbShannons, MAX_CAPACITY_SHANNONS);
    assertUnsignedBigInt("remoteReservedCkbShannons", input.remoteReservedCkbShannons, MAX_CAPACITY_SHANNONS);

    // Role order: the x-only key must equal the one in the revoked cell's lock args.
    const localFundingPubkey = pubkeyOf(keys.fundingKey);
    const orderedPubkeys: [Uint8Array, Uint8Array] = input.forRemote
        ? [localFundingPubkey, input.remoteFundingPubkey]
        : [input.remoteFundingPubkey, localFundingPubkey];

    const { capacityShannons, data } = commitmentCellValue(input, calculateCommitmentTxFee(input));
    const output: CellOutput = { capacityShannons, lock: input.payoutScript, type: input.udtTypeScript };
    const commitmentLockArgs = concatBytes(
        blake160(aggregateXOnlyPubkey(orderedPubkeys)),
        uint64Le(SINCE_RELATIVE_EPOCH_FLAGS | input.commitmentDelayEpoch),
        uint64Be(BigInt(input.revokedCommitmentNumber)),
    );
    return { output, outputData: moleculeBytes(data), commitmentLockArgs };
}
