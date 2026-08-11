import { concatBytes } from "@noble/hashes/utils.js";
import {
    COMPRESSED_POINT_LENGTH,
    MAX_AMOUNT_SHANNONS,
    assertBytes,
    assertUnsignedBigInt,
    assertUnsignedInteger,
    blake160,
    ckbBlake2b,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_COMMITMENT_NUMBER, pubkeyOf } from "../derivation";
import { MAX_CAPACITY_SHANNONS, MAX_SINCE_PAYLOAD, SINCE_RELATIVE_EPOCH_FLAGS } from "./digest.constants";
import type { RevocationInput } from "./digest.types";
import { calculateFee, commitmentTxSize } from "./fee";
import { aggregateXOnlyPubkey, encodeCellOutput, moleculeBytes, subtractFee, uint128Le, uint64Be, uint64Le } from "./utils";

/**
 * Recomputes a revocation digest: fiber's hash over the punishment output, its data, and the revoked cell's lock args.
 * @param keys The channel's four secrets.
 * @param input Everything the message is a function of, as the node attached it.
 * @returns The 32-byte digest a compliant signing request must carry.
 */
export function computeRevocationDigest(keys: FiberChannelKeys, input: RevocationInput): Uint8Array {
    assertBytes("remoteFundingPubkey", input.remoteFundingPubkey, COMPRESSED_POINT_LENGTH);
    assertUnsignedInteger("revokedCommitmentNumber", input.revokedCommitmentNumber, MAX_COMMITMENT_NUMBER);
    assertUnsignedBigInt("commitmentDelayEpoch", input.commitmentDelayEpoch, MAX_SINCE_PAYLOAD);
    assertUnsignedBigInt("toLocalShannons", input.toLocalShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("toRemoteShannons", input.toRemoteShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("localReservedCkbShannons", input.localReservedCkbShannons, MAX_CAPACITY_SHANNONS);
    assertUnsignedBigInt("remoteReservedCkbShannons", input.remoteReservedCkbShannons, MAX_CAPACITY_SHANNONS);

    // Role order on purpose: the x-only key must equal the one baked into the revoked commitment cell's lock args.
    const localFundingPubkey = pubkeyOf(keys.fundingKey);
    const orderedPubkeys: [Uint8Array, Uint8Array] = input.forRemote
        ? [localFundingPubkey, input.remoteFundingPubkey]
        : [input.remoteFundingPubkey, localFundingPubkey];

    const fee = calculateFee(input.commitmentFeeRate, commitmentTxSize(input.cellDepsCount, input.udtTypeScript, input.commitmentLock));
    const isUdt = input.udtTypeScript !== null;
    const liquidCapacity = input.toLocalShannons + input.toRemoteShannons;
    assertUnsignedBigInt("liquid capacity", liquidCapacity, MAX_AMOUNT_SHANNONS);
    const totalReserved = input.localReservedCkbShannons + input.remoteReservedCkbShannons;
    const capacity = subtractFee(isUdt ? totalReserved : liquidCapacity + totalReserved, fee);

    const output = encodeCellOutput(capacity, input.payoutScript, input.udtTypeScript);
    const outputData = moleculeBytes(isUdt ? uint128Le(liquidCapacity) : new Uint8Array(0));
    const lockArgs = concatBytes(
        blake160(aggregateXOnlyPubkey(orderedPubkeys)),
        uint64Le(SINCE_RELATIVE_EPOCH_FLAGS | input.commitmentDelayEpoch),
        uint64Be(BigInt(input.revokedCommitmentNumber)),
    );
    return ckbBlake2b(output, outputData, lockArgs);
}
