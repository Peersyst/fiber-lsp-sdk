import { COMPRESSED_POINT_LENGTH, MAX_AMOUNT_SHANNONS, assertBytes, assertUnsignedBigInt, ckbBlake2b, compareBytes } from "../common";
import type { FiberChannelKeys } from "../derivation";
import { pubkeyOf } from "../derivation";
import type { ChannelAnnouncementInput } from "./digest.types";
import { aggregateXOnlyPubkey, encodeOutPoint, encodeScriptOpt, moleculeTable, uint128Le, uint64Le } from "./utils";

const CHAIN_HASH_LENGTH = 32;
const SIGNATURE_PLACEHOLDER_LENGTH = 64;

/**
 * Recomputes a channel announcement digest: fiber's `message_to_sign` over the announcement with zeroed signatures.
 * @param keys The channel's four secrets.
 * @param input Everything the announcement is a function of, as the node attached it.
 * @returns The 32-byte digest a compliant signing request must carry.
 */
export function computeChannelAnnouncementDigest(keys: FiberChannelKeys, input: ChannelAnnouncementInput): Uint8Array {
    assertBytes("chainHash", input.chainHash, CHAIN_HASH_LENGTH);
    assertBytes("nodeIds[0]", input.nodeIds[0], COMPRESSED_POINT_LENGTH);
    assertBytes("nodeIds[1]", input.nodeIds[1], COMPRESSED_POINT_LENGTH);
    assertBytes("remoteFundingPubkey", input.remoteFundingPubkey, COMPRESSED_POINT_LENGTH);
    assertUnsignedBigInt("capacityShannons", input.capacityShannons, MAX_AMOUNT_SHANNONS);

    const localFundingPubkey = pubkeyOf(keys.fundingKey);
    const sortedFundingPubkeys: [Uint8Array, Uint8Array] =
        compareBytes(localFundingPubkey, input.remoteFundingPubkey) <= 0
            ? [localFundingPubkey, input.remoteFundingPubkey]
            : [input.remoteFundingPubkey, localFundingPubkey];
    const [firstNode, secondNode] = input.nodeIds;
    const sortedNodeIds = compareBytes(firstNode, secondNode) <= 0 ? [firstNode, secondNode] : [secondNode, firstNode];

    // The unsigned announcement is the full table with the two ECDSA and one Schnorr signature fields left zeroed, and the
    // feature vector at the only value fiber ever builds it with: `ChannelAnnouncement::new_unsigned` defaults it to zero.
    const announcement = moleculeTable([
        new Uint8Array(SIGNATURE_PLACEHOLDER_LENGTH),
        new Uint8Array(SIGNATURE_PLACEHOLDER_LENGTH),
        new Uint8Array(SIGNATURE_PLACEHOLDER_LENGTH),
        uint64Le(0n),
        input.chainHash,
        encodeOutPoint(input.fundingOutPoint),
        ...sortedNodeIds,
        aggregateXOnlyPubkey(sortedFundingPubkeys),
        uint128Le(input.capacityShannons),
        encodeScriptOpt(input.udtTypeScript),
    ]);
    return ckbBlake2b(announcement);
}
