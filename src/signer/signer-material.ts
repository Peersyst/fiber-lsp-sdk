import type { FiberChannelKeys } from "../derivation";
import type { ChannelOpenSignerMaterial, NextChannelSignerMaterial } from "../rpc";
import { getBasePublicKeys, getChannelCommitmentPoint, getPublicNonce } from "./musig2-engine";

/**
 * Builds the public material `open_tenant_channel` carries.
 * @param keys The channel's secrets.
 * @returns The material, with no announcement nonce.
 */
export function buildChannelOpenMaterial(keys: FiberChannelKeys): ChannelOpenSignerMaterial {
    const { fundingPubkey, tlcBasePubkey } = getBasePublicKeys(keys);
    // Fiber's `channel_open_material` (`fiber-lsp-sdk/src/signer.rs:318-360`, installed by `fiber-lib/src/fiber/channel.rs:5975-6005`);
    // a tenant channel is private, and fiber refuses an announcement nonce on one.
    return {
        fundingPubkey,
        tlcBaseKey: tlcBasePubkey,
        firstCommitmentPoint: getChannelCommitmentPoint(keys, 1),
        secondCommitmentPoint: getChannelCommitmentPoint(keys, 2),
        commitmentNonce: getPublicNonce(keys, 0, "COMMITMENT"),
        nextCommitmentNonce: getPublicNonce(keys, 1, "COMMITMENT"),
        revocationNonce: getPublicNonce(keys, 2, "REVOKE"),
        channelAnnouncementNonce: null,
    };
}

/**
 * Builds the material an answer carries for the next commitment number.
 * @param keys The channel's secrets.
 * @param commitmentNumber The number after the request's slot.
 * @returns The material.
 */
export function buildNextMaterial(keys: FiberChannelKeys, commitmentNumber: number): NextChannelSignerMaterial {
    // Fiber's `next_material` (`fiber-lsp-sdk/src/signer.rs:363-385`).
    return {
        nextCommitmentPoint: getChannelCommitmentPoint(keys, commitmentNumber),
        nextCommitmentNonce: getPublicNonce(keys, commitmentNumber, "COMMITMENT"),
        nextRevocationNonce: getPublicNonce(keys, commitmentNumber, "REVOKE"),
    };
}
