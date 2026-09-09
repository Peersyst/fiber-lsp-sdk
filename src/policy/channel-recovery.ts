import { bytesToHex } from "@noble/hashes/utils.js";
import { COMPRESSED_POINT_LENGTH, assertBytes, assertNonEmptyString, isDecimalShannons } from "../common";
import { CHANNEL_INDEX_SCAN_GAP } from "./policy.constants";
import type { ChannelReconciliation, NodeChannelState, ReconciledChannel } from "./policy.types";
import type { SignerStore } from "./signer-store";
import { buildChannelRecord } from "./utils";

export class ChannelRecovery {
    private readonly store: SignerStore;

    /**
     * Set by a reconciliation, and only in memory: a device that restarts reconciles again before it allocates.
     */
    private reconciled = false;

    /**
     * Creates the recovery half of the policy layer over a store.
     * @param store Typed persistence holding the records, the alias map and the allocator's counter.
     */
    constructor(store: SignerStore) {
        this.store = store;
    }

    /**
     * Maps the node's channels back onto the indexes that derive their keys, restoring every record the storage lost.
     * @param fundingPubkeyOf Derives the funding public key of a channel index; recovery never sees a secret.
     * @param nodeChannels The channels the node holds for this device, closed ones included: a used index is never free again.
     * @returns What each channel resolved to, the ones no index owns, and the counter the allocator continues from.
     */
    async reconcile(
        fundingPubkeyOf: (channelIndex: number) => Uint8Array,
        nodeChannels: readonly NodeChannelState[],
    ): Promise<ChannelReconciliation> {
        const wanted = new Set(nodeChannels.map((channel) => bytesToHex(assertNodeChannelState(channel).localFundingPubkey)));
        const indexByPubkey = await this.scanChannelIndexes(fundingPubkeyOf, wanted);

        const channels: ReconciledChannel[] = [];
        const unmatchedChannelIds: string[] = [];
        let highestIndex = -1;
        for (const channel of nodeChannels) {
            const channelIndex = indexByPubkey.get(bytesToHex(channel.localFundingPubkey));
            if (channelIndex === undefined) {
                unmatchedChannelIds.push(channel.channelId);
                continue;
            }
            channels.push({ channelId: channel.channelId, channelIndex, status: await this.restoreChannel(channelIndex, channel) });
            highestIndex = Math.max(highestIndex, channelIndex);
        }
        if (highestIndex >= 0) await this.store.raiseNextChannelIndex(highestIndex);

        this.reconciled = true;
        return { channels, unmatchedChannelIds, nextChannelIndex: await this.store.getNextChannelIndex() };
    }

    /**
     * Hands out the index a new channel derives its keys from.
     * @returns A channel index no channel on this device holds.
     */
    async allocateChannelIndex(): Promise<number> {
        if (!this.reconciled) {
            throw new Error("reconcile the node's channels before allocating a channel index");
        }
        return this.store.allocateChannelIndex();
    }

    /**
     * Walks the index space until every channel the node named is matched, or the scan runs past the gap.
     * @param fundingPubkeyOf Derives the funding public key of a channel index.
     * @param wanted Funding public keys to look for, as lowercase hex.
     * @returns The index each of the found public keys derives from.
     */
    private async scanChannelIndexes(
        fundingPubkeyOf: (channelIndex: number) => Uint8Array,
        wanted: ReadonlySet<string>,
    ): Promise<Map<string, number>> {
        const indexByPubkey = new Map<string, number>();
        let limit = (await this.store.getNextChannelIndex()) + CHANNEL_INDEX_SCAN_GAP;
        for (let channelIndex = 0; channelIndex < limit && indexByPubkey.size < wanted.size; channelIndex++) {
            const pubkey = fundingPubkeyOf(channelIndex);
            assertBytes(`fundingPubkeyOf(${channelIndex})`, pubkey, COMPRESSED_POINT_LENGTH);
            const hex = bytesToHex(pubkey);
            if (!wanted.has(hex) || indexByPubkey.has(hex)) continue;
            indexByPubkey.set(hex, channelIndex);
            limit = Math.max(limit, channelIndex + 1 + CHANNEL_INDEX_SCAN_GAP);
        }
        return indexByPubkey;
    }

    /**
     * Gives a channel back the record and the name it needs to be signed for again, leaving any record it still has alone.
     * @param channelIndex Index the channel's keys derive from.
     * @param channel The channel as the node reports it.
     * @returns Where the record the channel now has came from.
     */
    private async restoreChannel(channelIndex: number, channel: NodeChannelState): Promise<ReconciledChannel["status"]> {
        const existing = await this.store.getChannelRecord(channelIndex);
        let status: ReconciledChannel["status"] = "known";
        if (existing === null) {
            const watermark = await this.store.getChannelWatermark(channelIndex);
            status = watermark === null ? "unguarded" : "restored";
            await this.store.updateChannelRecord(
                channelIndex,
                (current) => current ?? buildChannelRecord(channel.channelId, watermark, channel.localExposureShannons),
            );
        }
        // After the record, as in registration: a name that resolves to an empty index has nothing to refuse with.
        await this.store.claimChannelAlias(channel.channelId, channelIndex);
        return status;
    }
}

/**
 * Asserts that a channel the node reported has the shape recovery reads it as.
 * @param channel Channel to check.
 * @returns The channel, unchanged.
 */
function assertNodeChannelState(channel: NodeChannelState): NodeChannelState {
    assertNonEmptyString("channelId", channel.channelId);
    assertBytes("localFundingPubkey", channel.localFundingPubkey, COMPRESSED_POINT_LENGTH);
    if (!isDecimalShannons(channel.localExposureShannons)) {
        throw new TypeError("localExposureShannons must be an amount in decimal shannons");
    }
    return channel;
}
