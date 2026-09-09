import { equalBytes } from "@noble/curves/utils.js";
import { assertNonEmptyString, assertUnsignedInteger, isDecimalShannons } from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_CHANNEL_INDEX } from "../derivation";
import { computeChannelAnnouncementDigest, computeCommitmentTxDigest, computeRevocationDigest, computeShutdownTxDigest } from "../digest";
import type { SignerErrorCode } from "../protocol";
import { refuse } from "./policy.error";
import type { ChannelPolicyRecord, PolicySignRequest, PolicyVerdict, SignOperation } from "./policy.types";
import type { SignerStore } from "./signer-store";
import { assertSignSession, buildChannelRecord, buildSessionCommitment, resolveSignSlot, signSlotKey } from "./utils";

export class PolicyEngine {
    private readonly store: SignerStore;

    /**
     * Creates the gate over a store.
     * @param store Typed persistence the checks read and claim slots in.
     */
    constructor(store: SignerStore) {
        this.store = store;
    }

    /**
     * Registers a channel whose keys this device holds, creating the record every later check reads.
     * @param channelId Channel identifier the node uses on the wire, which the open handshake may still change.
     * @param channelIndex Index the channel seed derives from, the one piece recovery cannot re-seed from the node.
     * @param localExposureShannons The device's share at open, in decimal shannons.
     * @returns The stored record, the existing one when the channel was already registered.
     */
    async registerChannel(channelId: string, channelIndex: number, localExposureShannons: string): Promise<ChannelPolicyRecord> {
        assertNonEmptyString("channelId", channelId);
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        if (!isDecimalShannons(localExposureShannons)) {
            throw new TypeError("localExposureShannons must be an amount in decimal shannons");
        }
        const aliased = await this.store.resolveChannelIndex(channelId);
        if (aliased !== null && aliased !== channelIndex) {
            throw new TypeError(`channel ${channelId} is already registered under a different channel index`);
        }
        // An index with a watermark has signed before, so the record starts from it and not from zero.
        const watermark = await this.store.getChannelWatermark(channelIndex);
        const record = await this.store.updateChannelRecord(channelIndex, (current) => {
            if (current === null) {
                return buildChannelRecord(channelId, watermark, localExposureShannons);
            }
            if (current.channelId !== channelId) {
                assertUnservedRecord(channelIndex, current);
                return { ...current, channelId };
            }
            return current;
        });
        // Written after the record: the reverse order could leave a name resolving to an index that holds nothing.
        await this.store.claimChannelAlias(channelId, channelIndex);
        return record;
    }

    /**
     * Reads the index a channel's keys re-derive from.
     * @param channelId Channel identifier the alias is keyed by.
     * @returns The channel index.
     */
    async requireChannelIndex(channelId: string): Promise<number> {
        assertNonEmptyString("channelId", channelId);
        const channelIndex = await this.store.resolveChannelIndex(channelId);
        if (channelIndex === null) refuse("unknown_channel", `channel ${channelId} is not registered on this device`);
        return channelIndex;
    }

    /**
     * Records a user-initiated debit, the only thing that lets a later message lower the device's exposure.
     * @param channelId Channel identifier the alias is keyed by.
     * @param amountShannons Highest amount the user authorised, fee budget included, in decimal shannons.
     */
    async recordDebitIntent(channelId: string, amountShannons: string): Promise<void> {
        if (!isDecimalShannons(amountShannons)) {
            throw new TypeError("amountShannons must be an amount in decimal shannons");
        }
        const channelIndex = await this.requireChannelIndex(channelId);
        await this.store.updateChannelRecord(channelIndex, (current) => {
            if (current === null) throw missingRecord(channelId, channelIndex);
            return { ...current, pendingDebitsShannons: [...current.pendingDebitsShannons, amountShannons] };
        });
    }

    /**
     * Runs the five checks and claims the request's slot for its session, so the engine may sign it exactly once.
     * @param keys The channel's four secrets, which the digest recomputation needs.
     * @param request The signing request as the node sent it.
     * @returns The claimed slot, and whether this exact session had already been served.
     */
    async checkAndClaim(keys: FiberChannelKeys, request: PolicySignRequest): Promise<PolicyVerdict> {
        const { channelId, session, operation, stateVersion, nonceCommitmentNumber } = request;
        const slot = refusing("malformed", () => {
            assertNonEmptyString("channelId", channelId);
            assertUnsignedInteger("stateVersion", stateVersion, Number.MAX_SAFE_INTEGER);
            assertSignSession(keys, session);
            return resolveSignSlot(operation, nonceCommitmentNumber);
        });
        const sessionCommitment = buildSessionCommitment(session);
        const slotKey = signSlotKey(slot);
        const channelIndex = await this.requireChannelIndex(channelId);

        let status: PolicyVerdict["status"] = "fresh";
        await this.store.updateChannelRecord(channelIndex, (current) => {
            if (current === null) throw missingRecord(channelId, channelIndex);

            const expected = refusing("malformed", () => recomputeDigest(keys, operation));
            if (!equalBytes(expected, session.message)) {
                refuse("malformed", "the message does not match the attached channel state");
            }

            const served = current.signedSessions[slotKey];
            if (served !== undefined) {
                if (served !== sessionCommitment) {
                    refuse("policy_refusal", `slot ${slotKey} has already served a different signing session`);
                }
                status = "already-signed";
                return current;
            }

            const lastSigned = current.lastSignedCommitmentNumbers[slot.context];
            if (lastSigned !== undefined && slot.commitmentNumber <= lastSigned) {
                refuse(
                    "stale_state",
                    `commitment number ${slot.commitmentNumber} is not above the last ${slot.context} signed, ${lastSigned}`,
                );
            }
            if (stateVersion < current.lastStateVersion) {
                refuse("stale_state", `state version ${stateVersion} is below the last seen, ${current.lastStateVersion}`);
            }

            return {
                ...current,
                lastSignedCommitmentNumbers: { ...current.lastSignedCommitmentNumbers, [slot.context]: slot.commitmentNumber },
                signedSessions: { ...current.signedSessions, [slotKey]: sessionCommitment },
                lastStateVersion: stateVersion,
                ...applyExposureRule(current, operation),
            };
        });
        return { ...slot, status };
    }
}

/**
 * Asserts that a record may still take a new channel name, which only one that has never served a slot may do.
 * @param channelIndex Index the record is keyed by.
 * @param record The record found at that index.
 */
function assertUnservedRecord(channelIndex: number, record: ChannelPolicyRecord): void {
    const served = Object.keys(record.signedSessions).length > 0 || Object.keys(record.lastSignedCommitmentNumbers).length > 0;
    if (served) {
        throw new TypeError(`channel index ${channelIndex} already serves channel ${record.channelId}`);
    }
}

/**
 * Builds the failure of a channel name that resolves to an index holding no record.
 * @param channelId Channel identifier the name came from.
 * @param channelIndex Index it resolved to.
 * @returns The error to throw, never a refusal: the storage lost a record it still has the name of.
 */
function missingRecord(channelId: string, channelIndex: number): TypeError {
    return new TypeError(`channel ${channelId} resolves to channel index ${channelIndex}, which holds no record`);
}

/**
 * Rebuilds the message the request asks the device to sign, from the state the node attached to it.
 * @param keys The channel's four secrets.
 * @param operation Operation the request asks for, carrying its own inputs.
 * @returns The 32-byte digest a compliant request must carry.
 */
function recomputeDigest(keys: FiberChannelKeys, operation: SignOperation): Uint8Array {
    switch (operation.kind) {
        case "commitment_tx":
            return computeCommitmentTxDigest(keys, operation.input);
        case "shutdown_tx":
            return computeShutdownTxDigest(keys, operation.input);
        case "revocation":
            return computeRevocationDigest(keys, operation.input);
        case "channel_announcement":
            return computeChannelAnnouncementDigest(keys, operation.input);
    }
}

/**
 * Applies the balance rule: an exposure the message lowers must be covered by a user-initiated debit, which it consumes.
 * @param record The channel's current record.
 * @param operation Operation the request asks for.
 * @returns The exposure and debit fields of the record the claim writes.
 */
function applyExposureRule(
    record: ChannelPolicyRecord,
    operation: SignOperation,
): Pick<ChannelPolicyRecord, "localExposureShannons" | "pendingDebitsShannons"> {
    const exposure = localExposureOf(operation);
    const unchanged = {
        localExposureShannons: record.localExposureShannons,
        pendingDebitsShannons: record.pendingDebitsShannons,
    };
    if (exposure === null) return unchanged;

    const previous = BigInt(record.localExposureShannons);
    if (exposure >= previous) return { ...unchanged, localExposureShannons: exposure.toString() };

    const decrease = previous - exposure;
    const intent = smallestSufficientIntent(record.pendingDebitsShannons, decrease);
    if (intent === -1) {
        refuse("policy_refusal", `the message lowers the local amount by ${decrease} shannons with no debit intent covering it`);
    }
    return {
        localExposureShannons: exposure.toString(),
        pendingDebitsShannons: record.pendingDebitsShannons.filter((_, index) => index !== intent),
    };
}

/**
 * Reads the device's share out of an operation, for the operations that move funds.
 * @param operation Operation the request asks for.
 * @returns The exposure in shannons, or `null` when the message moves no funds.
 */
function localExposureOf(operation: SignOperation): bigint | null {
    switch (operation.kind) {
        case "commitment_tx":
            return operation.input.settlementLocalShannons;
        case "shutdown_tx":
            return operation.input.toLocalShannons;
        case "revocation":
        case "channel_announcement":
            return null;
    }
}

/**
 * Finds the smallest recorded debit that covers a decrease, so a large intent is not spent on a small one.
 * @param intents Pending debit intents, in decimal shannons.
 * @param decrease Amount the message lowers the exposure by.
 * @returns Index of the intent to consume, or `-1` when none covers the decrease.
 */
function smallestSufficientIntent(intents: readonly string[], decrease: bigint): number {
    let chosen = -1;
    let chosenAmount = 0n;
    for (const [index, intent] of intents.entries()) {
        const amount = BigInt(intent);
        if (amount < decrease) continue;
        if (chosen === -1 || amount < chosenAmount) {
            chosen = index;
            chosenAmount = amount;
        }
    }
    return chosen;
}

/**
 * Runs a step over node-supplied input, turning anything it throws into a wire refusal.
 * @param code Wire error code the refusal carries.
 * @param step Step to run.
 * @returns Whatever the step returned.
 */
function refusing<T>(code: SignerErrorCode, step: () => T): T {
    try {
        return step();
    } catch (error) {
        refuse(code, String(error));
    }
}
