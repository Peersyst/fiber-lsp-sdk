import { equalBytes } from "@noble/curves/utils.js";
import type { SignerErrorCode, TlcHashAlgorithm } from "../common";
import {
    PAYMENT_HASH_LENGTH,
    TLC_HASH_ALGORITHMS,
    TRUNCATED_PAYMENT_HASH_LENGTH,
    assertDecimalShannons,
    assertHexBytes,
    assertNonEmptyString,
    assertOneOf,
    assertUnsignedInteger,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_CHANNEL_INDEX } from "../derivation";
import { computeChannelAnnouncementDigest, computeCommitmentTxDigest, computeRevocationDigest, computeShutdownTxDigest } from "../digest";
import { judgeCommitment, judgeShutdown, toPolicyViewTlcs } from "./balance-rule";
import { CHANNEL_POLICY_RECORD_VERSION, PAYMENT_RECORD_VERSION, POLICY_VIEWS } from "./policy.constants";
import { DebitIntentError, HoldInvoiceError, refusePolicyRequest } from "./policy.error";
import type {
    BalanceRuleContext,
    ChannelPolicyRecord,
    DebitIntentRecord,
    HoldInvoicePolicyRecord,
    PolicySignRequest,
    PolicyVerdict,
    PolicyView,
    PolicyViewSnapshot,
    PolicyViewTlc,
    SignOperation,
    SignSlotRef,
} from "./policy.types";
import type { SignerStore } from "./signer-store";
import { assertSignSession, boundPaymentHashOf, buildSessionCommitment, resolveSignSlot, signSlotKey } from "./utils";

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
        assertDecimalShannons("localExposureShannons", localExposureShannons);
        const aliased = await this.store.resolveChannelIndex(channelId);
        if (aliased !== null && aliased !== channelIndex) {
            throw new TypeError(`channel ${channelId} is already registered under a different channel index`);
        }
        const record = await this.store.updateChannelRecord(channelIndex, (current) => {
            if (current === null) {
                return {
                    version: CHANNEL_POLICY_RECORD_VERSION,
                    channelId,
                    lastSignedCommitmentNumbers: {},
                    signedSessions: {},
                    lastStateVersion: 0,
                    views: { remote: openingSnapshot(localExposureShannons), local: openingSnapshot(localExposureShannons) },
                };
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
        if (channelIndex === null) refusePolicyRequest("unknown_channel", `channel ${channelId} is not registered on this device`);
        return channelIndex;
    }

    /**
     * Records the budget the user approved for a payment, the only thing that lets an offered TLC under its hash be signed.
     * @param paymentHashHex The payment hash, 32 bytes of lowercase hex.
     * @param maxShannons Highest amount the payment may take, fee budget included, in decimal shannons.
     */
    async recordDebitIntent(paymentHashHex: string, maxShannons: string): Promise<void> {
        assertHexBytes("paymentHashHex", paymentHashHex, PAYMENT_HASH_LENGTH);
        assertDecimalShannons("maxShannons", maxShannons);
        const key = boundPaymentHashOf(paymentHashHex);
        await this.store.withBalanceLock(async () => {
            // The rule would read the hash both as a payment out and as an invoice.
            if ((await this.store.getHoldInvoiceRecord(key)) !== null) {
                throw new DebitIntentError("own_invoice", `${paymentHashHex} is the hash of a hold invoice of this device`);
            }
            const current = await this.store.getDebitIntent(key);
            if (current !== null) {
                assertSameHash(current, paymentHashHex);
                if (current.open) {
                    // Idempotent repeat.
                    if (current.maxShannons === maxShannons) return;
                    throw new DebitIntentError("intent_open", `a debit intent for ${paymentHashHex} is already open with another maximum`);
                }
                if (await this.chargedAnywhere(current)) {
                    throw new DebitIntentError(
                        "intent_charged",
                        `a payment under ${paymentHashHex} has already been charged, it cannot be authorised again`,
                    );
                }
            }
            await this.store.updateDebitIntent(key, () => ({
                version: PAYMENT_RECORD_VERSION,
                paymentHash: paymentHashHex,
                maxShannons,
                open: true,
                channelIndexes: current?.channelIndexes ?? [],
            }));
        });
    }

    /**
     * Closes a payment's debit intent, so no TLC under its hash may grow; those already shown stay signable.
     * @param paymentHashHex The payment hash, 32 bytes of lowercase hex.
     */
    async closeDebitIntent(paymentHashHex: string): Promise<void> {
        assertHexBytes("paymentHashHex", paymentHashHex, PAYMENT_HASH_LENGTH);
        await this.store.withBalanceLock(async () => {
            await this.store.updateDebitIntent(boundPaymentHashOf(paymentHashHex), (current) => {
                if (current === null) throw new TypeError(`no debit intent was recorded for ${paymentHashHex}`);
                assertSameHash(current, paymentHashHex);
                return current.open ? { ...current, open: false } : current;
            });
        });
    }

    /**
     * Records a hold invoice whose preimage this device holds, before the node hears of its hash.
     * @param paymentHashHex The payment hash, 32 bytes of lowercase hex.
     * @param amountShannons The invoice's amount, in decimal shannons.
     * @param hashAlgorithm The algorithm the invoice locks its payment with.
     */
    async recordHoldInvoice(paymentHashHex: string, amountShannons: string, hashAlgorithm: TlcHashAlgorithm): Promise<void> {
        assertHexBytes("paymentHashHex", paymentHashHex, PAYMENT_HASH_LENGTH);
        assertDecimalShannons("amountShannons", amountShannons);
        assertOneOf("hashAlgorithm", hashAlgorithm, TLC_HASH_ALGORITHMS);
        const key = boundPaymentHashOf(paymentHashHex);
        await this.store.withBalanceLock(async () => {
            // A host bug, not the user's: the preimage is derived per invoice.
            if ((await this.store.getDebitIntent(key)) !== null) {
                throw new TypeError(`${paymentHashHex} is the hash of a payment this device has authorised`);
            }
            await this.store.updateHoldInvoiceRecord(key, (current) => {
                if (current === null) {
                    return {
                        version: PAYMENT_RECORD_VERSION,
                        paymentHash: paymentHashHex,
                        amountShannons,
                        hashAlgorithm,
                        released: false,
                        channelIndexes: [],
                    };
                }
                assertSameHash(current, paymentHashHex);
                if (current.amountShannons !== amountShannons || current.hashAlgorithm !== hashAlgorithm) {
                    throw new TypeError(`a hold invoice for ${paymentHashHex} is already recorded with another amount or algorithm`);
                }
                return current;
            });
        });
    }

    /**
     * Marks a hold invoice's preimage as released, from when on every commitment must pay for its received TLCs.
     * @param paymentHashHex The payment hash, 32 bytes of lowercase hex.
     */
    async markHoldInvoiceReleased(paymentHashHex: string): Promise<void> {
        assertHexBytes("paymentHashHex", paymentHashHex, PAYMENT_HASH_LENGTH);
        const key = boundPaymentHashOf(paymentHashHex);
        await this.store.withBalanceLock(async () => {
            const current = await this.store.getHoldInvoiceRecord(key);
            if (current === null) throw new TypeError(`no hold invoice was recorded for ${paymentHashHex}`);
            assertSameHash(current, paymentHashHex);
            if (current.released) return;
            // An offered TLC failing beside a released held one could pass for both being paid.
            for (const index of current.channelIndexes) {
                const record = await this.store.getChannelRecord(index);
                if (record === null) throw unlistedRecord(index);
                const tlcs = POLICY_VIEWS.flatMap((view) => record.views[view].tlcs);
                // Received only: no intent can take this hash.
                const held = tlcs.filter((tlc) => tlc.boundPaymentHash === key);
                // The preimage does not open a TLC under another algorithm.
                if (held.some((tlc) => tlc.hashAlgorithm !== current.hashAlgorithm)) {
                    throw new HoldInvoiceError(
                        "algorithm_mismatch",
                        `channel index ${index} lists a TLC under ${paymentHashHex} locked with another algorithm than the invoice's`,
                    );
                }
                const holds = held.length > 0;
                if (holds && tlcs.some((tlc) => tlc.direction === "offered")) {
                    throw new HoldInvoiceError(
                        "offered_in_flight",
                        `channel index ${index} lists an offered TLC, so the preimage of ${paymentHashHex} is not released yet`,
                    );
                }
            }
            await this.store.updateHoldInvoiceRecord(key, (latest) => {
                if (latest === null) throw vanishedPaymentRecord();
                return { ...latest, released: true };
            });
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
        const channelIndex = await this.requireChannelIndex(channelId);

        const expected = refusing("malformed", () => recomputeDigest(keys, operation));
        if (!equalBytes(expected, session.message)) {
            refusePolicyRequest("malformed", "the message does not match the attached channel state");
        }

        const claim: Claim = {
            channelId,
            channelIndex,
            slot,
            sessionCommitment: buildSessionCommitment(session),
            stateVersion,
            operation,
            tlcs: operation.kind === "commitment_tx" ? toPolicyViewTlcs(operation.input.tlcs) : [],
        };
        // Serialized: channels share budgets, and nothing may move the record between deciding and claiming.
        return this.store.withBalanceLock(async () => {
            const current = await this.store.getChannelRecord(channelIndex);
            if (current === null) throw missingRecord(channelId, channelIndex);
            const context = await this.loadBalanceContext(claim, current);
            // Decided before writing, so a refusal leaves the payment records untouched.
            if (decideClaim(claim, current, context).verdict.status === "fresh") {
                await this.fileChannel(claim, context);
            }
            return this.claim(claim, context);
        });
    }

    /**
     * Decides a claim on the channel's record and writes it, as one step on the record.
     * @param claim The checked request.
     * @param context What the balance rule reads beyond the record, empty for an operation that reads nothing.
     * @returns The verdict.
     */
    private async claim(claim: Claim, context: BalanceRuleContext): Promise<PolicyVerdict> {
        let verdict: PolicyVerdict = { ...claim.slot, status: "fresh" };
        await this.store.updateChannelRecord(claim.channelIndex, (current) => {
            if (current === null) throw missingRecord(claim.channelId, claim.channelIndex);
            const decision = decideClaim(claim, current, context);
            verdict = decision.verdict;
            return decision.record;
        });
        return verdict;
    }

    /**
     * Loads what the balance rule reads for a commitment beyond the channel's record.
     * @param claim The checked request, whose channel is left out of the other channels.
     * @param record The channel's record.
     * @returns The intents and invoices under every hash involved, and both views of every other channel they list.
     */
    private async loadBalanceContext(claim: Claim, record: ChannelPolicyRecord): Promise<BalanceRuleContext> {
        const intents = new Map<string, DebitIntentRecord>();
        const invoices = new Map<string, HoldInvoicePolicyRecord>();
        if (claim.operation.kind !== "commitment_tx") return { intents, invoices, otherChannels: [] };

        // The rule reads the invoices of both views.
        const listed = [...claim.tlcs, ...record.views.remote.tlcs, ...record.views.local.tlcs];
        const hashes = new Set(listed.map((tlc) => tlc.boundPaymentHash));
        const others = new Set<number>();
        for (const hash of hashes) {
            const intent = await this.store.getDebitIntent(hash);
            const invoice = await this.store.getHoldInvoiceRecord(hash);
            if (intent !== null) intents.set(hash, intent);
            if (invoice !== null) invoices.set(hash, invoice);
            for (const index of [...(intent?.channelIndexes ?? []), ...(invoice?.channelIndexes ?? [])]) others.add(index);
        }
        others.delete(claim.channelIndex);

        const otherChannels: Record<PolicyView, PolicyViewSnapshot>[] = [];
        for (const index of others) {
            const other = await this.store.getChannelRecord(index);
            if (other === null) throw unlistedRecord(index);
            otherChannels.push(other.views);
        }
        return { intents, invoices, otherChannels };
    }

    /**
     * Lists the channel on the record of every hash its commitment shows, before the claim that shows it is written.
     * @param claim The commitment or close about to be claimed.
     * @param context The records loaded for it, which say which hashes have one.
     */
    private async fileChannel(claim: Claim, context: BalanceRuleContext): Promise<void> {
        const { channelIndex } = claim;
        for (const hash of new Set(claim.tlcs.map((tlc) => tlc.boundPaymentHash))) {
            if (context.intents.has(hash)) await this.store.updateDebitIntent(hash, (current) => withChannel(current, channelIndex));
            if (context.invoices.has(hash)) await this.store.updateHoldInvoiceRecord(hash, (current) => withChannel(current, channelIndex));
        }
    }

    /**
     * Tells whether anything has been charged to a debit intent, in any channel and either view.
     * @param intent The intent.
     * @returns Whether some view of some channel it lists holds a charge under its hash.
     */
    private async chargedAnywhere(intent: DebitIntentRecord): Promise<boolean> {
        const hash = boundPaymentHashOf(intent.paymentHash);
        for (const index of intent.channelIndexes) {
            const record = await this.store.getChannelRecord(index);
            if (record === null) throw unlistedRecord(index);
            if (POLICY_VIEWS.some((view) => record.views[view].chargedShannons[hash] !== undefined)) return true;
        }
        return false;
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
 * Builds the failure of a payment record that vanished, which only a broken storage causes.
 * @returns The error to throw.
 */
function vanishedPaymentRecord(): TypeError {
    return new TypeError("a payment record disappeared inside the balance lane");
}

/**
 * Builds the failure of a payment record that lists a channel holding no record.
 * @param channelIndex Index the payment record lists.
 * @returns The error to throw.
 */
function unlistedRecord(channelIndex: number): TypeError {
    return new TypeError(`a payment record lists channel index ${channelIndex}, which holds no record`);
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
 * A request whose shape, channel and digest have been checked.
 */
type Claim = {
    channelId: string;
    channelIndex: number;
    slot: SignSlotRef;
    sessionCommitment: string;
    stateVersion: number;
    operation: SignOperation;
    /**
     * Empty for any operation but a commitment.
     */
    tlcs: PolicyViewTlc[];
};

/**
 * Runs sign-once, monotonicity and the balance rule over a record, without writing anything.
 * @param claim The checked request.
 * @param current The channel's record.
 * @param context What the balance rule reads beyond the record, empty for an operation that reads nothing.
 * @returns The verdict, and the record to write: the one given when nothing changes.
 */
function decideClaim(
    claim: Claim,
    current: ChannelPolicyRecord,
    context: BalanceRuleContext,
): { verdict: PolicyVerdict; record: ChannelPolicyRecord } {
    const { slot, sessionCommitment, stateVersion } = claim;
    const slotKey = signSlotKey(slot);
    const served = current.signedSessions[slotKey];
    if (served !== undefined) {
        if (served !== sessionCommitment) {
            refusePolicyRequest("policy_refusal", `slot ${slotKey} has already served a different signing session`);
        }
        return { verdict: { ...slot, status: "already-signed" }, record: current };
    }

    const lastSigned = current.lastSignedCommitmentNumbers[slot.context];
    if (lastSigned !== undefined && slot.commitmentNumber <= lastSigned) {
        refusePolicyRequest(
            "stale_state",
            `commitment number ${slot.commitmentNumber} is not above the last ${slot.context} signed, ${lastSigned}`,
        );
    }
    if (stateVersion < current.lastStateVersion) {
        refusePolicyRequest("stale_state", `state version ${stateVersion} is below the last seen, ${current.lastStateVersion}`);
    }

    return {
        verdict: { ...slot, status: "fresh" },
        record: {
            ...current,
            lastSignedCommitmentNumbers: { ...current.lastSignedCommitmentNumbers, [slot.context]: slot.commitmentNumber },
            signedSessions: { ...current.signedSessions, [slotKey]: sessionCommitment },
            lastStateVersion: stateVersion,
            views: applyBalanceRule(current.views, claim, context),
        },
    };
}

/**
 * Applies the balance rule to the operations that move funds.
 * @param views The channel's two snapshots.
 * @param claim The checked request, carrying the operation and the TLCs it lists.
 * @param context What the rule reads beyond the record.
 * @returns The snapshots once the operation is signed.
 */
function applyBalanceRule(
    views: Record<PolicyView, PolicyViewSnapshot>,
    claim: Claim,
    context: BalanceRuleContext,
): Record<PolicyView, PolicyViewSnapshot> {
    const { operation } = claim;
    switch (operation.kind) {
        case "commitment_tx": {
            const view = viewOf(operation.input.forRemote);
            const next = { exposureShannons: operation.input.settlementLocalShannons, tlcs: claim.tlcs };
            return { ...views, [view]: judgeCommitment(view, views, next, context) };
        }
        case "shutdown_tx":
            judgeShutdown(views, operation.input.toLocalShannons);
            return views;
        case "revocation":
        case "channel_announcement":
            return views;
    }
}

/**
 * Names the view a commitment belongs to.
 * @param forRemote Fiber's direction parameter of the commitment.
 * @returns `remote` for the peer's commitment, `local` for the device's own.
 */
function viewOf(forRemote: boolean): PolicyView {
    return forRemote ? "remote" : "local";
}

/**
 * Builds a view's state before its first message: no TLCs, nothing charged or credited.
 * @param exposureShannons The device's share at open, in decimal shannons.
 * @returns The opening snapshot.
 */
function openingSnapshot(exposureShannons: string): PolicyViewSnapshot {
    return { exposureShannons, tlcs: [], chargedShannons: {}, creditedShannons: {} };
}

/**
 * Asserts that a record filed under a bound payment hash is the one for this full hash.
 * @param record The record found.
 * @param paymentHashHex The full payment hash the caller named.
 */
function assertSameHash(record: { paymentHash: string }, paymentHashHex: string): void {
    if (record.paymentHash !== paymentHashHex) {
        throw new TypeError(
            `${paymentHashHex} shares its bound ${TRUNCATED_PAYMENT_HASH_LENGTH} bytes with a recorded payment, ${record.paymentHash}`,
        );
    }
}

/**
 * Adds a channel to the channels a payment record lists.
 * @param current The record.
 * @param channelIndex The channel's index.
 * @returns The record listing the channel, the one given when it already did.
 */
function withChannel<T extends { channelIndexes: number[] }>(current: T | null, channelIndex: number): T {
    if (current === null) throw vanishedPaymentRecord();
    if (current.channelIndexes.includes(channelIndex)) return current;
    return { ...current, channelIndexes: [...current.channelIndexes, channelIndex] };
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
        refusePolicyRequest(code, String(error));
    }
}
