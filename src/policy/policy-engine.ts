import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { OutPoint, Script, SignerErrorCode, TlcHashAlgorithm } from "../common";
import {
    PAYMENT_HASH_LENGTH,
    SCHNORR_SIGNATURE_LENGTH,
    TLC_HASH_ALGORITHMS,
    TRUNCATED_PAYMENT_HASH_LENGTH,
    UINT64_MAX,
    assertBytes,
    assertDecimalShannons,
    assertHexBytes,
    assertNonEmptyString,
    assertOneOf,
    assertOutPoint,
    assertUnsignedBigInt,
    assertUnsignedInteger,
    isPlainObject,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_CHANNEL_INDEX } from "../derivation";
import { computeChannelAnnouncementDigest, computeClosingTxDigest, computeCommitmentTxDigest, computeRevocationDigest } from "../digest";
import { judgeClosingTx, judgeCommitment, judgeOpeningCommitment, toPolicyViewTlcs } from "./balance-rule";
import { judgeCapacityBounds } from "./capacity-bounds";
import { openingChannelPins } from "./channel-opening";
import { channelTermsPins, findChannelPinConflict, fundingCellPins, statedChannelPins, withChannelPins } from "./channel-pins";
import {
    CHANNEL_POLICY_RECORD_VERSION,
    CHANNEL_TERMS_PINS,
    FIRST_SIGHT_CHANNEL_PINS,
    MAX_REVOKED_VERSION,
    NONCE_REUSE_MODES,
    PAYMENT_RECORD_VERSION,
    POLICY_VIEWS,
} from "./policy.constants";
import { ChannelPinError, DebitIntentError, HoldInvoiceError, refusePolicyRequest } from "./policy.error";
import type {
    BalanceRuleContext,
    ChannelPins,
    ChannelPolicyRecord,
    ChannelTermsPin,
    DebitIntentRecord,
    FirstSightChannelPin,
    HoldInvoicePolicyRecord,
    NonceReuseMode,
    PolicyChannelTerms,
    PolicyEngineOptions,
    PolicySignRequest,
    PolicyVerdict,
    PolicyView,
    PolicyViewSnapshot,
    PolicyViewTlc,
    RevocationEvidence,
    RevokedCommitmentSignature,
    SignOperation,
    SignSlotClaim,
    StatedChannelPins,
} from "./policy.types";
import type { SignerStore } from "./signer-store";
import { assertSignSession, boundPaymentHashOf, buildSessionCommitment, isTlcOfPaymentRecord, resolveSignSlot, signSlotKey } from "./utils";

export class PolicyEngine {
    private readonly store: SignerStore;

    private readonly nonceReuse: NonceReuseMode;

    /**
     * Creates the gate over a store.
     * @param store Typed persistence the checks read and claim slots in.
     * @param options The nonce reuse mode.
     */
    constructor(store: SignerStore, options: PolicyEngineOptions = {}) {
        if (!isPlainObject(options)) throw new TypeError("options must be an object");
        // Not `??`: a `null` is refused below.
        const nonceReuse = options.nonceReuse === undefined ? "refuse" : options.nonceReuse;
        assertOneOf("options.nonceReuse", nonceReuse, NONCE_REUSE_MODES);
        this.store = store;
        this.nonceReuse = nonceReuse;
    }

    /**
     * Registers a channel whose keys this device holds, creating the record every later check reads.
     * @param channelId Channel id, which the open handshake may still change.
     * @param channelIndex Index the channel seed derives from.
     * @param fundedShannons What the user paid in, reserve included.
     * @param localCloseScript The open's shutdown script.
     * @returns The stored record, the existing one on a repeat.
     */
    async registerChannel(
        channelId: string,
        channelIndex: number,
        fundedShannons: string,
        localCloseScript: Script,
    ): Promise<ChannelPolicyRecord> {
        assertNonEmptyString("channelId", channelId);
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        const pins = openingChannelPins(fundedShannons, localCloseScript);
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
                    nonceReuse: {},
                    commitmentHashes: {},
                    revocations: [],
                    pins,
                    views: { remote: openingSnapshot(fundedShannons), local: openingSnapshot(fundedShannons) },
                };
            }
            if (current.pins.fundedShannons !== pins.fundedShannons || current.pins.localCloseScript !== pins.localCloseScript) {
                throw new TypeError(`channel index ${channelIndex} is already registered with another funded amount or close script`);
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
     * Pins the funding cell the host signs, throwing a {@link ChannelPinError} when the channel pinned another.
     * @param channelId Channel identifier, any name the channel was registered under.
     * @param fundingOutPoint The funding output.
     * @param capacityShannons That output's capacity, in decimal shannons.
     */
    async pinFundingCell(channelId: string, fundingOutPoint: OutPoint, capacityShannons: string): Promise<void> {
        assertOutPoint("fundingOutPoint", fundingOutPoint);
        assertUint64Shannons("capacityShannons", capacityShannons);
        await this.pinHostValues(channelId, fundingCellPins(fundingOutPoint, capacityShannons), FIRST_SIGHT_CHANNEL_PINS);
    }

    /**
     * Pins the terms no signing request states, throwing a {@link ChannelPinError} when the channel pinned others.
     * @param channelId Channel identifier, any name the channel was registered under.
     * @param terms The terms, from the node's opening context.
     */
    async pinChannelTerms(channelId: string, terms: PolicyChannelTerms): Promise<void> {
        if (!isPlainObject(terms)) throw new TypeError("terms must be an object");
        assertUnsignedBigInt("terms.commitmentFeeRate", terms.commitmentFeeRate, UINT64_MAX);
        assertUint64Shannons("terms.remoteReservedCkbShannons", terms.remoteReservedCkbShannons);
        // Liquid capacity sits in the funding cell, so a cell's u64 bounds it.
        assertUint64Shannons("terms.liquidCapacityShannons", terms.liquidCapacityShannons);
        await this.pinHostValues(channelId, channelTermsPins(terms), CHANNEL_TERMS_PINS);
    }

    /**
     * Records the complete revocation signature of a superseded peer commitment, once the caller has verified it.
     * @param channelId Channel identifier, any name the channel was registered under.
     * @param evidence The revoked version and the aggregated signature.
     */
    async recordRevocation(channelId: string, evidence: RevokedCommitmentSignature): Promise<void> {
        if (!isPlainObject(evidence)) throw new TypeError("evidence must be an object");
        assertUnsignedInteger("evidence.version", evidence.version, MAX_REVOKED_VERSION);
        assertBytes("evidence.signature", evidence.signature, SCHNORR_SIGNATURE_LENGTH);
        const { version } = evidence;
        const entry: RevocationEvidence = { version, forRemote: true, signature: bytesToHex(evidence.signature) };
        const channelIndex = await this.requireRegisteredIndex(channelId);
        // Outside the balance lane: a claim only checks the evidence is there, which nothing here undoes, so the record's lane is enough.
        await this.store.updateChannelRecord(channelIndex, (current) => {
            if (current === null) throw missingRecord(channelId, channelIndex);
            const slot = signSlotKey({ context: "REVOKE", commitmentNumber: version + 1 });
            if (current.signedSessions[slot] === undefined) {
                throw new TypeError(`channel ${channelId} never signed the revocation of version ${version}, at slot ${slot}`);
            }
            // Rewritten on every delivery of the signature, so a crash between signing and recording heals itself.
            const recorded = current.revocations.find((revocation) => revocation.version === version);
            if (recorded?.signature === entry.signature) return current;
            const others = current.revocations.filter((revocation) => revocation !== recorded);
            return { ...current, revocations: [...others, entry].sort((a, b) => a.version - b.version) };
        });
    }

    /**
     * Pins values the host states, in the balance lane, refusing one the channel pinned otherwise.
     * @param channelId Channel identifier, any name the channel was registered under.
     * @param stated The values, in the pins' forms.
     * @param fields The fields the host may pin with them.
     */
    private async pinHostValues(
        channelId: string,
        stated: StatedChannelPins,
        fields: readonly (FirstSightChannelPin | ChannelTermsPin)[],
    ): Promise<void> {
        const channelIndex = await this.requireRegisteredIndex(channelId);
        await this.store.withBalanceLock(async () => {
            await this.store.updateChannelRecord(channelIndex, (current) => {
                if (current === null) throw missingRecord(channelId, channelIndex);
                const conflict = findChannelPinConflict(current.pins, stated);
                if (conflict !== null) throw new ChannelPinError(channelId, conflict);
                const pins = withChannelPins(current.pins, stated, fields);
                return pins === current.pins ? current : { ...current, pins };
            });
        });
    }

    /**
     * Resolves a name the host gives to the channel index it was registered under.
     * @param channelId Channel identifier, any name the channel was registered under.
     * @returns The index; throws a host error for an unregistered name.
     */
    private async requireRegisteredIndex(channelId: string): Promise<number> {
        const channelIndex = await this.store.resolveChannelIndex(channelId);
        if (channelIndex === null) throw new TypeError(`channel ${channelId} is not registered on this device`);
        return channelIndex;
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
     * Reads the values a channel is pinned to.
     * @param channelId Channel identifier the alias is keyed by.
     * @returns A copy of the pins.
     */
    async readChannelPins(channelId: string): Promise<ChannelPins> {
        const channelIndex = await this.requireChannelIndex(channelId);
        const record = await this.store.getChannelRecord(channelIndex);
        if (record === null) throw missingRecord(channelId, channelIndex);
        return { ...record.pins, localReservedCkbShannons: { ...record.pins.localReservedCkbShannons } };
    }

    /**
     * Records the budget the user approved for a payment, which an offered TLC under its hash needs.
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
                // Received only: no intent can take this hash. A twin under the full-hash layout is not the invoice's.
                const held = tlcs.filter((tlc) => tlc.boundPaymentHash === key && isTlcOfPaymentRecord(tlc, current));
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
     * Runs the six checks and claims the request's slot for its session, so the engine may sign it exactly once.
     * @param keys The channel's four secrets.
     * @param request The signing request as the node sent it.
     * @returns The claimed slot and its status.
     */
    async checkAndClaim(keys: FiberChannelKeys, request: PolicySignRequest): Promise<PolicyVerdict> {
        const { channelId, session, operation, slot } = request;
        const claimed = refusing("malformed", () => {
            assertNonEmptyString("channelId", channelId);
            assertSignSession(keys, session);
            return resolveSignSlot(operation, slot);
        });
        const channelIndex = await this.requireChannelIndex(channelId);

        const expected = refusing("malformed", () => recomputeDigest(keys, operation));
        if (!equalBytes(expected, session.message)) {
            refusePolicyRequest("malformed", "the message does not match the attached channel state");
        }

        const claim: Claim = {
            channelId,
            channelIndex,
            slot: claimed,
            sessionCommitment: buildSessionCommitment(session),
            message: bytesToHex(session.message),
            nonceReuse: this.nonceReuse,
            operation,
            tlcs: operation.kind === "commitment_tx" ? toPolicyViewTlcs(operation.input.tlcs, operation.input.lockLayout) : [],
        };
        // Serialized: channels share budgets, and nothing may move the record between deciding and claiming.
        return this.store.withBalanceLock(async () => {
            const current = await this.store.getChannelRecord(channelIndex);
            if (current === null) throw missingRecord(channelId, channelIndex);
            const context = await this.loadBalanceContext(claim, current);
            // Decided before writing, so a refusal leaves the payment records untouched; a repeat writes nothing at all.
            if (decideClaim(claim, current, context).record !== current) {
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
        let verdict: PolicyVerdict = { context: claim.slot.context, commitmentNumber: claim.slot.commitmentNumber, status: "fresh" };
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
     * @param claim The checked request.
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
        case "closing_tx":
            return computeClosingTxDigest(keys, operation.input);
        case "revocation":
            return computeRevocationDigest(keys, operation.input);
        case "channel_announcement":
            return computeChannelAnnouncementDigest(keys, operation.input);
    }
}

type Claim = {
    channelId: string;
    channelIndex: number;
    slot: SignSlotClaim;
    sessionCommitment: string;
    // Lowercase hex.
    message: string;
    nonceReuse: NonceReuseMode;
    operation: SignOperation;
    // Empty for any operation but a commitment.
    tlcs: PolicyViewTlc[];
};

/**
 * Runs every check of a claim on the record, writing nothing.
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
    const { slot, sessionCommitment, operation } = claim;
    const slotKey = signSlotKey(slot);
    const ref = { context: slot.context, commitmentNumber: slot.commitmentNumber };
    const served = current.signedSessions[slotKey];
    const reused = current.nonceReuse[slotKey];
    // Both repeats leave here, before the counters and views they would trip, whatever the mode.
    if (served === sessionCommitment) return { verdict: { ...ref, status: "already-signed" }, record: current };
    if (reused?.sessionCommitment === sessionCommitment) return { verdict: { ...ref, status: "reused" }, record: current };

    if (served !== undefined) {
        // Three sessions under one deterministic nonce are three equations that solve for the funding key.
        if (reused !== undefined) {
            refusePolicyRequest("policy_refusal", `slot ${slotKey} has already served two signing sessions, the most one nonce can`);
        }
        if (claim.nonceReuse === "refuse") {
            refusePolicyRequest("policy_refusal", `slot ${slotKey} has already served a different signing session`);
        }
    }
    const lastSigned = current.lastSignedCommitmentNumbers[slot.lane];
    if (lastSigned !== undefined) {
        // A fresh slot must be above its lane's last; a reused one may be that last, never below it.
        const fresh = served === undefined;
        if (fresh ? slot.commitmentNumber <= lastSigned : slot.commitmentNumber < lastSigned) {
            refusePolicyRequest(
                "stale_state",
                `commitment number ${slot.commitmentNumber} is ${fresh ? "not above" : "below"} the last ${slot.lane} signed, ${lastSigned}`,
            );
        }
    }

    assertReplacementSigned(current, operation, slot.commitmentNumber);
    const commitmentHashes = nextCommitmentHashes(current, operation, claim.message);
    const pins = pinClaim(current.pins, operation);
    const views = applyBalanceRule(current, claim, context);
    // A reused slot moves its lane too: a revocation round's second side is that lane's claim, and the remote view reads it.
    const lastSignedCommitmentNumbers = { ...current.lastSignedCommitmentNumbers, [slot.lane]: slot.commitmentNumber };
    if (served !== undefined) {
        return {
            verdict: { ...ref, status: "reused" },
            record: {
                ...current,
                lastSignedCommitmentNumbers,
                nonceReuse: { ...current.nonceReuse, [slotKey]: { sessionCommitment, message: claim.message } },
                commitmentHashes,
                pins,
                views,
            },
        };
    }
    return {
        verdict: { ...ref, status: "fresh" },
        record: {
            ...current,
            lastSignedCommitmentNumbers,
            signedSessions: { ...current.signedSessions, [slotKey]: sessionCommitment },
            commitmentHashes,
            pins,
            views,
        },
    };
}

/**
 * Holds a commitment's version to its view's last one, and records it with the hash of the tx signed.
 * @param current The channel's record.
 * @param operation The operation, whose digest already matched.
 * @param message The digest, lowercase hex: a commitment's `compute_tx_message`.
 * @returns The commitment hashes once the operation is signed, the ones given for any other operation.
 */
function nextCommitmentHashes(
    current: ChannelPolicyRecord,
    operation: SignOperation,
    message: string,
): ChannelPolicyRecord["commitmentHashes"] {
    if (operation.kind !== "commitment_tx") return current.commitmentHashes;
    const { commitmentNumber, forRemote } = operation.input;
    const view = viewOf(forRemote);
    const last = current.commitmentHashes[view];
    if (last !== undefined) {
        if (forRemote) {
            assertRemoteSuccessor(current, commitmentNumber, last.commitmentNumber);
        } else if (commitmentNumber <= last.commitmentNumber) {
            refusePolicyRequest(
                "stale_state",
                `the local commitment's version ${commitmentNumber} is not above the last one signed in its view, ${last.commitmentNumber}`,
            );
        }
    }
    return { ...current.commitmentHashes, [view]: { commitmentNumber, txHash: message } };
}

/**
 * Holds the peer's commitment to one above its view's last, and behind the revocation of the one before that last.
 * @param current The channel's record.
 * @param version The commitment's version.
 * @param last The version of the last remote commitment signed.
 */
function assertRemoteSuccessor(current: ChannelPolicyRecord, version: number, last: number): void {
    if (version !== last + 1) {
        refusePolicyRequest(
            "stale_state",
            `the remote commitment's version ${version} is not one above the last one signed in its view, ${last}`,
        );
    }
    // The dispatch ties a commitment's version to its slot, so no session below the last means the last followed none.
    if (current.signedSessions[signSlotKey({ context: "COMMITMENT", commitmentNumber: last - 1 })] === undefined) return;
    // The lane, not the slot, says the peer's revocation took it; the evidence, that the device holds the complete signature,
    // which the claim alone does not once a delivery failed.
    const revoked = current.lastSignedCommitmentNumbers["REVOKE:local"];
    const recorded = current.revocations.some((revocation) => revocation.version === last - 1);
    let missing: string | null = null;
    if (revoked === undefined) missing = "nothing has been signed on REVOKE:local";
    else if (revoked !== last) missing = `the last REVOKE:local signed is ${revoked}`;
    else if (!recorded) missing = "its complete signature has not been recorded";
    if (missing === null) return;
    refusePolicyRequest(
        "stale_state",
        `the remote commitment's version ${version} must follow the revocation of version ${last - 1}, at slot REVOKE:${last}, and ${missing}`,
    );
}

/**
 * Holds a revocation to its replacement, the last commitment signed in the revoked one's view, at the slot's number.
 * @param current The channel's record.
 * @param operation The operation, whose digest already matched.
 * @param slotNumber The revoked version plus one, the replacement's version.
 */
function assertReplacementSigned(current: ChannelPolicyRecord, operation: SignOperation, slotNumber: number): void {
    if (operation.kind !== "revocation") return;
    // Fiber's device SDK refuses the same way (`fiber-lsp-sdk/src/commitment.rs:671-689`).
    const view = viewOf(operation.input.forRemote);
    const replacement = current.commitmentHashes[view];
    if (replacement?.commitmentNumber !== slotNumber) {
        const last =
            replacement === undefined
                ? `no ${view} commitment has been signed`
                : `the last one signed is version ${replacement.commitmentNumber}`;
        refusePolicyRequest(
            "stale_state",
            `the revocation at slot ${slotNumber} must follow its replacement, the ${view} commitment at version ${slotNumber}, and ${last}`,
        );
    }
}

/**
 * Holds an operation to the channel's pinned values and to the bounds on what it takes from the funding cell.
 * @param pins The channel's pins.
 * @param operation The operation, whose digest already matched.
 * @returns The pins once the operation is signed, with every value it states for the first time.
 */
function pinClaim(pins: ChannelPins, operation: SignOperation): ChannelPins {
    const stated = statedChannelPins(operation);
    const conflict = findChannelPinConflict(pins, stated);
    if (conflict !== null) {
        refusePolicyRequest(
            "policy_refusal",
            `the request states ${conflict.field} ${conflict.stated}, but the channel pinned ${conflict.pinned}`,
        );
    }
    // The node's first statement of a term is no evidence of it: only the host pins one.
    const unpinned = CHANNEL_TERMS_PINS.find((field) => stated[field] !== undefined && pins[field] === undefined);
    if (unpinned !== undefined) {
        refusePolicyRequest("policy_refusal", `the request states ${unpinned}, which the host has not pinned for the channel yet`);
    }
    judgeCapacityBounds(operation);
    return withChannelPins(pins, stated, FIRST_SIGHT_CHANNEL_PINS);
}

/**
 * Applies the balance rule to the operations that move funds.
 * @param record The channel's record before the operation.
 * @param claim The checked request.
 * @param context What the rule reads beyond the record.
 * @returns The snapshots once the operation is signed.
 */
function applyBalanceRule(record: ChannelPolicyRecord, claim: Claim, context: BalanceRuleContext): Record<PolicyView, PolicyViewSnapshot> {
    const { operation } = claim;
    const { views } = record;
    switch (operation.kind) {
        case "commitment_tx": {
            const { input } = operation;
            const view = viewOf(input.forRemote);
            // What the witness pays the device, reserve included.
            const next = { exposureShannons: input.settlementLocalShannons + input.localReservedCkbShannons, tlcs: claim.tlcs };
            // A close claims the same lane: after one, the views alone judge.
            if (record.lastSignedCommitmentNumbers["COMMITMENT:local"] === undefined) {
                judgeOpeningCommitment(record.pins.fundedShannons, next);
            }
            return { ...views, [view]: judgeCommitment(view, views, next, context) };
        }
        case "closing_tx":
            judgeClosingTx(views, operation.input.localCapacityShannons);
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
 * @param exposureShannons What the user funded, in decimal shannons.
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
 * Asserts that a host-stated amount is decimal shannons a CKB cell's capacity can hold.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
function assertUint64Shannons(name: string, value: string): void {
    assertDecimalShannons(name, value);
    if (BigInt(value) > UINT64_MAX) throw new RangeError(`${name} must be at most ${UINT64_MAX}, the most a CKB cell's capacity holds`);
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
