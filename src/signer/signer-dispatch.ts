import { equalBytes } from "@noble/curves/utils.js";
import type { Script } from "../common";
import { assertBytes, assertNonEmptyString, assertPositiveInteger, assertScriptTemplate } from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MASTER_SEED_LENGTH, deriveChannelKeys, deriveChannelSeed, pubkeyOf } from "../derivation";
import { MAX_CELL_DEPS_COUNT } from "../digest";
import type { PolicyEngine, SignSession } from "../policy";
import { PolicyRefusalError, assertChannelOpening, refusePolicyRequest } from "../policy";
import type { ChannelSigningRequest, ChannelSigningStatus, WatchtowerSigningRequest, WatchtowerSigningStatus } from "../protocol";
import { CHANNEL_SIGNING_RULES, ProtocolError, decodeChannelSigningStatus, decodeWatchtowerSigningStatus } from "../protocol";
import type { WireField } from "../wire";
import {
    aggregatePartialSignatures,
    aggregatePublicNonces,
    getPublicNonce,
    partialSign,
    verifyPeerPartialSignature,
} from "./musig2-engine";
import { signOnchain } from "./onchain-signature";
import { buildChannelOpenMaterial, buildNextMaterial } from "./signer-material";
import type {
    DispatchOutcome,
    PendingChannelOpen,
    SignerDispatchOptions,
    SigningNetwork,
    SigningWarning,
    WatchtowerDispatchOutcome,
} from "./signer.types";
import { buildSignOperation, computeSigningMessage, readPeerFundingPubkey } from "./utils";

export class SignerDispatch {
    private readonly masterSeed: Uint8Array;

    private readonly network: SigningNetwork;

    private readonly policy: PolicyEngine;

    /**
     * Creates the dispatch over the device's seed, the network's constants and the policy gate.
     * @param options The seed (copied), the network's constants and the gate.
     */
    constructor(options: SignerDispatchOptions) {
        assertBytes("masterSeed", options.masterSeed, MASTER_SEED_LENGTH);
        assertScriptTemplate("commitmentLock", options.commitmentLock);
        assertPositiveInteger("fundingLockCellDepsCount", options.fundingLockCellDepsCount, MAX_CELL_DEPS_COUNT);
        this.masterSeed = Uint8Array.from(options.masterSeed);
        this.network = { commitmentLock: options.commitmentLock, fundingLockCellDepsCount: options.fundingLockCellDepsCount };
        this.policy = options.policy;
    }

    /**
     * Answers a channel's signing status: idle, a signature, a refusal, or a fault that is the device's own.
     * @param channelId The channel the status was read for.
     * @param status The `status` member of `get_channel_signing_status`.
     * @returns The outcome; nothing on this path throws.
     */
    async handle(channelId: string, status: WireField): Promise<DispatchOutcome> {
        let decoded: ChannelSigningStatus;
        try {
            decoded = decodeChannelSigningStatus(status);
        } catch (error) {
            if (error instanceof ProtocolError) return refusedOutcome(null, error);
            return { kind: "fault", cause: error };
        }
        if (decoded.kind === "none") return { kind: "idle" };
        try {
            return await this.sign(channelId, decoded);
        } catch (error) {
            if (error instanceof PolicyRefusalError) return refusedOutcome(decoded, error);
            return { kind: "fault", cause: error };
        }
    }

    /**
     * Answers a channel's watchtower signing status: idle, a signature, a refusal, or a fault that is the device's own.
     * @param channelId The channel the status was read for.
     * @param status The `status` member of `get_watchtower_signing_status`.
     * @returns The outcome; nothing on this path throws.
     */
    async handleWatchtower(channelId: string, status: WireField): Promise<WatchtowerDispatchOutcome> {
        let decoded: WatchtowerSigningStatus;
        try {
            decoded = decodeWatchtowerSigningStatus(status);
        } catch (error) {
            if (error instanceof ProtocolError) return watchtowerRefusedOutcome(null, error);
            return { kind: "fault", cause: error };
        }
        if (decoded.kind === "none") return { kind: "idle" };
        try {
            return await this.signWatchtower(channelId, decoded);
        } catch (error) {
            if (error instanceof PolicyRefusalError) return watchtowerRefusedOutcome(decoded, error);
            return { kind: "fault", cause: error };
        }
    }

    /**
     * Derives the public material `open_tenant_channel` carries.
     * @param channelIndex The index the channel's keys derive from.
     * @param fundedShannons What the user pays in, reserve included, in decimal shannons.
     * @param localCloseScript The script the device's side of a close pays to.
     * @returns The material, and what to register the channel with once the node names it.
     */
    prepareChannelOpen(channelIndex: number, fundedShannons: string, localCloseScript: Script): PendingChannelOpen {
        assertChannelOpening(fundedShannons, localCloseScript);
        const keys = this.channelKeys(channelIndex);
        return {
            channelIndex,
            fundedShannons,
            // Copied: the caller's bytes may change before the node names the channel.
            localCloseScript: {
                ...localCloseScript,
                codeHash: Uint8Array.from(localCloseScript.codeHash),
                args: Uint8Array.from(localCloseScript.args),
            },
            material: buildChannelOpenMaterial(keys),
        };
    }

    /**
     * Runs one request through the checks, the claim and the signature.
     * @param channelId The channel the status was read for.
     * @param request The decoded request.
     * @returns The signed outcome; a refusal or a fault is thrown.
     */
    private async sign(channelId: string, request: ChannelSigningRequest): Promise<DispatchOutcome> {
        const { slot, transition, evidence } = request;
        const rule = CHANNEL_SIGNING_RULES[transition];
        const channelIndex = await this.policy.requireChannelIndex(channelId);
        const keys = this.channelKeys(channelIndex);
        if (transition === "SignChannelAnnouncement") {
            refusePolicyRequest("policy_refusal", "a channel announcement is never signed: every channel of this device is private");
        }

        const peerFundingPubkey = malformedUnless(() =>
            readPeerFundingPubkey(transition, request.keyAggregation, pubkeyOf(keys.fundingKey)),
        );
        const devicePublicNonce = getPublicNonce(keys, slot.commitmentNumber, slot.context);
        if (!equalBytes(aggregatePublicNonces(devicePublicNonce, evidence.peerPublicNonce), request.aggNonce)) {
            refusePolicyRequest(
                "malformed",
                `the aggregated nonce is not the sum of this device's nonce at ${slotKeyOf(request)} and the peer's`,
            );
        }
        const session: SignSession = {
            orderedPublicKeys: [...request.keyAggregation],
            aggregatedNonce: request.aggNonce,
            message: malformedUnless(() => computeSigningMessage(request.content)),
        };
        if (rule.peerPartialSignature) {
            const cosign = { ...session, devicePublicNonce, peerPublicNonce: evidence.peerPublicNonce };
            const peerPartialSignature = evidence.peerPartialSignature;
            if (peerPartialSignature === null || !malformedUnless(() => verifyPeerPartialSignature(keys, cosign, peerPartialSignature))) {
                refusePolicyRequest("malformed", `the peer's partial signature does not verify over the message ${transition} carries`);
            }
        }
        const pins = await this.policy.readChannelPins(channelId);
        const prepared = malformedUnless(() => buildSignOperation(keys, request, peerFundingPubkey, pins, this.network));

        const verdict = await this.policy.checkAndClaim(keys, {
            channelId,
            slot: { commitmentNumber: slot.commitmentNumber, counter: request.counter },
            session,
            operation: prepared.operation,
        });
        // The slot the gate claimed must be the one the aggregated nonce was checked at.
        if (verdict.context !== slot.context || verdict.commitmentNumber !== slot.commitmentNumber) {
            throw new Error(
                `the gate claimed ${verdict.context}:${verdict.commitmentNumber}, not the slot ${slotKeyOf(request)} the nonce was checked at`,
            );
        }
        const partialSignature = partialSign(keys, { ...session, commitmentNumber: verdict.commitmentNumber, context: verdict.context });
        // Recorded on every delivery, so a crash between signing and recording heals on the next one.
        if (transition === "CompleteReceivedRevokeAndAck" && evidence.peerPartialSignature !== null) {
            const signature = aggregatePartialSignatures(session, [evidence.peerPartialSignature, partialSignature]);
            await this.policy.recordRevocation(channelId, { version: slot.commitmentNumber - 1, signature });
        }
        const warnings: SigningWarning[] = verdict.status === "reused" ? [{ kind: "nonce-reused", slot: slotKeyOf(request) }] : [];
        return {
            kind: "signed",
            requestId: request.requestId,
            transition,
            slot: { context: slot.context, commitmentNumber: slot.commitmentNumber },
            commitmentNumber: prepared.commitmentNumber,
            view: prepared.view,
            partialSignature,
            nextMaterial: rule.nextMaterial ? buildNextMaterial(keys, slot.commitmentNumber + 1) : null,
            status: verdict.status,
            warnings,
        };
    }

    /**
     * Runs a watchtower spend through the policy, then signs it unless its signature is already recorded.
     * @param channelId The channel the status was read for.
     * @param request The decoded request.
     * @returns The signed outcome; a refusal or a fault is thrown.
     */
    private async signWatchtower(channelId: string, request: WatchtowerSigningRequest): Promise<WatchtowerDispatchOutcome> {
        const { requestId, purpose } = request;
        // Malformed, as the policy refuses it, rather than a fault of the index lookup.
        malformedUnless(() => assertNonEmptyString("channelId", channelId));
        const keys = this.channelKeys(await this.policy.requireChannelIndex(channelId));
        const verdict = await this.policy.checkWatchtowerSpend(keys, channelId, request);
        if (verdict.status === "already-signed" && verdict.signature !== null) {
            return { kind: "signed", requestId, purpose, signature: verdict.signature, claimed: true };
        }
        // A claim with no signature is a crash between the two writes: signing again gives the same bytes, deterministic.
        const signature = signOnchain(keys, purpose, request.transaction);
        if (verdict.status === "unclaimed") return { kind: "signed", requestId, purpose, signature, claimed: false };
        // Recorded before it leaves, so a failed write leaves a fault the next delivery heals.
        await this.policy.recordWatchtowerSignature(channelId, requestId, signature);
        return { kind: "signed", requestId, purpose, signature, claimed: true };
    }

    /**
     * Derives a channel's secrets from its index, never cached.
     * @param channelIndex The channel's index.
     * @returns The channel's keys.
     */
    private channelKeys(channelIndex: number): FiberChannelKeys {
        return deriveChannelKeys(deriveChannelSeed(this.masterSeed, channelIndex));
    }
}

/**
 * Runs a step over what the node sent, turning its type and range errors into a `malformed` refusal.
 * @param step The step.
 * @returns What the step returned.
 */
function malformedUnless<T>(step: () => T): T {
    try {
        return step();
    } catch (error) {
        if (error instanceof TypeError || error instanceof RangeError) refusePolicyRequest("malformed", error.message);
        throw error;
    }
}

/**
 * Writes a request's slot as the registry keys it.
 * @param request The request.
 * @returns The `<context>:<number>` key.
 */
function slotKeyOf(request: ChannelSigningRequest): SigningWarning["slot"] {
    return `${request.slot.context}:${request.slot.commitmentNumber}`;
}

/**
 * Builds the outcome of a refused request.
 * @param request The decoded request, or `null` when the status could not be decoded.
 * @param error The refusal.
 * @returns The outcome.
 */
function refusedOutcome(request: ChannelSigningRequest | null, error: PolicyRefusalError | ProtocolError): DispatchOutcome {
    return {
        kind: "refused",
        requestId: request?.requestId ?? null,
        transition: request?.transition ?? null,
        error: { code: error.code, message: error.message },
    };
}

/**
 * Builds the outcome of a refused watchtower request.
 * @param request The decoded request, or `null` when the status could not be decoded.
 * @param error The refusal.
 * @returns The outcome.
 */
function watchtowerRefusedOutcome(
    request: WatchtowerSigningRequest | null,
    error: PolicyRefusalError | ProtocolError,
): WatchtowerDispatchOutcome {
    return {
        kind: "refused",
        requestId: request?.requestId ?? null,
        purpose: request?.purpose ?? null,
        error: { code: error.code, message: error.message },
    };
}
