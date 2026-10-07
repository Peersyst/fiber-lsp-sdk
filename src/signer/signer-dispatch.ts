import type { Script, ScriptTemplate } from "../common";
import { assertBytes } from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MASTER_SEED_LENGTH, deriveChannelKeys, deriveChannelSeed, deriveTlcKey } from "../derivation";
import type { PolicyEngine } from "../policy";
import { ANNOUNCEMENT_SLOT_NUMBER, PolicyRefusalError, assertChannelOpening } from "../policy";
import type { SignRequest, SignResult } from "../protocol";
import { ProtocolError, decodeSignParams } from "../protocol";
import { getBasePublicKeys, getChannelCommitmentPoint, getPublicNonce, partialSign } from "./musig2-engine";
import type { DispatchOutcome, PendingChannelRegistration, SignerDispatchOptions } from "./signer.types";

export class SignerDispatch {
    private readonly masterSeed: Uint8Array;

    private readonly commitmentLock: ScriptTemplate;

    private readonly policy: PolicyEngine;

    /**
     * Creates the dispatch over the device's seed, the network's commitment lock and the policy gate.
     * @param options The seed, copied so the host may discard its own, the lock template and the gate.
     */
    constructor(options: SignerDispatchOptions) {
        assertBytes("masterSeed", options.masterSeed, MASTER_SEED_LENGTH);
        this.masterSeed = Uint8Array.from(options.masterSeed);
        this.commitmentLock = options.commitmentLock;
        this.policy = options.policy;
    }

    /**
     * Answers one sign request: a result, a refusal the node is answered with, or a fault that is the device's own.
     * @param request The envelope, with its params as the node sent them.
     * @returns The outcome; nothing on this path throws.
     */
    async handle(request: SignRequest): Promise<DispatchOutcome> {
        try {
            return { kind: "result", result: await this.dispatch(request) };
        } catch (error) {
            if (error instanceof PolicyRefusalError || error instanceof ProtocolError) {
                return { kind: "refusal", error: { code: error.code, message: error.message } };
            }
            return { kind: "fault", cause: error };
        }
    }

    /**
     * Derives a channel's registration: the base public keys and the delegated settlement key, never the funding key.
     * @param channelIndex Index the channel's keys derive from, allocated by the caller.
     * @param fundedShannons What the user pays into the channel, reserve included, in decimal shannons.
     * @param localCloseScript The script the device's side of a close pays to.
     * @returns The registration to send, and what to file the channel with once the node names it.
     */
    prepareChannelRegistration(channelIndex: number, fundedShannons: string, localCloseScript: Script): PendingChannelRegistration {
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
            registration: { ...getBasePublicKeys(keys), localSettlementKey: keys.tlcBaseKey },
        };
    }

    /**
     * Files a registered channel under the name the node gave it, which is what lets its requests resolve from then on.
     * @param channelId Channel identifier the node answered the registration with.
     * @param pending The registration as prepared.
     */
    async channelRegistered(channelId: string, pending: PendingChannelRegistration): Promise<void> {
        await this.policy.registerChannel(channelId, pending.channelIndex, pending.fundedShannons, pending.localCloseScript);
    }

    /**
     * Runs one request: params, channel, keys, then the method, with the policy gate ahead of every signature.
     * @param request The envelope.
     * @returns The method's result.
     */
    private async dispatch(request: SignRequest): Promise<SignResult> {
        const params = decodeSignParams(request, this.commitmentLock);
        const channelIndex = await this.policy.requireChannelIndex(request.channelId);
        const keys = this.channelKeys(channelIndex);
        switch (params.method) {
            case "get_base_public_keys":
                return { kind: "base_public_keys", ...getBasePublicKeys(keys) };
            case "get_commitment_point":
                return { kind: "commitment_point", commitmentPoint: getChannelCommitmentPoint(keys, params.commitmentNumber) };
            case "get_commitment_pub_nonce":
                return { kind: "pub_nonce", pubNonce: getPublicNonce(keys, params.commitmentNumber, "COMMITMENT") };
            case "get_revocation_pub_nonce":
                return { kind: "pub_nonce", pubNonce: getPublicNonce(keys, params.commitmentNumber, "REVOKE") };
            case "get_channel_announcement_pub_nonce":
                return { kind: "pub_nonce", pubNonce: getPublicNonce(keys, ANNOUNCEMENT_SLOT_NUMBER, "ANNOUNCEMENT") };
            case "get_settlement_keys":
                return {
                    kind: "settlement_keys",
                    localSettlementKey: keys.tlcBaseKey,
                    tlcKey: deriveTlcKey(keys, params.commitmentNumber),
                };
            case "partial_sign_commitment_tx":
            case "partial_sign_closing_tx":
            case "partial_sign_revocation":
            case "partial_sign_channel_announcement": {
                // The engine signs the slot the gate claimed, never a number read from the operation.
                const verdict = await this.policy.checkAndClaim(keys, params.request);
                const partialSignature = partialSign(keys, {
                    ...params.request.session,
                    commitmentNumber: verdict.commitmentNumber,
                    context: verdict.context,
                });
                return { kind: "partial_signature", partialSignature };
            }
        }
    }

    /**
     * Derives a channel's four secrets from its index, per request and never cached.
     * @param channelIndex Index the channel seed derives from.
     * @returns The channel's keys.
     */
    private channelKeys(channelIndex: number): FiberChannelKeys {
        return deriveChannelKeys(deriveChannelSeed(this.masterSeed, channelIndex));
    }
}
