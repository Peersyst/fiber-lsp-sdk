import type { SignRequest } from "../../protocol";
import type { DispatchOutcome, PendingChannelRegistration } from "../../signer";

export interface ISessionHandler {
    /**
     * Answers one sign request.
     * @param request The request as the node sent it.
     * @returns The outcome; the session leaves a fault unanswered.
     */
    handle(request: SignRequest): Promise<DispatchOutcome>;
    /**
     * Files a channel under the name the node gave it.
     * @param channelId Channel identifier the node answered the registration with.
     * @param pending The registration as prepared.
     */
    channelRegistered(channelId: string, pending: PendingChannelRegistration): Promise<void>;
}
