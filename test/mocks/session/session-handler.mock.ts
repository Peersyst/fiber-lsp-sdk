import type { SignRequest } from "../../../src/protocol";
import type { ISessionHandler } from "../../../src/session";
import type { DispatchOutcome, PendingChannelRegistration } from "../../../src/signer";

export const DEFAULT_PUB_NONCE = new Uint8Array(66).fill(0x02);

export class SessionHandlerMock implements ISessionHandler {
    readonly handled: SignRequest[] = [];

    readonly registered: { channelId: string; pending: PendingChannelRegistration }[] = [];

    respond: (request: SignRequest) => DispatchOutcome | Promise<DispatchOutcome> = () => ({
        kind: "result",
        result: { kind: "pub_nonce", pubNonce: DEFAULT_PUB_NONCE },
    });

    file: (channelId: string, pending: PendingChannelRegistration) => void | Promise<void> = () => undefined;

    async handle(request: SignRequest): Promise<DispatchOutcome> {
        this.handled.push(request);
        return this.respond(request);
    }

    async channelRegistered(channelId: string, pending: PendingChannelRegistration): Promise<void> {
        await this.file(channelId, pending);
        this.registered.push({ channelId, pending });
    }
}
