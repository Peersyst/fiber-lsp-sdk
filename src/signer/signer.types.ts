import type { ScriptTemplate } from "../common";
import type { NonceContext } from "../derivation";
import type { PolicyEngine, SignSession } from "../policy";
import type { ChannelRegistration, SignError, SignResult } from "../protocol";

/**
 * One partial-signature request over an already-computed 32-byte digest.
 */
export type PartialSignRequest = SignSession & {
    commitmentNumber: number;
    context: NonceContext;
};

export type SignerDispatchOptions = {
    masterSeed: Uint8Array;
    commitmentLock: ScriptTemplate;
    policy: PolicyEngine;
};

/**
 * Answered, refused on the wire, or left unanswered because the failure was the device's own and none of the four codes.
 */
export type DispatchOutcome =
    { kind: "result"; result: SignResult } | { kind: "refusal"; error: SignError } | { kind: "fault"; cause: unknown };

export type PendingChannelRegistration = {
    channelIndex: number;
    localExposureShannons: string;
    registration: ChannelRegistration;
};
