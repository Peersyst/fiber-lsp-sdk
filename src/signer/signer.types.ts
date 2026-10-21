import type { Script, ScriptTemplate, SignerErrorCode } from "../common";
import type { NonceContext } from "../derivation";
import type { PolicyEngine, PolicyView, SignOperation, SignSession, SignSlot, SignSlotRef } from "../policy";
import type { ChannelSigningTransition } from "../protocol";
import type { ChannelOpenSignerMaterial, NextChannelSignerMaterial } from "../rpc";
import type { SIGNING_KEY_ORDERS } from "./signer.constants";

export type PartialSignRequest = SignSession & {
    commitmentNumber: number;
    context: NonceContext;
};

export type CosignSession = SignSession & {
    devicePublicNonce: Uint8Array;
    peerPublicNonce: Uint8Array;
};

export type SignerDispatchOptions = {
    masterSeed: Uint8Array;
    commitmentLock: ScriptTemplate;
    /**
     * Fiber counts these into the commitment fee although the commitment tx carries none.
     */
    fundingLockCellDepsCount: number;
    policy: PolicyEngine;
};

export type SigningNetwork = Pick<SignerDispatchOptions, "commitmentLock" | "fundingLockCellDepsCount">;

export type SigningKeyOrder = (typeof SIGNING_KEY_ORDERS)[ChannelSigningTransition];

export type PreparedSignOperation = {
    operation: SignOperation;
    commitmentNumber: number | null;
    view: PolicyView | null;
};

export type SigningWarning = {
    kind: "nonce-reused";
    slot: SignSlot;
};

export type SignerRefusal = {
    code: SignerErrorCode;
    message: string;
};

export type DispatchOutcome =
    | { kind: "idle" }
    | {
          kind: "signed";
          requestId: Uint8Array;
          transition: ChannelSigningTransition;
          slot: SignSlotRef;
          /**
           * The commitment's version or the revoked number; `null` for a close.
           */
          commitmentNumber: number | null;
          /**
           * For a revocation, the view of the commitment it revokes; `null` for a close.
           */
          view: PolicyView | null;
          partialSignature: Uint8Array;
          nextMaterial: NextChannelSignerMaterial | null;
          status: "fresh" | "already-signed" | "reused";
          warnings: SigningWarning[];
      }
    | { kind: "refused"; requestId: Uint8Array | null; transition: ChannelSigningTransition | null; error: SignerRefusal }
    | { kind: "fault"; cause: unknown };

export type PendingChannelOpen = {
    channelIndex: number;
    fundedShannons: string;
    localCloseScript: Script;
    material: ChannelOpenSignerMaterial;
};
