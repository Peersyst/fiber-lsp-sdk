import type { NonceContext } from "../derivation";
import { MAX_COMMITMENT_NUMBER } from "../derivation";
import type { NonceCounter } from "../policy";
import type {
    ChannelSigningContentKind,
    ChannelSigningRule,
    ChannelSigningStatusWire,
    ChannelSigningTransition,
    OnchainKeyPurposeWire,
    WatchtowerSigningStatusWire,
} from "./protocol.types";

/**
 * Shared by fiber's channel and watchtower signing statuses.
 */
export const SIGNING_STATUS_TYPES = [
    "NoSignatureRequired",
    "SignatureRequired",
] as const satisfies readonly (ChannelSigningStatusWire["type"] & WatchtowerSigningStatusWire["type"])[];

export const CHANNEL_SIGNING_TRANSITIONS = [
    "SendCommitmentSigned",
    "CompleteReceivedCommitment",
    "SendRevokeAndAck",
    "CompleteReceivedRevokeAndAck",
    "SendClosingSigned",
    "SignChannelAnnouncement",
] as const;

export const CHANNEL_SIGNING_CONTENT_KINDS = ["commitmentTx", "closingTx", "revocation", "announcement"] as const;

/**
 * Fiber's `Musig2SignableContent` tags.
 */
export const SIGNABLE_CONTENT_KINDS = {
    CommitmentTransaction: "commitmentTx",
    CooperativeCloseTransaction: "closingTx",
    Revocation: "revocation",
    ChannelAnnouncement: "announcement",
} as const satisfies Record<string, ChannelSigningContentKind>;

/**
 * Fiber's `NoncePurpose`; a close has none of its own and signs under `Commitment`.
 */
export const NONCE_PURPOSE_CONTEXTS = {
    Commitment: "COMMITMENT",
    Revocation: "REVOKE",
    ChannelAnnouncement: "ANNOUNCEMENT",
} as const satisfies Record<string, NonceContext>;

/**
 * Fiber's `CommitmentCounter`.
 */
export const COMMITMENT_COUNTERS = { Local: "local", Remote: "remote" } as const satisfies Record<string, NonceCounter>;

/**
 * What each transition must carry, as fiber builds and checks it (`fiber-lsp-sdk/src/lifecycle.rs:118-180`): the slot,
 * counter and content of a revocation or a close
 * (`fiber-lib/src/fiber/channel.rs:7999-8018,9200-9213,10194-10216`), the peer's evidence (`:11040-11080`), the
 * settlement and the next material (`fiber-types/src/channel_signer.rs:348-358,380-388`).
 */
export const CHANNEL_SIGNING_RULES = {
    SendCommitmentSigned: {
        context: "COMMITMENT",
        counter: "local",
        contentKind: "commitmentTx",
        settlementForRemote: true,
        peerPartialSignature: false,
        nextMaterial: true,
    },
    CompleteReceivedCommitment: {
        context: "COMMITMENT",
        counter: "local",
        contentKind: "commitmentTx",
        settlementForRemote: false,
        peerPartialSignature: true,
        nextMaterial: true,
    },
    SendRevokeAndAck: {
        context: "REVOKE",
        counter: "remote",
        contentKind: "revocation",
        settlementForRemote: null,
        peerPartialSignature: false,
        nextMaterial: true,
    },
    CompleteReceivedRevokeAndAck: {
        context: "REVOKE",
        counter: "local",
        contentKind: "revocation",
        settlementForRemote: null,
        peerPartialSignature: true,
        nextMaterial: true,
    },
    SendClosingSigned: {
        context: "COMMITMENT",
        counter: "local",
        contentKind: "closingTx",
        settlementForRemote: null,
        peerPartialSignature: false,
        nextMaterial: false,
    },
    SignChannelAnnouncement: {
        context: "ANNOUNCEMENT",
        counter: null,
        contentKind: "announcement",
        settlementForRemote: null,
        peerPartialSignature: false,
        nextMaterial: false,
    },
} as const satisfies Record<ChannelSigningTransition, ChannelSigningRule>;

/**
 * One below the derivation's bound: the answer publishes the material of `slot + 1`, which must still be derivable.
 */
export const MAX_SIGNING_SLOT_NUMBER = MAX_COMMITMENT_NUMBER - 1;

export const ONCHAIN_KEY_PURPOSE_TYPES = ["Settlement", "Tlc"] as const satisfies readonly OnchainKeyPurposeWire["type"][];
