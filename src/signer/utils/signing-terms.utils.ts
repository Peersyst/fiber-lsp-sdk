import { bytesToHex } from "@noble/hashes/utils.js";
import type { CellOutput, Transaction } from "../../common";
import { moleculeScript } from "../../common";
import type { FiberChannelKeys } from "../../derivation";
import type { CommitmentLockLayout, RevocationInput } from "../../digest";
import {
    COMMITMENT_LOCK_LAYOUTS,
    computeRevocationContentMessage,
    computeTxMessage,
    readClosingTx,
    readCommitmentLockDelay,
    readCommitmentLockLayout,
    readCommitmentLockVersion,
    settlementToCommitmentInput,
} from "../../digest";
import type { ChannelPins, ChannelTermsPin } from "../../policy";
import { refusePolicyRequest } from "../../policy";
import type { ChannelSigningContent, ChannelSigningRequest } from "../../protocol";
import type { PreparedSignOperation, SigningNetwork } from "../signer.types";

type RevocationContent = Extract<ChannelSigningContent, { kind: "revocation" }>;

// Unreachable through the dispatch, which refuses the announcement first.
const NO_ANNOUNCEMENT = "a channel announcement is refused before its content is read";

/**
 * Computes the message a request asks to sign, as fiber's `signing_message` does.
 * @param content The plaintext.
 * @returns The 32-byte message.
 */
export function computeSigningMessage(content: ChannelSigningContent): Uint8Array {
    switch (content.kind) {
        case "commitmentTx":
        case "closingTx":
            return computeTxMessage(content.transaction);
        case "revocation":
            return computeRevocationContentMessage(content.output, content.outputData, content.commitmentLockArgs);
        case "announcement":
            throw new TypeError(NO_ANNOUNCEMENT);
    }
}

/**
 * Builds the operation a request asks the gate for.
 * @param keys The channel's secrets.
 * @param request The decoded request.
 * @param peerFundingPubkey The peer's funding key.
 * @param pins The channel's pins, which hold the terms no request states.
 * @param network The signing network.
 * @returns The operation, its commitment number and its view.
 */
export function buildSignOperation(
    keys: FiberChannelKeys,
    request: ChannelSigningRequest,
    peerFundingPubkey: Uint8Array,
    pins: ChannelPins,
    network: SigningNetwork,
): PreparedSignOperation {
    const { content } = request;
    switch (content.kind) {
        case "commitmentTx":
            return buildCommitmentOperation(keys, request, content.transaction, peerFundingPubkey, pins, network);
        case "revocation":
            return buildRevocationOperation(request, content, peerFundingPubkey, pins, network);
        case "closingTx":
            return {
                operation: { kind: "closing_tx", input: readClosingTx(keys, peerFundingPubkey, content.transaction) },
                commitmentNumber: null,
                view: null,
            };
        case "announcement":
            throw new TypeError(NO_ANNOUNCEMENT);
    }
}

/**
 * Builds a commitment's operation from its snapshot and the commitment cell's lock args.
 * @param keys The channel's secrets.
 * @param request The decoded request.
 * @param transaction The commitment tx.
 * @param peerFundingPubkey The peer's funding key.
 * @param pins The channel's pins.
 * @param network The signing network.
 * @returns The operation, its version and its view.
 */
function buildCommitmentOperation(
    keys: FiberChannelKeys,
    request: ChannelSigningRequest,
    transaction: Transaction,
    peerFundingPubkey: Uint8Array,
    pins: ChannelPins,
    network: SigningNetwork,
): PreparedSignOperation {
    const { settlement, slot, transition } = request;
    if (settlement === null) throw new TypeError(`${transition} must carry the settlement its commitment is rebuilt from`);
    const [input] = transaction.inputs;
    const [output] = transaction.outputs;
    if (input === undefined) throw new TypeError("the commitment tx must spend the funding cell");
    if (output === undefined) throw new TypeError("the commitment tx must create the commitment cell");
    assertCkbOutput("the commitment cell", output);
    const args = output.lock.args;
    const lockLayout = readCommitmentLockLayout(args);
    // Bytes 28..36 of the lock args, big-endian (`fiber-lsp-sdk/src/commitment.rs:642`).
    const commitmentNumber = readCommitmentLockVersion(args);
    // A sent commitment's version is the slot's number; a received one carries the peer's.
    if (transition === "SendCommitmentSigned" && commitmentNumber !== slot.commitmentNumber) {
        throw new TypeError(`the commitment sent at slot ${slot.commitmentNumber} must carry that version, not ${commitmentNumber}`);
    }
    const commitmentInput = settlementToCommitmentInput(
        keys,
        settlement,
        {
            fundingOutPoint: input.previousOutput,
            remoteFundingPubkey: peerFundingPubkey,
            commitmentDelayEpoch: readCommitmentLockDelay(args),
            ...readChannelTerms(pins, lockLayout, network),
        },
        commitmentNumber,
    );
    return {
        operation: { kind: "commitment_tx", input: commitmentInput },
        commitmentNumber,
        view: settlement.forRemote ? "remote" : "local",
    };
}

/**
 * Builds a revocation's operation, checking the revoked number and a received one's payout script.
 * @param request The decoded request.
 * @param content The revocation.
 * @param peerFundingPubkey The peer's funding key.
 * @param pins The channel's pins.
 * @param network The signing network.
 * @returns The operation, the revoked number and its view.
 */
function buildRevocationOperation(
    request: ChannelSigningRequest,
    content: RevocationContent,
    peerFundingPubkey: Uint8Array,
    pins: ChannelPins,
    network: SigningNetwork,
): PreparedSignOperation {
    const { output, commitmentLockArgs } = content;
    const { slot, transition } = request;
    assertCkbOutput("the revocation output", output);
    const revokedCommitmentNumber = readCommitmentLockVersion(commitmentLockArgs);
    // Fiber revokes the version one below the slot's (`fiber-lib/src/fiber/channel.rs:7987`, `:10182`).
    if (revokedCommitmentNumber + 1 !== slot.commitmentNumber) {
        throw new TypeError(
            `the revocation at slot ${slot.commitmentNumber} must revoke version ${slot.commitmentNumber - 1}, not ${revokedCommitmentNumber}`,
        );
    }
    const forRemote = transition === "CompleteReceivedRevokeAndAck";
    // A received revocation sweeps the peer's commitment to the device.
    if (forRemote && bytesToHex(moleculeScript(output.lock)) !== pins.localCloseScript) {
        throw new TypeError("a revocation the device receives must pay the channel's close script");
    }
    const input: RevocationInput = {
        forRemote,
        revokedCommitmentNumber,
        payoutScript: output.lock,
        remoteFundingPubkey: peerFundingPubkey,
        commitmentDelayEpoch: readCommitmentLockDelay(commitmentLockArgs),
        ...readChannelTerms(pins, readPinnedLockLayout(pins), network),
    };
    return { operation: { kind: "revocation", input }, commitmentNumber: revokedCommitmentNumber, view: forRemote ? "remote" : "local" };
}

/**
 * Reads the terms a commitment and a revocation share and no request states.
 * @param pins The channel's pins.
 * @param lockLayout The layout the device's reserve is computed under.
 * @param network The signing network.
 * @returns The shared part of both inputs.
 */
function readChannelTerms(pins: ChannelPins, lockLayout: CommitmentLockLayout, network: SigningNetwork) {
    // In the engine's order, so both refuse on the same term first.
    const liquidCapacityShannons = readPinnedTerm(pins, "liquidCapacityShannons");
    const commitmentFeeRate = readPinnedTerm(pins, "commitmentFeeRate");
    const remoteReservedCkbShannons = readPinnedTerm(pins, "remoteReservedCkbShannons");
    return {
        commitmentFeeRate,
        cellDepsCount: network.fundingLockCellDepsCount,
        udtTypeScript: null,
        liquidCapacityShannons,
        localReservedCkbShannons: BigInt(pins.localReservedCkbShannons[lockLayout]),
        remoteReservedCkbShannons,
        commitmentLock: network.commitmentLock,
        lockLayout,
    };
}

/**
 * Reads one of the terms the host pins, refusing the request while the host has not.
 * @param pins The channel's pins.
 * @param field The term.
 * @returns Its value.
 */
function readPinnedTerm(pins: ChannelPins, field: ChannelTermsPin): bigint {
    const value = pins[field];
    if (value === undefined) {
        refusePolicyRequest("policy_refusal", `the message is a function of ${field}, which the host has not pinned for the channel yet`);
    }
    return BigInt(value);
}

/**
 * Reads the lock layout a commitment pinned, which a revocation's 36-byte args do not carry.
 * @param pins The channel's pins.
 * @returns The layout.
 */
function readPinnedLockLayout(pins: ChannelPins): CommitmentLockLayout {
    const layout = COMMITMENT_LOCK_LAYOUTS.find((candidate) => candidate === pins.lockLayout);
    if (layout === undefined) {
        refusePolicyRequest(
            "policy_refusal",
            "a revocation is sized under the lock layout, which no commitment of the channel has pinned yet",
        );
    }
    return layout;
}

/**
 * Asserts that an output carries no type script: every channel is a CKB channel.
 * @param name The output's name in a refusal.
 * @param output The output.
 */
function assertCkbOutput(name: string, output: CellOutput): void {
    if (output.type !== null) throw new TypeError(`${name} must carry no type script: the channel is a CKB channel`);
}
