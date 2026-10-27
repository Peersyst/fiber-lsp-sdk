import type { CellDep, Script, Transaction } from "../common";
import {
    HASH256_LENGTH,
    assertAnyBytes,
    assertDecimalShannons,
    assertFunction,
    assertScript,
    copyCellDep,
    copyScript,
    copyTransaction,
    isPlainObject,
} from "../common";
import { computeTxHash } from "../digest";
import { ChannelPinError, ChannelRegistrationError, assertChannelOpening } from "../policy";
import type { OpenTenantChannelResult } from "../rpc";
import { assertWireHexBytes } from "../wire";
import { readSdkChannelRecord } from "./channel-evidence";
import { assertUserLockCellDeps } from "./pending-opening";
import { DEFAULT_COMMITMENT_DELAY_EPOCH, DEFAULT_COMMITMENT_FEE_RATE, FUNDING_OUTPUT_INDEX } from "./sdk.constants";
import { SdkError } from "./sdk.error";
import type { PendingOpening, SdkChannelOpening, SdkContext, SdkOpeningPins, SdkSignFundingInputs } from "./sdk.types";
import { checkTenantOpening, describeSdkFailure } from "./utils";

export type SdkChannelOpeningOptions = Pick<
    SdkContext,
    "network" | "lspPubkey" | "store" | "rpc" | "policy" | "dispatch" | "allocator" | "activity" | "openings"
>;

export type SdkFundingSubmissionOptions = Pick<SdkContext, "store" | "rpc" | "policy">;

// The device's own copies, taken before the first await, so nothing the host changes afterwards reaches the node or the pins.
type OpeningArguments = { amountShannons: string; userLock: Script; userLockCellDeps: CellDep[] | undefined };

/**
 * Asks the node for a channel the user's lock funds, checks and pins its answer, and hands back the funding tx to sign.
 * @param options What the opening reads and writes.
 * @param amountShannons What the user pays in, reserve included, in decimal shannons.
 * @param userLock The lock that funds the channel and that the device's side of a close pays to.
 * @param userLockCellDeps The cell deps the node needs to spend the user's lock, when the chain's defaults lack them.
 * @returns The channel, the unsigned funding tx and the terms the node froze.
 */
export async function prepareSdkChannelOpen(
    options: SdkChannelOpeningOptions,
    amountShannons: string,
    userLock: Script,
    userLockCellDeps?: CellDep[],
): Promise<SdkChannelOpening> {
    assertOpeningArguments(amountShannons, userLock);
    assertUserLockCellDeps(userLockCellDeps);
    return openWithNode(options, copyOpeningArguments(amountShannons, userLock, userLockCellDeps));
}

/**
 * Hands the node the funding tx the host signed, once it is the one the device froze.
 * @param options The store and the policy that pin the funding cell, and the node's client.
 * @param channelId The channel, as the opening named it.
 * @param signedTx The funding tx, its inputs signed.
 */
export async function submitSdkFundingTx(options: SdkFundingSubmissionOptions, channelId: string, signedTx: Transaction): Promise<void> {
    assertWireHexBytes("channelId", channelId, HASH256_LENGTH);
    const txHash = hashSignedFundingTx(signedTx);
    // Copied in the same step as the hash: the host's object may change while the record is read.
    const tx = copyTransaction(signedTx);
    const { fundingOutPoint, fundingCapacityShannons } = (await readSdkChannelRecord(options.store, channelId)).pins;
    if (fundingOutPoint === undefined || fundingCapacityShannons === undefined) {
        throw new SdkError("funding_tx_altered", `channel ${channelId} pins no funding cell to check the signed tx against`);
    }
    try {
        // Restating the pinned cell writes nothing; another tx hash is the policy's conflict.
        await options.policy.pinFundingCell(channelId, { txHash, index: FUNDING_OUTPUT_INDEX }, fundingCapacityShannons);
    } catch (error) {
        if (!(error instanceof ChannelPinError)) throw error;
        throw new SdkError("funding_tx_altered", describeSdkFailure("the signed tx is not the funding tx the device froze", error), {
            cause: error,
        });
    }
    await options.rpc.submitSignedFundingTx({ channelId, signedFundingTx: tx });
}

/**
 * Opens a channel in one call: the opening, the host's signature of the funding inputs, and the submission.
 * @param options What the opening reads and writes.
 * @param amountShannons What the user pays in, reserve included, in decimal shannons.
 * @param userLock The lock that funds the channel and that the device's side of a close pays to.
 * @param signFundingInputs The host's signer, handed a copy of the unsigned funding tx.
 * @param userLockCellDeps The cell deps the node needs to spend the user's lock, when the chain's defaults lack them.
 * @returns The channel id.
 */
export async function openSdkChannel(
    options: SdkChannelOpeningOptions,
    amountShannons: string,
    userLock: Script,
    signFundingInputs: SdkSignFundingInputs,
    userLockCellDeps?: CellDep[],
): Promise<string> {
    assertOpeningArguments(amountShannons, userLock);
    assertFunction("signFundingInputs", signFundingInputs);
    assertUserLockCellDeps(userLockCellDeps);
    const opening = await openWithNode(options, copyOpeningArguments(amountShannons, userLock, userLockCellDeps));
    const signedTx = await signFundingInputs(opening.unsignedFundingTx);
    await submitSdkFundingTx(options, opening.channelId, signedTx);
    return opening.channelId;
}

/**
 * Asserts an opening's amount and lock, before anything is allocated or written.
 * @param amountShannons What the user pays in, in decimal shannons.
 * @param userLock The user's lock.
 */
function assertOpeningArguments(amountShannons: string, userLock: Script): void {
    assertDecimalShannons("amountShannons", amountShannons);
    assertScript("userLock", userLock);
    assertChannelOpening(amountShannons, userLock);
}

/**
 * Copies an opening's checked arguments, an empty list of cell deps as none: fiber reads the two alike.
 * @param amountShannons What the user pays in.
 * @param userLock The user's lock.
 * @param userLockCellDeps The lock's cell deps, if any.
 * @returns The device's copies.
 */
function copyOpeningArguments(amountShannons: string, userLock: Script, userLockCellDeps: CellDep[] | undefined): OpeningArguments {
    return {
        amountShannons,
        userLock: copyScript(userLock),
        userLockCellDeps: userLockCellDeps === undefined || userLockCellDeps.length === 0 ? undefined : userLockCellDeps.map(copyCellDep),
    };
}

/**
 * Runs the opening with the node over the pending one it resumes or a fresh one, then names and pins the answer.
 * @param options What the opening reads and writes.
 * @param args The opening's arguments, checked and copied.
 * @returns The opening, every part the node's freshly read answer.
 */
async function openWithNode(options: SdkChannelOpeningOptions, args: OpeningArguments): Promise<SdkChannelOpening> {
    const { network, lspPubkey, rpc, dispatch, openings } = options;
    const { amountShannons, userLock, userLockCellDeps } = args;
    const opening = (await resumableOpening(options, args)) ?? (await startOpening(options, args));
    const { material } = dispatch.prepareChannelOpen(opening.channelIndex, amountShannons, userLock);
    // Kept whatever this throws: an error cannot be told from fiber's interruption, whose remedy is this same request, and a
    // final refusal only repeats.
    const answer = await rpc.openTenantChannel({
        peerPubkey: lspPubkey,
        fundingAmountShannons: amountShannons,
        shutdownScript: userLock,
        fundingLockScript: userLock,
        fundingLockScriptCellDeps: userLockCellDeps,
        commitmentDelayEpoch: DEFAULT_COMMITMENT_DELAY_EPOCH,
        commitmentFeeRate: DEFAULT_COMMITMENT_FEE_RATE,
        signerMaterial: material,
    });
    let pins: SdkOpeningPins;
    try {
        pins = checkTenantOpening(
            {
                fundedShannons: amountShannons,
                userLock,
                commitmentDelayEpoch: DEFAULT_COMMITMENT_DELAY_EPOCH,
                commitmentFeeRate: DEFAULT_COMMITMENT_FEE_RATE,
                fundingPubkey: material.fundingPubkey,
                tlcBasePubkey: material.tlcBaseKey,
                fundingLock: network.fundingLock,
            },
            answer,
        );
    } catch (error) {
        // The answer arrives decoded, so the check's only failure is its own opening_rejected.
        throw await refuseOpening(options, opening, error as SdkError);
    }
    // Named before the pins, so an opening that fails past here, unwatched, is one the next same call's abort check can drop.
    await openings.setChannelId(opening.channelIndex, answer.channelId);
    await pinOpening(options, opening, userLock, answer, pins);
    return { channelId: answer.channelId, unsignedFundingTx: answer.unsignedFundingTx, openingContext: answer.openingContext };
}

/**
 * Reads the pending opening a call with the same arguments resumes, dropping one the node aborted.
 * @param options What the opening reads and writes.
 * @param args The opening's arguments.
 * @returns The opening to resume, or `null` when a fresh one is due.
 */
async function resumableOpening(options: SdkChannelOpeningOptions, args: OpeningArguments): Promise<PendingOpening | null> {
    const { rpc, openings } = options;
    const opening = await openings.readMatching(args.amountShannons, args.userLock, args.userLockCellDeps);
    if (opening === null || opening.channelId === null) return opening;
    const { channelId } = opening;
    // Fiber aborts an opening left unfunded, and then lists it, closed, only among the pending ones.
    const pending = await rpc.listChannelStates({ filter: "only_pending" });
    if (!pending.some((channel) => channel.channelId === channelId && channel.stateName === "Closed")) return opening;
    await dropOpening(options, opening);
    return null;
}

/**
 * Allocates a fresh index and records the opening under it, replacing any other pending one.
 * @param options What the opening reads and writes.
 * @param args The opening's arguments.
 * @returns The opening, with no channel yet.
 */
async function startOpening(options: SdkChannelOpeningOptions, args: OpeningArguments): Promise<PendingOpening> {
    const channelIndex = await options.allocator.allocateChannelIndex();
    return options.openings.write(channelIndex, args.amountShannons, args.userLock, args.userLockCellDeps);
}

/**
 * Registers the channel and pins the node's answer, all before the tx is handed out: fiber may ask for a signature meanwhile.
 * @param options What the opening reads and writes.
 * @param opening The pending opening.
 * @param userLock The user's lock, the device's close script.
 * @param answer The node's checked answer.
 * @param pins What the check read from it.
 */
async function pinOpening(
    options: SdkChannelOpeningOptions,
    opening: PendingOpening,
    userLock: Script,
    answer: OpenTenantChannelResult,
    pins: SdkOpeningPins,
): Promise<void> {
    const { policy, activity } = options;
    const { channelId } = answer;
    try {
        await policy.registerChannel(channelId, opening.channelIndex, opening.fundedShannons, userLock);
        await policy.pinChannelTerms(channelId, pins.terms);
        const fundingOutPoint = { txHash: computeTxHash(answer.unsignedFundingTx), index: FUNDING_OUTPUT_INDEX };
        await policy.pinFundingCell(channelId, fundingOutPoint, pins.fundingCapacityShannons);
    } catch (error) {
        // Any other failure, a broken store's included, is not the node's answer: the pending opening stays.
        if (error instanceof ChannelRegistrationError || error instanceof ChannelPinError) {
            throw await openingConflict(options, opening, channelId, error);
        }
        throw error;
    }
    await activity.watch("channel", channelId);
}

/**
 * Builds the refusal of an answer that conflicts with the device's record, dropping the pending opening.
 * @param options What the opening reads and writes.
 * @param opening The pending opening.
 * @param channelId The channel the node named.
 * @param cause What the policy refused.
 * @returns The error to throw.
 */
async function openingConflict(
    options: SdkChannelOpeningOptions,
    opening: PendingOpening,
    channelId: string,
    cause: Error,
): Promise<SdkError> {
    const what = `the node's opening of channel ${channelId} conflicts with the device's record`;
    return refuseOpening(options, opening, new SdkError("opening_conflict", describeSdkFailure(what, cause), { cause }));
}

/**
 * Drops the pending opening the device refuses, so the next call starts over, keeping the refusal when the drop fails.
 * @param options What the opening reads and writes.
 * @param opening The pending opening.
 * @param refusal The refusal.
 * @returns The refusal to throw; when the drop failed, the same code and cause, its message telling why.
 */
async function refuseOpening(options: SdkChannelOpeningOptions, opening: PendingOpening, refusal: SdkError): Promise<SdkError> {
    try {
        await dropOpening(options, opening);
        return refusal;
    } catch (failure) {
        // The refusal is what the host acts on; the next same call drops the leftover again, or reopens it once fiber aborted it.
        const message = describeSdkFailure(`${refusal.message}; the pending opening could not be dropped`, failure);
        return new SdkError(refusal.code, message, refusal.cause === undefined ? undefined : { cause: refusal.cause });
    }
}

/**
 * Drops the pending opening by its index, leaving one another call wrote since.
 * @param options What the opening reads and writes.
 * @param opening The pending opening.
 */
async function dropOpening(options: SdkChannelOpeningOptions, opening: PendingOpening): Promise<void> {
    await options.openings.clearIndex(opening.channelIndex);
}

/**
 * Hashes the signed funding tx as CKB does, refusing one that is not a transaction.
 * @param signedTx The funding tx.
 * @returns The tx hash.
 */
function hashSignedFundingTx(signedTx: Transaction): Uint8Array {
    if (!isPlainObject(signedTx)) throw new TypeError("signedTx must be an object");
    const witnesses: unknown = signedTx.witnesses;
    if (!Array.isArray(witnesses)) throw new TypeError("signedTx.witnesses must be an array");
    witnesses.forEach((witness: unknown, index) => assertAnyBytes(`signedTx.witnesses[${index}]`, witness));
    try {
        return computeTxHash(signedTx);
    } catch (error) {
        throw new TypeError(describeSdkFailure("signedTx is not a transaction", error), { cause: error });
    }
}
