import { hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../common";
import { HASH256_LENGTH, UINT64_MAX, assertUnsignedBigInt, decodeMoleculeScript, isPlainObject } from "../common";
import { calculateShutdownTxFee } from "../digest";
import type { ChannelPins } from "../policy";
import { MAX_SHUTDOWN_FEE_SHANNONS } from "../policy";
import { assertWireHexBytes } from "../wire";
import { readSdkChannelRecord } from "./channel-evidence";
import { SdkError } from "./sdk.error";
import type { SdkCloseOptions, SdkContext, SdkNetworkConfig } from "./sdk.types";

export type SdkChannelClosingContext = Pick<SdkContext, "network" | "store" | "rpc" | "poller">;

/**
 * Asks the node to close a channel cooperatively, once the device's fee on the close is one the policy signs.
 * @param context What the close reads and calls.
 * @param channelId The channel, under any name the node gave it.
 * @param options The device's fee rate, if any.
 */
export async function closeSdkChannel(context: SdkChannelClosingContext, channelId: string, options?: SdkCloseOptions): Promise<void> {
    const feeRate = readCloseArguments(channelId, options);
    const { pins } = await readSdkChannelRecord(context.store, channelId);
    const closeScript = checkCloseFee(context.network, channelId, pins, feeRate);
    // The opening's watch reports the close: the channel step forgets a channel only once it reads it closed.
    await context.rpc.shutdownChannel({ channelId, closeScript, ...(feeRate === undefined ? {} : { feeRate }) });
    context.poller.pollNow();
}

/**
 * Asserts the channel id and the options, reading the fee rate once.
 * @param channelId The channel.
 * @param options The host's options, if any.
 * @returns The fee rate the host asked, or `undefined` for the channel's commitment fee rate.
 */
function readCloseArguments(channelId: string, options: SdkCloseOptions | undefined): bigint | undefined {
    assertWireHexBytes("channelId", channelId, HASH256_LENGTH);
    if (options === undefined) return undefined;
    if (!isPlainObject(options)) throw new TypeError("options must be an object");
    const { feeRate } = options;
    if (feeRate !== undefined) assertUnsignedBigInt("options.feeRate", feeRate, UINT64_MAX);
    return feeRate;
}

/**
 * Computes the device's fee on the close over the two pinned close scripts, refusing one past what the policy signs.
 * @param network The network, whose funding lock's cell deps fiber counts into the close's size.
 * @param channelId The channel, named in a refusal.
 * @param pins The channel's pins.
 * @param feeRate The host's fee rate, or `undefined` for the pinned commitment fee rate, fiber's default.
 * @returns The device's close script, decoded from its pin.
 */
function checkCloseFee(network: SdkNetworkConfig, channelId: string, pins: ChannelPins, feeRate: bigint | undefined): Script {
    const localCloseScript = decodeMoleculeScript(hexToBytes(pins.localCloseScript), "localCloseScript");
    const remoteCloseScript = decodeMoleculeScript(hexToBytes(readClosePin(channelId, pins, "remoteCloseScript")), "remoteCloseScript");
    const rate = feeRate ?? BigInt(readClosePin(channelId, pins, "commitmentFeeRate"));
    const fee = calculateShutdownTxFee(rate, {
        cellDepsCount: network.fundingLockCellDepsCount,
        udtTypeScript: null,
        localCloseScript,
        remoteCloseScript,
    });
    // Fiber would ask a close the policy refuses, and a close never times out: the channel would stay closing until forced.
    if (fee > MAX_SHUTDOWN_FEE_SHANNONS) {
        throw new SdkError(
            "close_fee_too_high",
            `the device refuses the close: at ${rate} shannons per kilobyte its fee is ${fee}, more than the ${MAX_SHUTDOWN_FEE_SHANNONS} a close's fee may take`,
        );
    }
    return localCloseScript;
}

/**
 * Reads a pin the close is checked against, which only a store that failed during the opening leaves out.
 * @param channelId The channel, named in the failure.
 * @param pins The channel's pins.
 * @param field The pin.
 * @returns Its value.
 */
function readClosePin(channelId: string, pins: ChannelPins, field: "remoteCloseScript" | "commitmentFeeRate"): string {
    const value = pins[field];
    if (value === undefined) throw new TypeError(`channel ${channelId} pins no ${field} to check its close against`);
    return value;
}
