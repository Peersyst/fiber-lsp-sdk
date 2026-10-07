import type { Script } from "../common";
import { HASH256_LENGTH, UINT64_LENGTH, UINT64_MAX, assertDecimalShannons, assertScript } from "../common";
import { COMMITMENT_LOCK_ARGS_LENGTH } from "../digest";
import { scriptPin } from "./channel-pins";
import { RESERVED_SHUTDOWN_FEE_SHANNONS, SHANNONS_PER_OCCUPIED_BYTE } from "./policy.constants";
import type { ChannelPins } from "./policy.types";

/**
 * Asserts that fiber can open a channel with this funding and close script.
 * @param fundedShannons What the user pays into the channel, reserve included, in decimal shannons.
 * @param localCloseScript The script the device's side of a close pays to.
 */
export function assertChannelOpening(fundedShannons: string, localCloseScript: Script): void {
    assertDecimalShannons("fundedShannons", fundedShannons);
    assertScript("localCloseScript", localCloseScript);
    const funded = BigInt(fundedShannons);
    if (funded >= UINT64_MAX) {
        throw new RangeError(`fundedShannons must be below ${UINT64_MAX}, the most a CKB channel's capacity holds`);
    }
    const reserved = localReservedCkbShannons(localCloseScript);
    if (funded < reserved) {
        throw new RangeError(`fundedShannons ${fundedShannons} is below the ${reserved} the device's reserve takes over that close script`);
    }
}

/**
 * Builds the pins a channel is registered with.
 * @param fundedShannons What the user paid into the channel, reserve included, in decimal shannons.
 * @param localCloseScript The script the device's side of a close pays to.
 * @returns The opening pins.
 */
export function openingChannelPins(fundedShannons: string, localCloseScript: Script): ChannelPins {
    assertChannelOpening(fundedShannons, localCloseScript);
    return {
        fundedShannons,
        localCloseScript: scriptPin(localCloseScript),
        localReservedCkbShannons: localReservedCkbShannons(localCloseScript).toString(),
        udtTypeScript: null,
    };
}

/**
 * Port of fiber's `reserved_capacity` on a CKB channel.
 * @param localCloseScript The script the device's side of a close pays to.
 * @returns The device's reserve, in shannons.
 */
function localReservedCkbShannons(localCloseScript: Script): bigint {
    // Capacity, code hash, hash type and args, the args at least the commitment lock's.
    const argsLength = Math.max(localCloseScript.args.length, COMMITMENT_LOCK_ARGS_LENGTH);
    const occupiedBytes = UINT64_LENGTH + HASH256_LENGTH + 1 + argsLength;
    return BigInt(occupiedBytes) * SHANNONS_PER_OCCUPIED_BYTE + RESERVED_SHUTDOWN_FEE_SHANNONS;
}
