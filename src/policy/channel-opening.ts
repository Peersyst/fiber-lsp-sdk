import type { Script } from "../common";
import { HASH256_LENGTH, UINT64_LENGTH, UINT64_MAX, assertDecimalShannons, assertScript } from "../common";
import type { CommitmentLockLayout } from "../digest";
import { COMMITMENT_LOCK_ARGS_LENGTHS } from "../digest";
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
    // The lower floor: registration refuses only what no node would open.
    const reserved = localReservedCkbShannons(localCloseScript, "legacy");
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
        localReservedCkbShannons: {
            legacy: localReservedCkbShannons(localCloseScript, "legacy").toString(),
            fullPaymentHash: localReservedCkbShannons(localCloseScript, "fullPaymentHash").toString(),
        },
        udtTypeScript: null,
    };
}

/**
 * Port of fiber's `reserved_capacity` on a CKB channel: `occupied_capacity` with the args at no less than the layout's lock args.
 * @param localCloseScript The script the device's side of a close pays to.
 * @param lockLayout The layout whose lock args length floors the close script's.
 * @returns The device's reserve, in shannons.
 */
function localReservedCkbShannons(localCloseScript: Script, lockLayout: CommitmentLockLayout): bigint {
    // Capacity, code hash, hash type and args.
    const argsLength = Math.max(localCloseScript.args.length, COMMITMENT_LOCK_ARGS_LENGTHS[lockLayout]);
    const occupiedBytes = UINT64_LENGTH + HASH256_LENGTH + 1 + argsLength;
    return BigInt(occupiedBytes) * SHANNONS_PER_OCCUPIED_BYTE + RESERVED_SHUTDOWN_FEE_SHANNONS;
}
