import { bytesToHex } from "@noble/hashes/utils.js";
import type { OutPoint, Script } from "../common";
import { moleculeScript } from "../common";
import { COMMITMENT_LOCK_LAYOUTS } from "../digest";
import type {
    ChannelPinConflict,
    ChannelPins,
    ChannelTermsPin,
    FirstSightChannelPin,
    PolicyChannelTerms,
    SignOperation,
    StatedChannelPins,
} from "./policy.types";

// The device's reserve is a value per layout; every other pin is one string.
type PlainChannelPin = Exclude<keyof StatedChannelPins, "localReservedCkbShannons">;

/**
 * Builds the pins of the funding cell as the host reads it from the funding tx it is to sign.
 * @param fundingOutPoint The funding output.
 * @param capacityShannons Its capacity, in decimal shannons.
 * @returns The pins.
 */
export function fundingCellPins(fundingOutPoint: OutPoint, capacityShannons: string): StatedChannelPins {
    return { fundingOutPoint: outPointPin(fundingOutPoint), fundingCapacityShannons: capacityShannons };
}

/**
 * Builds the pins of the channel's terms as the host reads them from the node's opening context.
 * @param terms The terms.
 * @returns The pins.
 */
export function channelTermsPins(terms: PolicyChannelTerms): StatedChannelPins {
    return {
        liquidCapacityShannons: terms.liquidCapacityShannons,
        commitmentFeeRate: terms.commitmentFeeRate.toString(),
        remoteReservedCkbShannons: terms.remoteReservedCkbShannons,
    };
}

/**
 * Reads the pinned values an operation states.
 * @param operation The operation, its inputs already shaped by the digest recomputation.
 * @returns Each value it states, in the pins' forms.
 */
export function statedChannelPins(operation: SignOperation): StatedChannelPins {
    // Asset first, then layout: a conflict names the first value that differs, and the rest are read under those two.
    switch (operation.kind) {
        case "commitment_tx": {
            const { input } = operation;
            return {
                udtTypeScript: scriptOptPin(input.udtTypeScript),
                lockLayout: input.lockLayout,
                ...fundingCapacityPins(input),
                fundingOutPoint: outPointPin(input.fundingOutPoint),
                remoteFundingPubkey: bytesToHex(input.remoteFundingPubkey),
                remoteTlcBasePubkey: bytesToHex(input.remoteTlcBasePubkey),
                commitmentDelayEpoch: input.commitmentDelayEpoch.toString(),
                commitmentFeeRate: input.commitmentFeeRate.toString(),
            };
        }
        case "closing_tx": {
            const { input } = operation;
            // Its outputs are what is left after both fees, so it states neither capacity nor reserve.
            return {
                udtTypeScript: null,
                fundingOutPoint: outPointPin(input.fundingOutPoint),
                remoteFundingPubkey: bytesToHex(input.remoteFundingPubkey),
                localCloseScript: scriptPin(input.localCloseScript),
            };
        }
        case "revocation": {
            const { input } = operation;
            return {
                udtTypeScript: scriptOptPin(input.udtTypeScript),
                lockLayout: input.lockLayout,
                ...fundingCapacityPins(input),
                remoteFundingPubkey: bytesToHex(input.remoteFundingPubkey),
                commitmentDelayEpoch: input.commitmentDelayEpoch.toString(),
                commitmentFeeRate: input.commitmentFeeRate.toString(),
                // A received revocation pays the device's close script.
                ...(input.forRemote ? { localCloseScript: scriptPin(input.payoutScript) } : {}),
            };
        }
        case "channel_announcement": {
            const { input } = operation;
            return {
                udtTypeScript: scriptOptPin(input.udtTypeScript),
                fundingOutPoint: outPointPin(input.fundingOutPoint),
                liquidCapacityShannons: input.capacityShannons.toString(),
                remoteFundingPubkey: bytesToHex(input.remoteFundingPubkey),
            };
        }
    }
}

/**
 * Finds the first stated value that differs from the one pinned.
 * @param pins The channel's pins.
 * @param stated What a request or the host states.
 * @returns The conflict, or `null` when every stated value is pinned to itself or not pinned yet.
 */
export function findChannelPinConflict(pins: ChannelPins, stated: StatedChannelPins): ChannelPinConflict | null {
    for (const [field, value] of statedEntries(stated)) {
        const conflict =
            field === "localReservedCkbShannons" ? reserveConflict(pins, stated.lockLayout, value) : plainConflict(pins, field, value);
        if (conflict !== null) return conflict;
    }
    return null;
}

/**
 * Pins every stated value of the given fields not pinned yet; the caller has found no conflict first.
 * @param pins The channel's pins.
 * @param stated What a request or the host states.
 * @param fields The fields the statement may pin: the first-sight ones for a message, the terms for the host.
 * @returns The pins with the new values, the ones given when nothing is new.
 */
export function withChannelPins(
    pins: ChannelPins,
    stated: StatedChannelPins,
    fields: readonly (FirstSightChannelPin | ChannelTermsPin)[],
): ChannelPins {
    const fresh = fields.filter((field) => pins[field] === undefined && stated[field] !== undefined);
    if (fresh.length === 0) return pins;
    const next = { ...pins };
    for (const field of fresh) next[field] = stated[field];
    return next;
}

/**
 * Contrasts a stated value with the one pinned under its field.
 * @param pins The channel's pins.
 * @param field The field stated.
 * @param stated The value stated.
 * @returns The conflict, or `null` when the field is pinned to that value or not pinned yet.
 */
function plainConflict(pins: ChannelPins, field: PlainChannelPin, stated: string | null): ChannelPinConflict | null {
    const pinned = pins[field];
    return pinned === undefined || pinned === stated ? null : { field, pinned, stated };
}

/**
 * Contrasts a stated reserve with the one computed under the layout stated beside it.
 * @param pins The channel's pins.
 * @param declared The layout stated beside the reserve.
 * @param stated The reserve stated.
 * @returns The conflict, or `null` when the statement matches.
 */
function reserveConflict(pins: ChannelPins, declared: string | undefined, stated: string | null): ChannelPinConflict | null {
    const layout = COMMITMENT_LOCK_LAYOUTS.find((candidate) => candidate === declared);
    if (layout === undefined) throw new TypeError("a reserve is stated without the lock layout that sizes it");
    const pinned = pins.localReservedCkbShannons[layout];
    return pinned === stated ? null : { field: "localReservedCkbShannons", pinned, stated };
}

/**
 * Lists the values a statement holds.
 * @param stated The statement.
 * @returns Its fields and values, absent ones left out.
 */
function statedEntries(stated: StatedChannelPins): [keyof StatedChannelPins, string | null][] {
    return (Object.keys(stated) as (keyof StatedChannelPins)[]).flatMap((field) => {
        const value = stated[field];
        return value === undefined ? [] : [[field, value] as [keyof StatedChannelPins, string | null]];
    });
}

/**
 * Reads the capacity values a commitment or a revocation states.
 * @param input Its asset, liquid capacity and reserves.
 * @returns The liquid capacity, the funding cell's capacity and both reserves.
 */
function fundingCapacityPins(input: {
    udtTypeScript: Script | null;
    liquidCapacityShannons: bigint;
    localReservedCkbShannons: bigint;
    remoteReservedCkbShannons: bigint;
}): StatedChannelPins {
    const liquid = input.liquidCapacityShannons;
    const reserved = input.localReservedCkbShannons + input.remoteReservedCkbShannons;
    return {
        liquidCapacityShannons: liquid.toString(),
        // A UDT channel's capacity holds only the reserves.
        fundingCapacityShannons: (input.udtTypeScript === null ? liquid + reserved : reserved).toString(),
        localReservedCkbShannons: input.localReservedCkbShannons.toString(),
        remoteReservedCkbShannons: input.remoteReservedCkbShannons.toString(),
    };
}

/**
 * Writes an out point in its pin form.
 * @param outPoint The out point.
 * @returns `<tx hash hex>:<index>`.
 */
function outPointPin(outPoint: OutPoint): string {
    return `${bytesToHex(outPoint.txHash)}:${outPoint.index}`;
}

/**
 * Writes a script in its pin form.
 * @param script The script.
 * @returns Its molecule bytes, hex.
 */
export function scriptPin(script: Script): string {
    return bytesToHex(moleculeScript(script));
}

/**
 * Writes an optional script in its pin form.
 * @param script The script, or `null`.
 * @returns Its molecule bytes as hex, or `null`.
 */
function scriptOptPin(script: Script | null): string | null {
    return script === null ? null : scriptPin(script);
}
