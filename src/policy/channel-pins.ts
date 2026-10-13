import { bytesToHex } from "@noble/hashes/utils.js";
import type { OutPoint, Script } from "../common";
import { moleculeScript } from "../common";
import { FIRST_SIGHT_CHANNEL_PINS } from "./policy.constants";
import type { ChannelPinConflict, ChannelPins, SignOperation, StatedChannelPins } from "./policy.types";

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
 * Reads the pinned values an operation states.
 * @param operation The operation, its inputs already shaped by the digest recomputation.
 * @returns Each value it states, in the pins' forms.
 */
export function statedChannelPins(operation: SignOperation): StatedChannelPins {
    // Asset first: a conflict names the first value that differs, and the asset is the others' unit.
    switch (operation.kind) {
        case "commitment_tx": {
            const { input } = operation;
            return {
                udtTypeScript: scriptOptPin(input.udtTypeScript),
                ...fundingCapacityPins(input),
                fundingOutPoint: outPointPin(input.fundingOutPoint),
                remoteFundingPubkey: bytesToHex(input.remoteFundingPubkey),
                remoteTlcBasePubkey: bytesToHex(input.remoteTlcBasePubkey),
                commitmentDelayEpoch: input.commitmentDelayEpoch.toString(),
                commitmentFeeRate: input.commitmentFeeRate.toString(),
            };
        }
        case "shutdown_tx": {
            const { input } = operation;
            return {
                udtTypeScript: scriptOptPin(input.udtTypeScript),
                ...fundingCapacityPins(input),
                fundingOutPoint: outPointPin(input.fundingOutPoint),
                remoteFundingPubkey: bytesToHex(input.remoteFundingPubkey),
                localCloseScript: scriptPin(input.localCloseScript),
            };
        }
        case "revocation": {
            const { input } = operation;
            return {
                udtTypeScript: scriptOptPin(input.udtTypeScript),
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
        const pinned = pins[field];
        if (pinned !== undefined && pinned !== value) return { field, pinned, stated: value };
    }
    return null;
}

/**
 * Pins every stated value not pinned yet; the caller has found no conflict first.
 * @param pins The channel's pins.
 * @param stated What a request or the host states.
 * @returns The pins with the new values, the ones given when nothing is new.
 */
export function withChannelPins(pins: ChannelPins, stated: StatedChannelPins): ChannelPins {
    // The other pins are fixed at registration.
    const fresh = FIRST_SIGHT_CHANNEL_PINS.filter((field) => pins[field] === undefined && stated[field] !== undefined);
    if (fresh.length === 0) return pins;
    const next = { ...pins };
    for (const field of fresh) next[field] = stated[field];
    return next;
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
 * Reads the capacity values a transaction over the funding cell states.
 * @param input Its asset, balances and reserves.
 * @returns The liquid capacity, the funding cell's capacity and both reserves.
 */
function fundingCapacityPins(input: {
    udtTypeScript: Script | null;
    toLocalShannons: bigint;
    toRemoteShannons: bigint;
    localReservedCkbShannons: bigint;
    remoteReservedCkbShannons: bigint;
}): StatedChannelPins {
    const liquid = input.toLocalShannons + input.toRemoteShannons;
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
