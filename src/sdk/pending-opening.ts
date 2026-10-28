import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { CellDep, Script } from "../common";
import {
    DEP_TYPES,
    HASH256_LENGTH,
    UINT32_MAX,
    assertCellDeps,
    assertDecimalShannons,
    assertUnsignedInteger,
    decodeMoleculeScript,
    isDecimalShannons,
    isHexBytes,
    isNonEmptyHexBytes,
    isPlainObject,
    isUnsignedInteger,
    moleculeScript,
} from "../common";
import { MAX_CHANNEL_INDEX } from "../derivation";
import type { SignerRecordFormat, SignerStore } from "../policy";
import { isWireHex } from "../wire";
import { assertActivityId } from "./utils";
import { PENDING_OPENING_RECORD_KEY, PENDING_OPENING_RECORD_VERSION } from "./sdk.constants";
import type { PendingOpening, PendingOpeningCellDep, PendingOpeningRecord } from "./sdk.types";

/**
 * Asserts the cell deps an opening names for the user's lock.
 * @param value The cell deps, if any.
 */
export function assertUserLockCellDeps(value: unknown): asserts value is CellDep[] | undefined {
    if (value !== undefined) assertCellDeps("userLockCellDeps", value);
}

/**
 * Writes cell deps in the record's form, as given: an empty list stays one.
 * @param deps The cell deps, checked.
 * @returns The record's form, or `undefined` for none.
 */
function cellDepsRecordOf(deps: readonly CellDep[] | undefined): PendingOpeningCellDep[] | undefined {
    if (deps === undefined) return undefined;
    return deps.map(({ outPoint, depType }) => ({ txHash: bytesToHex(outPoint.txHash), index: outPoint.index, depType }));
}

/**
 * Checks that a value is cell deps in the record's form.
 * @param value Value to check.
 * @returns Whether the value reads as the record's cell deps.
 */
function isCellDepsRecord(value: unknown): value is PendingOpeningCellDep[] {
    return (
        Array.isArray(value) &&
        value.every(
            (dep: unknown) =>
                isPlainObject(dep) &&
                isHexBytes(dep.txHash, HASH256_LENGTH) &&
                isUnsignedInteger(dep.index, UINT32_MAX) &&
                DEP_TYPES.some((depType) => depType === dep.depType),
        )
    );
}

/**
 * Compares two lists of cell deps in the record's form.
 * @param a One list, or `undefined` for none.
 * @param b The other.
 * @returns Whether they name the same cell deps in the same order.
 */
function sameCellDeps(a: readonly PendingOpeningCellDep[] | undefined, b: readonly PendingOpeningCellDep[] | undefined): boolean {
    if (a === undefined || b === undefined) return a === b;
    return (
        a.length === b.length &&
        a.every((dep, index) => {
            const other = b[index];
            return other !== undefined && dep.txHash === other.txHash && dep.index === other.index && dep.depType === other.depType;
        })
    );
}

/**
 * Checks that a value is a script's molecule bytes as lowercase hex, the form the policy pins a script in.
 * @param value Value to check.
 * @returns Whether the value reads as a script.
 */
function isLockHex(value: unknown): value is string {
    if (!isNonEmptyHexBytes(value)) return false;
    try {
        decodeMoleculeScript(hexToBytes(value), "userLock");
        return true;
    } catch {
        return false;
    }
}

/**
 * Checks that a value has the shape of a pending opening, extra fields tolerated.
 * @param value Value to check.
 * @returns Whether the value is a valid pending opening.
 */
function isPendingOpening(value: unknown): value is PendingOpening {
    return (
        isPlainObject(value) &&
        isUnsignedInteger(value.channelIndex, MAX_CHANNEL_INDEX) &&
        isDecimalShannons(value.fundedShannons) &&
        isLockHex(value.userLock) &&
        (value.userLockCellDeps === undefined || isCellDepsRecord(value.userLockCellDeps)) &&
        (value.channelId === null || isWireHex(value.channelId, HASH256_LENGTH))
    );
}

/**
 * Checks that a value has the shape of a stored {@link PendingOpeningRecord}, extra fields tolerated.
 * @param value Value to check, typically freshly parsed JSON.
 * @returns Whether the value is a valid pending opening record.
 */
function isPendingOpeningRecord(value: unknown): value is PendingOpeningRecord {
    return (
        isPlainObject(value) &&
        value.version === PENDING_OPENING_RECORD_VERSION &&
        (value.opening === null || isPendingOpening(value.opening))
    );
}

const PENDING_OPENING_FORMAT: SignerRecordFormat<PendingOpeningRecord> = {
    name: "pending opening record",
    is: isPendingOpeningRecord,
    assert: (name, value) => {
        if (!isPendingOpeningRecord(value)) throw new TypeError(`${name} is not a valid pending opening record`);
    },
    belongsAt: () => true,
};

export class PendingOpeningStore {
    private readonly store: SignerStore;

    /**
     * Creates the store of the opening the node may still hold for this tenant.
     * @param store Typed persistence the opening is kept in.
     */
    constructor(store: SignerStore) {
        this.store = store;
    }

    /**
     * Reads the pending opening.
     * @returns The opening, or `null` when there is none.
     */
    async read(): Promise<PendingOpening | null> {
        return (await this.store.getRecord(PENDING_OPENING_RECORD_KEY, PENDING_OPENING_FORMAT))?.opening ?? null;
    }

    /**
     * Reads the pending opening only if it was asked with the same amount, lock and cell deps, the one a retry may resume.
     * @param fundedShannons The amount asked, in decimal shannons.
     * @param userLock The lock asked.
     * @param userLockCellDeps The lock's cell deps asked, if any.
     * @returns The opening, or `null` when there is none or it was asked with other parameters.
     */
    async readMatching(fundedShannons: string, userLock: Script, userLockCellDeps?: readonly CellDep[]): Promise<PendingOpening | null> {
        const lock = bytesToHex(moleculeScript(userLock, "userLock"));
        assertUserLockCellDeps(userLockCellDeps);
        const deps = cellDepsRecordOf(userLockCellDeps);
        const opening = await this.read();
        if (opening === null || opening.fundedShannons !== fundedShannons || opening.userLock !== lock) return null;
        return sameCellDeps(opening.userLockCellDeps, deps) ? opening : null;
    }

    /**
     * Records an opening about to be asked of the node, with no channel yet, replacing any other.
     * @param channelIndex The index allocated to it.
     * @param fundedShannons The amount asked, in decimal shannons.
     * @param userLock The lock asked.
     * @param userLockCellDeps The lock's cell deps asked, if any.
     * @returns The opening written.
     */
    async write(
        channelIndex: number,
        fundedShannons: string,
        userLock: Script,
        userLockCellDeps?: readonly CellDep[],
    ): Promise<PendingOpening> {
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        assertDecimalShannons("fundedShannons", fundedShannons);
        const lock = bytesToHex(moleculeScript(userLock, "userLock"));
        assertUserLockCellDeps(userLockCellDeps);
        const deps = cellDepsRecordOf(userLockCellDeps);
        const opening: PendingOpening = {
            channelIndex,
            fundedShannons,
            userLock: lock,
            ...(deps === undefined ? {} : { userLockCellDeps: deps }),
            channelId: null,
        };
        await this.store.updateRecord(PENDING_OPENING_RECORD_KEY, PENDING_OPENING_FORMAT, (): PendingOpeningRecord => ({
            version: PENDING_OPENING_RECORD_VERSION,
            opening,
        }));
        return opening;
    }

    /**
     * Records the channel the node answered for the opening under an index, unless another opening replaced it since.
     * @param channelIndex The opening's index.
     * @param channelId The channel, as the node names it.
     */
    async setChannelId(channelIndex: number, channelId: string): Promise<void> {
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        assertActivityId("channel", channelId);
        await this.store.updateRecord(PENDING_OPENING_RECORD_KEY, PENDING_OPENING_FORMAT, (current) => {
            if (current === null || current.opening === null) return current;
            const { opening } = current;
            if (opening.channelIndex !== channelIndex || opening.channelId === channelId) return current;
            return { ...current, opening: { ...opening, channelId } };
        });
    }

    /**
     * Drops the pending opening that names a channel, leaving any other.
     * @param channelId The channel whose opening is dropped.
     */
    async clear(channelId: string): Promise<void> {
        assertActivityId("channel", channelId);
        await this.clearWhere((opening) => opening.channelId === channelId);
    }

    /**
     * Drops the pending opening under an index, named or not, leaving any other.
     * @param channelIndex The opening's index.
     */
    async clearIndex(channelIndex: number): Promise<void> {
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        await this.clearWhere((opening) => opening.channelIndex === channelIndex);
    }

    /**
     * Drops the pending opening if it is the one sought, as one step in the record's lane.
     * @param sought Whether the pending opening is the one to drop.
     */
    private async clearWhere(sought: (opening: PendingOpening) => boolean): Promise<void> {
        await this.store.updateRecord(PENDING_OPENING_RECORD_KEY, PENDING_OPENING_FORMAT, (current) => {
            if (current === null || current.opening === null || !sought(current.opening)) return current;
            return { ...current, opening: null };
        });
    }
}
