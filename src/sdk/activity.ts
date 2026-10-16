import type { SignerRecordFormat, SignerStore } from "../policy";
import { ACTIVITY_RECORD_KEY } from "./sdk.constants";
import type { ActivityEntry, ActivityKind, ActivityRecord, ActivityStatus } from "./sdk.types";
import {
    activityField,
    assertActivityId,
    assertActivityRecord,
    assertActivityStatus,
    emptyActivityRecord,
    isActivityRecord,
} from "./utils";

const ACTIVITY_RECORD_FORMAT: SignerRecordFormat<ActivityRecord> = {
    name: "activity record",
    is: isActivityRecord,
    assert: assertActivityRecord,
    belongsAt: () => true,
};

type AnyActivityEntry = { status: string | null };

export class ActivityTracker {
    private readonly store: SignerStore;

    /**
     * Creates the tracker over the store that keeps the record of what is watched.
     * @param store Typed persistence the record is kept in.
     */
    constructor(store: SignerStore) {
        this.store = store;
    }

    /**
     * Reads what is being watched.
     * @returns The record, empty when nothing was ever watched.
     */
    async read(): Promise<ActivityRecord> {
        return (await this.store.getRecord(ACTIVITY_RECORD_KEY, ACTIVITY_RECORD_FORMAT)) ?? emptyActivityRecord();
    }

    /**
     * Starts watching something, with no event emitted for it yet; one already watched keeps its entry.
     * @param kind What it is.
     * @param id The id the node knows it under.
     */
    async watch(kind: ActivityKind, id: string): Promise<void> {
        assertActivityId(kind, id);
        await this.update(kind, (entries) => (Object.hasOwn(entries, id) ? entries : { ...entries, [id]: { status: null } }));
    }

    /**
     * Records the status an event was just emitted for, so a repeat of that status emits nothing more.
     * @param kind What it is.
     * @param id The id the node knows it under.
     * @param status The status the event announced.
     */
    async mark<Kind extends ActivityKind>(kind: Kind, id: string, status: ActivityStatus<Kind>): Promise<void> {
        assertActivityId(kind, id);
        assertActivityStatus(kind, status);
        await this.update(kind, (entries) => {
            const entry = Object.hasOwn(entries, id) ? entries[id] : undefined;
            if (entry === undefined) throw new TypeError(`${kind} ${id} is not being watched`);
            return entry.status === status ? entries : { ...entries, [id]: { ...entry, status } };
        });
    }

    /**
     * Stops watching something that reached a final status; one not watched is left alone.
     * @param kind What it is.
     * @param id The id the node knows it under.
     */
    async forget(kind: ActivityKind, id: string): Promise<void> {
        assertActivityId(kind, id);
        await this.update(kind, (entries) => {
            if (!Object.hasOwn(entries, id)) return entries;
            const rest = { ...entries };
            delete rest[id];
            return rest;
        });
    }

    /**
     * Rewrites one kind's entries as one step in the record's lane; entries handed back unchanged write nothing.
     * @param kind The kind whose entries change.
     * @param update Synchronous updater over that kind's entries.
     */
    private async update(
        kind: ActivityKind,
        update: (entries: Record<string, AnyActivityEntry>) => Record<string, AnyActivityEntry>,
    ): Promise<void> {
        const field = activityField(kind);
        await this.store.updateRecord(ACTIVITY_RECORD_KEY, ACTIVITY_RECORD_FORMAT, (current) => {
            const record = current ?? emptyActivityRecord();
            const entries = update(record[field]);
            if (entries === record[field]) return current;
            // The cast is checked: `updateRecord` asserts the record before writing it.
            return { ...record, [field]: entries as Record<string, ActivityEntry<ActivityKind>> } as ActivityRecord;
        });
    }
}
