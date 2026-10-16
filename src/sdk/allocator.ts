import { MILLISECONDS_PER_SECOND, isUnsignedInteger } from "../common";
import { MAX_CHANNEL_INDEX } from "../derivation";
import type { SignerRecordFormat, SignerStore } from "../policy";
import { ALLOCATION_FLOOR_MS, ALLOCATOR_KEY_PREFIX } from "./sdk.constants";
import { SdkError } from "./sdk.error";
import type { AllocationKind } from "./sdk.types";

// Both kinds share the channel index's bound, the largest safe integer.
const LAST_INDEX_FORMAT: SignerRecordFormat<number> = {
    name: "last allocated index",
    is: (value): value is number => isUnsignedInteger(value, MAX_CHANNEL_INDEX),
    assert: (name, value) => {
        if (!isUnsignedInteger(value, MAX_CHANNEL_INDEX)) throw new TypeError(`${name} is not a valid last allocated index`);
    },
    belongsAt: () => true,
};

export class IndexAllocator {
    private readonly store: SignerStore;

    private readonly now: () => number;

    /**
     * Creates the allocator over the store that keeps the last index of each kind.
     * @param store Typed persistence the last indexes are kept in.
     * @param now The clock, in milliseconds since the epoch.
     */
    constructor(store: SignerStore, now: () => number) {
        this.store = store;
        this.now = now;
    }

    /**
     * Allocates a channel index: the clock in seconds, or one past the last index when the clock has not moved past it.
     * @returns The index, persisted as the last one before it is returned.
     */
    async allocateChannelIndex(): Promise<number> {
        return this.allocate("channel", Math.floor(this.readClock() / Number(MILLISECONDS_PER_SECOND)));
    }

    /**
     * Allocates a hold invoice index: the clock in milliseconds, or one past the last index when the clock has not moved past it.
     * @returns The index, persisted as the last one before it is returned.
     */
    async allocateInvoiceIndex(): Promise<number> {
        return this.allocate("invoice", this.readClock());
    }

    /**
     * Reads the clock, refusing a reading no device of this SDK can have allocated under.
     * @returns Milliseconds since the epoch.
     */
    private readClock(): number {
        // Not `this.now()`: the host's clock gets no receiver.
        const clock = this.now;
        const now = clock();
        if (!isUnsignedInteger(now, MAX_CHANNEL_INDEX)) {
            throw new TypeError(`now() must return whole milliseconds since the epoch, got ${now}`);
        }
        if (now < ALLOCATION_FLOOR_MS) {
            throw new SdkError("clock_before_floor", `the clock reads ${now}, before the allocation floor ${ALLOCATION_FLOOR_MS}`);
        }
        return now;
    }

    /**
     * Takes the candidate or the next index after the last one, whichever is higher, writing it as the last before returning.
     * @param kind Which sequence the index belongs to.
     * @param candidate What the clock proposes.
     * @returns The index.
     */
    private async allocate(kind: AllocationKind, candidate: number): Promise<number> {
        return this.store.updateRecord(ALLOCATOR_KEY_PREFIX + kind, LAST_INDEX_FORMAT, (last) =>
            last === null ? candidate : Math.max(candidate, last + 1),
        );
    }
}
