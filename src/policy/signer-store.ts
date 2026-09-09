import {
    PAYMENT_HASH_LENGTH,
    PREIMAGE_LENGTH,
    assertHexBytes,
    assertNonEmptyString,
    assertUnsignedInteger,
    isCanonicalDecimal,
    isHexBytes,
    isUnsignedInteger,
} from "../common";
import { MAX_CHANNEL_INDEX } from "../derivation";
import type { IAsyncSignerStorage, ISignerStorage } from "./interfaces";
import {
    CHANNEL_ALIAS_KEY_PREFIX,
    CHANNEL_INDEX_PROBE_LIMIT,
    CHANNEL_RECORD_KEY_PREFIX,
    CHANNEL_WATERMARK_KEY_PREFIX,
    HOLD_INVOICE_PREIMAGE_KEY_PREFIX,
    NEXT_CHANNEL_INDEX_KEY,
} from "./policy.constants";
import type { ChannelPolicyRecord, ChannelWatermark } from "./policy.types";
import { assertChannelPolicyRecord, isChannelPolicyRecord, isChannelWatermark, projectChannelWatermark } from "./utils";

type Storage = ISignerStorage | IAsyncSignerStorage;

export class SignerStore {
    private readonly storage: Storage;

    private readonly recoveryStorage: Storage | null;

    private readonly lanes = new Map<string, Promise<unknown>>();

    /**
     * Last watermark written per index, so an update that does not move it costs the slow store nothing.
     */
    private readonly writtenWatermarks = new Map<number, string>();

    /**
     * Creates a store over the host's persistence.
     * @param storage Host key-value persistence, synchronous or asynchronous.
     * @param recoveryStorage Persistence that survives an uninstall; without it a restored device trusts the node's numbers.
     */
    constructor(storage: Storage, recoveryStorage: Storage | null = null) {
        this.storage = storage;
        this.recoveryStorage = recoveryStorage;
    }

    /**
     * Reads the channel index a channel name resolves to.
     * @param channelId Channel identifier as the node names it, which the open handshake may still change.
     * @returns The channel index, or `null` for a name this device never registered.
     */
    async resolveChannelIndex(channelId: string): Promise<number | null> {
        assertNonEmptyString("channelId", channelId);
        const key = CHANNEL_ALIAS_KEY_PREFIX + channelId;
        return this.serialize(key, () => this.readIndex(this.storage, key));
    }

    /**
     * Points a channel name at a channel index, keeping the names it already had and refusing to move one.
     * @param channelId Channel identifier as the node names it.
     * @param channelIndex Index the channel seed derives from.
     */
    async claimChannelAlias(channelId: string, channelIndex: number): Promise<void> {
        assertNonEmptyString("channelId", channelId);
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        const key = CHANNEL_ALIAS_KEY_PREFIX + channelId;
        await this.serialize(key, async () => {
            const current = await this.readIndex(this.storage, key);
            if (current === channelIndex) return;
            if (current !== null) {
                throw new TypeError(`the name at ${key} already resolves to channel index ${current}`);
            }
            await this.storage.set(key, String(channelIndex));
        });
    }

    /**
     * Reads a channel's policy record.
     * @param channelIndex Index the record is keyed by.
     * @returns The record, or `null` for an index this device never registered.
     */
    async getChannelRecord(channelIndex: number): Promise<ChannelPolicyRecord | null> {
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        const key = CHANNEL_RECORD_KEY_PREFIX + channelIndex;
        return this.serialize(key, () => this.readChannelRecord(key));
    }

    /**
     * Writes a channel's policy record, overwriting any previous one.
     * @param channelIndex Index the record is keyed by.
     * @param record Record to persist.
     */
    async setChannelRecord(channelIndex: number, record: ChannelPolicyRecord): Promise<void> {
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        assertChannelPolicyRecord("record", record);
        const key = CHANNEL_RECORD_KEY_PREFIX + channelIndex;
        await this.serialize(key, () => this.writeChannelRecord(channelIndex, key, record));
    }

    /**
     * Reads, updates and writes a channel's record as one step no concurrent call on the same channel can interleave with.
     * @param channelIndex Index the record is keyed by, so two names of one channel share the lane.
     * @param update Synchronous updater; handing back the record it was given means nothing changed, and skips the write.
     * @returns The record the key now holds.
     */
    async updateChannelRecord(
        channelIndex: number,
        update: (current: ChannelPolicyRecord | null) => ChannelPolicyRecord,
    ): Promise<ChannelPolicyRecord> {
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        const key = CHANNEL_RECORD_KEY_PREFIX + channelIndex;
        return this.serialize(key, async () => {
            const current = await this.readChannelRecord(key);
            const next = update(current);
            if (next === current) return current;
            assertChannelPolicyRecord("updated record", next);
            await this.writeChannelRecord(channelIndex, key, next);
            return next;
        });
    }

    /**
     * Reads the anti-rollback watermark a reinstall leaves behind for a channel.
     * @param channelIndex Index the watermark is keyed by.
     * @returns The watermark, or `null` when there is no recovery storage or it holds nothing for that index.
     */
    async getChannelWatermark(channelIndex: number): Promise<ChannelWatermark | null> {
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        const recoveryStorage = this.recoveryStorage;
        if (recoveryStorage === null) return null;
        const key = CHANNEL_WATERMARK_KEY_PREFIX + channelIndex;
        return this.serialize(key, async () => {
            const raw = (await recoveryStorage.get(key)) ?? null;
            if (raw === null) return null;
            // Corruption must throw: a watermark read as absent is a restored device trusting the node's numbers.
            return parseStored(key, raw, isChannelWatermark, "a channel watermark");
        });
    }

    /**
     * Reads the index the allocator hands out next, which is the highest either storage knows about.
     * @returns The next channel index, or `0` on a device that has never allocated one.
     */
    async getNextChannelIndex(): Promise<number> {
        return this.serialize(NEXT_CHANNEL_INDEX_KEY, () => this.readNextChannelIndex());
    }

    /**
     * Raises the allocator's counter to at least an index, which is how reconciliation reports what the node still holds.
     * @param channelIndex Index the counter must not hand out again.
     */
    async raiseNextChannelIndex(channelIndex: number): Promise<void> {
        assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
        await this.serialize(NEXT_CHANNEL_INDEX_KEY, async () => {
            const current = await this.readNextChannelIndex();
            if (current > channelIndex) return;
            await this.writeNextChannelIndex(channelIndex + 1);
        });
    }

    /**
     * Hands out a channel index no channel on this device holds, stepping over any the counter has fallen behind.
     * @returns The allocated channel index, persisted as spent before it is returned.
     */
    async allocateChannelIndex(): Promise<number> {
        return this.serialize(NEXT_CHANNEL_INDEX_KEY, async () => {
            let channelIndex = await this.readNextChannelIndex();
            for (let probe = 0; !(await this.isChannelIndexFree(channelIndex)); probe++) {
                if (probe >= CHANNEL_INDEX_PROBE_LIMIT) {
                    throw new Error(`channel indexes ${channelIndex - probe} to ${channelIndex} are all in use`);
                }
                channelIndex++;
            }
            assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX - 1);
            await this.writeNextChannelIndex(channelIndex + 1);
            return channelIndex;
        });
    }

    /**
     * Reads the device-held preimage of a hold invoice.
     * @param paymentHashHex Payment hash of the invoice, 32 bytes of lowercase hex.
     * @returns The 32-byte preimage as lowercase hex, or `null` if none is stored.
     */
    async getHoldInvoicePreimage(paymentHashHex: string): Promise<string | null> {
        assertHexBytes("paymentHashHex", paymentHashHex, PAYMENT_HASH_LENGTH);
        const key = HOLD_INVOICE_PREIMAGE_KEY_PREFIX + paymentHashHex;
        return this.serialize(key, async () => {
            const raw = (await this.storage.get(key)) ?? null;
            if (raw === null) return null;
            if (!isHexBytes(raw, PREIMAGE_LENGTH)) {
                throw new TypeError(`stored value at ${key} is not a preimage`);
            }
            return raw;
        });
    }

    /**
     * Stores the device-held preimage of a hold invoice, overwriting any previous one.
     * @param paymentHashHex Payment hash of the invoice, 32 bytes of lowercase hex.
     * @param preimageHex The 32-byte preimage as lowercase hex.
     */
    async setHoldInvoicePreimage(paymentHashHex: string, preimageHex: string): Promise<void> {
        assertHexBytes("paymentHashHex", paymentHashHex, PAYMENT_HASH_LENGTH);
        assertHexBytes("preimageHex", preimageHex, PREIMAGE_LENGTH);
        const key = HOLD_INVOICE_PREIMAGE_KEY_PREFIX + paymentHashHex;
        await this.serialize(key, async () => {
            await this.storage.set(key, preimageHex);
        });
    }

    /**
     * Checks that an index carries nothing this device has ever signed under.
     * @param channelIndex Index to check.
     * @returns Whether the index holds neither a record nor a watermark.
     */
    private async isChannelIndexFree(channelIndex: number): Promise<boolean> {
        const record = await this.getChannelRecord(channelIndex);
        if (record !== null) return false;
        return (await this.getChannelWatermark(channelIndex)) === null;
    }

    /**
     * Reads and parses the channel index at a key.
     * @param storage Storage to read from.
     * @param key Storage key to read.
     * @returns The channel index, or `null` if the key was never written.
     */
    private async readIndex(storage: Storage, key: string): Promise<number | null> {
        const raw = (await storage.get(key)) ?? null;
        if (raw === null) return null;
        // Corruption must throw: an alias read as absent would re-open the channel's slots under a second record.
        if (!isCanonicalDecimal(raw) || !isUnsignedInteger(Number(raw), MAX_CHANNEL_INDEX)) {
            throw new TypeError(`stored value at ${key} is not a channel index`);
        }
        return Number(raw);
    }

    /**
     * Reads the allocator's counter out of both storages, taking whichever is ahead.
     * @returns The next channel index, or `0` when neither storage holds one.
     */
    private async readNextChannelIndex(): Promise<number> {
        const stored = (await this.readIndex(this.storage, NEXT_CHANNEL_INDEX_KEY)) ?? 0;
        if (this.recoveryStorage === null) return stored;
        const kept = (await this.readIndex(this.recoveryStorage, NEXT_CHANNEL_INDEX_KEY)) ?? 0;
        return Math.max(stored, kept);
    }

    /**
     * Writes the allocator's counter, the surviving storage first so a crash can only leave it ahead.
     * @param nextChannelIndex Index to hand out next.
     */
    private async writeNextChannelIndex(nextChannelIndex: number): Promise<void> {
        await this.recoveryStorage?.set(NEXT_CHANNEL_INDEX_KEY, String(nextChannelIndex));
        await this.storage.set(NEXT_CHANNEL_INDEX_KEY, String(nextChannelIndex));
    }

    /**
     * Reads and parses the record at a storage key.
     * @param key Storage key to read.
     * @returns The record, or `null` if the key was never written.
     */
    private async readChannelRecord(key: string): Promise<ChannelPolicyRecord | null> {
        const raw = (await this.storage.get(key)) ?? null;
        if (raw === null) return null;
        // Corruption must throw: a record read as absent would re-open its sign-once slots.
        return parseStored(key, raw, isChannelPolicyRecord, "a channel policy record");
    }

    /**
     * Persists a record, and the watermark it projects onto before it.
     * @param channelIndex Index the record is keyed by.
     * @param key Storage key that holds it.
     * @param record Record to persist.
     */
    private async writeChannelRecord(channelIndex: number, key: string, record: ChannelPolicyRecord): Promise<void> {
        await this.writeChannelWatermark(channelIndex, record);
        await this.storage.set(key, JSON.stringify(record));
    }

    /**
     * Writes the watermark a record projects onto, before the record itself: behind it, a claim could outlive its floor.
     * @param channelIndex Index the watermark is keyed by.
     * @param record Record being written.
     */
    private async writeChannelWatermark(channelIndex: number, record: ChannelPolicyRecord): Promise<void> {
        const recoveryStorage = this.recoveryStorage;
        if (recoveryStorage === null) return;
        const value = JSON.stringify(projectChannelWatermark(record));
        if (this.writtenWatermarks.get(channelIndex) === value) return;
        const key = CHANNEL_WATERMARK_KEY_PREFIX + channelIndex;
        await this.serialize(key, async () => {
            await recoveryStorage.set(key, value);
        });
        this.writtenWatermarks.set(channelIndex, value);
    }

    /**
     * Runs an operation after every earlier one queued on the same key, so a read-modify-write never interleaves.
     * @param key Storage key whose lane the operation joins.
     * @param operation Operation to run once the lane is free.
     * @returns Whatever the operation returned.
     */
    private async serialize<T>(key: string, operation: () => Promise<T>): Promise<T> {
        const previous = this.lanes.get(key) ?? Promise.resolve();
        const result = previous.then(operation);
        // Swallowed here so a failed operation does not poison the lane.
        const lane = result.catch(() => undefined);
        this.lanes.set(key, lane);
        try {
            return await result;
        } finally {
            if (this.lanes.get(key) === lane) this.lanes.delete(key);
        }
    }
}

/**
 * Parses a stored value, refusing anything the storage returns that is not what the key holds.
 * @param key Storage key the value came from, used in the error message.
 * @param raw Raw string read from storage.
 * @param guard Shape guard the parsed value must pass.
 * @param expected Name of the shape, used in the error message.
 * @returns The parsed value.
 */
function parseStored<T>(key: string, raw: string, guard: (value: unknown) => value is T, expected: string): T {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw new TypeError(`stored value at ${key} is not valid JSON`);
    }
    if (!guard(parsed)) {
        throw new TypeError(`stored value at ${key} is not ${expected}`);
    }
    return parsed;
}
