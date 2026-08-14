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
import { CHANNEL_ALIAS_KEY_PREFIX, CHANNEL_RECORD_KEY_PREFIX, HOLD_INVOICE_PREIMAGE_KEY_PREFIX } from "./policy.constants";
import type { ChannelPolicyRecord } from "./policy.types";
import { assertChannelPolicyRecord, isChannelPolicyRecord } from "./utils";

export class SignerStore {
    private readonly storage: ISignerStorage | IAsyncSignerStorage;

    private readonly lanes = new Map<string, Promise<unknown>>();

    /**
     * Creates a store over the host's persistence.
     * @param storage Host key-value persistence, synchronous or asynchronous.
     */
    constructor(storage: ISignerStorage | IAsyncSignerStorage) {
        this.storage = storage;
    }

    /**
     * Reads the channel index a channel name resolves to.
     * @param channelId Channel identifier as the node names it, which the open handshake may still change.
     * @returns The channel index, or `null` for a name this device never registered.
     */
    async resolveChannelIndex(channelId: string): Promise<number | null> {
        assertNonEmptyString("channelId", channelId);
        const key = CHANNEL_ALIAS_KEY_PREFIX + channelId;
        return this.serialize(key, () => this.readChannelIndex(key));
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
            const current = await this.readChannelIndex(key);
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
        await this.serialize(key, () => this.writeChannelRecord(key, record));
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
            await this.writeChannelRecord(key, next);
            return next;
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
     * Reads and parses the channel index at an alias key.
     * @param key Storage key to read.
     * @returns The channel index, or `null` if the key was never written.
     */
    private async readChannelIndex(key: string): Promise<number | null> {
        const raw = (await this.storage.get(key)) ?? null;
        if (raw === null) return null;
        // Corruption must throw: an alias read as absent would re-open the channel's slots under a second record.
        if (!isCanonicalDecimal(raw) || !isUnsignedInteger(Number(raw), MAX_CHANNEL_INDEX)) {
            throw new TypeError(`stored value at ${key} is not a channel index`);
        }
        return Number(raw);
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
        return parseChannelRecord(key, raw);
    }

    /**
     * Serializes a record into the storage key that holds it.
     * @param key Storage key to write.
     * @param record Record to persist.
     */
    private async writeChannelRecord(key: string, record: ChannelPolicyRecord): Promise<void> {
        await this.storage.set(key, JSON.stringify(record));
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
 * Parses a stored channel record, refusing anything the storage returns that is not one.
 * @param key Storage key the value came from, used in the error message.
 * @param raw Raw string read from storage.
 * @returns The parsed record.
 */
function parseChannelRecord(key: string, raw: string): ChannelPolicyRecord {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw new TypeError(`stored value at ${key} is not valid JSON`);
    }
    if (!isChannelPolicyRecord(parsed)) {
        throw new TypeError(`stored value at ${key} is not a channel policy record`);
    }
    return parsed;
}
