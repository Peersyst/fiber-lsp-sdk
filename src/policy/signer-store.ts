import { PAYMENT_HASH_LENGTH, PREIMAGE_LENGTH, assertHexBytes, assertNonEmptyString, isHexBytes } from "../common";
import type { IAsyncSignerStorage, ISignerStorage } from "./interfaces";
import { CHANNEL_RECORD_KEY_PREFIX, HOLD_INVOICE_PREIMAGE_KEY_PREFIX } from "./policy.constants";
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
     * Reads a channel's policy record.
     * @param channelId Channel identifier the record is keyed by.
     * @returns The record, or `null` for a channel this device never registered.
     */
    async getChannelRecord(channelId: string): Promise<ChannelPolicyRecord | null> {
        assertNonEmptyString("channelId", channelId);
        const key = CHANNEL_RECORD_KEY_PREFIX + channelId;
        return this.serialize(key, () => this.readChannelRecord(key));
    }

    /**
     * Writes a channel's policy record, overwriting any previous one.
     * @param channelId Channel identifier the record is keyed by.
     * @param record Record to persist.
     */
    async setChannelRecord(channelId: string, record: ChannelPolicyRecord): Promise<void> {
        assertNonEmptyString("channelId", channelId);
        assertChannelPolicyRecord("record", record);
        const key = CHANNEL_RECORD_KEY_PREFIX + channelId;
        await this.serialize(key, () => this.writeChannelRecord(key, record));
    }

    /**
     * Reads, updates and writes a channel's record as one step no concurrent call on the same channel can interleave with.
     * @param channelId Channel identifier the record is keyed by.
     * @param update Synchronous updater over the stored record, or over `null` for an unregistered channel.
     * @returns The record that was written.
     */
    async updateChannelRecord(
        channelId: string,
        update: (current: ChannelPolicyRecord | null) => ChannelPolicyRecord,
    ): Promise<ChannelPolicyRecord> {
        assertNonEmptyString("channelId", channelId);
        const key = CHANNEL_RECORD_KEY_PREFIX + channelId;
        return this.serialize(key, async () => {
            const current = await this.readChannelRecord(key);
            const next = update(current);
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
