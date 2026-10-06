import {
    PAYMENT_HASH_LENGTH,
    PREIMAGE_LENGTH,
    TRUNCATED_PAYMENT_HASH_LENGTH,
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
    BALANCE_LANE_KEY,
    CHANNEL_ALIAS_KEY_PREFIX,
    CHANNEL_RECORD_KEY_PREFIX,
    DEBIT_INTENT_KEY_PREFIX,
    HOLD_INVOICE_PREIMAGE_KEY_PREFIX,
    HOLD_INVOICE_RECORD_KEY_PREFIX,
} from "./policy.constants";
import type { ChannelPolicyRecord, DebitIntentRecord, HoldInvoicePolicyRecord } from "./policy.types";
import {
    assertChannelPolicyRecord,
    assertDebitIntentRecord,
    assertHoldInvoicePolicyRecord,
    boundPaymentHashOf,
    isChannelPolicyRecord,
    isDebitIntentRecord,
    isHoldInvoicePolicyRecord,
} from "./utils";

type RecordFormat<T> = {
    name: string;
    is: (value: unknown) => value is T;
    assert: (name: string, value: unknown) => asserts value is T;
    /**
     * Whether the record agrees with the key it is stored under.
     */
    belongsAt: (key: string, record: T) => boolean;
};

const CHANNEL_RECORD_FORMAT: RecordFormat<ChannelPolicyRecord> = {
    name: "channel policy record",
    is: isChannelPolicyRecord,
    assert: assertChannelPolicyRecord,
    belongsAt: () => true,
};

const DEBIT_INTENT_FORMAT: RecordFormat<DebitIntentRecord> = {
    name: "debit intent record",
    is: isDebitIntentRecord,
    assert: assertDebitIntentRecord,
    belongsAt: (key, record) => key === DEBIT_INTENT_KEY_PREFIX + boundPaymentHashOf(record.paymentHash),
};

const HOLD_INVOICE_FORMAT: RecordFormat<HoldInvoicePolicyRecord> = {
    name: "hold invoice record",
    is: isHoldInvoicePolicyRecord,
    assert: assertHoldInvoicePolicyRecord,
    belongsAt: (key, record) => key === HOLD_INVOICE_RECORD_KEY_PREFIX + boundPaymentHashOf(record.paymentHash),
};

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
        return this.serialize(key, () => this.readRecord(key, CHANNEL_RECORD_FORMAT));
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
        await this.serialize(key, () => this.writeRecord(key, record));
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
        return this.updateRecord(CHANNEL_RECORD_KEY_PREFIX + channelIndex, CHANNEL_RECORD_FORMAT, update);
    }

    /**
     * Reads the debit intent filed under a payment hash.
     * @param boundPaymentHashHex The first 20 bytes of the payment hash, lowercase hex.
     * @returns The intent, or `null` if none was ever recorded.
     */
    async getDebitIntent(boundPaymentHashHex: string): Promise<DebitIntentRecord | null> {
        assertHexBytes("boundPaymentHashHex", boundPaymentHashHex, TRUNCATED_PAYMENT_HASH_LENGTH);
        const key = DEBIT_INTENT_KEY_PREFIX + boundPaymentHashHex;
        return this.serialize(key, () => this.readRecord(key, DEBIT_INTENT_FORMAT));
    }

    /**
     * Reads, updates and writes the debit intent filed under a payment hash as one step.
     * @param boundPaymentHashHex The first 20 bytes of the payment hash, lowercase hex.
     * @param update Synchronous updater; handing back the record it was given skips the write.
     * @returns The intent the key now holds.
     */
    async updateDebitIntent(
        boundPaymentHashHex: string,
        update: (current: DebitIntentRecord | null) => DebitIntentRecord,
    ): Promise<DebitIntentRecord> {
        assertHexBytes("boundPaymentHashHex", boundPaymentHashHex, TRUNCATED_PAYMENT_HASH_LENGTH);
        return this.updateRecord(DEBIT_INTENT_KEY_PREFIX + boundPaymentHashHex, DEBIT_INTENT_FORMAT, update);
    }

    /**
     * Reads the hold invoice record filed under a payment hash.
     * @param boundPaymentHashHex The first 20 bytes of the payment hash, lowercase hex.
     * @returns The record, or `null` if none was ever written.
     */
    async getHoldInvoiceRecord(boundPaymentHashHex: string): Promise<HoldInvoicePolicyRecord | null> {
        assertHexBytes("boundPaymentHashHex", boundPaymentHashHex, TRUNCATED_PAYMENT_HASH_LENGTH);
        const key = HOLD_INVOICE_RECORD_KEY_PREFIX + boundPaymentHashHex;
        return this.serialize(key, () => this.readRecord(key, HOLD_INVOICE_FORMAT));
    }

    /**
     * Reads, updates and writes the hold invoice record filed under a payment hash as one step.
     * @param boundPaymentHashHex The first 20 bytes of the payment hash, lowercase hex.
     * @param update Synchronous updater; handing back the record it was given skips the write.
     * @returns The record the key now holds.
     */
    async updateHoldInvoiceRecord(
        boundPaymentHashHex: string,
        update: (current: HoldInvoicePolicyRecord | null) => HoldInvoicePolicyRecord,
    ): Promise<HoldInvoicePolicyRecord> {
        assertHexBytes("boundPaymentHashHex", boundPaymentHashHex, TRUNCATED_PAYMENT_HASH_LENGTH);
        return this.updateRecord(HOLD_INVOICE_RECORD_KEY_PREFIX + boundPaymentHashHex, HOLD_INVOICE_FORMAT, update);
    }

    /**
     * Runs an operation alone in the balance lane.
     * @param operation Operation to run once the lane is free.
     * @returns Whatever the operation returned.
     */
    async withBalanceLock<T>(operation: () => Promise<T>): Promise<T> {
        return this.serialize(BALANCE_LANE_KEY, operation);
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
     * @param format The kind of record the key holds.
     * @returns The record, or `null` if the key was never written.
     */
    private async readRecord<T>(key: string, format: RecordFormat<T>): Promise<T | null> {
        const raw = (await this.storage.get(key)) ?? null;
        if (raw === null) return null;
        // Corruption must throw: a record read as absent would re-open sign-once slots or forget charges.
        return parseRecord(key, raw, format);
    }

    /**
     * Reads, updates and writes the record at a storage key as one step.
     * @param key Storage key of the record.
     * @param format The kind of record the key holds.
     * @param update Synchronous updater; handing back the record it was given skips the write.
     * @returns The record the key now holds.
     */
    private async updateRecord<T>(key: string, format: RecordFormat<T>, update: (current: T | null) => T): Promise<T> {
        return this.serialize(key, async () => {
            const current = await this.readRecord(key, format);
            const next = update(current);
            if (next === current) return next;
            format.assert("updated record", next);
            if (!format.belongsAt(key, next)) throw new TypeError(`updated record does not belong at ${key}`);
            await this.writeRecord(key, next);
            return next;
        });
    }

    /**
     * Serializes a record into the storage key that holds it.
     * @param key Storage key to write.
     * @param record Record to persist.
     */
    private async writeRecord(key: string, record: unknown): Promise<void> {
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
 * Parses a stored record, refusing anything the storage returns that is not one, or not the one its key names.
 * @param key Storage key the value came from, used in the error message.
 * @param raw Raw string read from storage.
 * @param format The kind of record the key holds.
 * @returns The parsed record.
 */
function parseRecord<T>(key: string, raw: string, format: RecordFormat<T>): T {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw new TypeError(`stored value at ${key} is not valid JSON`);
    }
    if (!format.is(parsed) || !format.belongsAt(key, parsed)) {
        throw new TypeError(`stored value at ${key} is not a ${format.name}`);
    }
    return parsed;
}
