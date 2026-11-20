import { PAYMENT_HASH_LENGTH, assertHexBytes } from "../common";
import type { SignerRecordFormat, SignerStore } from "../policy";
import { PAYMENT_HISTORY_INDEX_KEY, PAYMENT_HISTORY_RECORD_KEY_PREFIX } from "./sdk.constants";
import type { PaymentHistoryIndex, StoredPaymentRecord } from "./sdk.types";
import {
    assertPaymentHistoryIndex,
    assertStoredPaymentRecord,
    emptyPaymentHistoryIndex,
    isPaymentHistoryIndex,
    isStoredPaymentRecord,
    placeInPaymentHistoryIndex,
} from "./utils";

const PAYMENT_RECORD_FORMAT: SignerRecordFormat<StoredPaymentRecord> = {
    name: "payment record",
    is: isStoredPaymentRecord,
    assert: assertStoredPaymentRecord,
    belongsAt: (key, record) => key === PAYMENT_HISTORY_RECORD_KEY_PREFIX + record.paymentHashHex.slice(2),
};

const PAYMENT_HISTORY_INDEX_FORMAT: SignerRecordFormat<PaymentHistoryIndex> = {
    name: "payment history index",
    is: isPaymentHistoryIndex,
    assert: assertPaymentHistoryIndex,
    belongsAt: () => true,
};

export class PaymentHistory {
    private readonly store: SignerStore;

    /**
     * Creates the history over the store.
     * @param store Typed persistence the history is kept in.
     */
    constructor(store: SignerStore) {
        this.store = store;
    }

    /**
     * Reads one payment's record.
     * @param paymentHash The payment hash, lowercase hex.
     * @returns The record, or `null` when the history holds none.
     */
    async read(paymentHash: string): Promise<StoredPaymentRecord | null> {
        return this.store.getRecord(recordKey(paymentHash), PAYMENT_RECORD_FORMAT);
    }

    /**
     * Reads a page of the history, newest first.
     * @param limit The most records the page holds.
     * @param offset The records skipped before it.
     * @returns The page.
     */
    async list(limit: number, offset: number): Promise<StoredPaymentRecord[]> {
        const index = (await this.store.getRecord(PAYMENT_HISTORY_INDEX_KEY, PAYMENT_HISTORY_INDEX_FORMAT)) ?? emptyPaymentHistoryIndex();
        const page = index.entries.slice(offset, offset + limit);
        return Promise.all(
            page.map(async ({ paymentHash }) => {
                const record = await this.read(paymentHash);
                if (record === null) throw new TypeError(`the payment history lists 0x${paymentHash}, whose record is missing`);
                return record;
            }),
        );
    }

    /**
     * Rewrites one payment's record as one step in its lane, then places it in the index; nothing is ever deleted.
     * @param paymentHash The payment hash, lowercase hex.
     * @param update Synchronous updater; handing back the record it was given writes no record.
     * @returns The record the history now holds, `null` when it held none and still does not.
     */
    async update(
        paymentHash: string,
        update: (current: StoredPaymentRecord | null) => StoredPaymentRecord | null,
    ): Promise<StoredPaymentRecord | null> {
        const record = await this.store.updateRecord(recordKey(paymentHash), PAYMENT_RECORD_FORMAT, update);
        if (record === null) return null;
        // After the record: a stop in between leaves it out of the index until its next write, never an entry without a record.
        await this.store.updateRecord(PAYMENT_HISTORY_INDEX_KEY, PAYMENT_HISTORY_INDEX_FORMAT, (index) =>
            placeInPaymentHistoryIndex(index, { paymentHash, createdAtMs: record.createdAtMs }),
        );
        return record;
    }
}

/**
 * Names the key of a payment's record, refusing a hash of another form.
 * @param paymentHash The payment hash, lowercase hex.
 * @returns The key.
 */
function recordKey(paymentHash: string): string {
    assertHexBytes("paymentHash", paymentHash, PAYMENT_HASH_LENGTH);
    return PAYMENT_HISTORY_RECORD_KEY_PREFIX + paymentHash;
}
