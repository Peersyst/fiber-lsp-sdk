import type { ISignerStorage } from "@peersyst/fiber-lsp-sdk";
import { AgentRequestError } from "./agent.error";
import { readJsonObject } from "./agent.utils";

// The SDK's policy records, as `src/policy` keys and writes them: the facade records a debit intent only inside `transfer`,
// which sends the payment itself, and a driver's `Payment` precedes a `send_payment` the driver makes.
const DEBIT_INTENT_KEY_PREFIX = "fiber-lsp-sdk:intent:";
const HOLD_INVOICE_KEY_PREFIX = "fiber-lsp-sdk:invoice:";
const PAYMENT_RECORD_VERSION = 1;

// Records are keyed by the first 20 bytes of the hash, what a settlement witness binds.
const BOUND_PAYMENT_HASH_HEX_LENGTH = 40;

/**
 * Tells whether a stored debit intent is the open one this payment would record, untouched by any TLC.
 * @param raw The stored record.
 * @param paymentHash The payment hash, bare lowercase hex.
 * @param maxShannons The budget, decimal shannons.
 * @returns Whether it is.
 */
function isSameOpenIntent(raw: string, paymentHash: string, maxShannons: string): boolean {
    let record: Record<string, unknown>;
    try {
        record = readJsonObject(JSON.parse(raw), "the debit intent");
    } catch {
        return false;
    }
    const { channelIndexes } = record;
    return (
        record.version === PAYMENT_RECORD_VERSION &&
        record.paymentHash === paymentHash &&
        record.maxShannons === maxShannons &&
        record.open === true &&
        Array.isArray(channelIndexes) &&
        channelIndexes.length === 0
    );
}

/**
 * Reads the payment hash a stored payment record names.
 * @param raw The stored record.
 * @returns The hash, or `null` when the record names none.
 */
function storedPaymentHash(raw: string): string | null {
    try {
        const { paymentHash } = readJsonObject(JSON.parse(raw), "the payment record");
        return typeof paymentHash === "string" ? paymentHash : null;
    } catch {
        return null;
    }
}

/**
 * Records the SDK's open debit intent for a payment the driver sends, so the device signs its offered TLC within the budget.
 * @param storage The SDK's storage, written before the payment is sent, so no step of the SDK holds the key meanwhile.
 * @param paymentHash The payment hash, 32 bytes of `0x`-prefixed lowercase hex.
 * @param maxShannons What the payment may take, the routing fee budget included, decimal shannons.
 */
export function recordAgentDebitIntent(storage: ISignerStorage, paymentHash: string, maxShannons: string): void {
    const bareHash = paymentHash.slice(2);
    const boundHash = bareHash.slice(0, BOUND_PAYMENT_HASH_HEX_LENGTH);
    // As the SDK's `recordDebitIntent`: a twin's invoice binds another payment, and the balance rule would read the device's
    // own hash both as a payment out and as an invoice.
    const invoice = storage.get(HOLD_INVOICE_KEY_PREFIX + boundHash);
    if (invoice !== null) {
        const invoiceHash = storedPaymentHash(invoice);
        if (invoiceHash !== null && invoiceHash !== bareHash) {
            throw new AgentRequestError(`the 20 bytes of ${paymentHash} a TLC's witness binds are another payment's`);
        }
        throw new AgentRequestError(`${paymentHash} is the hash of a hold invoice of this device`);
    }
    const key = DEBIT_INTENT_KEY_PREFIX + boundHash;
    const current = storage.get(key);
    if (current !== null) {
        // The one this call wrote before a crash kept `agent.json` from recording the payment.
        if (isSameOpenIntent(current, bareHash, maxShannons)) return;
        throw new AgentRequestError(`the SDK already holds a debit intent under the bound hash of ${paymentHash}`);
    }
    const record = { version: PAYMENT_RECORD_VERSION, paymentHash: bareHash, maxShannons, open: true, channelIndexes: [] };
    storage.set(key, JSON.stringify(record));
}
