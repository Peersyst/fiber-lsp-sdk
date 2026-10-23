import type { Transaction } from "../common";
import { ckbBlake2b } from "../common";
import { serializeRawTransaction } from "./tx-message";

/**
 * Port of CKB's `calc_tx_hash`: the CKB blake2b of the raw tx, cell deps included.
 * @param tx The tx.
 * @returns The 32-byte tx hash.
 */
export function computeTxHash(tx: Transaction): Uint8Array {
    return ckbBlake2b(serializeRawTransaction(tx, true));
}
