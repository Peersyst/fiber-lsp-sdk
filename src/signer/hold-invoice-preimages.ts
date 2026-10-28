import type { TlcHashAlgorithm } from "../common";
import { assertBytes, ckbBlake2b } from "../common";
import { MASTER_SEED_LENGTH, deriveHoldInvoicePreimage } from "../derivation";

export class HoldInvoicePreimages {
    readonly hashAlgorithm: TlcHashAlgorithm = "ckb-hash";

    readonly #masterSeed: Uint8Array;

    /**
     * Keeps a copy of the master seed.
     * @param masterSeed The master seed.
     */
    constructor(masterSeed: Uint8Array) {
        assertBytes("masterSeed", masterSeed, MASTER_SEED_LENGTH);
        this.#masterSeed = Uint8Array.from(masterSeed);
    }

    /**
     * Derives the preimage of the hold invoice of one index.
     * @param invoiceIndex The invoice index.
     * @returns The 32-byte preimage.
     */
    preimage(invoiceIndex: number): Uint8Array {
        return deriveHoldInvoicePreimage(this.#masterSeed, invoiceIndex);
    }

    /**
     * Computes the payment hash of the hold invoice of one index, under `hashAlgorithm`.
     * @param invoiceIndex The invoice index.
     * @returns The 32-byte payment hash.
     */
    paymentHash(invoiceIndex: number): Uint8Array {
        return ckbBlake2b(this.preimage(invoiceIndex));
    }
}
