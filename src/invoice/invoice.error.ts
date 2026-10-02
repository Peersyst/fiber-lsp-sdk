export class InvoiceError extends Error {
    readonly path: string;

    readonly reason: string;

    /**
     * Creates a refusal of an invoice string.
     * @param path What was refused: a layer of the string, or a field inside its data.
     * @param reason What it had to be, never what it was.
     */
    constructor(path: string, reason: string) {
        super(`${path} ${reason}`);
        this.name = "InvoiceError";
        this.path = path;
        this.reason = reason;
    }
}

/**
 * Refuses an invoice string, ending the decode wherever it is.
 * @param path What was refused.
 * @param reason What it had to be.
 */
export function refuseInvoice(path: string, reason: string): never {
    throw new InvoiceError(path, reason);
}
