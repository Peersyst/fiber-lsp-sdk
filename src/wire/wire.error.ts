export class WireError extends Error {
    readonly path: string;

    readonly reason: string;

    /**
     * Creates a decode refusal.
     * @param path Path of the field that failed, the only thing a refusal names.
     * @param reason What the field had to be, never what it was.
     */
    constructor(path: string, reason: string) {
        super(`${path} ${reason}`);
        this.name = "WireError";
        this.path = path;
        this.reason = reason;
    }
}
