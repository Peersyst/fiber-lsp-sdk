export class AgentRequestError extends Error {
    /**
     * Builds the refusal.
     * @param message What the driver reads in `error`.
     */
    constructor(message: string) {
        super(message);
        this.name = "AgentRequestError";
    }
}
