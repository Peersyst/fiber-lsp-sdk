export class CoalescingTask {
    private running: Promise<void> | null = null;

    private pending = false;

    /**
     * Wraps the task, which reports its own failures: one that throws ends the runs queued behind it.
     * @param task The task.
     */
    constructor(private readonly task: () => Promise<void>) {}

    /**
     * Asks for a run that starts after this call.
     * @returns Settles once such a run ended.
     */
    run(): Promise<void> {
        this.pending = true;
        this.running ??= this.loop();
        return this.running;
    }

    /**
     * Runs the task while a run is asked for.
     * @returns Settles once no run is asked for.
     */
    private async loop(): Promise<void> {
        try {
            while (this.pending) {
                this.pending = false;
                await this.task();
            }
        } finally {
            this.running = null;
        }
    }
}
