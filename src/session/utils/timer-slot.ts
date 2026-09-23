import type { ITimer } from "../interfaces";

export class TimerSlot {
    private readonly timer: ITimer;

    private cancel: (() => void) | undefined;

    private arming = 0;

    /**
     * Creates a slot that holds at most one scheduled callback.
     * @param timer The host's timer.
     */
    constructor(timer: ITimer) {
        this.timer = timer;
    }

    /**
     * Schedules a callback in place of the held one, which never runs even if its cancel is ignored.
     * @param callback What to run.
     * @param delayMs Delay in milliseconds.
     */
    arm(callback: () => void, delayMs: number): void {
        this.clear();
        const arming = this.arming;
        this.cancel = this.timer.schedule(() => {
            if (this.arming !== arming) return;
            this.cancel = undefined;
            callback();
        }, delayMs);
    }

    /**
     * Drops whatever the slot held.
     */
    clear(): void {
        this.arming += 1;
        this.cancel?.();
        this.cancel = undefined;
    }
}
