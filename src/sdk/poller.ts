import type { ITimer } from "../session";
import { TimerSlot } from "../session";
import { SdkError } from "./sdk.error";
import type { SdkEvent } from "./sdk.types";
import { describeSdkFailure } from "./utils";

export type PollRun = {
    /**
     * True once the deadline passed or the poller stopped; a step checks it before every `emit` or `mark`.
     */
    readonly abandoned: boolean;
};

export type PollStep = (run: PollRun) => Promise<void>;

export type ActivityPollerOptions = {
    timer: ITimer;
    intervalMs: number;
    stepTimeoutMs: number;
    steps: readonly PollStep[];
    emit: (event: SdkEvent) => void;
};

export class ActivityPoller {
    private readonly timer: ITimer;

    private readonly slot: TimerSlot;

    private readonly intervalMs: number;

    private readonly stepTimeoutMs: number;

    private readonly steps: readonly PollStep[];

    private readonly emit: (event: SdkEvent) => void;

    private running = false;

    // Bumped by stop(): an older tick runs no further step and arms nothing.
    private generation = 0;

    private inFlight: { run: { abandoned: boolean }; release: () => void } | undefined;

    private ticking = false;

    private again = false;

    /**
     * Creates a poller; nothing runs until `start()`.
     * @param options The timer, the interval between ticks, a step's deadline, the steps of a tick and where a failure is reported.
     */
    constructor(options: ActivityPollerOptions) {
        this.timer = options.timer;
        this.slot = new TimerSlot(options.timer);
        this.intervalMs = options.intervalMs;
        this.stepTimeoutMs = options.stepTimeoutMs;
        this.steps = options.steps;
        this.emit = options.emit;
    }

    /**
     * Ticks now and then once per interval, measured from the end of each tick; a poller already running is left as it is.
     */
    start(): void {
        if (this.running) return;
        this.running = true;
        void this.tick();
    }

    /**
     * Stops ticking: the step in flight is abandoned and its tick ends at once, runs no further step and arms nothing.
     */
    stop(): void {
        this.running = false;
        this.again = false;
        this.generation += 1;
        const inFlight = this.inFlight;
        this.inFlight = undefined;
        if (inFlight) {
            inFlight.run.abandoned = true;
            inFlight.release();
        }
        this.slot.clear();
    }

    /**
     * Ticks now instead of at the interval, or once more right after the tick in flight; does nothing when stopped.
     */
    pollNow(): void {
        if (!this.running) return;
        if (this.ticking) {
            this.again = true;
            return;
        }
        this.slot.clear();
        void this.tick();
    }

    /**
     * Runs the steps in order, then arms the next tick, unless a stop() came in between.
     */
    private async tick(): Promise<void> {
        const generation = this.generation;
        this.ticking = true;
        for (const step of this.steps) {
            if (this.generation !== generation) return;
            try {
                await this.runStep(step);
            } catch (cause) {
                // A failure that settles across a stop() is the stopped tick's.
                if (this.generation === generation) this.report(cause);
            }
        }
        if (this.generation !== generation) return;
        this.ticking = false;
        if (this.again) {
            this.again = false;
            void this.tick();
            return;
        }
        try {
            this.slot.arm(() => void this.tick(), this.intervalMs);
        } catch (cause) {
            // A timer that throws ends the loop; start() resumes it.
            this.running = false;
            this.report(cause);
        }
    }

    /**
     * Runs one step against its deadline, so a call that never settles cannot hold the loop forever.
     * @param step The step.
     * @returns Settles with the step, at once on a stop(), or rejects once the deadline passes first.
     */
    private runStep(step: PollStep): Promise<void> {
        const run = { abandoned: false };
        return new Promise<void>((resolve, reject) => {
            /**
             * Settles the run, then cancels its deadline.
             * @param settle What settles the run.
             */
            const finish = (settle: () => void): void => {
                if (this.inFlight?.run === run) this.inFlight = undefined;
                settle();
                try {
                    cancel();
                } catch {
                    // A cancel that throws leaves a deadline that settles nothing.
                }
            };
            const cancel = this.timer.schedule(() => {
                run.abandoned = true;
                finish(() => reject(new Error(`the step did not settle within ${this.stepTimeoutMs} ms`)));
            }, this.stepTimeoutMs);
            this.inFlight = { run, release: () => finish(resolve) };
            let settling: Promise<void>;
            try {
                settling = step(run);
            } catch (cause) {
                settling = Promise.reject(cause);
            }
            settling.then(
                () => finish(resolve),
                (cause: unknown) => finish(() => reject(cause)),
            );
        });
    }

    /**
     * Reports a step's failure as a `poll_failed` error; an emitter that throws never breaks the loop.
     * @param cause What the step threw.
     */
    private report(cause: unknown): void {
        const error = new SdkError("poll_failed", describeSdkFailure("a poll of the node failed", cause), { cause });
        try {
            this.emit({ type: "ERROR", error });
        } catch {
            // The emitter's failure is the host's.
        }
    }
}
