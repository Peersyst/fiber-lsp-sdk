import type { ITimer } from "../../../src/session";

type Scheduled = { order: number; at: number; callback: () => void };

export class TimerMock implements ITimer {
    now = 0;

    ignoreCancel = false;

    readonly delays: number[] = [];

    private readonly scheduled: Scheduled[] = [];

    private nextOrder = 0;

    schedule(callback: () => void, delayMs: number): () => void {
        this.delays.push(delayMs);
        const entry: Scheduled = { order: this.nextOrder++, at: this.now + delayMs, callback };
        this.scheduled.push(entry);
        return () => {
            if (this.ignoreCancel) return;
            const index = this.scheduled.indexOf(entry);
            if (index >= 0) this.scheduled.splice(index, 1);
        };
    }

    get pending(): number {
        return this.scheduled.length;
    }

    advance(ms: number): void {
        const target = this.now + ms;
        for (;;) {
            const due = this.scheduled.filter((entry) => entry.at <= target).sort((a, b) => a.at - b.at || a.order - b.order);
            const next = due[0];
            if (!next) break;
            this.scheduled.splice(this.scheduled.indexOf(next), 1);
            this.now = Math.max(this.now, next.at);
            next.callback();
        }
        this.now = target;
    }
}
