import type { ActivityPollerOptions, PollRun, PollStep, SdkEvent } from "../../../src/sdk";
import { ActivityPoller, SdkError } from "../../../src/sdk";
import { TimerMock } from "../../mocks/session";
import { flush } from "../../utils/flush";

const INTERVAL_MS = 7_000;
const STEP_TIMEOUT_MS = 60_000;

type Held = { release: () => void; fail: (cause: unknown) => void };

function harness(steps: PollStep[], overrides: Partial<ActivityPollerOptions> = {}) {
    const timer = new TimerMock();
    const events: SdkEvent[] = [];
    const poller = new ActivityPoller({
        timer,
        intervalMs: INTERVAL_MS,
        stepTimeoutMs: STEP_TIMEOUT_MS,
        steps,
        emit: (event) => events.push(event),
        ...overrides,
    });
    const errors = (): SdkError[] => events.flatMap((event) => (event.type === "ERROR" ? [event.error] : []));
    // Intervals only: the steps' deadlines have specs of their own.
    const intervals = (): number[] => timer.delays.filter((delay) => delay !== STEP_TIMEOUT_MS);
    const armed = (): number => timer.pendingDelays.filter((delay) => delay !== STEP_TIMEOUT_MS).length;
    return { poller, timer, events, errors, intervals, armed };
}

function recording(log: string[], name: string): PollStep {
    return async () => {
        log.push(name);
    };
}

function holding(log: string[], name: string): { step: PollStep; held: Held[] } {
    const held: Held[] = [];
    const step: PollStep = () =>
        new Promise<void>((resolve, reject) => {
            log.push(`${name} started`);
            held.push({
                release: () => {
                    log.push(`${name} done`);
                    resolve();
                },
                fail: reject,
            });
        });
    return { step, held };
}

describe("ActivityPoller", () => {
    describe("start", () => {
        it("ticks at once, running the steps in order, then arms the interval", async () => {
            const log: string[] = [];
            const h = harness([recording(log, "channels"), recording(log, "payments"), recording(log, "invoices")]);
            h.poller.start();
            expect(log).toEqual(["channels"]);
            await flush();
            expect(log).toEqual(["channels", "payments", "invoices"]);
            expect(h.intervals()).toEqual([INTERVAL_MS]);
            expect(h.armed()).toBe(1);
        });

        it("ticks again when the interval elapses, and arms the next one after", async () => {
            const log: string[] = [];
            const h = harness([recording(log, "tick")]);
            h.poller.start();
            await flush();
            h.timer.advance(INTERVAL_MS - 1);
            expect(log).toEqual(["tick"]);
            h.timer.advance(1);
            await flush();
            expect(log).toEqual(["tick", "tick"]);
            expect(h.intervals()).toEqual([INTERVAL_MS, INTERVAL_MS]);
            h.timer.advance(INTERVAL_MS);
            await flush();
            expect(log).toEqual(["tick", "tick", "tick"]);
        });

        it("runs one step at a time: the next starts once the current has settled", async () => {
            const log: string[] = [];
            const first = holding(log, "first");
            const h = harness([first.step, recording(log, "second")]);
            h.poller.start();
            await flush();
            expect(log).toEqual(["first started"]);
            expect(h.armed()).toBe(0);
            first.held[0]?.release();
            await flush();
            expect(log).toEqual(["first started", "first done", "second"]);
        });

        it("measures the interval from the end of the tick, not its start", async () => {
            const log: string[] = [];
            const step = holding(log, "slow");
            const h = harness([step.step]);
            h.poller.start();
            h.timer.advance(INTERVAL_MS * 3);
            await flush();
            expect(h.intervals()).toEqual([]);
            step.held[0]?.release();
            await flush();
            expect(h.intervals()).toEqual([INTERVAL_MS]);
            expect(log).toEqual(["slow started", "slow done"]);
        });

        it("does nothing when already running, during a tick and between two", async () => {
            const log: string[] = [];
            const h = harness([recording(log, "tick")]);
            h.poller.start();
            h.poller.start();
            await flush();
            expect(log).toEqual(["tick"]);
            h.poller.start();
            await flush();
            expect(log).toEqual(["tick"]);
            expect(h.intervals()).toEqual([INTERVAL_MS]);
            expect(h.armed()).toBe(1);
        });

        it("ticks with no steps at all, arming the interval", async () => {
            const h = harness([]);
            h.poller.start();
            await flush();
            expect(h.intervals()).toEqual([INTERVAL_MS]);
            expect(h.events).toEqual([]);
        });
    });

    describe("failures", () => {
        it("reports a failing step as a poll_failed error carrying the cause, and runs the next step", async () => {
            const log: string[] = [];
            const cause = new Error("node is syncing");
            const h = harness([
                recording(log, "first"),
                async () => {
                    log.push("second");
                    throw cause;
                },
                recording(log, "third"),
            ]);
            h.poller.start();
            await flush();
            expect(log).toEqual(["first", "second", "third"]);
            expect(h.errors()).toHaveLength(1);
            const error = h.errors()[0];
            expect(error).toBeInstanceOf(SdkError);
            expect(error?.code).toBe("poll_failed");
            expect(error?.message).toBe("a poll of the node failed: node is syncing");
            expect(error?.cause).toBe(cause);
            expect(h.events.map((event) => event.type)).toEqual(["ERROR"]);
        });

        it("reports a step that throws synchronously the same way", async () => {
            const h = harness([
                () => {
                    throw new TypeError("stored value at fiber-lsp-sdk:activity is not valid JSON");
                },
            ]);
            h.poller.start();
            await flush();
            expect(h.errors().map((error) => error.message)).toEqual([
                "a poll of the node failed: stored value at fiber-lsp-sdk:activity is not valid JSON",
            ]);
        });

        it("reports a cause that is not an error without detail", async () => {
            const h = harness([() => Promise.reject("boom")]);
            h.poller.start();
            await flush();
            expect(h.errors()[0]?.message).toBe("a poll of the node failed");
            expect(h.errors()[0]?.cause).toBe("boom");
        });

        it("still arms the next tick after a failure, and reports every tick's failure", async () => {
            const h = harness([() => Promise.reject(new Error("down"))]);
            h.poller.start();
            await flush();
            expect(h.intervals()).toEqual([INTERVAL_MS]);
            h.timer.advance(INTERVAL_MS);
            await flush();
            expect(h.errors()).toHaveLength(2);
            expect(h.intervals()).toEqual([INTERVAL_MS, INTERVAL_MS]);
        });

        it("keeps the loop when the emitter throws", async () => {
            const log: string[] = [];
            const h = harness([() => Promise.reject(new Error("down")), recording(log, "second")], {
                emit: () => {
                    throw new Error("listener broke");
                },
            });
            h.poller.start();
            await flush();
            expect(log).toEqual(["second"]);
            expect(h.intervals()).toEqual([INTERVAL_MS]);
        });
    });

    describe("a step's deadline", () => {
        it("reports a step that never settles once its deadline passes, and moves the tick on", async () => {
            const log: string[] = [];
            const hung = holding(log, "hung");
            const h = harness([hung.step, recording(log, "next")]);
            h.poller.start();
            await flush();
            expect(h.timer.pendingDelays).toEqual([STEP_TIMEOUT_MS]);
            h.timer.advance(STEP_TIMEOUT_MS - 1);
            await flush();
            expect(log).toEqual(["hung started"]);
            expect(h.errors()).toEqual([]);
            h.timer.advance(1);
            await flush();
            expect(log).toEqual(["hung started", "next"]);
            expect(h.errors()).toHaveLength(1);
            expect(h.errors()[0]?.code).toBe("poll_failed");
            expect(h.errors()[0]?.message).toBe(`a poll of the node failed: the step did not settle within ${STEP_TIMEOUT_MS} ms`);
            expect(h.timer.pendingDelays).toEqual([INTERVAL_MS]);
        });

        it("starts a fresh tick on a stop() and a start() while a step hangs, without waiting out its deadline", async () => {
            const log: string[] = [];
            const hung = holding(log, "hung");
            const h = harness([hung.step]);
            h.poller.start();
            await flush();
            h.poller.stop();
            h.poller.start();
            await flush();
            expect(log).toEqual(["hung started", "hung started"]);
            expect(h.timer.pendingDelays).toEqual([STEP_TIMEOUT_MS]);
            expect(h.errors()).toEqual([]);
        });

        it("tells a step past its deadline that its run is abandoned, and the next tick's run that it is not", async () => {
            const runs: PollRun[] = [];
            const held: (() => void)[] = [];
            const h = harness([
                (run) => {
                    runs.push(run);
                    return new Promise<void>((resolve) => held.push(resolve));
                },
            ]);
            h.poller.start();
            await flush();
            expect(runs.map((run) => run.abandoned)).toEqual([false]);
            h.timer.advance(STEP_TIMEOUT_MS);
            await flush();
            expect(runs.map((run) => run.abandoned)).toEqual([true]);
            h.timer.advance(INTERVAL_MS);
            await flush();
            expect(runs.map((run) => run.abandoned)).toEqual([true, false]);
            held[0]?.();
            held[1]?.();
            await flush();
            expect(runs.map((run) => run.abandoned)).toEqual([true, false]);
        });

        it("abandons the run in flight on stop(), and only that one", async () => {
            const runs: PollRun[] = [];
            const held: (() => void)[] = [];
            const h = harness([
                async (run) => {
                    runs.push(run);
                },
                (run) => {
                    runs.push(run);
                    return new Promise<void>((resolve) => held.push(resolve));
                },
            ]);
            h.poller.start();
            await flush();
            h.poller.stop();
            expect(runs.map((run) => run.abandoned)).toEqual([false, true]);
            held[0]?.();
            await flush();
            expect(h.errors()).toEqual([]);
        });

        it("still abandons the run in flight on stop() after an earlier run settled past its deadline", async () => {
            const runs: PollRun[] = [];
            const held: (() => void)[] = [];
            const h = harness([
                () => new Promise<void>((resolve) => held.push(resolve)),
                (run) => {
                    runs.push(run);
                    return new Promise<void>(() => undefined);
                },
            ]);
            h.poller.start();
            await flush();
            h.timer.advance(STEP_TIMEOUT_MS);
            await flush();
            expect(runs.map((run) => run.abandoned)).toEqual([false]);
            held[0]?.();
            await flush();
            h.poller.stop();
            expect(runs.map((run) => run.abandoned)).toEqual([true]);
        });

        it("keeps polling across a stop() whose host cancel throws, which it swallows, and a start()", async () => {
            const log: string[] = [];
            const timer = new TimerMock();
            const throwing = {
                schedule: (callback: () => void, delayMs: number) => {
                    const cancel = timer.schedule(callback, delayMs);
                    if (delayMs !== INTERVAL_MS) return cancel;
                    return () => {
                        cancel();
                        throw new Error("cancel broke");
                    };
                },
            };
            const h = harness([recording(log, "tick")], { timer: throwing });
            h.poller.start();
            await flush();
            expect(() => h.poller.stop()).not.toThrow();
            h.poller.start();
            await flush();
            expect(log).toEqual(["tick", "tick"]);
            expect(h.errors()).toEqual([]);
            expect(timer.pendingDelays).toEqual([INTERVAL_MS]);
        });

        it("survives a host cancel that throws: the step settles on time and the loop carries on", async () => {
            const log: string[] = [];
            const timer = new TimerMock();
            const throwingCancel = {
                schedule: (callback: () => void, delayMs: number) => {
                    const cancel = timer.schedule(callback, delayMs);
                    if (delayMs !== STEP_TIMEOUT_MS) return cancel;
                    return () => {
                        cancel();
                        throw new Error("cancel broke");
                    };
                },
            };
            const h = harness([recording(log, "first"), recording(log, "second")], { timer: throwingCancel });
            h.poller.start();
            await flush();
            expect(log).toEqual(["first", "second"]);
            expect(h.errors()).toEqual([]);
            expect(timer.pendingDelays).toEqual([INTERVAL_MS]);
        });

        it("cancels the deadline of a step that settles, and of one that fails, in time", async () => {
            const log: string[] = [];
            const h = harness([
                recording(log, "ok"),
                async () => {
                    throw new Error("node down");
                },
            ]);
            h.poller.start();
            await flush();
            expect(h.timer.pendingDelays).toEqual([INTERVAL_MS]);
            expect(h.errors().map((error) => error.message)).toEqual(["a poll of the node failed: node down"]);
        });

        it("reports a step that throws synchronously, without waiting for its deadline", async () => {
            const cause = new Error("bad step");
            const h = harness([
                () => {
                    throw cause;
                },
            ]);
            h.poller.start();
            await flush();
            expect(h.errors()[0]?.cause).toBe(cause);
            expect(h.timer.pendingDelays).toEqual([INTERVAL_MS]);
        });
    });

    describe("a host timer that throws", () => {
        it("reports the failure, stops the loop instead of rejecting, and resumes on start()", async () => {
            const log: string[] = [];
            const cause = new Error("timer broke");
            let broken = true;
            const timer = new TimerMock();
            const flaky = {
                schedule: (callback: () => void, delayMs: number) => {
                    if (broken && delayMs === INTERVAL_MS) throw cause;
                    return timer.schedule(callback, delayMs);
                },
            };
            const h = harness([recording(log, "tick")], { timer: flaky });
            h.poller.start();
            await flush();
            expect(log).toEqual(["tick"]);
            expect(h.errors()).toHaveLength(1);
            expect(h.errors()[0]?.code).toBe("poll_failed");
            expect(h.errors()[0]?.cause).toBe(cause);
            h.poller.pollNow();
            await flush();
            expect(log).toEqual(["tick"]);
            broken = false;
            h.poller.start();
            await flush();
            expect(log).toEqual(["tick", "tick"]);
            expect(timer.delays.filter((delay) => delay === INTERVAL_MS)).toEqual([INTERVAL_MS]);
        });
    });

    describe("stop", () => {
        it("cancels the armed interval, so no tick follows", async () => {
            const log: string[] = [];
            const h = harness([recording(log, "tick")]);
            h.poller.start();
            await flush();
            h.poller.stop();
            expect(h.armed()).toBe(0);
            h.timer.advance(INTERVAL_MS * 2);
            await flush();
            expect(log).toEqual(["tick"]);
        });

        it("abandons the step in flight, runs no further step and arms nothing", async () => {
            const log: string[] = [];
            const first = holding(log, "first");
            const h = harness([first.step, recording(log, "second")]);
            h.poller.start();
            await flush();
            h.poller.stop();
            first.held[0]?.release();
            await flush();
            expect(log).toEqual(["first started", "first done"]);
            expect(h.armed()).toBe(0);
            expect(h.intervals()).toEqual([]);
        });

        it("is a no-op when not running", () => {
            const h = harness([]);
            expect(() => h.poller.stop()).not.toThrow();
            h.poller.start();
            h.poller.stop();
            expect(() => h.poller.stop()).not.toThrow();
            expect(h.armed()).toBe(0);
        });

        it("ignores a stale tick from a timer whose cancel does nothing", async () => {
            const log: string[] = [];
            const h = harness([recording(log, "tick")]);
            h.timer.ignoreCancel = true;
            h.poller.start();
            await flush();
            h.poller.stop();
            h.timer.advance(INTERVAL_MS);
            await flush();
            expect(log).toEqual(["tick"]);
        });
    });

    describe("start after stop", () => {
        it("ticks at once again", async () => {
            const log: string[] = [];
            const h = harness([recording(log, "tick")]);
            h.poller.start();
            await flush();
            h.poller.stop();
            h.poller.start();
            await flush();
            expect(log).toEqual(["tick", "tick"]);
            expect(h.armed()).toBe(1);
        });

        it("ends the stopped tick at once and starts a fresh one, which alone runs the later steps and arms", async () => {
            const log: string[] = [];
            const first = holding(log, "first");
            const h = harness([first.step, recording(log, "second")]);
            h.poller.start();
            await flush();
            h.poller.stop();
            h.poller.start();
            await flush();
            expect(log).toEqual(["first started", "first started"]);
            first.held[0]?.release();
            await flush();
            expect(log).toEqual(["first started", "first started", "first done"]);
            expect(h.armed()).toBe(0);
            first.held[1]?.release();
            await flush();
            expect(log).toEqual(["first started", "first started", "first done", "first done", "second"]);
            expect(h.intervals()).toEqual([INTERVAL_MS]);
            expect(h.armed()).toBe(1);
        });

        it("keeps one tick at a time: an extra tick asked after the restart queues behind the fresh one", async () => {
            const log: string[] = [];
            const first = holding(log, "first");
            const h = harness([first.step]);
            h.poller.start();
            await flush();
            h.poller.stop();
            h.poller.start();
            await flush();
            first.held[0]?.release();
            await flush();
            h.poller.pollNow();
            await flush();
            expect(log).toEqual(["first started", "first started", "first done"]);
            first.held[1]?.release();
            await flush();
            expect(log).toEqual(["first started", "first started", "first done", "first done", "first started"]);
        });

        it("reports nothing of a failure settled just before a stop(), which the stopped tick had yet to read", async () => {
            const stopper: { stop?: () => void } = {};
            const h = harness([
                async () => {
                    void Promise.resolve()
                        .then(() => undefined)
                        .then(() => stopper.stop?.());
                    throw new Error("settled first");
                },
            ]);
            stopper.stop = () => h.poller.stop();
            h.poller.start();
            await flush();
            expect(h.errors()).toEqual([]);
            expect(h.armed()).toBe(0);
        });

        it("reports nothing of the stopped tick, not even a failure its step answers late with", async () => {
            const log: string[] = [];
            const first = holding(log, "first");
            const h = harness([first.step]);
            h.poller.start();
            await flush();
            h.poller.stop();
            first.held[0]?.fail(new Error("late"));
            await flush();
            expect(h.errors()).toEqual([]);
            expect(h.armed()).toBe(0);
        });
    });

    describe("pollNow", () => {
        it("ticks at once instead of waiting out the interval, which starts over", async () => {
            const log: string[] = [];
            const h = harness([recording(log, "tick")]);
            h.poller.start();
            await flush();
            h.timer.advance(INTERVAL_MS - 1_000);
            h.poller.pollNow();
            await flush();
            expect(log).toEqual(["tick", "tick"]);
            expect(h.armed()).toBe(1);
            h.timer.advance(1_000);
            await flush();
            expect(log).toEqual(["tick", "tick"]);
            h.timer.advance(INTERVAL_MS - 1_000);
            await flush();
            expect(log).toEqual(["tick", "tick", "tick"]);
        });

        it("is not overlapped by the interval it replaced when its tick outlasts it", async () => {
            const log: string[] = [];
            const step = holding(log, "tick");
            const h = harness([step.step]);
            h.poller.start();
            step.held[0]?.release();
            await flush();
            h.timer.advance(INTERVAL_MS - 1_000);
            h.poller.pollNow();
            await flush();
            expect(log).toEqual(["tick started", "tick done", "tick started"]);
            h.timer.advance(5_000);
            await flush();
            expect(log).toEqual(["tick started", "tick done", "tick started"]);
            expect(step.held).toHaveLength(2);
            step.held[1]?.release();
            await flush();
            expect(h.intervals()).toEqual([INTERVAL_MS, INTERVAL_MS]);
        });

        it("queues exactly one more tick while one is in flight", async () => {
            const log: string[] = [];
            const step = holding(log, "tick");
            const h = harness([step.step]);
            h.poller.start();
            await flush();
            h.poller.pollNow();
            h.poller.pollNow();
            h.poller.pollNow();
            step.held[0]?.release();
            await flush();
            expect(log).toEqual(["tick started", "tick done", "tick started"]);
            expect(h.armed()).toBe(0);
            step.held[1]?.release();
            await flush();
            expect(log).toEqual(["tick started", "tick done", "tick started", "tick done"]);
            expect(h.intervals()).toEqual([INTERVAL_MS]);
        });

        it("ticks and re-arms past a host cancel that throws", async () => {
            const log: string[] = [];
            const timer = new TimerMock();
            const throwing = {
                schedule: (callback: () => void, delayMs: number) => {
                    const cancel = timer.schedule(callback, delayMs);
                    if (delayMs !== INTERVAL_MS) return cancel;
                    return () => {
                        cancel();
                        throw new Error("cancel broke");
                    };
                },
            };
            const h = harness([recording(log, "tick")], { timer: throwing });
            h.poller.start();
            await flush();
            expect(() => h.poller.pollNow()).not.toThrow();
            await flush();
            expect(log).toEqual(["tick", "tick"]);
            expect(timer.pendingDelays).toEqual([INTERVAL_MS]);
            timer.advance(INTERVAL_MS);
            await flush();
            expect(log).toEqual(["tick", "tick", "tick"]);
        });

        it("does nothing when stopped, before a start and after a stop", async () => {
            const log: string[] = [];
            const h = harness([recording(log, "tick")]);
            h.poller.pollNow();
            await flush();
            expect(log).toEqual([]);
            h.poller.start();
            await flush();
            h.poller.stop();
            h.poller.pollNow();
            await flush();
            expect(log).toEqual(["tick"]);
            expect(h.armed()).toBe(0);
        });

        it("queues nothing when called after a stop() while a tick is still in flight", async () => {
            const log: string[] = [];
            const step = holding(log, "tick");
            const h = harness([step.step]);
            h.poller.start();
            await flush();
            h.poller.stop();
            h.poller.pollNow();
            step.held[0]?.release();
            await flush();
            h.poller.start();
            await flush();
            step.held[1]?.release();
            await flush();
            expect(log).toEqual(["tick started", "tick done", "tick started", "tick done"]);
            expect(h.armed()).toBe(1);
            expect(step.held).toHaveLength(2);
        });

        it("does not carry a queued tick across a stop() and a start()", async () => {
            const log: string[] = [];
            const step = holding(log, "tick");
            const h = harness([step.step]);
            h.poller.start();
            await flush();
            h.poller.pollNow();
            h.poller.stop();
            step.held[0]?.release();
            await flush();
            h.poller.start();
            await flush();
            step.held[1]?.release();
            await flush();
            expect(log).toEqual(["tick started", "tick done", "tick started", "tick done"]);
            expect(h.armed()).toBe(1);
        });

        it("drops the queued tick when stopped before it runs", async () => {
            const log: string[] = [];
            const step = holding(log, "tick");
            const h = harness([step.step]);
            h.poller.start();
            await flush();
            h.poller.pollNow();
            h.poller.stop();
            step.held[0]?.release();
            await flush();
            expect(log).toEqual(["tick started", "tick done"]);
            expect(h.armed()).toBe(0);
        });
    });
});
