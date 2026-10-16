import type { ITimer } from "../../../../src/session";
import { runtimeTimer } from "../../../../src/sdk";
import { withRuntime } from "../../../utils/with-runtime";

function recordingRuntime() {
    const calls: { scheduled: unknown[][]; cleared: unknown[]; receivers: unknown[] } = { scheduled: [], cleared: [], receivers: [] };
    const handle = { id: 7 };
    return {
        calls,
        handle,
        // Not arrows, so the receiver is observable.
        setTimeout: function (this: unknown, ...args: unknown[]) {
            calls.receivers.push(this);
            calls.scheduled.push(args);
            return handle;
        },
        clearTimeout: function (this: unknown, cleared: unknown) {
            calls.receivers.push(this);
            calls.cleared.push(cleared);
        },
    };
}

describe("runtimeTimer", () => {
    it("runs the callback after the delay on the real runtime, and a cancelled one never", async () => {
        const timer: ITimer = runtimeTimer();
        const ran: string[] = [];
        timer.schedule(() => ran.push("kept"), 1);
        const cancel = timer.schedule(() => ran.push("cancelled"), 1);
        cancel();
        await new Promise((resolve) => setTimeout(resolve, 20));
        expect(ran).toEqual(["kept"]);
    });

    it("schedules through the runtime's setTimeout and cancels through its clearTimeout, both without a receiver", () => {
        const runtime = recordingRuntime();
        const timer = withRuntime(runtime, () => runtimeTimer());
        const callback = (): void => undefined;
        const cancel = timer.schedule(callback, 5_000);
        expect(runtime.calls.scheduled).toEqual([[callback, 5_000]]);
        cancel();
        expect(runtime.calls.cleared).toEqual([runtime.handle]);
        expect(runtime.calls.receivers).toEqual([undefined, undefined]);
    });

    it("reads the runtime's functions once, at construction", () => {
        const first = recordingRuntime();
        const second = recordingRuntime();
        const timer = withRuntime(first, () => runtimeTimer());
        withRuntime(second, () => timer.schedule(() => undefined, 1)());
        expect(first.calls.scheduled).toHaveLength(1);
        expect(first.calls.cleared).toHaveLength(1);
        expect(second.calls.scheduled).toEqual([]);
        expect(second.calls.cleared).toEqual([]);
    });

    it.each([
        ["no setTimeout", { setTimeout: undefined, clearTimeout: () => undefined }],
        ["no clearTimeout", { setTimeout: () => undefined, clearTimeout: undefined }],
        ["a setTimeout that is not a function", { setTimeout: "soon", clearTimeout: () => undefined }],
        ["a clearTimeout that is not a function", { setTimeout: () => undefined, clearTimeout: null }],
    ])("refuses to default when the runtime has %s", (_, runtime) => {
        expect(() => withRuntime(runtime, () => runtimeTimer())).toThrow(
            new TypeError("this runtime has no timer: pass one in the options"),
        );
    });
});
