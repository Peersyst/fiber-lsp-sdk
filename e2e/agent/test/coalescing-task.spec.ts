import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CoalescingTask } from "../src/coalescing-task";

type Gate = { promise: Promise<void>; open: () => void };

function gate(): Gate {
    let open: () => void = () => undefined;
    const promise = new Promise<void>((resolve) => (open = resolve));
    return { promise, open };
}

async function flush(): Promise<void> {
    await new Promise((resolve) => setImmediate(resolve));
}

describe("CoalescingTask", () => {
    it("runs once per call while idle", async () => {
        let runs = 0;
        const task = new CoalescingTask(async () => {
            runs++;
        });
        await task.run();
        await task.run();
        assert.equal(runs, 2);
    });

    it("folds the calls made during a run into one run after it, never two at once", async () => {
        const gates = [gate(), gate()];
        let running = 0;
        let overlapped = false;
        let runs = 0;
        const task = new CoalescingTask(async () => {
            const current = gates[runs++];
            running++;
            overlapped ||= running > 1;
            await current?.promise;
            running--;
        });
        const first = task.run();
        await flush();
        const second = task.run();
        const third = task.run();
        assert.equal(runs, 1);
        gates[0]?.open();
        await flush();
        assert.equal(runs, 2);
        gates[1]?.open();
        await Promise.all([first, second, third]);
        assert.equal(runs, 2);
        assert.equal(overlapped, false);
    });

    it("settles a call only once a run that started after it ended", async () => {
        const gates = [gate(), gate()];
        let runs = 0;
        const task = new CoalescingTask(async () => {
            await gates[runs++]?.promise;
        });
        void task.run();
        await flush();
        let settled = false;
        const late = task.run().then(() => (settled = true));
        gates[0]?.open();
        await flush();
        assert.equal(settled, false);
        gates[1]?.open();
        await late;
        assert.equal(settled, true);
    });

    it("rejects the calls of a run that throws, and runs again on the next call", async () => {
        let runs = 0;
        const task = new CoalescingTask(async () => {
            if (runs++ === 0) throw new Error("the disk is full");
        });
        await assert.rejects(task.run(), { message: "the disk is full" });
        await task.run();
        assert.equal(runs, 2);
    });
});
