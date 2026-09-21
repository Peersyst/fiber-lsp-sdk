import { TimerSlot } from "../../../../src/session";
import { TimerMock } from "../../../mocks/session";

describe("TimerSlot", () => {
    it("runs the callback after the delay", () => {
        const timer = new TimerMock();
        const slot = new TimerSlot(timer);
        const runs: number[] = [];
        slot.arm(() => runs.push(1), 500);
        timer.advance(499);
        expect(runs).toEqual([]);
        timer.advance(1);
        expect(runs).toEqual([1]);
        expect(timer.pending).toBe(0);
    });

    it("holds one callback: arming again cancels the earlier one", () => {
        const timer = new TimerMock();
        const slot = new TimerSlot(timer);
        const runs: string[] = [];
        slot.arm(() => runs.push("first"), 100);
        slot.arm(() => runs.push("second"), 200);
        expect(timer.pending).toBe(1);
        timer.advance(200);
        expect(runs).toEqual(["second"]);
    });

    it("clears what it holds", () => {
        const timer = new TimerMock();
        const slot = new TimerSlot(timer);
        const runs: number[] = [];
        slot.arm(() => runs.push(1), 100);
        slot.clear();
        slot.clear();
        expect(timer.pending).toBe(0);
        timer.advance(100);
        expect(runs).toEqual([]);
    });

    it("drops the earlier arming with no clear in between, through a timer whose cancel does nothing", () => {
        const timer = new TimerMock();
        timer.ignoreCancel = true;
        const slot = new TimerSlot(timer);
        const runs: string[] = [];
        slot.arm(() => runs.push("first"), 100);
        slot.arm(() => runs.push("second"), 200);
        expect(timer.pending).toBe(2);
        timer.advance(200);
        expect(runs).toEqual(["second"]);
    });

    it("never runs an earlier arming, even through a timer whose cancel does nothing", () => {
        const timer = new TimerMock();
        timer.ignoreCancel = true;
        const slot = new TimerSlot(timer);
        const runs: string[] = [];
        slot.arm(() => runs.push("first"), 100);
        slot.arm(() => runs.push("second"), 200);
        slot.arm(() => runs.push("third"), 300);
        slot.clear();
        slot.arm(() => runs.push("fourth"), 400);
        expect(timer.pending).toBe(4);
        timer.advance(400);
        expect(runs).toEqual(["fourth"]);
    });

    it("can be re-armed from inside its own callback", () => {
        const timer = new TimerMock();
        const slot = new TimerSlot(timer);
        const runs: string[] = [];
        slot.arm(() => {
            runs.push("first");
            slot.arm(() => runs.push("second"), 50);
        }, 100);
        timer.advance(150);
        expect(runs).toEqual(["first", "second"]);
    });

    it("is free again once the callback has run, so a clear afterwards cancels nothing", () => {
        const timer = new TimerMock();
        const cancels: number[] = [];
        const counting = {
            schedule: (callback: () => void, delayMs: number) => {
                const cancel = timer.schedule(callback, delayMs);
                return () => {
                    cancels.push(1);
                    cancel();
                };
            },
        };
        const counted = new TimerSlot(counting);
        counted.arm(() => undefined, 10);
        timer.advance(10);
        counted.clear();
        expect(cancels).toEqual([]);
    });
});
