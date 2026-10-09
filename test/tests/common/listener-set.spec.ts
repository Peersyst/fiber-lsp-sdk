import { ListenerSet } from "../../../src/common";

describe("ListenerSet", () => {
    it("delivers an event to every listener, in the order they subscribed", () => {
        const set = new ListenerSet<number>();
        const heard: string[] = [];
        set.add((event) => heard.push(`a${event}`));
        set.add((event) => heard.push(`b${event}`));
        set.emit(1);
        expect(heard).toEqual(["a1", "b1"]);
    });

    it("stops delivering to a listener once it unsubscribes, and the unsubscribe is idempotent", () => {
        const set = new ListenerSet<number>();
        const heard: number[] = [];
        const unsubscribe = set.add((event) => heard.push(event));
        set.emit(1);
        unsubscribe();
        unsubscribe();
        set.emit(2);
        expect(heard).toEqual([1]);
    });

    it("keeps delivering past a listener that throws", () => {
        const set = new ListenerSet<number>();
        const heard: number[] = [];
        set.add(() => {
            throw new Error("host bug");
        });
        set.add((event) => heard.push(event));
        expect(() => set.emit(1)).not.toThrow();
        expect(heard).toEqual([1]);
    });

    it("delivers an event to the listeners subscribed when it is raised, whatever they change during it", () => {
        const set = new ListenerSet<number>();
        const heard: string[] = [];
        const unsubscribeB = set.add((event) => heard.push(`b${event}`));
        set.add((event) => {
            heard.push(`a${event}`);
            unsubscribeB();
            set.add((next) => heard.push(`c${next}`));
        });
        set.emit(1);
        expect(heard).toEqual(["b1", "a1"]);
        set.emit(2);
        expect(heard).toEqual(["b1", "a1", "a2", "c2"]);
    });

    it("keeps one subscription per listener", () => {
        const set = new ListenerSet<number>();
        const heard: number[] = [];
        const listener = (event: number): void => {
            heard.push(event);
        };
        set.add(listener);
        set.add(listener);
        set.emit(1);
        expect(heard).toEqual([1]);
    });
});
