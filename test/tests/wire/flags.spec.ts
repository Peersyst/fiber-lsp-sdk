import { decodeFlags } from "../../../src/wire";
import { refusal } from "../../utils/refusal";

const NAMES = ["OUR_INIT_SENT", "THEIR_INIT_SENT", "INIT_SENT", "AWAITING_EXTERNAL_FUNDING"] as const;
const REASON = "must be distinct names among OUR_INIT_SENT, THEIR_INIT_SENT, INIT_SENT, AWAITING_EXTERNAL_FUNDING, joined by |";

function flags(value: unknown): string[] {
    return decodeFlags({ value, path: "state.state_flags" }, NAMES);
}

describe("decodeFlags", () => {
    it("reads the empty string as the empty set", () => {
        expect(flags("")).toEqual([]);
    });

    it.each(NAMES)("reads %s alone", (name) => {
        expect(flags(name)).toEqual([name]);
    });

    it("reads several names in the order the wire gives them, composites included", () => {
        expect(flags("OUR_INIT_SENT|INIT_SENT")).toEqual(["OUR_INIT_SENT", "INIT_SENT"]);
        expect(flags("INIT_SENT|OUR_INIT_SENT")).toEqual(["INIT_SENT", "OUR_INIT_SENT"]);
        expect(flags("OUR_INIT_SENT|THEIR_INIT_SENT|INIT_SENT|AWAITING_EXTERNAL_FUNDING")).toEqual([...NAMES]);
    });

    it.each([
        ["an unknown name", "COOPERATIVE"],
        ["a lowercase name", "our_init_sent"],
        ["a trailing separator", "OUR_INIT_SENT|"],
        ["a leading separator", "|OUR_INIT_SENT"],
        ["an empty name between two", "OUR_INIT_SENT||INIT_SENT"],
        ["a lone separator", "|"],
        ["padding around the separator", "OUR_INIT_SENT | INIT_SENT"],
        ["a padded name", " OUR_INIT_SENT"],
        ["a name twice", "OUR_INIT_SENT|OUR_INIT_SENT"],
        ["another separator", "OUR_INIT_SENT,INIT_SENT"],
    ])("refuses %s, with the path and the names it accepts", (_, value) => {
        const error = refusal(() => flags(value));
        expect(error.path).toBe("state.state_flags");
        expect(error.reason).toBe(REASON);
    });

    it.each([null, undefined, [], ["OUR_INIT_SENT"], 1])("refuses %p as not a string", (value) => {
        expect(refusal(() => flags(value)).reason).toBe("must be a string of flag names");
    });

    it("reads nothing but the empty set when no name is accepted", () => {
        expect(decodeFlags({ value: "", path: "flags" }, [])).toEqual([]);
        expect(refusal(() => decodeFlags({ value: "OUR_INIT_SENT", path: "flags" }, [])).path).toBe("flags");
    });
});
