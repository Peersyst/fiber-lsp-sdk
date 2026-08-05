import * as common from "../../../src/common";

describe("common module surface", () => {
    it("exports the guards the rest of the SDK consumes", () => {
        expect(Object.keys(common).sort()).toEqual(["assertBytes", "assertUnsignedInteger"].sort());
    });
});
