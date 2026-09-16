import { WireError } from "../../../src/wire";

describe("WireError", () => {
    it("names the field and what it had to be, and nothing else", () => {
        const error = new WireError("commitment_tx.tlcs[0].amount", "must be a u128");
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe("WireError");
        expect(error.message).toBe("commitment_tx.tlcs[0].amount must be a u128");
        expect(error.path).toBe("commitment_tx.tlcs[0].amount");
        expect(error.reason).toBe("must be a u128");
    });
});
