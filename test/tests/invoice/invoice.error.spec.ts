import { InvoiceError } from "../../../src/invoice";
import { refuseInvoice } from "../../../src/invoice/invoice.error";

describe("InvoiceError", () => {
    it("names what was refused and what it had to be, in its message too", () => {
        const error = new InvoiceError("data.attributes[2]", "must not repeat an attribute type");
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe("InvoiceError");
        expect(error.path).toBe("data.attributes[2]");
        expect(error.reason).toBe("must not repeat an attribute type");
        expect(error.message).toBe("data.attributes[2] must not repeat an attribute type");
    });
});

describe("refuseInvoice", () => {
    it("throws the refusal", () => {
        expect(() => refuseInvoice("amount", "must be decimal shannons")).toThrow(new InvoiceError("amount", "must be decimal shannons"));
    });
});
