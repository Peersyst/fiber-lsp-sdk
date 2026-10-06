import { boundPaymentHashOf } from "../../../../src/policy/utils/payment-hash.utils";

describe("boundPaymentHashOf", () => {
    it("keeps the 20 bytes a settlement witness binds, as lowercase hex", () => {
        expect(boundPaymentHashOf("6844f645bb03ff9d1c9c48ee5e9e971be09bf34a3612c81b20c2a5a1bff2a6b6")).toBe(
            "6844f645bb03ff9d1c9c48ee5e9e971be09bf34a",
        );
    });
});
