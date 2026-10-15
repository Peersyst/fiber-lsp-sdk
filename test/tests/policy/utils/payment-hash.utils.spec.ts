import { boundPaymentHashOf, isTlcOfPaymentRecord } from "../../../../src/policy/utils/payment-hash.utils";

const PAYMENT_HASH = "6844f645bb03ff9d1c9c48ee5e9e971be09bf34a3612c81b20c2a5a1bff2a6b6";
const BOUND_HASH = "6844f645bb03ff9d1c9c48ee5e9e971be09bf34a";
// The same bound 20 bytes, other unbound 12.
const TWIN_HASH = BOUND_HASH + "00".repeat(12);

describe("boundPaymentHashOf", () => {
    it("keeps the 20 bytes a legacy settlement witness binds, as lowercase hex", () => {
        expect(boundPaymentHashOf(PAYMENT_HASH)).toBe(BOUND_HASH);
    });
});

describe("isTlcOfPaymentRecord", () => {
    it("takes a TLC that binds no full hash as the record's, by the key alone", () => {
        expect(isTlcOfPaymentRecord({ fullPaymentHash: null }, { paymentHash: PAYMENT_HASH })).toBe(true);
    });

    it("takes a TLC that binds the record's whole hash as the record's", () => {
        expect(isTlcOfPaymentRecord({ fullPaymentHash: PAYMENT_HASH }, { paymentHash: PAYMENT_HASH })).toBe(true);
    });

    it("refuses a TLC that binds a twin of the record's hash", () => {
        expect(isTlcOfPaymentRecord({ fullPaymentHash: TWIN_HASH }, { paymentHash: PAYMENT_HASH })).toBe(false);
    });
});
