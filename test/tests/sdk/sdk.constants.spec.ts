import {
    SDK_NETWORK_INVOICE_CURRENCIES,
    SDK_NETWORK_PRESETS,
    DEFAULT_SDK_PAYMENT_PAGE_LIMIT,
    PAYMENT_HISTORY_INDEX_KEY,
    PAYMENT_HISTORY_RECORD_KEY_PREFIX,
    PAYMENT_HISTORY_RECORD_VERSION,
    SDK_PAYMENT_DIRECTIONS,
    SDK_PAYMENT_RECORD_STATUSES,
    SDK_RECEIVE_CANCELLED_REASON,
    SDK_RECEIVE_EXPIRED_REASON,
    SDK_REGISTRATION_CONSUMED_ERROR,
    SDK_REGISTRATION_INVALID_ERRORS,
} from "../../../src/sdk";

describe("SDK_NETWORK_INVOICE_CURRENCIES", () => {
    it("is each preset's invoice currency", () => {
        expect(SDK_NETWORK_INVOICE_CURRENCIES).toEqual({ mainnet: "Fibb", testnet: "Fibt" });
        expect(SDK_NETWORK_INVOICE_CURRENCIES.mainnet).toBe(SDK_NETWORK_PRESETS.mainnet.invoiceCurrency);
        expect(SDK_NETWORK_INVOICE_CURRENCIES.testnet).toBe(SDK_NETWORK_PRESETS.testnet.invoiceCurrency);
    });

    it("cannot be rewritten by a host", () => {
        expect(Object.isFrozen(SDK_NETWORK_INVOICE_CURRENCIES)).toBe(true);
    });
});

describe("the payment history", () => {
    it("pins the directions and the statuses", () => {
        expect(SDK_PAYMENT_DIRECTIONS).toEqual(["send", "receive"]);
        expect(SDK_PAYMENT_RECORD_STATUSES).toEqual(["pending", "completed", "failed"]);
    });

    it("pins the keys and the version, so a device reads the history it wrote", () => {
        expect(PAYMENT_HISTORY_INDEX_KEY).toBe("fiber-lsp-sdk:payment-history");
        expect(PAYMENT_HISTORY_RECORD_KEY_PREFIX).toBe("fiber-lsp-sdk:payment-history:");
        expect(PAYMENT_HISTORY_RECORD_VERSION).toBe(1);
    });

    it("pins the page's default size", () => {
        expect(DEFAULT_SDK_PAYMENT_PAGE_LIMIT).toBe(20);
    });

    it("pins the reasons of a receive that ended unpaid", () => {
        expect(SDK_RECEIVE_EXPIRED_REASON).toBe("the invoice expired");
        expect(SDK_RECEIVE_CANCELLED_REASON).toBe("the invoice was cancelled");
    });
});

describe("the registration's refusals", () => {
    it("pins fiber's answer for a spent request", () => {
        expect(SDK_REGISTRATION_CONSUMED_ERROR).toEqual({ code: -32000, message: "tenant registration request was already consumed" });
    });

    it("pins fiber's answers for a proof that does not verify", () => {
        expect(SDK_REGISTRATION_INVALID_ERRORS).toEqual([
            { code: -32000, message: "invalid RootSigner registration proof: signature failed verification" },
            { code: -32000, message: "invalid RootSigner registration proof: malformed signature" },
            { code: -32000, message: "invalid RootSigner registration proof: tenant registration signed_at is too far in the future" },
            { code: -32000, message: "invalid RootSigner registration proof: tenant registration signed_at is too old" },
        ]);
    });
});
