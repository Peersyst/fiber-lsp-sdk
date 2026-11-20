import { RpcError, RpcTransportError } from "../../../../src/rpc";
import {
    assertSdkAnsweredHash,
    formatFiberHash256,
    isFiberRefusal,
    isFiberRefusalByTemplate,
    isFiberRefusalUnderHash,
} from "../../../../src/sdk";

const HASH = "3c".repeat(32);
const ANSWER = { code: -32000, message: "Invoice is already paid" };

describe("isFiberRefusal", () => {
    it("takes fiber's answer by its code and its whole message", () => {
        expect(isFiberRefusal(new RpcError("settle_invoice", -32000, "Invoice is already paid"), ANSWER)).toBe(true);
    });

    it.each<[string, unknown]>([
        ["another code", new RpcError("settle_invoice", -32603, "Invoice is already paid")],
        ["a message with text past it", new RpcError("settle_invoice", -32000, "Invoice is already paid ")],
        ["a message cut short", new RpcError("settle_invoice", -32000, "Invoice is already")],
        ["an unknown outcome with the same message", new RpcTransportError("settle_invoice", "Invoice is already paid")],
        ["a plain object shaped like the answer", { name: "RpcError", code: -32000, message: "Invoice is already paid" }],
        ["nothing", undefined],
    ])("refuses %s", (_, error) => {
        expect(isFiberRefusal(error, ANSWER)).toBe(false);
    });
});

describe("isFiberRefusalUnderHash", () => {
    const ANSWERS = [
        { code: -32000, messagePrefix: "InvalidParameter: Payment session not found: ", messageSuffix: "" },
        { code: -32000, messagePrefix: "Payment session ", messageSuffix: " is busy" },
    ];

    it.each<[string, string]>([
        ["an answer with no text after the hash", `InvalidParameter: Payment session not found: Hash256(0x${HASH})`],
        ["an answer with text after the hash", `Payment session Hash256(0x${HASH}) is busy`],
    ])("takes %s for that very hash", (_, message) => {
        expect(isFiberRefusalUnderHash(new RpcError("get_payment", -32000, message), ANSWERS, HASH)).toBe(true);
    });

    it.each<[string, unknown]>([
        ["another hash", new RpcError("get_payment", -32000, `Payment session Hash256(0x${"3d".repeat(32)}) is busy`)],
        ["the hash in another form", new RpcError("get_payment", -32000, `Payment session 0x${HASH} is busy`)],
        ["another code", new RpcError("get_payment", -32603, `Payment session Hash256(0x${HASH}) is busy`)],
        ["the suffix dropped", new RpcError("get_payment", -32000, `Payment session Hash256(0x${HASH})`)],
        ["an unknown outcome", new RpcTransportError("get_payment", `Payment session Hash256(0x${HASH}) is busy`)],
    ])("refuses %s", (_, error) => {
        expect(isFiberRefusalUnderHash(error, ANSWERS, HASH)).toBe(false);
    });

    it("refuses everything against no answers", () => {
        expect(isFiberRefusalUnderHash(new RpcError("get_payment", -32000, `Payment session Hash256(0x${HASH}) is busy`), [], HASH)).toBe(
            false,
        );
    });
});

describe("isFiberRefusalByTemplate", () => {
    const TEMPLATES = ["fee {} is below {} (rate 0.5%)", "no path found"];

    it.each<[string, string]>([
        ["each number as fiber writes it", "fee 0 is below 1250000 (rate 0.5%)"],
        ["a number past 2^64", "fee 340282366920938463463374607431768211455 is below 1 (rate 0.5%)"],
        ["an answer with no number", "no path found"],
    ])("takes %s", (_, message) => {
        expect(isFiberRefusalByTemplate(new RpcError("send_payment", -32000, message), -32000, TEMPLATES)).toBe(true);
    });

    it.each<[string, unknown]>([
        ["a number signed", new RpcError("send_payment", -32000, "fee -1 is below 2 (rate 0.5%)")],
        ["a number as a fraction", new RpcError("send_payment", -32000, "fee 1.5 is below 2 (rate 0.5%)")],
        ["a number missing", new RpcError("send_payment", -32000, "fee  is below 2 (rate 0.5%)")],
        ["a number in hex", new RpcError("send_payment", -32000, "fee 0x1 is below 2 (rate 0.5%)")],
        ["the template's dot as any character", new RpcError("send_payment", -32000, "fee 1 is below 2 (rate 0x5%)")],
        ["the template's parenthesis dropped", new RpcError("send_payment", -32000, "fee 1 is below 2 rate 0.5%")],
        ["the template itself", new RpcError("send_payment", -32000, "fee {} is below {} (rate 0.5%)")],
        ["text before it", new RpcError("send_payment", -32000, "error: no path found")],
        ["text past it", new RpcError("send_payment", -32000, "no path found ")],
        ["another code", new RpcError("send_payment", -32603, "no path found")],
        ["an unknown outcome with the same message", new RpcTransportError("send_payment", "no path found")],
        ["a plain object shaped like the answer", { name: "RpcError", code: -32000, message: "no path found" }],
    ])("refuses %s", (_, error) => {
        expect(isFiberRefusalByTemplate(error, -32000, TEMPLATES)).toBe(false);
    });

    it("refuses everything against no templates", () => {
        expect(isFiberRefusalByTemplate(new RpcError("send_payment", -32000, "no path found"), -32000, [])).toBe(false);
    });
});

describe("formatFiberHash256", () => {
    it("writes the hash as fiber's messages write a Hash256", () => {
        expect(formatFiberHash256(HASH)).toBe(`Hash256(0x${HASH})`);
    });
});

describe("assertSdkAnsweredHash", () => {
    it("takes an answer about the hash asked", () => {
        expect(() => assertSdkAnsweredHash("payment", HASH, new Uint8Array(32).fill(0x3c))).not.toThrow();
    });

    it("refuses an answer about another hash, naming both and what was asked", () => {
        expect(() => assertSdkAnsweredHash("invoice", HASH, new Uint8Array(32).fill(0x7e))).toThrow(
            new Error(`the node answered the invoice of 0x${HASH} with that of 0x${"7e".repeat(32)}`),
        );
    });
});
