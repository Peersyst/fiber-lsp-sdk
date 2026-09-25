import { RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import { WireError } from "../../../src/wire";

describe("RpcTransportError", () => {
    it("names the method, what failed, and the status when a response arrived", () => {
        const error = new RpcTransportError("send_payment", "HTTP status 502", 502);
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe("RpcTransportError");
        expect(error.message).toBe("send_payment: HTTP status 502");
        expect(error.method).toBe("send_payment");
        expect(error.status).toBe(502);
        expect(error.cause).toBeUndefined();
    });

    it("carries the cause, and no status when no response arrived", () => {
        const cause = new TypeError("fetch failed");
        const error = new RpcTransportError("get_payment", "the request failed", undefined, { cause });
        expect(error.status).toBeUndefined();
        expect(error.cause).toBe(cause);
    });
});

describe("RpcError", () => {
    it("carries the method, the node's code and its message verbatim", () => {
        const error = new RpcError("settle_invoice", -32000, "invoice not found");
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe("RpcError");
        expect(error.message).toBe("invoice not found");
        expect(error.method).toBe("settle_invoice");
        expect(error.code).toBe(-32000);
    });
});

describe("RpcResponseError", () => {
    it("names the method and the field that could not be read, with the refusal as its cause", () => {
        const cause = new WireError("response.result.channel_id", "must be 32 bytes of 0x-prefixed lowercase hex");
        const error = new RpcResponseError("submit_signed_funding_tx", cause);
        expect(error).toBeInstanceOf(Error);
        expect(error).not.toBeInstanceOf(WireError);
        expect(error.name).toBe("RpcResponseError");
        expect(error.message).toBe("submit_signed_funding_tx: response.result.channel_id must be 32 bytes of 0x-prefixed lowercase hex");
        expect(error.method).toBe("submit_signed_funding_tx");
        expect(error.path).toBe("response.result.channel_id");
        expect(error.reason).toBe("must be 32 bytes of 0x-prefixed lowercase hex");
        expect(error.cause).toBe(cause);
    });
});

describe("the three errors", () => {
    it("are unrelated classes, so a catch on one never takes another", () => {
        const transport = new RpcTransportError("get_invoice", "the request failed");
        const node = new RpcError("get_invoice", -32000, "x");
        const response = new RpcResponseError("get_invoice", new WireError("response", "must be valid JSON"));
        expect([transport instanceof RpcError, transport instanceof RpcResponseError]).toEqual([false, false]);
        expect([node instanceof RpcTransportError, node instanceof RpcResponseError]).toEqual([false, false]);
        expect([response instanceof RpcTransportError, response instanceof RpcError]).toEqual([false, false]);
    });
});
