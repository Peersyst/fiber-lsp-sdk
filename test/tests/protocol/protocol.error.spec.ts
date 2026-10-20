import { ProtocolError } from "../../../src/protocol";
import { WireError } from "../../../src/wire";

describe("ProtocolError", () => {
    it("names the field and what it had to be, as a malformed refusal", () => {
        const error = new ProtocolError("response.result.status.request_id", "must be 32 bytes of 0x-prefixed lowercase hex");
        expect(error).toBeInstanceOf(WireError);
        expect(error.name).toBe("ProtocolError");
        expect(error.message).toBe("response.result.status.request_id must be 32 bytes of 0x-prefixed lowercase hex");
        expect(error.code).toBe("malformed");
        expect(error.path).toBe("response.result.status.request_id");
        expect(error.reason).toBe("must be 32 bytes of 0x-prefixed lowercase hex");
        expect(Object.keys(error)).not.toContain("requestId");
    });

    it("is the signing protocol's refusal, which a bare wire refusal is not", () => {
        const refusal = new WireError("response.result.channel_id", "must be 32 bytes of 0x-prefixed lowercase hex");
        expect(refusal).not.toBeInstanceOf(ProtocolError);
        expect(new ProtocolError(refusal.path, refusal.reason)).toBeInstanceOf(WireError);
    });
});
