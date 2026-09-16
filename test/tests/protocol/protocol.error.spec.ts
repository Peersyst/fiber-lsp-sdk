import { ProtocolError } from "../../../src/protocol";
import { WireError } from "../../../src/wire";

describe("ProtocolError", () => {
    it("names the field, what it had to be, and the request it is answered with", () => {
        const error = new ProtocolError("sign_request.params.to_local", "must be a u128", "0x2a");
        expect(error).toBeInstanceOf(WireError);
        expect(error.name).toBe("ProtocolError");
        expect(error.message).toBe("sign_request.params.to_local must be a u128");
        expect(error.code).toBe("malformed");
        expect(error.path).toBe("sign_request.params.to_local");
        expect(error.reason).toBe("must be a u128");
        expect(error.requestId).toBe("0x2a");
    });

    it("is the answerable refusal, which a bare wire refusal is not", () => {
        const refusal = new WireError("channel_registered.channel_id", "must be 32 bytes of 0x-prefixed lowercase hex");
        expect(refusal).not.toBeInstanceOf(ProtocolError);
        expect(new ProtocolError(refusal.path, refusal.reason, "0x2a")).toBeInstanceOf(WireError);
    });
});
