import { decodeRpcResponse, encodeRpcRequest } from "../../../src/rpc";
import { refusal } from "../../utils/refusal";
import { loadRpcVectors } from "../../utils/rpc-vectors";

const vectors = loadRpcVectors();

describe("encodeRpcRequest", () => {
    it("writes the request jsonrpsee reads, byte for byte", () => {
        const { request } = vectors.envelopes;
        const [params] = request.params as [Record<string, unknown>];
        expect(encodeRpcRequest(request.id, "get_payment", params)).toBe(request.text);
    });

    it("writes the params as the only item of a positional array", () => {
        expect(encodeRpcRequest(1, "abandon_channel", { channel_id: `0x${"11".repeat(32)}` })).toBe(
            `{"jsonrpc":"2.0","id":1,"method":"abandon_channel","params":[{"channel_id":"0x${"11".repeat(32)}"}]}`,
        );
    });
});

describe("decodeRpcResponse", () => {
    it.each(vectors.envelopes.results.map((entry) => [entry.name, entry] as const))("reads the %s as jsonrpsee writes it", (_, entry) => {
        expect(decodeRpcResponse(entry.text, entry.id)).toEqual({ result: { value: entry.result, path: "response.result" } });
    });

    it.each(vectors.envelopes.errors.map((entry) => [entry.name, entry] as const))("reads the %s error, ignoring its data", (_, entry) => {
        expect(decodeRpcResponse(entry.text, entry.id ?? 1)).toEqual({ error: { code: entry.code, message: entry.message } });
    });

    it("reads a null result as a result, not as its absence", () => {
        expect(decodeRpcResponse('{"jsonrpc":"2.0","id":3,"result":null}', 3)).toEqual({
            result: { value: null, path: "response.result" },
        });
    });

    it("reads an error with a null id, the answer to a request the node could not read", () => {
        expect(decodeRpcResponse('{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request"}}', 3)).toEqual({
            error: { code: -32600, message: "Invalid request" },
        });
    });

    it("ignores unknown members", () => {
        expect(decodeRpcResponse('{"jsonrpc":"2.0","id":3,"result":{},"extra":1}', 3)).toEqual({
            result: { value: {}, path: "response.result" },
        });
    });

    it.each([
        ["a body that is not JSON", "<html>502 Bad Gateway</html>", "response", "must be valid JSON"],
        ["an empty body", "", "response", "must be valid JSON"],
        ["an array", "[]", "response", "must be an object"],
        ["a batch answer", '[{"jsonrpc":"2.0","id":3,"result":null}]', "response", "must be an object"],
        ["null", "null", "response", "must be an object"],
        ["no version", '{"id":3,"result":null}', "response.jsonrpc", 'must be "2.0"'],
        ["another version", '{"jsonrpc":"1.0","id":3,"result":null}', "response.jsonrpc", 'must be "2.0"'],
        ["the version as a number", '{"jsonrpc":2,"id":3,"result":null}', "response.jsonrpc", 'must be "2.0"'],
        ["neither result nor error", '{"jsonrpc":"2.0","id":3}', "response", "must carry exactly one of result and error"],
        [
            "both result and error",
            '{"jsonrpc":"2.0","id":3,"result":null,"error":{"code":-32000,"message":"x"}}',
            "response",
            "must carry exactly one of result and error",
        ],
        [
            "a null error beside a result",
            '{"jsonrpc":"2.0","id":3,"result":{},"error":null}',
            "response",
            "must carry exactly one of result and error",
        ],
        ["another id", '{"jsonrpc":"2.0","id":4,"result":null}', "response.id", "must be 3, the id of the request"],
        ["the id as a string", '{"jsonrpc":"2.0","id":"3","result":null}', "response.id", "must be 3, the id of the request"],
        ["no id", '{"jsonrpc":"2.0","result":null}', "response.id", "must be 3, the id of the request"],
        ["no id on an error", '{"jsonrpc":"2.0","error":{"code":-32000,"message":"x"}}', "response.id", "must be 3, the id of the request"],
        ["a null id on a result", '{"jsonrpc":"2.0","id":null,"result":null}', "response.id", "must be 3, the id of the request"],
        [
            "another id on an error",
            '{"jsonrpc":"2.0","id":4,"error":{"code":-32000,"message":"x"}}',
            "response.id",
            "must be 3, the id of the request",
        ],
        ["an error that is not an object", '{"jsonrpc":"2.0","id":3,"error":"failed"}', "response.error", "must be an object"],
        ["a null error", '{"jsonrpc":"2.0","id":3,"error":null}', "response.error", "must be an object"],
        ["an error without a code", '{"jsonrpc":"2.0","id":3,"error":{"message":"x"}}', "response.error.code", "must be an integer"],
        [
            "a code as a string",
            '{"jsonrpc":"2.0","id":3,"error":{"code":"-32000","message":"x"}}',
            "response.error.code",
            "must be an integer",
        ],
        [
            "a fractional code",
            '{"jsonrpc":"2.0","id":3,"error":{"code":-32000.5,"message":"x"}}',
            "response.error.code",
            "must be an integer",
        ],
        ["an unsafe code", '{"jsonrpc":"2.0","id":3,"error":{"code":1e300,"message":"x"}}', "response.error.code", "must be an integer"],
        ["an error without a message", '{"jsonrpc":"2.0","id":3,"error":{"code":-32000}}', "response.error.message", "must be a string"],
        [
            "a message that is not a string",
            '{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":null}}',
            "response.error.message",
            "must be a string",
        ],
    ])("refuses %s", (_, text, path, reason) => {
        expect(refusal(() => decodeRpcResponse(text, 3))).toMatchObject({ path, reason });
    });

    it("never echoes the body it could not parse", () => {
        const error = refusal(() => decodeRpcResponse("secret-looking body", 3));
        expect(error.message).toBe("response must be valid JSON");
    });
});
