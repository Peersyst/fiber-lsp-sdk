import type { FetchInit, FetchResponseLike, IFetchLike } from "../../../src/rpc";
import { FiberRpcClient, RPC_UNAUTHORIZED_CODE, RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import type { Field } from "../../../src/wire";
import { WireError, decodeHexBytes, readObject } from "../../../src/wire";
import { FetchMock } from "../../mocks/rpc";
import { rejection } from "../../utils/rejection";
import { loadRpcVectors } from "../../utils/rpc-vectors";

const vectors = loadRpcVectors();

const URL = "http://fiber.example:8227";
const TOKEN = "En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiDs-token_example=";
const CHANNEL_ID = `0x${"11".repeat(32)}`;
const PARAMS = { channel_id: CHANNEL_ID };

function ok(body: string): { status: number; body: string } {
    return { status: 200, body };
}

const passThrough = (field: Field): unknown => field.value;

function decodeChannelId(field: Field): Uint8Array {
    return decodeHexBytes(readObject<{ channel_id: string }>(field)("channel_id"), 32);
}

function clientOf(mock: FetchMock, token?: string): FiberRpcClient {
    return new FiberRpcClient({ url: URL, token, fetch: mock.fetch });
}

describe("FiberRpcClient", () => {
    it("takes the host's fetch as it is", () => {
        // The assignment is the assertion, checked by tsc.
        const hostFetch: IFetchLike = fetch;
        expect(() => new FiberRpcClient({ url: URL, fetch: hostFetch })).not.toThrow();
    });

    describe("construction", () => {
        it("refuses an empty url", () => {
            expect(() => new FiberRpcClient({ url: "", fetch: new FetchMock().fetch })).toThrow(
                new TypeError("url must be a non-empty string"),
            );
        });

        it.each([
            ["an empty token", ""],
            ["a space", "abc def"],
            ["a newline", "abc\ndef"],
            ["a carriage return", "abc\r\ndef"],
            ["a tab", "abc\tdef"],
            ["a non-ASCII character", "abcé"],
            ["a control character", "abc\x00"],
            ["a delete character", "abc\x7f"],
        ])("refuses a token with %s, without echoing it", (_, token) => {
            expect(() => clientOf(new FetchMock(), token)).toThrow(new TypeError("token must be printable ASCII without spaces"));
        });
    });

    describe("the request", () => {
        it("posts the JSON-RPC text to the url, with the token as a Bearer header", async () => {
            const mock = new FetchMock().answer(ok('{"jsonrpc":"2.0","id":1,"result":null}'));
            await clientOf(mock, TOKEN).call("abandon_channel", PARAMS, passThrough);
            expect(mock.requests).toHaveLength(1);
            expect(mock.last.url).toBe(URL);
            expect(mock.last.init).toEqual({
                method: "POST",
                headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
                body: `{"jsonrpc":"2.0","id":1,"method":"abandon_channel","params":[{"channel_id":"${CHANNEL_ID}"}]}`,
            });
        });

        it("sends a token of the bounds of printable ASCII as it is", async () => {
            const mock = new FetchMock().answer(ok('{"jsonrpc":"2.0","id":1,"result":null}'));
            await clientOf(mock, "!~").call("abandon_channel", PARAMS, passThrough);
            expect(mock.last.init.headers.authorization).toBe("Bearer !~");
        });

        it("sends no authorization header without a token", async () => {
            const mock = new FetchMock().answer(ok('{"jsonrpc":"2.0","id":1,"result":null}'));
            await clientOf(mock).call("abandon_channel", PARAMS, passThrough);
            expect(mock.last.init.headers).toEqual({ "content-type": "application/json" });
        });

        it("calls fetch without a receiver, as a browser's fetch requires", async () => {
            const mock = new FetchMock().answer(ok('{"jsonrpc":"2.0","id":1,"result":null}'));
            await clientOf(mock).call("abandon_channel", PARAMS, passThrough);
            expect(mock.last.receiver).toBeUndefined();
        });

        it("hands every call headers of its own, so a fetch that alters them cannot reach the next call", async () => {
            const seen: Record<string, string>[] = [];
            const altering: IFetchLike = async (_url: string, init: FetchInit): Promise<FetchResponseLike> => {
                seen.push({ ...init.headers });
                init.headers.authorization = "Bearer stolen";
                const id = (JSON.parse(init.body) as { id: number }).id;
                return { status: 200, text: async () => `{"jsonrpc":"2.0","id":${id},"result":null}` };
            };
            const client = new FiberRpcClient({ url: URL, token: TOKEN, fetch: altering });
            await client.call("abandon_channel", PARAMS, passThrough);
            await client.call("abandon_channel", PARAMS, passThrough);
            expect(seen).toEqual([
                { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
                { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
            ]);
        });

        it("numbers the calls from 1, one id per call", async () => {
            const mock = new FetchMock().answer(
                ok('{"jsonrpc":"2.0","id":1,"result":null}'),
                ok('{"jsonrpc":"2.0","id":2,"result":null}'),
                ok('{"jsonrpc":"2.0","id":3,"result":null}'),
            );
            const client = clientOf(mock);
            await client.call("abandon_channel", PARAMS, passThrough);
            await Promise.all([client.call("get_invoice", PARAMS, passThrough), client.call("get_payment", PARAMS, passThrough)]);
            expect(mock.requests.map((request) => JSON.parse(request.init.body) as unknown)).toEqual([
                { jsonrpc: "2.0", id: 1, method: "abandon_channel", params: [PARAMS] },
                { jsonrpc: "2.0", id: 2, method: "get_invoice", params: [PARAMS] },
                { jsonrpc: "2.0", id: 3, method: "get_payment", params: [PARAMS] },
            ]);
        });

        it("never reuses the id of a call that failed", async () => {
            const mock = new FetchMock().answer({ rejection: new TypeError("fetch failed") }, ok('{"jsonrpc":"2.0","id":2,"result":null}'));
            const client = clientOf(mock);
            await rejection(client.call("abandon_channel", PARAMS, passThrough));
            await expect(client.call("abandon_channel", PARAMS, passThrough)).resolves.toBeNull();
            expect((JSON.parse(mock.last.init.body) as { id: number }).id).toBe(2);
        });

        it("keeps a count per client", async () => {
            const mock = new FetchMock().answer(ok('{"jsonrpc":"2.0","id":1,"result":null}'), ok('{"jsonrpc":"2.0","id":1,"result":null}'));
            await clientOf(mock).call("abandon_channel", PARAMS, passThrough);
            await clientOf(mock).call("abandon_channel", PARAMS, passThrough);
            expect(mock.requests.map((request) => (JSON.parse(request.init.body) as { id: number }).id)).toEqual([1, 1]);
        });
    });

    describe("a result", () => {
        it.each(vectors.envelopes.results.map((entry) => [entry.name, entry] as const))(
            "hands the %s to the method's decoder",
            async (_, entry) => {
                const mock = new FetchMock().answer(ok(entry.text.replace(`"id":${entry.id}`, '"id":1')));
                const decode = jest.fn(passThrough);
                await expect(clientOf(mock).call("get_payment", PARAMS, decode)).resolves.toEqual(entry.result);
                expect(decode).toHaveBeenCalledTimes(1);
                expect(decode).toHaveBeenCalledWith({ value: entry.result, path: "response.result" });
            },
        );

        it("returns what the decoder returns", async () => {
            const mock = new FetchMock().answer(ok(`{"jsonrpc":"2.0","id":1,"result":{"channel_id":"${CHANNEL_ID}"}}`));
            await expect(clientOf(mock).call("submit_signed_funding_tx", PARAMS, decodeChannelId)).resolves.toEqual(
                new Uint8Array(32).fill(0x11),
            );
        });

        it("turns the decoder's refusal into an RpcResponseError that names the field", async () => {
            const mock = new FetchMock().answer(ok('{"jsonrpc":"2.0","id":1,"result":{"channel_id":"0x11"}}'));
            const error = await rejection(clientOf(mock).call("submit_signed_funding_tx", PARAMS, decodeChannelId));
            expect(error).toBeInstanceOf(RpcResponseError);
            expect(error).toMatchObject({
                method: "submit_signed_funding_tx",
                path: "response.result.channel_id",
                reason: "must be 32 bytes of 0x-prefixed lowercase hex",
            });
            expect((error as RpcResponseError).cause).toBeInstanceOf(WireError);
        });

        it("lets a decoder's own bug through as it is, not as an answer it could not read", async () => {
            const bug = new TypeError("decoder bug");
            const mock = new FetchMock().answer(ok('{"jsonrpc":"2.0","id":1,"result":{}}'));
            const decode = (): never => {
                throw bug;
            };
            await expect(clientOf(mock).call("get_payment", PARAMS, decode)).rejects.toBe(bug);
        });
    });

    describe("an error", () => {
        it.each(vectors.envelopes.errors.map((entry) => [entry.name, entry] as const))("throws the %s as an RpcError", async (_, entry) => {
            const text = entry.id === null ? entry.text : entry.text.replace(`"id":${entry.id}`, '"id":1');
            const mock = new FetchMock().answer(ok(text));
            const decode = jest.fn(passThrough);
            const error = await rejection(clientOf(mock).call("settle_invoice", PARAMS, decode));
            expect(error).toBeInstanceOf(RpcError);
            expect(error).toMatchObject({ method: "settle_invoice", code: entry.code, message: entry.message });
            expect(decode).not.toHaveBeenCalled();
        });

        it("leaves an auth refusal to be told by its code alone", async () => {
            const mock = new FetchMock().answer(
                ok('{"jsonrpc":"2.0","id":1,"error":{"code":-32999,"message":"Unauthorized: Biscuit authorization timed out"}}'),
            );
            const error = await rejection(clientOf(mock, TOKEN).call("list_channels", {}, passThrough));
            expect((error as RpcError).code).toBe(RPC_UNAUTHORIZED_CODE);
        });
    });

    describe("an answer the client cannot read", () => {
        it.each([
            ["a body that is not JSON", "<html>502 Bad Gateway</html>", "response"],
            ["the answer to another id", '{"jsonrpc":"2.0","id":2,"result":null}', "response.id"],
            ["another version", '{"jsonrpc":"1.0","id":1,"result":null}', "response.jsonrpc"],
            ["an error without a code", '{"jsonrpc":"2.0","id":1,"error":{"message":"x"}}', "response.error.code"],
        ])("throws %s as an RpcResponseError, without decoding", async (_, text, path) => {
            const mock = new FetchMock().answer(ok(text));
            const decode = jest.fn(passThrough);
            const error = await rejection(clientOf(mock).call("new_invoice", PARAMS, decode));
            expect(error).toBeInstanceOf(RpcResponseError);
            expect(error).toMatchObject({ method: "new_invoice", path });
            expect(decode).not.toHaveBeenCalled();
        });
    });

    describe("a transport failure", () => {
        it("throws a fetch that rejects as an RpcTransportError, with no status", async () => {
            const cause = new TypeError("fetch failed");
            const mock = new FetchMock().answer({ rejection: cause });
            const error = await rejection(clientOf(mock).call("send_payment", PARAMS, passThrough));
            expect(error).toBeInstanceOf(RpcTransportError);
            expect(error).toMatchObject({ method: "send_payment", status: undefined, message: "send_payment: the request failed", cause });
        });

        it("throws a fetch that throws before returning a promise the same way", async () => {
            const cause = new TypeError("invalid url");
            const throwing: IFetchLike = () => {
                throw cause;
            };
            const client = new FiberRpcClient({ url: URL, fetch: throwing });
            await expect(client.call("send_payment", PARAMS, passThrough)).rejects.toMatchObject({ name: "RpcTransportError", cause });
        });

        it.each([100, 199, 300, 304, 400, 401, 404, 413, 415, 500, 502, 503])(
            "throws status %i without reading the body",
            async (status) => {
                const text = jest.fn(async () => '{"jsonrpc":"2.0","id":1,"result":null}');
                const fetchLike: IFetchLike = async () => ({ status, text });
                const error = await rejection(new FiberRpcClient({ url: URL, fetch: fetchLike }).call("get_invoice", PARAMS, passThrough));
                expect(error).toBeInstanceOf(RpcTransportError);
                expect(error).toMatchObject({ method: "get_invoice", status, message: `get_invoice: HTTP status ${status}` });
                expect(text).not.toHaveBeenCalled();
            },
        );

        it("throws a status that is not an integer", async () => {
            const mock = new FetchMock().answer({ status: NaN, body: '{"jsonrpc":"2.0","id":1,"result":null}' });
            await expect(clientOf(mock).call("get_invoice", PARAMS, passThrough)).rejects.toBeInstanceOf(RpcTransportError);
        });

        it.each([200, 201, 204, 299])("reads the body of status %i", async (status) => {
            const mock = new FetchMock().answer({ status, body: '{"jsonrpc":"2.0","id":1,"result":null}' });
            await expect(clientOf(mock).call("get_invoice", PARAMS, passThrough)).resolves.toBeNull();
        });

        it("throws a body that cannot be read as an RpcTransportError, with the status", async () => {
            const cause = new Error("connection reset");
            const mock = new FetchMock().answer({ status: 200, bodyError: cause });
            const error = await rejection(clientOf(mock).call("send_payment", PARAMS, passThrough));
            expect(error).toBeInstanceOf(RpcTransportError);
            expect(error).toMatchObject({ status: 200, message: "send_payment: the response body could not be read", cause });
        });
    });

    it("never puts the token in an error", async () => {
        const mock = new FetchMock().answer(
            { rejection: new TypeError("fetch failed") },
            { status: 500, body: "" },
            { status: 200, bodyError: new Error("reset") },
            ok("not json"),
            ok('{"jsonrpc":"2.0","id":5,"error":{"code":-32999,"message":"Unauthorized"}}'),
        );
        const client = clientOf(mock, TOKEN);
        for (let call = 0; call < 5; call++) {
            const error = (await rejection(client.call("list_channels", {}, passThrough))) as Error;
            expect(`${error.message} ${String(error.cause)}`).not.toContain(TOKEN);
        }
    });
});
