import { hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../src/common";
import type { OpenChannelWithExternalFundingParams, SubmitSignedFundingTxParams } from "../../../src/rpc";
import {
    CHANNEL_STATE_FLAGS,
    FiberRpcClient,
    RpcError,
    RpcResponseError,
    decodeAbandonChannelResult,
    decodeChannelState,
    decodeListChannelsResult,
    decodeOpenChannelWithExternalFundingResult,
    decodeSubmitSignedFundingTxResult,
    encodeAbandonChannelParams,
    encodeListChannelsParams,
    encodeOpenChannelWithExternalFundingParams,
    encodeSubmitSignedFundingTxParams,
} from "../../../src/rpc";
import type { Field } from "../../../src/wire";
import { FetchMock } from "../../mocks/rpc";
import { caseOf } from "../../utils/interop-vectors";
import { refusal } from "../../utils/refusal";
import { rejection } from "../../utils/rejection";
import {
    toChannel,
    toChannelState,
    toOpenChannelWithExternalFundingResult,
    toSubmitSignedFundingTxParams,
    toSubmitSignedFundingTxResult,
} from "../../utils/rpc-typed";
import { loadRpcVectors } from "../../utils/rpc-vectors";
import { ABOVE_U64, ABOVE_U128, U64_MAX_HEX, U128_MAX_HEX } from "../../utils/uint-hex";
import { withField } from "../../utils/with-field";

const vectors = loadRpcVectors();
const { open_channel_with_external_funding: open, submit_signed_funding_tx: submit, list_channels: list } = vectors.methods;

const RESULT = "response.result";
const CHANNEL_ID = `0x${"11".repeat(32)}`;
const PEER = `02${"ab".repeat(32)}`;

function result(value: unknown): Field {
    return { value, path: RESULT };
}

const SHUTDOWN: Script = { codeHash: hexToBytes("9b".repeat(32)), hashType: "type", args: hexToBytes("42".repeat(20)) };
const FUNDING_LOCK: Script = { codeHash: hexToBytes("9b".repeat(32)), hashType: "type", args: hexToBytes("75".repeat(20)) };

const OPEN: OpenChannelWithExternalFundingParams = {
    peerPubkey: hexToBytes(PEER),
    fundingAmountShannons: "16000000000",
    public: false,
    shutdownScript: SHUTDOWN,
    fundingLockScript: FUNDING_LOCK,
};

const READY_CHANNEL = {
    channel_id: CHANNEL_ID,
    is_public: true,
    is_acceptor: false,
    is_one_way: false,
    channel_outpoint: `0x${"a3".repeat(36)}`,
    pubkey: PEER,
    funding_udt_type_script: null,
    state: { state_name: "ChannelReady" },
    local_balance: "0x12a05f200",
    offered_tlc_balance: "0x0",
    remote_balance: "0x3b9aca00",
    received_tlc_balance: "0x8f0d180",
    pending_tlcs: [],
    latest_commitment_transaction_hash: `0x${"66".repeat(32)}`,
    created_at: "0x191dd9dec00",
    enabled: true,
    tlc_expiry_delta: "0x5265c00",
    tlc_fee_proportional_millionths: "0x3e8",
    shutdown_transaction_hash: null,
    failure_detail: null,
};

const CLOSED_CHANNEL = {
    ...READY_CHANNEL,
    state: { state_name: "Closed", state_flags: "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT" },
    shutdown_transaction_hash: `0x${"5d".repeat(32)}`,
};

// A failed opening as `only_pending` synthesizes it: unfunded, told from a timeout by its detail alone.
const ABORTED_CHANNEL = {
    ...READY_CHANNEL,
    is_public: false,
    channel_outpoint: null,
    state: { state_name: "Closed", state_flags: "FUNDING_ABORTED" },
    remote_balance: "0x0",
    received_tlc_balance: "0x0",
    latest_commitment_transaction_hash: null,
    enabled: false,
    tlc_expiry_delta: "0x0",
    tlc_fee_proportional_millionths: "0x0",
    failure_detail: "Channel was abandoned",
};

const LISTING = { channels: [READY_CHANNEL, CLOSED_CHANNEL, ABORTED_CHANNEL] };

describe("open_channel_with_external_funding", () => {
    describe("encodeOpenChannelWithExternalFundingParams", () => {
        it("writes the client's closed subset, the pubkey bare and the amount in hex, leaving every option to the node", () => {
            const wire = encodeOpenChannelWithExternalFundingParams(OPEN);
            expect(wire).toEqual({
                pubkey: PEER,
                funding_amount: "0x3b9aca000",
                public: false,
                shutdown_script: { code_hash: `0x${"9b".repeat(32)}`, hash_type: "type", args: `0x${"42".repeat(20)}` },
                funding_lock_script: { code_hash: `0x${"9b".repeat(32)}`, hash_type: "type", args: `0x${"75".repeat(20)}` },
            });
            expect(Object.keys(wire)).toEqual(["pubkey", "funding_amount", "public", "shutdown_script", "funding_lock_script"]);
        });

        it("always sends public, true included, rather than inheriting fiber's default", () => {
            expect(encodeOpenChannelWithExternalFundingParams({ ...OPEN, public: true }).public).toBe(true);
        });

        it.each<[string, Partial<OpenChannelWithExternalFundingParams>, Error]>([
            ["a pubkey of 32 bytes", { peerPubkey: new Uint8Array(32) }, new TypeError("peerPubkey must be 33 bytes, got 32")],
            ["a pubkey as a string", { peerPubkey: PEER as unknown as Uint8Array }, new TypeError("peerPubkey must be a Uint8Array")],
            [
                "a fractional amount",
                { fundingAmountShannons: "1.0" },
                new TypeError("fundingAmountShannons must be an amount in decimal shannons"),
            ],
            [
                "an amount with a leading zero",
                { fundingAmountShannons: "01" },
                new TypeError("fundingAmountShannons must be an amount in decimal shannons"),
            ],
            [
                "an amount past a u128",
                { fundingAmountShannons: "340282366920938463463374607431768211456" },
                new TypeError("fundingAmountShannons must be an amount in decimal shannons"),
            ],
            ["a public that is not a boolean", { public: "true" as unknown as boolean }, new TypeError("public must be a boolean")],
            [
                "a shutdown script with a short code hash",
                { shutdownScript: { ...SHUTDOWN, codeHash: new Uint8Array(31) } },
                new TypeError("shutdownScript.codeHash must be 32 bytes, got 31"),
            ],
            [
                "a funding lock with an unknown hash type",
                { fundingLockScript: { ...FUNDING_LOCK, hashType: "data3" as Script["hashType"] } },
                new TypeError("fundingLockScript.hashType must be one of data, type, data1, data2"),
            ],
        ])("refuses %s", (_, change, expected) => {
            expect(() => encodeOpenChannelWithExternalFundingParams({ ...OPEN, ...change })).toThrow(expected);
        });
    });

    describe("decodeOpenChannelWithExternalFundingResult", () => {
        it.each(open.results.map((entry) => [entry.name, entry] as const))("reads the %s", (_, entry) => {
            expect(decodeOpenChannelWithExternalFundingResult(result(entry.json))).toEqual(
                toOpenChannelWithExternalFundingResult(entry.values),
            );
        });

        const json = caseOf(open.results, "ckb channel").json;

        it.each([
            ["channel_id", "11".repeat(32)],
            ["channel_id", `0x${"11".repeat(31)}`],
            ["channel_id", undefined],
            ["unsigned_funding_tx", undefined],
            ["unsigned_funding_tx.outputs[0].capacity", "6100000000"],
            ["unsigned_funding_tx.witnesses[0]", "0x5"],
        ])("refuses %s = %p, naming the field from the result", (path, value) => {
            expect(refusal(() => decodeOpenChannelWithExternalFundingResult(result(withField(json, path, value)))).path).toBe(
                `${RESULT}.${path}`,
            );
        });
    });
});

describe("submit_signed_funding_tx", () => {
    describe("encodeSubmitSignedFundingTxParams", () => {
        const params: SubmitSignedFundingTxParams = toSubmitSignedFundingTxParams(caseOf(submit.params, "ckb channel").values);

        it("writes the channel id as it is and the transaction in CKB's shape", () => {
            expect(encodeSubmitSignedFundingTxParams(params)).toEqual(caseOf(submit.params, "ckb channel").json);
        });

        it.each([
            ["a bare channel id", "11".repeat(32)],
            ["an uppercase channel id", `0x${"AA".repeat(32)}`],
            ["a channel id of 31 bytes", `0x${"11".repeat(31)}`],
            ["a padded channel id", `${CHANNEL_ID} `],
        ])("refuses %s", (_, channelId) => {
            expect(() => encodeSubmitSignedFundingTxParams({ ...params, channelId })).toThrow(
                new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
            );
        });

        it("refuses a transaction it cannot write, naming the field", () => {
            const signedFundingTx = withField(params.signedFundingTx, "outputs[0].lock.codeHash", new Uint8Array(31));
            expect(() => encodeSubmitSignedFundingTxParams({ ...params, signedFundingTx })).toThrow(
                new TypeError("signedFundingTx.outputs[0].lock.codeHash must be 32 bytes, got 31"),
            );
        });
    });

    describe("decodeSubmitSignedFundingTxResult", () => {
        it.each(submit.results.map((entry) => [entry.name, entry] as const))("reads the %s", (_, entry) => {
            expect(decodeSubmitSignedFundingTxResult(result(entry.json))).toEqual(toSubmitSignedFundingTxResult(entry.values));
        });

        const json = caseOf(submit.results, "submitted").json;

        it.each([
            ["channel_id", "11".repeat(32)],
            ["channel_id", undefined],
            ["funding_tx_hash", `0x${"c1".repeat(31)}`],
            ["funding_tx_hash", null],
        ])("refuses %s = %p", (path, value) => {
            expect(refusal(() => decodeSubmitSignedFundingTxResult(result(withField(json, path, value)))).path).toBe(`${RESULT}.${path}`);
        });

        it("refuses a result that is not an object", () => {
            expect(refusal(() => decodeSubmitSignedFundingTxResult(result(null))).path).toBe(RESULT);
        });
    });
});

describe("abandon_channel", () => {
    it("writes the channel id as it is", () => {
        expect(encodeAbandonChannelParams({ channelId: CHANNEL_ID })).toEqual({ channel_id: CHANNEL_ID });
    });

    it.each(["11".repeat(32), `0x${"11".repeat(33)}`])("refuses the channel id %p", (channelId) => {
        expect(() => encodeAbandonChannelParams({ channelId })).toThrow(
            new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
        );
    });

    it.each(vectors.methods.abandon_channel.results.map((entry) => [entry.name, entry] as const))("reads the %s null", (_, entry) => {
        expect(decodeAbandonChannelResult(result(entry.json))).toBeUndefined();
    });

    it.each([{}, undefined, true, "null"])("refuses %p", (value) => {
        expect(refusal(() => decodeAbandonChannelResult(result(value))).message).toBe(`${RESULT} must be null`);
    });
});

describe("list_channels", () => {
    describe("encodeListChannelsParams", () => {
        it("sends nothing for the default mode, and the one flag of a filter", () => {
            expect(encodeListChannelsParams({})).toEqual({});
            expect(encodeListChannelsParams({ filter: "include_closed" })).toEqual({ include_closed: true });
            expect(encodeListChannelsParams({ filter: "only_pending" })).toEqual({ only_pending: true });
        });

        it("refuses a filter fiber has no flag for", () => {
            expect(() => encodeListChannelsParams({ filter: "closed" as "include_closed" })).toThrow(
                new TypeError("filter must be one of include_closed, only_pending"),
            );
        });
    });

    describe("decodeListChannelsResult", () => {
        it.each(list.results.map((entry) => [entry.name, entry] as const))("reads the %s listing", (_, entry) => {
            expect(decodeListChannelsResult(result(entry.json))).toEqual(entry.values.channels.map(toChannel));
        });

        it("reads a literal listing field by field", () => {
            expect(decodeListChannelsResult(result(LISTING))).toEqual([
                {
                    channelId: CHANNEL_ID,
                    peerPubkey: hexToBytes(PEER),
                    fundingUdtTypeScript: null,
                    state: { name: "ChannelReady", flags: [] },
                    localBalanceShannons: "5000000000",
                    remoteBalanceShannons: "1000000000",
                    offeredTlcBalanceShannons: "0",
                    receivedTlcBalanceShannons: "150000000",
                    createdAtMs: 1726000000000n,
                    shutdownTransactionHash: null,
                    failureDetail: null,
                },
                {
                    channelId: CHANNEL_ID,
                    peerPubkey: hexToBytes(PEER),
                    fundingUdtTypeScript: null,
                    state: { name: "Closed", flags: ["UNCOOPERATIVE_LOCAL", "WAITING_ONCHAIN_SETTLEMENT"] },
                    localBalanceShannons: "5000000000",
                    remoteBalanceShannons: "1000000000",
                    offeredTlcBalanceShannons: "0",
                    receivedTlcBalanceShannons: "150000000",
                    createdAtMs: 1726000000000n,
                    shutdownTransactionHash: hexToBytes("5d".repeat(32)),
                    failureDetail: null,
                },
                {
                    channelId: CHANNEL_ID,
                    peerPubkey: hexToBytes(PEER),
                    fundingUdtTypeScript: null,
                    state: { name: "Closed", flags: ["FUNDING_ABORTED"] },
                    localBalanceShannons: "5000000000",
                    remoteBalanceShannons: "0",
                    offeredTlcBalanceShannons: "0",
                    receivedTlcBalanceShannons: "0",
                    createdAtMs: 1726000000000n,
                    shutdownTransactionHash: null,
                    failureDetail: "Channel was abandoned",
                },
            ]);
        });

        it("reads the largest balance and timestamp", () => {
            const [channel] = decodeListChannelsResult(
                result({ channels: [{ ...READY_CHANNEL, local_balance: U128_MAX_HEX, created_at: U64_MAX_HEX }] }),
            );
            expect(channel?.localBalanceShannons).toBe("340282366920938463463374607431768211455");
            expect(channel?.createdAtMs).toBe(2n ** 64n - 1n);
        });

        it("ignores the members it does not read, even malformed", () => {
            const loose = { ...READY_CHANNEL, pending_tlcs: "x", is_public: 1, channel_outpoint: 5, enabled: null, extra: {} };
            expect(decodeListChannelsResult(result({ channels: [loose] }))).toEqual(
                decodeListChannelsResult(result({ channels: [READY_CHANNEL] })),
            );
        });

        it.each([
            ["channels", undefined],
            ["channels", {}],
            ["channels[1]", "channel"],
            ["channels[0].channel_id", "11".repeat(32)],
            ["channels[0].channel_id", `0x${"11".repeat(31)}`],
            ["channels[0].channel_id", undefined],
            ["channels[0].pubkey", `0x${PEER}`],
            ["channels[0].pubkey", PEER.slice(2)],
            ["channels[0].pubkey", PEER.toUpperCase()],
            ["channels[0].pubkey", undefined],
            ["channels[0].funding_udt_type_script", undefined],
            ["channels[0].funding_udt_type_script", "0x"],
            ["channels[0].state", undefined],
            ["channels[0].state.state_name", "Opened"],
            ["channels[0].state.state_name", "channel_ready"],
            ["channels[0].state.state_name", undefined],
            ["channels[0].state.state_flags", ""],
            ["channels[0].state.state_flags", null],
            ["channels[0].state.state_flags", "CHANNEL_READY"],
            ["channels[1].state.state_flags", undefined],
            ["channels[1].state.state_flags", null],
            ["channels[1].state.state_flags", "COOPERATIVE|OUR_SHUTDOWN_SENT"],
            ["channels[1].state.state_flags", "COOPERATIVE|COOPERATIVE"],
            ["channels[1].state.state_flags", "ABANDONED|"],
            ["channels[0].local_balance", "5000000000"],
            ["channels[0].local_balance", "0x012a05f200"],
            ["channels[0].local_balance", ABOVE_U128],
            ["channels[0].local_balance", 5000000000],
            ["channels[0].remote_balance", undefined],
            ["channels[0].offered_tlc_balance", "0"],
            ["channels[0].received_tlc_balance", null],
            ["channels[0].created_at", ABOVE_U64],
            ["channels[0].created_at", "1726000000000"],
            ["channels[0].created_at", undefined],
            ["channels[0].shutdown_transaction_hash", undefined],
            ["channels[1].shutdown_transaction_hash", "5d".repeat(32)],
            ["channels[1].shutdown_transaction_hash", `0x${"5d".repeat(31)}`],
            ["channels[0].failure_detail", undefined],
            ["channels[2].failure_detail", 1],
        ])("refuses %s = %p, naming the field from the result", (path, value) => {
            expect(refusal(() => decodeListChannelsResult(result(withField(LISTING, path, value)))).path).toBe(`${RESULT}.${path}`);
        });

        it("refuses a result that is not an object", () => {
            expect(refusal(() => decodeListChannelsResult(result([READY_CHANNEL]))).message).toBe(`${RESULT} must be an object`);
        });
    });
});

describe("decodeChannelState", () => {
    function state(value: unknown): unknown {
        return decodeChannelState({ value, path: "state" });
    }

    it("reads each state the vectors carry as the name and the flags fiber wrote", () => {
        for (const entry of list.results) {
            entry.values.channels.forEach((channel, index) => {
                const json = (entry.json as { channels: { state: unknown }[] }).channels[index]?.state;
                expect(state(json)).toEqual(toChannelState(channel.state));
            });
        }
    });

    it.each(Object.entries(CHANNEL_STATE_FLAGS).filter(([, flags]) => flags.length > 0))(
        "reads every flag %s has, and none",
        (name, flags) => {
            expect(state({ state_name: name, state_flags: flags.join("|") })).toEqual({ name, flags: [...flags] });
            expect(state({ state_name: name, state_flags: "" })).toEqual({ name, flags: [] });
        },
    );

    it.each(["ChannelReady", "Stale"])("reads %s, which has no flags, only without state_flags", (name) => {
        expect(state({ state_name: name })).toEqual({ name, flags: [] });
        expect(refusal(() => state({ state_name: name, state_flags: "" })).message).toBe(`state.state_flags must be absent for ${name}`);
    });

    it("keeps a leaked composite as fiber wrote it", () => {
        expect(state({ state_name: "NegotiatingFunding", state_flags: "OUR_INIT_SENT|INIT_SENT" })).toEqual({
            name: "NegotiatingFunding",
            flags: ["OUR_INIT_SENT", "INIT_SENT"],
        });
    });

    it("refuses a flag of another state", () => {
        expect(refusal(() => state({ state_name: "ShuttingDown", state_flags: "COOPERATIVE" })).path).toBe("state.state_flags");
    });
});

describe("FiberRpcClient channel methods", () => {
    const URL = "http://fiber.example:8227";

    function answering(result: unknown): FetchMock {
        return new FetchMock().answer({ status: 200, body: JSON.stringify({ jsonrpc: "2.0", id: 1, result }) });
    }

    function sent(mock: FetchMock): unknown {
        return JSON.parse(mock.last.init.body);
    }

    it("opens a channel and reads the unsigned funding transaction", async () => {
        const entry = caseOf(open.results, "udt channel with deps");
        const mock = answering(entry.json);
        await expect(new FiberRpcClient({ url: URL, fetch: mock.fetch }).openChannelWithExternalFunding(OPEN)).resolves.toEqual(
            toOpenChannelWithExternalFundingResult(entry.values),
        );
        expect(sent(mock)).toEqual({
            jsonrpc: "2.0",
            id: 1,
            method: "open_channel_with_external_funding",
            params: [encodeOpenChannelWithExternalFundingParams(OPEN)],
        });
    });

    it("submits the signed funding transaction", async () => {
        const params = caseOf(submit.params, "udt channel with deps");
        const entry = caseOf(submit.results, "submitted");
        const mock = answering(entry.json);
        await expect(
            new FiberRpcClient({ url: URL, fetch: mock.fetch }).submitSignedFundingTx(toSubmitSignedFundingTxParams(params.values)),
        ).resolves.toEqual(toSubmitSignedFundingTxResult(entry.values));
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "submit_signed_funding_tx", params: [params.json] });
    });

    it("abandons a channel, resolving with nothing", async () => {
        const mock = answering(null);
        await expect(
            new FiberRpcClient({ url: URL, fetch: mock.fetch }).abandonChannel({ channelId: CHANNEL_ID }),
        ).resolves.toBeUndefined();
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "abandon_channel", params: [{ channel_id: CHANNEL_ID }] });
    });

    it("lists channels in the default mode when given nothing", async () => {
        const mock = answering(LISTING);
        await expect(new FiberRpcClient({ url: URL, fetch: mock.fetch }).listChannels()).resolves.toHaveLength(3);
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "list_channels", params: [{}] });
    });

    it("lists channels with the filter's flag", async () => {
        const mock = answering({ channels: [] });
        await expect(new FiberRpcClient({ url: URL, fetch: mock.fetch }).listChannels({ filter: "only_pending" })).resolves.toEqual([]);
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "list_channels", params: [{ only_pending: true }] });
    });

    it("refuses params it cannot write before sending anything", async () => {
        const mock = new FetchMock();
        const client = new FiberRpcClient({ url: URL, fetch: mock.fetch });
        await expect(client.abandonChannel({ channelId: "11" })).rejects.toThrow(TypeError);
        expect(mock.requests).toHaveLength(0);
    });

    it("passes the node's refusal through", async () => {
        const mock = new FetchMock().answer({
            status: 200,
            body: '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"only_pending and include_closed are mutually exclusive"}}',
        });
        const error = await rejection(new FiberRpcClient({ url: URL, fetch: mock.fetch }).listChannels());
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({ method: "list_channels", code: -32000 });
    });

    it("names the nested field of an answer it cannot read", async () => {
        const mock = answering(withField(LISTING, "channels[1].state.state_flags", "COOPERATIVE|SHUTDOWN"));
        const error = await rejection(new FiberRpcClient({ url: URL, fetch: mock.fetch }).listChannels());
        expect(error).toBeInstanceOf(RpcResponseError);
        expect(error).toMatchObject({ method: "list_channels", path: "response.result.channels[1].state.state_flags" });
    });
});
