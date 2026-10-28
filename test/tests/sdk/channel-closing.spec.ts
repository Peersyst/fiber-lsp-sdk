import { hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../src/common";
import type { PolicyChannelTerms } from "../../../src/policy";
import { PolicyEngine, SignerStore } from "../../../src/policy";
import { FiberRpcClient, RPC_CALL_FAILED_CODE, RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import type { SdkChannelClosingContext, SdkCloseOptions, SdkNetworkConfig } from "../../../src/sdk";
import { ActivityPoller, SDK_NETWORK_PRESETS, SdkError, closeSdkChannel } from "../../../src/sdk";
import { TimerMock } from "../../mocks/common";
import { InMemorySignerStorage } from "../../mocks/policy";
import type { SentCall } from "../../mocks/rpc";
import { ScriptedNode } from "../../mocks/rpc";
import { rejection } from "../../utils/rejection";
import { storedAt, writes } from "../../utils/stored-records";

const URL = "http://127.0.0.1:8227";
const CHANNEL_ID = "0x5df11183f0223c41ea85677270eeaf085d3d2fa00f4a35b1b870b7af25b0287f";
const UNKNOWN_ID = `0x${"5a".repeat(32)}`;
const INDEX = 1_791_367_200;
const AMOUNT = "72000000000";
const UINT64_MAX = 18_446_744_073_709_551_615n;

const RECORD_KEY = `fiber-lsp-sdk:channel:${INDEX}`;

// The close only reads the channel's alias and its record.
const RECORD_READS = [`get fiber-lsp-sdk:alias:${CHANNEL_ID}`, `get ${RECORD_KEY}`];

const PEER_FUNDING_PUBKEY = "026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638";
const PEER_TLC_BASE_PUBKEY = "032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21";

const USER_LOCK: Script = {
    codeHash: hexToBytes("537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d769"),
    hashType: "type",
    args: hexToBytes("8d66477ba3b60a96feb27a3f57fe11f6697be87d"),
};
const USER_LOCK_WIRE = {
    code_hash: "0x537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d769",
    hash_type: "type",
    args: "0x8d66477ba3b60a96feb27a3f57fe11f6697be87d",
};
const PEER_LOCK: Script = {
    codeHash: hexToBytes("4d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba"),
    hashType: "type",
    args: hexToBytes("8f1e030962418183dc890ef5664b1f2a64b0064c"),
};

const TERMS: PolicyChannelTerms = {
    commitmentFeeRate: 1000n,
    remoteReservedCkbShannons: "10000000000",
    liquidCapacityShannons: "80500000000",
    remoteCloseScript: PEER_LOCK,
    remoteFundingPubkey: hexToBytes(PEER_FUNDING_PUBKEY),
    remoteTlcBasePubkey: hexToBytes(PEER_TLC_BASE_PUBKEY),
    commitmentDelayEpoch: 0x10000000001n,
};

// With USER_LOCK and PEER_LOCK, testnet's two cell deps size the close at 528 bytes, so the device's fee is
// floor(rate * 528 / 1000): this rate's is 100000000 shannons, the most a close's fee may take, and the next one's 100000001.
const LAST_ACCEPTED_RATE = 189_393_941n;
const FIRST_REFUSED_RATE = 189_393_942n;

const CLOSE_CALL: SentCall = { method: "shutdown_channel", params: { channel_id: CHANNEL_ID, close_script: USER_LOCK_WIRE } };

// Fiber's refusals of a close: a TLC of the device's out, a close already under way, and a channel whose close is confirmed,
// whose actor has stopped (`fiber/channel.rs:2726-2767`, `fiber/network.rs:8076-8093`).
const PENDING_TLCS = "Invalid state: Unable to process shutdown command, as there are pending outbound tlcs";
const SHUTTING_DOWN =
    "Invalid state: Trying to send shutdown message while in invalid state ShuttingDown(ShuttingDownFlags(OUR_SHUTDOWN_SENT | THEIR_SHUTDOWN_SENT))";
const NOT_FOUND = `Channel not found error: Hash256(${CHANNEL_ID})`;

type Harness = {
    storage: InMemorySignerStorage;
    node: ScriptedNode;
    pollNow: jest.SpyInstance<void, []>;
    context: SdkChannelClosingContext;
};

function harness(network: SdkNetworkConfig = SDK_NETWORK_PRESETS.testnet): Harness {
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    const node = new ScriptedNode();
    const poller = new ActivityPoller({
        timer: new TimerMock(),
        intervalMs: 5_000,
        stepTimeoutMs: 30_000,
        steps: [],
        emit: () => undefined,
    });
    const pollNow = jest.spyOn(poller, "pollNow");
    const context: SdkChannelClosingContext = {
        network,
        store,
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
        poller,
    };
    return { storage, node, pollNow, context };
}

async function opened(network?: SdkNetworkConfig, terms: PolicyChannelTerms = TERMS, userLock: Script = USER_LOCK): Promise<Harness> {
    const h = harness(network);
    const policy = new PolicyEngine(h.context.store);
    await policy.registerChannel(CHANNEL_ID, INDEX, AMOUNT, userLock);
    await policy.pinChannelTerms(CHANNEL_ID, terms);
    h.storage.ops.splice(0);
    return h;
}

function closeCall(sent: Record<string, unknown>): SentCall {
    return { method: "shutdown_channel", params: { channel_id: CHANNEL_ID, close_script: USER_LOCK_WIRE, ...sent } };
}

function feeTooHigh(rate: bigint, fee: bigint): SdkError {
    return new SdkError(
        "close_fee_too_high",
        `the device refuses the close: at ${rate} shannons per kilobyte its fee is ${fee}, more than the 100000000 a close's fee may take`,
    );
}

// `toEqual` compares an error's message alone.
function expectSdkError(error: unknown, expected: SdkError): void {
    expect(error).toBeInstanceOf(SdkError);
    expect(error).toEqual(expected);
    expect((error as SdkError).code).toBe(expected.code);
}

function editPins(h: Harness, edit: (pins: Record<string, unknown>) => Record<string, unknown>): void {
    const record = storedAt(h.storage, RECORD_KEY) as { pins: Record<string, unknown> };
    h.storage.map.set(RECORD_KEY, JSON.stringify({ ...record, pins: edit(record.pins) }));
}

function withoutPin(pins: Record<string, unknown>, field: string): Record<string, unknown> {
    return Object.fromEntries(Object.entries(pins).filter(([name]) => name !== field));
}

function expectNothingAsked(h: Harness): void {
    expect(h.node.calls()).toEqual([]);
    expect(writes(h.storage)).toEqual([]);
    expect(h.pollNow).not.toHaveBeenCalled();
}

describe("closeSdkChannel", () => {
    it("asks the node to close, paying the device's share to its pinned close script at fiber's default fee rate", async () => {
        const h = await opened();
        h.node.result(null);
        await expect(closeSdkChannel(h.context, CHANNEL_ID)).resolves.toBeUndefined();
        expect(h.node.calls()).toEqual([CLOSE_CALL]);
    });

    it("sends the host's fee rate as fee_rate", async () => {
        const h = await opened();
        h.node.result(null);
        await closeSdkChannel(h.context, CHANNEL_ID, { feeRate: 2000n });
        expect(h.node.calls()).toEqual([closeCall({ fee_rate: "0x7d0" })]);
    });

    it("reads the channel's record alone, writing nothing, and asks the poller for a tick once the node took the close", async () => {
        const h = await opened();
        let polls: number | undefined;
        h.node.onCall("shutdown_channel", () => {
            polls = h.pollNow.mock.calls.length;
        });
        h.node.result(null);
        await closeSdkChannel(h.context, CHANNEL_ID);
        expect(polls).toBe(0);
        expect(h.pollNow).toHaveBeenCalledTimes(1);
        expect(h.storage.ops).toEqual(RECORD_READS);
    });

    describe("the arguments", () => {
        it.each<[string, unknown]>([
            ["a channel id without the prefix", CHANNEL_ID.slice(2)],
            ["an uppercase channel id", CHANNEL_ID.toUpperCase().replace("0X", "0x")],
            ["a channel id a byte short", CHANNEL_ID.slice(0, -2)],
            ["a channel id one byte long", "0x5d"],
            ["a channel id that is not a string", hexToBytes(CHANNEL_ID.slice(2))],
            ["no channel id", undefined],
        ])("refuses %s before reading the store", async (_, channelId) => {
            const h = await opened();
            const error = await rejection(closeSdkChannel(h.context, channelId as string));
            expect(error).toEqual(new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"));
            expect(error).toBeInstanceOf(TypeError);
            expect(h.storage.ops).toEqual([]);
            expectNothingAsked(h);
        });

        it("refuses the channel id before the options", async () => {
            const h = await opened();
            const error = await rejection(closeSdkChannel(h.context, CHANNEL_ID.slice(2), { feeRate: -1n }));
            expect(error).toEqual(new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"));
            expect(error).toBeInstanceOf(TypeError);
            expect(h.storage.ops).toEqual([]);
            expectNothingAsked(h);
        });

        it.each<[string, unknown]>([
            ["null", null],
            ["a list", [2000n]],
            ["a string", "2000"],
            ["a bigint", 2000n],
        ])("refuses options that are %s before reading the store", async (_, options) => {
            const h = await opened();
            const error = await rejection(closeSdkChannel(h.context, CHANNEL_ID, options as SdkCloseOptions));
            expect(error).toEqual(new TypeError("options must be an object"));
            expect(error).toBeInstanceOf(TypeError);
            expect(h.storage.ops).toEqual([]);
            expectNothingAsked(h);
        });

        it.each<[string, unknown]>([
            ["negative", -1n],
            ["past a u64", UINT64_MAX + 1n],
            ["a number", 2000],
            ["a number that is not an integer", 2000.5],
            ["a decimal string", "2000"],
            ["null", null],
        ])("refuses a fee rate that is %s before reading the store", async (_, feeRate) => {
            const h = await opened();
            const error = await rejection(closeSdkChannel(h.context, CHANNEL_ID, { feeRate } as SdkCloseOptions));
            expect(error).toEqual(new RangeError(`options.feeRate must be a bigint between 0 and ${UINT64_MAX}, got ${String(feeRate)}`));
            expect(error).toBeInstanceOf(RangeError);
            expect(h.storage.ops).toEqual([]);
            expectNothingAsked(h);
        });

        it.each<[string, SdkCloseOptions]>([
            ["empty options", {}],
            ["a fee rate left undefined", { feeRate: undefined }],
        ])("takes %s as fiber's default fee rate, sending none", async (_, options) => {
            const h = await opened();
            h.node.result(null);
            await closeSdkChannel(h.context, CHANNEL_ID, options);
            expect(h.node.calls()).toEqual([CLOSE_CALL]);
        });

        it("sends a fee rate of 0, below the commitment's, for fiber to refuse", async () => {
            const h = await opened();
            h.node.result(null);
            await closeSdkChannel(h.context, CHANNEL_ID, { feeRate: 0n });
            expect(h.node.calls()).toEqual([closeCall({ fee_rate: "0x0" })]);
        });

        it("reads the host's fee rate once, so the rate checked is the one sent", async () => {
            const h = await opened();
            let reads = 0;
            const options = {
                get feeRate(): bigint {
                    reads += 1;
                    return reads === 1 ? 2000n : FIRST_REFUSED_RATE;
                },
            };
            h.node.result(null);
            await closeSdkChannel(h.context, CHANNEL_ID, options);
            expect(reads).toBe(1);
            expect(h.node.calls()).toEqual([closeCall({ fee_rate: "0x7d0" })]);
        });
    });

    describe("the channel", () => {
        it("refuses a channel this device never registered as unknown_channel", async () => {
            const h = await opened();
            expectSdkError(
                await rejection(closeSdkChannel(h.context, UNKNOWN_ID)),
                new SdkError("unknown_channel", `channel ${UNKNOWN_ID} is not registered on this device`),
            );
            expectNothingAsked(h);
        });

        it("refuses a channel registered without its terms, which only a store that failed in its opening leaves", async () => {
            const h = harness();
            await new PolicyEngine(h.context.store).registerChannel(CHANNEL_ID, INDEX, AMOUNT, USER_LOCK);
            h.storage.ops.splice(0);
            const error = await rejection(closeSdkChannel(h.context, CHANNEL_ID, { feeRate: 2000n }));
            expect(error).toEqual(new TypeError(`channel ${CHANNEL_ID} pins no remoteCloseScript to check its close against`));
            expect(error).toBeInstanceOf(TypeError);
            expectNothingAsked(h);
        });

        it("refuses a channel that pins no commitment fee rate when the host gives none", async () => {
            const h = await opened();
            editPins(h, (pins) => withoutPin(pins, "commitmentFeeRate"));
            const error = await rejection(closeSdkChannel(h.context, CHANNEL_ID));
            expect(error).toEqual(new TypeError(`channel ${CHANNEL_ID} pins no commitmentFeeRate to check its close against`));
            expect(error).toBeInstanceOf(TypeError);
            expectNothingAsked(h);
        });

        it("closes a channel that pins no commitment fee rate at the host's rate", async () => {
            const h = await opened();
            editPins(h, (pins) => withoutPin(pins, "commitmentFeeRate"));
            h.node.result(null);
            await closeSdkChannel(h.context, CHANNEL_ID, { feeRate: 2000n });
            expect(h.node.calls()).toEqual([closeCall({ fee_rate: "0x7d0" })]);
        });

        it.each<[string, string, string]>([
            ["remoteCloseScript", "the peer's", "remoteCloseScript must be exactly as long as its size says"],
            ["localCloseScript", "the device's", "localCloseScript must be exactly as long as its size says"],
        ])("refuses a pinned %s that is not a script, %s close script, by the decoder's refusal", async (field, _, message) => {
            const h = await opened();
            editPins(h, (pins) => ({ ...pins, [field]: "00" }));
            const error = await rejection(closeSdkChannel(h.context, CHANNEL_ID));
            expect(error).toEqual(new TypeError(message));
            expect(error).toBeInstanceOf(TypeError);
            expectNothingAsked(h);
        });
    });

    describe("the fee", () => {
        it("sends the last fee rate whose fee a close may take", async () => {
            const h = await opened();
            h.node.result(null);
            await closeSdkChannel(h.context, CHANNEL_ID, { feeRate: LAST_ACCEPTED_RATE });
            expect(h.node.calls()).toEqual([closeCall({ fee_rate: "0xb49ec15" })]);
        });

        it.each<[string, bigint, bigint]>([
            ["the first fee rate whose fee a close may not take", FIRST_REFUSED_RATE, 100_000_001n],
            ["a u64's whole fee rate", UINT64_MAX, 9_739_880_870_918_643_252n],
        ])("refuses %s as close_fee_too_high, sending nothing", async (_, feeRate, fee) => {
            const h = await opened();
            expectSdkError(await rejection(closeSdkChannel(h.context, CHANNEL_ID, { feeRate })), feeTooHigh(feeRate, fee));
            expectNothingAsked(h);
        });

        it("takes the pinned commitment fee rate, fiber's default, when the host gives none: the last it accepts", async () => {
            const h = await opened(undefined, { ...TERMS, commitmentFeeRate: LAST_ACCEPTED_RATE });
            h.node.result(null);
            await closeSdkChannel(h.context, CHANNEL_ID);
            expect(h.node.calls()).toEqual([CLOSE_CALL]);
        });

        it("takes the pinned commitment fee rate when the host gives none: the first it refuses", async () => {
            const h = await opened(undefined, { ...TERMS, commitmentFeeRate: FIRST_REFUSED_RATE });
            expectSdkError(await rejection(closeSdkChannel(h.context, CHANNEL_ID)), feeTooHigh(FIRST_REFUSED_RATE, 100_000_001n));
            expectNothingAsked(h);
        });

        it("judges a fee rate of 0 the host gives, not the pinned one it would refuse, and sends it", async () => {
            const h = await opened(undefined, { ...TERMS, commitmentFeeRate: FIRST_REFUSED_RATE });
            h.node.result(null);
            await closeSdkChannel(h.context, CHANNEL_ID, { feeRate: 0n });
            expect(h.node.calls()).toEqual([closeCall({ fee_rate: "0x0" })]);
        });

        it("judges the host's fee rate, not the pinned one, when both are there", async () => {
            const h = await opened(undefined, { ...TERMS, commitmentFeeRate: FIRST_REFUSED_RATE });
            h.node.result(null);
            await closeSdkChannel(h.context, CHANNEL_ID, { feeRate: LAST_ACCEPTED_RATE });
            expect(h.node.calls()).toEqual([closeCall({ fee_rate: "0xb49ec15" })]);
        });

        it("sizes the close over the network's funding lock cell deps: one fewer leaves the first refused rate's fee in bounds", async () => {
            const h = await opened({ ...SDK_NETWORK_PRESETS.testnet, fundingLockCellDepsCount: 1 });
            h.node.result(null);
            await closeSdkChannel(h.context, CHANNEL_ID, { feeRate: FIRST_REFUSED_RATE });
            expect(h.node.calls()).toEqual([closeCall({ fee_rate: "0xb49ec16" })]);
        });

        it.each<[string, () => Promise<Harness>]>([
            [
                "the peer's pinned close script",
                () => opened(undefined, { ...TERMS, remoteCloseScript: { ...PEER_LOCK, args: new Uint8Array(21) } }),
            ],
            ["the device's pinned close script", () => opened(undefined, TERMS, { ...USER_LOCK, args: new Uint8Array(21) })],
        ])("sizes the close over %s: a byte more of args takes the last accepted rate's fee out of bounds", async (_, build) => {
            const h = await build();
            const error = await rejection(closeSdkChannel(h.context, CHANNEL_ID, { feeRate: LAST_ACCEPTED_RATE }));
            expectSdkError(error, feeTooHigh(LAST_ACCEPTED_RATE, 100_189_394n));
            expectNothingAsked(h);
        });

        it("refuses a fee rate whose fee no u64 holds, as fiber does, with the fee's RangeError", async () => {
            // A peer's close script of 1000 bytes of args sizes the close at 1508 bytes.
            const h = await opened(undefined, { ...TERMS, remoteCloseScript: { ...PEER_LOCK, args: new Uint8Array(1000) } });
            const error = await rejection(closeSdkChannel(h.context, CHANNEL_ID, { feeRate: UINT64_MAX }));
            expect(error).toEqual(new RangeError(`fee must be a bigint between 0 and ${UINT64_MAX}, got 27817690063154003835`));
            expect(error).toBeInstanceOf(RangeError);
            expectNothingAsked(h);
        });
    });

    describe("the storage", () => {
        it.each<[string, string]>([
            ["the alias", `fiber-lsp-sdk:alias:${CHANNEL_ID}`],
            ["the record", RECORD_KEY],
        ])("passes through a failed read of %s, asking the node nothing", async (_, key) => {
            const h = await opened();
            const failure = new Error("storage offline");
            const get = h.storage.get.bind(h.storage);
            jest.spyOn(h.storage, "get").mockImplementation((asked: string) => {
                if (asked === key) throw failure;
                return get(asked);
            });
            expect(await rejection(closeSdkChannel(h.context, CHANNEL_ID))).toBe(failure);
            expectNothingAsked(h);
        });
    });

    describe("the node's refusal", () => {
        it.each<[string, string]>([
            ["a TLC of the device's out", PENDING_TLCS],
            ["a close already under way", SHUTTING_DOWN],
            ["a channel whose close is confirmed", NOT_FOUND],
        ])("comes through unwrapped for %s, writing nothing and asking no tick", async (_, message) => {
            const h = await opened();
            h.node.error(RPC_CALL_FAILED_CODE, message);
            const error = await rejection(closeSdkChannel(h.context, CHANNEL_ID));
            expect(error).toBeInstanceOf(RpcError);
            expect(error).toMatchObject({ method: "shutdown_channel", code: RPC_CALL_FAILED_CODE, message });
            expect(h.node.calls()).toEqual([CLOSE_CALL]);
            expect(h.storage.ops).toEqual(RECORD_READS);
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it.each<[string, (h: Harness) => void, new (...args: never[]) => Error]>([
            ["a transport failure", (h) => h.node.reject(new Error("offline")), RpcTransportError],
            ["an answer that is not null", (h) => h.node.result(true), RpcResponseError],
            ["fiber's lost actor reply", (h) => h.node.error(RPC_CALL_FAILED_CODE, "Messaging failed because channel is closed"), RpcError],
        ])("comes through unwrapped for %s, which may have closed, writing nothing and asking no tick", async (_, answer, errorClass) => {
            const h = await opened();
            answer(h);
            expect(await rejection(closeSdkChannel(h.context, CHANNEL_ID))).toBeInstanceOf(errorClass);
            expect(h.node.calls()).toEqual([CLOSE_CALL]);
            expect(h.storage.ops).toEqual(RECORD_READS);
            expect(h.pollNow).not.toHaveBeenCalled();
        });
    });
});
