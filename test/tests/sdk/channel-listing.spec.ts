import { SignerStore } from "../../../src/policy";
import { FiberRpcClient, RPC_CHANNEL_STATE_NAMES, RpcError, RpcResponseError } from "../../../src/rpc";
import type { SdkChannelInfo } from "../../../src/sdk";
import { SDK_CHANNEL_STATES, listSdkChannels } from "../../../src/sdk";
import { InMemorySignerStorage } from "../../mocks/policy";
import { ScriptedNode } from "../../mocks/rpc";
import { rejection } from "../../utils/rejection";
import { LIST_CHANNELS_WITH_CLOSED_CALL } from "../../utils/rpc-answers";

const URL = "http://127.0.0.1:8227";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const OTHER_ID = `0x${"2e".repeat(32)}`;
const PEER = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

const READY_CHANNEL = {
    channel_id: CHANNEL_ID,
    is_public: false,
    is_acceptor: false,
    is_one_way: false,
    channel_outpoint: `0x${"a3".repeat(36)}`,
    pubkey: PEER,
    funding_udt_type_script: null,
    state: { state_name: "ChannelReady" },
    local_balance: "0x12a05f200",
    offered_tlc_balance: "0x5f5e100",
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

const READY_INFO: SdkChannelInfo = {
    channelId: CHANNEL_ID,
    state: "ready",
    localBalanceShannons: "5000000000",
    remoteBalanceShannons: "1000000000",
    offeredTlcBalanceShannons: "100000000",
    receivedTlcBalanceShannons: "150000000",
    hasRecord: false,
};

// One row per fiber state, so a state added to rpc and not here fails the coverage check below.
const STATES: [string, unknown, SdkChannelInfo["state"]][] = [
    ["NegotiatingFunding", { state_name: "NegotiatingFunding", state_flags: "AWAITING_EXTERNAL_FUNDING" }, "opening"],
    ["CollaboratingFundingTx", { state_name: "CollaboratingFundingTx", state_flags: "OUR_TX_COMPLETE_SENT" }, "opening"],
    [
        "SigningCommitment",
        { state_name: "SigningCommitment", state_flags: "OUR_COMMITMENT_SIGNED_SENT|THEIR_COMMITMENT_SIGNED_SENT|COMMITMENT_SIGNED_SENT" },
        "opening",
    ],
    ["AwaitingTxSignatures", { state_name: "AwaitingTxSignatures", state_flags: "THEIR_TX_SIGNATURES_SENT" }, "opening"],
    ["AwaitingChannelReady", { state_name: "AwaitingChannelReady", state_flags: "OUR_CHANNEL_READY" }, "opening"],
    ["ChannelReady", { state_name: "ChannelReady" }, "ready"],
    ["ShuttingDown", { state_name: "ShuttingDown", state_flags: "OUR_SHUTDOWN_SENT" }, "closing"],
    ["Closed", { state_name: "Closed", state_flags: "FUNDING_ABORTED" }, "closed"],
    ["Stale", { state_name: "Stale" }, "stale"],
];

function harness() {
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    const node = new ScriptedNode();
    return { node, storage, store, rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }) };
}

describe("listSdkChannels", () => {
    it("pins the five states a wallet shows, each one some fiber state maps to", () => {
        expect(SDK_CHANNEL_STATES).toEqual(["opening", "ready", "closing", "closed", "stale"]);
        expect(new Set(STATES.map(([, , state]) => state))).toEqual(new Set(SDK_CHANNEL_STATES));
    });

    it("covers every state fiber writes", () => {
        expect(STATES.map(([name]) => name)).toEqual([...RPC_CHANNEL_STATE_NAMES]);
    });

    it.each(STATES)("maps %s", async (_, state, expected) => {
        const h = harness();
        h.node.result({ channels: [{ ...READY_CHANNEL, state }] });
        await expect(listSdkChannels(h.rpc, h.store)).resolves.toStrictEqual([{ ...READY_INFO, state: expected }]);
    });

    it("asks the node for its channels with the closed ones included, copying the balances in decimal shannons", async () => {
        const h = harness();
        h.node.result({ channels: [READY_CHANNEL] });
        await expect(listSdkChannels(h.rpc, h.store)).resolves.toStrictEqual([READY_INFO]);
        expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
    });

    it("keeps each channel's own balances, in the node's order", async () => {
        const h = harness();
        h.node.result({
            channels: [
                {
                    ...READY_CHANNEL,
                    channel_id: OTHER_ID,
                    local_balance: "0x0",
                    remote_balance: "0x1",
                    offered_tlc_balance: "0x2",
                    received_tlc_balance: "0x3",
                },
                READY_CHANNEL,
            ],
        });
        await expect(listSdkChannels(h.rpc, h.store)).resolves.toStrictEqual([
            {
                ...READY_INFO,
                channelId: OTHER_ID,
                localBalanceShannons: "0",
                remoteBalanceShannons: "1",
                offeredTlcBalanceShannons: "2",
                receivedTlcBalanceShannons: "3",
            },
            READY_INFO,
        ]);
    });

    it("copies the largest u128 balance whole", async () => {
        const h = harness();
        const max = "0xffffffffffffffffffffffffffffffff";
        h.node.result({ channels: [{ ...READY_CHANNEL, local_balance: max }] });
        await expect(listSdkChannels(h.rpc, h.store)).resolves.toStrictEqual([
            { ...READY_INFO, localBalanceShannons: "340282366920938463463374607431768211455" },
        ]);
    });

    it("tells the channels this device registered from the others", async () => {
        const h = harness();
        await h.store.claimChannelAlias(CHANNEL_ID, 1_790_812_800);
        h.node.result({ channels: [READY_CHANNEL, { ...READY_CHANNEL, channel_id: OTHER_ID }] });
        await expect(listSdkChannels(h.rpc, h.store)).resolves.toStrictEqual([
            { ...READY_INFO, hasRecord: true },
            { ...READY_INFO, channelId: OTHER_ID, hasRecord: false },
        ]);
        expect(h.storage.ops.filter((op) => op.startsWith("set "))).toEqual([`set fiber-lsp-sdk:alias:${CHANNEL_ID}`]);
    });

    it("lists nothing when the node has no channel", async () => {
        const h = harness();
        h.node.result({ channels: [] });
        await expect(listSdkChannels(h.rpc, h.store)).resolves.toStrictEqual([]);
    });

    it("rejects with the node's own error", async () => {
        const h = harness();
        h.node.error(-32000, "internal error");
        const error = await rejection(listSdkChannels(h.rpc, h.store));
        expect(error).toBeInstanceOf(RpcError);
        expect((error as RpcError).message).toBe("internal error");
    });

    it("rejects a state this SDK does not know, rather than guess its kind", async () => {
        const h = harness();
        h.node.result({ channels: [{ ...READY_CHANNEL, state: { state_name: "Splicing" } }] });
        await expect(listSdkChannels(h.rpc, h.store)).rejects.toBeInstanceOf(RpcResponseError);
    });

    it("rejects with the store's error when a registration cannot be read", async () => {
        const h = harness();
        h.storage.map.set(`fiber-lsp-sdk:alias:${CHANNEL_ID}`, "-1");
        h.node.result({ channels: [READY_CHANNEL] });
        await expect(listSdkChannels(h.rpc, h.store)).rejects.toThrow(
            new TypeError(`stored value at fiber-lsp-sdk:alias:${CHANNEL_ID} is not a channel index`),
        );
    });
});
