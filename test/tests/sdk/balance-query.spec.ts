import { SignerStore } from "../../../src/policy";
import { FiberRpcClient, RpcError } from "../../../src/rpc";
import { getSdkBalance } from "../../../src/sdk";
import { InMemorySignerStorage } from "../../mocks/policy";
import { ScriptedNode } from "../../mocks/rpc";
import { rejection } from "../../utils/rejection";
import { LIST_CHANNELS_WITH_CLOSED_CALL } from "../../utils/rpc-answers";

const URL = "http://127.0.0.1:8227";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const OTHER_ID = `0x${"2e".repeat(32)}`;
const THIRD_ID = `0x${"3d".repeat(32)}`;
const PEER = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const U128_MAX = "0xffffffffffffffffffffffffffffffff";

// 5000000000 local, 100000000 offered: 4900000000 spendable.
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

// 1000000000 local, nothing offered.
const OTHER_CHANNEL = { ...READY_CHANNEL, channel_id: OTHER_ID, local_balance: "0x3b9aca00", offered_tlc_balance: "0x0" };

const NOT_READY_STATES: [string, unknown][] = [
    ["NegotiatingFunding", { state_name: "NegotiatingFunding", state_flags: "AWAITING_EXTERNAL_FUNDING" }],
    ["CollaboratingFundingTx", { state_name: "CollaboratingFundingTx", state_flags: "OUR_TX_COMPLETE_SENT" }],
    ["SigningCommitment", { state_name: "SigningCommitment", state_flags: "OUR_COMMITMENT_SIGNED_SENT" }],
    ["AwaitingTxSignatures", { state_name: "AwaitingTxSignatures", state_flags: "THEIR_TX_SIGNATURES_SENT" }],
    ["AwaitingChannelReady", { state_name: "AwaitingChannelReady", state_flags: "OUR_CHANNEL_READY" }],
    ["ShuttingDown", { state_name: "ShuttingDown", state_flags: "OUR_SHUTDOWN_SENT" }],
    ["Closed", { state_name: "Closed", state_flags: "COOPERATIVE" }],
    ["Stale", { state_name: "Stale" }],
];

async function harness(...registered: string[]) {
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    for (const [index, channelId] of registered.entries()) await store.claimChannelAlias(channelId, index);
    const node = new ScriptedNode();
    return { node, storage, store, rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }) };
}

describe("getSdkBalance", () => {
    it("takes a ready registered channel's offered TLCs out of its local balance", async () => {
        const h = await harness(CHANNEL_ID);
        h.node.result({ channels: [READY_CHANNEL] });
        await expect(getSdkBalance(h.rpc, h.store)).resolves.toBe("4900000000");
        expect(h.node.calls()).toEqual([LIST_CHANNELS_WITH_CLOSED_CALL]);
    });

    it("sums every ready registered channel", async () => {
        const h = await harness(CHANNEL_ID, OTHER_ID);
        h.node.result({ channels: [READY_CHANNEL, OTHER_CHANNEL] });
        await expect(getSdkBalance(h.rpc, h.store)).resolves.toBe("5900000000");
    });

    it("leaves out a ready channel this device never registered", async () => {
        const h = await harness(OTHER_ID);
        h.node.result({ channels: [READY_CHANNEL, OTHER_CHANNEL] });
        await expect(getSdkBalance(h.rpc, h.store)).resolves.toBe("1000000000");
    });

    it.each(NOT_READY_STATES)("leaves out a registered channel in %s", async (_, state) => {
        const h = await harness(CHANNEL_ID, OTHER_ID);
        h.node.result({ channels: [{ ...READY_CHANNEL, state }, OTHER_CHANNEL] });
        await expect(getSdkBalance(h.rpc, h.store)).resolves.toBe("1000000000");
    });

    it("counts a channel whose offered TLCs exceed its local balance as zero, not against the others", async () => {
        const h = await harness(CHANNEL_ID, OTHER_ID);
        h.node.result({ channels: [READY_CHANNEL, { ...OTHER_CHANNEL, local_balance: "0x5f5e100", offered_tlc_balance: "0x12a05f200" }] });
        await expect(getSdkBalance(h.rpc, h.store)).resolves.toBe("4900000000");
    });

    it("counts a channel whose offered TLCs are its whole local balance as zero", async () => {
        const h = await harness(CHANNEL_ID, OTHER_ID);
        h.node.result({ channels: [{ ...READY_CHANNEL, offered_tlc_balance: "0x12a05f200" }, OTHER_CHANNEL] });
        await expect(getSdkBalance(h.rpc, h.store)).resolves.toBe("1000000000");
    });

    it("sums past the largest u128 without losing a shannon", async () => {
        const h = await harness(CHANNEL_ID, OTHER_ID, THIRD_ID);
        h.node.result({
            channels: [
                { ...READY_CHANNEL, local_balance: U128_MAX, offered_tlc_balance: "0x0" },
                { ...OTHER_CHANNEL, local_balance: U128_MAX },
                { ...READY_CHANNEL, channel_id: THIRD_ID, local_balance: "0x0", offered_tlc_balance: "0x0" },
            ],
        });
        await expect(getSdkBalance(h.rpc, h.store)).resolves.toBe("680564733841876926926749214863536422910");
    });

    it("is zero when the node has no channel", async () => {
        const h = await harness();
        h.node.result({ channels: [] });
        await expect(getSdkBalance(h.rpc, h.store)).resolves.toBe("0");
    });

    it("is zero when no channel is spendable", async () => {
        const h = await harness(CHANNEL_ID);
        h.node.result({ channels: [{ ...READY_CHANNEL, state: { state_name: "Stale" } }, OTHER_CHANNEL] });
        await expect(getSdkBalance(h.rpc, h.store)).resolves.toBe("0");
    });

    it("writes nothing", async () => {
        const h = await harness(CHANNEL_ID);
        const before = [...h.storage.ops];
        h.node.result({ channels: [READY_CHANNEL, OTHER_CHANNEL] });
        await getSdkBalance(h.rpc, h.store);
        expect(h.storage.ops.slice(before.length).filter((op) => !op.startsWith("get "))).toEqual([]);
    });

    it("rejects with the node's own error", async () => {
        const h = await harness();
        h.node.error(-32000, "internal error");
        const error = await rejection(getSdkBalance(h.rpc, h.store));
        expect(error).toBeInstanceOf(RpcError);
        expect((error as RpcError).message).toBe("internal error");
    });

    it("rejects with the store's error when a registration cannot be read", async () => {
        const h = await harness();
        h.storage.map.set(`fiber-lsp-sdk:alias:${CHANNEL_ID}`, "-1");
        h.node.result({ channels: [READY_CHANNEL] });
        await expect(getSdkBalance(h.rpc, h.store)).rejects.toThrow(
            new TypeError(`stored value at fiber-lsp-sdk:alias:${CHANNEL_ID} is not a channel index`),
        );
    });
});
