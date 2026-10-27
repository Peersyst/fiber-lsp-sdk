import { hexToBytes } from "@noble/hashes/utils.js";
import type { CellDep, Transaction } from "../../../src/common";
import { SignerStore } from "../../../src/policy";
import { RpcError, RpcTransportError } from "../../../src/rpc";
import { encodeTransaction } from "../../../src/wire";
import type { PendingOpening, SdkChannelInfo, SdkEvent, SdkSignFundingInputs } from "../../../src/sdk";
import { FiberLspSdk, PendingOpeningStore, SdkError } from "../../../src/sdk";
import { TimerMock } from "../../mocks/common";
import { InMemorySignerStorage } from "../../mocks/policy";
import { flush } from "../../utils/flush";
import { asArray, asRecord } from "../../utils/json-shape";
import { rejection } from "../../utils/rejection";
import { loadSigningVectors, toCkbCellDep } from "../../utils/signing-vectors";
import { CHANNEL, FUNDED, LSP_PUBKEY, TENANT_NODE_URL, post, tenantNode, tick } from "../../utils/tenant-flow";
import type { InMemoryTenantNode, TenantNodeForceClose, TenantNodeOpeningTamper } from "../../utils/tenant-node";

const vectors = loadSigningVectors();

const MASTER_SEED = hexToBytes(vectors.device.master_seed);

// Past the allocation floor: the first opening takes channel index 1_791_367_200, the next one 1_791_367_201.
const NOW_MS = 1_791_367_200_000;

const OPENING_INDEX = 1_791_367_200;

// Fiber's id of each index's TLC base key and the peer's.
const OPENING_CHANNEL_ID = "0x5df11183f0223c41ea85677270eeaf085d3d2fa00f4a35b1b870b7af25b0287f";

const REOPENED_CHANNEL_ID = "0x89ca0a4cb78121bad2d5044d5d583e2a9ff5dd7a741a7c5bb937d678079774d6";

const USER_LOCK = CHANNEL.localCloseScript;

const USER_LOCK_MOLECULE =
    "49000000100000003000000031000000537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d76901140000008d66477ba3b60a96feb27a3f57fe11f6697be87d";

const UNNAMED: PendingOpening = { channelIndex: OPENING_INDEX, fundedShannons: FUNDED, userLock: USER_LOCK_MOLECULE, channelId: null };

// Testnet's secp256k1 dep group, which the funding tx the node builds carries already, and a dep of the user's lock it lacks.
const SECP256K1_DEP_GROUP_TX_HASH = "f8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37";

const SECP256K1_DEP_GROUP: CellDep = { outPoint: { txHash: hexToBytes(SECP256K1_DEP_GROUP_TX_HASH), index: 0 }, depType: "dep_group" };

const USER_LOCK_DEP_TX_HASH = "3c7d9b1f5e2a4c6e8b0d2f4a6c8e1b3d5f7a9c0e2b4d6f8a1c3e5b7d9f0a2c4e";

const USER_LOCK_DEP: CellDep = { outPoint: { txHash: hexToBytes(USER_LOCK_DEP_TX_HASH), index: 2 }, depType: "code" };

// The hash of the funding tx the node freezes for the first index's opening.
const FROZEN_TX_HASH = "abe2085121bd6a8d485025206ed2f32edd7c44f1297e59fb06ba5448e6b22d5f";

// A `WitnessArgs` whose 65-byte lock stands for the user's signature.
const SIGNED_WITNESS = hexToBytes(`5500000010000000550000005500000041000000${"5a".repeat(65)}`);

// The peer's close script stands for the node's lock, which its watchtower pays.
const FORCE_CLOSE: TenantNodeForceClose = {
    fundingCellDeps: vectors.watchtower.funding_cell_deps.map(toCkbCellDep),
    settlementCellDeps: vectors.watchtower.settlement_cell_deps.map(toCkbCellDep),
    nodeLock: CHANNEL.remoteCloseScript,
    medianTimeMs: "1791367200000",
    preimages: [],
    commitmentsBack: 0,
};

// The first index's channel as `listChannels` shows it, its balances fiber's to_local and to_remote.
const LISTED: Omit<SdkChannelInfo, "state" | "hasRecord"> = {
    channelId: OPENING_CHANNEL_ID,
    localBalanceShannons: "62000000000",
    remoteBalanceShannons: "18500000000",
    offeredTlcBalanceShannons: "0",
    receivedTlcBalanceShannons: "0",
};

type OpeningFlow = { node: InMemoryTenantNode; sdk: FiberLspSdk; timer: TimerMock; storage: InMemorySignerStorage; events: SdkEvent[] };

function flow(lspPubkey = LSP_PUBKEY): OpeningFlow {
    const node = tenantNode([OPENING_INDEX, OPENING_INDEX + 1]);
    const timer = new TimerMock();
    const storage = new InMemorySignerStorage();
    // Fiber's nonce lifecycle signs the open's two commitments on one slot.
    const sdk = new FiberLspSdk(MASTER_SEED, {
        network: "testnet",
        storage,
        rpcUrl: TENANT_NODE_URL,
        lspPubkey,
        fetch: node.fetch,
        timer,
        now: () => NOW_MS,
        nonceReuse: "allow",
    });
    const events: SdkEvent[] = [];
    sdk.onEvent((event) => events.push(event));
    return { node, sdk, timer, storage, events };
}

async function connect(h: OpeningFlow): Promise<void> {
    h.sdk.connect();
    await flush();
}

const signFundingInputs: SdkSignFundingInputs = (unsigned) => Promise.resolve(signed(unsigned));

function signingInto(handed: Transaction[]): SdkSignFundingInputs {
    return (unsigned) => {
        handed.push(unsigned);
        return signFundingInputs(unsigned);
    };
}

function signed(unsigned: Transaction): Transaction {
    return { ...unsigned, witnesses: unsigned.witnesses.map(() => SIGNED_WITNESS) };
}

function eventsOf(h: OpeningFlow): string[] {
    return h.events.map((event) => {
        switch (event.type) {
            case "SIGNING":
                return `SIGNING ${event.transition ?? "unread"} ${event.outcome}`;
            case "CHANNEL_READY":
            case "CHANNEL_CLOSED":
                return `${event.type} ${event.channelId === OPENING_CHANNEL_ID ? "opening" : event.channelId}`;
            case "WATCHTOWER_SIGNING":
                return `WATCHTOWER_SIGNING ${event.outcome === "refused" ? `refused ${event.error.code}` : event.outcome}`;
            case "ERROR":
                return `ERROR ${event.error.code}`;
            default:
                return event.type;
        }
    });
}

function requests(h: OpeningFlow): string[] {
    return h.node.served.map((request) => `${request.transition} ${request.slot} ${request.answers.join("+") || "unanswered"}`);
}

function openCalls(h: OpeningFlow): unknown[] {
    return h.node.calls.filter((call) => call.method === "open_tenant_channel").map((call) => call.params);
}

async function refusalOf(h: OpeningFlow, method: string, params: unknown): Promise<unknown> {
    return asRecord(await post(h.node, { jsonrpc: "2.0", id: 1, method, params: [params] }), "answer").error;
}

async function listedOf(h: OpeningFlow, filter: object): Promise<Record<string, unknown>[]> {
    const answer = asRecord(await post(h.node, { jsonrpc: "2.0", id: 1, method: "list_channels", params: [filter] }), "answer");
    return asArray(asRecord(answer.result, "result").channels, "channels").map((channel, index) => asRecord(channel, `channels[${index}]`));
}

function without(params: unknown, member: string): Record<string, unknown> {
    return Object.fromEntries(Object.entries(asRecord(params, "params")).filter(([name]) => name !== member));
}

function pendingOf(h: OpeningFlow): Promise<PendingOpening | null> {
    return new PendingOpeningStore(new SignerStore(h.storage)).read();
}

describe("the channel opening over the tenant node", () => {
    it("opens in one call up to CHANNEL_READY, signing the open's commitments, then announces the force close", async () => {
        const h = flow();
        await connect(h);
        expect(await h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs)).toBe(OPENING_CHANNEL_ID);
        expect(await pendingOf(h)).toEqual({ ...UNNAMED, channelId: OPENING_CHANNEL_ID });
        await tick(h, 3);
        expect(requests(h)).toEqual(["SendCommitmentSigned Commitment@1 Applied", "CompleteReceivedCommitment Commitment@1 Applied"]);
        expect(eventsOf(h)).toEqual([
            "SIGNING SendCommitmentSigned signed",
            "SIGNING CompleteReceivedCommitment warning",
            "CHANNEL_READY opening",
        ]);
        expect(await pendingOf(h)).toBeNull();
        h.node.forceClose("local", FORCE_CLOSE);
        await tick(h);
        // The node's watchtower asks for the device's settlement, which a device without the host's approval refuses.
        expect(eventsOf(h).slice(3)).toEqual(["CHANNEL_CLOSED opening", "WATCHTOWER_SIGNING refused policy_refusal"]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "closed", hasRecord: true }]);
    });

    it("prepares, then submits the host's signed tx, listing the channel opening, ready, closing and closed", async () => {
        const h = flow();
        await connect(h);
        const prepared = await h.sdk.prepareChannelOpen(FUNDED, USER_LOCK);
        expect(prepared.channelId).toBe(OPENING_CHANNEL_ID);
        expect(prepared.openingContext).toEqual({
            remoteFundingKey: hexToBytes(vectors.peer.funding_pubkey),
            remoteSettlementKey: hexToBytes(vectors.peer.tlc_base_pubkey),
            remoteShutdownScript: CHANNEL.remoteCloseScript,
            commitmentDelayEpoch: 0x10000000001n,
            commitmentFeeRate: 1000n,
            localAmountShannons: FUNDED,
            remoteAmountShannons: "28500000000",
            localReservedCkbShannons: "10000000000",
            remoteReservedCkbShannons: "10000000000",
        });
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "opening", hasRecord: true }]);
        // Fiber waits for the signed tx before it asks for any commitment.
        await tick(h, 2);
        expect(requests(h)).toEqual([]);
        await h.sdk.submitFundingTx(OPENING_CHANNEL_ID, signed(prepared.unsignedFundingTx));
        await tick(h, 3);
        expect(eventsOf(h)).toEqual([
            "SIGNING SendCommitmentSigned signed",
            "SIGNING CompleteReceivedCommitment warning",
            "CHANNEL_READY opening",
        ]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "ready", hasRecord: true }]);
        h.node.shutdown();
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "closing", hasRecord: true }]);
        await tick(h, 2);
        expect(eventsOf(h).slice(3)).toEqual(["SIGNING SendClosingSigned signed", "CHANNEL_CLOSED opening"]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "closed", hasRecord: true }]);
    });

    it("signs the peer's commitment while the funding tx waits for the host, then the device's after the submit", async () => {
        const h = flow();
        h.node.receiveCommitmentEarly();
        await connect(h);
        const prepared = await h.sdk.prepareChannelOpen(FUNDED, USER_LOCK);
        await tick(h);
        expect(requests(h)).toEqual(["CompleteReceivedCommitment Commitment@1 Applied"]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "opening", hasRecord: true }]);
        expect((await listedOf(h, {}))[0]?.state).toEqual({
            state_name: "SigningCommitment",
            state_flags: "THEIR_COMMITMENT_SIGNED_SENT|COMMITMENT_SIGNED_SENT",
        });
        await h.sdk.submitFundingTx(OPENING_CHANNEL_ID, signed(prepared.unsignedFundingTx));
        await tick(h, 2);
        expect(requests(h)).toEqual(["CompleteReceivedCommitment Commitment@1 Applied", "SendCommitmentSigned Commitment@1 Applied"]);
        expect(eventsOf(h)).toEqual([
            "SIGNING CompleteReceivedCommitment signed",
            "SIGNING SendCommitmentSigned warning",
            "CHANNEL_READY opening",
        ]);
    });

    it("announces closed, and drops, an opening fiber aborts after the device signed the peer's commitment", async () => {
        const h = flow();
        h.node.receiveCommitmentEarly();
        await connect(h);
        await h.sdk.prepareChannelOpen(FUNDED, USER_LOCK);
        await tick(h);
        expect(requests(h)).toEqual(["CompleteReceivedCommitment Commitment@1 Applied"]);
        h.node.expireOpening();
        await tick(h);
        expect(eventsOf(h)).toEqual(["SIGNING CompleteReceivedCommitment signed", "CHANNEL_CLOSED opening"]);
        expect(await pendingOf(h)).toBeNull();
        expect(await h.sdk.listChannels()).toEqual([]);
        // Fiber's failure names the signing state the opening stopped in.
        expect((await listedOf(h, { only_pending: true }))[0]?.failure_detail).toBe(
            `[Channel Hash256(${OPENING_CHANNEL_ID})] External funding transaction submission timed out in state ` +
                "SigningCommitment(SigningCommitmentFlags(THEIR_COMMITMENT_SIGNED_SENT))",
        );
    });

    it("resumes after the node's answer is lost, under the same index with the identical request", async () => {
        const h = flow();
        h.node.dropNextAnswer("open_tenant_channel");
        expect(await rejection(h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs))).toBeInstanceOf(RpcTransportError);
        expect(await pendingOf(h)).toEqual({
            channelIndex: OPENING_INDEX,
            fundedShannons: FUNDED,
            userLock: USER_LOCK_MOLECULE,
            channelId: null,
        });
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "opening", hasRecord: false }]);
        expect(await h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs)).toBe(OPENING_CHANNEL_ID);
        const [first, again] = openCalls(h);
        expect(again).toEqual(first);
        await connect(h);
        await tick(h, 2);
        expect(eventsOf(h)).toEqual([
            "SIGNING SendCommitmentSigned signed",
            "SIGNING CompleteReceivedCommitment warning",
            "CHANNEL_READY opening",
        ]);
    });

    it("keeps an opening the host declined, announces it closed once fiber aborts it, then opens under a fresh index", async () => {
        const h = flow();
        await connect(h);
        const declined = new Error("the user declined");
        const handed: Transaction[] = [];
        const decline: SdkSignFundingInputs = (unsigned) => {
            handed.push(unsigned);
            return Promise.reject(declined);
        };
        expect(await rejection(h.sdk.openChannel(FUNDED, USER_LOCK, decline))).toBe(declined);
        expect(await pendingOf(h)).toEqual({ ...UNNAMED, channelId: OPENING_CHANNEL_ID });
        await tick(h);
        expect(eventsOf(h)).toEqual([]);
        h.node.expireOpening();
        await tick(h);
        expect(eventsOf(h)).toEqual(["CHANNEL_CLOSED opening"]);
        expect(await pendingOf(h)).toBeNull();
        // Fiber deletes the aborted channel's state: only a call for pending channels lists it, and a late submission finds none.
        expect(await h.sdk.listChannels()).toEqual([]);
        const [unsigned] = handed;
        if (unsigned === undefined) throw new Error("the host was handed no tx");
        expect(await rejection(h.sdk.submitFundingTx(OPENING_CHANNEL_ID, signed(unsigned)))).toEqual(
            new RpcError("submit_signed_funding_tx", -32000, `Channel not found error: Hash256(${OPENING_CHANNEL_ID})`),
        );
        expect(await h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs)).toBe(REOPENED_CHANNEL_ID);
        await tick(h, 3);
        expect(eventsOf(h).slice(1)).toEqual([
            "SIGNING SendCommitmentSigned signed",
            "SIGNING CompleteReceivedCommitment warning",
            `CHANNEL_READY ${REOPENED_CHANNEL_ID}`,
        ]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, channelId: REOPENED_CHANNEL_ID, state: "ready", hasRecord: true }]);
    });

    it("drops an opening fiber aborted while the device was away, and opens under a fresh index", async () => {
        const h = flow();
        await rejection(h.sdk.openChannel(FUNDED, USER_LOCK, () => Promise.reject(new Error("the app was closed"))));
        h.node.expireOpening();
        expect(await h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs)).toBe(REOPENED_CHANNEL_ID);
        expect(h.node.calls.map((call) => call.method)).toEqual([
            "open_tenant_channel",
            "list_channels",
            "open_tenant_channel",
            "submit_signed_funding_tx",
        ]);
        expect(h.node.calls[1]?.params).toEqual({ only_pending: true });
        expect(await pendingOf(h)).toEqual({ ...UNNAMED, channelIndex: OPENING_INDEX + 1, channelId: REOPENED_CHANNEL_ID });
    });

    it.each<[string, TenantNodeOpeningTamper, string]>([
        [
            "another delay",
            { kind: "delayEpoch", commitmentDelayEpoch: "2199023255553" },
            "openingContext.commitmentDelayEpoch is 2199023255553, not the 1099511627777 asked",
        ],
        [
            "another peer reserve",
            { kind: "reserve", side: "remote", shannons: "6300000000" },
            "openingContext.remoteReservedCkbShannons 6300000000 is not the peer's reserve over its shutdown script under the device's layout",
        ],
        [
            "another device reserve",
            { kind: "reserve", side: "local", shannons: "9800000000" },
            "openingContext.localReservedCkbShannons 9800000000 is not the device's reserve over its lock under either layout",
        ],
        [
            "another channel id",
            { kind: "channelId", channelId: REOPENED_CHANNEL_ID },
            `channelId ${REOPENED_CHANNEL_ID} is not ${OPENING_CHANNEL_ID}, the id of the two TLC base keys`,
        ],
        [
            "output 0 under another lock",
            { kind: "fundingLock", lock: CHANNEL.remoteCloseScript },
            "unsignedFundingTx.outputs[0].lock is not the network's funding lock over the two funding keys",
        ],
    ])("refuses an answer stating %s as opening_rejected, registering nothing", async (_, tamper, refusal) => {
        const h = flow();
        h.node.tamperOpening(tamper);
        expect(await rejection(h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs))).toEqual(
            new SdkError("opening_rejected", `the node's opening is refused: ${refusal}`),
        );
        expect(await pendingOf(h)).toBeNull();
        expect(h.node.calls.map((call) => call.method)).toEqual(["open_tenant_channel"]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "opening", hasRecord: false }]);
        // The node keeps its opening until it expires, so a fresh index is another opening it refuses.
        const refused = await rejection(h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs));
        expect(refused).toEqual(new RpcError("open_tenant_channel", -32000, "tenant already has a different channel opening"));
        // A refusal is no answer to drop the opening on: the same call resends it, and fiber answers it alike.
        expect(await pendingOf(h)).toEqual({ ...UNNAMED, channelIndex: OPENING_INDEX + 1 });
        expect(await rejection(h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs))).toEqual(refused);
        const [, resent, again] = openCalls(h);
        expect(again).toEqual(resent);
        expect(await pendingOf(h)).toEqual({ ...UNNAMED, channelIndex: OPENING_INDEX + 1 });
    });

    it("refuses a signed tx that is not the one frozen as funding_tx_altered, sending nothing", async () => {
        const h = flow();
        const prepared = await h.sdk.prepareChannelOpen(FUNDED, USER_LOCK);
        const altered = { ...signed(prepared.unsignedFundingTx), headerDeps: [new Uint8Array(32).fill(0x7e)] };
        const error = await rejection(h.sdk.submitFundingTx(OPENING_CHANNEL_ID, altered));
        expect(error).toEqual(
            new SdkError(
                "funding_tx_altered",
                `the signed tx is not the funding tx the device froze: channel ${OPENING_CHANNEL_ID} already pins fundingOutPoint to ` +
                    `${FROZEN_TX_HASH}:0, not 2264eb3d7cce59139151792a0d387eceb69c127532a864f7b24d35b18c8a9865:0`,
            ),
        );
        expect(h.node.calls.map((call) => call.method)).toEqual(["open_tenant_channel"]);
        // Sent, the node would refuse it too, and take the frozen one after.
        const wire = { channel_id: OPENING_CHANNEL_ID, signed_funding_tx: encodeTransaction("signedFundingTx", altered) };
        expect(await refusalOf(h, "submit_signed_funding_tx", wire)).toEqual({
            code: -32000,
            message: "Invalid parameter: Signed funding transaction raw data mismatch; only witnesses may change for external funding",
        });
        await h.sdk.submitFundingTx(OPENING_CHANNEL_ID, signed(prepared.unsignedFundingTx));
        expect(h.node.calls.map((call) => call.method)).toEqual([
            "open_tenant_channel",
            "submit_signed_funding_tx",
            "submit_signed_funding_tx",
        ]);
    });

    it("leaves a submission whose answer is lost to the node: a retry gets its refusal, and CHANNEL_READY confirms", async () => {
        const h = flow();
        const handed: Transaction[] = [];
        h.node.dropNextAnswer("submit_signed_funding_tx");
        expect(await rejection(h.sdk.openChannel(FUNDED, USER_LOCK, signingInto(handed)))).toBeInstanceOf(RpcTransportError);
        const [unsigned] = handed;
        if (unsigned === undefined) throw new Error("the host was handed no tx");
        expect(await rejection(h.sdk.submitFundingTx(OPENING_CHANNEL_ID, signed(unsigned)))).toEqual(
            new RpcError("submit_signed_funding_tx", -32000, "Repeated processing message: Signed funding tx has already been submitted"),
        );
        await connect(h);
        await tick(h, 2);
        expect(eventsOf(h)).toEqual([
            "SIGNING SendCommitmentSigned signed",
            "SIGNING CompleteReceivedCommitment warning",
            "CHANNEL_READY opening",
        ]);
        expect(await pendingOf(h)).toBeNull();
    });

    it("is refused by the node when the LSP it names is not the node's", async () => {
        const h = flow(hexToBytes(vectors.peer.funding_pubkey));
        expect(await rejection(h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs))).toEqual(
            new RpcError("open_tenant_channel", -32000, "tenant channel peer must be the LSP public node"),
        );
        expect(await pendingOf(h)).toEqual(UNNAMED);
        expect(await h.sdk.listChannels()).toEqual([]);
    });

    it("finds the node refusing what the facade never asks: a public channel, no signer, its open channel again", async () => {
        const h = flow();
        await connect(h);
        await h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs);
        await tick(h, 3);
        const [asked] = openCalls(h);
        const notPrivate = { code: -32000, message: "tenant channel requires public: false" };
        expect(await refusalOf(h, "open_tenant_channel", { ...asRecord(asked, "params"), public: true })).toEqual(notPrivate);
        expect(await refusalOf(h, "open_tenant_channel", without(asked, "public"))).toEqual(notPrivate);
        expect(await refusalOf(h, "open_tenant_channel", without(asked, "external_channel_signer"))).toEqual({
            code: -32000,
            message: "tenant channel requires external_channel_signer",
        });
        expect(await refusalOf(h, "open_tenant_channel", asked)).toEqual({ code: -32000, message: "tenant channel is already open" });
        // The facade's next opening is under a fresh index, which the node's single slot refuses.
        expect(await rejection(h.sdk.openChannel(FUNDED, USER_LOCK, signFundingInputs))).toEqual(
            new RpcError("open_tenant_channel", -32000, "tenant already has a different channel opening"),
        );
        expect(await pendingOf(h)).toEqual({ ...UNNAMED, channelIndex: OPENING_INDEX + 1 });
    });

    it("hands the node the user lock's cell deps, which it adds to the funding tx unless the tx carries them already", async () => {
        const h = flow();
        const handed: Transaction[] = [];
        await h.sdk.openChannel(FUNDED, USER_LOCK, signingInto(handed), [SECP256K1_DEP_GROUP, USER_LOCK_DEP]);
        expect(asRecord(openCalls(h)[0], "params").funding_lock_script_cell_deps).toEqual([
            { out_point: { tx_hash: `0x${SECP256K1_DEP_GROUP_TX_HASH}`, index: "0x0" }, dep_type: "dep_group" },
            { out_point: { tx_hash: `0x${USER_LOCK_DEP_TX_HASH}`, index: "0x2" }, dep_type: "code" },
        ]);
        expect(handed[0]?.cellDeps).toEqual([SECP256K1_DEP_GROUP, USER_LOCK_DEP]);
        expect(await pendingOf(h)).toEqual({
            ...UNNAMED,
            userLockCellDeps: [
                { txHash: SECP256K1_DEP_GROUP_TX_HASH, index: 0, depType: "dep_group" },
                { txHash: USER_LOCK_DEP_TX_HASH, index: 2, depType: "code" },
            ],
            channelId: OPENING_CHANNEL_ID,
        });
    });
});
