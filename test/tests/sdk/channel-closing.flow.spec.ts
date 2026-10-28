import { hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../src/common";
import type { UnsignedInvoice } from "../../../src/invoice";
import { encodeInvoice } from "../../../src/invoice";
import { SignerStore } from "../../../src/policy";
import { RpcError, RpcTransportError } from "../../../src/rpc";
import type { SdkChannelInfo, SdkEvent } from "../../../src/sdk";
import { ActivityTracker, FiberLspSdk, SdkError } from "../../../src/sdk";
import { TimerMock } from "../../mocks/common";
import { InMemorySignerStorage } from "../../mocks/policy";
import { flush } from "../../utils/flush";
import { signInvoice } from "../../utils/invoice-signing";
import { forgetSecondSession } from "../../utils/nonce-cap-bypass";
import { rejection } from "../../utils/rejection";
import { loadSigningVectors } from "../../utils/signing-vectors";
import { writes } from "../../utils/stored-records";
import { FUNDED, LSP_PUBKEY, TENANT_NODE_URL, tenantNode, tick } from "../../utils/tenant-flow";
import type { InMemoryTenantNode } from "../../utils/tenant-node";

const vectors = loadSigningVectors();

const MASTER_SEED = hexToBytes(vectors.device.master_seed);

// Past the allocation floor: the channel takes index 1_791_367_200.
const NOW_MS = 1_791_367_200_000;

const OPENING_INDEX = 1_791_367_200;

const OPENING_CHANNEL_ID = "0x5df11183f0223c41ea85677270eeaf085d3d2fa00f4a35b1b870b7af25b0287f";

// The user's lock, which the open pins as the device's close script.
const USER_LOCK: Script = {
    codeHash: hexToBytes("537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d769"),
    hashType: "type",
    args: hexToBytes("8d66477ba3b60a96feb27a3f57fe11f6697be87d"),
};

// The opening context's `remote_shutdown_script`, which the open pins as the peer's close script.
const PEER_LOCK: Script = {
    codeHash: hexToBytes("4d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba"),
    hashType: "type",
    args: hexToBytes("8f1e030962418183dc890ef5664b1f2a64b0064c"),
};

// The script a peer that changes its mind asks its share paid to.
const OTHER_PEER_LOCK: Script = {
    codeHash: hexToBytes("4d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba"),
    hashType: "type",
    args: hexToBytes("7777777777777777777777777777777777777777"),
};

const USER_LOCK_WIRE = {
    code_hash: "0x537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d769",
    hash_type: "type",
    args: "0x8d66477ba3b60a96feb27a3f57fe11f6697be87d",
};

// Molecule `Script`s, as the pins hold them.
const PEER_LOCK_MOLECULE =
    "490000001000000030000000310000004d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba01140000008f1e030962418183dc890ef5664b1f2a64b0064c";

const OTHER_PEER_LOCK_MOLECULE =
    "490000001000000030000000310000004d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba01140000007777777777777777777777777777777777777777";

// The secret of LSP_PUBKEY, which signs the invoice the device pays the LSP directly.
const LSP_SECRET_KEY = hexToBytes("4c".repeat(32));

const PREIMAGE = "a1".repeat(32);

// The ckb-hash of PREIMAGE.
const PAYMENT_HASH = "0x32d0c025ace2accaa7bbfcc42ab4dd31ba8647da25b459ff90bb17269cbcd937";

const LSP_INVOICE: UnsignedInvoice = {
    currency: "Fibt",
    amountShannons: "1000000000",
    timestampMs: 1_791_367_200_000n,
    paymentHash: hexToBytes(PAYMENT_HASH.slice(2)),
    attributes: [
        { type: "expiryTime", seconds: 3600n },
        { type: "finalHtlcMinimumExpiryDelta", milliseconds: 86_400_000n },
        { type: "payeePublicKey", publicKey: LSP_PUBKEY },
    ],
};

const LSP_INVOICE_STRING = encodeInvoice(signInvoice(LSP_INVOICE, LSP_SECRET_KEY));

// The opened channel as `listChannels` shows it.
const LISTED: Omit<SdkChannelInfo, "state"> = {
    channelId: OPENING_CHANNEL_ID,
    localBalanceShannons: "62000000000",
    remoteBalanceShannons: "18500000000",
    offeredTlcBalanceShannons: "0",
    receivedTlcBalanceShannons: "0",
    hasRecord: true,
};

// The tick that signs the close: the channel step's listing, the signing step's and the request signed, then the watchtower step's
// listing, which asks nothing of a channel closed cooperatively.
const CLOSE_TICK = ["list_channels", "list_channels", "get_channel_signing_status", "submit_channel_signature", "list_channels"];

// Each step's listing: the channel step reads the channel closed, which the other two pass over.
const CLOSED_TICK = ["list_channels", "list_channels", "list_channels"];

type ClosingFlow = { node: InMemoryTenantNode; sdk: FiberLspSdk; storage: InMemorySignerStorage; timer: TimerMock; events: SdkEvent[] };

// Fiber's nonce lifecycle signs the open's two commitments on one slot, and a payment's fulfil a third time.
function flow(): ClosingFlow {
    const node = tenantNode([OPENING_INDEX], () => NOW_MS);
    const timer = new TimerMock();
    const storage = new InMemorySignerStorage();
    const sdk = new FiberLspSdk(MASTER_SEED, {
        network: "testnet",
        storage,
        rpcUrl: TENANT_NODE_URL,
        lspPubkey: LSP_PUBKEY,
        fetch: node.fetch,
        timer,
        now: () => NOW_MS,
        nonceReuse: "allow",
    });
    node.bypassNonceCap((slot) => forgetSecondSession(storage, OPENING_INDEX, slot));
    const events: SdkEvent[] = [];
    sdk.onEvent((event) => events.push(event));
    return { node, sdk, storage, timer, events };
}

async function opened(): Promise<ClosingFlow> {
    const h = flow();
    h.sdk.connect();
    await flush();
    // The double compares the funding tx's raw data alone, which the host's witnesses leave as it is.
    await h.sdk.openChannel(FUNDED, USER_LOCK, (unsigned) => Promise.resolve(unsigned));
    await tick(h, 3);
    expect(eventsOf(h)).toEqual(["SIGNING SendCommitmentSigned signed", "SIGNING CompleteReceivedCommitment warning", "CHANNEL_READY"]);
    h.events.length = 0;
    return h;
}

// Lets the tick `closeChannel`'s `pollNow` starts run out.
async function askClose(h: ClosingFlow, feeRate?: bigint): Promise<void> {
    await h.sdk.closeChannel(OPENING_CHANNEL_ID, feeRate === undefined ? undefined : { feeRate });
    await flush();
}

function eventsOf(h: ClosingFlow): string[] {
    return h.events.map((event) => {
        switch (event.type) {
            case "SIGNING":
                return `SIGNING ${event.transition ?? "unread"} ${event.outcome === "refused" ? `refused ${event.error.code}` : event.outcome}`;
            case "CHANNEL_CLOSED":
                return `CHANNEL_CLOSED ${event.channelId === OPENING_CHANNEL_ID ? "opening" : event.channelId}`;
            case "PAYMENT_SENT":
                return `PAYMENT_SENT ${event.paymentHashHex === PAYMENT_HASH ? "payment" : event.paymentHashHex}`;
            case "ERROR":
                return `ERROR ${event.error.code}: ${event.error.message}`;
            default:
                return event.type;
        }
    });
}

function methods(h: ClosingFlow, from: number): string[] {
    return h.node.calls.slice(from).map((call) => call.method);
}

// The open's two requests aside.
function requests(h: ClosingFlow): string[] {
    return h.node.served.slice(2).map((request) => `${request.transition} ${request.slot} ${request.answers.join("+") || "unanswered"}`);
}

// The close's outputs in the order the node built them, the peer's first: its funding key sorts first.
function closeOutputsOf(h: ClosingFlow): { capacityShannons: bigint; lock: Script }[] {
    const transaction = h.node.closingTx;
    if (transaction === null) throw new Error("the node asked for no close");
    return transaction.outputs.map(({ capacityShannons, lock }) => ({ capacityShannons, lock }));
}

async function postShutdown(h: ClosingFlow, params: Record<string, unknown>): Promise<unknown> {
    const body = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "shutdown_channel",
        params: [{ channel_id: OPENING_CHANNEL_ID, ...params }],
    });
    const response = await h.node.fetch(TENANT_NODE_URL, { method: "POST", headers: { "content-type": "application/json" }, body });
    return JSON.parse(await response.text());
}

async function watchedChannels(h: ClosingFlow): Promise<string[]> {
    return Object.keys((await new ActivityTracker(new SignerStore(h.storage)).read()).channels);
}

describe("the cooperative close over the tenant node", () => {
    it("closes at the commitment fee rate: the tick the call asks for signs the close, the next announces CHANNEL_CLOSED", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        await askClose(h);
        // The device's pinned close script, and no fee rate: fiber's default is the commitment's.
        expect(h.node.calls[from]).toEqual({
            method: "shutdown_channel",
            params: { channel_id: OPENING_CHANNEL_ID, close_script: USER_LOCK_WIRE },
        });
        expect(methods(h, from)).toEqual(["shutdown_channel", ...CLOSE_TICK]);
        expect(requests(h)).toEqual(["SendClosingSigned Commitment@2 Applied"]);
        expect(eventsOf(h)).toEqual(["SIGNING SendClosingSigned signed"]);
        // 1000 shannons per kilobyte over the close's 528 bytes, from the device's share alone: the peer's answer states a rate of 0.
        expect(closeOutputsOf(h)).toEqual([
            { capacityShannons: 28_500_000_000n, lock: PEER_LOCK },
            { capacityShannons: 71_999_999_472n, lock: USER_LOCK },
        ]);
        await tick(h);
        expect(methods(h, from)).toEqual(["shutdown_channel", ...CLOSE_TICK, ...CLOSED_TICK]);
        expect(eventsOf(h)).toEqual(["SIGNING SendClosingSigned signed", "CHANNEL_CLOSED opening"]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "closed" }]);
        expect(await watchedChannels(h)).toEqual([]);
    });

    it("closes at the fee rate the host gives, which the device's output pays", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        await askClose(h, 2000n);
        expect(h.node.calls[from]).toEqual({
            method: "shutdown_channel",
            params: { channel_id: OPENING_CHANNEL_ID, close_script: USER_LOCK_WIRE, fee_rate: "0x7d0" },
        });
        expect(eventsOf(h)).toEqual(["SIGNING SendClosingSigned signed"]);
        expect(closeOutputsOf(h)).toEqual([
            { capacityShannons: 28_500_000_000n, lock: PEER_LOCK },
            { capacityShannons: 71_999_998_944n, lock: USER_LOCK },
        ]);
        await tick(h);
        expect(eventsOf(h)).toEqual(["SIGNING SendClosingSigned signed", "CHANNEL_CLOSED opening"]);
    });

    it("refuses a fee rate whose fee the policy would not sign as close_fee_too_high, calling nothing, and signs the highest it lets through", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        const error = await rejection(h.sdk.closeChannel(OPENING_CHANNEL_ID, { feeRate: 189_393_942n }));
        expect(error).toBeInstanceOf(SdkError);
        expect(error).toMatchObject({
            code: "close_fee_too_high",
            message:
                "the device refuses the close: at 189393942 shannons per kilobyte its fee is 100000001, more than the 100000000 a close's fee may take",
        });
        expect(methods(h, from)).toEqual([]);
        expect(await watchedChannels(h)).toEqual([OPENING_CHANNEL_ID]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "ready" }]);
        const highest = h.node.calls.length;
        await askClose(h, 189_393_941n);
        expect(h.node.calls[highest]).toEqual({
            method: "shutdown_channel",
            params: { channel_id: OPENING_CHANNEL_ID, close_script: USER_LOCK_WIRE, fee_rate: "0xb49ec15" },
        });
        // A fee of one CKB: the device's output is what it funded less one CKB, the least the policy signs.
        expect(closeOutputsOf(h)).toEqual([
            { capacityShannons: 28_500_000_000n, lock: PEER_LOCK },
            { capacityShannons: 71_900_000_000n, lock: USER_LOCK },
        ]);
        expect(eventsOf(h)).toEqual(["SIGNING SendClosingSigned signed"]);
    });

    it("throws fiber's refusal unwrapped while the outbound TLC is not committed, keeping the watch the opening set", async () => {
        const h = await opened();
        await h.sdk.transfer(LSP_INVOICE_STRING);
        // The tick `transfer` asks for signs the add's commitment; the peer's revoke_and_ack, which commits the TLC, is not signed yet.
        await flush();
        expect(requests(h)).toEqual(["SendCommitmentSigned Commitment@2 Applied", "CompleteReceivedRevokeAndAck Revocation@2 unanswered"]);
        const from = h.node.calls.length;
        const error = await rejection(h.sdk.closeChannel(OPENING_CHANNEL_ID));
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({
            method: "shutdown_channel",
            code: -32000,
            message: "Invalid state: Unable to process shutdown command, as there are pending outbound tlcs",
        });
        expect(methods(h, from)).toEqual(["shutdown_channel"]);
        expect(await watchedChannels(h)).toEqual([OPENING_CHANNEL_ID]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "ready", offeredTlcBalanceShannons: "1000000000" }]);
    });

    it("accepts the close once the TLC is committed, closing until the payee's fulfil, then signs it and announces CHANNEL_CLOSED", async () => {
        const h = await opened();
        await h.sdk.transfer(LSP_INVOICE_STRING);
        await flush();
        await tick(h, 3);
        expect(requests(h)).toEqual([
            "SendCommitmentSigned Commitment@2 Applied",
            "CompleteReceivedRevokeAndAck Revocation@2 Applied",
            "CompleteReceivedCommitment Commitment@3 Applied",
            "SendRevokeAndAck Revocation@2 Applied",
        ]);
        await askClose(h);
        await tick(h);
        // Both shutdowns are exchanged; fiber asks for the close only once no TLC is left.
        expect(requests(h)).toHaveLength(4);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "closing", offeredTlcBalanceShannons: "1000000000" }]);
        const again = h.node.calls.length;
        const error = await rejection(h.sdk.closeChannel(OPENING_CHANNEL_ID));
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({
            method: "shutdown_channel",
            code: -32000,
            message:
                "Invalid state: Trying to send shutdown message while in invalid state ShuttingDown(ShuttingDownFlags(OUR_SHUTDOWN_SENT | THEIR_SHUTDOWN_SENT))",
        });
        expect(methods(h, again)).toEqual(["shutdown_channel"]);
        h.node.fulfil(PAYMENT_HASH.slice(2), PREIMAGE);
        await tick(h, 5);
        expect(requests(h).slice(4)).toEqual([
            "CompleteReceivedCommitment Commitment@3 Applied",
            "SendRevokeAndAck Revocation@3 Applied",
            "SendCommitmentSigned Commitment@3 Applied",
            "CompleteReceivedRevokeAndAck Revocation@3 Applied",
            "SendClosingSigned Commitment@4 Applied",
        ]);
        // The device's output is its balance once the payment left it, less the close's fee.
        expect(closeOutputsOf(h)).toEqual([
            { capacityShannons: 29_500_000_000n, lock: PEER_LOCK },
            { capacityShannons: 70_999_999_472n, lock: USER_LOCK },
        ]);
        await tick(h);
        // The payment ends on the fulfil round's last signature; the close follows it.
        expect(eventsOf(h)).toEqual([
            "SIGNING SendCommitmentSigned signed",
            "SIGNING CompleteReceivedRevokeAndAck signed",
            "SIGNING CompleteReceivedCommitment signed",
            "SIGNING SendRevokeAndAck warning",
            "SIGNING CompleteReceivedCommitment warning",
            "SIGNING SendRevokeAndAck signed",
            "SIGNING SendCommitmentSigned warning",
            "SIGNING CompleteReceivedRevokeAndAck warning",
            "PAYMENT_SENT payment",
            "SIGNING SendClosingSigned signed",
            "CHANNEL_CLOSED opening",
        ]);
        expect(await h.sdk.listChannels()).toEqual([
            { ...LISTED, state: "closed", localBalanceShannons: "61000000000", remoteBalanceShannons: "19500000000" },
        ]);
    });

    it("signs the close the peer starts, whose fee the peer pays alone", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        h.node.peerShutdown();
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "closing" }]);
        // The node answers the peer's shutdown at a rate of 0: the device's output is all it funded.
        expect(closeOutputsOf(h)).toEqual([
            { capacityShannons: 28_499_999_472n, lock: PEER_LOCK },
            { capacityShannons: 72_000_000_000n, lock: USER_LOCK },
        ]);
        await tick(h, 2);
        expect(methods(h, from)).toEqual(["list_channels", ...CLOSE_TICK, ...CLOSED_TICK]);
        expect(requests(h)).toEqual(["SendClosingSigned Commitment@2 Applied"]);
        expect(eventsOf(h)).toEqual(["SIGNING SendClosingSigned signed", "CHANNEL_CLOSED opening"]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "closed" }]);
    });

    it("refuses the close of a peer that changes its close script, the channel staying closing, where closeChannel gets fiber's invalid state", async () => {
        const h = await opened();
        h.node.peerShutdown({ closeScript: OTHER_PEER_LOCK });
        await tick(h, 2);
        expect(requests(h)).toEqual(["SendClosingSigned Commitment@2 unanswered"]);
        expect(eventsOf(h)).toEqual([
            "SIGNING SendClosingSigned refused policy_refusal",
            "SIGNING SendClosingSigned refused policy_refusal",
        ]);
        const [refusal] = h.events;
        expect(refusal).toMatchObject({
            error: {
                code: "policy_refusal",
                message: `the request states remoteCloseScript ${OTHER_PEER_LOCK_MOLECULE}, but the channel pinned ${PEER_LOCK_MOLECULE}`,
            },
        });
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "closing" }]);
        const from = h.node.calls.length;
        const error = await rejection(h.sdk.closeChannel(OPENING_CHANNEL_ID));
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({
            method: "shutdown_channel",
            code: -32000,
            message:
                "Invalid state: Trying to send shutdown message while in invalid state ShuttingDown(ShuttingDownFlags(OUR_SHUTDOWN_SENT | THEIR_SHUTDOWN_SENT | DROPPING_PENDING))",
        });
        expect(methods(h, from)).toEqual(["shutdown_channel"]);
        expect(await watchedChannels(h)).toEqual([OPENING_CHANNEL_ID]);
    });

    it("throws fiber's channel not found for a close past the confirmed one, writing nothing and announcing no second CHANNEL_CLOSED", async () => {
        const h = await opened();
        await askClose(h);
        await tick(h);
        expect(eventsOf(h)).toEqual(["SIGNING SendClosingSigned signed", "CHANNEL_CLOSED opening"]);
        expect(await watchedChannels(h)).toEqual([]);
        const from = h.node.calls.length;
        h.storage.ops.splice(0);
        const error = await rejection(h.sdk.closeChannel(OPENING_CHANNEL_ID));
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({
            method: "shutdown_channel",
            code: -32000,
            message: `Channel not found error: Hash256(${OPENING_CHANNEL_ID})`,
        });
        await flush();
        expect(methods(h, from)).toEqual(["shutdown_channel"]);
        expect(writes(h.storage)).toEqual([]);
        await tick(h, 2);
        expect(eventsOf(h)).toEqual(["SIGNING SendClosingSigned signed", "CHANNEL_CLOSED opening"]);
        expect(await watchedChannels(h)).toEqual([]);
    });

    it("leaves a close whose answer is lost to the opening's watch, which signs it and announces CHANNEL_CLOSED", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        h.storage.ops.splice(0);
        h.node.dropNextAnswer("shutdown_channel");
        const error = await rejection(h.sdk.closeChannel(OPENING_CHANNEL_ID));
        expect(error).toBeInstanceOf(RpcTransportError);
        expect(error).toMatchObject({ message: "shutdown_channel: the request failed" });
        await flush();
        // The node ran the close, but the call asks no tick: the next one finds it.
        expect(methods(h, from)).toEqual(["shutdown_channel"]);
        expect(writes(h.storage)).toEqual([]);
        expect(await watchedChannels(h)).toEqual([OPENING_CHANNEL_ID]);
        await tick(h, 2);
        expect(methods(h, from)).toEqual(["shutdown_channel", ...CLOSE_TICK, ...CLOSED_TICK]);
        expect(eventsOf(h)).toEqual(["SIGNING SendClosingSigned signed", "CHANNEL_CLOSED opening"]);
        expect(await watchedChannels(h)).toEqual([]);
    });

    it("throws fiber's refusal of a fee rate below the commitment's unwrapped, the channel staying ready", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        h.storage.ops.splice(0);
        const error = await rejection(h.sdk.closeChannel(OPENING_CHANNEL_ID, { feeRate: 999n }));
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({
            method: "shutdown_channel",
            code: -32000,
            message: "Invalid parameter: Fee rate 999 shannons/KW is less than commitment fee rate 1000",
        });
        await flush();
        expect(methods(h, from)).toEqual(["shutdown_channel"]);
        expect(writes(h.storage)).toEqual([]);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "ready" }]);
        expect(eventsOf(h)).toEqual([]);
    });

    it("signs the close the peer starts at a fee rate of its own, which the peer's output pays alone", async () => {
        const h = await opened();
        h.node.peerShutdown({ feeRate: 2000n });
        // 2000 shannons per kilobyte over the close's 528 bytes.
        expect(closeOutputsOf(h)).toEqual([
            { capacityShannons: 28_499_998_944n, lock: PEER_LOCK },
            { capacityShannons: 72_000_000_000n, lock: USER_LOCK },
        ]);
        await tick(h, 2);
        expect(eventsOf(h)).toEqual(["SIGNING SendClosingSigned signed", "CHANNEL_CLOSED opening"]);
    });
});

// What the SDK never sends, posted to the node as fiber's RPC would take it.
describe("the tenant node's shutdown_channel", () => {
    it.each<[string, Record<string, unknown>, string]>([
        [
            "a close script one byte of args past the cell the device's share fills",
            { close_script: { ...USER_LOCK_WIRE, args: `0x${"8d".repeat(680)}` } },
            "Invalid parameter: Local shutdown capacity is less than occupied capacity 72100000000",
        ],
        [
            "the first fee rate whose fee the device's share cannot pay",
            { fee_rate: "0x1b6251ab0e" },
            "Invalid parameter: Local balance is not enough to pay the fee, expect fee 62100000001 <= available_max_fee 62100000000",
        ],
        [
            "a force close with a fee rate",
            { force: true, fee_rate: "0x3e8" },
            "close_script and fee_rate should not be set when force is true",
        ],
        [
            "a force close with a close script",
            { force: true, close_script: USER_LOCK_WIRE },
            "close_script and fee_rate should not be set when force is true",
        ],
    ])("refuses %s with fiber's text, the channel staying ready", async (_, params, message) => {
        const h = await opened();
        expect(await postShutdown(h, params)).toEqual({ jsonrpc: "2.0", id: 1, error: { code: -32000, message } });
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "ready" }]);
    });

    it("serves no force close, which the forceClose move stands for", async () => {
        const h = await opened();
        await expect(postShutdown(h, { force: true })).rejects.toThrow(
            new Error("the double serves no force close by shutdown_channel: the forceClose move stands for it"),
        );
    });
});

describe("the tenant node's peerShutdown", () => {
    it.each<[string, bigint, string]>([
        [
            "at the first fee rate whose fee the peer's share cannot pay",
            35_227_272_730n,
            "fiber's node refuses a shutdown whose fee the peer's share cannot pay",
        ],
        [
            "below the commitment fee rate",
            999n,
            "fiber's node answers no shutdown below the commitment fee rate: the double leaves the wait out",
        ],
    ])("throws on a shutdown %s, the channel staying ready", async (_, feeRate, message) => {
        const h = await opened();
        expect(() => h.node.peerShutdown({ feeRate })).toThrow(new Error(message));
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, state: "ready" }]);
    });

    it("throws on a shutdown while the device's add is still announced, which the double does not model", async () => {
        const h = await opened();
        await h.sdk.transfer(LSP_INVOICE_STRING);
        await flush();
        expect(() => h.node.peerShutdown()).toThrow(new Error("the double shuts down only once no TLC's add is still announced"));
    });

    it("throws on a shutdown on a channel already closing", async () => {
        const h = await opened();
        h.node.peerShutdown();
        expect(() => h.node.peerShutdown()).toThrow(new Error("a channel ShuttingDown does not shut down"));
    });
});
