import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../src/common";
import { blake160, moleculeScript } from "../../../src/common";
import { computeTxMessage, readCommitmentLockSettlementHash } from "../../../src/digest";
import type { ChannelPolicyRecord, NonceReuseMode, PolicyView } from "../../../src/policy";
import { CHANNEL_RECORD_KEY_PREFIX, POLICY_VIEWS } from "../../../src/policy";
import type { SubmitChannelSignatureParams } from "../../../src/rpc";
import { FiberRpcClient, RpcError } from "../../../src/rpc";
import { buildNextMaterial, getPublicNonce } from "../../../src/signer";
import { decodeMoleculeCellOutput } from "../../../src/wire";
import { InMemorySignerStorage } from "../../mocks/policy";
import { signingDeviceKeys } from "../../utils/signing-channel";
import { forgetSecondSession } from "../../utils/nonce-cap-bypass";
import { loadSigningVectors } from "../../utils/signing-vectors";
import type { TenantDevice, TenantFlow } from "../../utils/tenant-flow";
import {
    CHANNEL,
    CHANNEL_ID,
    CHANNEL_INDEX,
    OTHER_CHANNEL_ID,
    TENANT_NODE_URL,
    methods,
    openChannel,
    post,
    recordOf,
    start,
    tenantDevice,
    tenantNode,
    tick,
    ticks,
} from "../../utils/tenant-flow";
import type { InMemoryTenantNode, TenantNodePayment } from "../../utils/tenant-node";
import { writes } from "../../utils/stored-records";

const vectors = loadSigningVectors();
const SIGNED_TICK = ["get_channel_signing_status", "submit_channel_signature"];
const UNSIGNED_TICK = ["get_channel_signing_status"];

const RECEIVED: TenantNodePayment = {
    paymentHash: "3f1c9a5e7d2b4068a1e9c3d5f7b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6",
    amountShannons: "2250000000",
    hashAlgorithm: "sha256",
    expiryMs: "1760580000000",
};
const RECEIVED_AGAIN: TenantNodePayment = {
    paymentHash: "7c2e4a6b8d0f1e3c5a7b9d1f2e4c6a8b0d2f4e6c8a1b3d5f7e9c2a4b6d8f0e1c",
    amountShannons: "1250000000",
    hashAlgorithm: "sha256",
    expiryMs: "1760583600000",
};
const SENT: TenantNodePayment = {
    paymentHash: "b570807ecd66dbcebb2947e7406032a30e8cf3aa5b428a117ec408754480834f",
    amountShannons: "1500000000",
    hashAlgorithm: "ckb-hash",
    expiryMs: "1760576400000",
};
const SENT_BUDGET = "1600000000";
const SENT_AGAIN: TenantNodePayment = {
    paymentHash: "5d8e2f4a6c1b3d5e7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e1b3d5f7a9c2e4b6d",
    amountShannons: "800000000",
    hashAlgorithm: "sha256",
    expiryMs: "1760587200000",
};
const SENT_AGAIN_BUDGET = "900000000";
// The bound 20 bytes of SENT's hash, another tail.
const SENT_TWIN_HASH = "b570807ecd66dbcebb2947e7406032a30e8cf3aa0000000000000000000000ff";

function device(node: InMemoryTenantNode, nonceReuse: NonceReuseMode, storage: InMemorySignerStorage): TenantDevice {
    return tenantDevice(node, { policy: { nonceReuse }, watchtower: false, storage });
}

function flow(nonceReuse: NonceReuseMode): TenantFlow {
    const node = tenantNode();
    return { node, device: device(node, nonceReuse, new InMemorySignerStorage()) };
}

async function openedUnderAllow(): Promise<TenantFlow> {
    const h = flow("allow");
    await openChannel(h, "CompleteReceivedCommitment");
    await start(h.device);
    await tick(h.device);
    return h;
}

function signings(h: TenantFlow, device = h.device): string[] {
    const served = h.node.served;
    return device.events.map((event) => {
        if (event.type !== "SIGNING") return event.type === "ERROR" ? `ERROR ${event.error.code}` : event.type;
        if (event.channelId !== CHANNEL_ID) return `SIGNING on ${event.channelId}`;
        const slot = served.find((request) => request.requestId === event.requestId)?.slot ?? "an unserved request";
        const outcome = event.outcome === "refused" ? `refused ${event.error.code}` : event.outcome;
        return `${event.transition ?? "unread"} ${slot} ${outcome}`;
    });
}

function requests(h: TenantFlow): string[] {
    return h.node.served.map((request) => `${request.transition} ${request.slot} ${request.answers.join("+") || "unanswered"}`);
}

function refusalOf(h: TenantFlow): string {
    const last = h.device.events.at(-1);
    if (last?.type !== "SIGNING" || last.outcome !== "refused") throw new Error("the last event is no refusal");
    return last.error.message;
}

function messageOf(h: TenantFlow, index: number): string {
    const request = h.node.served[index];
    if (request === undefined) throw new Error(`the node served no request ${index}`);
    return request.message;
}

// Each view's last commitment, once its kept cell is the one the kept message signs.
function signedCommitmentsOf(record: ChannelPolicyRecord): Partial<Record<PolicyView, { commitmentNumber: number; txHash: string }>> {
    const signed: Partial<Record<PolicyView, { commitmentNumber: number; txHash: string }>> = {};
    for (const view of POLICY_VIEWS) {
        const entry = record.commitmentHashes[view];
        if (entry === undefined) continue;
        expect(Object.keys(entry)).toEqual(["commitmentNumber", "txHash", "source", "settlementWitness"]);
        const { commitmentNumber, txHash, source, settlementWitness } = entry;
        if (source === undefined || settlementWitness === undefined) throw new Error(`the ${view} commitment keeps no cell`);
        expect(Object.keys(source)).toEqual(["output", "outputData"]);
        expect(source.outputData).toBe("");
        const cell = decodeMoleculeCellOutput({ value: `0x${source.output}`, path: `${view}.source.output` });
        const signedTx = {
            version: 0,
            cellDeps: [],
            headerDeps: [],
            inputs: [{ since: 0n, previousOutput: CHANNEL.fundingOutPoint }],
            outputs: [cell],
            outputsData: [new Uint8Array(0)],
            witnesses: [],
        };
        expect(bytesToHex(computeTxMessage(signedTx))).toBe(txHash);
        expect(bytesToHex(blake160(hexToBytes(settlementWitness)))).toBe(bytesToHex(readCommitmentLockSettlementHash(cell.lock.args)));
        signed[view] = { commitmentNumber, txHash };
    }
    return signed;
}

async function expectRefused(h: TenantFlow, served: string, refusal: string): Promise<void> {
    const before = await recordOf(h.device);
    const sent = h.node.calls.length;
    h.device.storage.ops.length = 0;
    await tick(h.device, 2);
    expect(writes(h.device.storage)).toEqual([]);
    expect(h.node.calls.slice(sent).map((call) => call.method)).toEqual(ticks(UNSIGNED_TICK, 2));
    expect(requests(h).at(-1)).toBe(`${served} unanswered`);
    expect(signings(h).slice(-2)).toEqual([`${served} ${refusal}`, `${served} ${refusal}`]);
    expect(await recordOf(h.device)).toEqual(before);
}

describe("the signing step over the tenant node", () => {
    describe("the open", () => {
        it("signs the received commitment, then the sent one on the same slot as a warned second session, and goes idle", async () => {
            const h = await openedUnderAllow();
            await tick(h.device);
            expect(methods(h)).toEqual([...ticks(SIGNED_TICK, 2), ...UNSIGNED_TICK]);
            expect(requests(h)).toEqual(["CompleteReceivedCommitment Commitment@1 Applied", "SendCommitmentSigned Commitment@1 Applied"]);
            expect(signings(h)).toEqual(["CompleteReceivedCommitment Commitment@1 signed", "SendCommitmentSigned Commitment@1 warning"]);
            expect(h.node.counters).toEqual({ local: 2, remote: 2 });
            expect(h.node.published).toEqual({
                nonces: ["Commitment@0", "Commitment@1", "Commitment@2", "Revocation@2"],
                points: [1, 2],
            });
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 1 });
            expect(signedCommitmentsOf(record)).toEqual({
                local: { commitmentNumber: 1, txHash: messageOf(h, 0) },
                remote: { commitmentNumber: 1, txHash: messageOf(h, 1) },
            });
            expect(Object.keys(record.nonceReuse)).toEqual(["COMMITMENT:1"]);
            expect(record.revocations).toEqual([]);
        });

        it("signs the sent commitment first when fiber sends before the peer's arrives, the received one second", async () => {
            const h = flow("allow");
            await openChannel(h, "SendCommitmentSigned");
            await start(h.device);
            await tick(h.device);
            expect(methods(h)).toEqual(ticks(SIGNED_TICK, 2));
            expect(requests(h)).toEqual(["SendCommitmentSigned Commitment@1 Applied", "CompleteReceivedCommitment Commitment@1 Applied"]);
            expect(signings(h)).toEqual(["SendCommitmentSigned Commitment@1 signed", "CompleteReceivedCommitment Commitment@1 warning"]);
            expect(h.node.counters).toEqual({ local: 2, remote: 2 });
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 1 });
            expect(signedCommitmentsOf(record)).toEqual({
                remote: { commitmentNumber: 1, txHash: messageOf(h, 0) },
                local: { commitmentNumber: 1, txHash: messageOf(h, 1) },
            });
            expect(record.revocations).toEqual([]);
        });
    });

    describe("a payment received", () => {
        it("signs both rounds under allow, warning on the four second sessions the lifecycle asks for", async () => {
            const h = await openedUnderAllow();
            h.node.receivePayment(RECEIVED);
            await tick(h.device, 4);
            h.node.fulfil(RECEIVED.paymentHash);
            await tick(h.device, 4);
            expect(methods(h)).toEqual(ticks(SIGNED_TICK, 10));
            expect(requests(h)).toEqual([
                "CompleteReceivedCommitment Commitment@1 Applied",
                "SendCommitmentSigned Commitment@1 Applied",
                "CompleteReceivedCommitment Commitment@2 Applied",
                "SendRevokeAndAck Revocation@2 Applied",
                "SendCommitmentSigned Commitment@2 Applied",
                "CompleteReceivedRevokeAndAck Revocation@2 Applied",
                "SendCommitmentSigned Commitment@3 Applied",
                "CompleteReceivedRevokeAndAck Revocation@3 Applied",
                "CompleteReceivedCommitment Commitment@4 Applied",
                "SendRevokeAndAck Revocation@3 Applied",
            ]);
            expect(signings(h)).toEqual([
                "CompleteReceivedCommitment Commitment@1 signed",
                "SendCommitmentSigned Commitment@1 warning",
                "CompleteReceivedCommitment Commitment@2 signed",
                "SendRevokeAndAck Revocation@2 signed",
                "SendCommitmentSigned Commitment@2 warning",
                "CompleteReceivedRevokeAndAck Revocation@2 warning",
                "SendCommitmentSigned Commitment@3 signed",
                "CompleteReceivedRevokeAndAck Revocation@3 signed",
                "CompleteReceivedCommitment Commitment@4 signed",
                "SendRevokeAndAck Revocation@3 warning",
            ]);
            expect(h.node.counters).toEqual({ local: 4, remote: 4 });
            expect(h.node.published).toEqual({
                nonces: [
                    "Commitment@0",
                    "Commitment@1",
                    "Commitment@2",
                    "Commitment@3",
                    "Commitment@4",
                    "Commitment@5",
                    "Revocation@2",
                    "Revocation@3",
                    "Revocation@4",
                    "Revocation@5",
                ],
                points: [1, 2, 3, 4, 5],
            });
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 4, "REVOKE:local": 3, "REVOKE:remote": 3 });
            expect(signedCommitmentsOf(record)).toEqual({
                local: { commitmentNumber: 3, txHash: messageOf(h, 8) },
                remote: { commitmentNumber: 3, txHash: messageOf(h, 6) },
            });
            expect(record.revocations.map(({ version, forRemote }) => ({ version, forRemote }))).toEqual([
                { version: 1, forRemote: true },
                { version: 2, forRemote: true },
            ]);
            expect(Object.keys(record.nonceReuse).sort()).toEqual(["COMMITMENT:1", "COMMITMENT:2", "REVOKE:2", "REVOKE:3"]);
            // The received amount, now the device's in both views, reserve included.
            expect([record.views.local.exposureShannons, record.views.remote.exposureShannons]).toEqual(["74250000000", "74250000000"]);
        });

        it("stalls the second payment received at Commitment@4 under allow: the peer's round asks for a third session there", async () => {
            const h = await openedUnderAllow();
            h.node.receivePayment(RECEIVED);
            await tick(h.device, 4);
            h.node.fulfil(RECEIVED.paymentHash);
            await tick(h.device, 4);
            h.node.receivePayment(RECEIVED_AGAIN);
            await tick(h.device, 2);
            const before = await recordOf(h.device);
            await expectRefused(h, "SendCommitmentSigned Commitment@4", "refused policy_refusal");
            expect(refusalOf(h)).toBe("slot COMMITMENT:4 has already served two signing sessions, the most one nonce can");
            expect(methods(h)).toEqual([...ticks(SIGNED_TICK, 12), ...ticks(UNSIGNED_TICK, 2)]);
            expect(requests(h).slice(10)).toEqual([
                "CompleteReceivedCommitment Commitment@4 Applied",
                "SendRevokeAndAck Revocation@4 Applied",
                "SendCommitmentSigned Commitment@4 unanswered",
            ]);
            expect(signings(h).slice(10)).toEqual([
                "CompleteReceivedCommitment Commitment@4 warning",
                "SendRevokeAndAck Revocation@4 signed",
                "SendCommitmentSigned Commitment@4 refused policy_refusal",
                "SendCommitmentSigned Commitment@4 refused policy_refusal",
            ]);
            expect(h.node.counters).toEqual({ local: 4, remote: 5 });
            expect(before.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 4, "REVOKE:local": 3, "REVOKE:remote": 4 });
            expect(Object.keys(before.nonceReuse).sort()).toEqual(["COMMITMENT:1", "COMMITMENT:2", "COMMITMENT:4", "REVOKE:2", "REVOKE:3"]);
        });

        it("keeps the requests waiting on the node while the app is closed, and serves them in order once it starts", async () => {
            const h = await openedUnderAllow();
            h.device.poller.stop();
            h.node.receivePayment(RECEIVED);
            await tick(h.device, 3);
            expect(methods(h)).toEqual(ticks(SIGNED_TICK, 2));
            expect(requests(h).slice(2)).toEqual(["CompleteReceivedCommitment Commitment@2 unanswered"]);
            await start(h.device);
            await tick(h.device, 3);
            expect(methods(h)).toEqual(ticks(SIGNED_TICK, 6));
            expect(requests(h).slice(2)).toEqual([
                "CompleteReceivedCommitment Commitment@2 Applied",
                "SendRevokeAndAck Revocation@2 Applied",
                "SendCommitmentSigned Commitment@2 Applied",
                "CompleteReceivedRevokeAndAck Revocation@2 Applied",
            ]);
            expect(signings(h).slice(2)).toEqual([
                "CompleteReceivedCommitment Commitment@2 signed",
                "SendRevokeAndAck Revocation@2 signed",
                "SendCommitmentSigned Commitment@2 warning",
                "CompleteReceivedRevokeAndAck Revocation@2 warning",
            ]);
            expect(h.node.counters).toEqual({ local: 3, remote: 3 });
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 2, "REVOKE:local": 2, "REVOKE:remote": 2 });
            expect(signedCommitmentsOf(record)).toEqual({
                local: { commitmentNumber: 2, txHash: messageOf(h, 2) },
                remote: { commitmentNumber: 2, txHash: messageOf(h, 4) },
            });
            expect(record.revocations.map(({ version }) => version)).toEqual([1]);
        });
    });

    describe("a payment sent", () => {
        it("signs the add round and the peer's fulfil, then refuses the third session on Commitment@3 even under allow", async () => {
            const h = await openedUnderAllow();
            await h.device.policy.recordDebitIntent(SENT.paymentHash, SENT_BUDGET);
            h.node.sendPayment(SENT);
            await tick(h.device, 4);
            h.node.fulfil(SENT.paymentHash);
            await tick(h.device, 3);
            h.device.storage.ops.length = 0;
            await tick(h.device);
            expect(writes(h.device.storage)).toEqual([]);
            expect(methods(h)).toEqual([...ticks(SIGNED_TICK, 8), ...ticks(UNSIGNED_TICK, 2)]);
            expect(requests(h)).toEqual([
                "CompleteReceivedCommitment Commitment@1 Applied",
                "SendCommitmentSigned Commitment@1 Applied",
                "SendCommitmentSigned Commitment@2 Applied",
                "CompleteReceivedRevokeAndAck Revocation@2 Applied",
                "CompleteReceivedCommitment Commitment@3 Applied",
                "SendRevokeAndAck Revocation@2 Applied",
                "CompleteReceivedCommitment Commitment@3 Applied",
                "SendRevokeAndAck Revocation@3 Applied",
                "SendCommitmentSigned Commitment@3 unanswered",
            ]);
            expect(signings(h)).toEqual([
                "CompleteReceivedCommitment Commitment@1 signed",
                "SendCommitmentSigned Commitment@1 warning",
                "SendCommitmentSigned Commitment@2 signed",
                "CompleteReceivedRevokeAndAck Revocation@2 signed",
                "CompleteReceivedCommitment Commitment@3 signed",
                "SendRevokeAndAck Revocation@2 warning",
                "CompleteReceivedCommitment Commitment@3 warning",
                "SendRevokeAndAck Revocation@3 signed",
                "SendCommitmentSigned Commitment@3 refused policy_refusal",
                "SendCommitmentSigned Commitment@3 refused policy_refusal",
            ]);
            expect(refusalOf(h)).toBe("slot COMMITMENT:3 has already served two signing sessions, the most one nonce can");
            expect(h.node.counters).toEqual({ local: 3, remote: 4 });
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 3, "REVOKE:local": 2, "REVOKE:remote": 3 });
            expect(signedCommitmentsOf(record)).toEqual({
                remote: { commitmentNumber: 2, txHash: messageOf(h, 2) },
                local: { commitmentNumber: 3, txHash: messageOf(h, 6) },
            });
            expect(record.revocations.map(({ version }) => version)).toEqual([1]);
            // The local view paid the TLC out; the remote one still holds it offered.
            expect(record.views.local).toMatchObject({ exposureShannons: "70500000000", tlcs: [] });
            expect(record.views.local.chargedShannons).toEqual({ [SENT.paymentHash.slice(0, 40)]: SENT.amountShannons });
            expect(record.views.remote.tlcs.map(({ direction, amountShannons }) => ({ direction, amountShannons }))).toEqual([
                { direction: "offered", amountShannons: SENT.amountShannons },
            ]);
        });
    });

    describe("past Fiber's nonce stall, under a test-only bypass of the cap", () => {
        function bypassing(h: TenantFlow): void {
            h.node.bypassNonceCap((slot) => forgetSecondSession(h.device.storage, CHANNEL_INDEX, slot));
        }

        async function sentToTheEnd(h: TenantFlow): Promise<void> {
            bypassing(h);
            await h.device.policy.recordDebitIntent(SENT.paymentHash, SENT_BUDGET);
            h.node.sendPayment(SENT);
            await tick(h.device, 4);
            h.node.fulfil(SENT.paymentHash);
            await tick(h.device, 4);
        }

        async function receivedTwice(h: TenantFlow): Promise<void> {
            bypassing(h);
            h.node.receivePayment(RECEIVED);
            await tick(h.device, 4);
            h.node.fulfil(RECEIVED.paymentHash);
            await tick(h.device, 4);
            h.node.receivePayment(RECEIVED_AGAIN);
            await tick(h.device, 4);
            h.node.fulfil(RECEIVED_AGAIN.paymentHash);
            await tick(h.device, 4);
        }

        it("completes the payment sent: the third session on Commitment@3, then the peer's revocation of version 2", async () => {
            const h = await openedUnderAllow();
            await sentToTheEnd(h);
            await tick(h.device);
            expect(methods(h)).toEqual([...ticks(SIGNED_TICK, 10), ...UNSIGNED_TICK]);
            expect(requests(h).slice(2)).toEqual([
                "SendCommitmentSigned Commitment@2 Applied",
                "CompleteReceivedRevokeAndAck Revocation@2 Applied",
                "CompleteReceivedCommitment Commitment@3 Applied",
                "SendRevokeAndAck Revocation@2 Applied",
                "CompleteReceivedCommitment Commitment@3 Applied",
                "SendRevokeAndAck Revocation@3 Applied",
                "SendCommitmentSigned Commitment@3 Applied",
                "CompleteReceivedRevokeAndAck Revocation@3 Applied",
            ]);
            expect(signings(h).slice(2)).toEqual([
                "SendCommitmentSigned Commitment@2 signed",
                "CompleteReceivedRevokeAndAck Revocation@2 signed",
                "CompleteReceivedCommitment Commitment@3 signed",
                "SendRevokeAndAck Revocation@2 warning",
                "CompleteReceivedCommitment Commitment@3 warning",
                "SendRevokeAndAck Revocation@3 signed",
                "SendCommitmentSigned Commitment@3 warning",
                "CompleteReceivedRevokeAndAck Revocation@3 warning",
            ]);
            expect(h.node.counters).toEqual({ local: 4, remote: 4 });
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 3, "REVOKE:local": 3, "REVOKE:remote": 3 });
            expect(signedCommitmentsOf(record)).toEqual({
                local: { commitmentNumber: 3, txHash: messageOf(h, 6) },
                remote: { commitmentNumber: 3, txHash: messageOf(h, 8) },
            });
            expect(record.revocations.map(({ version }) => version)).toEqual([1, 2]);
            // Settled in both views: the device's side less the payment, nothing in flight, the payment charged once per view.
            for (const view of [record.views.local, record.views.remote]) {
                expect(view).toEqual({
                    exposureShannons: "70500000000",
                    tlcs: [],
                    chargedShannons: { [SENT.paymentHash.slice(0, 40)]: SENT.amountShannons },
                    creditedShannons: {},
                });
            }
        });

        it("signs a cooperative close after the payment sent, on the fresh Commitment@4", async () => {
            const h = await openedUnderAllow();
            await sentToTheEnd(h);
            h.node.shutdown();
            await tick(h.device);
            expect(methods(h)).toEqual(ticks(SIGNED_TICK, 11));
            expect(requests(h).slice(10)).toEqual(["SendClosingSigned Commitment@4 Applied"]);
            expect(signings(h).slice(10)).toEqual(["SendClosingSigned Commitment@4 signed"]);
            expect(signings(h).filter((line) => line.includes("refused"))).toEqual([]);
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 4, "REVOKE:local": 3, "REVOKE:remote": 3 });
            expect(signedCommitmentsOf(record)).toEqual({
                local: { commitmentNumber: 3, txHash: messageOf(h, 6) },
                remote: { commitmentNumber: 3, txHash: messageOf(h, 8) },
            });
            expect(record.revocations.map(({ version }) => version)).toEqual([1, 2]);
        });

        it("completes the second payment received: the third session on Commitment@4, then both rounds of its fulfil", async () => {
            const h = await openedUnderAllow();
            await receivedTwice(h);
            await tick(h.device);
            expect(methods(h)).toEqual([...ticks(SIGNED_TICK, 18), ...UNSIGNED_TICK]);
            expect(requests(h).slice(10)).toEqual([
                "CompleteReceivedCommitment Commitment@4 Applied",
                "SendRevokeAndAck Revocation@4 Applied",
                "SendCommitmentSigned Commitment@4 Applied",
                "CompleteReceivedRevokeAndAck Revocation@4 Applied",
                "SendCommitmentSigned Commitment@5 Applied",
                "CompleteReceivedRevokeAndAck Revocation@5 Applied",
                "CompleteReceivedCommitment Commitment@6 Applied",
                "SendRevokeAndAck Revocation@5 Applied",
            ]);
            expect(signings(h).slice(10)).toEqual([
                "CompleteReceivedCommitment Commitment@4 warning",
                "SendRevokeAndAck Revocation@4 signed",
                "SendCommitmentSigned Commitment@4 warning",
                "CompleteReceivedRevokeAndAck Revocation@4 warning",
                "SendCommitmentSigned Commitment@5 signed",
                "CompleteReceivedRevokeAndAck Revocation@5 signed",
                "CompleteReceivedCommitment Commitment@6 signed",
                "SendRevokeAndAck Revocation@5 warning",
            ]);
            expect(signings(h).filter((line) => line.includes("refused"))).toEqual([]);
            expect(h.node.counters).toEqual({ local: 6, remote: 6 });
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 6, "REVOKE:local": 5, "REVOKE:remote": 5 });
            expect(signedCommitmentsOf(record)).toEqual({
                local: { commitmentNumber: 5, txHash: messageOf(h, 16) },
                remote: { commitmentNumber: 5, txHash: messageOf(h, 14) },
            });
            expect(record.revocations.map(({ version }) => version)).toEqual([1, 2, 3, 4]);
            expect([record.views.local.exposureShannons, record.views.remote.exposureShannons]).toEqual(["75500000000", "75500000000"]);
        });

        it("runs a third payment, sent, after the second received: the third session on Commitment@7 the same way", async () => {
            const h = await openedUnderAllow();
            await receivedTwice(h);
            await h.device.policy.recordDebitIntent(SENT_AGAIN.paymentHash, SENT_AGAIN_BUDGET);
            h.node.sendPayment(SENT_AGAIN);
            await tick(h.device, 4);
            h.node.fulfil(SENT_AGAIN.paymentHash);
            await tick(h.device, 5);
            expect(methods(h)).toEqual([...ticks(SIGNED_TICK, 26), ...UNSIGNED_TICK]);
            expect(requests(h).slice(18)).toEqual([
                "SendCommitmentSigned Commitment@6 Applied",
                "CompleteReceivedRevokeAndAck Revocation@6 Applied",
                "CompleteReceivedCommitment Commitment@7 Applied",
                "SendRevokeAndAck Revocation@6 Applied",
                "CompleteReceivedCommitment Commitment@7 Applied",
                "SendRevokeAndAck Revocation@7 Applied",
                "SendCommitmentSigned Commitment@7 Applied",
                "CompleteReceivedRevokeAndAck Revocation@7 Applied",
            ]);
            expect(signings(h).slice(18)).toEqual([
                "SendCommitmentSigned Commitment@6 warning",
                "CompleteReceivedRevokeAndAck Revocation@6 signed",
                "CompleteReceivedCommitment Commitment@7 signed",
                "SendRevokeAndAck Revocation@6 warning",
                "CompleteReceivedCommitment Commitment@7 warning",
                "SendRevokeAndAck Revocation@7 signed",
                "SendCommitmentSigned Commitment@7 warning",
                "CompleteReceivedRevokeAndAck Revocation@7 warning",
            ]);
            expect(signings(h).filter((line) => line.includes("refused"))).toEqual([]);
            expect(h.node.counters).toEqual({ local: 8, remote: 8 });
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 7, "REVOKE:local": 7, "REVOKE:remote": 7 });
            expect(signedCommitmentsOf(record)).toEqual({
                local: { commitmentNumber: 7, txHash: messageOf(h, 22) },
                remote: { commitmentNumber: 7, txHash: messageOf(h, 24) },
            });
            expect(record.revocations.map(({ version }) => version)).toEqual([1, 2, 3, 4, 5, 6]);
            for (const view of [record.views.local, record.views.remote]) {
                expect(view).toMatchObject({
                    exposureShannons: "74700000000",
                    tlcs: [],
                    chargedShannons: { [SENT_AGAIN.paymentHash.slice(0, 40)]: SENT_AGAIN.amountShannons },
                });
            }
        });
    });

    describe("a crash between signing and submitting", () => {
        it("signs the same bytes again after the restart, and takes the node's AlreadyApplied as success", async () => {
            const node = tenantNode();
            const crashed = device(node, "allow", new InMemorySignerStorage());
            await openChannel({ node, device: crashed }, "CompleteReceivedCommitment");
            node.parkNextSubmission();
            await start(crashed);
            crashed.poller.stop();
            const restarted = device(node, "allow", crashed.storage);
            const h = { node, device: restarted };
            restarted.storage.ops.length = 0;
            await start(restarted);
            expect(writes(restarted.storage)).toEqual([]);
            await tick(restarted);
            const calls = node.calls;
            expect(calls.map((call) => call.method)).toEqual(ticks(SIGNED_TICK, 3));
            expect(calls[3]?.params).toEqual(calls[1]?.params);
            expect(requests(h)).toEqual([
                "CompleteReceivedCommitment Commitment@1 Applied+AlreadyApplied",
                "SendCommitmentSigned Commitment@1 Applied",
            ]);
            expect(signings(h, crashed)).toEqual([]);
            expect(signings(h)).toEqual(["CompleteReceivedCommitment Commitment@1 signed", "SendCommitmentSigned Commitment@1 warning"]);
            expect(node.counters).toEqual({ local: 2, remote: 2 });
            const record = await recordOf(restarted);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 1 });
            expect(signedCommitmentsOf(record)).toEqual({
                local: { commitmentNumber: 1, txHash: messageOf(h, 0) },
                remote: { commitmentNumber: 1, txHash: messageOf(h, 1) },
            });
        });
    });

    describe("the cooperative close", () => {
        it("signs the close on the commitment slot at the local number, with no next material", async () => {
            const h = await openedUnderAllow();
            h.node.shutdown();
            await tick(h.device);
            expect(methods(h)).toEqual(ticks(SIGNED_TICK, 3));
            expect(h.node.calls[5]?.params).not.toHaveProperty("next_material");
            expect(requests(h).slice(2)).toEqual(["SendClosingSigned Commitment@2 Applied"]);
            expect(signings(h).slice(2)).toEqual(["SendClosingSigned Commitment@2 signed"]);
            expect(h.node.counters).toEqual({ local: 2, remote: 2 });
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 2 });
            expect(signedCommitmentsOf(record)).toEqual({
                local: { commitmentNumber: 1, txHash: messageOf(h, 0) },
                remote: { commitmentNumber: 1, txHash: messageOf(h, 1) },
            });
        });

        it("signs a close after a payment received as a warned second session on Commitment@4, where the device's own last commitment was completed", async () => {
            const h = await openedUnderAllow();
            h.node.receivePayment(RECEIVED);
            await tick(h.device, 4);
            h.node.fulfil(RECEIVED.paymentHash);
            await tick(h.device, 4);
            h.node.shutdown();
            await tick(h.device);
            expect(methods(h)).toEqual(ticks(SIGNED_TICK, 11));
            expect(requests(h).slice(8)).toEqual([
                "CompleteReceivedCommitment Commitment@4 Applied",
                "SendRevokeAndAck Revocation@3 Applied",
                "SendClosingSigned Commitment@4 Applied",
            ]);
            expect(signings(h).slice(8)).toEqual([
                "CompleteReceivedCommitment Commitment@4 signed",
                "SendRevokeAndAck Revocation@3 warning",
                "SendClosingSigned Commitment@4 warning",
            ]);
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 4, "REVOKE:local": 3, "REVOKE:remote": 3 });
            expect(Object.keys(record.nonceReuse).sort()).toEqual(["COMMITMENT:1", "COMMITMENT:2", "COMMITMENT:4", "REVOKE:2", "REVOKE:3"]);
        });
    });

    describe("the deadline", () => {
        function deadlinesOf(h: TenantFlow): string[] {
            const served = h.node.served;
            return h.device.events.map((event) => {
                if (event.type !== "SIGNING") return event.type;
                const slot = served.find((request) => request.requestId === event.requestId)?.slot ?? "an unserved request";
                return `${event.transition ?? "unread"} ${slot} ${"deadlineMs" in event ? String(event.deadlineMs) : "absent"}`;
            });
        }

        it("reports fiber's deadline on the add round's commitments, which state the TLC received, and none on the rest", async () => {
            const h = await openedUnderAllow();
            h.node.receivePayment(RECEIVED);
            await tick(h.device, 4);
            h.node.fulfil(RECEIVED.paymentHash);
            await tick(h.device, 4);
            h.node.shutdown();
            await tick(h.device);
            // RECEIVED's expiry, 1_760_580_000_000, less two thirds of the delay the open pinned, one epoch of 4 h: 9_600_000.
            expect((await recordOf(h.device)).pins.commitmentDelayEpoch).toBe(CHANNEL.commitmentDelayEpoch.toString());
            expect(CHANNEL.commitmentDelayEpoch).toBe((1n << 40n) | 1n);
            expect(deadlinesOf(h)).toEqual([
                "CompleteReceivedCommitment Commitment@1 absent",
                "SendCommitmentSigned Commitment@1 absent",
                "CompleteReceivedCommitment Commitment@2 1760570400000",
                "SendRevokeAndAck Revocation@2 absent",
                "SendCommitmentSigned Commitment@2 1760570400000",
                "CompleteReceivedRevokeAndAck Revocation@2 absent",
                // The fulfil's commitments no longer state the TLC.
                "SendCommitmentSigned Commitment@3 absent",
                "CompleteReceivedRevokeAndAck Revocation@3 absent",
                "CompleteReceivedCommitment Commitment@4 absent",
                "SendRevokeAndAck Revocation@3 absent",
                "SendClosingSigned Commitment@4 absent",
            ]);
        });
    });

    describe("a received revocation whose evidence write failed", () => {
        // The receive's add round up to its CompleteReceivedRevokeAndAck, whose claim lands and evidence write throws.
        async function failedEvidence(): Promise<TenantFlow> {
            const h = await openedUnderAllow();
            h.node.receivePayment(RECEIVED);
            await tick(h.device, 3);
            const { storage } = h.device;
            const set = storage.set.bind(storage);
            const failing = jest.spyOn(storage, "set").mockImplementation((key, value) => {
                const record = key.startsWith(CHANNEL_RECORD_KEY_PREFIX) ? (JSON.parse(value) as { revocations: unknown[] }) : null;
                if (record !== null && record.revocations.length > 0) throw new Error("the storage is full");
                set(key, value);
            });
            await tick(h.device);
            failing.mockRestore();
            expect(methods(h)).toEqual([...ticks(SIGNED_TICK, 5), ...UNSIGNED_TICK]);
            expect(requests(h).at(-1)).toBe("CompleteReceivedRevokeAndAck Revocation@2 unanswered");
            expect(signings(h).at(-1)).toBe("ERROR poll_failed");
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 2, "REVOKE:local": 2, "REVOKE:remote": 2 });
            expect(record.revocations).toEqual([]);
            return h;
        }

        it("refuses the peer's next commitment when the node moves past the revocation without asking it again", async () => {
            const h = await failedEvidence();
            h.node.skipPending();
            h.node.fulfil(RECEIVED.paymentHash);
            await expectRefused(h, "SendCommitmentSigned Commitment@3", "refused stale_state");
            expect(refusalOf(h)).toBe(
                "the remote commitment's version 3 must follow the revocation of version 1, at slot REVOKE:2, and its complete signature has not been recorded",
            );
            expect(h.node.counters).toEqual({ local: 3, remote: 3 });
        });

        it("records the evidence when the node asks for the revocation again, then signs the peer's next commitment", async () => {
            const h = await failedEvidence();
            await tick(h.device);
            h.node.fulfil(RECEIVED.paymentHash);
            await tick(h.device);
            expect(methods(h)).toEqual([...ticks(SIGNED_TICK, 5), ...UNSIGNED_TICK, ...ticks(SIGNED_TICK, 2)]);
            expect(requests(h).slice(5)).toEqual([
                "CompleteReceivedRevokeAndAck Revocation@2 Applied",
                "SendCommitmentSigned Commitment@3 Applied",
                "CompleteReceivedRevokeAndAck Revocation@3 unanswered",
            ]);
            expect(signings(h).slice(5)).toEqual([
                "ERROR poll_failed",
                "CompleteReceivedRevokeAndAck Revocation@2 warning",
                "SendCommitmentSigned Commitment@3 signed",
            ]);
            const record = await recordOf(h.device);
            expect(record.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 3, "REVOKE:local": 2, "REVOKE:remote": 2 });
            expect(record.revocations.map(({ version, forRemote }) => ({ version, forRemote }))).toEqual([{ version: 1, forRemote: true }]);
            expect(signedCommitmentsOf(record).remote).toEqual({ commitmentNumber: 3, txHash: messageOf(h, 6) });
        });
    });

    describe("the controls", () => {
        it("refuses a second message on a slot under refuse: the open's second commitment", async () => {
            const h = flow("refuse");
            await openChannel(h, "CompleteReceivedCommitment");
            await start(h.device);
            await expectRefused(h, "SendCommitmentSigned Commitment@1", "refused policy_refusal");
            expect(refusalOf(h)).toBe("slot COMMITMENT:1 has already served a different signing session");
            expect(signings(h)).toEqual([
                "CompleteReceivedCommitment Commitment@1 signed",
                "SendCommitmentSigned Commitment@1 refused policy_refusal",
                "SendCommitmentSigned Commitment@1 refused policy_refusal",
            ]);
            expect(h.node.counters).toEqual({ local: 1, remote: 1 });
            const record = await recordOf(h.device);
            expect(signedCommitmentsOf(record)).toEqual({ local: { commitmentNumber: 1, txHash: messageOf(h, 0) } });
            expect(record.nonceReuse).toEqual({});
        });

        it("refuses an aggregate that sums another nonce than the device's at the slot", async () => {
            const h = await openedUnderAllow();
            h.node.tamperNext({ kind: "aggNonce" });
            h.node.receivePayment(RECEIVED);
            await expectRefused(h, "CompleteReceivedCommitment Commitment@2", "refused malformed");
            expect(refusalOf(h)).toBe("the aggregated nonce is not the sum of this device's nonce at COMMITMENT:2 and the peer's");
        });

        it("refuses a peer partial signature over another message than the content's", async () => {
            const h = await openedUnderAllow();
            h.node.tamperNext({ kind: "peerSignature" });
            h.node.receivePayment(RECEIVED);
            await expectRefused(h, "CompleteReceivedCommitment Commitment@2", "refused malformed");
            expect(refusalOf(h)).toBe("the peer's partial signature does not verify over the message CompleteReceivedCommitment carries");
        });

        it("refuses a peer partial signature over another message on a received revocation", async () => {
            const h = await openedUnderAllow();
            await h.device.policy.recordDebitIntent(SENT.paymentHash, SENT_BUDGET);
            h.node.tamperNext({ kind: "peerSignature" });
            h.node.sendPayment(SENT);
            await tick(h.device);
            await expectRefused(h, "CompleteReceivedRevokeAndAck Revocation@2", "refused malformed");
            expect(refusalOf(h)).toBe("the peer's partial signature does not verify over the message CompleteReceivedRevokeAndAck carries");
            expect(requests(h).slice(2)).toEqual([
                "SendCommitmentSigned Commitment@2 Applied",
                "CompleteReceivedRevokeAndAck Revocation@2 unanswered",
            ]);
        });

        it("refuses a settlement whose commitment does not hash to the transaction's", async () => {
            const h = await openedUnderAllow();
            // One shannon above the 72000000000 the transaction pays the device, reserve included.
            h.node.tamperNext({ kind: "settlement", localAmountShannons: "72000000001" });
            h.node.receivePayment(RECEIVED);
            await expectRefused(h, "CompleteReceivedCommitment Commitment@2", "refused malformed");
            expect(refusalOf(h)).toBe("the message does not match the attached channel state");
        });

        it("refuses an offered TLC under a hash that shares the debit intent's bound 20 bytes and not the rest", async () => {
            const h = await openedUnderAllow();
            await h.device.policy.recordDebitIntent(SENT.paymentHash, SENT_BUDGET);
            h.node.sendPayment({ ...SENT, paymentHash: SENT_TWIN_HASH });
            await expectRefused(h, "SendCommitmentSigned Commitment@2", "refused policy_refusal");
            expect(refusalOf(h)).toBe(
                `the remote commitment offers a TLC under ${SENT_TWIN_HASH}, not the ${SENT.paymentHash} the debit intent under its bound hash names`,
            );
        });

        it("refuses a commitment that moves a value the open pinned", async () => {
            const h = await openedUnderAllow();
            h.node.tamperNext({ kind: "delayEpoch", commitmentDelayEpoch: "1099511627778" });
            h.node.receivePayment(RECEIVED);
            await expectRefused(h, "CompleteReceivedCommitment Commitment@2", "refused policy_refusal");
            expect(refusalOf(h)).toBe("the request states commitmentDelayEpoch 1099511627778, but the channel pinned 1099511627777");
        });

        it("refuses a close that pays the device's side to another script", async () => {
            const h = await openedUnderAllow();
            const elsewhere: Script = {
                codeHash: hexToBytes("9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"),
                hashType: "type",
                args: hexToBytes("4f2b8e6d1c3a5b7d9f0e2c4a6b8d0f1e3c5a7b9d"),
            };
            h.node.tamperNext({ kind: "closeScript", script: elsewhere });
            h.node.shutdown();
            await expectRefused(h, "SendClosingSigned Commitment@2", "refused policy_refusal");
            expect(refusalOf(h)).toBe(
                `the request states localCloseScript ${bytesToHex(moleculeScript(elsewhere))}, ` +
                    `but the channel pinned ${bytesToHex(moleculeScript(CHANNEL.localCloseScript))}`,
            );
        });

        it("refuses the peer's next commitment while the revocation of the one before it was never served", async () => {
            const h = await openedUnderAllow();
            h.node.receivePayment(RECEIVED);
            // The node goes past the peer's revoke_and_ack without the device: L moves, REVOKE:local never does.
            h.node.skipNext("CompleteReceivedRevokeAndAck");
            await tick(h.device, 3);
            h.node.fulfil(RECEIVED.paymentHash);
            await expectRefused(h, "SendCommitmentSigned Commitment@3", "refused stale_state");
            expect(refusalOf(h)).toBe(
                "the remote commitment's version 3 must follow the revocation of version 1, at slot REVOKE:2, and nothing has been signed on REVOKE:local",
            );
            expect(requests(h).slice(2)).toEqual([
                "CompleteReceivedCommitment Commitment@2 Applied",
                "SendRevokeAndAck Revocation@2 Applied",
                "SendCommitmentSigned Commitment@2 Applied",
                "SendCommitmentSigned Commitment@3 unanswered",
            ]);
        });
    });

    describe("the node's checks on a submission", () => {
        async function pendingAnswer(): Promise<{ h: TenantFlow; rpc: FiberRpcClient; valid: SubmitChannelSignatureParams }> {
            const h = flow("allow");
            await openChannel(h, "CompleteReceivedCommitment");
            const rpc = new FiberRpcClient({ url: TENANT_NODE_URL, fetch: h.node.fetch });
            const { status } = await rpc.getChannelSigningStatus({ channelId: CHANNEL_ID });
            const outcome = await h.device.dispatch.handle(CHANNEL_ID, status);
            if (outcome.kind !== "signed" || outcome.nextMaterial === null) throw new Error("the open's first request was not signed");
            const valid = {
                channelId: CHANNEL_ID,
                requestId: outcome.requestId,
                partialSignature: outcome.partialSignature,
                nextMaterial: outcome.nextMaterial,
            };
            return { h, rpc, valid };
        }

        it.each<[string, (valid: SubmitChannelSignatureParams) => SubmitChannelSignatureParams, string]>([
            [
                "a partial signature that does not verify",
                (valid) => ({ ...valid, partialSignature: new Uint8Array(32).fill(1) }),
                "Invalid parameter: signature is invalid: Musig2 VerifyError: failed to verify signature: signature is invalid",
            ],
            [
                "a partial signature at or above the curve order",
                (valid) => ({ ...valid, partialSignature: new Uint8Array(32).fill(0xff) }),
                "received invalid scalar bytes",
            ],
            [
                "another request id",
                (valid) => ({ ...valid, requestId: new Uint8Array(32).fill(0xee) }),
                "Invalid state: signature request id does not match the current request",
            ],
            [
                "no next material on an advancing transition",
                (valid) => ({ ...valid, nextMaterial: null }),
                "Invalid parameter: channel signer must provide next_material for transition CompleteReceivedCommitment",
            ],
            [
                "one nonce for both purposes",
                (valid) => ({ ...valid, nextMaterial: withMaterial(valid, { nextRevocationNonce: material(valid).nextCommitmentNonce }) }),
                "Invalid parameter: channel signer commitment and revocation nonces must be distinct",
            ],
            [
                "another point than the one the open published",
                (valid) => ({
                    ...valid,
                    nextMaterial: withMaterial(valid, { nextCommitmentPoint: hexToBytes(vectors.peer.funding_pubkey) }),
                }),
                "Invalid parameter: channel signer commitment point 2 conflicts with persisted material",
            ],
            [
                "another revocation nonce than the one the open published",
                (valid) => ({
                    ...valid,
                    nextMaterial: withMaterial(valid, { nextRevocationNonce: getPublicNonce(signingDeviceKeys(vectors), 0, "COMMITMENT") }),
                }),
                "Invalid parameter: channel signer nonce NonceSlot { purpose: Revocation, commitment_number: 2 } conflicts with persisted material",
            ],
        ])("refuses %s, leaving the request pending", async (_name, mutate, message) => {
            const { h, rpc, valid } = await pendingAnswer();
            await expect(rpc.submitChannelSignature(mutate(valid))).rejects.toEqual(
                new RpcError("submit_channel_signature", -32000, message),
            );
            expect(requests(h)).toEqual(["CompleteReceivedCommitment Commitment@1 unanswered"]);
            await expect(rpc.submitChannelSignature(valid)).resolves.toBe("Applied");
        });

        it("answers a repeat with AlreadyApplied and another signature for the same request with a mismatch", async () => {
            const { h, rpc, valid } = await pendingAnswer();
            await expect(rpc.submitChannelSignature(valid)).resolves.toBe("Applied");
            await expect(rpc.submitChannelSignature(valid)).resolves.toBe("AlreadyApplied");
            await expect(rpc.submitChannelSignature({ ...valid, partialSignature: new Uint8Array(32).fill(1) })).rejects.toEqual(
                new RpcError(
                    "submit_channel_signature",
                    -32000,
                    "Invalid state: submitted signature does not match the previously applied result",
                ),
            );
            expect(requests(h)).toEqual([
                "CompleteReceivedCommitment Commitment@1 Applied+AlreadyApplied",
                "SendCommitmentSigned Commitment@1 unanswered",
            ]);
        });

        it.each(["next_commitment_point", "next_commitment_nonce", "next_revocation_nonce"])(
            "refuses next material without its %s, leaving the request pending",
            async (missing) => {
                const { h, valid } = await pendingAnswer();
                const { nextCommitmentPoint, nextCommitmentNonce, nextRevocationNonce } = material(valid);
                const full: Record<string, string> = {
                    next_commitment_point: bytesToHex(nextCommitmentPoint),
                    next_commitment_nonce: `0x${bytesToHex(nextCommitmentNonce)}`,
                    next_revocation_nonce: `0x${bytesToHex(nextRevocationNonce)}`,
                };
                const nextMaterial = Object.fromEntries(Object.entries(full).filter(([member]) => member !== missing));
                const answer = await post(h.node, rawSubmission(valid, nextMaterial));
                expect(answer).toEqual({
                    jsonrpc: "2.0",
                    id: 4,
                    error: { code: -32000, message: `Invalid parameter: channel signer next_material missing ${missing} for commitment 2` },
                });
                expect(requests(h)).toEqual(["CompleteReceivedCommitment Commitment@1 unanswered"]);
            },
        );

        it("checks and installs next material sent with a close, which needs none", async () => {
            const h = await openedUnderAllow();
            h.node.shutdown();
            const rpc = new FiberRpcClient({ url: TENANT_NODE_URL, fetch: h.node.fetch });
            const { status } = await rpc.getChannelSigningStatus({ channelId: CHANNEL_ID });
            const outcome = await h.device.dispatch.handle(CHANNEL_ID, status);
            if (outcome.kind !== "signed") throw new Error("the close was not signed");
            const submission = { channelId: CHANNEL_ID, requestId: outcome.requestId, partialSignature: outcome.partialSignature };
            const next = buildNextMaterial(signingDeviceKeys(vectors), 3);
            await expect(
                rpc.submitChannelSignature({ ...submission, nextMaterial: { ...next, nextRevocationNonce: next.nextCommitmentNonce } }),
            ).rejects.toEqual(
                new RpcError(
                    "submit_channel_signature",
                    -32000,
                    "Invalid parameter: channel signer commitment and revocation nonces must be distinct",
                ),
            );
            await expect(rpc.submitChannelSignature({ ...submission, nextMaterial: next })).resolves.toBe("Applied");
            expect(requests(h).slice(2)).toEqual(["SendClosingSigned Commitment@2 Applied"]);
            expect(h.node.published).toEqual({
                nonces: ["Commitment@0", "Commitment@1", "Commitment@2", "Commitment@3", "Revocation@2", "Revocation@3"],
                points: [1, 2, 3],
            });
        });

        it("refuses a nonce of another length, leaving the request pending", async () => {
            const { h, valid } = await pendingAnswer();
            const { nextCommitmentPoint, nextRevocationNonce } = material(valid);
            const answer = await post(
                h.node,
                rawSubmission(valid, {
                    next_commitment_point: bytesToHex(nextCommitmentPoint),
                    next_commitment_nonce: "0x12",
                    next_revocation_nonce: `0x${bytesToHex(nextRevocationNonce)}`,
                }),
            );
            expect(answer).toEqual({
                jsonrpc: "2.0",
                id: 4,
                error: { code: -32000, message: "error decoding musig2::nonces::PubNonce: unexpected length 1" },
            });
            expect(requests(h)).toEqual(["CompleteReceivedCommitment Commitment@1 unanswered"]);
        });

        it("installs only the members of partial next material sent with a close", async () => {
            const h = await openedUnderAllow();
            h.node.shutdown();
            const rpc = new FiberRpcClient({ url: TENANT_NODE_URL, fetch: h.node.fetch });
            const { status } = await rpc.getChannelSigningStatus({ channelId: CHANNEL_ID });
            const outcome = await h.device.dispatch.handle(CHANNEL_ID, status);
            if (outcome.kind !== "signed") throw new Error("the close was not signed");
            const next = buildNextMaterial(signingDeviceKeys(vectors), 3);
            const answer = await post(
                h.node,
                rawSubmission(outcome, { next_commitment_nonce: `0x${bytesToHex(next.nextCommitmentNonce)}` }),
            );
            expect(answer).toEqual({ jsonrpc: "2.0", id: 4, result: { type: "Applied" } });
            expect(h.node.published).toEqual({
                nonces: ["Commitment@0", "Commitment@1", "Commitment@2", "Commitment@3", "Revocation@2"],
                points: [1, 2],
            });
        });

        it("lists no channel before the open", async () => {
            const answer = await post(tenantNode(), { jsonrpc: "2.0", id: 1, method: "list_channels", params: [{}] });
            expect(answer).toEqual({ jsonrpc: "2.0", id: 1, result: { channels: [] } });
        });

        it("answers a method it does not serve as jsonrpsee does", async () => {
            const h = await openedUnderAllow();
            const answer = await post(h.node, { jsonrpc: "2.0", id: 9, method: "abandon_channel", params: [{}] });
            expect(answer).toEqual({ jsonrpc: "2.0", id: 9, error: { code: -32601, message: "Method not found" } });
        });

        it.each<[string, unknown, string]>([
            ["get_channel_signing_status", {}, "params.channel_id must be 32 bytes of 0x-prefixed lowercase hex"],
            ["get_channel_signing_status", "0x12", "params must be an object"],
            [
                "get_channel_signing_status",
                { channel_id: "0x12" },
                "failed to convert vector into type: params.channel_id must be 32 bytes of 0x-prefixed lowercase hex",
            ],
            [
                "submit_channel_signature",
                { channel_id: CHANNEL_ID, request_id: `0x${"ab".repeat(32)}`, partial_signature: "0x12" },
                "failed to convert vector into type: params.partial_signature must be 32 bytes of 0x-prefixed lowercase hex",
            ],
        ])("refuses %s params it cannot read as jsonrpsee does", async (method, params, data) => {
            const h = await openedUnderAllow();
            const answer = await post(h.node, { jsonrpc: "2.0", id: 5, method, params: [params] });
            expect(answer).toEqual({ jsonrpc: "2.0", id: 5, error: { code: -32602, message: "Invalid params", data } });
        });

        it.each([
            ["get_channel_signing_status", { channel_id: OTHER_CHANNEL_ID }],
            [
                "submit_channel_signature",
                { channel_id: OTHER_CHANNEL_ID, request_id: `0x${"ab".repeat(32)}`, partial_signature: `0x${"01".repeat(32)}` },
            ],
        ])("refuses %s for a channel it does not hold", async (method, params) => {
            const h = await openedUnderAllow();
            const answer = await post(h.node, { jsonrpc: "2.0", id: 6, method, params: [params] });
            expect(answer).toEqual({
                jsonrpc: "2.0",
                id: 6,
                error: { code: -32000, message: `channel Hash256(${OTHER_CHANNEL_ID}) not found` },
            });
        });

        it("refuses a submission while no request is pending", async () => {
            const h = await openedUnderAllow();
            const rpc = new FiberRpcClient({ url: TENANT_NODE_URL, fetch: h.node.fetch });
            const request = h.node.served[0];
            if (request === undefined) throw new Error("the node served no request");
            await expect(
                rpc.submitChannelSignature({
                    channelId: CHANNEL_ID,
                    requestId: hexToBytes(request.requestId.slice(2)),
                    partialSignature: new Uint8Array(32).fill(1),
                    nextMaterial: null,
                }),
            ).rejects.toEqual(new RpcError("submit_channel_signature", -32000, "Invalid state: channel is not waiting for a signature"));
        });
    });
});

function rawSubmission(answer: { requestId: Uint8Array; partialSignature: Uint8Array }, nextMaterial: Record<string, string>): unknown {
    const params = {
        channel_id: CHANNEL_ID,
        request_id: `0x${bytesToHex(answer.requestId)}`,
        partial_signature: `0x${bytesToHex(answer.partialSignature)}`,
        next_material: nextMaterial,
    };
    return { jsonrpc: "2.0", id: 4, method: "submit_channel_signature", params: [params] };
}

function material(valid: SubmitChannelSignatureParams): NonNullable<SubmitChannelSignatureParams["nextMaterial"]> {
    if (valid.nextMaterial === null) throw new Error("the answer carries no next material");
    return valid.nextMaterial;
}

function withMaterial(
    valid: SubmitChannelSignatureParams,
    changes: Partial<NonNullable<SubmitChannelSignatureParams["nextMaterial"]>>,
): SubmitChannelSignatureParams["nextMaterial"] {
    return { ...material(valid), ...changes };
}
