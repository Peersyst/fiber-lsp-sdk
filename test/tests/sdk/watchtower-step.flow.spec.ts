import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import type { CellDep, Script } from "../../../src/common";
import type { PolicyEngineOptions, PolicyView, WatchtowerKeyPurpose, WatchtowerSpendRecord } from "../../../src/policy";
import { CHANNEL_RECORD_KEY_PREFIX } from "../../../src/policy";
import type { SubmitWatchtowerSignatureParams } from "../../../src/rpc";
import { FiberRpcClient, RpcError } from "../../../src/rpc";
import type { SdkEvent } from "../../../src/sdk";
import type { WireField } from "../../../src/wire";
import { InMemorySignerStorage } from "../../mocks/policy";
import { asList, asRecord } from "../../utils/json-shape";
import { loadSigningVectors, toCkbCellDep, watchtowerApprovalOf } from "../../utils/signing-vectors";
import type { TenantDevice, TenantFlow } from "../../utils/tenant-flow";
import {
    CHANNEL_ID,
    CHANNEL_INDEX,
    OTHER_CHANNEL_ID,
    TENANT_NODE_URL,
    methods,
    negotiateChannel,
    openChannel,
    post,
    recordOf,
    start,
    tenantDevice,
    tenantNode,
    tick,
    ticks,
} from "../../utils/tenant-flow";
import type { InMemoryTenantNode, TenantNodeForceClose, TenantNodePayment } from "../../utils/tenant-node";
import { writes } from "../../utils/stored-records";

const vectors = loadSigningVectors();

const APPROVAL = watchtowerApprovalOf(vectors);
const APPROVED: PolicyEngineOptions = { nonceReuse: "allow", watchtower: APPROVAL };
const UNAPPROVED: PolicyEngineOptions = { nonceReuse: "allow" };

const PREIMAGE = "9c4e2a7b1d3f5e8a0c6b4d2f1e3a5c7b9d0e2f4a6c8b1d3e5f7a9c0b2d4e6f81";
// Under PREIMAGE's sha256, which the node learns as the payee.
const INBOUND: TenantNodePayment = {
    paymentHash: "32df43e34e9725d638e55b4e2555daf427e0bf85db599dcae76e0b35bfdb6fcc",
    amountShannons: "2250000000",
    hashAlgorithm: "sha256",
    expiryMs: "1760608800000",
};
const OUTBOUND: TenantNodePayment = {
    paymentHash: "6e1d3f5a7c9b2e4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1d",
    amountShannons: "1500000000",
    hashAlgorithm: "ckb-hash",
    expiryMs: "1760590800000",
};
const OUTBOUND_BUDGET = "1600000000";

const FUNDING_CELL_DEPS: CellDep[] = vectors.watchtower.funding_cell_deps.map(toCkbCellDep);

// The node's lock is the destination the host approves: fiber's watchtower pays the node it runs on.
const FORCE_CLOSE: TenantNodeForceClose = {
    fundingCellDeps: FUNDING_CELL_DEPS,
    settlementCellDeps: vectors.watchtower.settlement_cell_deps.map(toCkbCellDep),
    nodeLock: APPROVAL.destination,
    // Past the outbound TLC's expiry, short of the inbound one's.
    medianTimeMs: "1760600000000",
    preimages: [PREIMAGE],
    commitmentsBack: 0,
};
// Short of both expiries.
const EARLY_MEDIAN_TIME_MS = "1760580000000";
// Past both: the peer times the inbound TLC out.
const PEER_FIRST_MEDIAN_TIME_MS = "1760612400000";

// The funding lock's dep as a peer configured otherwise resolves it.
const OTHER_FUNDING_CELL_DEPS: CellDep[] = [
    { outPoint: { txHash: hexToBytes("8d2f4b6a1c3e5d7f9b0a2c4e6d8f1a3b5c7e9d0f2a4b6c8e1d3f5a7b9c0e2d4f"), index: 0 }, depType: "code" },
    ...FUNDING_CELL_DEPS.slice(1),
];
// Other cells of the node's, under which the rebuilt spend's request id sorts below the first one's, and above.
const LOWER_ID_SPONSOR = "node's backup";
const HIGHER_ID_SPONSOR = "node's second";
const ELSEWHERE: Script = {
    codeHash: hexToBytes("9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"),
    hashType: "type",
    args: hexToBytes("4f2b8e6d1c3a5b7d9f0e2c4a6b8d0f1e3c5a7b9d"),
};

const SOURCE_REFUSAL =
    "watchtower source: input 0, spent with a since, must be the cell of the last local or remote commitment signed, or of the " +
    "remote one before it, and the settlement body is none of theirs";

// The channel step lists while the channel is open; the two signing steps read their status alone.
const SIGNED_TICK = ["list_channels", "get_channel_signing_status", "submit_channel_signature", "get_watchtower_signing_status"];
// The first tick past a force close: the channel step sees it closed and forgets it, the signing step polls it no more.
const CLOSING_TICK = ["list_channels", "get_watchtower_signing_status", "submit_watchtower_signature"];
// Then only the watchtower step polls it: no call fiber would wake an evicted tenant for.
const SPENT_TICK = ["get_watchtower_signing_status", "submit_watchtower_signature"];
const UNSPENT_TICK = ["get_watchtower_signing_status"];

function device(node: InMemoryTenantNode, policy: PolicyEngineOptions, storage: InMemorySignerStorage): TenantDevice {
    return tenantDevice(node, { policy, watchtower: true, channelStep: true, storage });
}

function flow(policy: PolicyEngineOptions): TenantFlow {
    const node = tenantNode();
    return { node, device: device(node, policy, new InMemorySignerStorage()) };
}

async function open(h: TenantFlow): Promise<void> {
    await openChannel(h, "CompleteReceivedCommitment");
    await start(h.device);
    await tick(h.device);
}

// A payment received and one sent: both views' last commitments hold the two TLCs.
async function withTlcsInFlight(h: TenantFlow): Promise<void> {
    await open(h);
    h.node.receivePayment(INBOUND);
    await tick(h.device, 4);
    await h.device.policy.recordDebitIntent(OUTBOUND.paymentHash, OUTBOUND_BUDGET);
    h.node.sendPayment(OUTBOUND);
    await tick(h.device, 4);
}

async function inFlight(options: PolicyEngineOptions): Promise<TenantFlow> {
    const h = flow(options);
    await withTlcsInFlight(h);
    return h;
}

function purposeOf(purpose: WatchtowerKeyPurpose | null): string {
    if (purpose === null) return "unread";
    return purpose.kind === "settlement" ? "Settlement" : `Tlc@${purpose.commitmentNumber}`;
}

function spends(h: TenantFlow): string[] {
    return h.node.watchtowerServed.map(
        (served) => `${purposeOf(served.purpose)} ${served.unlock} ${served.answers.join("+") || "unanswered"}`,
    );
}

function chain(h: TenantFlow): string[] {
    return h.node.onchain.map((tx) => `${tx.by} ${tx.what}`);
}

function watchtowerSignings(device: TenantDevice): string[] {
    return device.events.flatMap((event) => {
        if (event.type === "ERROR") return [`ERROR ${event.error.code}`];
        if (event.type !== "WATCHTOWER_SIGNING") return [];
        return [`${purposeOf(event.purpose)} ${event.outcome === "refused" ? `refused ${event.error.code}` : event.outcome}`];
    });
}

function signedEventsOf(h: TenantFlow): SdkEvent[] {
    return h.node.watchtowerServed.map((served) => ({
        type: "WATCHTOWER_SIGNING",
        channelId: CHANNEL_ID,
        requestId: served.requestId,
        purpose: served.purpose,
        outcome: "signed",
    }));
}

function watchtowerEventsOf(device: TenantDevice): SdkEvent[] {
    return device.events.filter((event) => event.type === "WATCHTOWER_SIGNING");
}

function appliedSpendsOf(h: TenantFlow, view: PolicyView): WatchtowerSpendRecord[] {
    return h.node.watchtowerServed.map((served) => {
        if (served.signature === null) throw new Error(`fiber applied no signature for ${served.requestId}`);
        return {
            requestId: served.requestId.slice(2),
            purpose: served.purpose,
            view,
            commitmentNumber: served.commitmentNumber,
            tlcEntry: served.tlcEntry,
            txHash: served.txHash,
            remainder: served.remainder === null ? null : { output: served.remainder, outputData: "" },
            signature: served.signature,
            applied: true,
        };
    });
}

function refusalOf(device: TenantDevice): string {
    const last = device.events.at(-1);
    if (last?.type !== "WATCHTOWER_SIGNING" || last.outcome !== "refused") throw new Error("the last event is no watchtower refusal");
    return last.error.message;
}

async function expectRefused(h: TenantFlow, spend: string, refusal: string): Promise<void> {
    const before = await recordOf(h.device);
    const sent = h.node.calls.length;
    h.device.storage.ops.length = 0;
    await tick(h.device, 2);
    // The channel step forgets the closed channel; the refusals write nothing.
    expect(writes(h.device.storage)).toEqual(["fiber-lsp-sdk:activity"]);
    expect(methods(h, sent)).toEqual(["list_channels", ...ticks(UNSPENT_TICK, 2)]);
    expect(spends(h)).toEqual([`${spend} unanswered`]);
    const purpose = spend.split(" ")[0];
    expect(watchtowerSignings(h.device)).toEqual([`${purpose} ${refusal}`, `${purpose} ${refusal}`]);
    expect(await recordOf(h.device)).toEqual(before);
    expect(before.watchtowerSpends).toBeUndefined();
}

describe("the watchtower step over the tenant node", () => {
    it("polls the watchtower of the open channel on every tick, idle while no commitment is on chain", async () => {
        const h = await inFlight(APPROVED);
        expect(methods(h)).toEqual(ticks(SIGNED_TICK, 10));
        expect(h.node.calls.filter((call) => call.method === "list_channels").map((call) => call.params)).toEqual(
            ticks([{ include_closed: true }], 10),
        );
        expect(watchtowerSignings(h.device)).toEqual([]);
        expect(h.node.watchtowerServed).toEqual([]);
        expect((await recordOf(h.device)).watchtowerSpends).toBeUndefined();
    });

    describe("a force close with a TLC each way in flight", () => {
        it("sweeps the device's own commitment: the outbound TLC by timeout, the inbound one by preimage, then its balance", async () => {
            const h = await inFlight(APPROVED);
            const sent = h.node.calls.length;
            h.node.forceClose("local", FORCE_CLOSE);
            await tick(h.device, 4);
            expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...ticks(SPENT_TICK, 2), ...UNSPENT_TICK]);
            expect(spends(h)).toEqual([
                "Tlc@3 outbound TLC by timeout Applied",
                "Tlc@2 inbound TLC by preimage Applied",
                "Settlement settlement Applied",
            ]);
            expect(chain(h)).toEqual([
                "node local commitment",
                "node outbound TLC by timeout",
                "node inbound TLC by preimage",
                "node settlement",
            ]);
            expect(watchtowerEventsOf(h.device)).toEqual(signedEventsOf(h));
            expect((await recordOf(h.device)).watchtowerSpends).toEqual(appliedSpendsOf(h, "local"));
        });

        it("sweeps the peer's commitment: the inbound TLC by preimage, the outbound one by timeout, then the device's balance", async () => {
            const h = await inFlight(APPROVED);
            const sent = h.node.calls.length;
            h.node.forceClose("remote", FORCE_CLOSE);
            await tick(h.device, 4);
            expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...ticks(SPENT_TICK, 2), ...UNSPENT_TICK]);
            expect(spends(h)).toEqual([
                "Tlc@2 inbound TLC by preimage Applied",
                "Tlc@3 outbound TLC by timeout Applied",
                "Settlement settlement Applied",
            ]);
            expect(chain(h)).toEqual([
                "peer remote commitment",
                "node inbound TLC by preimage",
                "node outbound TLC by timeout",
                "node settlement",
            ]);
            expect(watchtowerEventsOf(h.device)).toEqual(signedEventsOf(h));
            expect((await recordOf(h.device)).watchtowerSpends).toEqual(appliedSpendsOf(h, "remote"));
        });

        // No signature covers them: the device names the commitment cell by the settlement body it carries.
        it("sweeps the peer's commitment broadcast with funding lock cell deps of the peer's own", async () => {
            const h = await inFlight(APPROVED);
            const sent = h.node.calls.length;
            h.node.forceClose("remote", { ...FORCE_CLOSE, fundingCellDeps: OTHER_FUNDING_CELL_DEPS });
            await tick(h.device, 4);
            expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...ticks(SPENT_TICK, 2), ...UNSPENT_TICK]);
            expect(spends(h)).toEqual([
                "Tlc@2 inbound TLC by preimage Applied",
                "Tlc@3 outbound TLC by timeout Applied",
                "Settlement settlement Applied",
            ]);
            expect(watchtowerEventsOf(h.device)).toEqual(signedEventsOf(h));
            expect((await recordOf(h.device)).watchtowerSpends).toEqual(appliedSpendsOf(h, "remote"));
        });

        it("signs the inbound TLC's claim by preimage at once, and the outbound one's only once the node asks for it past its expiry", async () => {
            const h = await inFlight(APPROVED);
            const sent = h.node.calls.length;
            h.node.forceClose("local", { ...FORCE_CLOSE, medianTimeMs: EARLY_MEDIAN_TIME_MS });
            await tick(h.device, 2);
            expect(spends(h)).toEqual(["Tlc@2 inbound TLC by preimage Applied"]);
            h.node.passTime(FORCE_CLOSE.medianTimeMs);
            await tick(h.device, 3);
            expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...UNSPENT_TICK, ...ticks(SPENT_TICK, 2), ...UNSPENT_TICK]);
            expect(spends(h)).toEqual([
                "Tlc@2 inbound TLC by preimage Applied",
                "Tlc@3 outbound TLC by timeout Applied",
                "Settlement settlement Applied",
            ]);
            expect(watchtowerEventsOf(h.device)).toEqual(signedEventsOf(h));
            expect((await recordOf(h.device)).watchtowerSpends).toEqual(appliedSpendsOf(h, "local"));
        });

        it("signs no claim of the inbound TLC the node holds no preimage for, and the device's balance once that TLC has expired", async () => {
            const h = await inFlight(APPROVED);
            const sent = h.node.calls.length;
            h.node.forceClose("local", { ...FORCE_CLOSE, preimages: [] });
            await tick(h.device, 2);
            h.node.passTime(PEER_FIRST_MEDIAN_TIME_MS);
            await tick(h.device, 2);
            expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...UNSPENT_TICK, ...SPENT_TICK, ...UNSPENT_TICK]);
            expect(spends(h)).toEqual(["Tlc@3 outbound TLC by timeout Applied", "Settlement settlement Applied"]);
            expect(chain(h)).toEqual(["node local commitment", "node outbound TLC by timeout", "node settlement"]);
            expect((await recordOf(h.device)).watchtowerSpends).toEqual(appliedSpendsOf(h, "local"));
        });

        it("claims the device's TLC from the peer's remainder, then settles as the last party once the peer has", async () => {
            const h = await inFlight(APPROVED);
            const sent = h.node.calls.length;
            h.node.forceClose("local", { ...FORCE_CLOSE, medianTimeMs: PEER_FIRST_MEDIAN_TIME_MS });
            h.node.peerSpend();
            await tick(h.device);
            h.node.peerSpend();
            await tick(h.device, 2);
            expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...SPENT_TICK, ...UNSPENT_TICK]);
            expect(spends(h)).toEqual(["Tlc@3 outbound TLC by timeout Applied", "Settlement settlement as the last party Applied"]);
            expect(chain(h)).toEqual([
                "node local commitment",
                "peer outbound TLC by timeout",
                "node outbound TLC by timeout",
                "peer settlement",
                "node settlement as the last party",
            ]);
            expect(watchtowerEventsOf(h.device)).toEqual(signedEventsOf(h));
            const record = await recordOf(h.device);
            expect(record.watchtowerSpends).toEqual(appliedSpendsOf(h, "local"));
            expect(record.watchtowerSpends?.map(({ remainder }) => remainder !== null)).toEqual([true, false]);
        });
    });

    it("signs the spends of the peer's commitment before its last, which the peer may broadcast until it revokes it", async () => {
        const h = flow(APPROVED);
        await open(h);
        h.node.receivePayment(INBOUND);
        await tick(h.device, 4);
        await h.device.policy.recordDebitIntent(OUTBOUND.paymentHash, OUTBOUND_BUDGET);
        h.node.sendPayment(OUTBOUND);
        // The device signs the peer's next commitment; the peer's revoke_and_ack of the one before is still to come.
        await tick(h.device);
        const before = await recordOf(h.device);
        expect([before.previousRemoteCommitment?.commitmentNumber, before.commitmentHashes.remote?.commitmentNumber]).toEqual([2, 3]);
        const sent = h.node.calls.length;
        h.node.forceClose("remote", { ...FORCE_CLOSE, commitmentsBack: 1 });
        await tick(h.device, 3);
        expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...SPENT_TICK, ...UNSPENT_TICK]);
        expect(spends(h)).toEqual(["Tlc@2 inbound TLC by preimage Applied", "Settlement settlement Applied"]);
        expect(h.node.watchtowerServed.map(({ commitmentNumber }) => commitmentNumber)).toEqual([2, 2]);
        expect(chain(h)).toEqual(["peer remote commitment", "node inbound TLC by preimage", "node settlement"]);
        expect(watchtowerEventsOf(h.device)).toEqual(signedEventsOf(h));
        expect((await recordOf(h.device)).watchtowerSpends).toEqual(appliedSpendsOf(h, "remote"));
    });

    it("settles a commitment with no TLC in flight in one spend of the device's balance", async () => {
        const h = flow(APPROVED);
        await open(h);
        const sent = h.node.calls.length;
        h.node.forceClose("remote", FORCE_CLOSE);
        await tick(h.device, 2);
        expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...UNSPENT_TICK]);
        expect(spends(h)).toEqual(["Settlement settlement Applied"]);
        expect(chain(h)).toEqual(["peer remote commitment", "node settlement"]);
        expect((await recordOf(h.device)).watchtowerSpends).toEqual(appliedSpendsOf(h, "remote"));
    });

    // Fiber creates the watch row at `RemoteTxComplete` (`event_handler.rs:41-67`), and answers "watched channel not found" before.
    it("reads nothing pending while the channel opens unwatched, then signs its spend once fiber watches it", async () => {
        const h = flow(APPROVED);
        await negotiateChannel(h);
        await start(h.device);
        await tick(h.device);
        const opening = ["list_channels", "get_channel_signing_status", "get_watchtower_signing_status"];
        expect(methods(h)).toEqual(ticks(opening, 2));
        expect(h.device.events).toEqual([]);
        h.node.completeTxCollaboration("CompleteReceivedCommitment");
        await tick(h.device, 2);
        const sent = h.node.calls.length;
        h.node.forceClose("remote", FORCE_CLOSE);
        await tick(h.device, 2);
        expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...UNSPENT_TICK]);
        expect(spends(h)).toEqual(["Settlement settlement Applied"]);
        expect(watchtowerSignings(h.device)).toEqual(["Settlement signed"]);
        expect((await recordOf(h.device)).watchtowerSpends).toEqual(appliedSpendsOf(h, "remote"));
    });

    // Fiber deletes the watch row of a channel closed cooperatively and never creates one after (`event_handler.rs:68-78`).
    it("drops a channel closed cooperatively once the node no longer watches it, and then calls the node for nothing", async () => {
        const h = flow(APPROVED);
        await open(h);
        const sent = h.node.calls.length;
        h.node.shutdown();
        await tick(h.device, 3);
        expect(methods(h, sent)).toEqual([
            "list_channels",
            "get_channel_signing_status",
            "submit_channel_signature",
            "get_watchtower_signing_status",
            "list_channels",
            "get_watchtower_signing_status",
        ]);
        expect(
            await post(h.node, { jsonrpc: "2.0", id: 6, method: "get_watchtower_signing_status", params: [{ channel_id: CHANNEL_ID }] }),
        ).toEqual({
            jsonrpc: "2.0",
            id: 6,
            error: { code: -32000, message: "watched channel not found" },
        });
        expect(await h.device.channels.read()).toEqual([]);
        expect(h.device.events.map((event) => event.type)).toEqual(["CHANNEL_READY", "SIGNING", "SIGNING", "SIGNING", "CHANNEL_CLOSED"]);
        const idle = h.node.calls.length;
        await tick(h.device, 2);
        expect(methods(h, idle)).toEqual([]);
    });

    it("calls the node for nothing while it opened no channel: fiber would wake an evicted tenant for a listing", async () => {
        const h = flow(APPROVED);
        await start(h.device);
        await tick(h.device, 3);
        expect(h.node.calls).toEqual([]);
        expect(h.device.events).toEqual([]);
    });

    it("refuses every spend while the host approved no destination, signing nothing, and the node keeps the first waiting", async () => {
        const h = await inFlight(UNAPPROVED);
        h.node.forceClose("local", FORCE_CLOSE);
        await expectRefused(h, "Tlc@3 outbound TLC by timeout", "refused policy_refusal");
        expect(refusalOf(h.device)).toBe("watchtower option: the host approved no destination, so the device signs no watchtower spend");
        expect(chain(h)).toEqual(["node local commitment"]);
    });

    it("signs the same bytes again after a lost answer, and takes the node's AlreadyApplied as success", async () => {
        const node = tenantNode();
        const crashed = device(node, APPROVED, new InMemorySignerStorage());
        await withTlcsInFlight({ node, device: crashed });
        node.forceClose("local", FORCE_CLOSE);
        node.parkNextSubmission("submit_watchtower_signature");
        await tick(crashed);
        crashed.poller.stop();
        const parked = node.calls.length - 1;
        const restarted = device(node, APPROVED, crashed.storage);
        const h = { node, device: restarted };
        restarted.storage.ops.length = 0;
        await start(restarted);
        // The repeat claims nothing: its one write marks the spend the node took.
        expect(writes(restarted.storage)).toEqual([`${CHANNEL_RECORD_KEY_PREFIX}${CHANNEL_INDEX}`]);
        await tick(restarted, 3);
        const calls = node.calls;
        // The crashed device's tick saw the close: the restarted one polls the watchtower alone.
        expect(methods(h, parked + 1)).toEqual([...ticks(SPENT_TICK, 3), ...UNSPENT_TICK]);
        expect(calls[parked + 2]?.params).toEqual(calls[parked]?.params);
        expect(spends(h)).toEqual([
            "Tlc@3 outbound TLC by timeout Applied+AlreadyApplied",
            "Tlc@2 inbound TLC by preimage Applied",
            "Settlement settlement Applied",
        ]);
        expect(watchtowerSignings(crashed)).toEqual([]);
        expect(watchtowerEventsOf(restarted)).toEqual(signedEventsOf(h));
        expect((await recordOf(restarted)).watchtowerSpends).toEqual(appliedSpendsOf(h, "local"));
    });

    // Fiber keeps the request a rebuild supersedes pending, and serves the lowest id first (`fiber-types/src/watchtower.rs:160-162`).
    describe("a spend fiber rebuilds for an unlock the device signed", () => {
        async function firstRequestPending(): Promise<{ h: TenantFlow; status: WireField }> {
            const h = flow(APPROVED);
            await open(h);
            h.node.forceClose("remote", FORCE_CLOSE);
            const rpc = new FiberRpcClient({ url: TENANT_NODE_URL, fetch: h.node.fetch });
            const { status } = await rpc.getWatchtowerSigningStatus({ channelId: CHANNEL_ID });
            return { h, status };
        }

        function submissionsOf(h: TenantFlow): unknown[] {
            return h.node.calls.filter((call) => call.method === "submit_watchtower_signature").map((call) => call.params);
        }

        it("signs it unclaimed when the first one's submission was lost, then keeps the first, which fiber confirms after", async () => {
            const { h, status } = await firstRequestPending();
            // The device signs the first request, and its submission never reaches the node.
            if ((await h.device.dispatch.handleWatchtower(CHANNEL_ID, status)).kind !== "signed")
                throw new Error("the spend was not signed");
            h.node.fundSpendsFrom(LOWER_ID_SPONSOR);
            const sent = h.node.calls.length;
            await tick(h.device, 3);
            const [first, rebuilt] = h.node.watchtowerServed;
            if (first === undefined || rebuilt === undefined) throw new Error("the node rebuilt no spend");
            expect(rebuilt.requestId < first.requestId).toBe(true);
            expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...SPENT_TICK, ...UNSPENT_TICK]);
            expect(submissionsOf(h)).toEqual([
                { channel_id: CHANNEL_ID, request_id: rebuilt.requestId, signature: `0x${rebuilt.signature ?? ""}` },
                { channel_id: CHANNEL_ID, request_id: first.requestId, signature: `0x${first.signature ?? ""}` },
            ]);
            expect(spends(h)).toEqual(["Settlement settlement Applied", "Settlement settlement Applied"]);
            // The rebuilt spend lands; fiber still takes the first one's signature once it serves it again.
            expect(h.node.onchain.map(({ txHash }) => txHash)).toEqual([expect.any(String), rebuilt.txHash]);
            expect(watchtowerEventsOf(h.device)).toEqual(signedEventsOf(h).reverse());
            expect((await recordOf(h.device)).watchtowerSpends).toEqual(appliedSpendsOf(h, "remote").slice(0, 1));
        });

        it("signs it unclaimed when the first one's mark was lost, keeping the first unconfirmed", async () => {
            const { h } = await firstRequestPending();
            h.node.fundSpendsFrom(HIGHER_ID_SPONSOR);
            jest.spyOn(h.device.policy, "markWatchtowerSpendApplied").mockRejectedValueOnce(new TypeError("storage is full"));
            const sent = h.node.calls.length;
            await tick(h.device, 3);
            const [first, rebuilt] = h.node.watchtowerServed;
            if (first === undefined || rebuilt === undefined) throw new Error("the node rebuilt no spend");
            expect(first.requestId < rebuilt.requestId).toBe(true);
            expect(methods(h, sent)).toEqual([...CLOSING_TICK, ...SPENT_TICK, ...UNSPENT_TICK]);
            expect(submissionsOf(h)).toEqual([
                { channel_id: CHANNEL_ID, request_id: first.requestId, signature: `0x${first.signature ?? ""}` },
                { channel_id: CHANNEL_ID, request_id: rebuilt.requestId, signature: `0x${rebuilt.signature ?? ""}` },
            ]);
            expect(spends(h)).toEqual(["Settlement settlement Applied", "Settlement settlement Applied"]);
            expect(h.node.onchain.map(({ txHash }) => txHash)).toEqual([expect.any(String), rebuilt.txHash]);
            expect(watchtowerSignings(h.device)).toEqual(["ERROR poll_failed", "Settlement signed"]);
            const [recorded] = appliedSpendsOf(h, "remote");
            expect((await recordOf(h.device)).watchtowerSpends).toEqual([{ ...recorded, applied: false }]);
        });
    });

    describe("the controls", () => {
        it.each<[string, PolicyView, number, string]>([
            ["the device's own commitment before its last, which it revoked", "local", 1, "Tlc@2 inbound TLC by preimage"],
            ["the peer's commitment two before its last, which it revoked", "remote", 2, "Settlement settlement"],
        ])("refuses a spend of %s", async (_name, view, commitmentsBack, spend) => {
            const h = await inFlight(APPROVED);
            h.node.forceClose(view, { ...FORCE_CLOSE, commitmentsBack });
            await expectRefused(h, spend, "refused policy_refusal");
            expect(refusalOf(h.device)).toBe(SOURCE_REFUSAL);
        });

        it("refuses a spend that pays another lock than the approved destination", async () => {
            const h = await inFlight(APPROVED);
            h.node.tamperSpends({ kind: "destination", lock: ELSEWHERE });
            h.node.forceClose("local", FORCE_CLOSE);
            await expectRefused(h, "Tlc@3 outbound TLC by timeout", "refused policy_refusal");
            expect(refusalOf(h.device)).toBe(
                "watchtower destination: output 1 must pay the approved destination, with no type and no data",
            );
        });

        it("refuses a spend whose remainder keeps less than the cell less what the unlock releases", async () => {
            const h = await inFlight(APPROVED);
            h.node.tamperSpends({ kind: "remainder", shannons: "100000000" });
            h.node.forceClose("local", FORCE_CLOSE);
            await expectRefused(h, "Tlc@3 outbound TLC by timeout", "refused policy_refusal");
            expect(refusalOf(h.device)).toBe("watchtower remainder: output 0 is not the remainder fiber's watchtower leaves");
        });

        it("refuses a spend that names the key of another commitment number than the TLC's", async () => {
            const h = await inFlight(APPROVED);
            h.node.tamperSpends({ kind: "purpose", purpose: { kind: "tlc", commitmentNumber: 2 } });
            h.node.forceClose("local", FORCE_CLOSE);
            await expectRefused(h, "Tlc@2 outbound TLC by timeout", "refused policy_refusal");
            expect(refusalOf(h.device)).toBe("watchtower key: TLC 0 does not settle to the device's TLC key at commitment number 2");
        });
    });

    describe("the node's checks on a watchtower submission", () => {
        async function pendingSpend(): Promise<{ h: TenantFlow; rpc: FiberRpcClient; valid: SubmitWatchtowerSignatureParams }> {
            const h = await inFlight(APPROVED);
            h.node.forceClose("local", FORCE_CLOSE);
            const rpc = new FiberRpcClient({ url: TENANT_NODE_URL, fetch: h.node.fetch });
            const { status } = await rpc.getWatchtowerSigningStatus({ channelId: CHANNEL_ID });
            const outcome = await h.device.dispatch.handleWatchtower(CHANNEL_ID, status);
            if (outcome.kind !== "signed") throw new Error("the first spend was not signed");
            return { h, rpc, valid: { channelId: CHANNEL_ID, requestId: outcome.requestId, signature: outcome.signature } };
        }

        it.each<[string, (valid: SubmitWatchtowerSignatureParams) => SubmitWatchtowerSignatureParams, string]>([
            [
                "a recovery id above 3",
                (valid) => ({ ...valid, signature: withRecoveryId(valid.signature, 4) }),
                "invalid recovery id: bad recovery id",
            ],
            [
                "an r at or above the curve order",
                (valid) => ({ ...valid, signature: concatBytes(new Uint8Array(32).fill(0xff), valid.signature.subarray(32)) }),
                "invalid compact signature: malformed signature",
            ],
            [
                "a zero r",
                (valid) => ({ ...valid, signature: concatBytes(new Uint8Array(32), valid.signature.subarray(32)) }),
                "failed to recover pubkey: malformed signature",
            ],
            [
                "the other recovery id, which recovers another key",
                (valid) => ({ ...valid, signature: withRecoveryId(valid.signature, (valid.signature[64] ?? 0) ^ 1) }),
                "recovered public key does not match expected public key",
            ],
            [
                "another request id",
                (valid) => ({ ...valid, requestId: new Uint8Array(32).fill(0xee) }),
                "signature request id not found in pending requests",
            ],
        ])("refuses %s, leaving the request pending", async (_name, mutate, message) => {
            const { h, rpc, valid } = await pendingSpend();
            await expect(rpc.submitWatchtowerSignature(mutate(valid))).rejects.toEqual(
                new RpcError("submit_watchtower_signature", -32000, message),
            );
            expect(spends(h)).toEqual(["Tlc@3 outbound TLC by timeout unanswered"]);
            await expect(rpc.submitWatchtowerSignature(valid)).resolves.toBe("Applied");
            expect(spends(h)).toEqual(["Tlc@3 outbound TLC by timeout Applied"]);
        });

        it("refuses a signature of another length than 65 bytes, leaving the request pending", async () => {
            const { h, valid } = await pendingSpend();
            const answer = await post(h.node, submission(valid.requestId, "0x12"));
            expect(answer).toEqual({ jsonrpc: "2.0", id: 4, error: { code: -32000, message: "watchtower signature must be 65 bytes" } });
            expect(spends(h)).toEqual(["Tlc@3 outbound TLC by timeout unanswered"]);
        });

        it("answers a resubmission of an applied spend with AlreadyApplied, and another signature for it with a mismatch", async () => {
            const h = await inFlight(APPROVED);
            h.node.forceClose("local", FORCE_CLOSE);
            await tick(h.device, 2);
            const [first] = h.node.watchtowerServed;
            if (first?.signature === null || first === undefined) throw new Error("fiber applied no first spend");
            const rpc = new FiberRpcClient({ url: TENANT_NODE_URL, fetch: h.node.fetch });
            const resubmission = {
                channelId: CHANNEL_ID,
                requestId: hexToBytes(first.requestId.slice(2)),
                signature: hexToBytes(first.signature),
            };
            await expect(rpc.submitWatchtowerSignature(resubmission)).resolves.toBe("AlreadyApplied");
            await expect(
                rpc.submitWatchtowerSignature({ ...resubmission, signature: withRecoveryId(resubmission.signature, 2) }),
            ).rejects.toEqual(
                new RpcError("submit_watchtower_signature", -32000, "submitted signature does not match the previously applied result"),
            );
            expect(spends(h)).toEqual(["Tlc@3 outbound TLC by timeout Applied+AlreadyApplied", "Tlc@2 inbound TLC by preimage Applied"]);
        });

        it("refuses a signature for a TLC key no commitment it watches holds, before reading the signature", async () => {
            const h = await inFlight(APPROVED);
            h.node.tamperSpends({ kind: "purpose", purpose: { kind: "tlc", commitmentNumber: 9 } });
            h.node.forceClose("local", FORCE_CLOSE);
            const rpc = new FiberRpcClient({ url: TENANT_NODE_URL, fetch: h.node.fetch });
            await rpc.getWatchtowerSigningStatus({ channelId: CHANNEL_ID });
            const [request] = h.node.watchtowerServed;
            if (request === undefined) throw new Error("the node built no spend");
            await expect(
                rpc.submitWatchtowerSignature({
                    channelId: CHANNEL_ID,
                    requestId: hexToBytes(request.requestId.slice(2)),
                    signature: new Uint8Array(65).fill(1),
                }),
            ).rejects.toEqual(new RpcError("submit_watchtower_signature", -32000, "TLC signing key not found for derivation index 9"));
            expect(spends(h)).toEqual(["Tlc@9 outbound TLC by timeout unanswered"]);
        });

        it("answers a submission while nothing is pending with the request it does not find", async () => {
            const h = await inFlight(APPROVED);
            const answer = await post(h.node, submission(new Uint8Array(32).fill(0xab), `0x${"01".repeat(65)}`));
            expect(answer).toEqual({
                jsonrpc: "2.0",
                id: 4,
                error: { code: -32000, message: "signature request id not found in pending requests" },
            });
        });

        it.each([
            ["get_watchtower_signing_status", { channel_id: OTHER_CHANNEL_ID }],
            [
                "submit_watchtower_signature",
                { channel_id: OTHER_CHANNEL_ID, request_id: `0x${"ab".repeat(32)}`, signature: `0x${"01".repeat(65)}` },
            ],
        ])("refuses %s for a channel it does not watch", async (method, params) => {
            const h = await inFlight(APPROVED);
            const answer = await post(h.node, { jsonrpc: "2.0", id: 6, method, params: [params] });
            expect(answer).toEqual({ jsonrpc: "2.0", id: 6, error: { code: -32000, message: "watched channel not found" } });
        });

        it.each<[string, unknown, string]>([
            ["get_watchtower_signing_status", {}, "params.channel_id must be 32 bytes of 0x-prefixed lowercase hex"],
            [
                "submit_watchtower_signature",
                { channel_id: CHANNEL_ID, request_id: "0x12", signature: "0x12" },
                "failed to convert vector into type: params.request_id must be 32 bytes of 0x-prefixed lowercase hex",
            ],
        ])("refuses %s params it cannot read as jsonrpsee does", async (method, params, data) => {
            const h = await inFlight(APPROVED);
            const answer = await post(h.node, { jsonrpc: "2.0", id: 5, method, params: [params] });
            expect(answer).toEqual({ jsonrpc: "2.0", id: 5, error: { code: -32602, message: "Invalid params", data } });
        });
    });

    describe("the node's listing", () => {
        it.each<[PolicyView, string]>([
            ["local", "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT"],
            ["remote", "UNCOOPERATIVE_REMOTE|WAITING_ONCHAIN_SETTLEMENT"],
        ])("lists the channel ready, then force closed in the %s view only to a call that asks for closed ones", async (view, flags) => {
            const h = await inFlight(APPROVED);
            const ready = [{ channel_id: CHANNEL_ID, state: { state_name: "ChannelReady" } }];
            expect(await listed(h, {})).toEqual(ready);
            expect(await listed(h, { include_closed: true })).toEqual(ready);
            h.node.forceClose(view, FORCE_CLOSE);
            expect(await listed(h, {})).toEqual([]);
            expect(await listed(h, { include_closed: true })).toEqual([
                { channel_id: CHANNEL_ID, state: { state_name: "Closed", state_flags: flags } },
            ]);
        });

        it("lists a channel closing cooperatively as shutting down, then as closed only to a call that asks for closed ones", async () => {
            const h = flow(APPROVED);
            await open(h);
            h.node.shutdown();
            expect(await listed(h, {})).toEqual([
                {
                    channel_id: CHANNEL_ID,
                    state: {
                        state_name: "ShuttingDown",
                        state_flags: "OUR_SHUTDOWN_SENT|THEIR_SHUTDOWN_SENT|AWAITING_PENDING_TLCS|DROPPING_PENDING",
                    },
                },
            ]);
            await tick(h.device);
            expect(await listed(h, {})).toEqual([]);
            expect(await listed(h, { include_closed: true })).toEqual([
                { channel_id: CHANNEL_ID, state: { state_name: "Closed", state_flags: "COOPERATIVE" } },
            ]);
        });
    });
});

async function listed(h: TenantFlow, params: object): Promise<unknown> {
    const answer = await post(h.node, { jsonrpc: "2.0", id: 2, method: "list_channels", params: [params] });
    if (typeof answer !== "object" || answer === null || !("result" in answer)) throw new Error("the node refused the listing");
    const { result } = answer;
    if (typeof result !== "object" || result === null || !("channels" in result)) throw new Error("the listing holds no channels");
    return asList(result.channels, "channels", (channel, path) => {
        const entry = asRecord(channel, path);
        return { channel_id: entry.channel_id, state: entry.state };
    });
}

function withRecoveryId(signature: Uint8Array, recoveryId: number): Uint8Array {
    return concatBytes(signature.subarray(0, 64), Uint8Array.of(recoveryId));
}

function submission(requestId: Uint8Array, signature: string): unknown {
    const params = { channel_id: CHANNEL_ID, request_id: `0x${bytesToHex(requestId)}`, signature };
    return { jsonrpc: "2.0", id: 4, method: "submit_watchtower_signature", params: [params] };
}
