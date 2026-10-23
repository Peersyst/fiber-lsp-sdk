import { schnorr } from "@noble/curves/secp256k1.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { keyAggExport, keyAggregate } from "@scure/btc-signer/musig2.js";
import { pubkeyOf } from "../../../src/derivation";
import type { PolicyEngineOptions } from "../../../src/policy";
import type { SdkChannelEvidence } from "../../../src/sdk";
import { readSdkChannelEvidence } from "../../../src/sdk";
import { InMemorySignerStorage } from "../../mocks/policy";
import { asRecord, asString } from "../../utils/json-shape";
import { signingDeviceKeys, signingPeerKeys } from "../../utils/signing-channel";
import { loadSigningVectors, toCkbCellDep, watchtowerApprovalOf } from "../../utils/signing-vectors";
import type { TenantDevice, TenantFlow } from "../../utils/tenant-flow";
import { CHANNEL_ID, openChannel, start, tenantDevice, tenantNode, tick } from "../../utils/tenant-flow";
import type { InMemoryTenantNode, TenantNodeForceClose, TenantNodePayment } from "../../utils/tenant-node";

const vectors = loadSigningVectors();

const APPROVED: PolicyEngineOptions = { nonceReuse: "allow", watchtower: watchtowerApprovalOf(vectors) };

// The funding keys as a received revocation aggregates them, the device's first.
const REVOCATION_KEY = keyAggExport(
    keyAggregate([pubkeyOf(signingDeviceKeys(vectors).fundingKey), pubkeyOf(signingPeerKeys(vectors).fundingKey)]),
);

const RECEIVED: TenantNodePayment = {
    paymentHash: "3f1c9a5e7d2b4068a1e9c3d5f7b2a4c6e8d0f1a3b5c7d9e1f2a4b6c8d0e2f4a6",
    amountShannons: "2250000000",
    hashAlgorithm: "sha256",
    expiryMs: "1760580000000",
};

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

// The node's lock is the destination the host approves; the chain's median time is past the outbound TLC's expiry only.
const FORCE_CLOSE: TenantNodeForceClose = {
    fundingCellDeps: vectors.watchtower.funding_cell_deps.map(toCkbCellDep),
    settlementCellDeps: vectors.watchtower.settlement_cell_deps.map(toCkbCellDep),
    nodeLock: watchtowerApprovalOf(vectors).destination,
    medianTimeMs: "1760600000000",
    preimages: [PREIMAGE],
    commitmentsBack: 0,
};

function device(node: InMemoryTenantNode, storage: InMemorySignerStorage): TenantDevice {
    return tenantDevice(node, { policy: APPROVED, watchtower: true, storage });
}

async function opened(): Promise<TenantFlow> {
    const node = tenantNode();
    const h = { node, device: device(node, new InMemorySignerStorage()) };
    await openChannel(h, "CompleteReceivedCommitment");
    await start(h.device);
    await tick(h.device);
    return h;
}

function servedAt(h: TenantFlow, index: number): { label: string; message: string } {
    const request = h.node.served[index];
    if (request === undefined) throw new Error(`the node served no request ${index}`);
    return { label: `${request.transition} ${request.slot}`, message: request.message };
}

function verifiedRevocations(h: TenantFlow, evidence: SdkChannelEvidence): boolean[] {
    const received = h.node.served.filter((request) => request.transition === "CompleteReceivedRevokeAndAck");
    expect(received).toHaveLength(evidence.revocations.length);
    return evidence.revocations.map(({ signature }, index) =>
        schnorr.verify(hexToBytes(signature.slice(2)), hexToBytes(received[index]?.message ?? ""), REVOCATION_KEY),
    );
}

function watchtowerSignaturesOf(h: TenantFlow, applied: boolean[]): SdkChannelEvidence["watchtowerSignatures"] {
    const submitted = h.node.calls
        .filter((call) => call.method === "submit_watchtower_signature")
        .map((call) => asRecord(call.params, "params"));
    return applied.map((taken, index) => {
        const served = h.node.watchtowerServed[index];
        if (served === undefined) throw new Error(`the node served no spend ${index}`);
        const submission = submitted.find((params) => params.request_id === served.requestId);
        return {
            requestId: served.requestId,
            purpose: served.purpose,
            signature: asString(submission?.signature, "signature"),
            applied: taken,
        };
    });
}

const SIGNATURE = expect.stringMatching(/^0x[0-9a-f]{128}$/) as unknown;

describe("the evidence over the tenant node", () => {
    it("keeps the open's commitments and nothing else", async () => {
        const h = await opened();
        expect([servedAt(h, 0).label, servedAt(h, 1).label]).toEqual([
            "CompleteReceivedCommitment Commitment@1",
            "SendCommitmentSigned Commitment@1",
        ]);
        expect(await readSdkChannelEvidence(h.device.store, CHANNEL_ID)).toStrictEqual({
            revocations: [],
            commitments: {
                local: { commitmentNumber: 1, txHash: `0x${servedAt(h, 0).message}` },
                remote: { commitmentNumber: 1, txHash: `0x${servedAt(h, 1).message}` },
            },
            watchtowerSignatures: [],
        });
    });

    it("keeps the peer's two revocations and each view's last commitment after a payment received and fulfilled", async () => {
        const h = await opened();
        h.node.receivePayment(RECEIVED);
        await tick(h.device, 4);
        h.node.fulfil(RECEIVED.paymentHash);
        await tick(h.device, 4);
        expect([servedAt(h, 6).label, servedAt(h, 8).label]).toEqual([
            "SendCommitmentSigned Commitment@3",
            "CompleteReceivedCommitment Commitment@4",
        ]);
        const evidence = await readSdkChannelEvidence(h.device.store, CHANNEL_ID);
        expect(evidence).toStrictEqual({
            revocations: [
                { version: 1, forRemote: true, signature: SIGNATURE },
                { version: 2, forRemote: true, signature: SIGNATURE },
            ],
            commitments: {
                local: { commitmentNumber: 3, txHash: `0x${servedAt(h, 8).message}` },
                remote: { commitmentNumber: 3, txHash: `0x${servedAt(h, 6).message}` },
            },
            watchtowerSignatures: [],
        });
        expect(verifiedRevocations(h, evidence)).toEqual([true, true]);
    });

    describe("a force close with a TLC each way in flight", () => {
        async function inFlight(storage: InMemorySignerStorage): Promise<TenantFlow> {
            const node = tenantNode();
            const h = { node, device: device(node, storage) };
            await openChannel(h, "CompleteReceivedCommitment");
            await start(h.device);
            await tick(h.device);
            h.node.receivePayment(INBOUND);
            await tick(h.device, 4);
            await h.device.policy.recordDebitIntent(OUTBOUND.paymentHash, OUTBOUND_BUDGET);
            h.node.sendPayment(OUTBOUND);
            await tick(h.device, 4);
            return h;
        }

        function commitmentsOf(h: TenantFlow): SdkChannelEvidence["commitments"] {
            expect([servedAt(h, 6).label, servedAt(h, 8).label]).toEqual([
                "SendCommitmentSigned Commitment@3",
                "CompleteReceivedCommitment Commitment@4",
            ]);
            return {
                local: { commitmentNumber: 3, txHash: `0x${servedAt(h, 8).message}` },
                remote: { commitmentNumber: 3, txHash: `0x${servedAt(h, 6).message}` },
            };
        }

        it("keeps every spend the watchtower took, in the order the device claimed them", async () => {
            const h = await inFlight(new InMemorySignerStorage());
            h.node.forceClose("local", FORCE_CLOSE);
            await tick(h.device, 4);
            expect(h.node.watchtowerServed.map(({ unlock }) => unlock)).toEqual([
                "outbound TLC by timeout",
                "inbound TLC by preimage",
                "settlement",
            ]);
            const evidence = await readSdkChannelEvidence(h.device.store, CHANNEL_ID);
            expect(evidence).toStrictEqual({
                revocations: [
                    { version: 1, forRemote: true, signature: SIGNATURE },
                    { version: 2, forRemote: true, signature: SIGNATURE },
                ],
                commitments: commitmentsOf(h),
                watchtowerSignatures: watchtowerSignaturesOf(h, [true, true, true]),
            });
            expect(evidence.watchtowerSignatures.map(({ purpose }) => purpose)).toEqual([
                { kind: "tlc", commitmentNumber: 3 },
                { kind: "tlc", commitmentNumber: 2 },
                { kind: "settlement" },
            ]);
            expect(verifiedRevocations(h, evidence)).toEqual([true, true]);
        });

        it("keeps a signature whose answer was lost as not applied, until the restarted device hears fiber took it", async () => {
            const storage = new InMemorySignerStorage();
            const h = await inFlight(storage);
            h.node.forceClose("local", FORCE_CLOSE);
            h.node.parkNextSubmission("submit_watchtower_signature");
            await tick(h.device);
            h.device.poller.stop();
            const crashed = await readSdkChannelEvidence(h.device.store, CHANNEL_ID);
            expect(crashed.watchtowerSignatures).toStrictEqual(watchtowerSignaturesOf(h, [false]));
            const restarted = { node: h.node, device: device(h.node, storage) };
            await start(restarted.device);
            await tick(restarted.device, 3);
            expect(await readSdkChannelEvidence(restarted.device.store, CHANNEL_ID)).toStrictEqual({
                revocations: crashed.revocations,
                commitments: commitmentsOf(h),
                watchtowerSignatures: watchtowerSignaturesOf(h, [true, true, true]),
            });
        });
    });
});
