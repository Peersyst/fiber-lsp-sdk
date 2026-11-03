import assert from "node:assert/strict";
import { test } from "node:test";
import { bareLowerHex } from "../src/agent.utils";
import { readDevnetEnv } from "./utils/devnet-env";
import { requestParam, SUBMIT_CHANNEL_SIGNATURE_METHOD } from "./utils/faulty-fetch";
import type { FaultyFetchRequest } from "./utils/faulty-fetch";
import { ensurePublicChannels } from "./utils/public-channels";
import {
    CHANNEL_FUNDING_SHANNONS,
    INVOICE_AMOUNT_SHANNONS,
    isSdkEvent,
    OPEN_STEPS,
    RECEIVED_STEPS,
    ScenarioDevice,
    signingSteps,
} from "./utils/scenario-device";
import { EVENT_TIMEOUT_MS, waitUntil } from "./utils/wait";

type SubmittedSignature = { channelId: string; requestId: string; partialSignature: string; nextMaterial: unknown };

function readSubmittedSignature(params: unknown): SubmittedSignature {
    const submitted = requestParam(params, SUBMIT_CHANNEL_SIGNATURE_METHOD);
    const { channel_id: channelId, request_id: requestId, partial_signature: partialSignature } = submitted;
    if (typeof channelId !== "string" || typeof requestId !== "string" || typeof partialSignature !== "string") {
        throw new Error(`${SUBMIT_CHANNEL_SIGNATURE_METHOD}: channel_id, request_id and partial_signature must be strings`);
    }
    return {
        channelId: bareLowerHex(channelId),
        requestId: bareLowerHex(requestId),
        partialSignature: bareLowerHex(partialSignature),
        nextMaterial: submitted.next_material,
    };
}

function submissionsOf(requests: readonly FaultyFetchRequest[], channelId: string): SubmittedSignature[] {
    return requests
        .filter((request) => request.method === SUBMIT_CHANNEL_SIGNATURE_METHOD)
        .map((request) => readSubmittedSignature(request.params))
        .filter((submitted) => submitted.channelId === bareLowerHex(channelId));
}

test("a restarted device serves the request whose signature never reached the node", async (t) => {
    const env = readDevnetEnv();
    await ensurePublicChannels(env);
    const device = await ScenarioDevice.create(env);
    try {
        const { node1, node2 } = device.nodes;
        const channelId = await device.openFundedChannel(CHANNEL_FUNDING_SHANNONS);
        const evidenceBefore = await device.sdk.channelEvidence(channelId);
        // The opening's own signatures and submissions are left out of what the payment is checked against.
        const eventsFrom = device.events.length;
        const requestsFrom = device.faults.requests.length;
        assert.deepEqual(signingSteps(device.events.slice(0, eventsFrom), channelId), OPEN_STEPS, "the opening's signing steps");

        // The device dies with its first submission of the payment lost: claimed in its store, never seen by the node.
        device.faults.refuse(SUBMIT_CHANNEL_SIGNATURE_METHOD, {
            when: (params) => {
                const ours = readSubmittedSignature(params).channelId === bareLowerHex(channelId);
                if (ours) device.sdk.disconnect();
                return ours;
            },
        });
        const invoice = await device.sdk.createInvoice(INVOICE_AMOUNT_SHANNONS, { description: "restart with a pending request" });
        const sent = await node1.sendPayment(invoice.invoice);
        assert.equal(bareLowerHex(sent.paymentHash), bareLowerHex(invoice.paymentHashHex));

        const lost = await waitUntil(
            `the first ${SUBMIT_CHANNEL_SIGNATURE_METHOD} of ${channelId} to be refused`,
            () =>
                Promise.resolve(
                    device.faults.requests.find(
                        (request) => request.method === SUBMIT_CHANNEL_SIGNATURE_METHOD && request.fault === "refused",
                    ),
                ),
            { timeoutMs: EVENT_TIMEOUT_MS },
        );
        const lostSignature = readSubmittedSignature(lost.params);
        const sentForPayment = device.faults.requests.slice(requestsFrom).filter((request) => request.fault !== "refused");
        assert.deepEqual(submissionsOf(sentForPayment, channelId), [], "a submission of the payment reached the node");
        const paymentEvents = device.events.slice(eventsFrom);
        assert.deepEqual(
            device.signingRecords(channelId).filter((recorded) => paymentEvents.includes(recorded)),
            [],
            "the lost signature was announced",
        );
        const pending = await node2.pendingSigningRequest(channelId, device.accessToken);
        assert.ok(pending !== undefined, `the node holds no signing request of ${channelId}`);
        assert.equal(pending.requestId, lostSignature.requestId, "the node holds another request than the lost signature's");
        assert.ok(
            pending.paymentHashes.includes(bareLowerHex(invoice.paymentHashHex)),
            `the lost ${pending.transition} carries no TLC of the payment`,
        );
        // The lost request signs the device's own commitment, C@2: its claim moved the local view alone.
        const evidenceAtLoss = await device.sdk.channelEvidence(channelId);
        const localBefore = evidenceBefore.commitments.local?.commitmentNumber;
        const localAtLoss = evidenceAtLoss.commitments.local?.commitmentNumber;
        assert.ok(localBefore !== undefined && localAtLoss !== undefined, "the opening and the claim each recorded a local commitment");
        assert.ok(localAtLoss > localBefore, `the claim did not advance the local commitment past ${localBefore}`);
        assert.deepEqual(
            { ...evidenceAtLoss, commitments: { ...evidenceAtLoss.commitments, local: null } },
            { ...evidenceBefore, commitments: { ...evidenceBefore.commitments, local: null } },
            "the claim persisted more than the local commitment",
        );
        assert.equal((await node1.getPayment(invoice.paymentHashHex)).status, "Inflight");

        await device.waitForSettled();
        const restarted = device.reopen();
        assert.deepEqual(await restarted.channelEvidence(channelId), evidenceAtLoss, "the restarted device read another record");
        restarted.connect();
        const served = await device.waitForEvent(
            isSdkEvent(
                "SIGNING",
                (event) =>
                    event.channelId === channelId && event.requestId !== null && bareLowerHex(event.requestId) === lostSignature.requestId,
            ),
        );
        assert.equal(served.outcome, "signed", "the same signature served again is no second session");
        assert.equal(device.events.find((recorded) => recorded.event === served)?.generation, 1, "the old facade served the request");
        const [resubmitted] = submissionsOf(device.faults.sent(SUBMIT_CHANNEL_SIGNATURE_METHOD), channelId).filter(
            (submitted) => submitted.requestId === lostSignature.requestId,
        );
        assert.deepEqual(resubmitted, lostSignature, "the restarted device served other bytes");

        await device.waitForPaymentReceived(invoice.paymentHashHex);
        await node1.waitForPaymentStatus(invoice.paymentHashHex, "Success");
        assert.equal((await node2.getInvoice(invoice.paymentHashHex, device.accessToken)).status, "Paid");
        // The lost signature was never announced, so the restarted facade announces the payment's every step.
        assert.deepEqual(await device.waitForSigningSteps(channelId, eventsFrom, RECEIVED_STEPS.length), RECEIVED_STEPS);
        assert.deepEqual(device.signingRecords(channelId, "refused"), [], "a request was refused, a third session among them");
    } finally {
        t.diagnostic(`events: ${device.describeEvents()}`);
        await device.close();
    }
});
