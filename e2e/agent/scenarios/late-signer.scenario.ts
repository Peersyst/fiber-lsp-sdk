import assert from "node:assert/strict";
import { test } from "node:test";
import { bareLowerHex } from "../src/agent.utils";
import { readDevnetEnv } from "./utils/devnet-env";
import { ensurePublicChannels } from "./utils/public-channels";
import {
    CHANNEL_FUNDING_SHANNONS,
    INVOICE_AMOUNT_SHANNONS,
    isSdkEvent,
    OPEN_STEPS,
    RECEIVED_STEPS,
    SCENARIO_POLL_INTERVAL_MS,
    ScenarioDevice,
    signingSteps,
} from "./utils/scenario-device";
import { EVENT_TIMEOUT_MS, sleep, waitUntil } from "./utils/wait";

// Long enough for several ticks the device would have run, had it been connected.
const OFFLINE_MS = 5 * SCENARIO_POLL_INTERVAL_MS;

test("a signer that comes back late serves the payment the node held for it", async (t) => {
    const env = readDevnetEnv();
    await ensurePublicChannels(env);
    const device = await ScenarioDevice.create(env);
    try {
        const { node1, node2 } = device.nodes;
        const channelId = await device.openFundedChannel(CHANNEL_FUNDING_SHANNONS);
        const invoice = await device.sdk.createInvoice(INVOICE_AMOUNT_SHANNONS, { description: "late signer" });
        const paymentHash = bareLowerHex(invoice.paymentHashHex);

        device.sdk.disconnect();
        // The tick that was running when it disconnected ends before anything offline is looked at.
        await device.waitForSettled();
        const offlineFrom = device.events.length;
        assert.deepEqual(signingSteps(device.events.slice(0, offlineFrom), channelId), OPEN_STEPS, "the opening's signing steps");
        const sent = await node1.sendPayment(invoice.invoice);
        assert.equal(bareLowerHex(sent.paymentHash), paymentHash);

        const pending = await waitUntil(
            `the node to hold a signing request of ${channelId}`,
            () => node2.pendingSigningRequest(channelId, device.accessToken),
            { timeoutMs: EVENT_TIMEOUT_MS },
        );
        assert.ok(pending.paymentHashes.includes(paymentHash), `the pending ${pending.transition} carries no TLC of the payment`);
        await node1.waitForPaymentStatus(invoice.paymentHashHex, "Inflight");

        await sleep(OFFLINE_MS);
        assert.deepEqual(await node2.pendingSigningRequest(channelId, device.accessToken), pending);
        assert.equal((await node1.getPayment(invoice.paymentHashHex)).status, "Inflight");
        assert.deepEqual(
            device.events.slice(offlineFrom).filter(({ event }) => event.type === "SIGNING"),
            [],
            "the device signed while disconnected",
        );

        device.sdk.connect();
        const signing = await device.waitForEvent(
            isSdkEvent(
                "SIGNING",
                (event) => event.channelId === channelId && event.requestId !== null && bareLowerHex(event.requestId) === pending.requestId,
            ),
        );
        const signedAt = device.events.find((recorded) => recorded.event === signing)?.at;
        assert.ok(signedAt !== undefined);
        assert.equal(signing.outcome, "signed");
        assert.equal(signing.transition, pending.transition);
        const { deadlineMs } = signing;
        assert.ok(deadlineMs !== undefined, "the SIGNING event of a request with a TLC carries its deadline");
        assert.ok(deadlineMs > signedAt, `deadline ${deadlineMs} is not after the signature at ${signedAt}`);

        await device.waitForPaymentReceived(invoice.paymentHashHex);
        await node1.waitForPaymentStatus(invoice.paymentHashHex, "Success");
        assert.equal((await node2.getInvoice(invoice.paymentHashHex, device.accessToken)).status, "Paid");
        assert.deepEqual(await device.waitForSigningSteps(channelId, offlineFrom, RECEIVED_STEPS.length), RECEIVED_STEPS);
    } finally {
        t.diagnostic(`events: ${device.describeEvents()}`);
        await device.close();
    }
});
