import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_POLL_INTERVAL_MS } from "@peersyst/fiber-lsp-sdk";
import { bareLowerHex } from "../src/agent.utils";
import { readDevnetEnv } from "./utils/devnet-env";
import { ensurePublicChannels } from "./utils/public-channels";
import { CHANNEL_READY_STATE } from "./utils/fiber-node";
import {
    CHANNEL_FUNDING_SHANNONS,
    CHECK_CHANNELS_INTERVAL_MS,
    INVOICE_AMOUNT_SHANNONS,
    isPaymentSent,
    OPEN_STEPS,
    PEER_CHANNEL_RESPONSE_TIMEOUT_MS,
    RECEIVED_STEPS,
    ScenarioDevice,
    SENT_STEPS,
    signingSteps,
} from "./utils/scenario-device";
import type { SigningStep } from "./utils/scenario-device";
import { sleep } from "./utils/wait";

const SERVED_SENT_STEPS: readonly SigningStep[] = [
    ...SENT_STEPS.slice(0, -1),
    { transition: "SendCommitmentSigned", outcome: "warning" }, // C@3, a third session served as a second
    { transition: "CompleteReceivedRevokeAndAck", outcome: "warning" }, // R@3
];

// Past #1701's window and the check after it.
const WATCHDOG_WAIT_MS = PEER_CHANNEL_RESPONSE_TIMEOUT_MS + 2 * CHECK_CHANNELS_INTERVAL_MS;

test("a payment the tenant sends completes once the third signing session on C@3 is served, and the channel stays ready", async (t) => {
    const env = readDevnetEnv();
    await ensurePublicChannels(env);
    const device = await ScenarioDevice.create(env, { nonceCapBypass: true, pollIntervalMs: DEFAULT_POLL_INTERVAL_MS });
    try {
        const { node1, node2 } = device.nodes;
        const channelId = bareLowerHex(await device.openFundedChannel(CHANNEL_FUNDING_SHANNONS));
        const sendFrom = device.events.length;
        assert.deepEqual(signingSteps(device.events.slice(0, sendFrom), channelId), OPEN_STEPS, "the opening's signing steps");

        const invoice = await device.nodeOneInvoice("served third session");
        const payment = await device.sdk.transfer(invoice.invoiceAddress);
        assert.equal(bareLowerHex(payment.paymentHashHex), bareLowerHex(invoice.paymentHash));
        await device.waitForEvent(isPaymentSent(payment.paymentHashHex));
        const sentSteps = await device.waitForSigningSteps(channelId, sendFrom, SERVED_SENT_STEPS.length);
        t.diagnostic(`the payment sent's steps, ms from the first: ${device.signingStepTimes(channelId, sendFrom)}`);
        assert.deepEqual(sentSteps, SERVED_SENT_STEPS);
        assert.deepEqual(device.signingRecords(channelId, "refused"), [], "no session refused");
        assert.equal((await node2.getPayment(payment.paymentHashHex, device.accessToken)).status, "Success");
        assert.equal((await node1.getInvoice(invoice.paymentHash)).status, "Paid", "node 1's invoice");

        await sleep(WATCHDOG_WAIT_MS);
        assert.equal((await device.fiberChannel(channelId))?.stateName, CHANNEL_READY_STATE, "the channel past #1701's window");
        assert.deepEqual(signingSteps(device.events.slice(sendFrom), channelId), SERVED_SENT_STEPS, "no step after the payment sent");

        const receiveFrom = device.events.length;
        const received = await device.sdk.createInvoice(INVOICE_AMOUNT_SHANNONS, { description: "after the served session" });
        await node1.sendPayment(received.invoice);
        await device.waitForPaymentReceived(received.paymentHashHex);
        await node1.waitForPaymentStatus(received.paymentHashHex, "Success");
        // RECEIVED_STEPS repeat, on later slots.
        const receivedSteps = await device.waitForSigningSteps(channelId, receiveFrom, RECEIVED_STEPS.length);
        t.diagnostic(`the payment received's steps, ms from the first: ${device.signingStepTimes(channelId, receiveFrom)}`);
        assert.deepEqual(receivedSteps, RECEIVED_STEPS);
        assert.deepEqual(device.signingRecords(channelId, "refused"), [], "no session refused");
        assert.equal((await device.fiberChannel(channelId))?.stateName, CHANNEL_READY_STATE, "the channel after both payments");
    } finally {
        t.diagnostic(`events: ${device.describeEvents()}`);
        await device.close();
    }
});
