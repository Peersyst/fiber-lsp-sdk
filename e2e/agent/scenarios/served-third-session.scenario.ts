import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_POLL_INTERVAL_MS } from "@peersyst/fiber-lsp-sdk";
import { bareLowerHex } from "../src/agent.utils";
import { readScenarioEnv, STILL_READY_SLACK_MS, watchdogLatestMs } from "./utils/scenario-env";
import { ensurePublicChannels } from "./utils/public-channels";
import { CHANNEL_READY_STATE } from "./utils/fiber-node";
import {
    INVOICE_AMOUNT_SHANNONS,
    isPaymentSent,
    isSdkEvent,
    OPEN_STEPS,
    OUTBOUND_AMOUNT_SHANNONS,
    OUTBOUND_MINIMUM_FEE_SHANNONS,
    RECEIVED_STEPS,
    ScenarioDevice,
    SENT_STEPS,
    signingSteps,
    untimedRecord,
} from "./utils/scenario-device";
import type { SigningStep } from "./utils/scenario-device";
import { sleep } from "./utils/wait";

const SERVED_SENT_STEPS: readonly SigningStep[] = [
    ...SENT_STEPS.slice(0, -1),
    { transition: "SendCommitmentSigned", outcome: "warning" }, // C@3, a third session served as a second
    { transition: "CompleteReceivedRevokeAndAck", outcome: "warning" }, // R@3
];

test("a payment the tenant sends completes once the third signing session on C@3 is served, and the channel stays ready", async (t) => {
    const env = readScenarioEnv();
    await ensurePublicChannels(env);
    const device = await ScenarioDevice.create(env, { nonceCapBypass: true, pollIntervalMs: DEFAULT_POLL_INTERVAL_MS });
    try {
        const { node1, node2 } = device.nodes;
        const channelId = bareLowerHex(await device.openFundedChannel());
        const sendFrom = device.events.length;
        assert.deepEqual(signingSteps(device.events.slice(0, sendFrom), channelId), OPEN_STEPS, "the opening's signing steps");

        const invoice = await device.nodeOneInvoice("served third session");
        const estimate = await device.sdk.estimateTransferFee(invoice.invoiceAddress, { maxFeeShannons: OUTBOUND_MINIMUM_FEE_SHANNONS });
        assert.equal(estimate.feeShannons, OUTBOUND_MINIMUM_FEE_SHANNONS, "the estimate, the whole budget");
        const payment = await device.sdk.transfer(invoice.invoiceAddress, { maxFeeShannons: estimate.feeShannons });
        assert.equal(bareLowerHex(payment.paymentHashHex), bareLowerHex(invoice.paymentHash));
        const sent = await device.waitForEvent(isPaymentSent(payment.paymentHashHex));
        assert.equal(sent.feeShannons, estimate.feeShannons, "PAYMENT_SENT's fee, the estimate");
        const sentRecord = {
            paymentHashHex: payment.paymentHashHex,
            direction: "send",
            status: "completed",
            amountShannons: OUTBOUND_AMOUNT_SHANNONS.toString(),
            invoice: invoice.invoiceAddress,
            description: "served third session",
            maxFeeShannons: estimate.feeShannons,
            feeShannons: estimate.feeShannons,
            failedReason: null,
            createdAtMs: 0,
            settledAtMs: 0,
        };
        assert.deepEqual(untimedRecord(sent.payment), sentRecord, "PAYMENT_SENT's record");
        assert.deepEqual(await device.sdk.getPayment(payment.paymentHashHex), sent.payment, "the history's record, the event's");
        const sentSteps = await device.waitForSigningSteps(channelId, sendFrom, SERVED_SENT_STEPS.length);
        t.diagnostic(`the payment sent's steps, ms from the first: ${device.signingStepTimes(channelId, sendFrom)}`);
        assert.deepEqual(sentSteps, SERVED_SENT_STEPS);
        assert.deepEqual(device.signingRecords(channelId, "refused"), [], "no session refused");
        assert.equal((await node2.getPayment(payment.paymentHashHex, device.accessToken)).status, "Success");
        assert.equal((await node1.getInvoice(invoice.paymentHash)).status, "Paid", "node 1's invoice");

        await sleep(watchdogLatestMs(env.chain) + STILL_READY_SLACK_MS);
        assert.equal((await device.fiberChannel(channelId))?.stateName, CHANNEL_READY_STATE, "the channel past #1701's window");
        assert.deepEqual(signingSteps(device.events.slice(sendFrom), channelId), SERVED_SENT_STEPS, "no step after the payment sent");

        const receiveFrom = device.events.length;
        const received = await device.sdk.createInvoice(INVOICE_AMOUNT_SHANNONS, { description: "after the served session" });
        await node1.sendPayment(received.invoice);
        const receivedEvent = await device.waitForPaymentReceived(received.paymentHashHex);
        assert.deepEqual(
            untimedRecord(receivedEvent.payment),
            {
                paymentHashHex: received.paymentHashHex,
                direction: "receive",
                status: "completed",
                amountShannons: INVOICE_AMOUNT_SHANNONS,
                invoice: received.invoice,
                description: "after the served session",
                maxFeeShannons: null,
                feeShannons: "0",
                failedReason: null,
                createdAtMs: 0,
                settledAtMs: 0,
            },
            "PAYMENT_RECEIVED's record",
        );
        const pendingEvent = device.events
            .slice(receiveFrom)
            .map(({ event }) => event)
            .find(isSdkEvent("PAYMENT_PENDING", (event) => event.paymentHashHex === received.paymentHashHex));
        assert.deepEqual(
            untimedRecord(pendingEvent?.payment ?? null),
            { ...untimedRecord(receivedEvent.payment), status: "pending", feeShannons: null, settledAtMs: null },
            "PAYMENT_PENDING's record",
        );
        assert.equal(pendingEvent?.payment.createdAtMs, receivedEvent.payment.createdAtMs, "the receive keeps its arrival time");
        assert.deepEqual(
            (await device.sdk.listPayments()).map(untimedRecord),
            [untimedRecord(receivedEvent.payment), sentRecord],
            "the history, newest first",
        );
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
