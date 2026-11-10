import assert from "node:assert/strict";
import { test } from "node:test";
import { bareLowerHex } from "../src/agent.utils";
import { readScenarioEnv } from "./utils/scenario-env";
import { EVENT_TIMEOUT_MS, waitUntil } from "./utils/wait";
import { CHANNEL_READY_STATE } from "./utils/fiber-node";
import { ensurePublicChannels } from "./utils/public-channels";
import { INVOICE_AMOUNT_SHANNONS, isSdkEvent, OPEN_STEPS, ScenarioDevice, signingSteps } from "./utils/scenario-device";

test("a cancelled invoice, even with its TLC held, ends as PAYMENT_CANCELLED and fails its payer, and a force close the device asked for ends as CHANNEL_CLOSED with the watchtower's spend signed once approved", async (t) => {
    const env = readScenarioEnv();
    await ensurePublicChannels(env);
    // Several payments cross one channel here, past the second signing session a slot is served.
    const device = await ScenarioDevice.create(env, { nonceCapBypass: true });
    try {
        const { node1, node2 } = device.nodes;
        const channelId = bareLowerHex(await device.openFundedChannel());
        assert.deepEqual(signingSteps(device.events, channelId), OPEN_STEPS, "the opening's signing steps");

        const invoice = await device.sdk.createInvoice(INVOICE_AMOUNT_SHANNONS, { description: "cancelled invoice" });
        assert.equal((await node2.getInvoice(invoice.paymentHashHex, device.accessToken)).status, "Open");
        const cancelFrom = device.events.length;
        await device.sdk.cancelInvoice(invoice.paymentHashHex);

        const cancelled = await device.waitForEvent(
            isSdkEvent("PAYMENT_CANCELLED", (event) => bareLowerHex(event.paymentHashHex) === bareLowerHex(invoice.paymentHashHex)),
        );
        assert.equal(bareLowerHex(cancelled.paymentHashHex), bareLowerHex(invoice.paymentHashHex));
        assert.equal((await node2.getInvoice(invoice.paymentHashHex, device.accessToken)).status, "Cancelled");
        // Idempotent: fiber's refusal of a cancelled invoice is no error.
        await device.sdk.cancelInvoice(invoice.paymentHashHex);

        // The TLC still enters and fails back through the device's channel: fiber checks a final TLC only once it is committed.
        const payment = await node1.sendPayment(invoice.invoice);
        assert.equal(bareLowerHex(payment.paymentHash), bareLowerHex(invoice.paymentHashHex));
        const failed = await node1.waitForPaymentStatus(invoice.paymentHashHex, "Failed");
        t.diagnostic(`the payer's failure on the cancelled invoice: ${failed.failedError ?? "no error"}`);
        assert.notEqual(failed.failedError, null, "the payer's failure names a reason");
        assert.equal((await node2.getInvoice(invoice.paymentHashHex, device.accessToken)).status, "Cancelled");
        const afterCancel = device.events.slice(cancelFrom).map(({ event }) => event);
        assert.deepEqual(
            afterCancel.filter((event) => event.type.startsWith("PAYMENT_")).map((event) => event.type),
            ["PAYMENT_CANCELLED"],
            "the invoice ends cancelled, never expired or received",
        );

        // The TLC is held once the device sees the invoice Received: the real crossing with the release.
        const heldInvoice = await device.sdk.createInvoice(INVOICE_AMOUNT_SHANNONS, { description: "cancelled while held" });
        const heldHash = bareLowerHex(heldInvoice.paymentHashHex);
        const before = await device.fiberChannel(channelId);
        const cancelling: Promise<void>[] = [];
        const stopListening = device.sdk.onEvent((event) => {
            if (event.type === "PAYMENT_PENDING" && bareLowerHex(event.paymentHashHex) === heldHash) {
                cancelling.push(device.sdk.cancelInvoice(heldInvoice.paymentHashHex));
            }
        });
        const heldFrom = device.events.length;
        try {
            await node1.sendPayment(heldInvoice.invoice);
            const heldCancelled = await device.waitForEvent(
                isSdkEvent("PAYMENT_CANCELLED", (event) => bareLowerHex(event.paymentHashHex) === heldHash),
            );
            assert.equal(bareLowerHex(heldCancelled.paymentHashHex), heldHash);
        } finally {
            stopListening();
        }
        assert.equal(cancelling.length, 1, "the cancel was asked once, from the PAYMENT_PENDING listener");
        await Promise.all(cancelling);
        const heldFailed = await node1.waitForPaymentStatus(heldHash, "Failed");
        t.diagnostic(`the payer's failure on the invoice cancelled while held: ${heldFailed.failedError ?? "no error"}`);
        assert.equal((await node2.getInvoice(heldHash, device.accessToken)).status, "Cancelled");
        const heldEvents = device.events.slice(heldFrom).map(({ event }) => event);
        assert.deepEqual(
            heldEvents.filter((event) => event.type.startsWith("PAYMENT_")).map((event) => event.type),
            ["PAYMENT_PENDING", "PAYMENT_CANCELLED"],
            "the held invoice ends cancelled, never received",
        );
        const after = await waitUntil(
            "the held TLC to leave the channel",
            async () => {
                const listed = await device.fiberChannel(channelId);
                return listed?.raw.received_tlc_balance === "0x0" ? listed : undefined;
            },
            { timeoutMs: EVENT_TIMEOUT_MS },
        );
        assert.equal(after.raw.local_balance, before?.raw.local_balance, "the device's balance after the cancelled payment");
        assert.equal(after.raw.remote_balance, before?.raw.remote_balance, "the LSP's balance after the cancelled payment");

        // The node broadcasts its latest commitment alone; with no approval yet, its settlement spend stays pending and refused.
        assert.equal((await device.fiberChannel(channelId))?.stateName, CHANNEL_READY_STATE, "the channel before the force close");
        const forceFrom = device.events.length;
        await device.sdk.forceCloseChannel(`0x${channelId}`);
        await device.confirmForceClose(channelId);
        const closed = device.events.slice(forceFrom).map(({ event }) => event);
        assert.ok(
            closed.some(isSdkEvent("CHANNEL_CLOSED", (event) => bareLowerHex(event.channelId) === channelId)),
            "CHANNEL_CLOSED of the channel",
        );
        assert.deepEqual(
            closed.filter((event) => event.type === "SIGNING"),
            [],
            "no signing request for a force close",
        );

        const refused = await device.waitForWatchtowerSigning(channelId, "refused");
        if (refused.outcome !== "refused") assert.fail("the awaited WATCHTOWER_SIGNING event must be a refusal");
        assert.equal(refused.error.code, "policy_refusal");
        assert.match(refused.error.message, /^watchtower option: the host approved no destination/);
        assert.notEqual(refused.requestId, null, "the refused spend is a pending request");
        assert.equal(
            device.events.some(({ event }) => event.type === "WATCHTOWER_SIGNING" && event.outcome === "signed"),
            false,
            "nothing signed before the approval",
        );
        device.approveWatchtowerToLsp();
        const signed = await device.waitForWatchtowerSigning(channelId, "signed");
        assert.equal(signed.requestId, refused.requestId, "the approval signs the spend that was pending, with no new facade");
    } finally {
        t.diagnostic(`events: ${device.describeEvents()}`);
        await device.close();
    }
});
