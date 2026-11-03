import assert from "node:assert/strict";
import { test } from "node:test";
import { bareLowerHex } from "../src/agent.utils";
import { readDevnetEnv } from "./utils/devnet-env";
import { ensurePublicChannels } from "./utils/public-channels";
import {
    CHANNEL_FUNDING_SHANNONS,
    isSdkEvent,
    OPEN_STEPS,
    OUTBOUND_AMOUNT_SHANNONS,
    ScenarioDevice,
    SENT_STEPS,
    signingSteps,
} from "./utils/scenario-device";

test("a payment the tenant sends asks a third signing session at C@3, and fiber#1701 force-closes the refused channel", async (t) => {
    const env = readDevnetEnv();
    await ensurePublicChannels(env);
    const device = await ScenarioDevice.create(env);
    try {
        const { node1, node2 } = device.nodes;
        const channelId = bareLowerHex(await device.openFundedChannel(CHANNEL_FUNDING_SHANNONS));
        const sendFrom = device.events.length;
        assert.deepEqual(signingSteps(device.events.slice(0, sendFrom), channelId), OPEN_STEPS, "the opening's signing steps");

        const invoice = await device.nodeOneInvoice("outbound payment");
        const payment = await device.sdk.transfer(invoice.invoiceAddress);
        const paymentHash = bareLowerHex(payment.paymentHashHex);
        assert.equal(paymentHash, bareLowerHex(invoice.paymentHash));
        assert.equal(payment.amountShannons, OUTBOUND_AMOUNT_SHANNONS.toString());

        const refusal = await device.waitForEvent(
            isSdkEvent("SIGNING", (event) => bareLowerHex(event.channelId) === channelId && event.outcome === "refused"),
        );
        if (refusal.outcome !== "refused") assert.fail("the awaited SIGNING event must be a refusal");
        const refusedAt = Date.now();
        assert.equal(refusal.transition, "SendCommitmentSigned");
        assert.equal(refusal.error.code, "policy_refusal");
        assert.match(refusal.error.message, /^slot COMMITMENT:3 has already served two signing sessions/);
        const refusalIndex = device.events.findIndex(({ event }) => event === refusal);
        assert.deepEqual(signingSteps(device.events.slice(sendFrom, refusalIndex + 1), channelId), SENT_STEPS);
        // Node 1 was paid before the fulfil reached the device, so the LSP holds the preimage.
        assert.equal((await node1.getInvoice(invoice.paymentHash)).status, "Paid", "node 1's invoice at the refusal");

        // The unbalanced ledger closes the channel uncooperatively, with no close the device signs.
        const leaving = await device.waitForForceClose(channelId);
        t.diagnostic(
            `the channel left ChannelReady ${leaving.at - refusedAt} ms after the refusal: ${JSON.stringify(leaving.channel.raw.state)}`,
        );
        await device.mineForceClose(channelId);

        // The sent TLC now settles on chain, past the commitment delay this scenario never mines to: the payment is unresolved.
        const outcome = await node2.getPayment(payment.paymentHashHex, device.accessToken);
        assert.deepEqual({ status: outcome.status, failedError: outcome.failedError }, { status: "Inflight", failedError: null });
        const paymentEvents = device.events
            .slice(sendFrom)
            .filter(({ event }) => event.type.startsWith("PAYMENT_"))
            .map(({ event }) => event);
        assert.deepEqual(paymentEvents, [], "no payment event while the payment is unresolved");
    } finally {
        t.diagnostic(`events: ${device.describeEvents()}`);
        await device.close();
    }
});
