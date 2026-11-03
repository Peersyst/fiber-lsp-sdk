import assert from "node:assert/strict";
import { test } from "node:test";
import type { TestContext } from "node:test";
import { bareLowerHex, messageOf } from "../src/agent.utils";
import { readDevnetEnv } from "./utils/devnet-env";
import { ensurePublicChannels } from "./utils/public-channels";
import { CHANNEL_FUNDING_SHANNONS, isSdkEvent, OPEN_STEPS, ScenarioDevice, signingSteps } from "./utils/scenario-device";
import type { SigningStep } from "./utils/scenario-device";

// As fiber's hosted tenant pays node 1 (`e2e/lsp`, steps 27 and 28).
const OUTBOUND_AMOUNT_SHANNONS = 100_000n;
const OUTBOUND_INVOICE_EXPIRY_SECONDS = 3600;

// How long the payment is watched past the refusal for the PAYMENT_SENT a stall never brings.
const STALL_WINDOW_MS = 30_000;

// docs/signing.md's payment sent under nonceReuse "allow": the send, then the peer's fulfil up to a third session on C@3.
const SENT_STEPS: readonly SigningStep[] = [
    { transition: "SendCommitmentSigned", outcome: "signed" }, // C@2
    { transition: "CompleteReceivedRevokeAndAck", outcome: "signed" }, // R@2
    { transition: "CompleteReceivedCommitment", outcome: "signed" }, // C@3
    { transition: "SendRevokeAndAck", outcome: "warning" }, // R@2
    { transition: "CompleteReceivedCommitment", outcome: "warning" }, // C@3
    { transition: "SendRevokeAndAck", outcome: "signed" }, // R@3
    { transition: "SendCommitmentSigned", outcome: "refused" }, // C@3, a third session
];

async function noteAtStall(t: TestContext, what: string, read: () => Promise<unknown>): Promise<void> {
    try {
        t.diagnostic(`${what} at the stall: ${JSON.stringify(await read())}`);
    } catch (error) {
        t.diagnostic(`${what} at the stall could not be read: ${messageOf(error)}`);
    }
}

test("a payment the tenant sends stalls on a third signing session at C@3", async (t) => {
    const env = readDevnetEnv();
    await ensurePublicChannels(env);
    const device = await ScenarioDevice.create(env);
    try {
        const { node1, node2 } = device.nodes;
        const channelId = bareLowerHex(await device.openFundedChannel(CHANNEL_FUNDING_SHANNONS));
        const sendFrom = device.events.length;
        assert.deepEqual(signingSteps(device.events.slice(0, sendFrom), channelId), OPEN_STEPS, "the opening's signing steps");

        const invoice = await node1.newInvoice({
            amountShannons: OUTBOUND_AMOUNT_SHANNONS,
            currency: env.network.invoiceCurrency,
            description: "outbound payment",
            expirySeconds: OUTBOUND_INVOICE_EXPIRY_SECONDS,
            allowTrampolineRouting: true,
        });
        const payment = await device.sdk.transfer(invoice.invoiceAddress);
        const paymentHash = bareLowerHex(payment.paymentHashHex);
        assert.equal(paymentHash, bareLowerHex(invoice.paymentHash));
        assert.equal(payment.amountShannons, OUTBOUND_AMOUNT_SHANNONS.toString());

        const refusal = await device.waitForEvent(
            isSdkEvent("SIGNING", (event) => bareLowerHex(event.channelId) === channelId && event.outcome === "refused"),
        );
        if (refusal.outcome !== "refused") assert.fail("the awaited SIGNING event must be a refusal");
        await assert.rejects(
            device.waitForEvent(
                isSdkEvent("PAYMENT_SENT", (event) => bareLowerHex(event.paymentHashHex) === paymentHash),
                STALL_WINDOW_MS,
            ),
            /no matching event/,
            "the payment must stall: PAYMENT_SENT arrived",
        );

        assert.equal(refusal.transition, "SendCommitmentSigned");
        assert.equal(refusal.error.code, "policy_refusal");
        assert.match(refusal.error.message, /^slot COMMITMENT:3 has already served two signing sessions/);
        assert.deepEqual(signingSteps(device.events.slice(sendFrom), channelId), SENT_STEPS);

        // The stall: node 1 was paid, so the LSP holds the preimage, while the tenant's own payment never resolves.
        assert.equal((await node1.getInvoice(invoice.paymentHash)).status, "Paid", "node 1's invoice at the stall");
        const stalled = await node2.getPayment(payment.paymentHashHex, device.accessToken);
        assert.equal(stalled.status, "Inflight", `the tenant's payment at the stall (failed_error ${stalled.failedError})`);
        const paymentEvents = device.events
            .slice(sendFrom)
            .filter(({ event }) => event.type.startsWith("PAYMENT_"))
            .map(({ event }) => event);
        assert.deepEqual(paymentEvents, [], "no payment event at the stall");
        await noteAtStall(t, "the device's channel", async () =>
            (await device.sdk.listChannels()).find((channel) => bareLowerHex(channel.channelId) === channelId),
        );
    } finally {
        t.diagnostic(`events: ${device.describeEvents()}`);
        await device.close();
    }
});
