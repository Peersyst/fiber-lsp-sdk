import assert from "node:assert/strict";
import { test } from "node:test";
import { bareLowerHex, readJsonObject } from "../src/agent.utils";
import { readDevnetEnv } from "./utils/devnet-env";
import { mineUntil } from "./utils/fiber-node";
import type { FiberChannel } from "./utils/fiber-node";
import { ensurePublicChannels } from "./utils/public-channels";
import { CHANNEL_FUNDING_SHANNONS, isSdkEvent, OPEN_STEPS, ScenarioDevice, signingSteps } from "./utils/scenario-device";
import type { SigningStep } from "./utils/scenario-device";
import { OPENING_TIMEOUT_MS, waitUntil } from "./utils/wait";

// As fiber's hosted tenant pays node 1 (`e2e/lsp`, steps 27 and 28).
const OUTBOUND_AMOUNT_SHANNONS = 100_000n;
const OUTBOUND_INVOICE_EXPIRY_SECONDS = 3600;

// fiber#1701 force-closes a channel whose revocation nonce ledger stays unbalanced past PEER_CHANNEL_RESPONSE_TIMEOUT, 30 s,
// on the next channel check, every 3 s in a debug build (d8dd6d28 `fiber/channel.rs:155,6787-6793`, `fiber/network.rs:252`);
// the rest is the probe's slack.
const FORCE_CLOSE_WINDOW_MS = 60_000;

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

async function tenantChannel(device: ScenarioDevice, channelId: string): Promise<FiberChannel | undefined> {
    const channels = await device.nodes.node2.listChannels({ includeClosed: true }, device.accessToken);
    return channels.find((channel) => bareLowerHex(channel.channelId) === channelId);
}

test("a payment the tenant sends asks a third signing session at C@3, and fiber#1701 force-closes the refused channel", async (t) => {
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
        const refusedAt = Date.now();
        assert.equal(refusal.transition, "SendCommitmentSigned");
        assert.equal(refusal.error.code, "policy_refusal");
        assert.match(refusal.error.message, /^slot COMMITMENT:3 has already served two signing sessions/);
        const refusalIndex = device.events.findIndex(({ event }) => event === refusal);
        assert.deepEqual(signingSteps(device.events.slice(sendFrom, refusalIndex + 1), channelId), SENT_STEPS);
        // Node 1 was paid before the fulfil reached the device, so the LSP holds the preimage.
        assert.equal((await node1.getInvoice(invoice.paymentHash)).status, "Paid", "node 1's invoice at the refusal");

        // The unbalanced ledger closes the channel uncooperatively, with no close the device signs.
        const leaving = await waitUntil(
            `fiber#1701 to force-close ${channelId}`,
            async () => {
                const channel = await tenantChannel(device, channelId);
                return channel !== undefined && channel.stateName !== "ChannelReady" ? channel : undefined;
            },
            { timeoutMs: FORCE_CLOSE_WINDOW_MS },
        );
        t.diagnostic(`the channel left ChannelReady ${Date.now() - refusedAt} ms after the refusal: ${JSON.stringify(leaving.raw.state)}`);
        const closedEvent = isSdkEvent("CHANNEL_CLOSED", (event) => bareLowerHex(event.channelId) === channelId);
        await mineUntil(
            env,
            `CHANNEL_CLOSED of ${channelId}`,
            () => Promise.resolve(device.events.some(({ event }) => closedEvent(event)) ? true : undefined),
            OPENING_TIMEOUT_MS,
        );
        const closed = await tenantChannel(device, channelId);
        if (closed === undefined) assert.fail(`the tenant's listing lost the closed channel ${channelId}`);
        assert.equal(closed.stateName, "Closed", "the tenant's channel once its close confirmed");
        // Only the tenant's side runs #1701's check: the LSP's side has the tenant for an internal peer, exempt (d8dd6d28
        // `fiber/channel.rs:4638-4641,6760-6769`).
        // Fiber writes a state's flags as one `|`-joined string.
        const flags = readJsonObject(closed.raw.state, "the closed channel's state").state_flags;
        if (typeof flags !== "string") assert.fail(`the closed channel's state_flags is not a string: ${JSON.stringify(flags)}`);
        assert.ok(flags.split("|").includes("UNCOOPERATIVE_LOCAL"), `the tenant's side closed it uncooperatively, its flags are ${flags}`);

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
