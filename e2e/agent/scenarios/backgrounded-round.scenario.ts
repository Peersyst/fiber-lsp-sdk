import assert from "node:assert/strict";
import { test } from "node:test";
import type { TestContext } from "node:test";
import { bareLowerHex } from "../src/agent.utils";
import { readDevnetEnv } from "./utils/devnet-env";
import { ensurePublicChannels } from "./utils/public-channels";
import { CHANNEL_READY_STATE } from "./utils/fiber-node";
import {
    CHANNEL_FUNDING_SHANNONS,
    CHECK_CHANNELS_INTERVAL_MS,
    INVOICE_AMOUNT_SHANNONS,
    isPaymentReceived,
    isSdkEvent,
    OPEN_STEPS,
    PEER_CHANNEL_RESPONSE_TIMEOUT_MS,
    RECEIVED_STEPS,
    ScenarioDevice,
    signingSteps,
} from "./utils/scenario-device";
import { OPENING_TIMEOUT_MS, PROBE_INTERVAL_MS, sleep, waitUntil } from "./utils/wait";

// Either side of #1701's window.
const WITHIN_WINDOW_MS = PEER_CHANNEL_RESPONSE_TIMEOUT_MS - 3 * CHECK_CHANNELS_INTERVAL_MS;
const PAST_WINDOW_MS = PEER_CHANNEL_RESPONSE_TIMEOUT_MS + 5 * CHECK_CHANNELS_INTERVAL_MS;

// Up to the device's SendRevokeAndAck.
const BEFORE_BACKGROUND_STEPS = RECEIVED_STEPS.slice(0, 2);

type BackgroundedRound = {
    device: ScenarioDevice;
    channelId: string;
    paymentHashHex: string;
    receiveFrom: number;
    backgroundedAt: number;
};

async function backgroundMidRound(
    t: TestContext,
    offlineMs: number,
    during?: (round: BackgroundedRound) => Promise<void>,
): Promise<BackgroundedRound> {
    const env = readDevnetEnv();
    await ensurePublicChannels(env);
    const device = await ScenarioDevice.create(env);
    t.after(async () => {
        t.diagnostic(`events: ${device.describeEvents()}`);
        await device.close();
    });
    const channelId = bareLowerHex(await device.openFundedChannel(CHANNEL_FUNDING_SHANNONS));
    const receiveFrom = device.events.length;
    assert.deepEqual(signingSteps(device.events.slice(0, receiveFrom), channelId), OPEN_STEPS, "the opening's signing steps");

    let backgroundedAt: number | undefined;
    const revoked = isSdkEvent(
        "SIGNING",
        (event) => bareLowerHex(event.channelId) === channelId && event.transition === "SendRevokeAndAck" && event.outcome === "signed",
    );
    const sdk = device.sdk;
    // In the listener, so no tick runs between the revocation and the disconnect.
    const stopListening = sdk.onEvent((event) => {
        if (backgroundedAt !== undefined || !revoked(event)) return;
        sdk.disconnect();
        backgroundedAt = Date.now();
    });
    const invoice = await sdk.createInvoice(INVOICE_AMOUNT_SHANNONS, { description: "backgrounded round" });
    await device.nodes.node1.sendPayment(invoice.invoice);
    const at = await waitUntil("the device's revocation of the payment's round", () => Promise.resolve(backgroundedAt), {
        timeoutMs: OPENING_TIMEOUT_MS,
    });
    stopListening();
    await device.waitForSettled();
    assert.deepEqual(signingSteps(device.events.slice(receiveFrom), channelId), BEFORE_BACKGROUND_STEPS);

    const round: BackgroundedRound = { device, channelId, paymentHashHex: invoice.paymentHashHex, receiveFrom, backgroundedAt: at };
    await during?.(round);
    const remaining = at + offlineMs - Date.now();
    if (remaining > 0) await sleep(remaining);
    assert.deepEqual(
        signingSteps(device.events.slice(receiveFrom), channelId),
        BEFORE_BACKGROUND_STEPS,
        "nothing signed in the background",
    );
    t.diagnostic(`back in the foreground ${Date.now() - at} ms after the revocation`);
    sdk.connect();
    return round;
}

test(`a device back ${WITHIN_WINDOW_MS / 1000} s after its revocation finishes the round, inside fiber#1701's window`, async (t) => {
    const { device, channelId, paymentHashHex, receiveFrom } = await backgroundMidRound(t, WITHIN_WINDOW_MS);
    await device.waitForPaymentReceived(paymentHashHex);
    await device.nodes.node1.waitForPaymentStatus(paymentHashHex, "Success");
    assert.deepEqual(await device.waitForSigningSteps(channelId, receiveFrom, RECEIVED_STEPS.length), RECEIVED_STEPS);
    assert.deepEqual(device.signingRecords(channelId, "refused"), [], "no session refused");
    assert.equal((await device.fiberChannel(channelId))?.stateName, CHANNEL_READY_STATE, "the channel after the round");
});

test(`a device back ${PAST_WINDOW_MS / 1000} s after its revocation finds its channel force-closed by fiber#1701`, async (t) => {
    const round = await backgroundMidRound(t, PAST_WINDOW_MS, async ({ device, channelId, backgroundedAt }) => {
        const leaving = await device.waitForForceClose(channelId, backgroundedAt + PAST_WINDOW_MS - Date.now() - PROBE_INTERVAL_MS);
        const leftAfterMs = leaving.at - backgroundedAt;
        t.diagnostic(`the channel left ChannelReady ${leftAfterMs} ms after the revocation: ${JSON.stringify(leaving.channel.raw.state)}`);
        assert.ok(leftAfterMs > PEER_CHANNEL_RESPONSE_TIMEOUT_MS, `the channel left ChannelReady ${leftAfterMs} ms after the revocation`);
    });
    const { device, channelId, paymentHashHex, receiveFrom } = round;
    await device.mineForceClose(channelId);
    const signedSince = signingSteps(device.events.slice(receiveFrom), channelId).filter(({ outcome }) => outcome !== "refused");
    assert.deepEqual(signedSince, BEFORE_BACKGROUND_STEPS, "nothing signed back in the foreground");
    const payer = await device.nodes.node1.getPayment(paymentHashHex);
    const invoice = await device.nodes.node2.getInvoice(paymentHashHex, device.accessToken);
    t.diagnostic(`the payment at the close: payer ${payer.status} (${payer.failedError ?? "no error"}), invoice ${invoice.status}`);
    // The peer's add applies only on the device's CompleteReceivedRevokeAndAck (d8dd6d28 `fiber/channel.rs:1337-1363,2580`), so
    // the invoice never held it; the TLC returns on chain past its expiry, never mined to.
    assert.deepEqual({ payer: payer.status, invoice: invoice.status }, { payer: "Inflight", invoice: "Open" });
    const received = isPaymentReceived(paymentHashHex);
    assert.ok(!device.events.some(({ event }) => received(event)), "no PAYMENT_RECEIVED for the payment the close left unresolved");
});
