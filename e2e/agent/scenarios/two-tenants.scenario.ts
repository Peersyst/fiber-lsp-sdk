import assert from "node:assert/strict";
import { test } from "node:test";
import { bareLowerHex } from "../src/agent.utils";
import { readDevnetEnv } from "./utils/devnet-env";
import { channelIdParam, GET_CHANNEL_SIGNING_STATUS_METHOD, SUBMIT_CHANNEL_SIGNATURE_METHOD } from "./utils/faulty-fetch";
import { ensurePublicChannels } from "./utils/public-channels";
import {
    CHANNEL_FUNDING_SHANNONS,
    INVOICE_AMOUNT_SHANNONS,
    OPEN_STEPS,
    RECEIVED_STEPS,
    ScenarioDevice,
    signingSteps,
} from "./utils/scenario-device";

type Tenant = { name: string; device: ScenarioDevice; channelId: string };

function distinct(values: string[]): string[] {
    return [...new Set(values)];
}

function signingChannels(device: ScenarioDevice, from = 0): string[] {
    return distinct(device.events.slice(from).flatMap(({ event }) => (event.type === "SIGNING" ? [bareLowerHex(event.channelId)] : [])));
}

function wireChannels(device: ScenarioDevice, method: string): string[] {
    return distinct(device.faults.sent(method).map((request) => channelIdParam(request.params, method)));
}

test("two tenants on one LSP each sign their own channel and nothing of the other's", async (t) => {
    const env = readDevnetEnv();
    await ensurePublicChannels(env);
    const devices: ScenarioDevice[] = [];
    try {
        const deviceA = await ScenarioDevice.create(env);
        devices.push(deviceA);
        const deviceB = await ScenarioDevice.create(env);
        devices.push(deviceB);
        assert.notEqual(deviceA.tenantId, deviceB.tenantId);
        const { node1, node2 } = deviceA.nodes;

        const a: Tenant = {
            name: "A",
            device: deviceA,
            channelId: bareLowerHex(await deviceA.openFundedChannel(CHANNEL_FUNDING_SHANNONS)),
        };
        const b: Tenant = {
            name: "B",
            device: deviceB,
            channelId: bareLowerHex(await deviceB.openFundedChannel(CHANNEL_FUNDING_SHANNONS)),
        };
        assert.notEqual(a.channelId, b.channelId);
        const tenants = [a, b];

        const invoiceA = await deviceA.sdk.createInvoice(INVOICE_AMOUNT_SHANNONS, { description: "tenant A" });
        const invoiceB = await deviceB.sdk.createInvoice(INVOICE_AMOUNT_SHANNONS, { description: "tenant B" });
        const paidFrom = [deviceA.events.length, deviceB.events.length];
        const [paymentA, paymentB] = await Promise.all([node1.sendPayment(invoiceA.invoice), node1.sendPayment(invoiceB.invoice)]);
        assert.equal(bareLowerHex(paymentA.paymentHash), bareLowerHex(invoiceA.paymentHashHex));
        assert.equal(bareLowerHex(paymentB.paymentHash), bareLowerHex(invoiceB.paymentHashHex));
        await Promise.all([
            deviceA.waitForPaymentReceived(invoiceA.paymentHashHex),
            deviceB.waitForPaymentReceived(invoiceB.paymentHashHex),
            node1.waitForPaymentStatus(invoiceA.paymentHashHex, "Success"),
            node1.waitForPaymentStatus(invoiceB.paymentHashHex, "Success"),
        ]);

        for (const [index, { name, device, channelId }] of tenants.entries()) {
            assert.deepEqual(signingChannels(device), [channelId], `${name}'s SIGNING events name its channel alone`);
            const from = paidFrom[index];
            if (from === undefined) assert.fail(`no event mark for ${name}`);
            assert.deepEqual(signingSteps(device.events.slice(0, from), channelId), OPEN_STEPS, `${name}'s opening's signing steps`);
            assert.deepEqual(signingChannels(device, from), [channelId], `${name} signed for its payment`);
            assert.deepEqual(
                await device.waitForSigningSteps(channelId, from, RECEIVED_STEPS.length),
                RECEIVED_STEPS,
                `${name}'s payment signed as a channel's first payment received`,
            );
            assert.deepEqual(
                wireChannels(device, GET_CHANNEL_SIGNING_STATUS_METHOD),
                [channelId],
                `${name} reads its channel's status alone`,
            );
            assert.deepEqual(wireChannels(device, SUBMIT_CHANNEL_SIGNATURE_METHOD), [channelId], `${name} submits for its channel alone`);
            const listed = await device.sdk.listChannels();
            assert.deepEqual(
                listed.map((channel) => ({ channelId: bareLowerHex(channel.channelId), hasRecord: channel.hasRecord })),
                [{ channelId, hasRecord: true }],
                `${name} lists its channel alone`,
            );
        }

        const ownStatus = await node2.channelSigningStatus(b.channelId, deviceB.accessToken);
        assert.equal(typeof ownStatus.channel_id === "string" ? bareLowerHex(ownStatus.channel_id) : ownStatus.channel_id, b.channelId);
        // Fiber looks the channel up in the token's tenant namespace alone: `channel {id:?} not found` (`lsp/service.rs:457`),
        // a `Hash256` written by its Debug as `Hash256(0x...)`.
        await assert.rejects(
            node2.channelSigningStatus(b.channelId, deviceA.accessToken),
            new RegExp(`channel Hash256\\(0x${b.channelId}\\) not found`),
        );
    } finally {
        for (const device of devices) {
            t.diagnostic(`events of tenant ${device.tenantId}: ${device.describeEvents()}`);
            await device.close();
        }
    }
});
