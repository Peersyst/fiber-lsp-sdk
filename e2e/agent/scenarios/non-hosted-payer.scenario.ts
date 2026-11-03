import assert from "node:assert/strict";
import { test } from "node:test";
import { bytesToHex } from "@noble/hashes/utils.js";
import { decodeInvoice } from "@peersyst/fiber-lsp-sdk";
import { bareLowerHex } from "../src/agent.utils";
import { readDevnetEnv } from "./utils/devnet-env";
import type { FiberNode } from "./utils/fiber-node";
import { ensurePublicChannels } from "./utils/public-channels";
import {
    CHANNEL_FUNDING_SHANNONS,
    INVOICE_AMOUNT_SHANNONS,
    OPEN_STEPS,
    RECEIVED_STEPS,
    ScenarioDevice,
    scenarioJson,
    signingSteps,
} from "./utils/scenario-device";
import { EVENT_TIMEOUT_MS, waitUntil } from "./utils/wait";

type Node1Balances = { fromNode3: bigint; toLsp: bigint };

// Summed over every channel to the peer, so the check holds whichever of them the route took.
async function localBalanceTo(node: FiberNode, peer: string): Promise<bigint> {
    const channels = await node.listChannels({ peer });
    return channels.reduce((sum, channel) => {
        const balance = channel.raw.local_balance;
        if (typeof balance !== "string") throw new Error(`list_channels: ${channel.channelId}'s local_balance must be a hex string`);
        return sum + BigInt(balance);
    }, 0n);
}

async function readNode1Balances(node1: FiberNode, node3Pubkey: string, lspPubkey: string): Promise<Node1Balances> {
    return { fromNode3: await localBalanceTo(node1, node3Pubkey), toLsp: await localBalanceTo(node1, lspPubkey) };
}

test("a node the LSP does not host pays the device's invoice through node 1 and the LSP", async (t) => {
    const env = readDevnetEnv();
    await ensurePublicChannels(env);
    const device = await ScenarioDevice.create(env);
    try {
        const { node1, node2, node3 } = device.nodes;
        const channelId = await device.openFundedChannel(CHANNEL_FUNDING_SHANNONS);
        const invoice = await device.sdk.createInvoice(INVOICE_AMOUNT_SHANNONS, { description: "non-hosted payer" });
        const hints = decodeInvoice(invoice.invoice).attributes.flatMap((attribute) =>
            attribute.type === "trampolineRouteHint" ? [bytesToHex(attribute.nodeId)] : [],
        );
        assert.deepEqual(hints, [bareLowerHex(env.node2Pubkey)], "the invoice's trampoline hint is not the LSP alone");

        const paidFrom = device.events.length;
        assert.deepEqual(signingSteps(device.events.slice(0, paidFrom), channelId), OPEN_STEPS, "the opening's signing steps");
        const before = await readNode1Balances(node1, env.node3Pubkey, env.node2Pubkey);
        const sent = await node3.sendPayment(invoice.invoice);
        assert.equal(bareLowerHex(sent.paymentHash), bareLowerHex(invoice.paymentHashHex));

        await device.waitForPaymentReceived(invoice.paymentHashHex);
        await node3.waitForPaymentStatus(invoice.paymentHashHex, "Success");
        assert.equal((await node2.getInvoice(invoice.paymentHashHex, device.accessToken)).status, "Paid");

        const amount = BigInt(INVOICE_AMOUNT_SHANNONS);
        let after = before;
        await waitUntil(
            "node 1's balances to show it forwarded the payment from node 3 to the LSP",
            async () => {
                after = await readNode1Balances(node1, env.node3Pubkey, env.node2Pubkey);
                return after.fromNode3 - before.fromNode3 >= amount && before.toLsp - after.toLsp >= amount ? true : undefined;
            },
            { timeoutMs: EVENT_TIMEOUT_MS },
        ).catch((error: unknown) => {
            throw new Error(`node 1's balances went from ${scenarioJson(before)} to ${scenarioJson(after)}`, {
                cause: error,
            });
        });
        assert.deepEqual(await device.waitForSigningSteps(channelId, paidFrom, RECEIVED_STEPS.length), RECEIVED_STEPS);
    } finally {
        t.diagnostic(`events: ${device.describeEvents()}`);
        await device.close();
    }
});
