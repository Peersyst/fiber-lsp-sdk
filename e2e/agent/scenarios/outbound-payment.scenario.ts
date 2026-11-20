import assert from "node:assert/strict";
import { test } from "node:test";
import { bytesToHex } from "@noble/hashes/utils.js";
import { RpcError, SdkError } from "@peersyst/fiber-lsp-sdk";
import type { SdkErrorCode } from "@peersyst/fiber-lsp-sdk";
import { bareLowerHex, messageOf } from "../src/agent.utils";
import { readScenarioEnv } from "./utils/scenario-env";
import { ensurePublicChannels } from "./utils/public-channels";
import {
    isSdkEvent,
    OPEN_STEPS,
    OUTBOUND_AMOUNT_SHANNONS,
    OUTBOUND_MINIMUM_FEE_SHANNONS,
    ScenarioDevice,
    SENT_STEPS,
    signingSteps,
    untimedRecord,
} from "./utils/scenario-device";

function describeCause(error: SdkError): string {
    const cause = error.cause;
    return cause instanceof RpcError ? `${cause.code} ${cause.message}` : messageOf(cause);
}

async function transferRefusal(transfer: Promise<unknown>, code: SdkErrorCode): Promise<SdkError> {
    try {
        await transfer;
    } catch (error) {
        if (!(error instanceof SdkError)) throw error;
        assert.equal(error.code, code, `the transfer's code; fiber said: ${describeCause(error)}`);
        return error;
    }
    assert.fail(`the transfer was accepted where ${code} was expected`);
}

test("a payment the tenant sends asks a third signing session at C@3, and fiber#1701 force-closes the refused channel", async (t) => {
    const env = readScenarioEnv();
    await ensurePublicChannels(env);
    const device = await ScenarioDevice.create(env);
    try {
        const { node1, node2 } = device.nodes;
        const status = await device.operator.getStatus();
        assert.equal(bytesToHex(status.publicNodeId), bareLowerHex(env.node2Pubkey), "the LSP's public node id");
        t.diagnostic(`lsp_get_status: ${status.registeredTenants} registered, ${status.activeTenants} active`);

        const channelId = bareLowerHex(await device.openFundedChannel());
        const sendFrom = device.events.length;
        assert.deepEqual(signingSteps(device.events.slice(0, sendFrom), channelId), OPEN_STEPS, "the opening's signing steps");

        const invoice = await device.nodeOneInvoice("outbound payment");
        // Through the LSP as trampoline the fee is the whole budget, transfer's default without options.
        const defaultEstimate = await device.sdk.estimateTransferFee(invoice.invoiceAddress);
        assert.equal(defaultEstimate.feeShannons, ((OUTBOUND_AMOUNT_SHANNONS * 5n + 999n) / 1000n).toString(), "the default budget's fee");
        const estimate = await device.sdk.estimateTransferFee(invoice.invoiceAddress, { maxFeeShannons: OUTBOUND_MINIMUM_FEE_SHANNONS });
        assert.deepEqual(estimate, {
            paymentHashHex: `0x${bareLowerHex(invoice.paymentHash)}`,
            amountShannons: OUTBOUND_AMOUNT_SHANNONS.toString(),
            feeShannons: OUTBOUND_MINIMUM_FEE_SHANNONS,
        });
        assert.equal(await device.sdk.getPayment(estimate.paymentHashHex), null, "the dry run left no payment session");

        const unaffordable = await device.nodeOneInvoice("above the balance", BigInt(env.chain.tenantChannelShannons));
        const overdraft = await transferRefusal(device.sdk.transfer(unaffordable.invoiceAddress), "insufficient_balance");
        t.diagnostic(`a transfer above the balance: ${overdraft.code}, fiber said ${describeCause(overdraft)}`);
        const underBudget = (BigInt(estimate.feeShannons) - 1n).toString();
        await transferRefusal(
            device.sdk.estimateTransferFee(invoice.invoiceAddress, { maxFeeShannons: underBudget }),
            "fee_budget_too_low",
        );
        const lowFee = await transferRefusal(
            device.sdk.transfer(invoice.invoiceAddress, { maxFeeShannons: underBudget }),
            "fee_budget_too_low",
        );
        t.diagnostic(`a transfer one shannon under the floor: ${lowFee.code}, fiber said ${describeCause(lowFee)}`);
        const overdraftHashHex = `0x${bareLowerHex(unaffordable.paymentHash)}`;
        assert.deepEqual(
            untimedRecord(await device.sdk.getPayment(overdraftHashHex)),
            {
                paymentHashHex: overdraftHashHex,
                direction: "send",
                status: "failed",
                amountShannons: env.chain.tenantChannelShannons,
                invoice: unaffordable.invoiceAddress,
                description: "above the balance",
                maxFeeShannons: ((BigInt(env.chain.tenantChannelShannons) * 5n + 999n) / 1000n).toString(),
                feeShannons: null,
                failedReason: overdraft.message,
                createdAtMs: 0,
                settledAtMs: 0,
            },
            "the node's refusal for want of balance stays in the history",
        );
        assert.deepEqual(
            untimedRecord(await device.sdk.getPayment(`0x${bareLowerHex(invoice.paymentHash)}`)),
            {
                paymentHashHex: `0x${bareLowerHex(invoice.paymentHash)}`,
                direction: "send",
                status: "failed",
                amountShannons: OUTBOUND_AMOUNT_SHANNONS.toString(),
                invoice: invoice.invoiceAddress,
                description: "outbound payment",
                maxFeeShannons: underBudget,
                feeShannons: null,
                failedReason: lowFee.message,
                createdAtMs: 0,
                settledAtMs: 0,
            },
            "the node's refusal of the fee stays in the history",
        );

        const payment = await device.sdk.transfer(invoice.invoiceAddress, { maxFeeShannons: estimate.feeShannons });
        const paymentHash = bareLowerHex(payment.paymentHashHex);
        assert.equal(paymentHash, bareLowerHex(invoice.paymentHash));
        assert.equal(payment.amountShannons, OUTBOUND_AMOUNT_SHANNONS.toString());
        assert.equal(payment.maxFeeShannons, estimate.feeShannons);

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
        await device.confirmForceClose(channelId);

        // The sent TLC settles on chain only past the commitment delay, which this scenario never reaches.
        const outcome = await node2.getPayment(payment.paymentHashHex, device.accessToken);
        assert.deepEqual({ status: outcome.status, failedError: outcome.failedError }, { status: "Inflight", failedError: null });
        const record = await device.sdk.getPayment(payment.paymentHashHex);
        assert.deepEqual(
            untimedRecord(record),
            {
                paymentHashHex: payment.paymentHashHex,
                direction: "send",
                status: "pending",
                amountShannons: OUTBOUND_AMOUNT_SHANNONS.toString(),
                invoice: invoice.invoiceAddress,
                description: "outbound payment",
                maxFeeShannons: estimate.feeShannons,
                feeShannons: null,
                failedReason: null,
                createdAtMs: 0,
                settledAtMs: null,
            },
            "the retry put the refused send back to pending",
        );
        const history = await device.sdk.listPayments();
        assert.deepEqual(
            history.map(({ paymentHashHex, status }) => ({ paymentHashHex, status })),
            [
                { paymentHashHex: payment.paymentHashHex, status: "pending" },
                { paymentHashHex: `0x${bareLowerHex(unaffordable.paymentHash)}`, status: "failed" },
            ],
            "the history, newest first",
        );
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
