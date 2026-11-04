import assert from "node:assert/strict";
import { test } from "node:test";
import { SdkError } from "@peersyst/fiber-lsp-sdk";
import type { Script } from "@peersyst/fiber-lsp-sdk";
import { bareLowerHex, readJsonObject } from "../src/agent.utils";
import { scriptFromJson } from "../src/open-params";
import { readScenarioEnv } from "./utils/scenario-env";
import {
    channelIdParam,
    OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD,
    requestParam,
    SUBMIT_CHANNEL_SIGNATURE_METHOD,
    SUBMIT_SIGNED_FUNDING_TX_METHOD,
} from "./utils/faulty-fetch";
import { fiberNodes, toHexQuantity } from "./utils/fiber-node";
import { ensurePublicChannels } from "./utils/public-channels";
import { OPEN_STEPS, ScenarioDevice, signingSteps } from "./utils/scenario-device";

// Takes the script's args past both commitment lock layouts' 57 and 58 bytes, so the peer's reserve over it moves too.
const EXTRA_ARGS_HEX = "ab".repeat(64);

type Answer = Record<string, unknown>;

type Alteration = {
    name: string;
    field: RegExp;
    alter: (answer: Answer) => Answer;
};

function readHexString(value: unknown, where: string): string {
    if (typeof value !== "string") throw new Error(`${where} must be a hex string`);
    return value;
}

function bumpQuantity(value: unknown, where: string): string {
    return toHexQuantity(BigInt(readHexString(value, where)) + 1n);
}

function alterContext(answer: Answer, alter: (context: Answer) => Answer): Answer {
    return {
        ...answer,
        opening_context: alter(readJsonObject(answer.opening_context, `${OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD}.opening_context`)),
    };
}

const ALTERATIONS: Alteration[] = [
    {
        name: "the LSP's close script, grown past the reserve the node states",
        field: /openingContext\.remoteReservedCkbShannons /,
        alter: (answer) =>
            alterContext(answer, (context) => {
                const script = readJsonObject(context.remote_shutdown_script, "opening_context.remote_shutdown_script");
                const args = readHexString(script.args, "opening_context.remote_shutdown_script.args");
                return { ...context, remote_shutdown_script: { ...script, args: `${args}${EXTRA_ARGS_HEX}` } };
            }),
    },
    {
        name: "the funding output's capacity",
        field: /unsignedFundingTx\.outputs\[0\]\.capacityShannons /,
        alter: (answer) => {
            const tx = readJsonObject(answer.unsigned_funding_tx, `${OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD}.unsigned_funding_tx`);
            const { outputs } = tx;
            if (!Array.isArray(outputs))
                throw new Error(`${OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD}.unsigned_funding_tx.outputs must be an array`);
            const [funding, ...rest] = outputs as unknown[];
            const output = readJsonObject(funding, "unsigned_funding_tx.outputs[0]");
            const capacity = bumpQuantity(output.capacity, "unsigned_funding_tx.outputs[0].capacity");
            return { ...answer, unsigned_funding_tx: { ...tx, outputs: [{ ...output, capacity }, ...rest] } };
        },
    },
    {
        name: "the commitment fee rate",
        field: /openingContext\.commitmentFeeRate /,
        alter: (answer) =>
            alterContext(answer, (context) => ({
                ...context,
                commitment_fee_rate: bumpQuantity(context.commitment_fee_rate, "opening_context.commitment_fee_rate"),
            })),
    },
];

async function refuseAltered(device: ScenarioDevice, alteration: Alteration, userLock: Script): Promise<string> {
    const seen: { channelId?: string } = {};
    device.faults.rewriteResult(OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD, (result) => {
        const answer = readJsonObject(result, OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD);
        seen.channelId = bareLowerHex(readHexString(answer.channel_id, `${OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD}.channel_id`));
        return alteration.alter(answer);
    });
    await assert.rejects(
        device.sdk.prepareChannelOpen(device.env.chain.tenantChannelShannons, userLock),
        (error: unknown) => error instanceof SdkError && error.code === "opening_rejected" && alteration.field.test(error.message),
        `${alteration.name}: the altered opening must be refused as opening_rejected naming ${alteration.field}`,
    );
    if (seen.channelId === undefined)
        assert.fail(`${alteration.name}: ${OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD}'s answer was never rewritten`);
    return seen.channelId;
}

function assertNoSignatureServed(device: ScenarioDevice, channelId: string): void {
    assert.deepEqual(device.signingRecords(channelId), [], `no SIGNING for the refused channel ${channelId}`);
    const submitted = device.faults
        .sent(SUBMIT_CHANNEL_SIGNATURE_METHOD)
        .filter((request) => channelIdParam(request.params, SUBMIT_CHANNEL_SIGNATURE_METHOD) === channelId);
    assert.deepEqual(submitted, [], `no signature submitted for the refused channel ${channelId}`);
}

function submittedFundingChannels(device: ScenarioDevice): string[] {
    return device.faults
        .sent(SUBMIT_SIGNED_FUNDING_TX_METHOD)
        .map((request) => channelIdParam(request.params, SUBMIT_SIGNED_FUNDING_TX_METHOD));
}

function openingFundingKeys(device: ScenarioDevice): string[] {
    return device.faults.sent(OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD).map((request) => {
        const signer = readJsonObject(
            requestParam(request.params, OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD).external_channel_signer,
            "external_channel_signer",
        );
        const keys = readJsonObject(signer.base_public_keys, "external_channel_signer.base_public_keys");
        return bareLowerHex(readHexString(keys.funding_pubkey, "base_public_keys.funding_pubkey"));
    });
}

test("an opening the node altered is refused before anything is signed, and a fresh index opens", async (t) => {
    const env = readScenarioEnv();
    await ensurePublicChannels(env);
    const device = await ScenarioDevice.create(env);
    try {
        const userLock = scriptFromJson((await fiberNodes(env).node1.nodeInfo()).defaultFundingLockScript);
        const refused: string[] = [];
        // One device throughout: each refusal drops the SDK's pending opening, so the next opening takes a fresh index, and
        // fiber keys a tenant's openings by their signer's keys, so it holds none of the refused ones against the next.
        for (const alteration of ALTERATIONS) {
            const channelId = await refuseAltered(device, alteration, userLock);
            assertNoSignatureServed(device, channelId);
            assert.deepEqual(submittedFundingChannels(device), [], `${alteration.name}: no funding tx submitted`);
            refused.push(channelId);
            t.diagnostic(`${alteration.name}: channel ${channelId} refused`);
        }

        const channelId = bareLowerHex(await device.openFundedChannel());
        assert.deepEqual(signingSteps(device.events, channelId), OPEN_STEPS, "the fresh opening's signing steps");

        assert.equal(refused.includes(channelId), false, "the fresh opening is none of the refused ones");
        const keys = openingFundingKeys(device);
        assert.equal(keys.length, ALTERATIONS.length + 1, "the refused openings and the fresh one");
        assert.equal(new Set(keys).size, keys.length, "every opening runs on a channel index of its own");
        assert.deepEqual(submittedFundingChannels(device), [channelId]);
        for (const refusedId of refused) assertNoSignatureServed(device, refusedId);
    } catch (error) {
        t.diagnostic(`events of tenant ${device.tenantId}: ${device.describeEvents()}`);
        throw error;
    } finally {
        await device.close();
    }
});
