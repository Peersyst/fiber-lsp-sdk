import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { agentStatus } from "../src/status";

const TENANT_ID = "fefc063a4af63d0caaaee18e6633c5dd12a510e241e04521378325402fe58005";
const ROOT_SIGNER_PUBKEY = "03c678e8403439140e930dbb199b67d7b6b128406029d026cecba66989032dc5b6";
const TENANT_TOKEN = "EoYDCpsCCkBmZWZjMDYzYTRhZjYzZDBjYWFhZWUxOGU2NjMzYzVkZDEyYTUxMGUyNDFlMDQ1MjEzNzgzMjU0MDJmZTU4MDA1";
const CHANNEL_A = "0x446ff736f9f4df89d8b601fd0005107b50f00453f5ebf1d2ce2ebbe9b75cd7b8";
const CHANNEL_B = "0x9a1c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";
const CHANNEL_C = "0x7f00000000000000000000000000000000000000000000000000000000000001";
const SIGNATURE = `0x${"5a".repeat(32)}`;

describe("agentStatus", () => {
    it("writes the marker and empty maps while no channel is bound, the token null before registration", () => {
        assert.equal(
            JSON.stringify(agentStatus({ tenantId: TENANT_ID, rootSignerPubkey: ROOT_SIGNER_PUBKEY, tenantToken: null, channels: [] })),
            JSON.stringify({
                tenant_id: TENANT_ID,
                root_signer_pubkey: ROOT_SIGNER_PUBKEY,
                tenant_token: null,
                channel_open_signer_material: { allocated_at_open: true },
                bound_channel_ids: [],
                watchtower_submissions: {},
                revoked_commitments: {},
            }),
        );
    });

    it("writes fiber's sample status, keys in its order, for one bound channel with no evidence", () => {
        const status = agentStatus({
            tenantId: TENANT_ID,
            rootSignerPubkey: ROOT_SIGNER_PUBKEY,
            tenantToken: TENANT_TOKEN,
            channels: [{ channelId: CHANNEL_A, evidence: { revocations: [], watchtowerSignatures: [] } }],
        });
        assert.equal(
            JSON.stringify(status),
            JSON.stringify({
                tenant_id: TENANT_ID,
                root_signer_pubkey: ROOT_SIGNER_PUBKEY,
                tenant_token: TENANT_TOKEN,
                channel_open_signer_material: null,
                bound_channel_ids: [CHANNEL_A],
                watchtower_submissions: {},
                revoked_commitments: { [CHANNEL_A]: [] },
            }),
        );
    });

    it("writes the ids bare and lowercase, from hex with 0x or from bytes", () => {
        const status = agentStatus({
            tenantId: `0x${TENANT_ID.toUpperCase()}`,
            rootSignerPubkey: Uint8Array.from(Buffer.from(ROOT_SIGNER_PUBKEY, "hex")),
            tenantToken: null,
            channels: [],
        });
        assert.equal(status.tenant_id, TENANT_ID);
        assert.equal(status.root_signer_pubkey, ROOT_SIGNER_PUBKEY);
        const prefixed = agentStatus({ tenantId: TENANT_ID, rootSignerPubkey: `0x${ROOT_SIGNER_PUBKEY}`, tenantToken: null, channels: [] });
        assert.equal(prefixed.root_signer_pubkey, ROOT_SIGNER_PUBKEY);
    });

    it("sorts the bound channels, 0x lowercase, with one revoked_commitments entry each", () => {
        const status = agentStatus({
            tenantId: TENANT_ID,
            rootSignerPubkey: ROOT_SIGNER_PUBKEY,
            tenantToken: TENANT_TOKEN,
            channels: [
                { channelId: CHANNEL_B.slice(2).toUpperCase(), evidence: { revocations: [], watchtowerSignatures: [] } },
                { channelId: CHANNEL_A, evidence: { revocations: [], watchtowerSignatures: [] } },
                { channelId: CHANNEL_C, evidence: { revocations: [], watchtowerSignatures: [] } },
            ],
        });
        assert.deepEqual(status.bound_channel_ids, [CHANNEL_A, CHANNEL_C, CHANNEL_B]);
        assert.deepEqual(status.watchtower_submissions, {});
        assert.equal(JSON.stringify(status.revoked_commitments), JSON.stringify({ [CHANNEL_A]: [], [CHANNEL_C]: [], [CHANNEL_B]: [] }));
        assert.equal(status.channel_open_signer_material, null);
    });

    it("writes the applied watchtower signatures with their key purpose, keying only a channel that has one", () => {
        const status = agentStatus({
            tenantId: TENANT_ID,
            rootSignerPubkey: ROOT_SIGNER_PUBKEY,
            tenantToken: TENANT_TOKEN,
            channels: [
                {
                    channelId: CHANNEL_A,
                    evidence: {
                        revocations: [],
                        watchtowerSignatures: [
                            { requestId: "settle-1", purpose: { kind: "settlement" }, signature: SIGNATURE, applied: true },
                            { requestId: "tlc-1", purpose: { kind: "tlc", commitmentNumber: 26 }, signature: SIGNATURE, applied: true },
                            { requestId: "tlc-2", purpose: { kind: "tlc", commitmentNumber: 27 }, signature: SIGNATURE, applied: false },
                            { requestId: "tlc-3", purpose: { kind: "tlc", commitmentNumber: 0 }, signature: SIGNATURE, applied: true },
                        ],
                    },
                },
                {
                    channelId: CHANNEL_B,
                    evidence: {
                        revocations: [],
                        watchtowerSignatures: [
                            { requestId: "settle-2", purpose: { kind: "settlement" }, signature: SIGNATURE, applied: false },
                        ],
                    },
                },
            ],
        });
        assert.equal(
            JSON.stringify(status.watchtower_submissions),
            JSON.stringify({
                [CHANNEL_A]: [
                    { request_id: "settle-1", key_purpose: { type: "Settlement" } },
                    { request_id: "tlc-1", key_purpose: { type: "Tlc", commitment_number: "0x1a" } },
                    { request_id: "tlc-3", key_purpose: { type: "Tlc", commitment_number: "0x0" } },
                ],
            }),
        );
    });

    it("writes the revoked commitments with the version as a number, in the evidence's order", () => {
        const status = agentStatus({
            tenantId: TENANT_ID,
            rootSignerPubkey: ROOT_SIGNER_PUBKEY,
            tenantToken: TENANT_TOKEN,
            channels: [
                {
                    channelId: CHANNEL_A,
                    evidence: {
                        revocations: [
                            { version: 1, forRemote: true, signature: SIGNATURE },
                            { version: 2, forRemote: false, signature: SIGNATURE },
                        ],
                        watchtowerSignatures: [],
                    },
                },
            ],
        });
        assert.equal(
            JSON.stringify(status.revoked_commitments),
            JSON.stringify({
                [CHANNEL_A]: [
                    { for_remote: true, version: 1 },
                    { for_remote: false, version: 2 },
                ],
            }),
        );
    });

    it("refuses a channel bound twice, and ids that are not hex bytes", () => {
        const empty = { revocations: [], watchtowerSignatures: [] };
        assert.throws(() =>
            agentStatus({
                tenantId: TENANT_ID,
                rootSignerPubkey: ROOT_SIGNER_PUBKEY,
                tenantToken: null,
                channels: [
                    { channelId: CHANNEL_A, evidence: empty },
                    { channelId: CHANNEL_A.toUpperCase().replace("0X", "0x"), evidence: empty },
                ],
            }),
        );
        assert.throws(() => agentStatus({ tenantId: "tenant", rootSignerPubkey: ROOT_SIGNER_PUBKEY, tenantToken: null, channels: [] }));
        assert.throws(() => agentStatus({ tenantId: TENANT_ID, rootSignerPubkey: "0x", tenantToken: null, channels: [] }));
        assert.throws(() =>
            agentStatus({
                tenantId: TENANT_ID,
                rootSignerPubkey: ROOT_SIGNER_PUBKEY,
                tenantToken: null,
                channels: [{ channelId: "0x1", evidence: empty }],
            }),
        );
    });
});
