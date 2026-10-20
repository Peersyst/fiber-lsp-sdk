import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Session } from "@scure/btc-signer/musig2.js";
import type { Script } from "../../../src/common";
import { moleculeScript, moleculeScriptOpt, moleculeTable, uint64Le } from "../../../src/common";
import { deriveChannelKeys, deriveChannelSeed, deriveNonceSeed, deriveTlcKey, pubkeyOf } from "../../../src/derivation";
import type { ChannelPolicyRecord, ISignerStorage } from "../../../src/policy";
import { CHANNEL_ALIAS_KEY_PREFIX, CHANNEL_RECORD_KEY_PREFIX, PolicyEngine, SignerStore } from "../../../src/policy";
import type { ChannelSigningTransition } from "../../../src/protocol";
import type { DispatchOutcome, SignerRefusal } from "../../../src/signer";
import { SignerDispatch, buildChannelOpenMaterial, getPublicNonce } from "../../../src/signer";
import * as musig2Engine from "../../../src/signer/musig2-engine";
import type { WireField } from "../../../src/wire";
import { InMemorySignerStorage } from "../../mocks/policy";
import { toScript } from "../../utils/digest-inputs";
import { resignPeerHalf } from "../../utils/peer-musig";
import type { SigningChannel } from "../../utils/signing-channel";
import { openSigningChannel, signingDeviceKeys, signingPeerKeys, signingViewTlcs } from "../../utils/signing-channel";
import type { SigningCaseVector } from "../../utils/signing-vectors";
import { loadSigningVectors, signingCaseOf, signingStatusField } from "../../utils/signing-vectors";
import { withField } from "../../utils/with-field";

const vectors = loadSigningVectors();
const KEYS = signingDeviceKeys(vectors);
const PEER_KEYS = signingPeerKeys(vectors);
const MASTER_SEED = hexToBytes(vectors.device.master_seed);
const CHANNEL_INDEX = vectors.device.channel_index;
const DEVICE_FUNDING_PUBKEY = hexToBytes(vectors.device.funding_pubkey);
const PEER_FUNDING_PUBKEY = hexToBytes(vectors.peer.funding_pubkey);
const COMMITMENT_LOCK = { codeHash: hexToBytes(vectors.channel.commitment_lock.code_hash), hashType: "type" } as const;
const LOCAL_CLOSE_SCRIPT = toScript(vectors.channel.local_close_script);
const PEER_CLOSE_SCRIPT = toScript(vectors.channel.remote_close_script);
const FUNDED = "72000000000";
const UNKNOWN_CHANNEL_ID = `0x${"2e".repeat(32)}`;
const TYPE_SCRIPT: Script = { codeHash: new Uint8Array(32).fill(0x91), hashType: "type", args: new Uint8Array(32).fill(0x86) };

const SIGNED: readonly ChannelSigningTransition[] = [
    "SendCommitmentSigned",
    "CompleteReceivedCommitment",
    "SendRevokeAndAck",
    "CompleteReceivedRevokeAndAck",
    "SendClosingSigned",
];

function caseOf(transition: ChannelSigningTransition): SigningCaseVector {
    return signingCaseOf(vectors, transition);
}

function statusOf(transition: ChannelSigningTransition): WireField {
    return signingStatusField(caseOf(transition));
}

function mutated(status: WireField, path: string, replacement: unknown): WireField {
    return { value: withField(status.value, path, replacement), path: status.path };
}

// The status as it now stands, its peer half signed again over it: what a node that changed the request would send.
function resigned(status: WireField, randByte = 0x51): WireField {
    return resignPeerHalf(status, KEYS, PEER_KEYS.fundingKey, randByte);
}

function keyAggContextWire(first: Uint8Array, second: Uint8Array): string {
    return `0x0000000002${bytesToHex(first)}${bytesToHex(second)}`;
}

// A revocation's output in molecule hex, fiber's `EntityHex`.
function revocationOutputWire(capacityShannons: bigint, lock: Script, type: Script | null): string {
    return `0x${bytesToHex(moleculeTable([uint64Le(capacityShannons), moleculeScript(lock), moleculeScriptOpt(type)]))}`;
}

// The capacity both vector revocations pay: the funding cell less the commitment fee.
const REVOCATION_CAPACITY = 0x1689bac637n;

function signedOf(outcome: DispatchOutcome): Extract<DispatchOutcome, { kind: "signed" }> {
    if (outcome.kind !== "signed") throw new Error(`expected a signature, got ${JSON.stringify(outcome)}`);
    return outcome;
}

function refusedOf(outcome: DispatchOutcome): Extract<DispatchOutcome, { kind: "refused" }> {
    if (outcome.kind !== "refused") throw new Error(`expected a refusal, got ${outcome.kind}`);
    return outcome;
}

function faultOf(outcome: DispatchOutcome): unknown {
    if (outcome.kind !== "fault") throw new Error(`expected a fault, got ${outcome.kind}`);
    return outcome.cause;
}

function writesOf(storage: InMemorySignerStorage): string[] {
    return storage.ops.filter((op) => op.startsWith("set "));
}

// Handles a status that must be refused before the claim: nothing is written, nor is the record changed.
async function refusedUnclaimed(channel: SigningChannel, status: WireField, channelId = channel.channelId): Promise<SignerRefusal> {
    const before = [...channel.storage.map.entries()];
    channel.storage.ops.length = 0;
    const outcome = refusedOf(await channel.dispatch.handle(channelId, status));
    expect(writesOf(channel.storage)).toEqual([]);
    expect([...channel.storage.map.entries()]).toEqual(before);
    return outcome.error;
}

async function recordOf(channel: SigningChannel): Promise<ChannelPolicyRecord> {
    const record = await channel.store.getChannelRecord(channel.channelIndex);
    if (record === null) throw new Error("the channel holds no record");
    return record;
}

async function updateRecord(channel: SigningChannel, update: (record: ChannelPolicyRecord) => ChannelPolicyRecord): Promise<void> {
    await channel.store.updateChannelRecord(channel.channelIndex, (current) => {
        if (current === null) throw new Error("the channel holds no record");
        return update(current);
    });
}

function partialSignatureVerifies(signed: Extract<DispatchOutcome, { kind: "signed" }>, status: WireField): boolean {
    const content = (status.value as { content: { key_agg_ctx: string; agg_nonce: string } }).content;
    const evidence = (status.value as { session_evidence: { peer_public_nonce: string } }).session_evidence;
    const keyAgg = hexToBytes(content.key_agg_ctx.slice(2));
    const keys = [keyAgg.slice(5, 38), keyAgg.slice(38)];
    const deviceIndex = bytesToHex(keys[0] ?? new Uint8Array()) === vectors.device.funding_pubkey ? 0 : 1;
    const deviceNonce = getPublicNonce(KEYS, signed.slot.commitmentNumber, signed.slot.context);
    const peerNonce = hexToBytes(evidence.peer_public_nonce.slice(2));
    const nonces = deviceIndex === 0 ? [deviceNonce, peerNonce] : [peerNonce, deviceNonce];
    const message = hexToBytes(caseOf(signed.transition).expected.message);
    const session = new Session(hexToBytes(content.agg_nonce.slice(2)), keys, message);
    return session.partialSigVerify(signed.partialSignature, nonces, deviceIndex);
}

describe("constructor", () => {
    it.each([31, 33])("rejects a master seed of %i bytes", (length) => {
        const policy = new PolicyEngine(new SignerStore(new InMemorySignerStorage()));
        expect(
            () =>
                new SignerDispatch({
                    masterSeed: new Uint8Array(length),
                    commitmentLock: COMMITMENT_LOCK,
                    fundingLockCellDepsCount: 2,
                    policy,
                }),
        ).toThrow(TypeError);
    });

    it("rejects a commitment lock that is not a script template", () => {
        const policy = new PolicyEngine(new SignerStore(new InMemorySignerStorage()));
        const commitmentLock = { codeHash: new Uint8Array(31), hashType: "type" as const };
        expect(() => new SignerDispatch({ masterSeed: MASTER_SEED, commitmentLock, fundingLockCellDepsCount: 2, policy })).toThrow(
            TypeError,
        );
    });

    it.each([1, 255])("takes a funding lock cell deps count of %p, the bounds included", (fundingLockCellDepsCount) => {
        const policy = new PolicyEngine(new SignerStore(new InMemorySignerStorage()));
        expect(
            () => new SignerDispatch({ masterSeed: MASTER_SEED, commitmentLock: COMMITMENT_LOCK, fundingLockCellDepsCount, policy }),
        ).not.toThrow();
    });

    // Fiber's funding lock has cell deps, and the commitment fee is sized over them: none is no network.
    it.each([0, -1, 1.5, 256])("rejects a funding lock cell deps count of %p", (fundingLockCellDepsCount) => {
        const policy = new PolicyEngine(new SignerStore(new InMemorySignerStorage()));
        expect(
            () => new SignerDispatch({ masterSeed: MASTER_SEED, commitmentLock: COMMITMENT_LOCK, fundingLockCellDepsCount, policy }),
        ).toThrow(new RangeError(`fundingLockCellDepsCount must be an integer between 1 and 255, got ${fundingLockCellDepsCount}`));
    });

    it("keeps its own copy of the seed, so the host may discard its buffer", async () => {
        const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
        const masterSeed = Uint8Array.from(MASTER_SEED);
        const dispatch = new SignerDispatch({
            masterSeed,
            commitmentLock: COMMITMENT_LOCK,
            fundingLockCellDepsCount: 2,
            policy: channel.policy,
        });
        masterSeed.fill(0);
        const signed = signedOf(await dispatch.handle(channel.channelId, statusOf("SendCommitmentSigned")));
        expect(bytesToHex(signed.partialSignature)).toBe(caseOf("SendCommitmentSigned").expected.partial_signature);
    });
});

describe("prepareChannelOpen", () => {
    const policy = new PolicyEngine(new SignerStore(new InMemorySignerStorage()));
    const dispatch = new SignerDispatch({ masterSeed: MASTER_SEED, commitmentLock: COMMITMENT_LOCK, fundingLockCellDepsCount: 2, policy });

    it("derives the opening material of the index, the one the channel signs under later", () => {
        const pending = dispatch.prepareChannelOpen(CHANNEL_INDEX, FUNDED, LOCAL_CLOSE_SCRIPT);
        expect(pending.material).toEqual(buildChannelOpenMaterial(KEYS));
        expect(bytesToHex(pending.material.fundingPubkey)).toBe(vectors.device.funding_pubkey);
        expect(pending.material.channelAnnouncementNonce).toBeNull();
    });

    it("never hands out a secret", () => {
        const pending = dispatch.prepareChannelOpen(CHANNEL_INDEX, FUNDED, LOCAL_CLOSE_SCRIPT);
        const published = Object.values(pending.material).flatMap((value) => (value instanceof Uint8Array ? [bytesToHex(value)] : []));
        const secrets = [MASTER_SEED, KEYS.fundingKey, KEYS.tlcBaseKey, KEYS.musig2BaseNonce, KEYS.commitmentSeed].map(bytesToHex);
        for (const value of published) for (const secret of secrets) expect(value).not.toContain(secret);
    });

    it("derives each index's own channel, and keeps the index and the funded amount", () => {
        const pending = dispatch.prepareChannelOpen(CHANNEL_INDEX + 1, FUNDED, LOCAL_CLOSE_SCRIPT);
        const other = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, CHANNEL_INDEX + 1));
        expect(pending.material).toEqual(buildChannelOpenMaterial(other));
        expect(pending.channelIndex).toBe(CHANNEL_INDEX + 1);
        expect(pending.fundedShannons).toBe(FUNDED);
    });

    it("keeps a copy of the close script, which the caller's later writes do not reach", () => {
        const script = toScript(vectors.channel.local_close_script);
        const pending = dispatch.prepareChannelOpen(CHANNEL_INDEX, FUNDED, script);
        script.args.fill(0);
        script.codeHash.fill(0);
        expect(pending.localCloseScript).toEqual(LOCAL_CLOSE_SCRIPT);
    });

    // The device's reserve over this script is 99 CKB under the lower layout, so that is the least it may fund.
    it("refuses a funding fiber would not open, ahead of any round trip", () => {
        expect(dispatch.prepareChannelOpen(CHANNEL_INDEX, "9900000000", LOCAL_CLOSE_SCRIPT).fundedShannons).toBe("9900000000");
        expect(() => dispatch.prepareChannelOpen(CHANNEL_INDEX, "9899999999", LOCAL_CLOSE_SCRIPT)).toThrow(RangeError);
        expect(() => dispatch.prepareChannelOpen(CHANNEL_INDEX, "1e10", LOCAL_CLOSE_SCRIPT)).toThrow(TypeError);
    });

    it.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1])("rejects the channel index %p", (channelIndex) => {
        expect(() => dispatch.prepareChannelOpen(channelIndex, FUNDED, LOCAL_CLOSE_SCRIPT)).toThrow(RangeError);
    });
});

describe("each transition", () => {
    // The number the message carries and the view: a commitment's version, a revocation's revoked number and the view it revokes.
    const REPORTED: Record<string, { commitmentNumber: number | null; view: "remote" | "local" | null }> = {
        SendCommitmentSigned: { commitmentNumber: 4, view: "remote" },
        CompleteReceivedCommitment: { commitmentNumber: 2, view: "local" },
        SendRevokeAndAck: { commitmentNumber: 2, view: "local" },
        CompleteReceivedRevokeAndAck: { commitmentNumber: 3, view: "remote" },
        SendClosingSigned: { commitmentNumber: null, view: null },
    };

    it.each(SIGNED)("signs %s to the byte fiber expects, with the material it expects", async (transition) => {
        const kase = caseOf(transition);
        const channel = await openSigningChannel(vectors, kase);
        const signed = signedOf(await channel.dispatch.handle(channel.channelId, statusOf(transition)));
        const status = kase.result.status as { request_id: string; content: { slot: { commitment_number: string } } };

        expect(bytesToHex(signed.partialSignature)).toBe(kase.expected.partial_signature);
        expect(signed.status).toBe("fresh");
        expect(signed.warnings).toEqual([]);
        expect(signed.transition).toBe(transition);
        expect(bytesToHex(signed.requestId)).toBe(status.request_id.slice(2));
        expect(signed.slot.commitmentNumber).toBe(Number(status.content.slot.commitment_number));
        expect({ commitmentNumber: signed.commitmentNumber, view: signed.view }).toEqual(REPORTED[transition]);
        const material = signed.nextMaterial;
        expect(
            material === null
                ? null
                : {
                      next_commitment_point: bytesToHex(material.nextCommitmentPoint),
                      next_commitment_nonce: bytesToHex(material.nextCommitmentNonce),
                      next_revocation_nonce: bytesToHex(material.nextRevocationNonce),
                  },
        ).toEqual(kase.expected.next_material);
    });

    it.each(SIGNED)("answers %s with a half the node verifies under the nonce the device published for the slot", async (transition) => {
        const channel = await openSigningChannel(vectors, caseOf(transition));
        const signed = signedOf(await channel.dispatch.handle(channel.channelId, statusOf(transition)));
        expect(partialSignatureVerifies(signed, statusOf(transition))).toBe(true);
    });

    it.each(SIGNED)("claims the slot %s signs at, before anything is signed", async (transition) => {
        const channel = await openSigningChannel(vectors, caseOf(transition));
        const signed = signedOf(await channel.dispatch.handle(channel.channelId, statusOf(transition)));
        const record = await recordOf(channel);
        expect(Object.keys(record.signedSessions)).toEqual([`${signed.slot.context}:${signed.slot.commitmentNumber}`]);
    });

    it.each(["SendCommitmentSigned", "CompleteReceivedCommitment"] as const)(
        "records the commitment %s signs under its view, hashed as fiber's message",
        async (transition) => {
            const channel = await openSigningChannel(vectors, caseOf(transition));
            const signed = signedOf(await channel.dispatch.handle(channel.channelId, statusOf(transition)));
            const view = signed.view ?? "remote";
            expect((await recordOf(channel)).commitmentHashes[view]).toEqual({
                commitmentNumber: signed.commitmentNumber,
                txHash: caseOf(transition).expected.message,
            });
        },
    );

    it("keeps the complete revocation signature of the peer's commitment it receives the revocation of", async () => {
        const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedRevokeAndAck"));
        signedOf(await channel.dispatch.handle(channel.channelId, statusOf("CompleteReceivedRevokeAndAck")));
        expect((await recordOf(channel)).revocations).toEqual([
            { version: 3, forRemote: true, signature: caseOf("CompleteReceivedRevokeAndAck").expected.signature },
        ]);
    });

    it.each(["SendCommitmentSigned", "CompleteReceivedCommitment", "SendRevokeAndAck", "SendClosingSigned"] as const)(
        "keeps no revocation evidence after %s",
        async (transition) => {
            const channel = await openSigningChannel(vectors, caseOf(transition));
            signedOf(await channel.dispatch.handle(channel.channelId, statusOf(transition)));
            expect((await recordOf(channel)).revocations).toEqual([]);
        },
    );
});

describe("no request", () => {
    it("is idle, reading nothing, even for a channel the device never registered", async () => {
        const channel = await openSigningChannel(vectors, caseOf("SendClosingSigned"));
        channel.storage.ops.length = 0;
        const status: WireField = { value: { type: "NoSignatureRequired" }, path: "response.result.status" };
        expect(await channel.dispatch.handle(UNKNOWN_CHANNEL_ID, status)).toEqual({ kind: "idle" });
        expect(channel.storage.ops).toEqual([]);
    });
});

describe("refusals, in the order of the steps", () => {
    describe("1. the decode", () => {
        it("refuses what the decoder refuses as malformed, with no request id to name", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            const outcome = refusedOf(
                await channel.dispatch.handle(
                    channel.channelId,
                    mutated(statusOf("SendCommitmentSigned"), "content.commitment_counter", "Remote"),
                ),
            );
            expect(outcome.requestId).toBeNull();
            expect(outcome.transition).toBeNull();
            expect(outcome.error.code).toBe("malformed");
            expect(outcome.error.message).toBe("response.result.status.content.commitment_counter must be Local for SendCommitmentSigned");
        });

        // Fiber's codec takes some of these as well formed: refusing them is the signer's job.
        it.each(vectors.variants.map((variant) => [variant.name, variant] as const))("refuses the variant with %s", async (_, variant) => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            expect((await refusedUnclaimed(channel, signingStatusField(variant))).code).toBe("malformed");
        });

        it.each(["CompleteReceivedCommitment", "CompleteReceivedRevokeAndAck"] as const)(
            "refuses %s without the peer's partial signature",
            async (transition) => {
                const channel = await openSigningChannel(vectors, caseOf(transition));
                const status = mutated(statusOf(transition), "session_evidence.peer_partial_signature", null);
                expect(await refusedUnclaimed(channel, status)).toEqual({
                    code: "malformed",
                    message: `response.result.status.session_evidence.peer_partial_signature must be present for ${transition}`,
                });
            },
        );

        it("refuses a malformed status as malformed even for a channel the device never registered", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            const status = mutated(statusOf("SendCommitmentSigned"), "request_id", "0x00");
            expect((await refusedUnclaimed(channel, status, UNKNOWN_CHANNEL_ID)).code).toBe("malformed");
        });

        it("refuses a status that is not one", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            expect((await refusedUnclaimed(channel, { value: undefined, path: "response.result.status" })).code).toBe("malformed");
        });
    });

    describe("2. the channel", () => {
        it.each([...SIGNED, "SignChannelAnnouncement"] as const)(
            "refuses %s for a channel the device never registered, naming the request",
            async (transition) => {
                const channel = await openSigningChannel(vectors, caseOf(transition));
                channel.storage.ops.length = 0;
                const outcome = refusedOf(await channel.dispatch.handle(UNKNOWN_CHANNEL_ID, statusOf(transition)));
                expect(outcome.error).toEqual({
                    code: "unknown_channel",
                    message: `channel ${UNKNOWN_CHANNEL_ID} is not registered on this device`,
                });
                expect(outcome.transition).toBe(transition);
                expect(bytesToHex(outcome.requestId ?? new Uint8Array())).toBe(
                    (caseOf(transition).result.status as { request_id: string }).request_id.slice(2),
                );
                expect(writesOf(channel.storage)).toEqual([]);
            },
        );
    });

    describe("3. the announcement", () => {
        it("refuses to sign a channel announcement: every channel of the device is private", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SignChannelAnnouncement"));
            expect(await refusedUnclaimed(channel, statusOf("SignChannelAnnouncement"))).toEqual({
                code: "policy_refusal",
                message: "a channel announcement is never signed: every channel of this device is private",
            });
        });

        it("refuses the announcement ahead of its key order", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SignChannelAnnouncement"));
            const status = mutated(
                statusOf("SignChannelAnnouncement"),
                "content.key_agg_ctx",
                keyAggContextWire(DEVICE_FUNDING_PUBKEY, PEER_FUNDING_PUBKEY),
            );
            expect((await refusedUnclaimed(channel, status)).code).toBe("policy_refusal");
        });
    });

    describe("4. the key order", () => {
        // With the vectors' keys the peer sorts first, so the sorted transitions take [peer, device] and the received revocation [device, peer].
        it.each(["SendCommitmentSigned", "CompleteReceivedCommitment", "SendClosingSigned"] as const)(
            "refuses %s with the keys out of ascending order",
            async (transition) => {
                const channel = await openSigningChannel(vectors, caseOf(transition));
                const status = mutated(
                    statusOf(transition),
                    "content.key_agg_ctx",
                    keyAggContextWire(DEVICE_FUNDING_PUBKEY, PEER_FUNDING_PUBKEY),
                );
                expect(await refusedUnclaimed(channel, status)).toEqual({
                    code: "malformed",
                    message: `the key aggregation is not in the ascending order ${transition} aggregates under`,
                });
            },
        );

        it("refuses SendRevokeAndAck with the device's key first", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendRevokeAndAck"));
            const status = mutated(
                statusOf("SendRevokeAndAck"),
                "content.key_agg_ctx",
                keyAggContextWire(DEVICE_FUNDING_PUBKEY, PEER_FUNDING_PUBKEY),
            );
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: "the key aggregation is not in the peer-first order SendRevokeAndAck aggregates under",
            });
        });

        it("refuses CompleteReceivedRevokeAndAck with the keys sorted, the peer's first", async () => {
            const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedRevokeAndAck"));
            const status = mutated(
                statusOf("CompleteReceivedRevokeAndAck"),
                "content.key_agg_ctx",
                keyAggContextWire(PEER_FUNDING_PUBKEY, DEVICE_FUNDING_PUBKEY),
            );
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: "the key aggregation is not in the device-first order CompleteReceivedRevokeAndAck aggregates under",
            });
        });

        it.each(SIGNED)("refuses %s aggregating a key in place of the device's", async (transition) => {
            const channel = await openSigningChannel(vectors, caseOf(transition));
            const stranger = pubkeyOf(PEER_KEYS.tlcBaseKey);
            const status = mutated(statusOf(transition), "content.key_agg_ctx", keyAggContextWire(PEER_FUNDING_PUBKEY, stranger));
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: "the key aggregation does not include the channel's funding key",
            });
        });

        it("refuses the key order ahead of the aggregated nonce", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            let status = mutated(
                statusOf("SendCommitmentSigned"),
                "content.key_agg_ctx",
                keyAggContextWire(DEVICE_FUNDING_PUBKEY, PEER_FUNDING_PUBKEY),
            );
            status = mutated(status, "session_evidence.peer_public_nonce", caseOfPeerNonce("SendClosingSigned"));
            expect((await refusedUnclaimed(channel, status)).message).toContain("key aggregation");
        });
    });

    describe("5. the aggregated nonce", () => {
        it.each(SIGNED)("refuses %s whose aggregate sums another peer nonce than the one it names", async (transition) => {
            const channel = await openSigningChannel(vectors, caseOf(transition));
            const other = transition === "SendClosingSigned" ? "SendCommitmentSigned" : "SendClosingSigned";
            const status = mutated(statusOf(transition), "session_evidence.peer_public_nonce", caseOfPeerNonce(other));
            const slot = (caseOf(transition).result.status as { content: { slot: { purpose: string; commitment_number: string } } }).content
                .slot;
            const context = slot.purpose === "Commitment" ? "COMMITMENT" : "REVOKE";
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: `the aggregated nonce is not the sum of this device's nonce at ${context}:${Number(slot.commitment_number)} and the peer's`,
            });
        });

        it("refuses an aggregate over the device's nonce of another slot", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            const status = mutated(statusOf("SendCommitmentSigned"), "content.slot.commitment_number", "0x5");
            expect((await refusedUnclaimed(channel, status)).message).toBe(
                "the aggregated nonce is not the sum of this device's nonce at COMMITMENT:5 and the peer's",
            );
        });

        it("refuses the aggregate ahead of the peer's signature", async () => {
            const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedRevokeAndAck"));
            let status = mutated(statusOf("CompleteReceivedRevokeAndAck"), "content.slot.commitment_number", "0x5");
            status = mutated(status, "session_evidence.peer_partial_signature", `0x${"11".repeat(32)}`);
            expect((await refusedUnclaimed(channel, status)).message).toContain("aggregated nonce");
        });
    });

    describe("7. the peer's partial signature", () => {
        it.each(["CompleteReceivedCommitment", "CompleteReceivedRevokeAndAck"] as const)(
            "refuses %s whose peer signature is not over its message",
            async (transition) => {
                const channel = await openSigningChannel(vectors, caseOf(transition));
                const status = mutated(statusOf(transition), "session_evidence.peer_partial_signature", `0x${"11".repeat(32)}`);
                expect(await refusedUnclaimed(channel, status)).toEqual({
                    code: "malformed",
                    message: `the peer's partial signature does not verify over the message ${transition} carries`,
                });
            },
        );

        it("refuses a received commitment the node changed after the peer signed it", async () => {
            const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedCommitment"));
            const status = mutated(
                statusOf("CompleteReceivedCommitment"),
                "content.content.transaction.outputs[0].capacity",
                "0x1689bac638",
            );
            expect((await refusedUnclaimed(channel, status)).message).toBe(
                "the peer's partial signature does not verify over the message CompleteReceivedCommitment carries",
            );
        });

        it("refuses the peer's signature of the right message under another aggregate", async () => {
            const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedRevokeAndAck"));
            const genuine = resigned(statusOf("CompleteReceivedRevokeAndAck"), 0x61);
            const other = resigned(statusOf("CompleteReceivedRevokeAndAck"), 0x62);
            const status = mutated(
                genuine,
                "session_evidence.peer_partial_signature",
                (other.value as { session_evidence: { peer_partial_signature: string } }).session_evidence.peer_partial_signature,
            );
            expect((await refusedUnclaimed(channel, status)).message).toContain("peer's partial signature");
        });

        // Unreachable through the decoder, which sizes every value first: the mapping is what keeps it the node's.
        it("refuses as malformed a peer half whose verification throws a type error", async () => {
            const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedCommitment"));
            const verify = jest.spyOn(musig2Engine, "verifyPeerPartialSignature").mockImplementation(() => {
                throw new TypeError("peerPublicNonce must be 66 bytes, got 65");
            });
            try {
                expect(await refusedUnclaimed(channel, statusOf("CompleteReceivedCommitment"))).toEqual({
                    code: "malformed",
                    message: "peerPublicNonce must be 66 bytes, got 65",
                });
            } finally {
                verify.mockRestore();
            }
        });

        it("signs a received commitment whose peer half was signed again over it", async () => {
            const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedCommitment"));
            expect(
                signedOf(await channel.dispatch.handle(channel.channelId, resigned(statusOf("CompleteReceivedCommitment")))).status,
            ).toBe("fresh");
        });
    });

    describe("8. the operation's input", () => {
        it("refuses a snapshot whose settlement key is not the device's", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            const status = mutated(statusOf("SendCommitmentSigned"), "settlement.local_settlement_pubkey", vectors.peer.tlc_base_pubkey);
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: "settlement.localSettlementPubkey is not this device's TLC base key",
            });
        });

        it("refuses a snapshot TLC whose key is not the device's at its number", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            const status = mutated(statusOf("SendCommitmentSigned"), "settlement.tlcs[0].local_key_pubkey", vectors.device.tlc_base_pubkey);
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: "settlement.tlcs[0].localKeyPubkey is not this device's TLC key at commitment number 2",
            });
        });

        it.each([
            ["0x5", 5],
            ["0x3", 3],
        ])("refuses the commitment it sends at slot %s carrying version 4", async (number, slot) => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            const status = resigned(mutated(statusOf("SendCommitmentSigned"), "content.slot.commitment_number", number));
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: `the commitment sent at slot ${slot} must carry that version, not 4`,
            });
        });

        it("refuses a commitment cell with a type script", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            const type = { code_hash: `0x${"91".repeat(32)}`, hash_type: "type", args: `0x${"86".repeat(32)}` };
            const status = mutated(statusOf("SendCommitmentSigned"), "content.content.transaction.outputs[0].type", type);
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: "the commitment cell must carry no type script: the channel is a CKB channel",
            });
        });

        it.each([
            ["SendRevokeAndAck", "0x4", 4, 2],
            ["SendRevokeAndAck", "0x2", 2, 2],
            ["CompleteReceivedRevokeAndAck", "0x5", 5, 3],
            ["CompleteReceivedRevokeAndAck", "0x3", 3, 3],
        ] as const)("refuses %s at slot %s (%i), which carries the revocation of %i", async (transition, number, slot, revoked) => {
            const channel = await openSigningChannel(vectors, caseOf(transition));
            const status = resigned(mutated(statusOf(transition), "content.slot.commitment_number", number));
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: `the revocation at slot ${slot} must revoke version ${slot - 1}, not ${revoked}`,
            });
        });

        it("refuses a received revocation that pays another script than the channel's close script", async () => {
            const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedRevokeAndAck"));
            const output = revocationOutputWire(REVOCATION_CAPACITY, PEER_CLOSE_SCRIPT, null);
            const status = resigned(mutated(statusOf("CompleteReceivedRevokeAndAck"), "content.content.output", output));
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: "a revocation the device receives must pay the channel's close script",
            });
        });

        it.each(["SendRevokeAndAck", "CompleteReceivedRevokeAndAck"] as const)(
            "refuses %s whose output has a type script",
            async (transition) => {
                const channel = await openSigningChannel(vectors, caseOf(transition));
                const lock = transition === "SendRevokeAndAck" ? PEER_CLOSE_SCRIPT : LOCAL_CLOSE_SCRIPT;
                const output = revocationOutputWire(REVOCATION_CAPACITY, lock, TYPE_SCRIPT);
                const status = resigned(mutated(statusOf(transition), "content.content.output", output));
                expect(await refusedUnclaimed(channel, status)).toEqual({
                    code: "malformed",
                    message: "the revocation output must carry no type script: the channel is a CKB channel",
                });
            },
        );

        it("rebuilds the vectors' revocation output to the byte, so the refusals above change only what they name", () => {
            const status = caseOf("CompleteReceivedRevokeAndAck").result.status as { content: { content: { output: string } } };
            expect(revocationOutputWire(REVOCATION_CAPACITY, LOCAL_CLOSE_SCRIPT, null)).toBe(status.content.content.output);
        });

        it.each(["liquidCapacityShannons", "commitmentFeeRate", "remoteReservedCkbShannons"] as const)(
            "refuses a commitment and a revocation while the host has not pinned %s, and still signs a close",
            async (field) => {
                for (const transition of ["SendCommitmentSigned", "CompleteReceivedRevokeAndAck"] as const) {
                    const channel = await openSigningChannel(vectors, caseOf(transition));
                    await updateRecord(channel, (record) => {
                        const pins = { ...record.pins };
                        delete pins[field];
                        return { ...record, pins };
                    });
                    expect(await refusedUnclaimed(channel, statusOf(transition))).toEqual({
                        code: "policy_refusal",
                        message: `the message is a function of ${field}, which the host has not pinned for the channel yet`,
                    });
                }
                const close = await openSigningChannel(vectors, caseOf("SendClosingSigned"));
                await updateRecord(close, (record) => {
                    const pins = { ...record.pins };
                    delete pins[field];
                    return { ...record, pins };
                });
                expect(signedOf(await close.dispatch.handle(close.channelId, statusOf("SendClosingSigned"))).status).toBe("fresh");
            },
        );

        it("refuses a revocation while no commitment has pinned the lock layout", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendRevokeAndAck"));
            await updateRecord(channel, (record) => {
                const pins = { ...record.pins };
                delete pins.lockLayout;
                return { ...record, pins };
            });
            expect(await refusedUnclaimed(channel, statusOf("SendRevokeAndAck"))).toEqual({
                code: "policy_refusal",
                message: "a revocation is sized under the lock layout, which no commitment of the channel has pinned yet",
            });
        });
    });

    describe("9. the gate", () => {
        it("refuses a commitment whose snapshot does not rebuild its tx", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            const status = mutated(statusOf("SendCommitmentSigned"), "settlement.local_amount", "0x103d6c8981");
            expect(await refusedUnclaimed(channel, status)).toEqual({
                code: "malformed",
                message: "the message does not match the attached channel state",
            });
        });

        it("refuses a commitment tx the snapshot does not rebuild, its peer half signed over it", async () => {
            const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedCommitment"));
            const status = resigned(
                mutated(statusOf("CompleteReceivedCommitment"), "content.content.transaction.outputs[0].capacity", "0x1689bac638"),
            );
            expect((await refusedUnclaimed(channel, status)).message).toBe("the message does not match the attached channel state");
        });

        it("refuses a revocation output the channel's terms do not rebuild", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendRevokeAndAck"));
            const output = revocationOutputWire(REVOCATION_CAPACITY + 1n, PEER_CLOSE_SCRIPT, null);
            const status = mutated(statusOf("SendRevokeAndAck"), "content.content.output", output);
            expect((await refusedUnclaimed(channel, status)).message).toBe("the message does not match the attached channel state");
        });

        it("refuses a revocation whose data is not the empty data a CKB channel's is", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendRevokeAndAck"));
            const status = mutated(statusOf("SendRevokeAndAck"), "content.content.output_data", "0x0100000000");
            expect((await refusedUnclaimed(channel, status)).message).toBe("the message does not match the attached channel state");
        });

        it("refuses a close whose tx says more than its outputs: an input with a since", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendClosingSigned"));
            const status = mutated(statusOf("SendClosingSigned"), "content.content.transaction.inputs[0].since", "0x1");
            expect((await refusedUnclaimed(channel, status)).message).toBe("the message does not match the attached channel state");
        });

        it("refuses a commitment below its lane as stale_state", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            await updateRecord(channel, (record) => ({ ...record, lastSignedCommitmentNumbers: { "COMMITMENT:local": 4 } }));
            expect(await refusedUnclaimed(channel, statusOf("SendCommitmentSigned"))).toEqual({
                code: "stale_state",
                message: "commitment number 4 is not above the last COMMITMENT:local signed, 4",
            });
        });

        // The vectors' sent revocation at 3 follows the device's own commitment at 3, the received one at 4 the peer's at 4.
        it.each([
            ["SendRevokeAndAck", "local", 3],
            ["CompleteReceivedRevokeAndAck", "remote", 4],
        ] as const)(
            "signs %s with its replacement, the %s commitment at the slot's number, as its view's last",
            async (transition, view, slot) => {
                const channel = await openSigningChannel(vectors, caseOf(transition));
                const { commitmentHashes } = await recordOf(channel);
                expect(Object.keys(commitmentHashes)).toEqual([view]);
                expect(commitmentHashes[view]?.commitmentNumber).toBe(slot);
                expect(signedOf(await channel.dispatch.handle(channel.channelId, statusOf(transition))).status).toBe("fresh");
                expect((await recordOf(channel)).commitmentHashes).toEqual(commitmentHashes);
            },
        );

        it.each([
            ["SendRevokeAndAck", "local", 3, null, "no local commitment has been signed"],
            ["SendRevokeAndAck", "local", 3, 2, "the last one signed is version 2"],
            ["SendRevokeAndAck", "local", 3, 4, "the last one signed is version 4"],
            ["CompleteReceivedRevokeAndAck", "remote", 4, null, "no remote commitment has been signed"],
            ["CompleteReceivedRevokeAndAck", "remote", 4, 3, "the last one signed is version 3"],
            ["CompleteReceivedRevokeAndAck", "remote", 4, 5, "the last one signed is version 5"],
        ] as const)(
            "refuses %s as stale_state while the %s view's last commitment is not the one at %p but %p",
            async (transition, view, slot, last, tail) => {
                const channel = await openSigningChannel(vectors, caseOf(transition));
                await updateRecord(channel, (record) => {
                    const replacement = record.commitmentHashes[view];
                    if (replacement === undefined) throw new Error("the case holds no replacement");
                    return { ...record, commitmentHashes: last === null ? {} : { [view]: { ...replacement, commitmentNumber: last } } };
                });
                expect(await refusedUnclaimed(channel, statusOf(transition))).toEqual({
                    code: "stale_state",
                    message: `the revocation at slot ${slot} must follow its replacement, the ${view} commitment at version ${slot}, and ${tail}`,
                });
            },
        );

        it("refuses a peer funding key other than the one the channel pinned", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendRevokeAndAck"));
            const pinned = bytesToHex(pubkeyOf(PEER_KEYS.tlcBaseKey));
            await updateRecord(channel, (record) => ({ ...record, pins: { ...record.pins, remoteFundingPubkey: pinned } }));
            expect(await refusedUnclaimed(channel, statusOf("SendRevokeAndAck"))).toEqual({
                code: "policy_refusal",
                message: `the request states remoteFundingPubkey ${vectors.peer.funding_pubkey}, but the channel pinned ${pinned}`,
            });
        });

        it("refuses offered TLCs no debit intent covers", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
            await updateRecord(channel, (record) => ({
                ...record,
                views: { ...record.views, remote: { exposureShannons: FUNDED, tlcs: [], chargedShannons: {}, creditedShannons: {} } },
            }));
            const refusal = await refusedUnclaimed(channel, statusOf("SendCommitmentSigned"));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toContain("which no debit intent covers");
        });

        it("refuses a close that pays the device less than its commitments by more than the close fee", async () => {
            const channel = await openSigningChannel(vectors, caseOf("SendClosingSigned"));
            // Both views pay the device 72000000000 and the close fee may take 1 CKB of it: one shannon below 71900000000.
            const status = mutated(statusOf("SendClosingSigned"), "content.content.transaction.outputs[1].capacity", "0x10bd92eeff");
            const refusal = await refusedUnclaimed(channel, status);
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toContain("by more than the 100000000 its fee may take");
        });
    });
});

describe("re-delivery", () => {
    it.each(SIGNED)("answers %s delivered twice with the same bytes, the second as already signed", async (transition) => {
        const channel = await openSigningChannel(vectors, caseOf(transition));
        const first = signedOf(await channel.dispatch.handle(channel.channelId, statusOf(transition)));
        const recorded = [...channel.storage.map.entries()];
        const second = signedOf(await channel.dispatch.handle(channel.channelId, statusOf(transition)));
        expect(second).toEqual({ ...first, status: "already-signed" });
        expect([...channel.storage.map.entries()]).toEqual(recorded);
    });

    it("writes nothing when a commitment is delivered again", async () => {
        const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
        signedOf(await channel.dispatch.handle(channel.channelId, statusOf("SendCommitmentSigned")));
        channel.storage.ops.length = 0;
        signedOf(await channel.dispatch.handle(channel.channelId, statusOf("SendCommitmentSigned")));
        expect(writesOf(channel.storage)).toEqual([]);
    });

    it("writes the revocation evidence again on the delivery after it was lost", async () => {
        const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedRevokeAndAck"));
        signedOf(await channel.dispatch.handle(channel.channelId, statusOf("CompleteReceivedRevokeAndAck")));
        await updateRecord(channel, (record) => ({ ...record, revocations: [] }));
        const again = signedOf(await channel.dispatch.handle(channel.channelId, statusOf("CompleteReceivedRevokeAndAck")));
        expect(again.status).toBe("already-signed");
        expect((await recordOf(channel)).revocations).toEqual([
            { version: 3, forRemote: true, signature: caseOf("CompleteReceivedRevokeAndAck").expected.signature },
        ]);
    });

    it("heals a crash between the claim and the evidence on the next delivery", async () => {
        const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedRevokeAndAck"));
        const recordKey = `${CHANNEL_RECORD_KEY_PREFIX}${CHANNEL_INDEX}`;
        let recordWrites = 0;
        const crashing: ISignerStorage = {
            get: (key) => channel.storage.get(key),
            set: (key, value) => {
                // The claim is the first write of the record, the evidence the second.
                if (key === recordKey && ++recordWrites === 2) throw new Error("the device lost power");
                channel.storage.set(key, value);
            },
        };
        const dispatch = new SignerDispatch({
            masterSeed: MASTER_SEED,
            commitmentLock: COMMITMENT_LOCK,
            fundingLockCellDepsCount: 2,
            policy: new PolicyEngine(new SignerStore(crashing)),
        });
        expect(faultOf(await dispatch.handle(channel.channelId, statusOf("CompleteReceivedRevokeAndAck")))).toEqual(
            new Error("the device lost power"),
        );
        expect((await recordOf(channel)).revocations).toEqual([]);
        expect(Object.keys((await recordOf(channel)).signedSessions)).toEqual(["REVOKE:4"]);

        const healed = signedOf(await dispatch.handle(channel.channelId, statusOf("CompleteReceivedRevokeAndAck")));
        expect(healed.status).toBe("already-signed");
        expect(bytesToHex(healed.partialSignature)).toBe(caseOf("CompleteReceivedRevokeAndAck").expected.partial_signature);
        expect((await recordOf(channel)).revocations).toEqual([
            { version: 3, forRemote: true, signature: caseOf("CompleteReceivedRevokeAndAck").expected.signature },
        ]);
    });
});

describe("a second session on a served slot", () => {
    // Fiber's open lands both commitment transitions on one slot: the received commitment, moved onto the sent one's slot.
    function secondSession(randByte = 0x71): WireField {
        return resigned(mutated(statusOf("CompleteReceivedCommitment"), "content.slot.commitment_number", "0x4"), randByte);
    }

    async function servedChannel(nonceReuse: "refuse" | "allow"): Promise<SigningChannel> {
        const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"), { nonceReuse });
        const settlement = (caseOf("CompleteReceivedCommitment").result.status as { settlement: { local_amount: string } }).settlement;
        await updateRecord(channel, (record) => ({
            ...record,
            views: {
                ...record.views,
                local: {
                    exposureShannons: BigInt(settlement.local_amount).toString(),
                    tlcs: signingViewTlcs(vectors),
                    chargedShannons: {},
                    creditedShannons: {},
                },
            },
        }));
        signedOf(await channel.dispatch.handle(channel.channelId, statusOf("SendCommitmentSigned")));
        return channel;
    }

    it("is refused by default, claiming nothing", async () => {
        const channel = await servedChannel("refuse");
        expect(await refusedUnclaimed(channel, secondSession())).toEqual({
            code: "policy_refusal",
            message: "slot COMMITMENT:4 has already served a different signing session",
        });
    });

    it("is signed under allow, reported as reused with its warning", async () => {
        const channel = await servedChannel("allow");
        const status = secondSession();
        const signed = signedOf(await channel.dispatch.handle(channel.channelId, status));
        expect(signed.status).toBe("reused");
        expect(signed.warnings).toEqual([{ kind: "nonce-reused", slot: "COMMITMENT:4" }]);
        expect(signed.view).toBe("local");
        expect(signed.commitmentNumber).toBe(2);
        expect(Object.keys((await recordOf(channel)).nonceReuse)).toEqual(["COMMITMENT:4"]);
        const value = status.value as { content: { agg_nonce: string }; session_evidence: { peer_public_nonce: string } };
        const session = new Session(
            hexToBytes(value.content.agg_nonce.slice(2)),
            [PEER_FUNDING_PUBKEY, DEVICE_FUNDING_PUBKEY],
            hexToBytes(caseOf("CompleteReceivedCommitment").expected.message),
        );
        const nonces = [hexToBytes(value.session_evidence.peer_public_nonce.slice(2)), getPublicNonce(KEYS, 4, "COMMITMENT")];
        expect(session.partialSigVerify(signed.partialSignature, nonces, 1)).toBe(true);
    });

    it("refuses a third session under allow: three equations solve for the funding key", async () => {
        const channel = await servedChannel("allow");
        signedOf(await channel.dispatch.handle(channel.channelId, secondSession()));
        const third = resigned(statusOf("SendCommitmentSigned"), 0x72);
        expect(await refusedUnclaimed(channel, third)).toEqual({
            code: "policy_refusal",
            message: "slot COMMITMENT:4 has already served two signing sessions, the most one nonce can",
        });
    });

    it("answers each served session again with its bytes, the reused one with its warning every time", async () => {
        const channel = await servedChannel("allow");
        const second = signedOf(await channel.dispatch.handle(channel.channelId, secondSession()));
        channel.storage.ops.length = 0;
        const secondAgain = signedOf(await channel.dispatch.handle(channel.channelId, secondSession()));
        expect(secondAgain).toEqual(second);
        const firstAgain = signedOf(await channel.dispatch.handle(channel.channelId, statusOf("SendCommitmentSigned")));
        expect(firstAgain.status).toBe("already-signed");
        expect(firstAgain.warnings).toEqual([]);
        expect(bytesToHex(firstAgain.partialSignature)).toBe(caseOf("SendCommitmentSigned").expected.partial_signature);
        expect(writesOf(channel.storage)).toEqual([]);
    });

    it("keeps the complete revocation signature of a received revocation reused under allow", async () => {
        const channel = await openSigningChannel(vectors, caseOf("CompleteReceivedRevokeAndAck"), { nonceReuse: "allow" });
        // Both revocations land on REVOKE:4: the device's own moves onto it with its revoked version, after its local replacement.
        const local = { commitmentNumber: 4, txHash: caseOf("CompleteReceivedCommitment").expected.message };
        await updateRecord(channel, (record) => ({ ...record, commitmentHashes: { ...record.commitmentHashes, local } }));
        const args = (statusOf("SendRevokeAndAck").value as { content: { content: { commitment_lock_script_args: string } } }).content
            .content.commitment_lock_script_args;
        const moved = mutated(statusOf("SendRevokeAndAck"), "content.slot.commitment_number", "0x4");
        const sent = resigned(mutated(moved, "content.content.commitment_lock_script_args", `${args.slice(0, -2)}03`), 0x73);
        expect(signedOf(await channel.dispatch.handle(channel.channelId, sent)).status).toBe("fresh");
        expect((await recordOf(channel)).revocations).toEqual([]);

        const received = statusOf("CompleteReceivedRevokeAndAck");
        const signed = signedOf(await channel.dispatch.handle(channel.channelId, received));
        expect(signed.status).toBe("reused");
        expect(signed.warnings).toEqual([{ kind: "nonce-reused", slot: "REVOKE:4" }]);
        expect((await recordOf(channel)).revocations).toEqual([
            { version: 3, forRemote: true, signature: caseOf("CompleteReceivedRevokeAndAck").expected.signature },
        ]);
    });
});

describe("faults", () => {
    // The aggregated nonce was checked at the request's slot, so a claim of another one is the device's own bug.
    it.each([
        ["another context", { context: "COMMITMENT" as const }, "COMMITMENT:3"],
        ["another number", { commitmentNumber: 4 }, "REVOKE:4"],
    ])("leaves a verdict for %s than the request's slot a fault, signing nothing", async (_, skew, claimed) => {
        const channel = await openSigningChannel(vectors, caseOf("SendRevokeAndAck"));
        const claim = channel.policy.checkAndClaim.bind(channel.policy);
        channel.policy.checkAndClaim = async (keys, request) => ({ ...(await claim(keys, request)), ...skew });
        const sign = jest.spyOn(musig2Engine, "partialSign");
        try {
            const cause = faultOf(await channel.dispatch.handle(channel.channelId, statusOf("SendRevokeAndAck")));
            expect(cause).toEqual(new Error(`the gate claimed ${claimed}, not the slot REVOKE:3 the nonce was checked at`));
            expect(sign).not.toHaveBeenCalled();
        } finally {
            sign.mockRestore();
        }
    });

    it("leaves a status whose storage throws unanswered, carrying the cause", async () => {
        const failure = Object.assign(new Error("no space left on device"), { code: "ENOSPC" });
        const storage: ISignerStorage = {
            get() {
                throw failure;
            },
            set() {
                throw failure;
            },
        };
        const dispatch = new SignerDispatch({
            masterSeed: MASTER_SEED,
            commitmentLock: COMMITMENT_LOCK,
            fundingLockCellDepsCount: 2,
            policy: new PolicyEngine(new SignerStore(storage)),
        });
        expect(await dispatch.handle(vectors.channel.channel_id, statusOf("SendCommitmentSigned"))).toEqual({
            kind: "fault",
            cause: failure,
        });
    });

    it("reports a corrupt record as a fault that claims nothing, and signs once the record is back", async () => {
        const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
        const key = `${CHANNEL_RECORD_KEY_PREFIX}${CHANNEL_INDEX}`;
        const record = channel.storage.map.get(key) ?? "";
        channel.storage.map.set(key, "garbage");
        channel.storage.ops.length = 0;
        expect(faultOf(await channel.dispatch.handle(channel.channelId, statusOf("SendCommitmentSigned")))).toBeInstanceOf(TypeError);
        expect(writesOf(channel.storage)).toEqual([]);
        channel.storage.map.set(key, record);
        expect(signedOf(await channel.dispatch.handle(channel.channelId, statusOf("SendCommitmentSigned"))).status).toBe("fresh");
    });

    it("leaves a status that fails to read for a reason no codec names as a fault, not a refusal", async () => {
        const channel = await openSigningChannel(vectors, caseOf("SendCommitmentSigned"));
        const failure = new Error("the host handed over a value whose fields throw");
        const value = Object.defineProperty({}, "type", {
            enumerable: true,
            get() {
                throw failure;
            },
        });
        channel.storage.ops.length = 0;
        expect(await channel.dispatch.handle(channel.channelId, { value, path: "response.result.status" })).toEqual({
            kind: "fault",
            cause: failure,
        });
        expect(channel.storage.ops).toEqual([]);
    });

    // The record's absence is the storage's failure, never the node's: it is not answered as malformed.
    it("reports a name that resolves to an index holding no record as a fault", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(`${CHANNEL_ALIAS_KEY_PREFIX}${vectors.channel.channel_id}`, String(CHANNEL_INDEX));
        const dispatch = new SignerDispatch({
            masterSeed: MASTER_SEED,
            commitmentLock: COMMITMENT_LOCK,
            fundingLockCellDepsCount: 2,
            policy: new PolicyEngine(new SignerStore(storage)),
        });
        expect(faultOf(await dispatch.handle(vectors.channel.channel_id, statusOf("SendCommitmentSigned")))).toBeInstanceOf(TypeError);
        expect(writesOf(storage)).toEqual([]);
    });
});

describe("secret hygiene", () => {
    it("names no key material in any refusal", async () => {
        const secrets = [
            MASTER_SEED,
            KEYS.fundingKey,
            KEYS.tlcBaseKey,
            KEYS.musig2BaseNonce,
            KEYS.commitmentSeed,
            deriveNonceSeed(KEYS, 4, "COMMITMENT"),
            deriveNonceSeed(KEYS, 4, "REVOKE"),
            deriveTlcKey(KEYS, 2),
        ].map(bytesToHex);
        const refusals: SignerRefusal[] = [];
        const refuse = async (transition: ChannelSigningTransition, status: WireField, channelId?: string) => {
            const channel = await openSigningChannel(vectors, caseOf(transition));
            refusals.push(refusedOf(await channel.dispatch.handle(channelId ?? channel.channelId, status)).error);
        };
        await refuse("SendCommitmentSigned", mutated(statusOf("SendCommitmentSigned"), "request_id", "0x00"));
        await refuse("SendCommitmentSigned", statusOf("SendCommitmentSigned"), UNKNOWN_CHANNEL_ID);
        await refuse("SignChannelAnnouncement", statusOf("SignChannelAnnouncement"));
        await refuse(
            "SendCommitmentSigned",
            mutated(statusOf("SendCommitmentSigned"), "content.key_agg_ctx", keyAggContextWire(DEVICE_FUNDING_PUBKEY, PEER_FUNDING_PUBKEY)),
        );
        await refuse("SendCommitmentSigned", mutated(statusOf("SendCommitmentSigned"), "content.slot.commitment_number", "0x5"));
        await refuse(
            "CompleteReceivedRevokeAndAck",
            mutated(statusOf("CompleteReceivedRevokeAndAck"), "session_evidence.peer_partial_signature", `0x${"11".repeat(32)}`),
        );
        await refuse(
            "SendCommitmentSigned",
            mutated(statusOf("SendCommitmentSigned"), "settlement.tlcs[0].local_key_pubkey", vectors.device.tlc_base_pubkey),
        );
        await refuse("SendCommitmentSigned", mutated(statusOf("SendCommitmentSigned"), "settlement.local_amount", "0x103d6c8981"));
        await refuse("SendRevokeAndAck", resigned(mutated(statusOf("SendRevokeAndAck"), "content.slot.commitment_number", "0x4")));

        expect(new Set(refusals.map((refusal) => refusal.code))).toEqual(new Set(["malformed", "unknown_channel", "policy_refusal"]));
        for (const { message } of refusals) for (const secret of secrets) expect(message).not.toContain(secret);
    });
});

function caseOfPeerNonce(transition: ChannelSigningTransition): string {
    return (caseOf(transition).result.status as { session_evidence: { peer_public_nonce: string } }).session_evidence.peer_public_nonce;
}
