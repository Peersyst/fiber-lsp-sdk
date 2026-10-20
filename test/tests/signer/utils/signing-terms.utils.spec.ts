import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../../src/common";
import { computeClosingTxDigest, computeCommitmentTxDigest, computeRevocationDigest } from "../../../../src/digest";
import type { ChannelPins, SignOperation } from "../../../../src/policy";
import { PolicyRefusalError } from "../../../../src/policy";
import type { ChannelSigningRequest, ChannelSigningTransition } from "../../../../src/protocol";
import { decodeChannelSigningStatus } from "../../../../src/protocol";
import type { SigningNetwork } from "../../../../src/signer/signer.types";
import { buildSignOperation, computeSigningMessage } from "../../../../src/signer/utils/signing-terms.utils";
import { signingDeviceKeys, signingPeerKeys } from "../../../utils/signing-channel";
import { loadSigningVectors, signingCaseOf, signingStatusField } from "../../../utils/signing-vectors";
import { pubkeyOf } from "../../../../src/derivation";

const vectors = loadSigningVectors();
const KEYS = signingDeviceKeys(vectors);
const PEER_FUNDING_PUBKEY = hexToBytes(vectors.peer.funding_pubkey);

const NETWORK: SigningNetwork = {
    commitmentLock: { codeHash: hexToBytes("740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8"), hashType: "type" },
    fundingLockCellDepsCount: 2,
};

// The vectors' channel as registered, its terms pinned by the host and its layout by a commitment.
const PINS: ChannelPins = {
    fundedShannons: "72000000000",
    localCloseScript:
        "490000001000000030000000310000005373" +
        "20e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d76901140000008d66477ba3b60a96feb27a3f57fe11f6697be87d",
    // 20-byte args under the lock's 57 or 58: 98 or 99 CKB occupied, plus the 1 CKB close fee.
    localReservedCkbShannons: { legacy: "9900000000", fullPaymentHash: "10000000000" },
    udtTypeScript: null,
    liquidCapacityShannons: "80500000000",
    commitmentFeeRate: "1000",
    remoteReservedCkbShannons: "6300000000",
    lockLayout: "fullPaymentHash",
};

const PEER_CLOSE_SCRIPT: Script = {
    codeHash: hexToBytes("4d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba"),
    hashType: "type",
    args: hexToBytes("8f1e030962418183dc890ef5664b1f2a64b0064c"),
};

const TYPE_SCRIPT: Script = { codeHash: new Uint8Array(32).fill(0x91), hashType: "type", args: new Uint8Array(32).fill(0x86) };

// A fresh copy per call, so a spec's mutation stays its own.
function requestOf(transition: ChannelSigningTransition): ChannelSigningRequest {
    const status = decodeChannelSigningStatus(signingStatusField(signingCaseOf(vectors, transition)));
    if (status.kind !== "required") throw new Error(`${transition} asks for no signature`);
    return status;
}

function build(request: ChannelSigningRequest, pins: ChannelPins = PINS) {
    return buildSignOperation(KEYS, request, PEER_FUNDING_PUBKEY, pins, NETWORK);
}

function digestOf(operation: SignOperation): Uint8Array {
    switch (operation.kind) {
        case "commitment_tx":
            return computeCommitmentTxDigest(KEYS, operation.input);
        case "revocation":
            return computeRevocationDigest(KEYS, operation.input);
        case "closing_tx":
            return computeClosingTxDigest(KEYS, operation.input);
        case "channel_announcement":
            throw new Error("never built");
    }
}

function contentOf<Kind extends ChannelSigningRequest["content"]["kind"]>(request: ChannelSigningRequest, kind: Kind) {
    const { content } = request;
    if (content.kind !== kind) throw new Error(`the request carries a ${content.kind}`);
    return content as Extract<ChannelSigningRequest["content"], { kind: Kind }>;
}

function withSlot(request: ChannelSigningRequest, commitmentNumber: number): ChannelSigningRequest {
    return { ...request, slot: { ...request.slot, commitmentNumber } };
}

function withoutPin(field: keyof ChannelPins): ChannelPins {
    const pins = { ...PINS };
    delete pins[field];
    return pins;
}

function policyRefusal(step: () => unknown): PolicyRefusalError {
    try {
        step();
    } catch (error) {
        if (error instanceof PolicyRefusalError) return error;
        throw error;
    }
    throw new Error("the step did not refuse");
}

const SIGNED_TRANSITIONS = [
    "SendCommitmentSigned",
    "CompleteReceivedCommitment",
    "SendRevokeAndAck",
    "CompleteReceivedRevokeAndAck",
    "SendClosingSigned",
] as const;

describe("computeSigningMessage", () => {
    it.each(SIGNED_TRANSITIONS)("computes the message fiber signs for %s", (transition) => {
        const kase = signingCaseOf(vectors, transition);
        expect(bytesToHex(computeSigningMessage(requestOf(transition).content))).toBe(kase.expected.message);
    });

    it("computes nothing for an announcement, which is refused before its content is read", () => {
        expect(() => computeSigningMessage(requestOf("SignChannelAnnouncement").content)).toThrow(
            new TypeError("a channel announcement is refused before its content is read"),
        );
    });
});

describe("buildSignOperation", () => {
    it.each([
        ["SendCommitmentSigned", "commitment_tx", 4, "remote"],
        ["CompleteReceivedCommitment", "commitment_tx", 2, "local"],
        ["SendRevokeAndAck", "revocation", 2, "local"],
        ["CompleteReceivedRevokeAndAck", "revocation", 3, "remote"],
        ["SendClosingSigned", "closing_tx", null, null],
    ] as const)("builds %s as a %s at %p in the %p view", (transition, kind, commitmentNumber, view) => {
        const prepared = build(requestOf(transition));
        expect(prepared.operation.kind).toBe(kind);
        expect(prepared.commitmentNumber).toBe(commitmentNumber);
        expect(prepared.view).toBe(view);
    });

    // The input is right when the digest rebuilt from it is the message fiber computed from the plaintext.
    it.each(SIGNED_TRANSITIONS)("builds the input of %s whose digest is fiber's message", (transition) => {
        expect(bytesToHex(digestOf(build(requestOf(transition)).operation))).toBe(signingCaseOf(vectors, transition).expected.message);
    });

    it("builds a commitment from its tx, its snapshot, the pins and the network", () => {
        const { operation } = build(requestOf("SendCommitmentSigned"));
        if (operation.kind !== "commitment_tx") throw new Error("not a commitment");
        const { input } = operation;
        expect(bytesToHex(input.fundingOutPoint.txHash)).toBe(vectors.channel.funding_out_point.tx_hash);
        expect(input.fundingOutPoint.index).toBe(0);
        expect(bytesToHex(input.remoteFundingPubkey)).toBe(vectors.peer.funding_pubkey);
        expect(bytesToHex(input.remoteTlcBasePubkey)).toBe(vectors.peer.tlc_base_pubkey);
        expect(input.commitmentNumber).toBe(4);
        expect(input.commitmentDelayEpoch).toBe(1099511627777n);
        expect(input.commitmentFeeRate).toBe(1000n);
        expect(input.cellDepsCount).toBe(2);
        expect(input.udtTypeScript).toBeNull();
        expect(input.liquidCapacityShannons).toBe(80500000000n);
        expect(input.localReservedCkbShannons).toBe(10000000000n);
        expect(input.remoteReservedCkbShannons).toBe(6300000000n);
        expect(input.commitmentLock).toBe(NETWORK.commitmentLock);
        expect(input.lockLayout).toBe("fullPaymentHash");
        expect(input.forRemote).toBe(true);
    });

    it("reads a commitment's layout from its lock args, leaving a pinned layout of the other kind to the gate", () => {
        const { operation } = build(requestOf("SendCommitmentSigned"), { ...PINS, lockLayout: "legacy" });
        expect(operation.kind === "commitment_tx" && operation.input.lockLayout).toBe("fullPaymentHash");
        const { operation: unpinned } = build(requestOf("SendCommitmentSigned"), withoutPin("lockLayout"));
        expect(unpinned.kind === "commitment_tx" && unpinned.input.lockLayout).toBe("fullPaymentHash");
    });

    it("builds a revocation under the pinned layout, paying the script its output locks", () => {
        for (const [transition, forRemote] of [
            ["SendRevokeAndAck", false],
            ["CompleteReceivedRevokeAndAck", true],
        ] as const) {
            const request = requestOf(transition);
            const { operation } = build(request);
            if (operation.kind !== "revocation") throw new Error("not a revocation");
            expect(operation.input.forRemote).toBe(forRemote);
            expect(operation.input.lockLayout).toBe("fullPaymentHash");
            expect(operation.input.localReservedCkbShannons).toBe(10000000000n);
            expect(operation.input.payoutScript).toEqual(contentOf(request, "revocation").output.lock);
            expect(operation.input.revokedCommitmentNumber).toBe(request.slot.commitmentNumber - 1);
        }
    });

    it("builds a close without the host's terms, which it is no function of", () => {
        const pins = withoutPin("commitmentFeeRate");
        delete pins.liquidCapacityShannons;
        delete pins.remoteReservedCkbShannons;
        expect(build(requestOf("SendClosingSigned"), pins).operation.kind).toBe("closing_tx");
    });

    it("builds no announcement", () => {
        expect(() => build(requestOf("SignChannelAnnouncement"))).toThrow(
            new TypeError("a channel announcement is refused before its content is read"),
        );
    });

    describe("a commitment", () => {
        it.each(["SendCommitmentSigned", "CompleteReceivedCommitment"] as const)("refuses %s without a settlement", (transition) => {
            expect(() => build({ ...requestOf(transition), settlement: null })).toThrow(
                new TypeError(`${transition} must carry the settlement its commitment is rebuilt from`),
            );
        });

        it("refuses a tx that spends nothing", () => {
            const request = requestOf("SendCommitmentSigned");
            contentOf(request, "commitmentTx").transaction.inputs = [];
            expect(() => build(request)).toThrow(new TypeError("the commitment tx must spend the funding cell"));
        });

        it("refuses a tx that creates nothing", () => {
            const request = requestOf("SendCommitmentSigned");
            contentOf(request, "commitmentTx").transaction.outputs = [];
            expect(() => build(request)).toThrow(new TypeError("the commitment tx must create the commitment cell"));
        });

        it("refuses a commitment cell with a type script", () => {
            const request = requestOf("SendCommitmentSigned");
            const [output] = contentOf(request, "commitmentTx").transaction.outputs;
            if (output === undefined) throw new Error("no output");
            output.type = TYPE_SCRIPT;
            expect(() => build(request)).toThrow(
                new TypeError("the commitment cell must carry no type script: the channel is a CKB channel"),
            );
        });

        it("refuses lock args of neither layout", () => {
            const request = requestOf("SendCommitmentSigned");
            const [output] = contentOf(request, "commitmentTx").transaction.outputs;
            if (output === undefined) throw new Error("no output");
            output.lock = { ...output.lock, args: output.lock.args.slice(0, 36) };
            expect(() => build(request)).toThrow(TypeError);
        });

        it("signs the commitment it sends only at the version its slot names, refusing one above and one below", () => {
            const request = requestOf("SendCommitmentSigned");
            expect(build(withSlot(request, 4)).commitmentNumber).toBe(4);
            expect(() => build(withSlot(request, 5))).toThrow(
                new TypeError("the commitment sent at slot 5 must carry that version, not 4"),
            );
            expect(() => build(withSlot(request, 3))).toThrow(
                new TypeError("the commitment sent at slot 3 must carry that version, not 4"),
            );
        });

        // The commitment the peer signed is versioned by the remote number, which the view keeps increasing.
        it("takes the commitment it receives at the remote number its args carry, whatever the slot", () => {
            const request = requestOf("CompleteReceivedCommitment");
            expect(build(request).commitmentNumber).toBe(2);
            expect(build(withSlot(request, 9)).commitmentNumber).toBe(2);
        });

        it("refuses a snapshot whose settlement key is not the device's", () => {
            const request = requestOf("SendCommitmentSigned");
            if (request.settlement === null) throw new Error("no settlement");
            request.settlement.localSettlementPubkey = pubkeyOf(signingPeerKeys(vectors).tlcBaseKey);
            expect(() => build(request)).toThrow(new TypeError("settlement.localSettlementPubkey is not this device's TLC base key"));
        });

        it("refuses a snapshot TLC whose key is not the device's at its number", () => {
            const request = requestOf("SendCommitmentSigned");
            const tlc = request.settlement?.tlcs[1];
            if (tlc === undefined) throw new Error("no TLC");
            tlc.localKeyCommitmentNumber += 1;
            expect(() => build(request)).toThrow(
                new TypeError(
                    `settlement.tlcs[1].localKeyPubkey is not this device's TLC key at commitment number ${tlc.localKeyCommitmentNumber}`,
                ),
            );
        });

        it.each(["liquidCapacityShannons", "commitmentFeeRate", "remoteReservedCkbShannons"] as const)(
            "refuses a commitment while the host has not pinned %s",
            (field) => {
                const refusal = policyRefusal(() => build(requestOf("SendCommitmentSigned"), withoutPin(field)));
                expect(refusal.code).toBe("policy_refusal");
                expect(refusal.message).toBe(`the message is a function of ${field}, which the host has not pinned for the channel yet`);
            },
        );

        it("names the first missing term in the gate's order", () => {
            const pins = withoutPin("remoteReservedCkbShannons");
            delete pins.liquidCapacityShannons;
            expect(policyRefusal(() => build(requestOf("SendCommitmentSigned"), pins)).message).toContain("liquidCapacityShannons");
        });
    });

    describe("a revocation", () => {
        it.each(["SendRevokeAndAck", "CompleteReceivedRevokeAndAck"] as const)(
            "refuses %s whose output has a type script",
            (transition) => {
                const request = requestOf(transition);
                contentOf(request, "revocation").output.type = TYPE_SCRIPT;
                expect(() => build(request)).toThrow(
                    new TypeError("the revocation output must carry no type script: the channel is a CKB channel"),
                );
            },
        );

        it.each(["SendRevokeAndAck", "CompleteReceivedRevokeAndAck"] as const)(
            "holds %s to revoking the number one below its slot",
            (transition) => {
                const request = requestOf(transition);
                const slot = request.slot.commitmentNumber;
                expect(build(request).commitmentNumber).toBe(slot - 1);
                expect(() => build(withSlot(request, slot + 1))).toThrow(
                    new TypeError(`the revocation at slot ${slot + 1} must revoke version ${slot}, not ${slot - 1}`),
                );
                expect(() => build(withSlot(request, slot - 1))).toThrow(
                    new TypeError(`the revocation at slot ${slot - 1} must revoke version ${slot - 2}, not ${slot - 1}`),
                );
            },
        );

        it("refuses a received revocation that pays another script than the channel's close script", () => {
            const request = requestOf("CompleteReceivedRevokeAndAck");
            contentOf(request, "revocation").output.lock = PEER_CLOSE_SCRIPT;
            expect(() => build(request)).toThrow(new TypeError("a revocation the device receives must pay the channel's close script"));
        });

        it("builds a sent revocation whatever script it pays, which is the peer's own", () => {
            const request = requestOf("SendRevokeAndAck");
            const output = contentOf(request, "revocation").output;
            output.lock = { ...output.lock, args: new Uint8Array(20).fill(0x55) };
            const { operation } = build(request);
            expect(operation.kind === "revocation" && bytesToHex(operation.input.payoutScript.args)).toBe("55".repeat(20));
        });

        it.each(["SendRevokeAndAck", "CompleteReceivedRevokeAndAck"] as const)(
            "refuses %s while no commitment has pinned the layout",
            (transition) => {
                const refusal = policyRefusal(() => build(requestOf(transition), withoutPin("lockLayout")));
                expect(refusal.code).toBe("policy_refusal");
                expect(refusal.message).toBe(
                    "a revocation is sized under the lock layout, which no commitment of the channel has pinned yet",
                );
            },
        );

        it.each(["liquidCapacityShannons", "commitmentFeeRate", "remoteReservedCkbShannons"] as const)(
            "refuses a revocation while the host has not pinned %s",
            (field) => {
                expect(policyRefusal(() => build(requestOf("SendRevokeAndAck"), withoutPin(field))).code).toBe("policy_refusal");
            },
        );
    });

    describe("a close", () => {
        it("refuses a close with a typed output, through the digest's reading of it", () => {
            const request = requestOf("SendClosingSigned");
            const [first] = contentOf(request, "closingTx").transaction.outputs;
            if (first === undefined) throw new Error("no output");
            first.type = TYPE_SCRIPT;
            expect(() => build(request)).toThrow(TypeError);
        });

        it("reads the device's output by funding-key order", () => {
            const { operation } = build(requestOf("SendClosingSigned"));
            if (operation.kind !== "closing_tx") throw new Error("not a close");
            expect(bytesToHex(operation.input.localCloseScript.args)).toBe(vectors.channel.local_close_script.args);
            expect(bytesToHex(operation.input.remoteCloseScript.args)).toBe(vectors.channel.remote_close_script.args);
        });
    });
});
